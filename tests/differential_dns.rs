//! Differential test: `claude-guard dns-nxdomain` against dns-nxdomain.py, both running for real on free
//! localhost ports with temp logs. Every generated datagram goes to both in lock-step, followed by a sentinel
//! query, so "no reply" is seen without timeouts; replies must match byte for byte, and the web.log lines (time
//! left out) must match in order, which also covers the once-a-minute log limit and its 5,000-name reset.
//! The sentinel's own lines are left out of that comparison: each server first logs it at its own start, so once
//! a run passes 60 s (a loaded Mac) the two log it again at different packets. Both must still have logged it.
//! Reference: dns-nxdomain.py (default tests/reference/dns-nxdomain.py). Names are made up.
//! Env (test only): CLAUDE_GUARD_REF_DNS, CLAUDE_GUARD_DIFF_CASES (default 3000), CLAUDE_GUARD_DIFF_SEED.

mod common;
use common::*;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn query(id: u16, flags: u16, labels: &[Vec<u8>], tail: &[u8]) -> Vec<u8> {
    let mut p = id.to_be_bytes().to_vec();
    p.extend_from_slice(&flags.to_be_bytes());
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for l in labels {
        p.push(l.len() as u8);
        p.extend_from_slice(l);
    }
    p.push(0);
    p.extend_from_slice(tail);
    p
}

const SENTINEL_ID: u16 = 0xFEED;

fn sentinel() -> Vec<u8> {
    query(
        SENTINEL_ID,
        0x0100,
        &[b"sentinel".to_vec(), b"test".to_vec()],
        &[0, 1, 0, 1],
    )
}

/// Send `packet`, then the sentinel; the reply to `packet` (if any) arrives before the sentinel's.
fn exchange(sock: &UdpSocket, port: u16, packet: &[u8]) -> Option<Vec<u8>> {
    sock.send_to(packet, ("127.0.0.1", port)).unwrap();
    sock.send_to(&sentinel(), ("127.0.0.1", port)).unwrap();
    let mut got = None;
    let mut buf = [0u8; 8192];
    loop {
        let (n, _) = sock.recv_from(&mut buf).expect("no reply to the sentinel");
        let r = buf[..n].to_vec();
        if r.len() >= 2
            && u16::from_be_bytes([r[0], r[1]]) == SENTINEL_ID
            && r[12..] == sentinel()[12..]
        {
            return got;
        }
        got = Some(r);
    }
}

fn start(cmd: &[&str], port: u16, log: &str) -> Server {
    let mut args: Vec<String> = cmd[1..].iter().map(|s| s.to_string()).collect();
    args.extend([
        "--port".into(),
        port.to_string(),
        "--log".into(),
        log.into(),
    ]);
    let child = Command::new(cmd[0])
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let server = Server { child, port };
    // Wait until it answers.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    for _ in 0..100 {
        sock.send_to(&sentinel(), ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 512];
        if sock.recv_from(&mut buf).is_ok() {
            return server;
        }
    }
    panic!("server on port {port} never answered: {cmd:?}");
}

fn label(rng: &mut Rng) -> Vec<u8> {
    let n = match rng.below(10) {
        0 => 0,
        1 => 63,
        _ => 1 + rng.below(12),
    };
    (0..n)
        .map(|_| match rng.below(10) {
            0 => rng.below(256) as u8,
            1 => b'A' + rng.below(26) as u8,
            2 => *rng.pick(b"-_.\\\"\x00\x7f "),
            _ => b'a' + rng.below(26) as u8,
        })
        .collect()
}

fn packet(rng: &mut Rng, i: usize) -> Vec<u8> {
    let id = (i % 0xFE00) as u16;
    let flags = match rng.below(8) {
        0 => rng.below(0x10000) as u16,
        1 => 0x8100, // a response
        2 => 0x2900, // opcode 5 (update), RD
        _ => 0x0100,
    };
    let n = 1 + rng.below(4);
    let mut labels: Vec<Vec<u8>> = (0..n)
        .map(|_| label(rng))
        .filter(|l| !l.is_empty())
        .collect();
    if labels.is_empty() {
        labels.push(b"x".to_vec());
    }
    let tail: Vec<u8> = match rng.below(8) {
        0 => vec![],
        1 => vec![0, 1],
        2 => vec![0, 1, 0, 1, 0, 0, 0x29, 0x10, 0, 0, 0, 0, 0, 0, 0], // EDNS OPT record after the question
        _ => vec![0, 1, 0, 1],
    };
    let mut p = query(id, flags, &labels, &tail);
    match rng.below(14) {
        0 => p.truncate(rng.below(p.len() + 1)),
        1 => {
            let k = 12 + rng.below(p.len().saturating_sub(12).max(1));
            if k < p.len() {
                p[k] = 0xC0 | rng.below(64) as u8; // compression pointer or bad length
            }
        }
        2 => {
            let k = rng.below(p.len());
            p[k] = rng.below(256) as u8;
        }
        3 => p.extend(std::iter::repeat_n(b'z', 4096 + rng.below(200))), // past the 4,096-byte read
        4 => p = (0..rng.below(40)).map(|_| rng.below(256) as u8).collect(),
        _ => {}
    }
    p
}

#[test]
fn differential_dns() {
    let reference = env_or(
        "CLAUDE_GUARD_REF_DNS",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/reference/dns-nxdomain.py"
        ),
    );
    if !std::path::Path::new(&reference).exists() {
        eprintln!("differential dns: skipped, no reference at {reference}");
        return;
    }
    let n: usize = env_or("CLAUDE_GUARD_DIFF_CASES", "3000").parse().unwrap();
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261124")
        .parse()
        .unwrap();
    let d = fresh_dir("dns-diff");
    let (py_log, rs_log) = (format!("{d}/py/web.log"), format!("{d}/rs/web.log"));
    let py = start(
        &["/usr/bin/python3", "-I", &reference],
        free_port(),
        &py_log,
    );
    let rs = start(&[BIN, "dns-nxdomain"], free_port(), &rs_log);
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    let mut rng = Rng(seed | 1);
    let mut packets: Vec<Vec<u8>> = (0..n).map(|i| packet(&mut rng, i)).collect();
    // 5,100 different names, then the first ones again: past 5,000 the log limit forgets every name.
    for i in 0..5100 {
        packets.push(query(
            1,
            0x0100,
            &[format!("n{i}").into_bytes(), b"example".to_vec()],
            &[0, 1, 0, 1],
        ));
    }
    for i in 0..50 {
        packets.push(query(
            2,
            0x0100,
            &[format!("n{i}").into_bytes(), b"example".to_vec()],
            &[0, 1, 0, 1],
        ));
    }
    let (mut same, mut answered, mut bad) = (0, 0, Vec::new());
    for p in &packets {
        let a = exchange(&sock, py.port, p);
        let b = exchange(&sock, rs.port, p);
        if a.is_some() {
            answered += 1;
        }
        if a == b {
            same += 1;
        } else {
            bad.push(format!(
                "packet {:02x?}\n  python: {:02x?}\n  rust:   {:02x?}",
                &p[..p.len().min(80)],
                a,
                b
            ));
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    // (log lines without their time, sentinel lines dropped; how many sentinel lines there were)
    let read = |p: &str| -> (Vec<String>, usize) {
        let lines: Vec<String> = std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .map(|l| {
                l.find(", \"mode\"")
                    .map_or(l.to_string(), |i| l[i..].to_string())
            })
            .collect();
        let is_sentinel = |l: &String| l.contains("\"name\": \"sentinel.test\",");
        let sentinels = lines.iter().filter(|l| is_sentinel(l)).count();
        (
            lines.into_iter().filter(|l| !is_sentinel(l)).collect(),
            sentinels,
        )
    };
    let ((pl, py_sentinels), (rl, rs_sentinels)) = (read(&py_log), read(&rs_log));
    use std::os::unix::fs::PermissionsExt;
    let modes = [&py_log, &rs_log].map(|p| {
        std::fs::metadata(p)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0)
    });
    drop(py);
    drop(rs);
    let _ = std::fs::remove_dir_all(&d);
    eprintln!(
        "differential dns: {} datagrams, {same} identical replies ({answered} answered), {} unexpected; {} log lines",
        packets.len(),
        bad.len(),
        pl.len()
    );
    assert!(
        bad.is_empty(),
        "{} different (first 8):\n{}",
        bad.len(),
        bad.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
    );
    assert!(
        py_sentinels > 0 && rs_sentinels > 0,
        "sentinel logged: python {py_sentinels}, rust {rs_sentinels}"
    );
    assert_eq!(pl.len(), rl.len(), "log line counts");
    let diff: Vec<_> = pl
        .iter()
        .zip(&rl)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .take(5)
        .collect();
    assert!(diff.is_empty(), "log lines differ: {diff:?}");
    assert_eq!(modes, [0o600, 0o600], "log file modes");
    assert!(
        pl.len() > 5100,
        "the 5,000-name reset logged the repeats again"
    );
}
