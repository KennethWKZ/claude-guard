//! `claude-guard dns-nxdomain [--port N] [--log FILE]`: answer every DNS query with "no such domain" (NXDOMAIN)
//! at once, on 127.0.0.1:10053 (UDP). Port of dns-nxdomain.py, the responder dns-blocklist's /etc/resolver files
//! point the web guard's canary and callback domains at. Without an answer macOS keeps retrying a dead port for
//! about 30 seconds; this answers at once and forwards and resolves nothing.
//!
//! Same packets in, same packets out, same web.log lines as the Python daemon: the question name read label by
//! label from offset 12 (no compression pointers; bytes past ASCII read as U+FFFD; lowercased), queries shorter
//! than 17 bytes, unreadable questions and responses ignored, the reply built from the query's id, opcode and RD
//! bit with QR, AA, RA and RCODE 3, one question and no records. Each name is logged at most once a minute
//! (`{"mode": "dns", "name": ...}`, the name only); the memory of logged names is cleared past 5,000 entries.
//!
//! One difference on purpose: a failed send is skipped (the Python daemon raised, exited and was restarted by
//! launchd, dropping queries meanwhile).

use crate::hookio::py_str;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

const HOST: &str = "127.0.0.1";
const PORT: u16 = 10053;

/// `(name, end offset of the question)`, or None for a packet whose question can't be read.
pub fn question_name(packet: &[u8]) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut i = 12;
    loop {
        let n = *packet.get(i)? as usize;
        if n == 0 {
            i += 1;
            break;
        }
        if n & 0xC0 != 0 {
            return None; // compression pointers don't belong in a query's question
        }
        // packet[i+1:i+1+n]: a slice, so a label cut short by the end of the packet is just shorter.
        let start = (i + 1).min(packet.len());
        let end = (i + 1 + n).min(packet.len());
        labels.push(
            packet[start..end]
                .iter()
                .map(|&b| if b < 0x80 { b as char } else { '\u{fffd}' })
                .collect(),
        );
        i += 1 + n;
    }
    if i + 4 > packet.len() {
        return None;
    }
    Some((labels.join(".").to_ascii_lowercase(), i + 4))
}

/// The NXDOMAIN reply to a query, or None for a response.
pub fn nxdomain(packet: &[u8], end: usize) -> Option<Vec<u8>> {
    let flags_in = u16::from_be_bytes([packet[2], packet[3]]);
    if flags_in & 0x8000 != 0 {
        return None;
    }
    let (opcode, rd) = (flags_in & 0x7800, flags_in & 0x0100);
    let flags: u16 = 0x8000 | opcode | 0x0400 | rd | 0x0080 | 3; // QR, AA, RD copied, RA, RCODE=NXDOMAIN
    let mut out = Vec::with_capacity(end);
    out.extend_from_slice(&packet[0..2]);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&packet[12..end]);
    Some(out)
}

/// The reply and the name to log for one received datagram (`packet` already cut at 4096 bytes).
pub fn handle(packet: &[u8]) -> Option<(Vec<u8>, String)> {
    if packet.len() < 17 {
        return None;
    }
    let (name, end) = question_name(packet)?;
    Some((nxdomain(packet, end)?, name))
}

/// One web.log line, as the Python daemon wrote it (folder 0700, file 0600, append). Never fails.
fn log(path: &str, name: &str) {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = std::path::Path::new(path)
        .parent()
        .map(|p| p.as_os_str().to_owned())
        .unwrap_or_default();
    if dir.is_empty()
        || std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .is_err()
    {
        return; // os.makedirs("") raised, so Python logged nothing
    }
    let short: String = name.chars().take(253).collect();
    let line = format!(
        "{{\"time\": {}, \"mode\": \"dns\", \"name\": {}, \"decision\": \"nxdomain\", \"rule\": \"dns-blocklist\"}}\n",
        py_str(&crate::prompt::local_time()),
        py_str(&short)
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Options as the Python daemon read them: `--port N` (a bad number is an error), `--log FILE`; anything else,
/// and a flag without a value, is skipped.
fn options(args: &[String]) -> Result<(u16, String), String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut port = PORT;
    let mut path = crate::pyfs::expanduser("~/.local/state/claude-guard/web.log")
        .unwrap_or_else(|_| format!("{home}/.local/state/claude-guard/web.log"));
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if a == "--port" && i < args.len() {
            port = args[i]
                .trim()
                .parse()
                .map_err(|_| format!("invalid port {:?}", args[i]))?;
            i += 1;
        } else if a == "--log" && i < args.len() {
            path = args[i].clone();
            i += 1;
        }
    }
    Ok((port, path))
}

/// Run the responder until killed. Exits 1 when the port can't be bound (launchd restarts it).
pub fn serve(args: &[String]) -> i32 {
    let (port, path) = match options(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("dns-nxdomain: {e}");
            return 1;
        }
    };
    let sock = match UdpSocket::bind((HOST, port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("dns-nxdomain: can't listen on {HOST}:{port}: {e}");
            return 1;
        }
    };
    let mut last: HashMap<String, f64> = HashMap::new(); // name -> time logged, so a retry storm doesn't flood the log
    let mut buf = [0u8; 4096];
    loop {
        let Ok((n, addr)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let Some((reply, name)) = handle(&buf[..n]) else {
            continue;
        };
        let _ = sock.send_to(&reply, addr);
        let t = now();
        if t - last.get(&name).copied().unwrap_or(0.0) > 60.0 {
            last.insert(name.clone(), t);
            if last.len() > 5000 {
                last.clear();
            }
            log(&path, &name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, flags: u16) -> Vec<u8> {
        let mut p = vec![0x12, 0x34];
        p.extend_from_slice(&flags.to_be_bytes());
        p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        for l in name.split('.') {
            p.push(l.len() as u8);
            p.extend_from_slice(l.as_bytes());
        }
        p.extend_from_slice(&[0, 0, 1, 0, 1]);
        p
    }

    #[test]
    fn answers_like_the_python_daemon() {
        let q = query("Probe.Example.COM", 0x0100);
        let (reply, name) = handle(&q).unwrap();
        assert_eq!(name, "probe.example.com");
        assert_eq!(
            &reply[..12],
            &[0x12, 0x34, 0x85, 0x83, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&reply[12..], &q[12..]);
        assert!(
            handle(&query("a.b", 0x8100)).is_none(),
            "a response gets no answer"
        );
        assert!(handle(&q[..16]).is_none(), "under 17 bytes");
        let mut ptr = query("example.com", 0);
        ptr[12] = 0xC0;
        assert!(handle(&ptr).is_none(), "compression pointer");
        let mut hi = query("ex\u{7f}mple.com", 0);
        hi[14] = 0xE9;
        assert_eq!(handle(&hi).unwrap().1, "e\u{fffd}\u{7f}mple.com");
    }
}
