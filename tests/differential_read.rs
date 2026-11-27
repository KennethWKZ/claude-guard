//! Differential test: `claude-guard read` against guard-read-keys.py on generated paths, files and JSON edges.
//! Exit code and stderr must match exactly, except a crash (both block; the texts differ).
//! Env (test only): CLAUDE_GUARD_REF_READ, CLAUDE_GUARD_DIFF_CASES (default 4000), CLAUDE_GUARD_DIFF_SEED,
//! CLAUDE_GUARD_DIFF_WORKERS (default 2; pass "$(test-workers)").

mod common;
use common::*;
use serde_json::{Value, json};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::{Command, Stdio};

fn fixture(d: &str) {
    let w = |name: &str, body: String| std::fs::write(format!("{d}/{name}"), body).unwrap();
    w(
        "openssh",
        format!("{}\nAAAA\n", header("OPENSSH PRIVATE KEY")),
    );
    w(
        "bag.txt",
        format!("Bag Attributes\n{}\nAAAA\n", header("PRIVATE KEY")),
    );
    w("ec.txt", format!("{}\n", header("EC PRIVATE KEY")));
    w("enc.txt", format!("{}\n", header("ENCRYPTED PRIVATE KEY")));
    w("pgp.asc", format!("{}\n", header("PGP PRIVATE KEY BLOCK")));
    w("putty", "PuTTY-User-Key-File-2: ssh-rsa\n".into());
    w(
        "crlf.txt",
        format!("x\r\n{}\r\n", header("RSA PRIVATE KEY")),
    );
    w("cr-only.txt", format!("x\r{}\r", header("RSA PRIVATE KEY")));
    w("indented.txt", format!("  {}\n", header("RSA PRIVATE KEY")));
    w("lower.txt", "-----begin rsa private key-----\n".into());
    w("pub.txt", format!("{}\n", header("PUBLIC KEY")));
    w(
        "late.txt",
        format!("{}\n{}\n", "x".repeat(5000), header("PRIVATE KEY")),
    );
    w(
        "edge.txt",
        format!("{}\n{}\n", "x".repeat(4060), header("PRIVATE KEY")),
    ); // header starts inside 4 KiB, ends past it
    w("ok.md", "notes\n".into());
    w("empty", String::new());
    w("ключ.pem", "x".into());
    w("İD_RSA", "x".into());
    w("id_rsa.pub", "ssh-rsa AAAA\n".into());
    std::fs::create_dir_all(format!("{d}/dir.pem")).unwrap();
    std::fs::create_dir_all(format!("{d}/sub/.lima/_config")).unwrap();
    w("sub/.lima/_config/user", "x".into());
    w("locked.txt", format!("{}\n", header("PRIVATE KEY")));
    let _ = std::fs::set_permissions(
        format!("{d}/locked.txt"),
        std::fs::Permissions::from_mode(0o000),
    );
    let _ = symlink(format!("{d}/openssh"), format!("{d}/to-key"));
    let _ = symlink("/nonexistent/real.pem", format!("{d}/to-pem"));
    let _ = symlink(format!("{d}/to-key"), format!("{d}/chain"));
    let _ = symlink(format!("{d}/loop-b"), format!("{d}/loop-a"));
    let _ = symlink(format!("{d}/loop-a"), format!("{d}/loop-b"));
    let _ = symlink(format!("{}/.npmrc", home()), format!("{d}/to-npmrc"));
    let _ = symlink("sub", format!("{d}/rel-sub"));
    let _ = Command::new("mkfifo").arg(format!("{d}/fifo")).status();
}

fn generate(rng: &mut Rng, d: &str, user: &str) -> String {
    let h = home();
    let prefixes = [
        format!("{d}/"),
        "~/".into(),
        "~".into(),
        "/tmp/".into(),
        "".into(),
        "./".into(),
        "../".into(),
        format!("~{user}/"),
        "~root/".into(),
        "~nosuchuser42/".into(),
        format!("{h}/"),
        format!("{h}//"),
        "$HOME/".into(),
        format!("{d}/rel-sub/../"),
    ];
    let middles = [
        "",
        "",
        "",
        "x/",
        ".ssh/",
        ".lima/_config/",
        "_lima/_config/",
        ".colima/_lima/_config/",
        ".config/gh/",
        ".gnupg/private-keys-v1.d/",
        "a/../",
        "./",
        "sub/",
        ".docker/",
        ".cargo/",
        "vm/.vagrant/machines/default/vb/",
    ];
    let names = [
        "openssh",
        "bag.txt",
        "ec.txt",
        "enc.txt",
        "pgp.asc",
        "putty",
        "crlf.txt",
        "cr-only.txt",
        "indented.txt",
        "lower.txt",
        "pub.txt",
        "late.txt",
        "edge.txt",
        "ok.md",
        "empty",
        "ключ.pem",
        "İD_RSA",
        "id_rsa.pub",
        "dir.pem",
        "user",
        "USER",
        "locked.txt",
        "to-key",
        "to-pem",
        "chain",
        "loop-a",
        "to-npmrc",
        "fifo",
        "x.pem",
        "X.PEM",
        "a.key",
        "b.Keystore",
        "c.p12",
        "d.pfx",
        "e.jks",
        "repo_deploy_key",
        "x_private_key",
        "private_key_prod",
        "private_key",
        "id_rsa",
        "ID_RSA",
        "id_ed25519",
        "id_ed25519-work",
        "id_rsa_github",
        "id_ecdsa_sk.x",
        "id_rsa.pub",
        "id_rsax",
        "keys.ts",
        ".npmrc",
        ".yarnrc.yml",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        ".pgpass",
        ".my.cnf",
        ".vault-token",
        "config.json",
        "hosts.yml",
        "credentials.toml",
        "credentials",
        ".credentials.json",
        "auth.json",
        "0A1B2C",
        "config",
        "README.md",
        "",
    ];
    let suffixes = ["", "", "", "", ".pub", "/", ".bak", "~"];
    format!(
        "{}{}{}{}",
        rng.pick(&prefixes),
        rng.pick(&middles),
        rng.pick(&names),
        rng.pick(&suffixes)
    )
}

#[test]
fn rust_matches_python() {
    let h = home();
    let reference = env_or(
        "CLAUDE_GUARD_REF_READ",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/reference/guard-read-keys.py"
        ),
    );
    if !std::path::Path::new(&reference).exists() {
        eprintln!("SKIPPED: reference hook not found ({reference})");
        return;
    }
    let n: usize = env_or("CLAUDE_GUARD_DIFF_CASES", "4000").parse().unwrap();
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261124")
        .parse()
        .unwrap();
    let workers: usize = env_or("CLAUDE_GUARD_DIFF_WORKERS", "2").parse().unwrap();
    let user = env_or("USER", "nobody");
    let d = fresh_dir("read-diff");
    fixture(&d);

    let cwds = [
        json!(d),
        json!(h),
        json!(""),
        Value::Null,
        json!("/"),
        json!("/nonexistent"),
        json!(5),
        json!(true),
        json!([1]),
        json!(0),
    ];
    let mut rng = Rng(seed | 1);
    let mut inputs: Vec<String> = Vec::new();
    for _ in 0..n {
        let path = generate(&mut rng, &d, &user);
        let cwd = if rng.chance(50) {
            json!(d)
        } else {
            rng.pick(&cwds).clone()
        };
        let mut v =
            json!({"tool_name": "Read", "session_id": "diff", "tool_input": {"file_path": path}});
        if !cwd.is_null() {
            v["cwd"] = cwd;
        }
        if rng.chance(5) {
            v["tool_input"]["limit"] = json!(10);
        }
        inputs.push(v.to_string());
    }
    for raw in [
        "",
        "not json",
        "[]",
        "{}",
        "null",
        "{\"tool_input\": null}",
        "{\"tool_input\": []}",
        "{\"tool_input\": {\"file_path\": null}}",
        "{\"tool_input\": {\"file_path\": 42}}",
        "{\"tool_input\": {\"file_path\": [\"/tmp/x.pem\"]}}",
        "{\"tool_input\": {\"file_path\": \"\"}}",
        "{\"tool_input\": {\"file_path\": \"/tmp/x.pem\"}, \"n\": NaN}",
        "{\"tool_input\": {\"file_path\": \"/tmp/a\\u0000b.pem\"}}",
        "{\"tool_input\": {\"file_path\": \"/tmp/a\\u0000b\"}}",
        "{\"tool_input\": {\"file_path\": \"~a\\u0000b/x\"}}",
        "{\"tool_input\": {\"file_path\": \"/tmp/\\ud800.pem\"}}",
        "{\"tool_input\": {\"file_path\": \"relative.txt\"}, \"cwd\": 1.5}",
        "{\"tool_input\": {\"file_path\": \"/abs.pem\"}, \"cwd\": 1.5}",
    ] {
        inputs.push(raw.to_string());
    }

    let driver = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference_driver.py");
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", driver, "read", &reference])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        let feed: String = inputs
            .iter()
            .map(|i| json!({"input": i}).to_string() + "\n")
            .collect();
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = stdin.write_all(feed.as_bytes());
        });
    }
    let py_out = child.wait_with_output().unwrap();
    let py: Vec<Value> = String::from_utf8_lossy(&py_out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        py.len(),
        inputs.len(),
        "driver answered {} of {}",
        py.len(),
        inputs.len()
    );
    let rust: Vec<Out> = parallel(&inputs, workers, |_, i| run(&[BIN, "read"], i));

    // Spot check the driver against real runs.
    let spot: Vec<usize> = (0..inputs.len())
        .step_by((inputs.len() / 60).max(1))
        .collect();
    let real: Vec<Out> = parallel(&spot, workers, |_, &i| {
        run(&["/usr/bin/python3", "-I", &reference], &inputs[i])
    });
    for (k, &i) in spot.iter().enumerate() {
        let crashed = real[k].stderr.contains("crashed");
        if !crashed {
            assert_eq!(
                (real[k].code, real[k].stderr.as_str()),
                (
                    py[i]["code"].as_i64().unwrap() as i32,
                    py[i]["stderr"].as_str().unwrap()
                ),
                "driver vs real on {}",
                inputs[i]
            );
        }
    }

    let (mut same, mut known, mut bad, mut blocked) = (
        0,
        std::collections::BTreeMap::<&str, usize>::new(),
        Vec::new(),
        0,
    );
    for i in 0..inputs.len() {
        let (pc, pe) = (
            py[i]["code"].as_i64().unwrap() as i32,
            py[i]["stderr"].as_str().unwrap_or(""),
        );
        let r = &rust[i];
        if r.code == 2 {
            blocked += 1;
        }
        if r.code == pc && r.stderr == pe && r.stdout.is_empty() {
            same += 1;
        } else if pc == 2
            && r.code == 2
            && pe.contains("crashed, so the read is blocked")
            && r.stderr.contains("crashed, so the read is blocked")
        {
            *known.entry("both-crashed").or_default() += 1;
        } else if inputs[i].contains("\\ud800") && pc == r.code {
            *known.entry("lone-surrogate-text").or_default() += 1;
        } else {
            bad.push(format!(
                "input: {}\n  python: {pc} {pe:?}\n  rust:   {} {:?}",
                inputs[i], r.code, r.stderr
            ));
        }
    }
    let _ = std::fs::set_permissions(
        format!("{d}/locked.txt"),
        std::fs::Permissions::from_mode(0o600),
    );
    let _ = std::fs::remove_dir_all(&d);
    eprintln!(
        "differential read: {} inputs, {same} identical, known {:?}, {} unexpected; {blocked} blocked; {} spot checks",
        inputs.len(),
        known,
        bad.len(),
        spot.len()
    );
    assert!(
        bad.is_empty(),
        "{} unexpected differences (first 15):\n{}",
        bad.len(),
        bad.iter().take(15).cloned().collect::<Vec<_>>().join("\n")
    );
}
