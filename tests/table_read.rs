//! Table test for `claude-guard read`: guard-read-keys.py's own 70 cases (test_guard_read_keys.sh),
//! plus the message text and input edges.

mod common;
use common::*;
use std::os::unix::fs::symlink;

fn j(path: &str, cwd: &str) -> String {
    serde_json::json!({"tool_name": "Read", "cwd": cwd, "tool_input": {"file_path": path}})
        .to_string()
}

fn code(input: &str) -> i32 {
    run(&[BIN, "read"], input).code
}

#[test]
fn guard_read_keys_cases() {
    let h = home();
    let d = fresh_dir("read-table");
    let mut fails = Vec::new();
    let mut n = 0;
    let mut t = |want: i32, input: String, label: &str| {
        n += 1;
        let got = code(&input);
        if got != want {
            fails.push(format!("[{label}] want={want} got={got}"));
        }
    };
    // must block
    for p in [
        format!("{h}/certs/x.pem"),
        format!("{h}/certs/X.PEM"),
        format!("{h}/Downloads/a.key"),
        format!("{h}/Library/b.Keystore"),
        "/tmp/c.p12".into(),
        "/tmp/d.pfx".into(),
        "/tmp/e.jks".into(),
        "/tmp/repo_deploy_key".into(),
        "/tmp/private_key_prod".into(),
        "/tmp/id_ed25519".into(),
        "/tmp/ID_RSA".into(),
        "~/certs/tilde.pem".into(),
        format!("{h}/.cache/uv/x/certifi/cacert.pem"),
        format!("{h}/vm/.vagrant/machines/default/virtualbox/private_key"),
        format!("{h}/.vagrant.d/insecure_private_key"),
        format!("{h}/.lima/_config/user"),
        format!("{h}/.colima/_lima/_config/user"),
        format!("{h}/.LIMA/_config/USER"),
    ] {
        t(2, j(&p, &h), &p);
    }
    t(
        2,
        j("relative/dir/k.key", &format!("{h}/code/app")),
        "relative path",
    );
    let link = format!("{d}/link.txt");
    symlink("/nonexistent/certs/real.pem", &link).unwrap();
    t(2, j(&link, &h), "symlink to a .pem");
    for p in [
        format!("{h}/.ssh/id_ed25519-personal"),
        "/tmp/id_rsa_work".into(),
        "/tmp/ID_ED25519-WORK".into(),
    ] {
        t(2, j(&p, &h), &p);
    }
    // keys with any name, found by their first lines
    std::fs::write(
        format!("{d}/github_work"),
        format!("{}\nAAAA\n", header("OPENSSH PRIVATE KEY")),
    )
    .unwrap();
    std::fs::write(
        format!("{d}/bag.txt"),
        format!(
            "Bag Attributes\n    friendlyName: x\n{}\nAAAA\n",
            header("PRIVATE KEY")
        ),
    )
    .unwrap();
    std::fs::write(
        format!("{d}/putty-key"),
        "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n",
    )
    .unwrap();
    std::fs::write(
        format!("{d}/secret.asc"),
        format!("{}\n\nAAAA\n", header("PGP PRIVATE KEY BLOCK")),
    )
    .unwrap();
    symlink(format!("{d}/github_work"), format!("{d}/notes.txt")).unwrap();
    for f in [
        "github_work",
        "bag.txt",
        "putty-key",
        "secret.asc",
        "notes.txt",
    ] {
        t(2, j(&format!("{d}/{f}"), &h), f);
    }
    // must allow
    for p in [
        "/tmp/id_ed25519.pub".to_string(),
        "/tmp/server.crt".into(),
        "/tmp/ca.cer".into(),
        "/tmp/req.csr".into(),
        format!("{h}/.ssh/config"),
        "/tmp/README.md".into(),
        "/tmp/keys.ts".into(),
        "/tmp/key.md".into(),
        "/tmp/pem-notes.txt".into(),
        "/tmp/monkey".into(),
        "/tmp/keyfile.json".into(),
        "/tmp/user".into(),
        format!("{h}/.lima/_config/user.pub"),
        format!("{h}/.lima/_config/networks.yaml"),
        "/tmp/private_key.md".into(),
        format!("{h}/project/_config/user"),
    ] {
        t(0, j(&p, &h), &p);
    }
    std::fs::write(
        format!("{d}/pub.txt"),
        format!("{}\nAAAA\n", header("PUBLIC KEY")),
    )
    .unwrap();
    std::fs::write(
        format!("{d}/cert.txt"),
        format!("{}\nAAAA\n", header("CERTIFICATE")),
    )
    .unwrap();
    std::fs::write(
        format!("{d}/code.py"),
        format!("HEADER = (\n    \"{}\"\n)\n", header("RSA PRIVATE KEY")),
    )
    .unwrap();
    std::fs::write(
        format!("{d}/late.txt"),
        format!("{}\n{}\n", "x".repeat(5000), header("OPENSSH PRIVATE KEY")),
    )
    .unwrap();
    for f in ["pub.txt", "cert.txt", "code.py", "late.txt"] {
        t(0, j(&format!("{d}/{f}"), &h), f);
    }
    t(0, j(&d, &h), "a folder");
    for p in [
        format!("{h}/.ssh/id_ed25519-personal.pub"),
        "/tmp/id_ed25519-cert.pub".into(),
    ] {
        t(0, j(&p, &h), &p);
    }
    // tools' credential files in the home folder (by path; they needn't exist)
    for p in [
        format!("{h}/.npmrc"),
        format!("{h}/.docker/config.json"),
        format!("{h}/.config/gh/hosts.yml"),
        format!("{h}/.claude/.credentials.json"),
        format!("{h}/.graphmind/config.json"),
        format!("{h}/.gnupg/private-keys-v1.d/0A1B2C3D"),
        "~/.netrc".into(),
    ] {
        t(2, j(&p, &h), &p);
    }
    t(2, j(".npmrc", &h), "relative ~/.npmrc");
    symlink(format!("{h}/.npmrc"), format!("{d}/npm-settings")).unwrap();
    t(
        2,
        j(&format!("{d}/npm-settings"), &h),
        "symlink to ~/.npmrc",
    );
    for p in [
        format!("{h}/code/app/.npmrc"),
        format!("{h}/.config/gh/config.yml"),
        format!("{h}/.docker/daemon.json"),
        format!("{h}/.gnupg/pubring.kbx"),
        "/tmp/.npmrc".into(),
    ] {
        t(0, j(&p, &h), &p);
    }
    for (input, label) in [
        ("not json", "unreadable input"),
        ("[]", "JSON list"),
        ("{\"tool_name\":\"Read\"}", "no tool_input"),
        ("{\"tool_input\":{\"file_path\":\"\"}}", "empty path"),
        ("{\"tool_input\":{\"file_path\":42}}", "path not a string"),
    ] {
        t(0, input.to_string(), label);
    }
    let _ = std::fs::remove_dir_all(&d);
    assert_eq!(n, 70, "case count");
    assert!(
        fails.is_empty(),
        "{} of {n} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

/// The real home folder from the user database, as the guard finds it; not `$HOME`, which the test's
/// caller could have changed.
fn real_home() -> String {
    let user = std::process::Command::new("/usr/bin/id")
        .arg("-un")
        .output()
        .unwrap();
    let user = String::from_utf8_lossy(&user.stdout).trim().to_string();
    let o = std::process::Command::new("/usr/bin/dscl")
        .args([".", "-read", &format!("/Users/{user}"), "NFSHomeDirectory"])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    let h = out
        .split_whitespace()
        .nth(1)
        .expect("NFSHomeDirectory")
        .to_string();
    assert!(std::path::Path::new(&h).is_dir(), "real home {h}");
    h
}

/// A caller can set HOME to any folder. Credential files are found in the real home (user database), as
/// guard-read-keys.py does: a fake HOME neither hides the real ones nor turns its own files into credentials.
/// Key names block wherever they are.
#[test]
fn a_fake_home_changes_nothing() {
    let real = real_home();
    let fake = fresh_dir("read-fake-home");
    assert_ne!(fake, real);
    let env = [("HOME", fake.as_str())];
    for (want, path, label) in [
        (
            0,
            "~/.npmrc".to_string(),
            "~/.npmrc under a fake HOME is the fake folder's file",
        ),
        (
            2,
            format!("{real}/.npmrc"),
            "the real ~/.npmrc stays blocked under a fake HOME",
        ),
        (
            2,
            "~/.ssh/id_rsa".to_string(),
            "a key name under a fake HOME",
        ),
    ] {
        let o = run_in(&[BIN, "read"], &j(&path, "/tmp"), &env, None);
        assert_eq!(o.code, want, "{label}: {path} (stderr: {})", o.stderr);
    }
    let _ = std::fs::remove_dir_all(&fake);
}

#[test]
fn message_is_python_s() {
    let o = run(&[BIN, "read"], &j("/tmp/a/Server.PEM", "/"));
    assert_eq!(o.code, 2);
    assert_eq!(
        o.stderr,
        "Blocked by guard-read-keys.py: Server.PEM looks like a private key or certificate store. Don't read key or credential files; work from the path, and ask the user if the task needs the contents.\n"
    );
    assert_eq!(o.stdout, "");
    // A relative path with a non-string cwd: Python raised TypeError (crash, blocked).
    let o = run(
        &[BIN, "read"],
        "{\"cwd\": 5, \"tool_input\": {\"file_path\": \"x.txt\"}}",
    );
    assert_eq!(o.code, 2);
    assert!(
        o.stderr.contains("crashed, so the read is blocked"),
        "{}",
        o.stderr
    );
}

#[test]
fn shadow_read_never_blocks() {
    let d = fresh_dir("read-shadow");
    let log = format!("{d}/shadow.log");
    let missing = format!("{d}/missing.py");
    for p in ["/tmp/x.pem", "/tmp/notes.md"] {
        let o = run(
            &[
                BIN,
                "read",
                "--shadow",
                "--reference",
                &missing,
                "--log",
                &log,
            ],
            &j(p, "/"),
        );
        assert_eq!(
            (o.code, o.stdout.as_str(), o.stderr.as_str()),
            (0, "", ""),
            "{p}"
        );
    }
    let mut text = String::new();
    for _ in 0..200 {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.lines().count() >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(text.contains("\"rust\": \"key-name\""), "{text}");
    assert!(!text.contains("x.pem"), "the log must not hold the path");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn json_limits_match_python() {
    // `levels` counts the outer object: json.load reads 993 levels; at 994 guard-read-keys.py crashed (blocks).
    let nested = |levels: usize, path: &str| {
        format!(
            "{{\"tool_input\": {{\"file_path\": \"{path}\"}}, \"a\": {}1{}}}",
            "[".repeat(levels - 1),
            "]".repeat(levels - 1)
        )
    };
    assert_eq!(code(&nested(993, "/x/a.pem")), 2);
    assert_eq!(code(&nested(993, "/x/a.txt")), 0);
    for p in ["/x/a.pem", "/x/a.txt"] {
        let o = run(&[BIN, "read"], &nested(994, p));
        assert_eq!(o.code, 2, "{p}");
        assert!(
            o.stderr.contains("crashed, so the read is blocked")
                && o.stderr.contains("RecursionError")
        );
    }
    // Numbers past f64's range: Python read inf, so the rest of the input was still checked.
    let o = run(
        &[BIN, "read"],
        "{\"tool_input\": {\"file_path\": \"/x/a.pem\"}, \"n\": 1e400}",
    );
    assert_eq!(o.code, 2);
}
