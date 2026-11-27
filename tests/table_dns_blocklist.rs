//! Table tests for `claude-guard dns` (the DNS blocklist): each case states what the port prints and exits with,
//! and the bash reference (`tests/reference/dns-blocklist`) must give the same on an identical fake Mac.

mod common;
use common::dnsbl::*;
use common::*;

fn roots(tag: &str) -> (String, String) {
    (
        fresh_dir(&format!("dnsbl-t-{tag}-a")),
        fresh_dir(&format!("dnsbl-t-{tag}-b")),
    )
}

/// Run both sides; check they agree; return the port's normalised outcome.
fn both(tag: &str, sc: &Scenario) -> Outcome {
    let (a, b) = roots(tag);
    build(&a, sc);
    build(&b, sc);
    let mut n = Normalised::default();
    let want = normalise(&run_bash(&a, &sc.command), &a, &mut n);
    let got = normalise(&run_rust(&b, &sc.command), &b, &mut n);
    for (field, g, w) in [
        ("stdout", &got.stdout, &want.stdout),
        ("stderr", &got.stderr, &want.stderr),
        ("log", &got.log, &want.log),
        ("tree", &got.tree, &want.tree),
    ] {
        if g != w {
            let gl: Vec<&str> = g.lines().collect();
            let wl: Vec<&str> = w.lines().collect();
            let i = gl
                .iter()
                .zip(&wl)
                .position(|(a, b)| a != b)
                .unwrap_or(gl.len().min(wl.len()));
            panic!(
                "[{tag}] {field} differs at line {i}:\n  port: {:?}\n  bash: {:?}",
                gl.get(i),
                wl.get(i)
            );
        }
    }
    assert_eq!(got.code, want.code, "[{tag}] exit code");
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
    got
}

fn files(names: &[String], body: &str) -> Vec<(String, Entry)> {
    names
        .iter()
        .map(|n| (n.clone(), Entry::File(format!("{body}\n").into_bytes())))
        .collect()
}

fn all_names() -> Vec<String> {
    let mut v = builtin();
    v.push(SELFTEST.into());
    v.extend(RELAY.iter().map(|s| s.to_string()));
    v
}

/// A Mac with the blocklist installed and loaded, the agent answering, nothing resolving but example.com.
fn installed(command: &str) -> Scenario {
    let mut sc = Scenario::new(command);
    sc.resolver = Some(files(&all_names(), BODY));
    sc.plist = Plist::New;
    sc.agent_up = true;
    // launchctl bootout stops the agent; bootstrap starts it again.
    sc.up_after_bootstrap = true;
    sc.scutil = scutil_text(&builtin());
    sc
}

#[test]
fn list() {
    let o = both("list-plain", &Scenario::new("list"));
    assert_eq!(
        (o.code, o.stdout.clone()),
        (0, builtin().iter().map(|h| format!("{h}\n")).collect())
    );

    let mut sc = Scenario::new("list");
    // Kelvin sign K lowercases to k in Python; 1.5 and -0.0 are floats whose str() passes the filter.
    sc.policy = Some(Some(
        r#"{"block_hosts": ["Evil.Example.", "..dots.example..", "a_b.example", "x", "K.example", 1.5, -0.0, 1e16, true, null, ["n.example"], {"o.example": 1}, "canarytokens.com"]}"#
            .as_bytes()
            .to_vec(),
    ));
    let o = both("list-policy", &sc);
    assert_eq!(o.code, 0);
    for want in [
        "evil.example\n",
        "dots.example\n",
        "k.example\n",
        "1.5\n",
        "-0.0\n",
    ] {
        assert!(o.stdout.contains(want), "{want:?} missing:\n{}", o.stdout);
    }
    for not in ["a_b.example", "n.example", "o.example", "1e+16", "true"] {
        assert!(!o.stdout.contains(not), "{not:?} listed");
    }

    let mut sc = Scenario::new("list");
    sc.policy = Some(Some(
        br#"{"block_hosts": {"keys.example": 1, "Other.Example": [1]}}"#.to_vec(),
    ));
    let o = both("list-dict", &sc);
    assert!(o.stdout.contains("keys.example\n") && o.stdout.contains("other.example\n"));

    let mut sc = Scenario::new("list");
    sc.policy = Some(Some(br#"{"block_hosts": "abc.def"}"#.to_vec()));
    let o = both("list-string", &sc);
    assert_eq!(
        o.stdout.lines().count(),
        builtin().len(),
        "a string's characters are never names"
    );

    for (tag, body) in [
        ("null", &br#"{"block_hosts": null}"#[..]),
        ("number", br#"{"block_hosts": 3}"#),
        ("toplist", br#"["a.example"]"#),
        ("invalid", br#"{"block_hosts": ["#),
        ("empty", b""),
        ("utf8", b"{\"block_hosts\": [\"\xff.example\"]}"),
    ] {
        let mut sc = Scenario::new("list");
        sc.policy = Some(Some(body.to_vec()));
        let o = both(&format!("list-bad-{tag}"), &sc);
        assert_eq!(
            (o.code, o.stdout.as_str(), o.stderr.as_str()),
            (1, "", "<policy error>\n"),
            "{tag}"
        );
    }
    let mut sc = Scenario::new("list");
    sc.policy = Some(None);
    assert_eq!(both("list-policy-dir", &sc).code, 1);

    let mut sc = Scenario::new("list");
    sc.cg = Cg::Missing;
    let o = both("list-no-cg", &sc);
    assert_eq!(
        (o.code, o.stderr.as_str()),
        (
            1,
            "dns-blocklist: no block list: install claude-guard (Step 16, claude-guard)\n"
        )
    );
}

#[test]
fn status() {
    assert_eq!(
        both("st-missing", &Scenario::new("status")).stdout,
        "MISSING\n"
    );
    assert_eq!(
        both("st-ok", &installed("status")).stdout,
        "ok (43 of 43 loaded, responder answering, self-test blocked)\n"
    );
    let mut sc = installed("status");
    sc.plist = Plist::OldPython;
    assert!(
        both("st-old", &sc)
            .stdout
            .contains("still runs the old Python script")
    );
    let mut sc = installed("status");
    sc.resolver = Some(files(&builtin(), BODY));
    assert!(
        both("st-extras", &sc)
            .stdout
            .contains("missing self-test or Private Relay file")
    );
    let mut sc = installed("status");
    sc.resolves.push("*.sslip.io".into());
    let o = both("st-bypassed", &sc);
    assert!(
        o.stdout.starts_with("BYPASSED (43 of 43 loaded"),
        "{}",
        o.stdout
    );
    let mut sc = installed("status");
    sc.agent_up = false;
    assert_eq!(
        both("st-down", &sc).stdout,
        "INCOMPLETE (46 files, 43 of 43 loaded, responder down)\n"
    );
    let mut sc = installed("status");
    sc.scutil = scutil_text(&builtin()[..10]);
    assert_eq!(
        both("st-partial", &sc).stdout,
        "INCOMPLETE (46 files, 10 of 43 loaded, responder answering)\n"
    );
    // A domain's dots match any character in the script's grep, so a near miss still counts as loaded.
    let mut sc = installed("status");
    let mut names = builtin();
    names[0] = names[0].replacen('.', "X", 1);
    sc.scutil = scutil_text(&names);
    assert!(
        both("st-dot-wildcard", &sc)
            .stdout
            .starts_with("ok (43 of 43")
    );
    let mut sc = installed("status");
    sc.policy = Some(Some(br#"[1]"#.to_vec()));
    let o = both("st-bad-policy", &sc);
    assert_eq!((o.code, o.stdout.as_str()), (1, ""));
}

#[test]
fn install() {
    let mut sc = Scenario::new("install");
    sc.up_after_bootstrap = true;
    sc.old_responder = true;
    sc.plist = Plist::OldPython;
    let o = both("in-fresh", &sc);
    assert_eq!(o.code, 0);
    assert!(
        o.stdout
            .contains("dns-blocklist: responder agent answering on 127.0.0.1:10053\n")
    );
    assert!(
        o.stdout
            .contains("writing 46 files in <root>/resolver (sudo)")
    );
    assert!(o.stdout.contains("macOS hasn't read the files yet"));
    assert!(o.tree.contains(
        "<string><root>/home/.local/bin/claude-guard</string><string>dns-nxdomain</string>"
    ));
    assert!(
        !o.tree.contains("dns-nxdomain.py"),
        "old responder removed:\n{}",
        o.tree
    );
    assert_eq!(
        o.tree
            .matches(" 644 \"nameserver 127.0.0.1\\nport 10053\\n\"")
            .count(),
        46
    );

    // A foreign file stays, an old-format file is rewritten, ours no longer listed go (in glob order).
    let mut sc = installed("install");
    let mut entries = files(&all_names(), BODY);
    entries[0].1 = Entry::File(b"nameserver 1.1.1.1\n".to_vec());
    entries[1].1 = Entry::File(format!("{OLD_BODY}\n").into_bytes());
    entries[2].1 = Entry::File(b"# dns-blocklist test\nnameserver 9.9.9.9\n".to_vec());
    entries[3].1 = Entry::Dir;
    for n in [
        "zz.example",
        "a_b.example",
        "a-b.example",
        "A.example",
        "0.example",
    ] {
        entries.push((n.into(), Entry::File(format!("{BODY}\n\n").into_bytes())));
    }
    entries.push((
        ".dns-blocklist-left.example".into(),
        Entry::File(b"x".to_vec()),
    ));
    sc.resolver = Some(entries);
    let o = both("in-mixed", &sc);
    let b = builtin();
    assert!(
        o.stdout.contains(&format!(
            "  skip {}: <root>/resolver/{} exists and isn't ours\n",
            b[0], b[0]
        )),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains(&format!(
        "  skip {}: <root>/resolver/{} exists and isn't ours\n",
        b[3], b[3]
    )));
    assert!(
        !o.stdout.contains(&format!("skip {}:", b[2])),
        "a '# dns-blocklist' file is rewritten"
    );
    let removed: Vec<&str> = o
        .stdout
        .lines()
        .filter(|l| l.contains("(no longer listed)"))
        .collect();
    assert_eq!(removed.len(), 5, "{}", o.stdout);
    assert!(
        o.stdout
            .contains("Self-test: blocked. Run 'dns-blocklist check'")
    );

    let mut sc = installed("install");
    sc.scutil = scutil_text(&builtin()[..5]);
    let o = both("in-diagnose", &sc);
    assert!(o.stdout.contains("Only some loaded: testing which file format macOS accepts...\nvariant 1 (nameserver 127.0.0.1): NOT loaded\n"));
    assert!(o.stdout.ends_with("(test files removed)\n"));

    let mut sc = installed("install");
    sc.bootstrap_exit = 5;
    assert_eq!(both("in-bootstrap-fails", &sc).code, 5);

    let mut sc = Scenario::new("install");
    let o = both("in-never-up", &sc);
    assert_eq!(o.code, 1);
    assert!(o.stderr.starts_with(
        "dns-blocklist: responder agent didn't answer on 127.0.0.1:10053 (launchctl print gui/"
    ));

    sc = installed("install");
    sc.cg = Cg::NotExecutable;
    assert_eq!(both("in-no-cg", &sc).code, 1);

    let mut sc = installed("install");
    sc.dscache_exit = 4;
    assert_eq!(both("in-flush-fails", &sc).code, 4);
}

#[test]
fn check() {
    let o = both("ck-none", &Scenario::new("check"));
    assert_eq!(
        (o.code, o.stderr.as_str()),
        (
            1,
            "dns-blocklist: not installed (no files in <root>/resolver with this script's content)\n"
        )
    );
    let o = both("ck-ok", &installed("check"));
    assert_eq!(o.code, 0, "{}", o.stdout);
    assert!(o.stdout.ends_with("ok: 43 domains and their subdomains resolve nowhere, self-test blocked, Private Relay blocked; example.com still resolves\n"));

    let mut sc = installed("check");
    let mut e = files(&all_names(), BODY);
    e[5].1 = Entry::File(format!("{OLD_BODY}\n").into_bytes());
    sc.resolver = Some(e);
    let o = both("ck-old", &sc);
    assert_eq!(o.code, 1);
    assert!(o.stdout.contains("1 files still point at the old port 5"));

    let b = builtin();
    let mut sc = installed("check");
    let mut e = files(&all_names(), BODY);
    e.remove(2);
    sc.resolver = Some(e);
    sc.resolves = vec![
        "example.com".into(),
        format!("probe-*.{}", b[7]),
        "mask.icloud.com".into(),
    ];
    sc.agent_up = false;
    let o = both("ck-bad", &sc);
    assert_eq!(o.code, 1);
    assert!(o.stdout.contains(&format!("MISSING {}\n", b[2])));
    assert!(o.stdout.contains(&format!("RESOLVES probe-N.{}\n", b[7])));
    assert!(
        o.stdout
            .contains("RESOLVES mask.icloud.com (an answer cached")
    );
    assert!(o.stdout.contains("responder agent: NOT answering"));

    let mut sc = installed("check");
    sc.resolves = vec![];
    assert!(
        both("ck-offline", &sc)
            .stdout
            .contains("WARNING: example.com doesn't resolve either")
    );

    let mut sc = installed("check");
    sc.resolver = Some(files(&builtin(), BODY));
    let o = both("ck-no-extras", &sc);
    assert!(
        o.stdout
            .contains("MISSING self-test file <root>/resolver/selftest.192-0-2-1.sslip.io")
    );
    assert!(
        o.stdout
            .contains("MISSING Private Relay file <root>/resolver/mask-h2.icloud.com")
    );

    // A policy file it can't read stops check, as it stops list and status. The script carried on here with no
    // domains and could print "ok: 0 domains"; the port differs on purpose, so bash is only checked to show that.
    let mut sc = installed("check");
    sc.policy = Some(Some(b"{".to_vec()));
    let (a, b) = roots("ck-bad-policy");
    build(&a, &sc);
    build(&b, &sc);
    let mut n = Normalised::default();
    let bash = normalise(&run_bash(&a, "check"), &a, &mut n);
    assert!(
        bash.stdout.starts_with("macOS has loaded 0 of 0 domains"),
        "{}",
        bash.stdout
    );
    let port = normalise(&run_rust(&b, "check"), &b, &mut n);
    assert_eq!(
        (port.code, port.stdout.as_str(), port.stderr.as_str()),
        (1, "", "<policy error>\n")
    );
    // So does a missing claude-guard (no list at all): the script printed "0 of 0 domains" here too.
    let mut sc = installed("check");
    sc.cg = Cg::Missing;
    let (a, b) = roots("ck-no-cg");
    build(&a, &sc);
    build(&b, &sc);
    let bash = normalise(&run_bash(&a, "check"), &a, &mut n);
    assert!(
        bash.stdout.starts_with("macOS has loaded 0 of 0 domains"),
        "{}",
        bash.stdout
    );
    let port = normalise(&run_rust(&b, "check"), &b, &mut n);
    assert_eq!(
        (port.code, port.stdout.as_str(), port.stderr.as_str()),
        (
            1,
            "",
            "dns-blocklist: no block list: install claude-guard (Step 16, claude-guard)\n"
        )
    );
    // Not installed still comes first.
    let mut sc = Scenario::new("check");
    sc.policy = Some(Some(b"{".to_vec()));
    let o = both("ck-bad-policy-none", &sc);
    assert!(
        o.stderr.starts_with("dns-blocklist: not installed"),
        "{}",
        o.stderr
    );
}

#[test]
fn diagnose_remove_agent_help() {
    let mut sc = Scenario::new("diagnose");
    sc.scutil = scutil_text(&["dnsdiag-2.invalid".into(), "dnsdiag-4.invalid".into()]);
    let o = both("dg", &sc);
    assert_eq!(
        o.stdout,
        "variant 1 (nameserver 127.0.0.1): NOT loaded\nvariant 2 (nameserver 127.0.0.1;port 5): loaded\nvariant 3 (nameserver 127.0.0.1;timeout 1): NOT loaded\nvariant 4 (nameserver 127.0.0.1;port 10053): loaded\n(test files removed)\n"
    );
    let mut sc = Scenario::new("diagnose");
    sc.scutil_exit = 3;
    assert_eq!(both("dg-scutil-fails", &sc).code, 3);

    let mut sc = installed("remove");
    sc.old_responder = true;
    let o = both("rm", &sc);
    assert_eq!(o.code, 0);
    assert_eq!(
        o.stdout
            .lines()
            .filter(|l| l.starts_with("  removed "))
            .count(),
        46
    );
    assert!(
        o.stdout
            .ends_with("  responder agent stopped and removed\ndns-blocklist: removed\n")
    );
    assert!(o.tree.contains("LaunchAgents: none") || !o.tree.contains(".plist"));

    let mut sc = Scenario::new("agent");
    sc.up_after_bootstrap = true;
    sc.plist = Plist::OldPython;
    sc.old_responder = true;
    let o = both("agent", &sc);
    assert_eq!(
        o.stdout,
        "dns-blocklist: responder agent answering on 127.0.0.1:10053\n"
    );

    for (cmd, code) in [("", 0), ("help", 2), ("bogus", 2)] {
        let o = both(&format!("help-{cmd}"), &Scenario::new(cmd));
        assert_eq!(o.code, code, "{cmd:?}");
        assert!(
            o.stdout
                .starts_with("dns-blocklist: make the web guard's canary")
        );
    }
}

/// A command the port finds but can't run exits 126, as bash does ("Permission denied"); one it can't find exits 127.
/// Port only: with the system folders on PATH, bash and execvp would skip a stub that can't be run and start the
/// real /bin/launchctl, so the PATH here holds only the stub folder, and bash isn't run.
#[test]
fn refused_exec_exits_126() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for (tag, make_launchctl, want) in [("refused", true, 126), ("missing", false, 127)] {
        let root = fresh_dir(&format!("dnsbl-t-exec-{tag}"));
        build(&root, &Scenario::new("agent"));
        let stubs = format!("{root}/stubs");
        let lc = format!("{stubs}/launchctl");
        if make_launchctl {
            std::fs::set_permissions(&lc, std::fs::Permissions::from_mode(0o644)).unwrap();
        } else {
            std::fs::remove_file(&lc).unwrap();
        }
        symlink("/bin/mkdir", format!("{stubs}/mkdir")).unwrap();
        let o = std::process::Command::new(BIN)
            .args([
                "dns",
                "--resolver-dir",
                &format!("{root}/resolver"),
                "--real-home",
                &format!("{root}/realhome"),
            ])
            .args([
                "--path",
                &stubs,
                "--resolve-with",
                &format!("{stubs}/resolve"),
                "--no-sleep",
                "agent",
            ])
            .env_clear()
            .env("HOME", format!("{root}/home"))
            .env("PATH", &stubs)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.status.code(), Some(want), "[{tag}] {err}");
        assert!(
            err.starts_with("dns-blocklist: launchctl: "),
            "[{tag}] {err}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
