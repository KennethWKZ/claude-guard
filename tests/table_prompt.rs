//! Table tests for `claude-guard prompt`: guard-prompt's own cases (test_guard_prompt.sh), the allow-name log, --strict, fail-open and the JSON depth limit.
//!
//! Secrets are built at run time, so this file never contains one (secret scanners flag them). Names and IC
//! numbers are made up. The real blocked-terms file and allow-name log are never used: every run passes
//! `--terms` and `--log` under a temp folder.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_claude-guard");

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Env {
        let dir =
            std::env::temp_dir().join(format!("claude-guard-prompt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("terms.txt"),
            "# made-up customers\nZorbenta Quillfeather\nNexaprime Holdings\n\nĆwiekowska\nx\n",
        )
        .unwrap();
        Env { dir }
    }
    fn p(&self, name: &str) -> String {
        self.dir.join(name).to_str().unwrap().to_string()
    }
    fn log_lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.p("allow.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run_raw(args: &[&str], input: &[u8], cwd: &Path, envs: &[(&str, &str)]) -> (i32, String) {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(
        o.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into(),
    )
}

fn hook_input(prompt: &str) -> Vec<u8> {
    serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "test-session",
        "cwd": "/tmp/test-cwd",
        "prompt": prompt,
    })
    .to_string()
    .into_bytes()
}

fn run(e: &Env, prompt: &str) -> (i32, String) {
    run_terms(e, prompt, &e.p("terms.txt"))
}

fn run_terms(e: &Env, prompt: &str, terms: &str) -> (i32, String) {
    run_raw(
        &["prompt", "--terms", terms, "--log", &e.p("allow.log")],
        &hook_input(prompt),
        &e.dir,
        &[],
    )
}

fn rep(s: &str, n: usize) -> String {
    s.repeat(n)
}

/// want: "block:<rule>", "block:*" (any rule), "allow" or "warn". `secret`: text the output must never echo.
fn check(e: &Env, want: &str, label: &str, prompt: &str, secret: &str) -> Option<String> {
    let (rc, out) = run(e, prompt);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_default();
    let ok = rc == 0
        && match want.split_once(':') {
            Some(("block", rule)) => {
                v["decision"] == "block"
                    && (rule == "*"
                        || v["reason"]
                            .as_str()
                            .is_some_and(|r| r.contains(&format!("(rule {rule})"))))
            }
            _ if want == "allow" => out.is_empty(),
            _ => v.get("decision").is_none() && v["systemMessage"].is_string(),
        };
    let leaked = !secret.is_empty() && out.to_lowercase().contains(&secret.to_lowercase());
    (!ok || leaked).then(|| {
        format!(
            "[{label}] want={want} rc={rc} leaked={leaked}: {}",
            out.chars().take(160).collect::<String>()
        )
    })
}

fn gitleaks_installed() -> bool {
    ["/opt/homebrew/bin/gitleaks", "/usr/local/bin/gitleaks"]
        .iter()
        .any(|p| Path::new(p).exists())
}

#[test]
fn guard_prompt_cases() {
    let e = Env::new("cases");
    let aws = format!("AKIA{}", "QX3MPLW4RTZKVNAB");
    let ghp = format!("ghp_{}aB3dE5", rep("aB3dE5fG7h", 3));
    let (b, end) = ("-----BEGIN", "-----");
    let jwt = format!(
        "eyJ{}.eyJ{}.{}",
        rep("hbGciOiJI", 2),
        rep("zdWIiOiIx", 2),
        rep("SflKxwRJ", 3)
    );
    let npm = format!("npm_{}", rep("a1b2c3d4e5f6", 3));
    let mut cases: Vec<(&str, &str, String, String)> = vec![
        // must block: secrets
        ("block:aws-access-key-id", "AWS key", format!("my key is {aws} ok"), aws.clone()),
        ("block:private-key", "private key block", format!("{b} OPENSSH PRIVATE KEY{end}\nb3BlbnNzaC1rZXk\n"), String::new()),
        ("block:github-pat", "GitHub classic token", format!("use {ghp} for the api"), ghp.clone()),
        ("block:github-pat", "GitHub fine-grained token", format!("github_pat_{}ab", rep("11ABCDEFG0", 8)), String::new()),
        ("block:atlassian-api-token", "Atlassian token", format!("ATATT3xFfGF0{}", rep("Zq9_xY2-wV", 12)), String::new()),
        ("block:bitbucket-app-password", "Bitbucket app password", format!("ATBB{}", rep("kP3mN8qR", 4)), String::new()),
        ("block:slack-token", "Slack bot token", format!("xoxb-{}-abcdefABCDEF", rep("1234567890", 2)), String::new()),
        ("block:slack-webhook-url", "Slack webhook", format!("post to https://hooks.slack.com/services/T0ABCDEFG/B0ABCDEFG/{}", rep("aBc1", 6)), String::new()),
        ("block:stripe-secret-key", "Stripe live key", format!("sk_live_{}", "4eC39HqLyjWDarjtT1zdp7dc"), String::new()),
        ("block:gcp-api-key", "Google API key", format!("AIza{}abcdefgh", rep("SyD3x8kLm", 3)), String::new()),
        ("block:jwt", "JWT", format!("Authorization: Bearer {jwt}"), String::new()),
        ("block:secret-assignment", ".env password", "DB_PASSWORD=Xk29pq0zA!".into(), "Xk29pq0zA!".into()),
        ("block:secret-assignment", "JSON password", r#"{"user":"ops","password":"hunter2hunter"}"#.into(), "hunter2hunter".into()),
        ("block:secret-assignment", "aws secret key", format!("aws_secret_access_key = {}", rep("wJalrXUtnFEMIK7MDENG", 2)), String::new()),
        ("block:secret-assignment", "quoted api key", format!("API_KEY='abc123{}'", "def456ghi"), String::new()),
        // names warn, the prompt goes through
        ("warn", "name, any case", "check the transfer for ZORBENTA QUILLFEATHER today".into(), "Zorbenta".into()),
        ("warn", "name across a line break", "client is Nexaprime\nHoldings, see the deck".into(), "Nexaprime".into()),
        ("warn", "name at end with punctuation", "is this nexaprime holdings.".into(), "nexaprime".into()),
        ("warn", "non-ASCII name", "zapytaj ćwiekowska o to".into(), "ćwiekowska".into()),
        // must block: IC numbers
        ("block:malaysian-ic", "IC with dashes", "customer IC 900115-10-5821 needs a check".into(), "900115-10-5821".into()),
        ("block:malaysian-ic", "IC without dashes", "ic=900115105821".into(), String::new()),
        ("block:malaysian-ic", "IC, foreign-born code", "041231-71-0007".into(), String::new()),
        ("block:malaysian-ic", "IC, 29 Feb", "000229-14-1234".into(), String::new()),
        // must allow
        ("allow", "plain prose", "reset my password please, the API key rotation is done".into(), String::new()),
        ("allow", "order id, place code 00", "order 241124000123 is stuck".into(), String::new()),
        ("allow", "order id with prefix", "Order ORD-20261124-000123 failed at 10:31".into(), String::new()),
        ("allow", "order id, bad day", "refund 250631120045 now".into(), String::new()),
        ("allow", "phone numbers", "call +60 12-345 6789 or 0123456789 or 60123456789".into(), String::new()),
        ("allow", "date", "deploy on 2026-11-24 at 09:00".into(), String::new()),
        ("allow", "IC month 13", "901315-10-5821".into(), String::new()),
        ("allow", "IC 30 Feb", "900230-10-5821".into(), String::new()),
        ("allow", "IC place code 00", "900115-00-5821".into(), String::new()),
        ("allow", "IC place code 70", "900115-70-5821".into(), String::new()),
        ("allow", "IC too long", "900115-10-58211".into(), String::new()),
        ("allow", "IC mixed dashes", "900115-105821".into(), String::new()),
        ("allow", "code reading a password", r#"const password = req.body.password; $pw = request.input("password");"#.into(), String::new()),
        ("allow", "env reference", "DB_PASSWORD=${DB_PASSWORD} and secret: ${{ secrets.DEPLOY_KEY }}".into(), String::new()),
        ("allow", "secret name, not value", r#"aws secretsmanager get-secret-value --secret-id prod/mmt/db; SecretId=prod/mmt/db; secret_name = "prod/db-creds""#.into(), String::new()),
        ("allow", "path value", "DB_PASSWORD=/run/secrets/db_password".into(), String::new()),
        ("allow", "placeholder value", "password=your_password and API_KEY=changeme".into(), String::new()),
        ("allow", "password hash column", r#"password_hash = "$2y$10$abcdefghijABCDEFGHIJ12""#.into(), String::new()),
        ("allow", "UUID and git sha", "session d7a49f29-d893-4da3-b2ab-965a491df512 at commit 021b3249c1e5d3a7f0b2c4e6a8d0f1e3b5c7d9e0".into(), String::new()),
        ("allow", "long kebab file name", "edit session-name-from-title.sh and macbook-setup-runbook.md".into(), String::new()),
        ("allow", "partial word of a name", "zorbentas and nexaprimeholdings are fine".into(), String::new()),
        ("allow", "short term line ignored", "x marks the spot".into(), String::new()),
        ("allow", "empty prompt", String::new(), String::new()),
        // Unicode boundaries, as Python's str patterns read them
        ("block:malaysian-ic", "IC after a letter", "IC900115-10-5821".into(), String::new()),
        ("allow", "IC after a digit", "1900115-10-5821".into(), String::new()),
        ("block:malaysian-ic", "IC with Arabic-Indic date digits", "٩٠٠١١٥-10-5821".into(), String::new()),
        ("allow", "IC with an Arabic-Indic place code", "900115-١٠-5821".into(), String::new()),
        ("allow", "name inside a non-ASCII word", "éZorbenta Quillfeather".into(), String::new()),
        ("warn", "name after a combining mark", "\u{301}Zorbenta Quillfeather".into(), "Zorbenta".into()),
        ("block:github-pat", "GitHub token after a combining mark", format!("\u{301}{ghp}"), ghp.clone()),
        // IGNORECASE as Python reads it: İ and ı match i, ſ matches s, K (Kelvin) matches k
        ("block:secret-assignment", "dotted capital I in a key name", "apİ_key=Xk29pq0zA!".into(), "Xk29pq0zA!".into()),
        ("block:secret-assignment", "dotless i in a key name", "clıent_secret: Xk29pq0zA!".into(), String::new()),
        ("block:secret-assignment", "dotted I before the key counts as a letter", "İapi_key=Xk29pq0zA!".into(), String::new()),
        ("allow", "placeholder with a dotted I", "password=undefİned".into(), String::new()),
        ("warn", "name with a dotted I", "Zorbenta Quİllfeather".into(), "Zorbenta".into()),
        // `\b` after a key that ends in `-` needs a word character next
        ("block:gcp-api-key", "Google key ending in - before a letter", format!("AIza{}abcdefg-x", rep("SyD3x8kLm", 3)), String::new()),
        ("warn", "name with a dotless i", "ZORBENTA QUıLLFEATHER".into(), "Zorbenta".into()),
        ("warn", "name with a combining mark after it is still a whole word", "Zorbenta Quillfeather\u{301}".into(), "Zorbenta".into()),
    ];
    if gitleaks_installed() {
        cases.push((
            "block:*",
            "gitleaks-only rule (npm token)",
            format!("npm config set //registry.npmjs.org/:_authToken {npm}"),
            String::new(),
        ));
        // Inside a word the built-in rule doesn't match (no \b); gitleaks' own rule does.
        cases.push((
            "block:github-pat",
            "GitHub token inside a word",
            format!("x{ghp}"),
            ghp.clone(),
        ));
    }
    let fails: Vec<String> = cases
        .iter()
        .filter_map(|(want, label, prompt, secret)| check(&e, want, label, prompt, secret))
        .collect();
    assert!(
        fails.is_empty(),
        "{} of {} failed:\n{}",
        fails.len(),
        cases.len(),
        fails.join("\n")
    );
    // A missing terms file is no terms.
    assert_eq!(
        run_terms(&e, "Zorbenta Quillfeather", &e.p("missing.txt")),
        (0, String::new())
    );
}

#[test]
fn name_notice_and_log() {
    let e = Env::new("log");
    let aws = format!("AKIA{}", "QX3MPLW4RTZKVNAB");
    let (_, out) = run(&e, "Nexaprime Holdings payout");
    assert_eq!(
        out,
        "{\"systemMessage\": \"guard-prompt: this prompt has a name on your blocked list. It was sent to Claude (logged); GraphMind skips it.\"}\n"
    );
    let (_, out) = run(&e, "Nexaprime Holdings payout");
    assert!(out.contains("blocked list"));
    let (_, out) = run(
        &e,
        "[allow-name] payout for Zorbenta Quillfeather failed twice",
    );
    assert_eq!(
        out,
        "{\"systemMessage\": \"guard-prompt: [allow-name] let a blocked name through for this prompt (logged).\"}\n"
    );
    let lines = e.log_lines();
    assert_eq!(lines.len(), 3, "{lines:?}");
    let markers: Vec<bool> = lines
        .iter()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["session_id"], "test-session");
            assert_eq!(v["cwd"], "/tmp/test-cwd");
            assert_eq!(v["rule"], "blocked-term");
            assert!(
                !l.to_lowercase().contains("zorbenta") && !l.to_lowercase().contains("nexaprime")
            );
            v["marker"].as_bool().unwrap()
        })
        .collect();
    assert_eq!(markers, [false, false, true]);
    // Python's json.dumps layout, local time with its offset.
    assert!(
        lines[0].starts_with("{\"time\": \"20")
            && lines[0].contains(", \"session_id\": \"test-session\", \"cwd\": ")
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(e.p("allow.log"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    // No name, no line; a prompt blocked for an IC number or a secret logs nothing either.
    assert_eq!(run(&e, "[allow-name] just checking"), (0, String::new()));
    assert!(
        run(&e, "[allow-name] Zorbenta Quillfeather IC 900115-10-5821")
            .1
            .contains("malaysian-ic")
    );
    assert!(
        run(&e, &format!("Zorbenta Quillfeather key {aws}"))
            .1
            .contains("aws-access-key-id")
    );
    assert_eq!(e.log_lines().len(), 3);
    // The log's folder is created 0700 when missing.
    let nested = e.p("state/sub/allow.log");
    run_raw(
        &["prompt", "--terms", &e.p("terms.txt"), "--log", &nested],
        &hook_input("Nexaprime Holdings"),
        &e.dir,
        &[],
    );
    let dmode = std::fs::metadata(e.p("state/sub"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dmode, 0o700);
}

#[test]
fn strict() {
    let e = Env::new("strict");
    let strict = |input: serde_json::Value| {
        run_raw(
            &[
                "prompt",
                "--strict",
                "--terms",
                &e.p("terms.txt"),
                "--log",
                &e.p("allow.log"),
            ],
            input.to_string().as_bytes(),
            &e.dir,
            &[],
        )
    };
    let (_, out) = strict(
        serde_json::json!({"prompt": "[allow-name] payout for Zorbenta Quillfeather", "session_id": "strict"}),
    );
    assert_eq!(
        out,
        "{\"decision\": \"block\", \"reason\": \"Blocked: looks like a name on your blocked list (rule blocked-term). Remove it and send again.\"}\n"
    );
    let (_, out) = strict(serde_json::json!({"prompt": "payout for Nexaprime Holdings"}));
    assert!(out.contains("\"block\"") && !out.to_lowercase().contains("nexaprime"));
    assert_eq!(
        strict(serde_json::json!({"prompt": "how does the deploy pipeline work"})),
        (0, String::new())
    );
    assert!(e.log_lines().is_empty(), "--strict never logs");
    // Options in any order; parsing stops at an unknown argument, as Python's did.
    let (_, out) = run_raw(
        &[
            "prompt",
            "--terms",
            &e.p("terms.txt"),
            "--strict",
            "--log",
            &e.p("allow.log"),
        ],
        &hook_input("Nexaprime Holdings"),
        &e.dir,
        &[],
    );
    assert!(out.contains("\"block\""));
    let (_, out) = run_raw(
        &[
            "prompt",
            "--terms",
            &e.p("terms.txt"),
            "--log",
            &e.p("allow.log"),
            "--bogus",
            "--strict",
        ],
        &hook_input("Nexaprime Holdings"),
        &e.dir,
        &[],
    );
    assert!(
        out.contains("systemMessage"),
        "--strict after an unknown argument is ignored: {out}"
    );
}

#[test]
fn fails_open() {
    let e = Env::new("open");
    let args = [
        "prompt",
        "--terms",
        &e.p("terms.txt"),
        "--log",
        &e.p("allow.log"),
    ];
    let failed = |name: &str| {
        format!(
            "{{\"systemMessage\": \"guard-prompt.py failed ({name}); prompt allowed unchecked.\"}}\n"
        )
    };
    assert_eq!(
        run_raw(&args, b"not json", &e.dir, &[]),
        (0, failed("JSONDecodeError"))
    );
    assert_eq!(
        run_raw(&args, b"", &e.dir, &[]),
        (0, failed("JSONDecodeError"))
    );
    assert_eq!(
        run_raw(&args, b"{\"prompt\": \"\xff\"}", &e.dir, &[]),
        (0, failed("UnicodeDecodeError"))
    );
    // Not an object, or no text prompt: nothing to check.
    for input in [
        "[]",
        "5",
        "{}",
        "{\"prompt\": 5}",
        "{\"prompt\": null}",
        "{\"prompt\": [\"x\"]}",
    ] {
        assert_eq!(
            run_raw(&args, input.as_bytes(), &e.dir, &[]),
            (0, String::new()),
            "{input}"
        );
    }
    // A terms path that can't be read (a folder) is an error, so the prompt goes through with the warning.
    let (_, out) = run_terms(&e, "hello", &e.dir.to_string_lossy());
    assert_eq!(out, failed("IsADirectoryError"));
    // Python accepted lone surrogates and NaN.
    let (_, out) = run_raw(
        &args,
        b"{\"prompt\": \"IC 900115-10-5821 \\ud800\", \"n\": NaN}",
        &e.dir,
        &[],
    );
    assert!(out.contains("malaysian-ic"), "{out}");
}

#[test]
fn json_depth_matches_python() {
    let e = Env::new("depth");
    let args = [
        "prompt",
        "--terms",
        &e.p("terms.txt"),
        "--log",
        &e.p("allow.log"),
    ];
    // `levels` counts the outer object: Python's json.load reads 993 levels and raises RecursionError at 994.
    let nested = |levels: usize, open: &str, close: &str| {
        format!(
            "{{\"prompt\": \"IC 900115-10-5821\", \"a\": {}1{}}}",
            open.repeat(levels - 1),
            close.repeat(levels - 1)
        )
    };
    for (open, close) in [("[", "]"), ("{\"k\": ", "}")] {
        let (_, out) = run_raw(&args, nested(993, open, close).as_bytes(), &e.dir, &[]);
        assert!(
            out.contains("malaysian-ic"),
            "993 levels are checked: {out}"
        );
        let (_, out) = run_raw(&args, nested(994, open, close).as_bytes(), &e.dir, &[]);
        assert!(out.contains("failed (RecursionError)"), "994 levels: {out}");
    }
    // A syntax error before the too-deep part is bad JSON, as Python reads left to right.
    let bad = format!(
        "{{\"prompt\": x, \"a\": {}{}}}",
        "[".repeat(2000),
        "]".repeat(2000)
    );
    let (_, out) = run_raw(&args, bad.as_bytes(), &e.dir, &[]);
    assert!(out.contains("failed (JSONDecodeError)"), "{out}");
}

#[test]
fn repo_config_cannot_allowlist() {
    if !gitleaks_installed() {
        return;
    }
    let e = Env::new("tamper");
    let npm = format!("npm_{}", rep("a1b2c3d4e5f6", 3));
    let repo = e.dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join(".gitleaks.toml"),
        "[allowlist]\nregexes = [\".*\"]\npaths = [\".*\"]\n",
    )
    .unwrap();
    std::fs::write(repo.join(".gitleaksignore"), format!("{npm}\n")).unwrap();
    let cfg = repo.join(".gitleaks.toml");
    let (_, out) = run_raw(
        &[
            "prompt",
            "--terms",
            &e.p("terms.txt"),
            "--log",
            &e.p("allow.log"),
        ],
        &hook_input(&format!("token {npm}")),
        &repo,
        &[("GITLEAKS_CONFIG", cfg.to_str().unwrap())],
    );
    assert!(out.contains("\"block\""), "{out}");
}

#[test]
fn shadow_never_blocks() {
    let e = Env::new("shadow");
    let log = e.p("shadow.log");
    let missing = e.p("missing.py");
    for p in ["IC 900115-10-5821", "hello"] {
        let (rc, out) = run_raw(
            &[
                "prompt",
                "--shadow",
                "--reference",
                &missing,
                "--terms",
                &e.p("terms.txt"),
                "--log",
                &log,
            ],
            &hook_input(p),
            &e.dir,
            &[],
        );
        assert_eq!((rc, out.as_str()), (0, ""), "{p}");
    }
    let mut text = String::new();
    for _ in 0..200 {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.lines().count() >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(text.contains("\"rust\": \"block:malaysian-ic\""));
    assert!(!text.contains("900115"), "the log must not hold the prompt");
    assert!(
        e.log_lines().is_empty(),
        "shadow never writes the allow-name log"
    );
}
