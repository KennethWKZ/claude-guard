//! Differential test: `claude-guard prompt` against guard-prompt.py on generated prompts and hook inputs.
//! stdout must match byte for byte, and the allow-name log lines (time left out) must match as a set.
//! Reference: guard-prompt.py (default ~/.claude/hooks/guard-prompt.py) (the source the live hook and the team
//! runbook copy are made from). Names come from a made-up terms file; the real blocked-terms file is never read.
//! Env (test only): CLAUDE_GUARD_REF_PROMPT, CLAUDE_GUARD_DIFF_CASES (default 3000), CLAUDE_GUARD_DIFF_SEED,
//! CLAUDE_GUARD_DIFF_WORKERS (default 2; pass "$(test-workers)").

mod common;
use common::*;
use serde_json::{Value, json};
use std::process::{Command, Stdio};

/// Made-up names, with the shapes the parser has to handle: several words, extra spaces, regex characters,
/// non-ASCII, case folding (ſ, ß, K), CR and CRLF line ends, splitlines-only breaks (\x1c, \u2028), comments,
/// one-character lines and blank lines.
const TERMS: &str = "# made-up customers\nZorbenta Quillfeather\r\nNexaprime Holdings\rĆwiekowska\nx\n\n  Spaced   Trellow  \nA.B Corp\nC++ Labs\n(Paren) Vantor\nÖlund\tTrading\nſtarvale\nGroßmark\nKelvaro\n_under_core\n42 Capital\nVexa\u{1c}Torvin\nMirelle\u{2028}Dunhaven\n";

fn secrets() -> Vec<String> {
    let r = |s: &str, n: usize| s.repeat(n);
    vec![
        format!("AKIA{}", "QX3MPLW4RTZKVNAB"),
        format!("ASIA{}", "QX3MPLW4RTZKVNA7"),
        format!("A3TX{}", "QX3MPLW4RTZKVNAB"),
        format!("AKIA{}", "QX3MPLW4RTZKVNA"), // one short
        format!("{} RSA PRIVATE KEY{}", "-----BEGIN", "-----"),
        format!("{} PGP PRIVATE KEY BLOCK{}", "-----BEGIN", "-----"),
        format!("{} private key{}", "-----BEGIN", "-----"),
        format!("ghp_{}aB3dE5", r("aB3dE5fG7h", 3)),
        format!("gho_{}aB3dE", r("aB3dE5fG7h", 3)), // one short
        format!("ghp_{}aB3dE5x", r("aB3dE5fG7h", 3)), // one long
        format!("github_pat_{}ab", r("11ABCDEFG0", 8)),
        format!("ATATT3xFfGF0{}", r("Zq9_xY2-wV", 12)),
        format!("ATATT3{}", r("Zq9_xY2-wV", 9)),
        format!("ATBB{}", r("kP3mN8qR", 4)),
        format!("ATBB{}", r("kP3.N8-R", 3)),
        format!("xoxb-{}-abcdefABCDEF", r("1234567890", 2)),
        format!("xoxq-{}", r("1234567890", 2)),
        format!(
            "hooks.slack.com/services/T0ABCDEFG/B0ABCDEFG/{}",
            r("aBc1", 6)
        ),
        format!("hooks.slack.com/triggers/{}", r("aB/c", 4)),
        format!("sk_live_{}", "4eC39HqLyjWDarjtT1zdp7dc"),
        format!("rk_live_{}", "4eC39HqLyjWDarjt"),
        format!("AIza{}abcdefgh", r("SyD3x8kLm", 3)),
        format!("AIza{}abcdefg", r("SyD3x8kLm", 3)),
        format!(
            "eyJ{}.eyJ{}.{}",
            r("hbGciOiJI", 2),
            r("zdWIiOiIx", 2),
            r("SflKxwRJ", 3)
        ),
        format!(
            "eyJ{}.eyJ{}.{}",
            r("hbGci", 1),
            r("zdWIiOiIx", 2),
            r("SflKxwRJ", 3)
        ),
        format!("npm_{}", r("a1b2c3d4e5f6", 3)),
        format!("glpat-{}", "a1B2c3D4e5F6g7H8i9J0"),
        "commit 021b3249c1e5d3a7f0b2c4e6a8d0f1e3b5c7d9e0".into(),
        "d7a49f29-d893-4da3-b2ab-965a491df512".into(),
        "session-name-from-title-and-macbook-setup".into(),
    ]
}

const KEYS: &[&str] = &[
    "password",
    "PASSWORD",
    "Passwd",
    "secret",
    "SECRET_KEY",
    "secret-key",
    "api_key",
    "API-KEY",
    "apikey",
    "access_key",
    "auth_token",
    "AUTHTOKEN",
    "access-token",
    "client_secret",
    "private_key",
    "DB_PASSWORD",
    "aws_secret_access_key",
    "x.password",
    "mysecret",
    "paſsword",
    "pass_word",
    "token",
    "my-api-key",
    "apİ_key",
    "clıent_secret",
    "İapi_key",
    "PRİVATE_KEY",
    "\u{212a}api_key",
];
const SEPS: &[&str] = &[
    "=",
    ": ",
    " = ",
    ":",
    "\t=\t",
    "\u{a0}=\u{a0}",
    "\u{1c}=",
    "\"=",
    "'= ",
    " := ",
    "=\n",
];
const VALUES: &[&str] = &[
    "Xk29pq0zA!",
    "hunter2hunter",
    "\"hunter2hunter\"",
    "'abc123def456'",
    "\"abc 123def\"",
    "changeme",
    "your_password",
    "YOUR-KEY-HERE",
    "${DB_PASSWORD}",
    "<secret>",
    "/run/secrets/db",
    "./x/y",
    "~/.key",
    "***hidden",
    "xxxsecret1",
    "...",
    "env(\"X\")",
    "process.env.X",
    "getenv('X')",
    "Test_pass1",
    "dummy123",
    "sample-key",
    "abcdefgh",
    "abcdefg1",
    "1234567890",
    "ab1",
    "\"Ünïcødé12\"",
    "abcdefgh1€",
    "null",
    "None",
    "%(x)s",
    "aaaaaaaa+",
    "--------",
    "=========a",
    "undefİned",
    "dummİ123",
    "\"İİİİİİİİ1\"",
];
const SPACES: &[&str] = &[
    " ", "  ", "\t", "\n", "\u{a0}", "\u{2003}", "\u{1c}", "\u{3000}", "\r\n", "\u{85}",
];
const EDGES: &[&str] = &[
    "", "", "", " ", "x", "X", "1", "_", "-", ".", "é", "\u{301}", "\u{93e}", "٣", "Ⅻ", "²", "/",
    "\"", "(", "‿", "\u{200d}", "ß", "K",
];
const FILLER: &[&str] = &[
    "please check why the payout is stuck",
    "order 241124000123 failed",
    "call +60 12-345 6789",
    "deploy on 2026-11-24 at 09:00",
    "const password = req.body.password;",
    "see the deck",
    "",
    "Order ORD-20261124-000123",
    "refund 250631120045 now",
    "aws secretsmanager get-secret-value",
];
const DIGITS: &[&str] = &[
    "0123456789",
    "٠١٢٣٤٥٦٧٨٩",
    "０１２３４５６７８９",
    "०१२३४५६७८९",
];

fn ic(rng: &mut Rng) -> String {
    let d = |rng: &mut Rng| char::from(b'0' + rng.below(10) as u8);
    let yy: String = (0..2).map(|_| d(rng)).collect();
    let mm = if rng.chance(80) {
        format!("{:02}", 1 + rng.below(12))
    } else {
        format!("{:02}", rng.below(20))
    };
    let dd = if rng.chance(80) {
        format!("{:02}", 1 + rng.below(29))
    } else {
        format!("{:02}", rng.below(40))
    };
    let pb = if rng.chance(60) {
        rng.pick(&[
            "01", "14", "16", "21", "59", "68", "71", "72", "74", "79", "82", "93", "98", "99",
        ])
        .to_string()
    } else {
        format!("{:02}", rng.below(100))
    };
    let g: String = (0..4).map(|_| d(rng)).collect();
    let (a, b) = match rng.below(5) {
        0 | 1 => ("-", "-"),
        2 => ("", ""),
        3 => ("-", ""),
        _ => ("", "-"),
    };
    let mut s = format!("{yy}{mm}{dd}{a}{pb}{b}{g}");
    if rng.chance(15) {
        // the same number in other decimal digits, all or one part
        let set: Vec<char> = rng.pick(DIGITS).chars().collect();
        let part = rng.below(3);
        s = s
            .char_indices()
            .map(|(i, c)| match c.to_digit(10) {
                Some(v)
                    if part == 0 || (part == 1 && i < 6) || (part == 2 && (7..9).contains(&i)) =>
                {
                    set[v as usize]
                }
                _ => c,
            })
            .collect();
    }
    if rng.chance(10) {
        s.pop(); // too short
    }
    if rng.chance(10) {
        s.push(d(rng)); // too long
    }
    s
}

fn case_mix(rng: &mut Rng, s: &str) -> String {
    match rng.below(6) {
        0 => s.to_uppercase(),
        1 => s.to_lowercase(),
        2 => s
            .chars()
            .map(|c| {
                if rng.chance(50) {
                    c.to_uppercase().collect::<String>()
                } else {
                    c.to_lowercase().collect()
                }
            })
            .collect(),
        3 => s
            .chars()
            .map(|c| match c {
                'i' | 'I' if rng.chance(50) => {
                    if rng.chance(50) {
                        'İ'
                    } else {
                        'ı'
                    }
                }
                's' | 'S' if rng.chance(30) => 'ſ',
                'k' | 'K' if rng.chance(50) => '\u{212a}',
                c => c,
            })
            .collect(),
        _ => s.to_string(),
    }
}

fn name(rng: &mut Rng) -> String {
    let terms = [
        "Zorbenta Quillfeather",
        "Nexaprime Holdings",
        "Ćwiekowska",
        "Spaced Trellow",
        "A.B Corp",
        "C++ Labs",
        "(Paren) Vantor",
        "Ölund Trading",
        "starvale",
        "ſtarvale",
        "Großmark",
        "GROSSMARK",
        "großmark",
        "Kelvaro",
        "\u{212a}elvaro",
        "_under_core",
        "42 Capital",
        "Vexa",
        "Torvin",
        "Vexa Torvin",
        "Mirelle",
        "Dunhaven",
        "Zorbenta",
        "AxB Corp",
        "x",
        "Quillfeather Zorbenta",
    ];
    let picked = *rng.pick(&terms);
    let t = case_mix(rng, picked);
    let ws = rng.pick(SPACES).to_string();
    let t = if rng.chance(40) {
        t.replace(' ', &ws)
    } else {
        t
    };
    format!("{}{t}{}", rng.pick(EDGES), rng.pick(EDGES))
}

fn fragment(rng: &mut Rng, secrets: &[String]) -> String {
    match rng.below(9) {
        0 | 1 => {
            let s = rng.pick(secrets).clone();
            let s = if rng.chance(10) {
                s[..s.len() * 3 / 4].to_string()
            } else {
                s
            };
            format!("{}{s}{}", rng.pick(EDGES), rng.pick(EDGES))
        }
        2 | 3 => {
            let lead = if rng.chance(30) {
                rng.pick(EDGES).to_string()
            } else {
                String::new()
            };
            let v = rng.pick(VALUES).to_string();
            let v = if rng.chance(5) {
                "a1".repeat(100 + rng.below(3))
            } else {
                v
            };
            let mut s = format!("{lead}{}{}{v}", rng.pick(KEYS), rng.pick(SEPS));
            if rng.chance(25) {
                // finditer goes on past a placeholder to a later literal
                s = format!(
                    "{s} {}{}{}",
                    rng.pick(KEYS),
                    rng.pick(SEPS),
                    rng.pick(VALUES)
                );
            }
            s
        }
        4 | 5 => format!("{}{}{}", rng.pick(EDGES), ic(rng), rng.pick(EDGES)),
        6 | 7 => name(rng),
        _ => rng.pick(FILLER).to_string(),
    }
}

fn prompt(rng: &mut Rng, secrets: &[String]) -> String {
    let n = 1 + rng.below(4);
    let mut out = String::new();
    if rng.chance(20) {
        out.push_str(rng.pick(&[
            "[allow-name] ",
            "[allow-name]",
            " [allow-name] ",
            "[ALLOW-NAME] ",
        ]));
    }
    for i in 0..n {
        if i > 0 {
            out.push_str(rng.pick(SPACES));
        }
        out.push_str(&fragment(rng, secrets));
    }
    out
}

/// A hook input around `prompt`, sometimes with odd field types, and the hook arguments.
fn hook_input(rng: &mut Rng, i: usize, prompt: &str) -> (String, bool) {
    let sid: Value = match rng.below(12) {
        0 => Value::Null,
        1 => json!(i),
        2 => json!(true),
        3 => json!(""),
        _ => json!(format!("diff-{i}")),
    };
    let cwd: Value = match rng.below(12) {
        0 => Value::Null,
        1 => json!(0),
        2 => json!(format!("/tmp/é \"quoted\" {i}")),
        _ => json!(format!("/tmp/diff-{i}")),
    };
    let strict = rng.chance(15);
    let mut obj = json!({"hook_event_name": "UserPromptSubmit", "session_id": sid, "cwd": cwd, "prompt": prompt});
    if rng.chance(5) {
        obj.as_object_mut().unwrap().remove("session_id");
    }
    (obj.to_string(), strict)
}

/// Inputs that aren't a generated prompt: shapes, bad JSON, depth, surrogates.
fn edge_inputs() -> Vec<(String, bool)> {
    let deep = |levels: usize, open: &str, close: &str, p: &str| {
        format!(
            "{{\"prompt\": {}, \"a\": {}1{}}}",
            json!(p),
            open.repeat(levels - 1),
            close.repeat(levels - 1)
        )
    };
    let mut v: Vec<String> = [
        "",
        "not json",
        "[]",
        "5",
        "null",
        "\"prompt\"",
        "{}",
        "{\"prompt\": null}",
        "{\"prompt\": 5}",
        "{\"prompt\": [\"IC 900115-10-5821\"]}",
        "{\"prompt\": {\"a\": 1}}",
        "{\"prompt\": \"\"}",
        "{\"prompt\": true}",
        "{\"prompt\": \"IC 900115-10-5821\"} x",
        "{\"prompt\": \"IC 900115-10-5821\"}\n\n",
        "  {\"prompt\": \"Nexaprime Holdings\", \"session_id\": \"s\"}  ",
        "{\"prompt\": \"a\\u0000b Zorbenta Quillfeather\"}",
        "{\"prompt\": \"IC 900115-10-5821 \\ud800\"}",
        "{\"prompt\": \"Nexaprime Holdings\", \"n\": NaN}",
        "{\"prompt\": \"Nexaprime Holdings\", \"n\": -Infinity}",
        "{\"prompt\": \"\\udc00\\ud800Zorbenta Quillfeather\"}",
        "{\"prompt\": \"Nexaprime Holdings\", \"prompt\": \"hello\"}",
        "{\"prompt\": \"hello\", \"prompt\": \"Nexaprime Holdings\"}",
        "\u{feff}{\"prompt\": \"Nexaprime Holdings\"}",
        "{\"prompt\": \"x\", }",
        "{'prompt': 'x'}",
        "{\"prompt\": \"Nexaprime Holdings\", \"session_id\": 1.5}",
        "{\"prompt\": \"Nexaprime Holdings\", \"session_id\": 1e400}",
        "{\"prompt\": \"Nexaprime Holdings\", \"session_id\": 10000000000000000000000}",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for (open, close) in [("[", "]"), ("{\"k\": ", "}")] {
        for levels in [128, 129, 500, 992, 993, 994, 995, 3000] {
            v.push(deep(levels, open, close, "IC 900115-10-5821"));
            v.push(deep(levels, open, close, "Nexaprime Holdings"));
        }
    }
    v.push(format!(
        "{{\"prompt\": x, \"a\": {}{}}}",
        "[".repeat(2000),
        "]".repeat(2000)
    ));
    v.push(format!(
        "{{\"a\": {}{}, \"prompt\": \"hi\"}}",
        "[".repeat(2000),
        "]".repeat(1990)
    ));
    v.into_iter()
        .flat_map(|s| [(s.clone(), false), (s, true)])
        .collect()
}

/// A log line without its time, for comparing two logs written at different moments.
fn untimed(line: &str) -> String {
    match line.find(", \"session_id\"") {
        Some(i) if line.starts_with("{\"time\": ") => line[i..].to_string(),
        _ => line.to_string(),
    }
}

#[test]
fn differential_prompt() {
    let reference = env_or(
        "CLAUDE_GUARD_REF_PROMPT",
        &format!("{}/.claude/hooks/guard-prompt.py", home()),
    );
    if !std::path::Path::new(&reference).exists() {
        eprintln!("differential prompt: skipped, no reference at {reference}");
        return;
    }
    let n: usize = env_or("CLAUDE_GUARD_DIFF_CASES", "3000").parse().unwrap();
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261124")
        .parse()
        .unwrap();
    let workers: usize = env_or("CLAUDE_GUARD_DIFF_WORKERS", "2").parse().unwrap();
    let d = fresh_dir("prompt-diff");
    let terms = format!("{d}/terms.txt");
    std::fs::write(&terms, TERMS).unwrap();
    let (py_log, rust_log) = (format!("{d}/py-allow.log"), format!("{d}/rust-allow.log"));

    let mut rng = Rng(seed | 1);
    let secrets = secrets();
    let mut inputs = edge_inputs();
    for i in 0..n {
        let p = prompt(&mut rng, &secrets);
        inputs.push(hook_input(&mut rng, i, &p));
    }
    let args = |strict: bool, log: &str| {
        let mut a = vec![
            "--terms".to_string(),
            terms.clone(),
            "--log".into(),
            log.to_string(),
        ];
        if strict {
            a.insert(0, "--strict".into());
        }
        a
    };

    let driver = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference_driver.py");
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", driver, "prompt", &reference])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        let feed: String = inputs
            .iter()
            .map(|(i, strict)| {
                json!({"input": i, "args": args(*strict, &py_log)}).to_string() + "\n"
            })
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
    let rust: Vec<Out> = parallel(&inputs, workers, |_, (i, strict)| {
        let a = args(*strict, &rust_log);
        let mut cmd = vec![BIN, "prompt"];
        cmd.extend(a.iter().map(String::as_str));
        run(&cmd, i)
    });

    // Spot check the driver against real runs (log to /dev/null: the driver's log is compared below), the
    // depth cases included, since the driver calls main() from a different stack.
    let mut spot: Vec<usize> = (0..inputs.len())
        .step_by((inputs.len() / 60).max(1))
        .collect();
    spot.extend(
        (0..inputs.len())
            .filter(|&i| inputs[i].0.len() > 1900 && inputs[i].0.starts_with("{\"prompt\": ")),
    );
    let real: Vec<Out> = parallel(&spot, workers, |_, &i| {
        let a = args(inputs[i].1, "/dev/null");
        let mut cmd = vec!["/usr/bin/python3", "-I", reference.as_str()];
        cmd.extend(a.iter().map(String::as_str));
        run(&cmd, &inputs[i].0)
    });
    for (k, &i) in spot.iter().enumerate() {
        assert_eq!(
            real[k].stdout,
            py[i]["stdout"].as_str().unwrap(),
            "driver vs real on {}",
            inputs[i].0.chars().take(300).collect::<String>()
        );
    }

    let (mut same, mut bad) = (0, Vec::new());
    let mut known = std::collections::BTreeMap::<&str, usize>::new();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for i in 0..inputs.len() {
        let p = py[i]["stdout"].as_str().unwrap_or("");
        let r = &rust[i];
        *counts.entry(claude_guard_rule(p)).or_default() += 1;
        let gitleaks_block = |o: &str| {
            o.starts_with(
                "{\"decision\": \"block\", \"reason\": \"Blocked: looks like a secret (rule ",
            )
        };
        if r.code == 0 && r.stdout == p && r.stderr.is_empty() {
            same += 1;
        } else if r.code == 0 && gitleaks_block(p) && gitleaks_block(&r.stdout) {
            // gitleaks lists several findings in a different order from run to run, and both hooks name the
            // first one: same verdict, sometimes another rule name.
            *known.entry("gitleaks-finding-order").or_default() += 1;
        } else {
            bad.push(format!(
                "input (strict={}): {}\n  python: {p:?}\n  rust:   {} {:?} {:?}",
                inputs[i].1,
                inputs[i].0.chars().take(400).collect::<String>(),
                r.code,
                r.stdout,
                r.stderr
            ));
        }
    }
    let read_log = |p: &str| {
        let mut v: Vec<String> = std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .map(untimed)
            .collect();
        v.sort();
        v
    };
    let (pl, rl) = (read_log(&py_log), read_log(&rust_log));
    let _ = std::fs::remove_dir_all(&d);
    eprintln!(
        "differential prompt: {} inputs, {same} identical, known {known:?}, {} unexpected; outcomes {counts:?}; {} log lines; {} spot checks",
        inputs.len(),
        bad.len(),
        pl.len(),
        spot.len()
    );
    assert!(
        bad.is_empty(),
        "{} unexpected differences (first 15):\n{}",
        bad.len(),
        bad.iter().take(15).cloned().collect::<Vec<_>>().join("\n")
    );
    assert_eq!(pl.len(), rl.len(), "allow-name log line counts");
    let diff: Vec<_> = pl
        .iter()
        .zip(&rl)
        .filter(|(a, b)| a != b)
        .take(10)
        .collect();
    assert!(diff.is_empty(), "allow-name log lines differ: {diff:?}");
}

/// The outcome of a guard-prompt output, for the summary line.
fn claude_guard_rule(stdout: &str) -> String {
    let v: Value = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
    if let Some(r) = v.get("reason").and_then(Value::as_str) {
        return format!(
            "block:{}",
            r.split("(rule ")
                .nth(1)
                .and_then(|x| x.split(')').next())
                .unwrap_or("?")
        );
    }
    match v.get("systemMessage").and_then(Value::as_str) {
        Some(m) if m.contains("failed (") => "failed".into(),
        Some(_) => "warn".into(),
        None => "allow".into(),
    }
}
