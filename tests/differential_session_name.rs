//! Differential test: `claude-guard session-name` against session-name-from-title.sh (run for real with /bin/dash,
//! the way settings.json runs it) on generated cases: a transcript, a session registry (through CLAUDE_CONFIG_DIR,
//! which both read) with live, dead and odd pids, and the hook input. stdout must match byte for byte.
//! Titles and names are made up. Env (test only): CLAUDE_GUARD_REF_SESSION_NAME, CLAUDE_GUARD_DIFF_CASES (default
//! 1500), CLAUDE_GUARD_DIFF_SEED, CLAUDE_GUARD_DIFF_WORKERS (default 2).

mod common;
use common::*;
use serde_json::json;
use std::process::Command;

/// (title, its slug) for building clashes; the slugs are what the script makes of the titles.
const TITLES: &[(&str, &str)] = &[
    ("Valkey cluster hash tags", "valkey-cluster-hash-tags"),
    (
        "Fix OAuth 2.0 redirect loop in billing_api login",
        "fix-oauth-redirect-loop",
    ),
    ("Herdr tab agent tags", "herdr-tab-agent-tags"),
    ("Payout holds", "payout-holds"),
    (
        "Supercalifragilisticexpialidocious internationalization",
        "supercalifragilisticexpialido",
    ),
    ("The quick-fix for a b", "quick-fix-b"),
];
const ODD_TITLES: &[&str] = &[
    "2026 Q4 deck update",
    "The 42",
    "  leading spaces and a b c d e",
    "İstanbul office",
    "\u{212a}elvin units",
    "ÉCOLE École",
    "naïve café",
    "x²y",
    "Ａｂｃ fullwidth",
    "tabs\tand\nnewlines",
    "trailing dash -",
    "-",
    "...",
    "A",
    "über-long-name-with-many-hyphenated-words-here",
    "123abc def",
    "mixed CASE Words",
    "of the and",
    "Straße ẞ",
    "emoji 🚀 launch",
    "snake_case_name",
    "dots.in.title",
    "\"quoted\"",
    "back\\slash",
];
const IDS: &[&str] = &[
    "1a2b3c4d-0000-0000-0000-000000000000",
    "f9e8d7c6-1111-2222-3333-444455556666",
    "ab",
    "a",
    "",
    "ABCD-1234",
    "x y",
    "é1a2b",
    "--",
    "0c",
    "zz-99",
];
const OWN_NAMES: &[&str] = &[
    "notes-app-f9",
    "mmt-0c",
    "a-bcdef",
    "noprefix",
    "web-admin-aap-e1",
    "x-1",
    "api-dms-8fab",
    "trail-",
    "UP-AB",
];

fn ai_line(title: &str) -> String {
    format!("{{\"type\":\"ai-title\",\"aiTitle\":{}}}", json!(title))
}

struct Case {
    dir: String,
    input: String,
}

fn build(rng: &mut Rng, root: &str, i: usize, pids: &[String]) -> Case {
    let dir = format!("{root}/c{i}");
    let sessions = format!("{dir}/cfg/sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    // Transcript.
    let use_known = rng.chance(60);
    let (title, slug) = if use_known {
        let t = rng.pick(TITLES);
        (t.0.to_string(), t.1.to_string())
    } else {
        (rng.pick(ODD_TITLES).to_string(), String::new())
    };
    let mut lines: Vec<String> = vec!["{\"type\":\"user\",\"message\":\"hi\"}".into()];
    if rng.chance(30) {
        lines.push(ai_line("Old title"));
    }
    match rng.below(14) {
        0 => {}
        1 => lines.push("{\"type\":\"custom-title\",\"customTitle\":\"payout-holds\"}".into()),
        2 => lines.push("{\"type\":\"ai-title\",\"aiTitle\":1e2}".into()),
        3 => lines.push("{\"type\":\"ai-title\",\"aiTitle\":{\"a\":[1,\"Big Plan\"]}}".into()),
        4 => lines.push("{\"type\":\"ai-title\",\"aiTitle\":null}".into()),
        5 => lines.push("{\"type\":\"ai-title\",\"aiTitle\":\"broken".into()),
        6 => lines.push(format!("{} {}", ai_line(&title), ai_line("Second value"))),
        7 => lines.push(format!("{}\r", ai_line(&title))),
        8 => lines.push("{\"type\":\"ai-title\",\"aiTitle\":\"\\u0130stanbul \\ud800 x\"}".into()),
        _ => lines.push(ai_line(&title)),
    }
    if rng.chance(15) {
        lines.push("{\"type\":\"assistant\",\"text\":\"not a title\"}".into());
    }
    let transcript = format!("{dir}/tr.jsonl");
    let mut body = lines.join("\n");
    if rng.chance(80) {
        body.push('\n');
    }
    std::fs::write(&transcript, body).unwrap();

    // Registry.
    let me = rng.pick(IDS).to_string();
    let candidates: Vec<String> = if slug.is_empty() {
        vec!["other-name".into()]
    } else {
        let id2: String = me
            .chars()
            .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            .take(2)
            .collect();
        let id4: String = me
            .chars()
            .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            .take(4)
            .collect();
        let s27: String = slug.chars().take(27).collect();
        vec![
            slug.clone(),
            format!("{slug}-f9"),
            format!("{slug}-0c"),
            format!("{slug}-{id2}"),
            format!("{}-{id4}", s27.trim_end_matches('-')),
            format!("{slug}-bcdef"),
        ]
    };
    let n = rng.below(5);
    for k in 0..n {
        let name = rng.pick(&candidates).clone();
        let pid = rng.pick(pids).clone();
        let sid = if rng.chance(15) {
            me.clone()
        } else {
            format!("0000{k}aaa")
        };
        let source = if rng.chance(50) { "hook" } else { "derived" };
        let spacing = if rng.chance(30) { ": " } else { ":" };
        let text = match rng.below(12) {
            0 => format!(
                "{{\"pid\"{spacing}{pid},\"sessionId\":\"{sid}\",\"name\"{spacing}\"{name}\"}} x"
            ),
            1 => format!("[{{\"name\"{spacing}\"{name}\"}}]"),
            2 => format!("{{\"name\"{spacing}\"{name}\",\"pid\":{pid}}}\n{{\"name\":\"zz\"}}"),
            _ => format!(
                "{{\"pid\"{spacing}{pid},\"sessionId\"{spacing}\"{sid}\",\"name\"{spacing}\"{name}\",\"nameSource\"{spacing}\"{source}\"}}"
            ),
        };
        std::fs::write(format!("{sessions}/{}.json", 10 + k), text).unwrap();
    }
    if rng.chance(60) && !me.is_empty() {
        let own = rng.pick(OWN_NAMES);
        let src = if rng.chance(85) { "derived" } else { "user" };
        let pid = std::process::id();
        std::fs::write(
            format!("{sessions}/{}.json", 90 + rng.below(3)),
            format!(
                "{{\"pid\":{pid},\"sessionId\":{},\"name\":\"{own}\",\"nameSource\":\"{src}\"}}",
                json!(me)
            ),
        )
        .unwrap();
    }
    if rng.chance(5) {
        std::fs::create_dir_all(format!("{sessions}/dir.json")).unwrap();
    }

    // Hook input.
    let event = match rng.below(12) {
        0 => json!("SessionStart"),
        1 => json!(5),
        2 => json!(""),
        3 => json!({"x": 1}),
        4 => json!("é\u{1}\"x"),
        _ => json!("UserPromptSubmit"),
    };
    let tpath = match rng.below(14) {
        0 => json!(format!("{dir}/missing.jsonl")),
        1 => json!(dir.clone()),
        2 => json!(null),
        _ => json!(transcript),
    };
    let mut obj = json!({"hook_event_name": event, "session_id": me, "transcript_path": tpath});
    match rng.below(14) {
        0 => obj["session_title"] = json!("payout-holds"),
        1 => obj["session_title"] = json!(""),
        2 => obj["session_title"] = json!(false),
        3 => obj["session_title"] = json!(0),
        4 => obj["session_title"] = json!("\n"),
        5 => obj["session_id"] = json!(42),
        _ => {}
    }
    let mut input = obj.to_string();
    match rng.below(25) {
        0 => input.push_str(" {\"session_title\":\"later\"}"),
        1 => input.push_str(" garbage"),
        2 => input = format!("5 {input}"),
        3 => input = "nope".into(),
        4 => input.push_str("\n\n"),
        _ => {}
    }
    Case { dir, input }
}

#[test]
fn differential_session_name() {
    let reference = env_or(
        "CLAUDE_GUARD_REF_SESSION_NAME",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/reference/session-name-from-title.sh"
        ),
    );
    if !std::path::Path::new(&reference).exists() {
        eprintln!("differential session-name: skipped, no reference at {reference}");
        return;
    }
    let n: usize = env_or("CLAUDE_GUARD_DIFF_CASES", "1500").parse().unwrap();
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261124")
        .parse()
        .unwrap();
    let workers: usize = env_or("CLAUDE_GUARD_DIFF_WORKERS", "2").parse().unwrap();
    let root = fresh_dir("name-diff");
    let mut live = Command::new("/bin/sleep").arg("600").spawn().unwrap();
    let lp = live.id();
    let pids: Vec<String> = [
        lp.to_string(),
        format!("\"{lp}\""),
        format!("\" {lp}\""),
        format!("\"+{lp}\""),
        format!("{lp}.0"),
        "99998".into(),
        "0".into(),
        "-1".into(),
        "null".into(),
        "\"\"".into(),
        "99999999999".into(),
        std::process::id().to_string(),
        "1".into(),
        "[1]".into(),
    ]
    .to_vec();
    let mut rng = Rng(seed | 1);
    let cases: Vec<Case> = (0..n).map(|i| build(&mut rng, &root, i, &pids)).collect();
    let results: Vec<(Out, Out)> = parallel(&cases, workers, |_, c| {
        let cfg = format!("{}/cfg", c.dir);
        let env = [("CLAUDE_CONFIG_DIR", cfg.as_str())];
        let r = run_in(&["/bin/dash", &reference], &c.input, &env, None);
        let o = run_in(&[BIN, "session-name"], &c.input, &env, None);
        (r, o)
    });
    let _ = live.kill();
    let _ = live.wait();
    let (mut same, mut named, mut bad) = (0, 0, Vec::new());
    for (c, (r, o)) in cases.iter().zip(&results) {
        if !r.stdout.is_empty() {
            named += 1;
        }
        if o.code == 0 && r.code == 0 && o.stdout == r.stdout && o.stderr.is_empty() {
            same += 1;
        } else {
            let reg: Vec<String> = std::fs::read_dir(format!("{}/cfg/sessions", c.dir))
                .map(|d| {
                    d.filter_map(|e| e.ok())
                        .map(|e| {
                            format!(
                                "{}={}",
                                e.file_name().to_string_lossy(),
                                std::fs::read_to_string(e.path()).unwrap_or_default()
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let tr = std::fs::read_to_string(format!("{}/tr.jsonl", c.dir)).unwrap_or_default();
            bad.push(format!(
                "input: {}\n  transcript: {tr:?}\n  registry: {reg:?}\n  script: {} {:?}\n  rust:   {} {:?} {:?}",
                c.input.chars().take(300).collect::<String>(),
                r.code,
                r.stdout,
                o.code,
                o.stdout,
                o.stderr
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
        "differential session-name: {n} cases, {same} identical, {named} named by the script, {} unexpected",
        bad.len()
    );
    assert!(
        bad.is_empty(),
        "{} unexpected differences (first 8):\n{}",
        bad.len(),
        bad.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
    );
}
