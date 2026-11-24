//! Table tests for `claude-guard session-name`: session-name-from-title.sh's own cases
//! (test_session_name_hook.sh). A fake registry through
//! CLAUDE_CONFIG_DIR (the hook reads Claude Code's own setting, as the script does) and a `sleep` child as a live
//! peer session; nothing real is touched.

mod common;
use common::*;
use serde_json::{Value, json};
use std::process::{Child, Command};

struct Env {
    d: String,
    live: Child,
    dead: u32,
}

const ME: &str = "1a2b3c4d-0000-0000-0000-000000000000";

impl Env {
    fn new(tag: &str) -> Env {
        let d = fresh_dir(&format!("name-{tag}"));
        std::fs::create_dir_all(format!("{d}/cfg/sessions")).unwrap();
        let live = Command::new("/bin/sleep").arg("300").spawn().unwrap();
        // A pid nobody holds: count down from a high one until kill -0 fails.
        let mut dead = 99_999;
        while unsafe { kill(dead as i32, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(1)
        {
            dead -= 1;
        }
        Env { d, live, dead }
    }
    fn transcript(&self, lines: &[&str]) {
        std::fs::write(format!("{}/tr.jsonl", self.d), lines.join("\n") + "\n").unwrap();
    }
    fn reg(&self, file: &str, name: &str, sid: &str, pid: u32, source: &str) {
        let v = json!({"pid": pid, "sessionId": sid, "name": name, "nameSource": source});
        std::fs::write(
            format!("{}/cfg/sessions/{file}.json", self.d),
            v.to_string(),
        )
        .unwrap();
    }
    fn unreg(&self, file: &str) {
        std::fs::remove_file(format!("{}/cfg/sessions/{file}.json", self.d)).unwrap();
    }
    fn input(&self, extra: &str, event: &str) -> String {
        format!(
            "{{\"hook_event_name\":\"{event}\",\"session_id\":\"{ME}\",\"transcript_path\":\"{}/tr.jsonl\"{extra}}}",
            self.d
        )
    }
    fn run_raw(&self, input: &str, path: Option<&str>) -> Out {
        let cfg = format!("{}/cfg", self.d);
        let mut env = vec![("CLAUDE_CONFIG_DIR", cfg.as_str())];
        if let Some(p) = path {
            env.push(("PATH", p));
        }
        run_in(&[BIN, "session-name"], input, &env, None)
    }
    fn name(&self, extra: &str, event: &str) -> String {
        let o = self.run_raw(&self.input(extra, event), None);
        assert_eq!(o.code, 0);
        if o.stdout.is_empty() {
            return String::new();
        }
        let v: Value = serde_json::from_str(&o.stdout).unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], event);
        v["hookSpecificOutput"]["sessionTitle"]
            .as_str()
            .unwrap()
            .to_string()
    }
}

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.live.kill();
        let _ = self.live.wait();
        let _ = std::fs::remove_dir_all(&self.d);
    }
}

#[test]
fn session_name_cases() {
    let e = Env::new("cases");
    let me_pid = std::process::id();
    let (live, dead) = (e.live.id(), e.dead);
    let ups = "UserPromptSubmit";
    e.transcript(&[
        r#"{"type":"ai-title","aiTitle":"Old"}"#,
        r#"{"type":"ai-title","aiTitle":"Valkey cluster hash tags"}"#,
    ]);
    e.reg("me", "notes-app-f9", ME, me_pid, "derived");
    assert_eq!(
        e.name("", ups),
        "valkey-cluster-hash-tags",
        "latest ai-title"
    );
    assert_eq!(
        e.name("", "SessionStart"),
        "valkey-cluster-hash-tags",
        "SessionStart event"
    );
    e.reg(
        "other",
        "valkey-cluster-hash-tags",
        "0000aaaa",
        live,
        "hook",
    );
    assert_eq!(
        e.name("", ups),
        "valkey-cluster-hash-tags-f9",
        "live clash -> own suffix"
    );
    e.reg(
        "other",
        "valkey-cluster-hash-tags",
        "0000aaaa",
        dead,
        "hook",
    );
    assert_eq!(
        e.name("", ups),
        "valkey-cluster-hash-tags",
        "dead clash ignored"
    );
    e.reg(
        "other",
        "valkey-cluster-hash-tags",
        "0000aaaa",
        live,
        "hook",
    );
    e.reg(
        "other2",
        "valkey-cluster-hash-tags-f9",
        "0000bbbb",
        live,
        "hook",
    );
    assert_eq!(
        e.name("", ups),
        "valkey-cluster-hash-tags-1a2b",
        "double clash -> 4 chars"
    );
    e.unreg("other2");
    e.reg("me", "valkey-cluster-hash-tags", ME, me_pid, "hook");
    assert_eq!(
        e.name("", ups),
        "valkey-cluster-hash-tags-1a",
        "own file not a clash"
    );
    e.unreg("me");
    assert_eq!(
        e.name("", ups),
        "valkey-cluster-hash-tags-1a",
        "no own file -> id suffix"
    );
    e.unreg("other");
    assert_eq!(
        e.name(",\"session_title\":\"payout-holds\"", ups),
        "",
        "already named"
    );
    e.transcript(&[
        r#"{"type":"custom-title","customTitle":"payout-holds"}"#,
        r#"{"type":"ai-title","aiTitle":"Other"}"#,
    ]);
    assert_eq!(e.name("", "SessionStart"), "", "resume of named session");
    e.transcript(&[r#"{"type":"user"}"#]);
    assert_eq!(e.name("", ups), "", "no ai-title yet");
    for (title, want, label) in [
        (
            "Fix OAuth 2.0 redirect loop in billing_api login",
            "fix-oauth-redirect-loop",
            "digits and filler dropped",
        ),
        (
            "2026 Q4 deck update",
            "q4-deck-update",
            "starts with a letter",
        ),
        (
            "Supercalifragilisticexpialidocious internationalization",
            "supercalifragilisticexpialido",
            "29-char cap",
        ),
        ("The 42", "", "nothing usable"),
        (
            "İstanbul office KELVİN",
            "istanbul-office-kelvin",
            "dotted capital I lowercases to i (UTF-8 tr)",
        ),
    ] {
        let t = json!({"type": "ai-title", "aiTitle": title});
        std::fs::write(
            format!("{}/tr.jsonl", e.d),
            format!("{{\"type\":\"ai-title\",\"aiTitle\":{}}}\n", t["aiTitle"]),
        )
        .unwrap();
        assert_eq!(e.name("", ups), want, "{label}");
    }
    e.transcript(&[r#"{"type":"ai-title","aiTitle":"Valkey cluster hash tags"}"#]);
    // A repo's settings env can replace PATH for hooks; this hook runs no other program.
    let o = e.run_raw(&e.input("", ups), Some("/nonexistent"));
    assert!(
        o.stdout.contains("valkey-cluster-hash-tags"),
        "repo PATH ignored: {}",
        o.stdout
    );
    assert_eq!(e.run_raw("nope", None).stdout, "", "garbage stdin");
    assert_eq!(
        e.run_raw(
            r#"{"hook_event_name":"UserPromptSubmit","transcript_path":"/nonexistent"}"#,
            None
        )
        .stdout,
        "",
        "missing transcript"
    );
    let o = e.run_raw(r#"{"hook_event_name":"UserPromptSubmit"}"#, None);
    assert_eq!((o.code, o.stdout.as_str()), (0, ""), "exit code");
    // Output is jq -c's, event text escaped as jq escapes it.
    let o = e.run_raw(
        &format!("{{\"hook_event_name\":\"é\\u0001\\\"x\",\"session_id\":\"{ME}\",\"transcript_path\":\"{}/tr.jsonl\"}}", e.d),
        None,
    );
    assert_eq!(
        o.stdout,
        "{\"hookSpecificOutput\":{\"hookEventName\":\"é\\u0001\\\"x\",\"sessionTitle\":\"valkey-cluster-hash-tags\"}}\n"
    );
}

#[test]
fn shadow_never_prints() {
    let e = Env::new("shadow");
    e.transcript(&[r#"{"type":"ai-title","aiTitle":"Valkey cluster hash tags"}"#]);
    let log = format!("{}/shadow.log", e.d);
    let missing = format!("{}/missing.sh", e.d);
    let cfg = format!("{}/cfg", e.d);
    let o = run_in(
        &[
            BIN,
            "session-name",
            "--shadow",
            "--reference",
            &missing,
            "--log",
            &log,
        ],
        &e.input("", "UserPromptSubmit"),
        &[("CLAUDE_CONFIG_DIR", cfg.as_str())],
        None,
    );
    assert_eq!((o.code, o.stdout.as_str(), o.stderr.as_str()), (0, "", ""));
    let mut text = String::new();
    for _ in 0..200 {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if !text.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(
        text.contains("\"hook\": \"session-name\"") && text.contains("\"rust\": \"name\""),
        "{text}"
    );
    assert!(!text.contains("valkey"), "the log must not hold the name");
}
