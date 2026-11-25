//! Table tests for `claude-guard repo pre-bash` with a generic fixture config (no real repo's wording).

mod common;
use common::*;
use serde_json::json;

const CONFIG: &str = r#"{
  "version": 1,
  "repo_label": "fixture",
  "error_log": "private/errors.log",
  "pre_bash": {
    "logs_insights": {
      "guard_module": "cost_guard",
      "raw_cli_reason": "raw query: use the wrapper",
      "script_reason": "{path} queries without the guard",
      "inline_reason": "inline Python queries without the guard",
      "block_message": "Blocked: {why}. Route queries through the guard."
    }
  }
}"#;

const UNGUARDED: &str = "import boto3\nboto3.client('logs').start_query(logGroupName='g')\n";

fn world(tag: &str) -> String {
    let d = fresh_dir(tag);
    for sub in ["sub", "home", "other", ".claude"] {
        std::fs::create_dir_all(format!("{d}/{sub}")).unwrap();
    }
    let w = |p: &str, s: &str| std::fs::write(format!("{d}/{p}"), s).unwrap();
    w(".claude/repo-guard.json", CONFIG);
    w("sub/old.py", UNGUARDED);
    w("sub/new.py", &format!("import cost_guard\n{UNGUARDED}"));
    w("home/h.py", UNGUARDED);
    w("x.py", UNGUARDED);
    w(
        "shell.py",
        "import os\nos.system('aws logs start-query --x 1')\n",
    );
    w(
        "argv.py",
        "import subprocess\nsubprocess.run(['aws', 'logs', 'start-query'])\n",
    );
    d
}

fn hook(d: &str, input: &str) -> Out {
    run_in(
        &[BIN, "repo", "pre-bash"],
        input,
        &[("CLAUDE_PROJECT_DIR", d), ("HOME", &format!("{d}/home"))],
        Some(d),
    )
}

fn bash(d: &str, command: &str) -> Out {
    hook(
        d,
        &json!({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": d}).to_string(),
    )
}

#[test]
fn blocks_unguarded_queries_wherever_they_run() {
    let d = world("repo-block");
    for (command, why) in [
        (
            "aws logs start-query --query-string x",
            "raw query: use the wrapper",
        ),
        (
            "aws --profile p logs start-query",
            "raw query: use the wrapper",
        ),
        (
            "echo \"$(aws logs start-query)\"",
            "raw query: use the wrapper",
        ),
        (
            "bash -c 'aws logs start-query'",
            "raw query: use the wrapper",
        ),
        (
            "bash <<EOF\naws logs start-query\nEOF",
            "raw query: use the wrapper",
        ),
        ("python3 sub/old.py", "sub/old.py queries without the guard"),
        (
            "cd sub && python3 old.py",
            "old.py queries without the guard",
        ),
        ("cd sub\npython3 old.py", "old.py queries without the guard"),
        (
            "pushd sub >/dev/null && uv run python old.py",
            "old.py queries without the guard",
        ),
        ("python3 ~/h.py", "~/h.py queries without the guard"),
        (
            "python3 $CLAUDE_PROJECT_DIR/x.py",
            "$CLAUDE_PROJECT_DIR/x.py queries without the guard",
        ),
        ("python3 x.py; echo done", "x.py queries without the guard"),
        ("python3 shell.py", "shell.py queries without the guard"),
        ("python3 argv.py", "argv.py queries without the guard"),
        (
            "(cd other && ls); python3 x.py",
            "x.py queries without the guard",
        ),
        (
            "python3 -c \"import boto3; boto3.client('logs').start_query()\"",
            "inline Python queries without the guard",
        ),
        (
            "python3 - <<'EOF'\nimport boto3\nboto3.client('logs').start_query()\nEOF",
            "inline Python queries without the guard",
        ),
    ] {
        let o = bash(&d, command);
        assert_eq!(
            (o.code, o.stderr.as_str(), o.stdout.as_str()),
            (
                2,
                format!("Blocked: {why}. Route queries through the guard.\n").as_str(),
                ""
            ),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn allows_guarded_missing_unknown_and_data() {
    let d = world("repo-allow");
    for command in [
        "cd sub && python3 new.py",
        "cd other && python3 old.py",
        "(cd sub && ls); python3 old.py",
        "python3 $NOT_SET_ANYWHERE/x.py",
        "python3 \"$(ls sub/*.py | head -1)\"",
        "cat sub/old.py",
        "git commit -m 'aws logs start-query'",
        "cat <<EOF\naws logs start-query\nEOF",
        "aws logs describe-queries",
        "python3 - <<'EOF'\nimport cost_guard, boto3\nboto3.client('logs').start_query()\nEOF",
    ] {
        let o = bash(&d, command);
        assert_eq!(
            (o.code, o.stderr.as_str(), o.stdout.as_str()),
            (0, "", ""),
            "{command}"
        );
    }
    let o = hook(
        &d,
        &json!({"tool_name": "Read", "tool_input": {"command": "aws logs start-query"}})
            .to_string(),
    );
    assert_eq!(o.code, 0, "only Bash is checked");
    assert!(
        !std::path::Path::new(&format!("{d}/private/errors.log")).exists(),
        "no crash on any of these"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn crashes_allow_and_log_one_line() {
    let d = world("repo-crash");
    let log = format!("{d}/private/errors.log");
    for (i, input) in [
        "not json".to_string(),
        "[]".to_string(),
        json!({"tool_name": "Bash", "tool_input": ["x"]}).to_string(),
        json!({"tool_name": "Bash", "tool_input": {"command": 5}}).to_string(),
        json!({"tool_name": "Bash", "tool_input": {"command": "python3 x.py"}, "cwd": 5})
            .to_string(),
        format!("{}{}", "[".repeat(1000), "]".repeat(1000)),
    ]
    .iter()
    .enumerate()
    {
        let o = hook(&d, input);
        assert_eq!((o.code, o.stderr.as_str()), (0, ""), "{input}");
        let lines = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .count();
        assert_eq!(lines, i + 1, "one log line per crash: {input}");
    }
    let o = run_in(
        &[
            BIN,
            "repo",
            "pre-bash",
            "--crash-log",
            &format!("{d}/other/c.log"),
        ],
        "not json",
        &[("CLAUDE_PROJECT_DIR", &d)],
        Some(&d),
    );
    assert_eq!(o.code, 0);
    assert!(
        std::path::Path::new(&format!("{d}/other/c.log")).exists(),
        "--crash-log overrides the config"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn missing_or_bad_config_allows_with_a_warning() {
    let d = fresh_dir("repo-noconfig");
    let input =
        json!({"tool_name": "Bash", "tool_input": {"command": "aws logs start-query"}}).to_string();
    let o = run_in(
        &[BIN, "repo", "pre-bash"],
        &input,
        &[("CLAUDE_PROJECT_DIR", &d)],
        Some(&d),
    );
    assert_eq!(o.code, 0);
    assert!(
        o.stdout
            .starts_with("{\"systemMessage\": \"claude-guard repo pre-bash: no usable config"),
        "{}",
        o.stdout
    );
    std::fs::create_dir_all(format!("{d}/.claude")).unwrap();
    std::fs::write(format!("{d}/.claude/repo-guard.json"), "{\"version\": 2}").unwrap();
    let o = run_in(
        &[BIN, "repo", "pre-bash"],
        &input,
        &[("CLAUDE_PROJECT_DIR", &d)],
        Some(&d),
    );
    assert!(o.stdout.contains("version is not 1"), "{}", o.stdout);
    std::fs::write(
        format!("{d}/.claude/repo-guard.json"),
        "{\"version\": 1, \"error_log\": \"e.log\"}",
    )
    .unwrap();
    let o = run_in(
        &[BIN, "repo", "pre-bash"],
        &input,
        &[("CLAUDE_PROJECT_DIR", &d)],
        Some(&d),
    );
    assert!(
        o.stdout
            .contains("no rules (pre_bash.logs_insights or pre_bash.git)"),
        "{}",
        o.stdout
    );
    std::fs::write(
        format!("{d}/.claude/repo-guard.json"),
        "{\"version\": 1, \"error_log\": \"e.log\", \"pre_bash\": {\"logs_insights\": {}}}",
    )
    .unwrap();
    let o = run_in(
        &[BIN, "repo", "pre-bash"],
        &input,
        &[("CLAUDE_PROJECT_DIR", &d)],
        Some(&d),
    );
    assert!(
        o.stdout
            .contains("pre_bash.logs_insights.guard_module is missing"),
        "a section that is there must be complete: {}",
        o.stdout
    );
    let o = run_in(&[BIN, "repo", "pre-bash", "--bogus"], &input, &[], Some(&d));
    assert_eq!(o.code, 64, "unknown arguments are a usage error");
    let _ = std::fs::remove_dir_all(&d);
}
