//! Table tests for `claude-guard bash`: guard-bash's own cases (tests/fixtures/guard_bash_cases.tsv), the pip
//! rule from block-pip.sh, and the input edge cases (bad JSON, non-string fields, crashes, shadow mode).

use std::io::Write;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_claude-guard");

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Test crash log: never the real one under ~/.local/state.
fn crash_log() -> String {
    format!(
        "{}/claude-guard-table-bash-crash-{}.log",
        tmpdir(),
        std::process::id()
    )
}

fn run(args: &[&str], input: &str) -> Out {
    let log = crash_log();
    let mut args = args.to_vec();
    if args == ["bash"] {
        args.extend(["--crash-log", log.as_str()]);
    }
    run_raw(&args, input)
}

fn run_raw(args: &[&str], input: &str) -> Out {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into(),
        stderr: String::from_utf8_lossy(&o.stderr).into(),
    }
}

fn bash_input(cmd: &str) -> String {
    serde_json::json!({"tool_name": "Bash", "tool_input": {"command": cmd}}).to_string()
}

fn tmpdir() -> String {
    std::env::var("TMPDIR")
        .unwrap_or_else(|_| "/tmp".into())
        .trim_end_matches('/')
        .to_string()
}

#[test]
fn guard_bash_cases() {
    let table = include_str!("fixtures/guard_bash_cases.tsv");
    let t = tmpdir();
    let mut fails = Vec::new();
    let mut n = 0;
    for line in table.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (want, cmd) = line.split_once('\t').unwrap();
        let cmd = cmd.replace("{TMPDIR}", &t).replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&cmd));
        let got = if o.stdout.trim().is_empty() {
            "allow"
        } else {
            "deny"
        };
        assert_eq!(o.code, 0, "exit code for {cmd:?}");
        if got != want {
            fails.push(format!("want={want} got={got} :: {cmd}"));
        }
        n += 1;
    }
    assert!(n > 150, "fixture has {n} cases");
    assert!(
        fails.is_empty(),
        "{} of {n} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn pip_rule() {
    let p = "pip"; // kept apart so this file's text doesn't trip the live pip hook
    let block = [
        format!("{p} install requests"),
        format!("{p}3 install x"),
        format!("python -m {p} install x"),
        format!("python3 -m {p} install x"),
        format!("ls; {p} install x"),
        format!("ls && {p} install x"),
        format!("ls | {p} install x"),
        format!("ls &{p} install x"),
        format!("echo hi\n{p} install x"),
        format!("cd /tmp && python3 -m {p} install -r r.txt"),
    ];
    let allow = [
        format!("uv {p} install x"),
        format!("{p}x install x"),
        format!("echo {p} install"),
        format!("  {p} install x"),
        format!("ls;\n  {p} install x"),
        format!("{p} list"),
        "npm install".to_string(),
    ];
    for c in &block {
        let o = run(&["bash"], &bash_input(c));
        assert_eq!(
            (o.code, o.stdout.as_str(), o.stderr.trim()),
            (
                2,
                "",
                "Do not use pip. Use uv instead. Example: uv add <packages>"
            ),
            "{c:?}"
        );
    }
    for c in &allow {
        let o = run(&["bash"], &bash_input(c));
        assert_eq!((o.code, o.stdout.as_str()), (0, ""), "{c:?}");
    }
    // A guard-bash rule wins over the pip rule (one message, the deny).
    let o = run(&["bash"], &bash_input(&format!("sudo {p} install x")));
    assert_eq!(o.code, 0);
    assert!(o.stdout.contains("sudo is blocked"));
}

/// rust-anything: only the read-only subcommands run; every other one (and any added later) is blocked, as its
/// MCP tools are. Rust-only rule, so these cases stay out of guard_bash_cases.tsv (the differential test replays
/// that file against the Python guard).
#[test]
fn rust_anything_rule() {
    let block = [
        // Every code-running or source-editing subcommand of rust-anything 4.1.
        "rust-anything go --agent claude -- python3 app.py",
        "rust-anything bridge src/util.ts --name util",
        "rust-anything refresh rust/util",
        "rust-anything record rust/util",
        "rust-anything build rust/util",
        "rust-anything diff rust/util",
        "rust-anything bench rust/util",
        "rust-anything fuzz rust/util --seed 7",
        "rust-anything profile . -- node bench.mjs",
        "rust-anything enable rust/util",
        "rust-anything disable rust/util",
        "rust-anything report rust/util",
        "rust-anything clean",
        "rust-anything shadow rust/util",
        "rust-anything gate rust/util",
        "rust-anything package rust/util",
        "rust-anything app record -- ./cli",
        "rust-anything mcp",
        "rust-anything setup",
        // A subcommand this list doesn't know yet.
        "rust-anything port-everything",
        // Called by path, after options, or with no subcommand (xargs could supply one).
        "~/.cargo/bin/rust-anything build rust/util",
        "/opt/tools/bin/rust-anything go -- node x.js",
        "rust-anything --verbose build rust/util",
        "rust-anything",
        // --help after `--` goes to the workload, not to rust-anything.
        "rust-anything go -- python3 app.py --help",
        "ls rust | xargs rust-anything",
        "ls rust | xargs -n1 rust-anything build",
        // In a list, a pipeline, a subshell or command substitution.
        "cd /tmp && rust-anything build rust/util",
        "true; rust-anything diff rust/util",
        "(cd x && rust-anything gate rust/util)",
        "echo $(rust-anything build rust/util)",
        "echo `rust-anything build rust/util`",
        // Behind a prefix, an assignment or a wrapper with options.
        "env FOO=1 rust-anything build rust/util",
        "CARGO_TARGET_DIR=/tmp/t rust-anything build rust/util",
        "env -i rust-anything build rust/util",
        "nice -n 10 rust-anything bench rust/util",
        "timeout 600 rust-anything fuzz rust/util",
        "caffeinate -i rust-anything go -- node x.js",
        "nohup rust-anything go -- node x.js",
        "exec rust-anything mcp",
        // Inside a shell's -c string or a heredoc the shell reads.
        "bash -c 'rust-anything build rust/util'",
        "sh -lc \"cd x && rust-anything gate rust/util\"",
        "zsh -ec 'timeout 9 rust-anything go'",
        "bash -c 'bash -c \"rust-anything build x\"'",
        "bash <<'EOF'⏎rust-anything build rust/util⏎EOF",
    ];
    let allow = [
        "rust-anything analyze",
        "rust-anything analyze . --json",
        "rust-anything analyze ~/Repositories/app -o /tmp/plan.md",
        "rust-anything analyze --whole-app --lang ts",
        "rust-anything map",
        "rust-anything map --write",
        "rust-anything map --check --json",
        "rust-anything doctor",
        "rust-anything doctor --json",
        "rust-anything help",
        "rust-anything help build",
        "rust-anything --help",
        "rust-anything -h",
        "rust-anything -V",
        "rust-anything --version",
        "rust-anything build --help",
        "rust-anything bridge src/util.ts -h",
        "rust-anything -h go",
        "~/.cargo/bin/rust-anything analyze .",
        "timeout 60 rust-anything map",
        "bash -c 'rust-anything doctor'",
        // Naming it isn't running it.
        "echo rust-anything build",
        "rg -n rust-anything src",
        "git commit -m 'block rust-anything build in the guard'",
        "cat ~/.claude/skills/rust-anything/SKILL.md",
        "cargo install rust-anything",
        "bash -c 'echo rust-anything build'",
        "rust-anything-helper build",
        "ls ~/.cargo/bin/rust-anything",
    ];
    let mut fails = Vec::new();
    for c in &block {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        let ok = o.code == 0
            && o.stdout.contains("\"permissionDecision\": \"deny\"")
            && o.stdout.contains("guard-bash: rust-anything ")
            && o.stdout.contains("analyze, map, doctor and help");
        if !ok {
            fails.push(format!("want=deny :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    for c in &allow {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want=allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
    // The subcommand is named in the reason.
    let o = run(&["bash"], &bash_input("rust-anything go -- node x.js"));
    assert!(
        o.stdout.contains("rust-anything go can build"),
        "{}",
        o.stdout
    );
    let o = run(&["bash"], &bash_input("rust-anything"));
    assert!(
        o.stdout.contains("rust-anything without a subcommand"),
        "{}",
        o.stdout
    );
}

#[test]
fn input_edges() {
    // Bad JSON, wrong shapes and empty commands allow (as the Python guard did).
    for input in [
        "not json",
        "{}",
        "[]",
        "{\"tool_input\": null}",
        "{\"tool_input\": \"x\"}",
        "{\"tool_input\": {\"command\": \"\"}}",
        "{\"tool_input\": {\"command\": 0}}",
    ] {
        let o = run(&["bash"], input);
        assert_eq!((o.code, o.stdout.as_str()), (0, ""), "{input}");
    }
    // A parse error in the command allows (a quoting mistake never locks the shell).
    let o = run(&["bash"], &bash_input("cat \"unterminated"));
    assert_eq!((o.code, o.stdout.as_str()), (0, ""));
    // A command that isn't text: allowed with one warning that never repeats the input.
    for v in [
        "5",
        "1.5",
        "NaN",
        "-Infinity",
        "1e400",
        "true",
        "[\"sudo\", \"ls\"]",
        "{\"a\": \"sudo ls\"}",
    ] {
        let o = run(
            &["bash"],
            &format!("{{\"tool_input\": {{\"command\": {v}}}}}"),
        );
        assert_eq!(
            (o.code, o.stdout.as_str()),
            (
                0,
                "{\"systemMessage\": \"guard-bash: couldn't check this command (input not text); allowed.\"}\n"
            ),
            "{v}"
        );
    }
    // Empty non-strings: nothing to check, silent allow.
    for v in ["null", "0", "[]", "{}", "false"] {
        let o = run(
            &["bash"],
            &format!("{{\"tool_input\": {{\"command\": {v}}}}}"),
        );
        assert_eq!((o.code, o.stdout.as_str()), (0, ""), "{v}");
    }
    // Python accepted lone surrogates and NaN; a parse failure here would fail open.
    let o = run(
        &["bash"],
        "{\"tool_input\": {\"command\": \"sudo ls \\ud800\"}, \"n\": NaN}",
    );
    assert!(o.stdout.contains("sudo is blocked"), "{}", o.stdout);
    // A number past f64's range elsewhere in the input: Python read it as inf; serde_json alone refused it all.
    let o = run(
        &["bash"],
        "{\"tool_input\": {\"command\": \"sudo ls\"}, \"n\": 1e400, \"m\": -2e999}",
    );
    assert!(o.stdout.contains("sudo is blocked"), "{}", o.stdout);
    // JSON nested deeper than Python reads (994 levels with the outer object) blocks; 993 is checked as usual.
    let nested = |levels: usize, cmd: &str| {
        format!(
            "{{\"tool_input\": {{\"command\": \"{cmd}\"}}, \"a\": {}1{}}}",
            "[".repeat(levels - 1),
            "]".repeat(levels - 1)
        )
    };
    let o = run(&["bash"], &nested(993, "sudo ls"));
    assert!(o.stdout.contains("sudo is blocked"), "{}", o.stdout);
    assert_eq!(run(&["bash"], &nested(993, "ls")).stdout, "");
    for cmd in ["ls", "sudo ls"] {
        let o = run(&["bash"], &nested(994, cmd));
        assert!(
            o.stdout.contains("deny")
                && o.stdout.contains(
                    "RecursionError: maximum recursion depth exceeded while decoding a JSON array"
                ),
            "{}",
            o.stdout
        );
    }
    let _ = std::fs::remove_file(crash_log());
    // Output is byte-for-byte Python's json.dumps (ensure_ascii, ", " and ": ").
    let o = run(&["bash"], &bash_input("sudo é"));
    assert_eq!(
        o.stdout,
        "{\"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \"permissionDecision\": \"deny\", \"permissionDecisionReason\": \"guard-bash: sudo is blocked: Claude never needs admin rights. Run it yourself if you must.\"}}\n"
    );
    // Deep brace nesting is a crash (blocked), never a stack overflow that would let the command run.
    // It stays blocked (anyone can pad a command this way) and writes one record to the crash log it names.
    let _ = std::fs::remove_file(crash_log());
    let deep = format!("cat {}{}", "{a,".repeat(5000), "}".repeat(5000));
    let o = run(&["bash"], &bash_input(&deep));
    assert_eq!(o.code, 0);
    assert!(
        o.stdout.contains("deny") && o.stdout.contains("RecursionError"),
        "deep nesting: {}",
        o.stdout
    );
    assert!(
        o.stdout.contains(&crash_log()),
        "the reason names the log it wrote"
    );
    let logged = std::fs::read_to_string(crash_log()).unwrap_or_default();
    assert_eq!(
        logged.matches("--- ").count(),
        1,
        "one record in the test crash log"
    );
    let _ = std::fs::remove_file(crash_log());
}

#[test]
fn shadow_never_blocks() {
    let dir = std::env::temp_dir().join(format!("claude-guard-shadow-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("shadow.log");
    let missing = dir.join("missing.py");
    for cmd in ["sudo ls", "ls"] {
        let o = run(
            &[
                "bash",
                "--shadow",
                "--reference",
                missing.to_str().unwrap(),
                "--pip-reference",
                missing.to_str().unwrap(),
                "--log",
                log.to_str().unwrap(),
            ],
            &bash_input(cmd),
        );
        assert_eq!(
            (o.code, o.stdout.as_str(), o.stderr.as_str()),
            (0, "", ""),
            "{cmd}"
        );
    }
    // The comparison runs detached after the hook exits: wait for its lines.
    let mut text = String::new();
    for _ in 0..200 {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.lines().count() >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert_eq!(text.lines().count(), 2);
    assert!(text.contains("\"rust\": \"sudo\""));
    assert!(
        !text.contains("sudo ls"),
        "the log must not hold the command"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
