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
        // block-pip's pattern missed these (leading blanks, a keyword or an assignment first); each simple command
        // is now checked too.
        format!("  {p} install x"),
        format!("ls;\n  {p} install x"),
        format!("if true; then {p} install x; fi"),
        format!("for a in b; do {p} install x; done"),
        format!("{{ {p} install x; }}"),
        format!("X=1 {p} install x"),
    ];
    let allow = [
        format!("uv {p} install x"),
        format!("{p}x install x"),
        format!("echo {p} install"),
        format!("echo \"{p} install x\""),
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

/// Every rule also holds inside `bash -c STRING` (and sh, zsh, dash, ksh; `-lc`, `-ec`, options before `-c`),
/// nested or not. Rust only: the Python guard read the string as one word, so these cases stay out of
/// guard_bash_cases.tsv (the differential test lists them as a known difference).
#[test]
fn shell_c_strings_every_rule() {
    let p = "pip"; // kept apart so this file's text doesn't trip the live pip hook
    // (command, words the deny reason must hold)
    let deny = [
        ("bash -c 'sudo ls'".to_string(), "sudo is blocked"),
        (
            "sh -c 'rm -rf /srv/app'".to_string(),
            "recursive force delete",
        ),
        (
            "bash -lc 'rm -fr ~/work'".to_string(),
            "recursive force delete",
        ),
        ("zsh -c 'cat .env'".to_string(), "reading a secrets file"),
        (
            "bash -c \"head -5 config/.env.production\"".to_string(),
            "reading a secrets file",
        ),
        (
            "dash -c 'cat ./prod.env'".to_string(),
            "reading a secrets file",
        ),
        (
            "ksh -c 'base64 .envrc'".to_string(),
            "reading a secrets file",
        ),
        ("bash -c 'grep -r token .'".to_string(), "recursive grep"),
        ("sh -c 'rg --hidden token'".to_string(), "rg with --hidden"),
        (
            "bash -c 'git push -f origin main'".to_string(),
            "git push --force",
        ),
        (
            "bash -c 'rust-anything build rust/util'".to_string(),
            "rust-anything build",
        ),
        // Option spellings and positions.
        ("bash -ec 'sudo ls'".to_string(), "sudo is blocked"),
        ("bash -xc 'sudo ls'".to_string(), "sudo is blocked"),
        (
            "bash -o pipefail -c 'sudo ls'".to_string(),
            "sudo is blocked",
        ),
        ("/bin/bash -c 'sudo ls'".to_string(), "sudo is blocked"),
        (
            "/usr/bin/env bash -c 'sudo ls'".to_string(),
            "sudo is blocked",
        ),
        ("env FOO=1 sh -c 'sudo ls'".to_string(), "sudo is blocked"),
        (
            "timeout 60 bash -c 'sudo ls'".to_string(),
            "sudo is blocked",
        ),
        (
            "nice -n 5 sh -c 'git push -f'".to_string(),
            "git push --force",
        ),
        // Inside lists, pipes, subshells; nested -c; a shell heredoc around it.
        (
            "cd /tmp && bash -c 'cd x; sudo ls'".to_string(),
            "sudo is blocked",
        ),
        (
            "echo hi | bash -c 'cat .env'".to_string(),
            "reading a secrets file",
        ),
        (
            "(bash -c 'git push --force')".to_string(),
            "git push --force",
        ),
        ("bash -c \"sh -c 'sudo ls'\"".to_string(), "sudo is blocked"),
        (
            "bash <<'EOF'⏎bash -c 'cat .env'⏎EOF".to_string(),
            "reading a secrets file",
        ),
        // A guard rule outside the string still wins over pip and keeps the Python guard's reason.
        (
            format!("bash -c '{p} install x'; sudo ls"),
            "sudo is blocked",
        ),
        (
            format!("bash -c 'cat .env'; {p} install x"),
            "reading a secrets file",
        ),
    ];
    let pip = [
        format!("bash -c '{p} install requests'"),
        format!("sh -c 'cd app && python3 -m {p} install -r r.txt'"),
        format!("bash -c \"sh -c '{p}3 install x'\""),
    ];
    let allow = [
        "bash -c 'ls -la'",
        "bash -c 'cat .env.example'",
        "bash -c 'echo hello'",
        "bash -c 'rm -rf /tmp/claude-scratch'",
        "bash -c 'git push --force-with-lease'",
        "bash -c 'rg -g \"!.env*\" --hidden token'",
        "bash -c 'rust-anything analyze .'",
        "bash -c",
        "bash script.sh",
        "bash -n script.sh",
        "bash --rcfile x.rc",
        // A string that doesn't parse is allowed, as a whole command is.
        "bash -c 'echo \"unterminated'",
        // Text that only mentions a blocked command.
        "echo 'bash -c sudo ls'",
        "git commit -m \"bash -c 'sudo ls' is blocked now\"",
        "python3 -c 'print(1)'",
    ];
    let mut fails = Vec::new();
    for (c, want) in &deny {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        let ok = o.code == 0
            && o.stdout.contains("\"permissionDecision\": \"deny\"")
            && o.stdout.contains(want);
        if !ok {
            fails.push(format!(
                "want deny ({want}) :: {c:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    for c in &pip {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str(), o.stderr.trim())
            != (
                2,
                "",
                "Do not use pip. Use uv instead. Example: uv add <packages>",
            )
        {
            fails.push(format!(
                "want pip :: {c:?} -> {} {}",
                o.code,
                o.stdout.trim()
            ));
        }
    }
    for c in &allow {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

/// Every rule also holds inside `eval ARG...`: its arguments joined with spaces, as eval runs them, nested or not.
/// Rust only, like the -c strings (the differential test lists them as a known difference).
#[test]
fn eval_strings_every_rule() {
    let p = "pip"; // kept apart so this file's text doesn't trip the live pip hook
    // (command, words the deny reason must hold)
    let deny = [
        ("eval sudo ls".to_string(), "sudo is blocked"),
        ("eval 'sudo ls'".to_string(), "sudo is blocked"),
        (
            "eval \"rm -rf /srv/app\"".to_string(),
            "recursive force delete",
        ),
        ("eval rm -fr ~/work".to_string(), "recursive force delete"),
        ("eval 'head -3 .env'".to_string(), "reading a secrets file"),
        ("eval grep -r token .".to_string(), "recursive grep"),
        (
            "eval 'rg --no-ignore token'".to_string(),
            "rg with --hidden",
        ),
        (
            "eval git push -f origin main".to_string(),
            "git push --force",
        ),
        (
            "eval 'rust-anything build rust/util'".to_string(),
            "rust-anything build",
        ),
        // Words split across arguments are joined first, as eval does.
        ("eval 'git' 'push' '-f'".to_string(), "git push --force"),
        ("eval 'sudo' ls".to_string(), "sudo is blocked"),
        // `--`, prefixes, lists and nesting with -c strings and other evals.
        ("eval -- sudo ls".to_string(), "sudo is blocked"),
        ("command eval sudo ls".to_string(), "sudo is blocked"),
        ("builtin eval 'sudo ls'".to_string(), "sudo is blocked"),
        ("cd x && eval 'sudo ls'".to_string(), "sudo is blocked"),
        (
            "if true; then eval 'git push --force'; fi".to_string(),
            "git push --force",
        ),
        ("eval \"bash -c 'sudo ls'\"".to_string(), "sudo is blocked"),
        ("bash -c \"eval 'sudo ls'\"".to_string(), "sudo is blocked"),
        ("eval 'eval sudo ls'".to_string(), "sudo is blocked"),
        // A guard rule outside the eval still wins and keeps the Python guard's reason.
        ("eval 'git push -f'; sudo ls".to_string(), "sudo is blocked"),
        (format!("eval 'sudo ls'; {p} install x"), "sudo is blocked"),
    ];
    let pip = [
        format!("eval {p} install requests"),
        format!("eval 'cd app && python3 -m {p} install -r r.txt'"),
        format!("bash -c \"eval '{p}3 install x'\""),
        format!("eval \"sh -c '{p} install x'\""),
    ];
    let allow = [
        "eval \"$(ssh-agent -s)\"",
        "eval \"$(/opt/homebrew/bin/brew shellenv)\"",
        "eval ls -la",
        "eval 'echo hi'",
        "eval 'rm -rf /tmp/claude-scratch'",
        "eval 'git push --force-with-lease'",
        "eval 'rust-anything map'",
        "eval",
        "eval --",
        // A string that doesn't parse is allowed, as a whole command is.
        "eval 'echo \"unterminated'",
        // Text that only mentions a blocked command.
        "echo eval sudo ls",
        "git commit -m 'eval sudo ls is blocked now'",
        "rg -n 'eval sudo' src",
    ];
    let mut fails = Vec::new();
    for (c, want) in &deny {
        let o = run(&["bash"], &bash_input(c));
        let ok = o.code == 0
            && o.stdout.contains("\"permissionDecision\": \"deny\"")
            && o.stdout.contains(want);
        if !ok {
            fails.push(format!(
                "want deny ({want}) :: {c:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    for c in &pip {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str(), o.stderr.trim())
            != (
                2,
                "",
                "Do not use pip. Use uv instead. Example: uv add <packages>",
            )
        {
            fails.push(format!(
                "want pip :: {c:?} -> {} {}",
                o.code,
                o.stdout.trim()
            ));
        }
    }
    for c in &allow {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

/// source and `.`: heredocs (checked since the Python guard), here-strings and `source <(echo ...)` (Rust only);
/// here-strings and process substitution fed to a shell too; and `xargs ... sh -c`. Every rule holds inside them.
#[test]
fn source_here_strings_and_xargs_every_rule() {
    let p = "pip"; // kept apart so this file's text doesn't trip the live pip hook
    // (command, words the deny reason must hold)
    let deny = [
        // Heredocs to source and `.` (the Python guard already checked these; pinned here).
        (
            "source /dev/stdin <<EOF⏎sudo ls⏎EOF".to_string(),
            "sudo is blocked",
        ),
        (
            ". /dev/stdin <<'EOF'⏎cat .env⏎EOF".to_string(),
            "reading a secrets file",
        ),
        (
            "source <<-EOF⏎\tgit push -f⏎\tEOF".to_string(),
            "git push --force",
        ),
        // Here-strings fed to source, `.` or a shell.
        (
            "source /dev/stdin <<< 'sudo ls'".to_string(),
            "sudo is blocked",
        ),
        (
            ". /dev/stdin <<< \"rm -rf /srv/app\"".to_string(),
            "recursive force delete",
        ),
        ("bash <<< 'grep -r token .'".to_string(), "recursive grep"),
        (
            "sh -s <<< 'rg --hidden token'".to_string(),
            "rg with --hidden",
        ),
        ("zsh<<<'git push --force'".to_string(), "git push --force"),
        (
            "bash <<< 'rust-anything build rust/util'".to_string(),
            "rust-anything build",
        ),
        (
            "timeout 9 bash <<< 'sudo ls'".to_string(),
            "sudo is blocked",
        ),
        // echo or printf output through process substitution.
        ("source <(echo 'sudo ls')".to_string(), "sudo is blocked"),
        (
            ". <(echo -n 'rm -rf /srv/app')".to_string(),
            "recursive force delete",
        ),
        (
            "source <(printf 'git push -f')".to_string(),
            "git push --force",
        ),
        (
            "bash <(echo 'cat .env')".to_string(),
            "reading a secrets file",
        ),
        // xargs in front of sh -c, with and without its own options.
        ("ls | xargs sh -c 'sudo ls'".to_string(), "sudo is blocked"),
        (
            "find . -name '*.md' | xargs -I{} sh -c 'git push -f'".to_string(),
            "git push --force",
        ),
        (
            "ls | xargs -n1 bash -c 'rm -rf /srv/app'".to_string(),
            "recursive force delete",
        ),
        (
            "ls | xargs -0 -P 4 bash -lc 'grep -r token .'".to_string(),
            "recursive grep",
        ),
        (
            "ls | xargs -I % sh -c 'rust-anything build %'".to_string(),
            "rust-anything build",
        ),
        // Nesting across the forms.
        (
            "source <(echo \"bash -c 'sudo ls'\")".to_string(),
            "sudo is blocked",
        ),
        ("bash <<< \"eval 'sudo ls'\"".to_string(), "sudo is blocked"),
        (
            "ls | xargs sh -c \"bash <<< 'sudo ls'\"".to_string(),
            "sudo is blocked",
        ),
        // A guard rule outside still wins and keeps the Python guard's reason.
        (
            "bash <<< 'git push -f'; sudo ls".to_string(),
            "sudo is blocked",
        ),
    ];
    let pip = [
        format!("source /dev/stdin <<< '{p} install x'"),
        format!("bash <<< 'python3 -m {p} install y'"),
        format!("source <(echo '{p} install x')"),
        format!("ls | xargs sh -c '{p}3 install x'"),
    ];
    let allow = [
        "source ~/.zshrc",
        ". ./venv/bin/activate",
        "source <(kubectl completion zsh)",
        "source <(echo 'export A=1')",
        "bash <<< 'ls -la'",
        "source /dev/stdin <<< 'echo hi'",
        "cat <<< 'sudo ls'",
        "grep x <<< 'git push -f'",
        "ls | xargs -I{} sh -c 'echo {}'",
        "ls | xargs rm -f",
        "ls | xargs sh -c 'git push --force-with-lease'",
        "source <(echo)",
        // A string that doesn't parse is allowed, as a whole command is.
        "bash <<< 'echo \"unterminated'",
    ];
    let mut fails = Vec::new();
    for (c, want) in &deny {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        let ok = o.code == 0
            && o.stdout.contains("\"permissionDecision\": \"deny\"")
            && o.stdout.contains(want);
        if !ok {
            fails.push(format!(
                "want deny ({want}) :: {c:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    for c in &pip {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str(), o.stderr.trim())
            != (
                2,
                "",
                "Do not use pip. Use uv instead. Example: uv add <packages>",
            )
        {
            fails.push(format!(
                "want pip :: {c:?} -> {} {}",
                o.code,
                o.stdout.trim()
            ));
        }
    }
    for c in &allow {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

/// echo or printf output piped into something that runs stdin as a script (bash, sh -s, zsh, `source /dev/stdin`,
/// `. /dev/fd/0`), checked line by line with every rule. Rust only (the differential test lists it as a known
/// difference).
#[test]
fn piped_scripts_every_rule() {
    let p = "pip"; // kept apart so this file's text doesn't trip the live pip hook
    // (command, words the deny reason must hold)
    let deny = [
        ("echo 'sudo ls' | bash".to_string(), "sudo is blocked"),
        ("echo sudo ls | sh".to_string(), "sudo is blocked"),
        (
            "echo 'rm -rf /srv/app' | sh -s".to_string(),
            "recursive force delete",
        ),
        (
            "echo 'head .env' | zsh".to_string(),
            "reading a secrets file",
        ),
        (
            "echo 'grep -r token .' | bash -x".to_string(),
            "recursive grep",
        ),
        (
            "echo 'rg --hidden token' | dash".to_string(),
            "rg with --hidden",
        ),
        ("echo 'git push -f' | ksh".to_string(), "git push --force"),
        (
            "echo 'rust-anything build x' | bash".to_string(),
            "rust-anything build",
        ),
        // source and `.` reading stdin.
        (
            "echo 'sudo ls' | source /dev/stdin".to_string(),
            "sudo is blocked",
        ),
        (
            "echo 'git push -f' | . /dev/stdin".to_string(),
            "git push --force",
        ),
        (
            "echo 'sudo ls' | source /dev/fd/0".to_string(),
            "sudo is blocked",
        ),
        (
            "echo 'sudo ls' | bash /dev/stdin".to_string(),
            "sudo is blocked",
        ),
        (
            "echo 'sudo ls' | bash -s -- arg".to_string(),
            "sudo is blocked",
        ),
        // printf: the format dropped when arguments follow it; \n read as a new line, each line checked.
        ("printf 'sudo ls\\n' | sh".to_string(), "sudo is blocked"),
        (
            "printf '%s\\n' 'git push -f' | bash".to_string(),
            "git push --force",
        ),
        (
            "printf -- 'cd x\\nsudo ls\\n' | sh".to_string(),
            "sudo is blocked",
        ),
        (
            "echo -e 'cd x\\nrm -rf /srv/app' | bash".to_string(),
            "recursive force delete",
        ),
        ("echo -n 'sudo ls' | bash".to_string(), "sudo is blocked"),
        // Prefixes and wrappers on either side; inside lists and subshells.
        (
            "env A=1 echo 'sudo ls' | env bash".to_string(),
            "sudo is blocked",
        ),
        (
            "echo 'sudo ls' | timeout 9 bash".to_string(),
            "sudo is blocked",
        ),
        (
            "cd x && echo 'sudo ls' | bash && ls".to_string(),
            "sudo is blocked",
        ),
        ("echo 'sudo ls' | (bash)".to_string(), "sudo is blocked"),
        (
            "/bin/echo 'sudo ls' | /bin/bash".to_string(),
            "sudo is blocked",
        ),
        // Nesting with the other forms.
        (
            "echo \"bash -c 'sudo ls'\" | sh".to_string(),
            "sudo is blocked",
        ),
        (
            "bash -c \"echo 'sudo ls' | sh\"".to_string(),
            "sudo is blocked",
        ),
        (
            "eval \"echo 'git push -f' | bash\"".to_string(),
            "git push --force",
        ),
        // A guard rule outside still wins and keeps the Python guard's reason.
        (
            "echo 'git push -f' | bash; sudo ls".to_string(),
            "sudo is blocked",
        ),
    ];
    let pip = [
        format!("echo '{p} install x' | bash"),
        format!("printf 'cd app\\npython3 -m {p} install y\\n' | sh"),
        format!("echo '{p}3 install x' | source /dev/stdin"),
        format!("bash -c \"echo '{p} install x' | sh\""),
    ];
    let allow = [
        "echo 'ls -la' | bash",
        "echo 'sudo ls' | cat",
        "echo 'sudo ls' | grep sudo",
        "echo 'sudo ls' | bash -c 'cat'",
        "echo 'sudo ls' | bash script.sh",
        "echo 'sudo ls' | source ./env.sh",
        "echo 'sudo ls' > notes.txt",
        "echo 'git push --force-with-lease' | sh",
        "echo 'rm -rf /tmp/claude-scratch' | bash",
        "printf '%s\\n' a b | sh -c 'xargs echo'",
        "echo | bash",
        "cat script.sh | bash",
        "echo \"$CMD\" | bash",
        // A line that doesn't parse is allowed, as a whole command is.
        "echo 'echo \"unterminated' | bash",
    ];
    let mut fails = Vec::new();
    for (c, want) in &deny {
        let o = run(&["bash"], &bash_input(c));
        let ok = o.code == 0
            && o.stdout.contains("\"permissionDecision\": \"deny\"")
            && o.stdout.contains(want);
        if !ok {
            fails.push(format!(
                "want deny ({want}) :: {c:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    for c in &pip {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str(), o.stderr.trim())
            != (
                2,
                "",
                "Do not use pip. Use uv instead. Example: uv add <packages>",
            )
        {
            fails.push(format!(
                "want pip :: {c:?} -> {} {}",
                o.code,
                o.stdout.trim()
            ));
        }
    }
    for c in &allow {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

/// A newline outside quotes and heredoc bodies ends a command, as `;` does, for every rule; backslash-newline
/// continues the line. Rust only: the Python guard read a newline as a space (the differential test lists it as a
/// known difference). ⏎ marks a newline.
#[test]
fn newline_separates_commands_every_rule() {
    let p = "pip"; // kept apart so this file's text doesn't trip the live pip hook
    // (command, words the deny reason must hold)
    let deny = [
        ("cd x⏎sudo ls", "sudo is blocked"),
        ("cd x⏎rm -rf /srv/app", "recursive force delete"),
        ("cd x⏎grep -r token .", "recursive grep"),
        ("cd x⏎rg --hidden token", "rg with --hidden"),
        ("cd x⏎git push -f", "git push --force"),
        ("cd x⏎rust-anything build rust/util", "rust-anything build"),
        ("ls⏎⏎⏎sudo ls", "sudo is blocked"),
        ("ls⏎  \tsudo ls", "sudo is blocked"),
        // A comment ends at its newline; the next line is still a command.
        ("ls # note⏎sudo ls", "sudo is blocked"),
        ("echo a#b⏎git push --force", "git push --force"),
        // A continued line, then a new command after the continuation.
        ("cd x \\⏎  && sudo ls", "sudo is blocked"),
        ("ls \\⏎  -la⏎sudo ls", "sudo is blocked"),
        // Blocks written over several lines.
        ("for f in *.md⏎do⏎  sudo ls⏎done", "sudo is blocked"),
        ("if true⏎then⏎  git push -f⏎fi", "git push --force"),
        ("{⏎  cd x⏎  sudo ls⏎}", "sudo is blocked"),
        // A heredoc's body is still data, and the line after its delimiter is a command.
        ("cat <<EOF⏎sudo ls⏎EOF⏎sudo ls", "sudo is blocked"),
        // Newlines inside strings run as commands.
        ("bash -c 'cd x⏎sudo ls'", "sudo is blocked"),
        ("eval 'cd x⏎git push -f'", "git push --force"),
        ("bash <<< 'cd x⏎sudo ls'", "sudo is blocked"),
        // A pipe continued on the next line still pipes.
        ("echo 'sudo ls' |⏎  bash", "sudo is blocked"),
        // A guard rule on the first line keeps the Python guard's reason.
        ("git push -f⏎sudo ls", "git push --force"),
    ];
    let allow = [
        "cd x⏎ls -la⏎pwd",
        "ls # sudo ls⏎pwd",
        "echo 'a⏎sudo b'",
        "git commit -m \"subject⏎⏎sudo ls is blocked now\"",
        "cat <<EOF⏎sudo ls⏎EOF",
        "cat <<'EOF' > notes.md⏎git push -f⏎EOF⏎ls",
        "cd x \\⏎  && ls",
        "printf 'a\\nb'⏎ls",
        "ls⏎",
        "⏎",
    ];
    let mut fails = Vec::new();
    for (c, want) in &deny {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        let ok = o.code == 0
            && o.stdout.contains("\"permissionDecision\": \"deny\"")
            && o.stdout.contains(want);
        if !ok {
            fails.push(format!(
                "want deny ({want}) :: {c:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    // block-pip already read the command line by line; a newline in a nested string now counts too.
    for c in [
        format!("cd x⏎{p} install y"),
        format!("bash -c 'cd x⏎{p} install y'"),
    ] {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        if (o.code, o.stdout.as_str()) != (2, "") {
            fails.push(format!(
                "want pip :: {c:?} -> {} {}",
                o.code,
                o.stdout.trim()
            ));
        }
    }
    for c in &allow {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn heredocs_in_quoted_strings_every_rule() {
    let p = "pip"; // kept apart so this file's text doesn't trip the live pip hook
    // (command, words the deny reason must hold)
    let deny = [
        // A heredoc fed to a shell inside a `bash -c` string: every rule.
        ("bash -c 'bash <<EOF⏎sudo ls⏎EOF'", "sudo is blocked"),
        (
            "bash -c 'sh <<EOF⏎rm -rf /srv/app⏎EOF'",
            "recursive force delete",
        ),
        ("sh -c 'bash <<EOF⏎cat .env⏎EOF'", ".env"),
        ("bash -c 'bash <<EOF⏎grep -r token .⏎EOF'", "recursive grep"),
        (
            "bash -c 'bash <<EOF⏎rg --hidden token⏎EOF'",
            "rg with --hidden",
        ),
        ("bash -c 'bash <<EOF⏎git push -f⏎EOF'", "git push --force"),
        (
            "bash -c 'bash <<EOF⏎rust-anything build rust/util⏎EOF'",
            "rust-anything build",
        ),
        // Quoted and tab-stripped delimiters, double-quoted strings, -lc.
        ("sh -c \"sh <<'X'⏎git push -f⏎X\"", "git push --force"),
        ("bash -lc 'bash <<-EOF⏎\tsudo ls⏎\tEOF'", "sudo is blocked"),
        (
            "bash -c 'source /dev/stdin <<EOF⏎sudo ls⏎EOF'",
            "sudo is blocked",
        ),
        // The line after a data heredoc's delimiter is a command again.
        ("bash -c 'cat <<EOF⏎x⏎EOF⏎sudo ls'", "sudo is blocked"),
        (
            "bash -c 'cat <<EOF > notes.md⏎x⏎EOF⏎rm -rf /srv/app'",
            "recursive force delete",
        ),
        // Other strings run as commands, and nesting.
        ("eval 'bash <<EOF⏎sudo ls⏎EOF'", "sudo is blocked"),
        ("bash <<< 'bash <<EOF⏎git push -f⏎EOF'", "git push --force"),
        (
            "bash -c \"bash -c 'bash <<EOF⏎sudo ls⏎EOF'\"",
            "sudo is blocked",
        ),
        // The Python reading takes a data heredoc whose line starts with a shell as fed to that shell; kept (it
        // fails closed).
        (
            "bash -c 'cat <<EOF > notes.md⏎sudo ls⏎EOF⏎ls'",
            "sudo is blocked",
        ),
        // A `<<WORD` in quotes or a comment is no heredoc, so it hides nothing.
        ("echo 'a <<EOF'⏎sudo ls", "sudo is blocked"),
        ("echo \"see <<EOF\"⏎git push -f⏎EOF", "git push --force"),
        ("ls # cat <<EOF⏎sudo ls", "sudo is blocked"),
        // A heredoc inside "$(...)" is code: its body fed to a shell is checked.
        ("x=\"$(bash <<EOF⏎sudo ls⏎EOF⏎)\"", "sudo is blocked"),
    ];
    let allow = [
        // Data heredocs inside strings stay data.
        "bash -c 'cat <<EOF⏎sudo ls⏎EOF'",
        "bash -c 'cat <<\"EOF\" > notes.md⏎# notes⏎EOF⏎ls'",
        "sh -c \"cat <<'X'⏎cat .env⏎X\"",
        "eval 'cat <<EOF⏎sudo ls⏎EOF'",
        // Claude's commit messages: the body is data even with odd quotes in it.
        "git commit -m \"$(cat <<'EOF'⏎Fix the \"quoted bug⏎⏎sudo ls and git push -f are blocked⏎EOF⏎)\"",
        "git commit -m \"$(cat <<'EOF'⏎don't block this⏎EOF⏎)\" && git log -1",
        "gh pr create --body \"$(cat <<'EOF'⏎`sudo ls` is blocked⏎EOF⏎)\"",
        // Not heredocs at all.
        "echo $((1<<2))",
        "echo 'a <<EOF'⏎ls",
    ];
    let mut fails = Vec::new();
    for (c, want) in &deny {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        let ok = o.code == 0
            && o.stdout.contains("\"permissionDecision\": \"deny\"")
            && o.stdout.contains(want);
        if !ok {
            fails.push(format!(
                "want deny ({want}) :: {c:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    for c in [
        format!("bash -c 'bash <<EOF⏎{p} install y⏎EOF'"),
        format!("bash -c 'cat <<EOF⏎x⏎EOF⏎{p} install y'"),
    ] {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        if (o.code, o.stdout.as_str()) != (2, "") {
            fails.push(format!(
                "want pip :: {c:?} -> {} {}",
                o.code,
                o.stdout.trim()
            ));
        }
    }
    for c in &allow {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn heredoc_piped_into_shell_every_rule() {
    let p = "pip"; // kept apart so this file's text doesn't trip the live pip hook
    // (command, words the deny reason must hold)
    let deny = [
        ("cat <<EOF | bash⏎sudo ls⏎EOF", "sudo is blocked"),
        (
            "cat <<EOF | bash⏎rm -rf /srv/app⏎EOF",
            "recursive force delete",
        ),
        ("cat <<EOF | sh⏎cat .env⏎EOF", ".env"),
        ("cat <<EOF | bash⏎grep -r token .⏎EOF", "recursive grep"),
        ("cat <<EOF | bash⏎rg --hidden token⏎EOF", "rg with --hidden"),
        ("cat <<EOF | bash⏎git push -f⏎EOF", "git push --force"),
        (
            "cat <<EOF | bash⏎rust-anything build rust/util⏎EOF",
            "rust-anything build",
        ),
        // Delimiter forms, readers of stdin, paths and wrappers.
        ("cat <<'X' | sh -s⏎git push -f⏎X", "git push --force"),
        ("cat <<\"X\" | zsh⏎sudo ls⏎X", "sudo is blocked"),
        ("cat <<-EOF | bash⏎\tsudo ls⏎\tEOF", "sudo is blocked"),
        (
            "cat <<EOF | source /dev/stdin⏎sudo ls⏎EOF",
            "sudo is blocked",
        ),
        ("cat <<EOF | . /dev/stdin⏎sudo ls⏎EOF", "sudo is blocked"),
        ("cat <<EOF | bash /dev/stdin⏎sudo ls⏎EOF", "sudo is blocked"),
        ("/bin/cat <<EOF | /bin/bash⏎sudo ls⏎EOF", "sudo is blocked"),
        ("cat <<EOF | timeout 9 bash⏎sudo ls⏎EOF", "sudo is blocked"),
        ("cat <<EOF|bash⏎sudo ls⏎EOF", "sudo is blocked"),
        ("cat - <<EOF | bash⏎sudo ls⏎EOF", "sudo is blocked"),
        ("tee run.log <<EOF | bash⏎sudo ls⏎EOF", "sudo is blocked"),
        ("cd x && cat <<EOF | bash⏎sudo ls⏎EOF", "sudo is blocked"),
        // Inside strings run as commands, and nested.
        ("bash -c 'cat <<EOF | bash⏎sudo ls⏎EOF'", "sudo is blocked"),
        ("eval 'cat <<EOF | sh⏎git push -f⏎EOF'", "git push --force"),
        ("x=\"$(cat <<EOF | bash⏎sudo ls⏎EOF⏎)\"", "sudo is blocked"),
        ("cat <<EOF | bash⏎bash -c 'sudo ls'⏎EOF", "sudo is blocked"),
    ];
    let allow = [
        // Piped into something that isn't a shell running stdin: data.
        "cat <<EOF | grep sudo⏎sudo ls⏎EOF",
        "cat <<EOF | tee notes.md⏎git push -f⏎EOF",
        "cat <<EOF | bash -c cat⏎sudo ls⏎EOF",
        "cat <<EOF | bash script.sh⏎sudo ls⏎EOF",
        "cat <<EOF > run.sh⏎sudo ls⏎EOF",
        "cat <<EOF | wc -l⏎rm -rf /srv/app⏎EOF",
        // Piped into a shell, but nothing in it breaks a rule.
        "cat <<EOF | bash⏎ls -la⏎git status⏎EOF",
        // Claude's commit messages.
        "git commit -m \"$(cat <<'EOF'⏎sudo ls | bash is blocked⏎EOF⏎)\"",
    ];
    let mut fails = Vec::new();
    for (c, want) in &deny {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        let ok = o.code == 0
            && o.stdout.contains("\"permissionDecision\": \"deny\"")
            && o.stdout.contains(want);
        if !ok {
            fails.push(format!(
                "want deny ({want}) :: {c:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    for c in [
        format!("cat <<EOF | bash⏎{p} install y⏎EOF"),
        format!("bash -c 'cat <<EOF | sh⏎{p} install y⏎EOF'"),
    ] {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        if (o.code, o.stdout.as_str()) != (2, "") {
            fails.push(format!(
                "want pip :: {c:?} -> {} {}",
                o.code,
                o.stdout.trim()
            ));
        }
    }
    for c in &allow {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn heredoc_through_filters_and_next_line_pipes_every_rule() {
    let p = "pip"; // kept apart so this file's text doesn't trip the live pip hook
    // (command, words the deny reason must hold)
    let deny = [
        // Any command reading the heredoc, piped into a shell: the body is checked as written.
        ("sed s/a/b/ <<EOF | bash⏎sudo ls⏎EOF", "sudo is blocked"),
        (
            "sed 's/x/y/' <<EOF | sh⏎rm -rf /srv/app⏎EOF",
            "recursive force delete",
        ),
        ("sed -e 's/x/y/' <<'X' | bash⏎cat .env⏎X", ".env"),
        (
            "sed s/a/b/ <<EOF | bash⏎grep -r token .⏎EOF",
            "recursive grep",
        ),
        (
            "sed s/a/b/ <<EOF | bash⏎rg --hidden token⏎EOF",
            "rg with --hidden",
        ),
        (
            "sed s/a/b/ <<EOF | bash⏎git push -f⏎EOF",
            "git push --force",
        ),
        (
            "sed s/a/b/ <<EOF | bash⏎rust-anything build rust/util⏎EOF",
            "rust-anything build",
        ),
        ("awk '{print}' <<EOF | bash⏎sudo ls⏎EOF", "sudo is blocked"),
        ("envsubst <<EOF | sh -s⏎sudo ls⏎EOF", "sudo is blocked"),
        (
            "tr a-z a-z <<EOF | source /dev/stdin⏎sudo ls⏎EOF",
            "sudo is blocked",
        ),
        // Filters between the heredoc and the shell.
        (
            "cat <<EOF | sed s/a/b/ | bash⏎sudo ls⏎EOF",
            "sudo is blocked",
        ),
        (
            "cat <<EOF | grep -v '^#' | sh⏎git push -f⏎EOF",
            "git push --force",
        ),
        // A line ending in `|`: the pipeline goes on after the bodies.
        ("cat <<EOF |⏎sudo ls⏎EOF⏎bash", "sudo is blocked"),
        (
            "cat <<EOF |⏎rm -rf /srv/app⏎EOF⏎sh",
            "recursive force delete",
        ),
        ("cat <<EOF |⏎cat .env⏎EOF⏎bash", ".env"),
        ("cat <<EOF |⏎grep -r token .⏎EOF⏎bash", "recursive grep"),
        ("cat <<EOF |⏎rg --hidden token⏎EOF⏎bash", "rg with --hidden"),
        ("cat <<EOF |⏎git push -f⏎EOF⏎bash", "git push --force"),
        (
            "cat <<EOF |⏎rust-anything build rust/util⏎EOF⏎bash",
            "rust-anything build",
        ),
        ("cat <<'X' |⏎sudo ls⏎X⏎  sh -s", "sudo is blocked"),
        (
            "cat <<EOF |⏎sudo ls⏎EOF⏎⏎# run it⏎timeout 9 bash",
            "sudo is blocked",
        ),
        (
            "cat <<EOF |⏎sudo ls⏎EOF⏎sed s/a/b/ | bash",
            "sudo is blocked",
        ),
        (
            "cat <<EOF |⏎sudo ls⏎EOF⏎sed s/a/b/ |⏎bash",
            "sudo is blocked",
        ),
        (
            "cat <<EOF | sed s/a/b/ |⏎sudo ls⏎EOF⏎bash",
            "sudo is blocked",
        ),
        (
            "sed s/a/b/ <<EOF |⏎sudo ls⏎EOF⏎source /dev/stdin",
            "sudo is blocked",
        ),
        ("cat <<-EOF |⏎\tsudo ls⏎\tEOF⏎bash", "sudo is blocked"),
        // Inside strings run as commands.
        ("bash -c 'cat <<EOF |⏎sudo ls⏎EOF⏎bash'", "sudo is blocked"),
        (
            "eval 'sed s/a/b/ <<EOF | sh⏎git push -f⏎EOF'",
            "git push --force",
        ),
    ];
    let allow = [
        "sed s/a/b/ <<EOF > run.sh⏎sudo ls⏎EOF",
        "sed s/a/b/ <<EOF | grep x⏎sudo ls⏎EOF",
        "grep -v x <<EOF | wc -l⏎rm -rf /srv/app⏎EOF",
        "cat <<EOF |⏎sudo ls⏎EOF⏎grep x",
        "cat <<EOF |⏎sudo ls⏎EOF⏎bash -c cat",
        "cat <<EOF |⏎sudo ls⏎EOF⏎tee notes.md",
        "cat <<EOF |⏎git push -f⏎EOF⏎wc -l⏎ls",
        "sed s/a/b/ <<EOF | bash⏎ls -la⏎EOF",
        "cat <<EOF |⏎ls -la⏎EOF⏎bash",
        "git commit -m \"$(cat <<'EOF'⏎sudo ls |⏎EOF⏎)\"",
    ];
    let mut fails = Vec::new();
    for (c, want) in &deny {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        let ok = o.code == 0
            && o.stdout.contains("\"permissionDecision\": \"deny\"")
            && o.stdout.contains(want);
        if !ok {
            fails.push(format!(
                "want deny ({want}) :: {c:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    for c in [
        format!("sed s/a/b/ <<EOF | bash⏎{p} install y⏎EOF"),
        format!("cat <<EOF |⏎{p} install y⏎EOF⏎bash"),
    ] {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        if (o.code, o.stdout.as_str()) != (2, "") {
            fails.push(format!(
                "want pip :: {c:?} -> {} {}",
                o.code,
                o.stdout.trim()
            ));
        }
    }
    for c in &allow {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

/// Each rule's command and the words its deny reason holds.
const EVERY_RULE: &[(&str, &str)] = &[
    ("sudo ls", "sudo is blocked"),
    ("rm -rf /srv/app", "recursive force delete"),
    ("cat .env", ".env"),
    ("grep -r token .", "recursive grep"),
    ("rg --hidden token", "rg with --hidden"),
    ("git push -f", "git push --force"),
    ("rust-anything build rust/util", "rust-anything build"),
];

/// Runs every template (`C` = a rule's command, `⏎` = newline) with every rule's command (deny with its reason) and
/// with a pip install (exit 2), and each allow case; fails listing every miss.
fn every_rule_table(templates: &[&str], allow: &[&str]) {
    every_rule_table_with("C", templates, allow);
}

/// `every_rule_table` with another placeholder for the command (`ph`), plus `@L@` and `@S@` for its words as a
/// double- or single-quoted list (`"git", "push", "-f"`), for templates whose text holds a capital C or an argv.
fn every_rule_table_with(ph: &str, templates: &[&str], allow: &[&str]) {
    let fill = |t: &str, c: &str| {
        let words: Vec<&str> = c.split_whitespace().collect();
        let dq = words
            .iter()
            .map(|w| format!("\"{w}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let sq = words
            .iter()
            .map(|w| format!("'{w}'"))
            .collect::<Vec<_>>()
            .join(", ");
        t.replace("@L@", &dq)
            .replace("@S@", &sq)
            .replace(ph, c)
            .replace('⏎', "\n")
    };
    let pip = format!("{} install y", "pip"); // kept apart so this file's text doesn't trip the live pip hook
    let mut fails = Vec::new();
    let mut checked = 0;
    for t in templates {
        for (c, want) in EVERY_RULE {
            let cmd = fill(t, c);
            let o = run(&["bash"], &bash_input(&cmd));
            checked += 1;
            if !(o.code == 0
                && o.stdout.contains("\"permissionDecision\": \"deny\"")
                && o.stdout.contains(want))
            {
                fails.push(format!(
                    "want deny ({want}) :: {cmd:?} -> {}",
                    o.stdout.trim()
                ));
            }
        }
        let cmd = fill(t, &pip);
        let o = run(&["bash"], &bash_input(&cmd));
        if (o.code, o.stdout.as_str()) != (2, "") {
            fails.push(format!(
                "want pip :: {cmd:?} -> {} {}",
                o.code,
                o.stdout.trim()
            ));
        }
    }
    for c in allow {
        let c = c.replace('⏎', "\n");
        let o = run(&["bash"], &bash_input(&c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(checked > 0);
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn case_patterns_in_substitutions_every_rule() {
    every_rule_table(
        &[
            // A case pattern's `)` doesn't end the `$(...)`, so the heredoc in the arm is still code.
            "x=\"$(case $y in a) bash <<EOF;; esac⏎C⏎EOF⏎)\"",
            "x=\"$(case $y in (a) sh <<EOF;; esac⏎C⏎EOF⏎)\"",
            "x=\"$(case $y in a) ;; b) bash <<EOF;; esac⏎C⏎EOF⏎)\"",
            // A heredoc behind `then` or an assignment.
            "if true; then bash <<EOF⏎C⏎EOF⏎fi",
            "X=1 bash <<EOF⏎C⏎EOF",
            // In "..." a `<<WORD` is text (bash reads no heredoc there): the lines after it are commands.
            "echo \"see <<EOF\"⏎C",
            "echo \"$(echo esac) <<EOF\"⏎C",
            // A "..." string run as a command is checked with its heredoc.
            "bash -c \"bash <<EOF⏎C⏎EOF\"",
            "eval \"cat <<EOF | sh⏎C⏎EOF\"",
        ],
        &[
            "git commit -m \"$(case $x in a) ;; esac; cat <<'EOF'⏎Fix \"odd⏎sudo ls⏎EOF⏎)\"",
            "x=\"$(case $y in a) cat <<EOF;; esac⏎sudo ls⏎EOF⏎)\"",
            "echo \"case <<EOF\"⏎ls",
            "echo case; x=\"$(echo a)\"⏎ls",
        ],
    );
}

#[test]
fn argv_wrappers_every_rule() {
    every_rule_table(
        &[
            "timeout 9 C",
            "timeout -s KILL 9 C",
            "timeout --signal=KILL -k 5 9 C",
            "gtimeout 9 C",
            "caffeinate -i C",
            "caffeinate -t 60 C",
            "stdbuf -oL C",
            "nice -n 5 C",
            "nice -5 C",
            "env -i C",
            "env -u HOME FOO=1 C",
            "xargs -I{} C",
            "xargs -n 1 -P 4 C",
            "setsid C",
            "ionice -c3 C",
            "ionice -c 2 -n 7 C",
            "arch -arm64 C",
            "arch -arch x86_64 C",
            "chroot /x C",
            "taskset 0x1 C",
            "chrt 10 C",
            "unbuffer C",
            "sandbox-exec -p '(version 1)' C",
            "doas C",
            "pkexec C",
            "exec -a name C",
            "time -p C",
            "timeout 9 nice -n 5 env -i C",
            "cd x && timeout 9 C",
        ],
        &[
            "command -v sudo",
            "timeout 9 ls -la",
            "nice -n 5 cargo build",
            "env -i PATH=/usr/bin ls",
            "xargs -I{} echo {}",
            "caffeinate -i cargo test",
        ],
    );
}

#[test]
fn ssh_strings_every_rule() {
    every_rule_table(
        &[
            "ssh host C",
            "ssh host 'C'",
            "ssh -p 22 -i key.pem host 'C'",
            "ssh -o BatchMode=yes host 'C'",
            "ssh -tt -- user@host 'C'",
            "ssh -J bastion host \"cd /app && C\"",
            "ssh host bash -c \"'C'\"",
            // stdin to a remote shell
            "ssh host <<EOF⏎C⏎EOF",
            "ssh host 'bash -s' <<'EOF'⏎C⏎EOF",
            "ssh host <<< 'C'",
            "echo 'C' | ssh host",
            "cat <<EOF | ssh host⏎C⏎EOF",
        ],
        &[
            "ssh host uptime",
            "ssh host 'cat /tmp/x' <<< 'sudo ls'",
            "ssh -p 22 host 'ls -la /srv'",
            "ssh host",
            "scp a host:/tmp/a",
        ],
    );
}

#[test]
fn find_exec_every_rule() {
    every_rule_table(
        &[
            "find . -exec C {} +",
            "find . -name x -exec C {} \\;",
            "find . -execdir C \\;",
            "find . -ok C {} \\;",
            "find . -type f -exec sh -c 'C' \\;",
            "find . -exec bash -c 'C' _ {} +",
        ],
        &[
            "find . -name '*.tmp' -exec rm -rf {} +",
            "find /tmp/x -exec rm -rf {} +",
            "find . -exec ls -la {} +",
            "find . -name x -print",
        ],
    );
    // `{}` is each start path.
    let o = run(
        &["bash"],
        &bash_input("find /srv/old -mtime +7 -exec rm -rf {} +"),
    );
    assert!(o.stdout.contains("recursive force delete"), "{}", o.stdout);
}

#[test]
fn user_switch_strings_every_rule() {
    every_rule_table(
        &[
            "su -c 'C'",
            "su root -c 'C'",
            "su - app -c 'C'",
            "su --command='C' app",
            "su -l app --command 'C'",
            "runuser -c 'C' app",
            "runuser -u app -- C",
            "runuser -u app C",
            "sg docker -c 'C'",
            "sg docker 'C'",
        ],
        &[
            "su -c 'ls -la' app",
            "runuser -u app -- ls",
            "sg docker -c 'docker ps'",
        ],
    );
}

#[test]
fn container_commands_every_rule() {
    every_rule_table(
        &[
            "docker exec web C",
            "docker exec -it web sh -c 'C'",
            "docker exec -u root -w /app web bash -c 'C'",
            "docker exec -e A=1 --env-file e web C",
            "docker container exec web C",
            "docker --context prod exec web C",
            "docker run --rm node:22 C",
            "docker run --rm -v a:/b -e X=1 -p 80:80 --name n node:22 sh -c 'C'",
            "docker run --entrypoint sh img -c 'C'",
            "podman exec web C",
            "nerdctl run img C",
            "docker compose exec app C",
            "docker compose -f dc.yml run --rm app sh -c 'C'",
            "docker-compose exec app bash -c 'C'",
            "kubectl exec pod -- C",
            "kubectl -n prod exec -it pod -c app -- sh -c 'C'",
            "oc exec pod -- C",
            // stdin into a shell in the container
            "docker exec -i web sh <<EOF⏎C⏎EOF",
            "docker exec -i web sh <<< 'C'",
            "echo 'C' | kubectl exec -i pod -- bash",
        ],
        &[
            "docker ps",
            "docker run --rm node:22 node -v",
            "docker exec web ls -la",
            "docker compose up -d",
            "kubectl get pods",
            "kubectl exec pod -- ls",
            "docker logs web",
        ],
    );
}

#[test]
fn string_runners_every_rule() {
    every_rule_table(
        &[
            "watch 'C'",
            "watch -n 1 'C'",
            "watch --interval 5 -d C",
            "script -q /dev/null C",
            "script -c 'C' /tmp/log",
            "flock /tmp/l -c 'C'",
            "flock -w 5 /tmp/l C",
            "env -S 'C'",
            "env -S'C'",
        ],
        &[
            "watch -n 1 'ls -la'",
            "script -q /dev/null ls",
            "flock /tmp/l -c 'ls'",
            "env -S 'ls -la'",
        ],
    );
}

#[test]
fn heredoc_output_run_every_rule() {
    every_rule_table(
        &[
            "eval \"$(cat <<EOF⏎C⏎EOF⏎)\"",
            "eval \"$(cat <<'EOF'⏎C⏎EOF⏎)\"",
            "bash -c \"$(cat <<EOF⏎C⏎EOF⏎)\"",
            "$(cat <<EOF⏎C⏎EOF⏎)",
            "bash <(cat <<EOF⏎C⏎EOF⏎)",
            "source <(cat <<EOF⏎C⏎EOF⏎)",
            ". <(sed s/a/b/ <<EOF⏎C⏎EOF⏎)",
            "timeout 9 bash <<EOF⏎C⏎EOF",
            "env bash <<EOF⏎C⏎EOF",
        ],
        &[
            "x=\"$(cat <<EOF⏎sudo ls⏎EOF⏎)\"",
            "echo \"$(cat <<EOF⏎sudo ls⏎EOF⏎)\"",
            "git commit -m \"$(cat <<'EOF'⏎sudo ls⏎EOF⏎)\"",
            "diff <(cat <<EOF⏎sudo ls⏎EOF⏎) b.txt",
        ],
    );
}

#[test]
fn variables_every_rule() {
    every_rule_table(
        &[
            "c='C'; bash -c \"$c\"",
            "c='C'⏎eval \"$c\"",
            "export c='C'; sh -c \"${c}\"",
            "local c='C'; $c",
            "c='C'; $c",
            "c=\"C\" && ssh host \"$c\"",
            "declare -r c='C'; echo \"$c\" | bash",
        ],
        &[
            "msg='sudo ls is blocked'; echo \"$msg\"",
            "d=$(mktemp -d); rm -rf \"$d\"",
            "d=/tmp/x; rm -rf \"$d\"",
            "PATH=$PATH:/x; ls",
            "c='git status'; $c",
        ],
    );
    let o = run(&["bash"], &bash_input("d=/srv/app; rm -rf \"$d\""));
    assert!(o.stdout.contains("recursive force delete"), "{}", o.stdout);
}

#[test]
fn scripts_written_and_run_every_rule() {
    every_rule_table(
        &[
            "cat > run.sh <<EOF⏎C⏎EOF⏎bash run.sh",
            "cat <<'EOF' > run.sh⏎C⏎EOF⏎chmod +x run.sh && ./run.sh",
            "cat >> /tmp/run.sh <<EOF⏎C⏎EOF⏎sh /tmp/run.sh",
            "tee run.sh <<EOF >/dev/null⏎C⏎EOF⏎source ./run.sh",
            "echo 'C' > run.sh; sh ./run.sh",
            "printf '%s\\n' 'C' > run.sh && . run.sh",
            "cat > run.sh <<EOF⏎C⏎EOF⏎timeout 9 bash -x run.sh",
        ],
        &[
            "cat > notes.md <<EOF⏎sudo ls⏎EOF⏎cat notes.md",
            "echo 'sudo ls' > notes.txt; wc -l notes.txt",
            "cat > run.sh <<EOF⏎ls -la⏎EOF⏎bash run.sh",
            "cat > a.sh <<EOF⏎sudo ls⏎EOF⏎bash b.sh",
            // A segment that is only a redirection (crashed once).
            "> run.sh",
            "gojq$( > head",
        ],
    );
}

#[test]
fn script_files_on_disk_every_rule() {
    let dir = format!(
        "{}/claude-guard-table-scripts-{}",
        tmpdir(),
        std::process::id()
    );
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(format!("{dir}/scripts/sub")).unwrap();
    let write = |name: &str, text: &str| std::fs::write(format!("{dir}/{name}"), text).unwrap();
    let pip = format!("{} install y", "pip"); // kept apart so this file's text doesn't trip the live pip hook
    let mut bodies: Vec<(String, String)> = EVERY_RULE
        .iter()
        .map(|(c, want)| (c.to_string(), want.to_string()))
        .collect();
    bodies.push((pip.clone(), String::new()));
    // Fed to a shell by name or on stdin, run as the command, behind a wrapper, through ssh.
    let templates = [
        "bash F",
        "sh -x F",
        "zsh F",
        "source F",
        ". ./F",
        "./F",
        "cat F | bash",
        "cat -- F | sh -s",
        "bash < F",
        "timeout 9 bash F",
        "ssh host < F",
        "cd x; bash F",
    ];
    let mut fails = Vec::new();
    let mut checked = 0;
    for (i, (body, want)) in bodies.iter().enumerate() {
        // A shell script with a shebang, one without, and one that sources another.
        write(
            &format!("scripts/r{i}.sh"),
            &format!("#!/usr/bin/env bash\nset -euo pipefail\necho start\n{body}\n"),
        );
        write(&format!("scripts/plain{i}"), &format!("ls\n{body}\n"));
        write(
            &format!("scripts/outer{i}.sh"),
            &format!("#!/bin/sh\n. scripts/sub/inner{i}.sh\n"),
        );
        write(&format!("scripts/sub/inner{i}.sh"), &format!("{body}\n"));
        let mut cmds: Vec<String> = templates
            .iter()
            .map(|t| t.replace('F', &format!("scripts/r{i}.sh")))
            .collect();
        cmds.push(format!("./scripts/plain{i}"));
        cmds.push(format!("bash scripts/outer{i}.sh"));
        cmds.push(format!("bash {dir}/scripts/r{i}.sh"));
        for cmd in cmds {
            let input = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": dir}).to_string();
            let o = run(&["bash"], &input);
            checked += 1;
            let ok = if want.is_empty() {
                (o.code, o.stdout.as_str()) == (2, "")
            } else {
                o.code == 0 && o.stdout.contains("\"deny\"") && o.stdout.contains(want.as_str())
            };
            if !ok {
                fails.push(format!(
                    "want {} :: {cmd:?} -> {} {}",
                    if want.is_empty() { "pip" } else { want },
                    o.code,
                    o.stdout.trim()
                ));
            }
        }
    }
    // Not read, or nothing to block.
    write("scripts/ok.sh", "#!/bin/sh\nls -la\ngit status\n");
    write(
        "scripts/tool.js",
        "#!/usr/bin/env node\nconsole.log('x')\nsudo ls\n",
    );
    write("scripts/a.sh", ". scripts/b.sh\nls\n");
    write("scripts/b.sh", ". scripts/a.sh\npwd\n");
    std::fs::copy("/bin/ls", format!("{dir}/scripts/bin")).unwrap();
    let mut bin = std::fs::read(format!("{dir}/scripts/bin")).unwrap();
    bin.extend(b"\nsudo ls\n");
    std::fs::write(format!("{dir}/scripts/bin"), bin).unwrap();
    let allow = [
        "bash scripts/ok.sh",
        "./scripts/ok.sh",
        "cat scripts/ok.sh | bash",
        "./scripts/tool.js", // another interpreter's shebang, run as the command
        "./scripts/bin",     // a binary
        "bash scripts/a.sh", // scripts that source each other: each read once
        "bash scripts/missing.sh",
        "bash scripts",          // a directory
        "cat scripts/r0.sh",     // reading isn't running
        "bash -n scripts/r0.sh", // syntax check only
        "bash -c 'echo hi' scripts/r0.sh",
        "less scripts/r0.sh",
    ];
    for cmd in allow {
        let input =
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": dir})
                .to_string();
        let o = run(&["bash"], &input);
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!(
                "want allow :: {cmd:?} -> {} {}",
                o.code,
                o.stdout.trim()
            ));
        }
    }
    // A harmless script turned into a blocked one by a filter on the way to the shell.
    for cmd in [
        "cat scripts/ok.sh | sed 's/^/sudo /' | bash",
        "cat scripts/ok.sh | awk '{print \"sudo \" $0}' | sh",
    ] {
        let input =
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": dir})
                .to_string();
        let o = run(&["bash"], &input);
        if !o.stdout.contains("sudo is blocked") {
            fails.push(format!(
                "want deny (sudo, filtered script) :: {cmd:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    // Outside the project and temp folders (a tool or dotfile): not read.
    let outside = format!(
        "{}/claude-guard-outside-{}.sh",
        env!("CARGO_TARGET_TMPDIR"),
        std::process::id()
    );
    std::fs::write(&outside, "sudo ls\n").unwrap();
    for cmd in [format!("bash {outside}"), format!("source {outside}")] {
        let input =
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": dir})
                .to_string();
        let o = run(&["bash"], &input);
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!(
                "want allow (outside) :: {cmd:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    let _ = std::fs::remove_file(&outside);
    // Relative paths need a text cwd; without one the file isn't read.
    let o = run(&["bash"], &bash_input("bash scripts/r0.sh"));
    if (o.code, o.stdout.as_str()) != (0, "") {
        fails.push(format!("want allow without cwd -> {}", o.stdout.trim()));
    }
    // Over the size cap: blocked, not checked in part.
    write("scripts/big.sh", &"ls\n".repeat(100_000));
    let input = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "bash scripts/big.sh"}, "cwd": dir}).to_string();
    let o = run(&["bash"], &input);
    if !o.stdout.contains("too big for the guard to check") {
        fails.push(format!("want too big -> {}", o.stdout.trim()));
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(checked > 0);
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn test_brackets_are_existence_tests() {
    // `[[ ... ]]`, `[ ! ... ]` and `test ! ...` only test a file; what follows them is still checked.
    every_rule_table(
        &[
            "[[ -f .env ]] && C",
            "[[ -f .env && -s .env ]] || C",
            "[[ ! -e .env ]]; C",
            "if [[ -r .envrc ]]; then C; fi",
            "[ ! -f .env ] && C",
            "test ! -f .env || C",
            // A substitution inside the test is run.
            "[[ \"$(C)\" == x ]]",
            "[ -n \"$(C)\" ]",
        ],
        &[
            "[[ -f .env ]]",
            "[[ -e .env.local ]] && echo y",
            "[[ -f .env && -s .env ]]",
            "[[ ! -f .env ]] && cp .env.example .env",
            "[[ -f .env || -f .env.local ]]",
            "[[ -r .envrc ]]",
            "if [[ -f .env.production ]]; then echo prod; fi",
            "[[ -f prod.env ]] && echo y",
            "[ ! -f .env ]",
            "[ ! -e .env ] && touch .env",
            "test ! -f .env",
            "[ \\( -f .env \\) ]",
            "[[ $x =~ ^(a|b)$ ]] && echo y",
        ],
    );
    // Reading the file after the test is still blocked.
    for c in [
        "[[ -f .env ]] && source .env",
        "[[ -f .env ]] && cat .env",
        "[ -f .env ] && . ./.env",
    ] {
        let o = run(&["bash"], &bash_input(c));
        assert!(
            o.stdout.contains("reading a secrets file"),
            "{c} -> {}",
            o.stdout
        );
    }
}

#[test]
fn substitutions_in_double_quotes_and_backticks_every_rule() {
    every_rule_table(
        &[
            "echo \"$(C)\"",
            "x=\"$(C)\"",
            "echo \"a $(C) b\"",
            "echo \"$(echo \"$(C)\")\"",
            "echo `C`",
            "echo \"`C`\"",
            "x=`C`",
            "printf '%s' \"$(cd x && C)\"",
            "git commit -m \"fix `C`\"",
        ],
        &[
            "echo \"$((1+2)) $(date) `date`\"",
            "echo '$(sudo ls)' '`git push -f`'",
            "git commit -m \"$(cat <<'EOF'⏎fix: sudo ls and git push -f are blocked⏎EOF⏎)\"",
            "x=\"$(git rev-parse HEAD)\"",
            "echo \"$HOME $(pwd)\"",
            "# echo \"$(sudo ls)\"",
        ],
    );
    let o = run(&["bash"], &bash_input("x=\"$(<.env)\""));
    assert!(o.stdout.contains("reading a secrets file"), "{}", o.stdout);
}

#[test]
fn filters_that_build_commands_every_rule() {
    // A filter on the way to a shell builds the command from a harmless body (`C` = the rule's command).
    every_rule_table(
        &[
            "sed 's#^#C #' <<EOF | bash⏎x⏎EOF",
            "sed 's#.*#C#' <<EOF | sh⏎ls⏎EOF",
            "sed -e 's#x#C#' <<'EOF' | bash⏎x⏎EOF",
            "sed -E 's#(.*)#C#' <<EOF | bash⏎ls⏎EOF",
            "sed 's#\\(.*\\)#C#g' <<EOF | bash⏎ls⏎EOF",
            "sed '1i C' <<EOF | bash⏎ls⏎EOF",
            "sed '$a C' <<EOF | bash⏎ls⏎EOF",
            "sed 's#a#b#;s#^#C #' <<EOF | bash⏎ls⏎EOF",
            "gsed -n -e 's#^#C #' <<EOF | bash⏎x⏎EOF",
            "cat <<EOF | sed 's#^#C #' | bash⏎x⏎EOF",
            "cat <<EOF | grep -v '^$' | sed 's#^#C #' | sh -s⏎x⏎EOF",
            "cat <<EOF |⏎x⏎EOF⏎sed 's#^#C #' | bash",
            "awk '{print \"C \" $0}' <<EOF | bash⏎x⏎EOF",
            "awk 'BEGIN{print \"C\"}' <<EOF | sh⏎ls⏎EOF",
            "perl -pe 's#^#C #' <<EOF | bash⏎x⏎EOF",
            "echo x | sed 's#^#C #' | bash",
            "printf 'x\\n' | awk '{print \"C \" $0}' | sh",
            "bash -c \"sed 's#^#C #' <<EOF | bash⏎x⏎EOF\"",
            "x=\"$(sed 's#^#C #' <<EOF | bash⏎x⏎EOF⏎)\"",
        ],
        &[
            "sed 's/^/# /' <<EOF | bash⏎ls⏎EOF",
            "sed 's/^/sudo /' <<EOF⏎ls⏎EOF",
            "sed 's/^/sudo /' <<EOF | grep x⏎ls⏎EOF",
            "sed 's/x/y/' <<EOF | bash⏎ls -la⏎EOF",
            "awk '{print $1}' <<EOF | bash⏎ls -la⏎EOF",
            "echo ls | sed 's/^/echo /' | bash",
            "git commit -m \"$(cat <<'EOF'⏎a & b; c (d) sudo⏎EOF⏎)\"",
        ],
    );
    // The body as written is still checked: a filter that removes a line fails closed.
    let o = run(
        &["bash"],
        &bash_input("sed 's/sudo //' <<EOF | bash\nsudo ls\nEOF"),
    );
    assert!(o.stdout.contains("sudo is blocked"), "{}", o.stdout);
}

#[test]
fn commands_sed_and_awk_run_every_rule() {
    // awk system(), "CMD" | getline, print | "CMD"; sed `e CMD`, a bare `e`, `s///e` (`C` = the rule's command).
    every_rule_table(
        &[
            "awk 'BEGIN{system(\"C\")}'",
            "awk '{system(\"C \" $1)}' f.txt",
            "awk 'BEGIN { \"C\" | getline x }'",
            "awk '{print \"C\" | \"sh\"}' f.txt",
            "awk 'BEGIN{print \"x\" | \"C\"}'",
            "gawk -F, -v a=1 'BEGIN { system(\"C\") }'",
            "awk '{system(\"C\")}' <<EOF⏎x⏎EOF",
            "echo x | awk '{system(\"C\")}'",
            "sed 'e C' f.txt",
            "sed '1e C' f.txt",
            "sed -n '$e C' f.txt",
            "sed 's#.*#C#e' f.txt",
            "sed 's#^#C #e' <<EOF⏎x⏎EOF",
            "echo x | sed 's#.*#C#e'",
            "sed e <<EOF⏎C⏎EOF",
            "cat <<EOF | sed 's#^#C #e'⏎x⏎EOF",
            "bash -c \"sed 'e C' f.txt\"",
            "timeout 9 awk 'BEGIN{system(\"C\")}'",
        ],
        &[
            "awk '{print $1}' f.txt",
            "awk 'BEGIN{system(\"ls -la\")}'",
            "sed 's/x/y/' f.txt",
            "sed -e 's/e/E/g' f.txt",
            "sed '/^#/d;s/edge/x/' f.txt",
            "echo 'see the e command' | sed 's/see/x/'",
            "sed 's/^/echo /e' <<EOF⏎hello⏎EOF",
            "sed -n '/end/p' f.txt",
        ],
    );
}

#[test]
fn interpreter_code_every_rule() {
    // `@@` = the rule's command; `@L@` / `@S@` = its words as a quoted list.
    every_rule_table_with(
        "@@",
        &[
            // perl
            "perl -e 'system(\"@@\")'",
            "perl -e 'system @L@'",
            "perl -le 'print `@@`'",
            "perl -e 'my $x = qx{@@}'",
            "perl -ne 'exec(\"@@\")' f.txt",
            "perl -e 'open(my $f, \"-|\", @L@)'",
            "perl -e 'open(F, \"@@ |\")'",
            "perl - <<'EOF'⏎system(\"@@\");⏎EOF",
            // python
            "python3 -c 'import os; os.system(\"@@\")'",
            "python3 -c \"import subprocess; subprocess.run([@S@])\"",
            "python3 -c 'import subprocess as sp; sp.check_output(\"@@\", shell=True)'",
            "python -c 'from subprocess import run; run([@L@])'",
            "python3.12 -c 'import os; os.popen(f\"@@\")'",
            "python3 - <<EOF⏎import os⏎os.system(\"@@\")⏎EOF",
            "python3 <<'EOF'⏎import subprocess⏎subprocess.call(\"@@\", shell=True)⏎EOF",
            "echo 'import os; os.system(\"@@\")' | python3",
            // node, bun, deno
            "node -e 'require(\"child_process\").execSync(\"@@\")'",
            "node -e \"const {spawnSync} = require('child_process'); spawnSync(@S@)\"",
            "node -e 'const cp = require(\"node:child_process\"); cp.exec(`@@`)'",
            "node <<EOF⏎require('child_process').execSync('@@')⏎EOF",
            "bun -e 'Bun.spawn([@L@])'",
            "bun -e 'await $`@@`'",
            "deno eval 'Deno.run({cmd: [@L@]})'",
            "deno eval 'new Deno.Command(\"bash\", {args: [\"-c\", \"@@\"]}).outputSync()'",
            // ruby
            "ruby -e 'system(\"@@\")'",
            "ruby -e 'system @L@'",
            "ruby -e 'puts `@@`'",
            "ruby -e 'x = %x(@@)'",
            "ruby -e 'IO.popen([@L@]).read'",
            "ruby -e 'require \"open3\"; Open3.capture2(\"@@\")'",
            // php, lua, osascript
            "php -r 'shell_exec(\"@@\");'",
            "php -r 'echo `@@`;'",
            "php -r 'proc_open([@L@], [], $p);'",
            "lua -e 'os.execute(\"@@\")'",
            "lua -e 'io.popen(\"@@\")'",
            "osascript -e 'do shell script \"@@\"'",
            // behind a wrapper
            "timeout 9 python3 -c 'import os; os.system(\"@@\")'",
        ],
        &[
            "python3 -c 'print(\"sudo ls\")'",
            "perl -e 'my $exec = \"sudo ls\"; print $exec'",
            "php -r '$pdo->exec(\"DELETE FROM t\");'",
            "node -e 'console.log(/x/.exec(\"sudo ls\"))'",
            "python3 -c 'import os; os.system(\"ls -la\")'",
            "ruby -e 'puts \"system(\\\"sudo ls\\\")\"'",
            "python3 -m http.server",
            "node --version",
            "python3 -c 'exec(\"print(1)\")'",
            "node -e 'require(\"child_process\").execSync(\"git status\")'",
            // An interpolation is a placeholder word: a path built on one stays relative.
            "python3 -c 'import os; os.system(f\"rm -rf {d}/build\")'",
            "node -e 'require(\"child_process\").execSync(`rm -rf ${dir}/node_modules`)'",
        ],
    );
    // ...and one that was absolute before it stays absolute.
    for c in [
        "node -e 'require(\"child_process\").execSync(`rm -rf /srv/${name}`)'",
        "ruby -e 'system(\"rm -rf /srv/#{x}\")'",
    ] {
        let o = run(&["bash"], &bash_input(c));
        assert!(
            o.stdout.contains("recursive force delete"),
            "{c} -> {}",
            o.stdout
        );
    }
}

#[test]
fn interpreter_script_files_every_rule() {
    let dir = format!(
        "{}/claude-guard-table-interp-{}",
        tmpdir(),
        std::process::id()
    );
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(format!("{dir}/scripts")).unwrap();
    std::fs::create_dir_all(format!("{dir}/node_modules/pkg")).unwrap();
    let write = |name: &str, text: &str| std::fs::write(format!("{dir}/{name}"), text).unwrap();
    let pip = format!("{} install y", "pip");
    let mut bodies: Vec<(String, String)> = EVERY_RULE
        .iter()
        .map(|(c, want)| (c.to_string(), want.to_string()))
        .collect();
    bodies.push((pip, String::new()));
    let mut fails = Vec::new();
    for (i, (c, want)) in bodies.iter().enumerate() {
        write(
            &format!("scripts/r{i}.py"),
            &format!("import os\nos.system(\"{c}\")\n"),
        );
        write(
            &format!("scripts/r{i}.js"),
            &format!("const cp = require('child_process');\ncp.execSync('{c}');\n"),
        );
        write(&format!("scripts/r{i}.rb"), &format!("system(\"{c}\")\n"));
        write(&format!("scripts/r{i}.pl"), &format!("system(\"{c}\");\n"));
        write(
            &format!("scripts/r{i}.php"),
            &format!("<?php\nshell_exec(\"{c}\");\n"),
        );
        write(
            &format!("scripts/r{i}.lua"),
            &format!("os.execute(\"{c}\")\n"),
        );
        write(
            &format!("scripts/x{i}"),
            &format!(
                "#!/usr/bin/env python3\nimport subprocess\nsubprocess.run(\"{c}\", shell=True)\n"
            ),
        );
        for cmd in [
            format!("python3 scripts/r{i}.py"),
            format!("node scripts/r{i}.js"),
            format!("bun run scripts/r{i}.js"),
            format!("ruby scripts/r{i}.rb"),
            format!("perl scripts/r{i}.pl"),
            format!("php scripts/r{i}.php"),
            format!("lua scripts/r{i}.lua"),
            format!("./scripts/x{i}"),
            format!("timeout 9 python3 -u scripts/r{i}.py"),
        ] {
            let input = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": dir}).to_string();
            let o = run(&["bash"], &input);
            let ok = if want.is_empty() {
                (o.code, o.stdout.as_str()) == (2, "")
            } else {
                o.code == 0 && o.stdout.contains("\"deny\"") && o.stdout.contains(want.as_str())
            };
            if !ok {
                fails.push(format!(
                    "want {} :: {cmd:?} -> {} {}",
                    if want.is_empty() { "pip" } else { want },
                    o.code,
                    o.stdout.trim()
                ));
            }
        }
    }
    // Not read: third-party code, a script over the cap (skipped, not blocked), harmless code.
    write(
        "node_modules/pkg/x.js",
        "require('child_process').execSync('sudo ls')\n",
    );
    write(
        "scripts/big.js",
        &format!(
            "require('child_process').execSync('sudo ls');\n{}",
            "//\n".repeat(100_000)
        ),
    );
    write("scripts/ok.py", "import os\nos.system('ls -la')\n");
    for cmd in [
        "node node_modules/pkg/x.js",
        "node scripts/big.js",
        "python3 scripts/ok.py",
        "python3 scripts/missing.py",
    ] {
        let input =
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": dir})
                .to_string();
        let o = run(&["bash"], &input);
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {cmd:?} -> {}", o.stdout.trim()));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn interpreter_variables_and_eval_every_rule() {
    // `@@` = the rule's command; `@L@` = its words as a list. Built through variables, joins, formats and eval.
    every_rule_table_with(
        "@@",
        &[
            // python
            "python3 -c 'import os; cmd = \"@@\"; os.system(cmd)'",
            "python3 -c 'import subprocess; args = [@L@]; subprocess.run(args)'",
            "python3 -c 'import os; os.system(\" \".join([@L@]))'",
            "python3 -c 'import os; x = \"@@\"; os.system(f\"{x}\")'",
            "python3 -c 'import os; os.system(\"%s\" % \"@@\")'",
            "python3 -c 'import os; os.system(\"{}\".format(\"@@\"))'",
            "python3 -c 'c = \"\"; c += \"@@\"; import os; os.system(c)'",
            "python3 -c '__import__(\"os\").system(\"@@\")'",
            "python3 -c 'exec(\"import os; os.system(\\\"@@\\\")\")'",
            "python3 - <<EOF⏎c = \"@@\"⏎import os⏎os.system(c)⏎EOF",
            // node
            "node -e 'const cp = require(\"child_process\"); const c = \"@@\"; cp.execSync(c)'",
            "node -e 'const cp = require(\"child_process\"); const c = \"@@\"; cp.execSync(`${c}`)'",
            "node -e 'const cp = require(\"child_process\"); cp.execSync([@L@].join(\" \"))'",
            "node -e 'eval(\"require(\\\"child_process\\\").execSync(\\\"@@\\\")\")'",
            "node -e 'new Function(\"require(\\\"child_process\\\").execSync(\\\"@@\\\")\")()'",
            // ruby
            "ruby -e 'c = \"@@\"; system(c)'",
            "ruby -e 'c = \"@@\"; system(\"#{c}\")'",
            "ruby -e 'eval(\"system(\\\"@@\\\")\")'",
            // perl
            "perl -e 'my $c = \"@@\"; system($c)'",
            "perl -e 'my @a = (@L@); system(@a)'",
            "perl -e 'my $c = \"@@\"; system(\"$c\")'",
            "perl -e 'eval \"system(\\\"@@\\\")\"'",
            "perl -e 'my $c = join(\" \", @L@); system $c'",
            // php, lua, osascript
            "php -r '$c = \"@@\"; shell_exec($c);'",
            "php -r 'eval(\"shell_exec(\\\"@@\\\");\");'",
            "lua -e 'local c = \"@@\"; os.execute(c)'",
            "lua -e 'load(\"os.execute(\\\"@@\\\")\")()'",
            "osascript -e 'set c to \"@@\"' -e 'do shell script c'",
        ],
        &[
            "python3 -c 'import os; cmd = \"ls -la\"; os.system(cmd)'",
            "python3 -c 'x = \"sudo ls\"; print(x)'",
            "node -e 'const cp = require(\"child_process\"); const d = process.argv[1]; cp.execSync(`rm -rf ${d}/build`)'",
            "python3 -c 'import os, sys; p = sys.argv[1]; os.system(f\"rm -rf {p}/build\")'",
            "python3 -c 'exec(\"print(1)\")'",
            "perl -e 'eval { system(\"ls\") }'",
            "node -e 'eval(\"1 + 1\")'",
        ],
    );
    // Split across two variables.
    let o = run(
        &["bash"],
        &bash_input("python3 -c 'import os; a = \"sud\"; b = \"o ls\"; os.system(a + b)'"),
    );
    assert!(o.stdout.contains("sudo is blocked"), "{}", o.stdout);
}

#[test]
fn interpreter_env_files_and_indirect_calls_every_rule() {
    // `@@` = the rule's command; `@L@` = its words as a list.
    every_rule_table_with(
        "@@",
        &[
            // The command gives the variable its value.
            "CMD='@@' python3 -c 'import os; os.system(os.environ[\"CMD\"])'",
            "export CMD=\"@@\"; python3 -c 'import os; os.system(os.getenv(\"CMD\"))'",
            "python3 -c 'import os; os.system(os.environ.get(\"CMD\", \"@@\"))'",
            "CMD='@@' node -e 'require(\"child_process\").execSync(process.env.CMD)'",
            "CMD='@@' ruby -e 'system(ENV[\"CMD\"])'",
            "CMD='@@' perl -e 'system($ENV{CMD})'",
            "CMD='@@' php -r 'shell_exec(getenv(\"CMD\"));'",
            "CMD='@@' lua -e 'os.execute(os.getenv(\"CMD\"))'",
            // Reached indirectly.
            "python3 -c 'import os; getattr(os, \"system\")(\"@@\")'",
            "python3 -c 'getattr(__import__(\"os\"), \"system\")(\"@@\")'",
            "python3 -c 'import os; f = os.system; f(\"@@\")'",
            "python3 -c 'from subprocess import run as r; r([@L@])'",
            "node -e 'const cp = require(\"child_process\"); cp[\"execSync\"](\"@@\")'",
            "node -e 'const cp = require(\"child_process\"); const run = cp.execSync; run(\"@@\")'",
            "node -e 'const {execSync: run} = require(\"child_process\"); run(\"@@\")'",
            "ruby -e 'send(:system, \"@@\")'",
            "ruby -e 'Kernel.public_send(:system, @L@)'",
            "ruby -e 'method(:system).call(\"@@\")'",
            "php -r 'call_user_func(\"system\", \"@@\");'",
            "php -r 'call_user_func_array(\"passthru\", [\"@@\"]);'",
            "php -r '$f = \"shell_exec\"; $f(\"@@\");'",
            // Read from a file the command writes first.
            "echo '@@' > cmd.txt; python3 -c 'import os; os.system(open(\"cmd.txt\").read())'",
            "printf '%s' '@@' > cmd.txt && node -e 'require(\"child_process\").execSync(require(\"fs\").readFileSync(\"cmd.txt\", \"utf8\"))'",
            "echo '@@' > c.txt; ruby -e 'system(File.read(\"c.txt\"))'",
            "echo '@@' > c.txt; php -r 'shell_exec(file_get_contents(\"c.txt\"));'",
            "echo '@@' > c.txt; lua -e 'os.execute(io.open(\"c.txt\"):read(\"a\"))'",
            "echo 'import os; os.system(\"@@\")' > x.py; python3 -c 'exec(open(\"x.py\").read())'",
        ],
        &[
            "python3 -c 'import os; os.system(os.environ[\"UNKNOWN\"])'",
            "python3 -c 'import os; os.system(os.environ.get(\"EDITOR\", \"vi\") + \" f.txt\")'",
            "python3 -c 'import os; f = os.path.join; f(\"a\", \"b\")'",
            "php -r '$f = \"strtoupper\"; $f(\"sudo ls\");'",
            "ruby -e 'send(:puts, \"sudo ls\")'",
            "CMD='ls -la' python3 -c 'import os; os.system(os.environ[\"CMD\"])'",
            "echo 'sudo ls' > notes.txt; python3 -c 'print(open(\"notes.txt\").read())'",
        ],
    );
    // A file already on disk in the project.
    let dir = format!(
        "{}/claude-guard-table-envfile-{}",
        tmpdir(),
        std::process::id()
    );
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(format!("{dir}/cmd.txt"), "sudo ls\n").unwrap();
    let cmd = "python3 -c 'import os; os.system(open(\"cmd.txt\").read())'";
    let input =
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": dir})
            .to_string();
    let o = run(&["bash"], &input);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(o.stdout.contains("sudo is blocked"), "{}", o.stdout);
}

#[test]
fn glued_operators_every_rule() {
    // A `)` glued to `;`, `&&`, `||` or `|` ends the command before it, as in bash (the Python guard read `);` as one
    // word, so the next command was its argument).
    every_rule_table(
        &[
            "x=$(date); C",
            "echo $(date); C",
            "x=$(date)&& C",
            "y=$(pwd)|| C",
            "(cd x)&& C",
            "(cd x); C",
            "echo $((1+2)); C",
            "x=$(date)⏎C",
            "bash -c \"x=\\$(date); C\"",
            "f() { ls; }; f; C",
        ],
        &[
            "x=$(date); ls -la",
            "cmd 2>&1 >/dev/null",
            "echo hi >| out.txt; cat out.txt",
            "diff <(ls a)<(ls b)",
            "git commit -m \"$(cat <<'EOF'⏎a);b⏎EOF⏎)\"",
            "x=$(git rev-parse HEAD)&& echo $x",
        ],
    );
}

#[test]
fn nesting_and_work_budget() {
    // Nested substitutions are checked once each: deep nesting stays fast, and a blocked command inside is found.
    let nest =
        |n: usize, inner: &str| format!("echo {}{}{}", "$(echo ".repeat(n), inner, ")".repeat(n));
    for (cmd, want_deny) in [
        (nest(100, "hi"), false),
        (nest(100, "$(sudo ls)"), true),
        (
            format!(
                "echo \"{}`git push -f`{}\"",
                "$(echo ".repeat(60),
                ")".repeat(60)
            ),
            true,
        ),
    ] {
        let start = std::time::Instant::now();
        let o = run(&["bash"], &bash_input(&cmd));
        assert!(
            start.elapsed().as_secs() < 5,
            "too slow: {:?}",
            start.elapsed()
        );
        assert_eq!(
            o.stdout.contains("\"deny\""),
            want_deny,
            "{} -> {}",
            &cmd[..60],
            o.stdout
        );
    }
    // More pieces than one check reads: blocked with a plain reason, never left to time out.
    let wide = format!(
        "echo {}",
        (0..12_000)
            .map(|i| format!("$(ls {i})"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let o = run(&["bash"], &bash_input(&wide));
    assert!(
        o.stdout
            .contains("more nested commands, strings and scripts"),
        "{}",
        o.stdout
    );
    // Large interpreter code is read in one pass per piece.
    let code = format!(
        "import os\n{}os.system('sudo ls')\n",
        "os.system('ls')\n".repeat(8000)
    );
    let start = std::time::Instant::now();
    let o = run(
        &["bash"],
        &bash_input(&format!("python3 - <<'EOF'\n{code}EOF")),
    );
    assert!(
        start.elapsed().as_secs() < 10,
        "too slow: {:?}",
        start.elapsed()
    );
    assert!(o.stdout.contains("sudo is blocked"), "{}", o.stdout);
}

#[test]
fn case_patterns_in_quoted_substitutions_every_rule() {
    every_rule_table(
        &[
            "echo \"$(case a in a) C;; esac)\"",
            // (A `*)` arm is left out: with no cwd, the Python reading takes its `*` as a glob that could match
            // .env, an existing rule.)
            "x=\"$(case $y in a|b) C;; c) ls;; esac)\"",
            "x=\"$(case $y in (a) ls;; b) C;; esac)\"",
            "echo \"$(case a in a) echo \"$(case b in b) C;; esac)\";; esac)\"",
        ],
        &[
            "echo \"$(case a in a) echo hi;; esac)\"",
            "x=\"$(case $y in a) ls;; esac)\"; echo \"$x\"",
            "echo \"case a) is fine\"",
        ],
    );
}

#[test]
fn nul_bytes_in_scripts_every_rule() {
    let dir = format!("{}/claude-guard-table-nul-{}", tmpdir(), std::process::id());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut fails = Vec::new();
    for (i, (c, want)) in EVERY_RULE.iter().enumerate() {
        // A NUL after the first line: bash still runs the file, so it is read (NULs dropped).
        let mut later = format!("#!/bin/bash\n{c}\n#").into_bytes();
        later.extend(b"\0tail\n");
        std::fs::write(format!("{dir}/later{i}.sh"), later).unwrap();
        // A NUL inside the command word: bash drops it and runs the rest.
        let split = c.replacen(' ', "\0 ", 1);
        std::fs::write(format!("{dir}/inside{i}.sh"), format!("ls\n{split}\n")).unwrap();
        for f in [format!("later{i}.sh"), format!("inside{i}.sh")] {
            let input = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": format!("bash {f}")}, "cwd": dir}).to_string();
            let o = run(&["bash"], &input);
            if !(o.stdout.contains("\"deny\"") && o.stdout.contains(want)) {
                fails.push(format!(
                    "want deny ({want}) :: bash {f} -> {}",
                    o.stdout.trim()
                ));
            }
        }
    }
    // A NUL in the first line: bash refuses the file ("cannot execute binary file"), so it isn't read.
    let mut first = b"#!/bin/bash\0\n".to_vec();
    first.extend(b"sudo ls\n");
    std::fs::write(format!("{dir}/first.sh"), first).unwrap();
    let input = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "bash first.sh"}, "cwd": dir}).to_string();
    let o = run(&["bash"], &input);
    if (o.code, o.stdout.as_str()) != (0, "") {
        fails.push(format!(
            "want allow :: bash first.sh -> {}",
            o.stdout.trim()
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn rm_redirect_targets_are_not_paths() {
    // A redirect's target is a file the shell opens, not one rm deletes; a real path outside temp is still blocked.
    let allow = [
        "rm -rf \"$tmp\" 2>/dev/null",
        "rm -rf build >/dev/null 2>&1",
        "rm -rf dist &>/dev/null",
        "rm -rf node_modules > /var/log/clean.log",
        "rm -rf x >| /srv/out.txt",
        "rm -rf x >> /srv/out.log",
        "rm -rf coverage 2> /srv/err.log",
        "bash -c 'rm -rf \"$d\" 2>/dev/null'",
        "if ! rm -rf \"$snap\" \"$lists\" 2>/dev/null; then echo failed; fi",
    ];
    let deny = [
        "rm -rf /srv/x 2>/dev/null",
        "rm -rf /srv/x >/dev/null",
        "rm -rf ~/x 2>/dev/null",
        "rm -rf / > /dev/null",
        "rm -rf x 2>/dev/null; rm -rf /srv/y",
        "rm -rf /srv/x 2>/dev/null /srv/y",
    ];
    let mut fails = Vec::new();
    for c in allow {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    for c in deny {
        let o = run(&["bash"], &bash_input(c));
        if !o.stdout.contains("recursive force delete") || o.stdout.contains("/dev/null") {
            fails.push(format!(
                "want deny without /dev/null :: {c:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
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

#[test]
fn words_after_a_substitution_stay_in_its_command() {
    // An unquoted `$(...)` or backticks is one word: the arguments after it belong to the same simple command and
    // are checked (the Python guard ended the command at the `)`).
    let deny = [
        ("cat $(true) .env", "reading a secrets file"),
        ("cat $(true) /srv/app/.env", "reading a secrets file"),
        ("true; cat $(true) .env", "reading a secrets file"),
        ("cat $(true)$(true) .env", "reading a secrets file"),
        ("echo $(echo $(ls)) > tail .env", "reading a secrets file"),
        (
            "echo $(echo $(echo $(echo $(ls)))) > tail .env",
            "reading a secrets file",
        ),
        ("cat $(echo $(echo x)) .env.local", "reading a secrets file"),
        ("rm -rf $(true) /srv/x", "recursive force delete"),
        ("ls $(true) && rm -rf $(true) ~/x", "recursive force delete"),
        ("rm -rf `true` /srv/x", "recursive force delete"),
        ("grep x $(true) -r .", "recursive grep"),
        ("git push $(true) --force", "git push --force"),
        ("bash -c 'cat $(true) .env'", "reading a secrets file"),
    ];
    let allow = [
        "rm -rf $(mktemp -d)/x",
        "rm -rf \"$(mktemp -d)\"",
        "cat $(ls) README.md",
        "echo $(date) > out.txt",
        "n=$(wc -l < .env.example); echo $n",
        "cp .env.example $(pwd)/.env",
        "[ -f $(pwd)/.env ] && echo yes",
        "echo \"$(date)\" .",
        "x=$(case $1 in a) echo 1;; esac) && echo $x",
    ];
    let mut fails = Vec::new();
    for (c, want) in deny {
        let o = run(&["bash"], &bash_input(c));
        if !o.stdout.contains(want) {
            fails.push(format!(
                "want deny ({want}) :: {c:?} -> {}",
                o.stdout.trim()
            ));
        }
    }
    for c in allow {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn home_prefix_applies_to_what_it_runs() {
    // `HOME=x CMD` runs CMD with that home: `~` and `$HOME` in the string or script it runs mean x. Not where the
    // command's own shell expands them first (unquoted, `"$HOME"`, `eval` arguments), not past the simple command,
    // and not when x can't be known (a substitution).
    let dir = format!(
        "{}/claude-guard-table-home-{}",
        tmpdir(),
        std::process::id()
    );
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        format!("{dir}/inst.sh"),
        "#!/bin/sh\nmkdir -p \"$HOME/.local/share\"\nrm -rf \"$HOME/.local/share/x\"\nrm -rf ~/.cache/x\n",
    )
    .unwrap();
    let allow = [
        "HOME=/tmp/h bash -c 'rm -rf \"$HOME/.local/x\"'",
        "HOME=/tmp/h bash -c 'rm -rf ~/.local/x'",
        "HOME=/tmp/h bash -c \"rm -rf ~/x\"",
        "env HOME=/tmp/h bash -c 'rm -rf ~/x'",
        "HOME=/tmp/h sh -c 'rm -rf ${HOME}/x'",
        "h=/tmp/h; HOME=\"$h\" bash -c 'rm -rf ~/x'",
        "HOME=/tmp/h timeout 9 bash -c 'rm -rf ~/x'",
        "HOME=/tmp/h nice timeout 9 sh -c 'rm -rf \"$HOME/x\"'",
        "HOME=/tmp/h bash -c 'bash -c \"rm -rf ~/x\"'",
        "HOME=/tmp/h bash <<< 'rm -rf ~/x'",
        "HOME=/tmp/h bash inst.sh",
        "HOME=/tmp/h timeout 9 bash inst.sh",
        "env HOME=/tmp/h sh inst.sh",
        "ih=/tmp/h/home; HOME=\"$ih\" bash inst.sh",
        // heeler-kit's test: a home under a mktemp folder the guard can't know, read like any unknown variable.
        "okd=$(mktemp -d); ih=\"$okd/home\"; HOME=\"$ih\" bash inst.sh >/dev/null 2>&1",
    ];
    let deny = [
        "HOME=/tmp/h rm -rf ~/x",
        "HOME=/tmp/h true; bash -c 'rm -rf ~/x'",
        "HOME=/srv/h bash -c 'rm -rf ~/x'",
        "HOME=~ bash -c 'rm -rf ~/x'",
        "HOME=$HOME bash -c 'rm -rf ~/x'",
        "HOME=/ bash -c 'rm -rf ~'",
        "HOME=$(mktemp -d) bash -c 'rm -rf ~/x'",
        "h=/srv/h; HOME=\"$h\" bash -c 'rm -rf ~/x'",
        "HOME=/tmp/h bash -c \"rm -rf $HOME/x\"",
        "HOME=/tmp/h eval rm -rf ~/x",
        "HOME=/tmp/h bash -c 'HOME=/srv/q bash -c \"rm -rf ~/x\"'",
        "HOME=/tmp/h bash -c 'rm -rf /srv/y'",
        // A wrapper's own words are expanded by the shell around it, before the prefix applies.
        "HOME=/tmp/h timeout 9 rm -rf ~/x",
        "HOME=/tmp/h timeout 9 rm -rf \"$HOME/x\"",
        "HOME=/tmp/h nice rm -rf ~/x",
        "env HOME=/tmp/h rm -rf ~/x",
        "HOME=/tmp/h timeout 9 bash -c \"rm -rf $HOME/x\"",
        "timeout 9 env HOME=/tmp/h bash -c \"rm -rf $HOME/x\"",
        "HOME=/tmp/h timeout 9 eval rm -rf ~/x",
        // Only a `HOME=` among the leading words counts, not one behind another wrapper (kept blocked).
        "timeout 9 env HOME=/tmp/h bash -c 'rm -rf ~/x'",
        "bash inst.sh",
        "HOME=/srv/h bash inst.sh",
        "HOME=/tmp/h true; bash inst.sh",
        "bash inst.sh; HOME=/tmp/h bash inst.sh",
        "HOME=/tmp/h bash inst.sh; bash inst.sh",
        "HOME=$(mktemp -d) bash inst.sh",
        "HOME=$HOME/sub bash inst.sh",
        // A script written here may hold this shell's expansion of `~` or `$HOME`: its home isn't changed.
        "printf 'rm -rf ~/x\\n' > s.sh; HOME=/tmp/h bash s.sh",
        "cat > s.sh <<EOF\nrm -rf $HOME/x\nEOF\nHOME=/tmp/h bash s.sh",
    ];
    let input = |c: &str| {
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": c}, "cwd": dir})
            .to_string()
    };
    let mut fails = Vec::new();
    for c in allow {
        let o = run(&["bash"], &input(c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    for c in deny {
        let o = run(&["bash"], &input(c));
        if !o.stdout.contains("recursive force delete") {
            fails.push(format!("want deny :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn search_patterns_case_patterns_and_path_verbs_are_not_reads() {
    // A grep/rg pattern, a case pattern, readlink/realpath (print a path) and chown/chgrp (change metadata) name .env
    // without reading it. The files a search reads, `-f` pattern files and commands after a case pattern still count.
    let allow = [
        "rg -n 'process\\.env' src",
        "rg 'process.env' src",
        "rg -e .env -e x src",
        "rg --regexp=.env src",
        "rg -g '*.ts' -n .env src",
        "rg -t ts -A 2 .env src",
        "grep -n '.env' README.md",
        "grep -e .env -e x README.md",
        "grep -A3 .env README.md",
        "grep -m 1 -- .env README.md",
        "egrep 'env_file: .env' docker-compose.yml",
        "fgrep .env.local notes.txt",
        "git ls-files | grep .env",
        "case \"$p\" in /.env|/.git/config) t=1;; esac",
        "case $f in .env) echo secret;; *.env.local) echo local;; esac",
        "case $f in a) echo a;; .env) echo b;; esac",
        "readlink -f current/.env",
        "E=$(readlink -f current/.env); echo \"$E\"",
        "realpath shared/.env",
        "chown ec2-user:ec2-user .env docker-compose.yml",
        "chgrp staff .env",
        "E=$(readlink -f .env); echo \"$E\"",
        "ls -l $(realpath .env)",
    ];
    let deny = [
        "grep KEY .env",
        "grep -n x .env.local",
        "grep -e x -- .env",
        "grep -f .env README.md",
        "rg x .env",
        "rg -e x .env",
        "rg --file .env src",
        "rg -n KEY -- .env",
        "grep -A 3 KEY .env",
        // A brace (or glob) pattern word is expanded first, into files the search then reads.
        "grep {x,.env} README.md",
        "case $f in a) cat .env;; esac",
        "case $f in a) echo a;; b) cat .env;; esac",
        "cat $(readlink -f .env)",
        "readlink -f .env; cat .env",
        // A substitution that only prints a path reads as that path in the command around it.
        "cat \"$(realpath shared/.env)\"",
        "cat $(echo .env)",
        "cat $(ls .env)",
        "cat \"$(printf %s .env)\"",
        "f=$(readlink -f .env); cat \"$f\"",
    ];
    let mut fails = Vec::new();
    for c in allow {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    for c in deny {
        let o = run(&["bash"], &bash_input(c));
        if !o.stdout.contains("reading a secrets file") {
            fails.push(format!("want deny :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn for_word_lists_and_zx_template_literals() {
    // A for/select word list only names files; what the body does with the loop variable is what counts.
    let allow = [
        "for f in .env .env.local; do echo \"$f\"; done",
        "for f in .env; do ls -l \"$f\"; done",
        "for f in .env .env.local; do [ -f \"$f\" ] && echo \"$f exists\"; done",
        "P=\"/x /.env\"; for p in $P; do echo \"$p\"; done",
        "select f in .env x; do echo $f; break; done",
        "for f in .env\ndo\n  test -e \"$f\" && echo yes\ndone",
        "for e in /home/*/*/.env; do [ -f \"$e\" ] && echo \"$e\"; done",
    ];
    let deny = [
        "for f in .env; do cat \"$f\"; done",
        "for f in x .env.local; do cat $f; done",
        "for f in .env; do source \"${f}\"; done",
        "for f in a b; do cat .env; done",
        "P=\".env x\"; for f in $P; do cat \"$f\"; done",
        "for f in .env\ndo\n  grep KEY \"$f\"\ndone",
        // Server paths: a glob shaped like a secrets file reads as one, whatever exists on this machine.
        "for e in /home/forge/*/.env /var/app/current/.env; do [ -f \"$e\" ] || continue; grep -E '^REDIS_HOST=' \"$e\"; done",
        "for e in /home/*/*/.env /home/*/*/shared/.env; do grep -oE '^AGRANI_[A-Z_]+' \"$e\"; done",
        // A copy of the loop variable reads as the file too.
        "ENV=\"\"; for e in \"$D/shared/.env\" \"$D/.env\"; do [ -f \"$e\" ] && { ENV=$e; break; }; done; grep -E '^QUEUE_CONNECTION=' \"$ENV\"",
        "a=.env; b=$a; cat \"$b\"",
    ];
    let mut fails = Vec::new();
    for c in allow {
        let o = run(&["bash"], &bash_input(c));
        if (o.code, o.stdout.as_str()) != (0, "") {
            fails.push(format!("want allow :: {c:?} -> {}", o.stdout.trim()));
        }
    }
    for c in deny {
        let o = run(&["bash"], &bash_input(c));
        if !o.stdout.contains("reading a secrets file") {
            fails.push(format!("want deny :: {c:?} -> {}", o.stdout.trim()));
        }
    }

    // zx / Bun shell: $`cmd` runs cmd; a regex end anchor before a template literal's closing backtick doesn't.
    let dir = format!("{}/claude-guard-table-zx-{}", tmpdir(), std::process::id());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let files = [
        (
            "regex.js",
            "const re = new RegExp(`^\\\\s*${key}\\\\s*=\\\\s*(.*)\\\\s*$`);\nconst env = process.env;\nconst t = `${env.HOME}/x`;\n",
            "",
        ),
        ("zx.mjs", "await $`sudo ls`;\n", "sudo is blocked"),
        (
            "zx2.mjs",
            "const out = await $`cat .env`;\n",
            "reading a secrets file",
        ),
        (
            "bun.js",
            "import { $ } from 'bun';\n($`rm -rf /srv/x`);\n",
            "recursive force delete",
        ),
    ];
    for (name, body, want) in files {
        std::fs::write(format!("{dir}/{name}"), body).unwrap();
        let input = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": format!("node {name}")}, "cwd": dir})
            .to_string();
        let o = run(&["bash"], &input);
        let ok = if want.is_empty() {
            (o.code, o.stdout.as_str()) == (0, "")
        } else {
            o.stdout.contains(want)
        };
        if !ok {
            fails.push(format!("node {name}: want {want:?} -> {}", o.stdout.trim()));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        fails.is_empty(),
        "{} failed:\n{}",
        fails.len(),
        fails.join("\n")
    );
}
