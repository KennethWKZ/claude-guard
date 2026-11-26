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
