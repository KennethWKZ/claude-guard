//! Table tests for the shared-working-tree rules of `claude-guard repo pre-bash`, with a generic fixture config.

mod common;
use common::*;
use serde_json::json;

const CONFIG: &str = r#"{
  "version": 1,
  "repo_label": "fixture",
  "error_log": "out/errors.log",
  "locked_dirs": ["records", "data"],
  "output_dirs": ["out"],
  "pre_bash": {
    "git": {
      "block_message": "Blocked: `git {op}` in {repo_label}: {message}. {advice}",
      "messages": {"commit": "use the queue", "gc --prune=now": "it prunes now"},
      "advice": {"commit": "Run the queue."},
      "default_message": "it touches shared state",
      "default_advice": "Ask first.",
      "saved_prune_message": "Blocked: `git gc` in {repo_label} with a prune saved ({where}): {prune_message}."
    },
    "shell_writes": {
      "block_message": "Blocked: a shell write to `{path}` in {repo_label}: {message}",
      "message": "use the editor."
    },
    "interpreter_writes": {
      "block_message": "Blocked: an interpreter write to `{target}` in {repo_label}: {message}",
      "message": "use the editor."
    },
    "write_ledger": {
      "dir": "out/.ledger",
      "override_env": "ACCEPT_EDITS",
      "block_message": "Blocked: `{hit}` in {repo_label}. {message}",
      "message": "The ledger is the scripts' own."
    },
    "logs_insights": {
      "guard_module": "cost_guard",
      "raw_cli_reason": "raw query",
      "script_reason": "{path} queries",
      "inline_reason": "inline queries",
      "block_message": "Blocked: {why}."
    }
  }
}"#;

fn git(d: &str, args: &[&str]) {
    let st = std::process::Command::new("git")
        .args(["-C", d])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
        .status;
    assert!(st.success(), "git {args:?}");
}

fn world(tag: &str) -> String {
    let d = fresh_dir(tag);
    for sub in [
        "records/sub",
        "data",
        "out",
        "sub",
        "wt/records",
        ".claude",
        "home",
    ] {
        std::fs::create_dir_all(format!("{d}/{sub}")).unwrap();
    }
    let w = |p: &str, s: &str| std::fs::write(format!("{d}/{p}"), s).unwrap();
    w(".claude/repo-guard.json", CONFIG);
    w("records/a.md", "x\n");
    w("file.md", "x\n");
    w("wt/.git", "gitdir: /nowhere\n");
    w("s.sh", "#!/bin/bash\ngit stash\n");
    w("w.sh", "#!/bin/sh\necho x > records/a.md\n");
    git(&d, &["init", "-q"]);
    d
}

fn hook(d: &str, command: &str, cwd: &str) -> Out {
    let input =
        json!({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd}).to_string();
    run_in(
        &[BIN, "repo", "pre-bash"],
        &input,
        &[
            ("CLAUDE_PROJECT_DIR", d),
            ("HOME", &format!("{d}/home")),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
        ],
        Some(d),
    )
}

fn blocked(d: &str, command: &str) -> String {
    let o = hook(d, command, d);
    assert_eq!(
        (o.code, o.stdout.as_str()),
        (2, ""),
        "not blocked: {command}"
    );
    o.stderr
}

fn allowed(d: &str, command: &str, cwd: &str) {
    let o = hook(d, command, cwd);
    assert_eq!(
        (o.code, o.stderr.as_str(), o.stdout.as_str()),
        (0, "", ""),
        "{command}"
    );
}

#[test]
fn git_operations_on_the_shared_tree() {
    let d = world("tree-git");
    assert_eq!(
        blocked(&d, "git commit -m x"),
        "Blocked: `git commit` in fixture: use the queue. Run the queue.\n"
    );
    assert_eq!(
        blocked(&d, "git stash"),
        "Blocked: `git stash` in fixture: it touches shared state. Ask first.\n",
        "defaults for a rule without its own texts"
    );
    for command in [
        "git commit --amend",
        "git add .",
        "git -C sub rebase main",
        "git reset --hard",
        "git reset HEAD~1",
        "git checkout main",
        "git checkout -- .",
        "git restore records",
        "git clean -fd",
        "git branch -f main HEAD~1",
        "git gc --prune=now",
        "git -c gc.pruneExpire=now gc",
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=gc.reflogExpire GIT_CONFIG_VALUE_0=all git gc",
        "git config --global gc.pruneexpire now",
        "git repack -a -d",
        "git config core.hooksPath x",
        "git pull",
        "bash -c 'git merge x'",
        "echo $(git cherry-pick x)",
        "bash <<EOF\ngit revert x\nEOF",
        "./s.sh",
        "cd sub && git switch x",
        "xargs git rm",
        "find . -exec git add {} \\;",
        "eval 'git am x'",
    ] {
        blocked(&d, command);
    }
    for command in [
        "git status",
        "git log --oneline",
        "git stash list",
        "git commit --help",
        "git reset",
        "git reset HEAD -- file.md",
        "git checkout file.md",
        "git checkout -- file.md",
        "git restore --staged .",
        "git clean -n",
        "git gc",
        "git prune -n",
        "git repack -A -d",
        "git config --get x",
        "git -C /tmp commit -m x",
        "cd wt && git commit -m x",
        "GIT_INDEX_FILE=/tmp/idx git add file.md",
        "cat <<EOF\ngit commit\nEOF",
        "echo 'git commit'",
        "# git commit",
        "(cd /tmp && git stash)",
    ] {
        allowed(&d, command, &d);
    }
    allowed(&d, "git commit -m x", &format!("{d}/wt"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_saved_prune_blocks_plain_gc() {
    let d = world("tree-saved");
    git(&d, &["config", "gc.pruneExpire", "now"]);
    let msg = blocked(&d, "git gc");
    assert!(
        msg.starts_with("Blocked: `git gc` in fixture with a prune saved (")
            && msg.ends_with("gc.pruneexpire=now): it prunes now.\n"),
        "{msg}"
    );
    allowed(&d, "git gc --help", &d);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn shell_writes_to_locked_folders() {
    let d = world("tree-write");
    assert_eq!(
        blocked(&d, "echo x > records/a.md"),
        "Blocked: a shell write to `records/a.md` in fixture: use the editor.\n"
    );
    for command in [
        "echo x >> data/new.md",
        "printf x | tee records/sub/b.md",
        "sed -i '' s/a/b/ records/a.md",
        "perl -pi -e s/a/b/ records/a.md",
        "cp /tmp/x records/",
        "mv /tmp/x data/y.md",
        "truncate -s 0 records/a.md",
        "cd records && echo x > a.md",
        "./w.sh",
    ] {
        blocked(&d, command);
    }
    for command in [
        "cat records/a.md",
        "cat records/a.md > out/copy.md",
        "sed -n p records/a.md",
        "echo x > wt/records/a.md",
        "echo x 2>&1",
        "cp records/a.md /tmp/",
    ] {
        allowed(&d, command, &d);
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_write_ledger_and_its_override() {
    let d = world("tree-ledger");
    assert_eq!(
        blocked(&d, "ls out/.ledger"),
        "Blocked: `.ledger` in fixture. The ledger is the scripts' own.\n"
    );
    for command in [
        "ACCEPT_EDITS=1 pnpm run x",
        "export ACCEPT_EDITS=1",
        "python3 - <<EOF\nimport os\nos.environ['ACCEPT_EDITS'] = '1'\nEOF",
        "echo $(ls out/.ledger)",
    ] {
        blocked(&d, command);
    }
    for command in [
        "echo -m 'ACCEPT_EDITS=1'",
        "echo --message='out/.ledger'",
        "cat <<EOF > out/notes.md\nout/.ledger\nEOF",
        "echo hi # out/.ledger",
        "ls out/.ledgers",
    ] {
        allowed(&d, command, &d);
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn interpreter_writes_to_locked_folders() {
    let d = world("tree-interp");
    assert_eq!(
        blocked(&d, "python3 -c \"open('records/a.md', 'w')\""),
        "Blocked: an interpreter write to `records/a.md` in fixture: use the editor.\n"
    );
    assert_eq!(
        blocked(
            &d,
            "python3 -c \"open('records/b.md' if x else 'data/a.md', 'w')\""
        ),
        "Blocked: an interpreter write to `records/b.md` in fixture: use the editor.\n",
        "the first literal, always"
    );
    for command in [
        "python3 - <<'EOF'\nfrom pathlib import Path\np = Path('data/x.yaml')\np.write_text('y')\nEOF",
        "node -e \"require('fs').writeFileSync('records/a.md', 'x')\"",
        "cat <<'EOF' | python3\nfor f in ['records/a.md']:\n    open(f, 'w')\nEOF",
        "perl -e 'open(my $fh, \">\", \"records/a.md\")'",
        "ruby -e 'File.write(\"data/a\", \"x\")'",
        "cd records && python3 -c \"open('a.md', 'w')\"",
    ] {
        blocked(&d, command);
    }
    for command in [
        "python3 -c \"print(open('records/a.md').read())\"",
        "python3 -c \"open('/tmp/records.md', 'w')\"",
        "python3 -c \"open('out/records-a.md', 'w')\"",
        "cat <<'EOF' > /tmp/x.py\nopen('records/a.md', 'w')\nEOF",
        "python3 x.py",
    ] {
        allowed(&d, command, &d);
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn both_rule_sets_run_and_the_first_block_wins() {
    let d = world("tree-order");
    assert_eq!(
        blocked(&d, "aws logs start-query; git commit -m x"),
        "Blocked: raw query.\n"
    );
    let log = format!("{d}/out/errors.log");
    let o = hook(&d, "git commit -m x", "relative-but-fine");
    assert_eq!(o.code, 2, "a relative cwd resolves; no crash");
    let input = json!({"tool_name": "Bash", "tool_input": {"command": "python3 x.py"}, "cwd": 5})
        .to_string();
    let o = run_in(
        &[BIN, "repo", "pre-bash"],
        &input,
        &[("CLAUDE_PROJECT_DIR", &d)],
        Some(&d),
    );
    assert_eq!((o.code, o.stderr.as_str()), (0, ""));
    let lines = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        lines.lines().count(),
        2,
        "one crash line per rule set: {lines}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn shadow_logs_agreement_without_blocking() {
    let d = world("tree-shadow");
    // Two stand-in reference hooks: one blocks a commit with Rust's exact message, one allows everything.
    let blocker = format!("{d}/out/ref_block.py");
    std::fs::write(
        &blocker,
        "import sys\nif 'git commit' in sys.stdin.read():\n    sys.stderr.write('Blocked: `git commit` in fixture: use the queue. Run the queue.\\n')\n    sys.exit(2)\n",
    )
    .unwrap();
    let allower = format!("{d}/out/ref_allow.py");
    std::fs::write(&allower, "import sys\nsys.stdin.read()\n").unwrap();
    let log = format!("{d}/out/shadow.log");
    let shadow = |command: &str, refs: &[&str]| {
        let input = json!({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": d, "session_id": "s1"})
            .to_string();
        let mut args = vec![BIN, "repo", "pre-bash", "--shadow"];
        for r in refs {
            args.extend(["--reference", r]);
        }
        args.extend(["--log", &log]);
        let before = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .count();
        let o = run_in(
            &args,
            &input,
            &[
                ("CLAUDE_PROJECT_DIR", &d),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_CONFIG_NOSYSTEM", "1"),
            ],
            Some(&d),
        );
        assert_eq!(
            (o.code, o.stdout.as_str(), o.stderr.as_str()),
            (0, "", ""),
            "shadow never blocks or prints"
        );
        for _ in 0..200 {
            let lines = std::fs::read_to_string(&log).unwrap_or_default();
            if lines.lines().count() > before {
                let last: serde_json::Value =
                    serde_json::from_str(lines.lines().last().unwrap()).unwrap();
                // (long enough not to occur by chance in a log line: "ls" is in "false")
                assert!(
                    command.len() < 5 || !lines.contains(command),
                    "the command is never logged"
                );
                return last;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("no shadow line for {command}");
    };
    let l = shadow("git commit -m x", &[&allower, &blocker]);
    assert_eq!(
        (
            l["hook"].as_str(),
            l["rust"].as_str(),
            l["reference"].as_str(),
            l["same"].as_bool(),
            l["same_reason"].as_bool()
        ),
        (
            Some("repo-pre-bash"),
            Some("git:commit"),
            Some("git:commit"),
            Some(true),
            Some(true)
        )
    );
    assert_eq!(l["session_id"], "s1");
    let l = shadow("git stash", &[&allower, &blocker]);
    assert_eq!(
        (
            l["rust"].as_str(),
            l["reference"].as_str(),
            l["same"].as_bool()
        ),
        (Some("git:stash"), Some("allow"), Some(false))
    );
    let l = shadow("ls", &[&allower]);
    assert_eq!(
        (
            l["rust"].as_str(),
            l["reference"].as_str(),
            l["same"].as_bool()
        ),
        (Some("allow"), Some("allow"), Some(true))
    );
    let o = run_in(&[BIN, "repo", "pre-bash", "--shadow"], "{}", &[], Some(&d));
    assert_eq!(o.code, 64, "shadow needs at least one reference");
    let _ = std::fs::remove_dir_all(&d);
}
