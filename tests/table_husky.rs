//! Table tests for `claude-guard husky` (husky-worktree-hooks.py's behaviour) on small real repo layouts.

mod common;
use common::*;
use serde_json::json;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::{Duration, SystemTime};

/// main/ (husky repo, .husky/_ with a script, a sub folder and a link; graphmind post-commit with the marker,
/// pre-push without), wt1 and wt2 (worktrees with .husky/), wt3 (worktree without .husky/), self (an entry that
/// points back at main), gone (an entry whose folder is missing).
fn layout(root: &str) {
    let m = format!("{root}/main");
    for d in [
        ".git/worktrees/wt1",
        ".git/worktrees/wt2",
        ".git/worktrees/wt3",
        ".git/worktrees/self",
        ".git/worktrees/gone",
        ".husky/_/sub",
    ] {
        fs::create_dir_all(format!("{m}/{d}")).unwrap();
    }
    fs::write(format!("{m}/.husky/_/h"), "#!/bin/sh\necho hook\n").unwrap();
    fs::set_permissions(format!("{m}/.husky/_/h"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(format!("{m}/.husky/_/.gitignore"), "*\n").unwrap();
    fs::write(format!("{m}/.husky/_/sub/x"), "x\n").unwrap();
    symlink("h", format!("{m}/.husky/_/link")).unwrap();
    fs::write(
        format!("{m}/.husky/post-commit"),
        "#!/bin/sh\n# graphmind: rebuild\n",
    )
    .unwrap();
    fs::write(format!("{m}/.husky/pre-push"), "#!/bin/sh\nnpm test\n").unwrap();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    fs::File::options()
        .write(true)
        .open(format!("{m}/.husky/_/h"))
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old).set_accessed(old))
        .unwrap();
    for wt in ["wt1", "wt2", "wt3"] {
        let w = format!("{root}/{wt}");
        fs::create_dir_all(format!("{w}/sub/deep")).unwrap();
        if wt != "wt3" {
            fs::create_dir_all(format!("{w}/.husky")).unwrap();
        }
        fs::write(
            format!("{w}/.git"),
            format!("gitdir: {m}/.git/worktrees/{wt}\n"),
        )
        .unwrap();
        fs::write(
            format!("{m}/.git/worktrees/{wt}/gitdir"),
            format!("{w}/.git\n"),
        )
        .unwrap();
        fs::write(format!("{m}/.git/worktrees/{wt}/commondir"), "../..\n").unwrap();
    }
    fs::write(format!("{root}/wt2/.husky/post-commit"), "mine\n").unwrap(); // must not be overwritten
    fs::write(
        format!("{m}/.git/worktrees/self/gitdir"),
        format!("{m}/.git\n"),
    )
    .unwrap();
    fs::write(
        format!("{m}/.git/worktrees/gone/gitdir"),
        format!("{root}/gone/.git\n"),
    )
    .unwrap();
}

fn hook(root: &str, input: serde_json::Value, extra: &[&str]) -> Out {
    let home = format!("{root}/home");
    fs::create_dir_all(&home).unwrap();
    let mut args = vec![BIN, "husky"];
    args.extend_from_slice(extra);
    run_in(&args, &input.to_string(), &[("HOME", &home)], Some(root))
}

#[test]
fn copies_into_worktrees_that_lack_them() {
    let r = fresh_dir("husky-copy");
    layout(&r);
    let o = hook(
        &r,
        json!({"hook_event_name": "SessionStart", "cwd": format!("{r}/wt1/sub/deep")}),
        &[],
    );
    assert_eq!(o.code, 0);
    let msg = "{\"hookSpecificOutput\": {\"hookEventName\": \"SessionStart\", \"additionalContext\": \"husky/graphmind hooks copied into worktree(s): ".to_string();
    assert!(o.stdout.starts_with(&msg), "{}", o.stdout);
    assert!(
        o.stdout
            .contains(&format!("{r}/wt1 (.husky/_, post-commit)")),
        "{}",
        o.stdout
    );
    assert!(
        o.stdout.contains(&format!("{r}/wt2 (.husky/_)")),
        "{}",
        o.stdout
    );
    assert!(
        !o.stdout.contains("wt3") && !o.stdout.contains("pre-push"),
        "{}",
        o.stdout
    );
    // copied as Python's copytree(symlinks=True) + copy2 would
    assert_eq!(
        fs::read_link(format!("{r}/wt1/.husky/_/link"))
            .unwrap()
            .to_str(),
        Some("h")
    );
    let h = fs::metadata(format!("{r}/wt1/.husky/_/h")).unwrap();
    assert_eq!(h.permissions().mode() & 0o777, 0o755);
    assert_eq!(
        h.modified().unwrap(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000)
    );
    assert_eq!(
        fs::read_to_string(format!("{r}/wt1/.husky/_/sub/x")).unwrap(),
        "x\n"
    );
    assert_eq!(
        fs::read_to_string(format!("{r}/wt2/.husky/post-commit")).unwrap(),
        "mine\n",
        "never overwrites"
    );
    assert!(!std::path::Path::new(&format!("{r}/wt3/.husky")).exists());
    // second run: nothing left to copy, nothing printed
    let o = hook(
        &r,
        json!({"hook_event_name": "SessionStart", "cwd": format!("{r}/main")}),
        &[],
    );
    assert_eq!((o.code, o.stdout.as_str()), (0, ""));
    let _ = fs::remove_dir_all(&r);
}

#[test]
fn bash_only_after_worktree_add() {
    let r = fresh_dir("husky-bash");
    layout(&r);
    let quiet = hook(
        &r,
        json!({"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": format!("{r}/main"), "tool_input": {"command": "git worktree list"}}),
        &[],
    );
    assert_eq!((quiet.code, quiet.stdout.as_str()), (0, ""));
    assert!(!std::path::Path::new(&format!("{r}/wt1/.husky/_")).exists());
    let o = hook(
        &r,
        json!({"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": format!("{r}/plain"), "tool_input": {"command": format!("git -C {r}/main worktree add ../wt9")}}),
        &[],
    );
    assert!(
        o.stdout.contains("hookEventName\": \"PostToolUse\""),
        "{}",
        o.stdout
    );
    assert!(std::path::Path::new(&format!("{r}/wt1/.husky/_/h")).exists());
    let _ = fs::remove_dir_all(&r);
}

#[test]
fn errors_are_logged_and_exit_0() {
    let r = fresh_dir("husky-err");
    for input in [
        "not json",
        "[]",
        "{\"hook_event_name\": \"PostToolUse\", \"tool_name\": \"Bash\", \"tool_input\": \"x\"}",
    ] {
        let home = format!("{r}/home");
        fs::create_dir_all(&home).unwrap();
        let o = run_in(&[BIN, "husky"], input, &[("HOME", &home)], Some(&r));
        assert_eq!(
            (o.code, o.stdout.as_str(), o.stderr.as_str()),
            (0, "", ""),
            "{input}"
        );
    }
    let log = fs::read_to_string(format!("{r}/home/.local/state/claude-guard/husky.log")).unwrap();
    assert_eq!(log.matches("--- ").count(), 3, "{log}");
    let _ = fs::remove_dir_all(&r);
}

#[test]
fn shadow_plans_without_copying_and_checks_the_reference() {
    let r = fresh_dir("husky-shadow");
    layout(&r);
    let log = format!("{r}/shadow.log");
    let input =
        json!({"hook_event_name": "SessionStart", "cwd": format!("{r}/main"), "session_id": "s"});
    let o = hook(&r, input.clone(), &["--shadow", "--log", &log]);
    assert_eq!((o.code, o.stdout.as_str()), (0, ""));
    // The shadow copied nothing; the real hook (here the Rust one standing in for Python) does, and the detached
    // check sees those copies.
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !std::path::Path::new(&format!("{r}/wt1/.husky/_")).exists(),
        "shadow must not copy"
    );
    let real = hook(&r, input, &[]);
    assert!(!real.stdout.is_empty());
    let mut text = String::new();
    for _ in 0..200 {
        text = fs::read_to_string(&log).unwrap_or_default();
        if !text.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        text.contains("\"rust\": \"copy:3\"")
            && text.contains("\"reference\": \"copy:3\"")
            && text.contains("\"same\": true"),
        "{text}"
    );
    assert!(!text.contains(&r), "the log must not hold paths");
    let _ = fs::remove_dir_all(&r);
}
