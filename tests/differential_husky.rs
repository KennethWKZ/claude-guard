//! Differential test: `claude-guard husky` against husky-worktree-hooks.py. Each case builds the same generated
//! repo layout twice (trees A and B), runs Python on A and Rust on B, and compares what they print (with each
//! tree's root path normalised), whether they logged an error, and the whole resulting tree: paths, file
//! contents, modes, file mtimes (copy2 keeps them) and link targets.
//! Env (test only): CLAUDE_GUARD_REF_HUSKY, CLAUDE_GUARD_DIFF_CASES (default 600), CLAUDE_GUARD_DIFF_SEED,
//! CLAUDE_GUARD_DIFF_WORKERS (default 2; pass "$(test-workers)").

mod common;
use common::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::time::{Duration, SystemTime};

const HOOKS: &[&str] = &[
    "post-commit",
    "post-checkout",
    "post-merge",
    "post-rewrite",
    "pre-push",
];

fn fixed_time(path: &str) {
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    if let Ok(f) = fs::File::open(path) {
        let _ = f.set_times(fs::FileTimes::new().set_modified(t).set_accessed(t));
    }
}

/// Build a generated layout under `r` from `seed`. Same seed, same layout (paths inside files use `r`).
fn build(r: &str, seed: u64) {
    let mut g = Rng(seed | 1);
    let m = format!("{r}/main");
    fs::create_dir_all(format!("{m}/.git/worktrees")).unwrap();
    fs::create_dir_all(format!("{r}/home")).unwrap();
    fs::create_dir_all(format!("{r}/plain")).unwrap();
    fs::create_dir_all(format!("{r}/other/.git")).unwrap();
    let husky = g.chance(85);
    let underscore = husky && g.chance(75);
    if husky {
        fs::create_dir_all(format!("{m}/.husky")).unwrap();
    }
    let mut files: Vec<String> = Vec::new();
    if underscore {
        fs::create_dir_all(format!("{m}/.husky/_/nested")).unwrap();
        fs::write(format!("{m}/.husky/_/h"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(
            format!("{m}/.husky/_/h"),
            fs::Permissions::from_mode(if g.chance(50) { 0o755 } else { 0o644 }),
        )
        .unwrap();
        fs::write(format!("{m}/.husky/_/.gitignore"), "*\n").unwrap();
        fs::write(format!("{m}/.husky/_/nested/n"), "n\n").unwrap();
        files.extend([
            format!("{m}/.husky/_/h"),
            format!("{m}/.husky/_/.gitignore"),
            format!("{m}/.husky/_/nested/n"),
        ]);
        if g.chance(50) {
            let _ = symlink("h", format!("{m}/.husky/_/rel-link"));
        }
        if g.chance(30) {
            let _ = symlink(format!("{m}/.husky/_/h"), format!("{m}/.husky/_/abs-link"));
        }
        if g.chance(20) {
            let _ = symlink("/nonexistent/x", format!("{m}/.husky/_/dangling"));
        }
    }
    if husky {
        for h in HOOKS {
            match g.below(4) {
                0 => {}
                1 => fs::write(
                    format!("{m}/.husky/{h}"),
                    "#!/bin/sh\n# graphmind: rebuild\n",
                )
                .unwrap(),
                2 => {
                    fs::write(format!("{m}/.husky/{h}"), "#!/bin/sh\r\n# graphmind: x\r\n").unwrap()
                }
                _ => fs::write(format!("{m}/.husky/{h}"), "#!/bin/sh\nnpm test\n").unwrap(),
            }
            if std::path::Path::new(&format!("{m}/.husky/{h}")).exists() {
                files.push(format!("{m}/.husky/{h}"));
            }
        }
    }
    let n = 1 + g.below(4);
    for k in 0..n {
        let wt = format!("wt{k}");
        let w = format!("{r}/{wt}");
        let entry = format!("{m}/.git/worktrees/{wt}");
        fs::create_dir_all(&entry).unwrap();
        fs::create_dir_all(format!("{w}/sub/deep")).unwrap();
        if g.chance(80) {
            fs::create_dir_all(format!("{w}/.husky")).unwrap();
            if g.chance(25) {
                fs::create_dir_all(format!("{w}/.husky/_")).unwrap();
            }
            if g.chance(25) {
                fs::write(format!("{w}/.husky/post-commit"), "mine\n").unwrap();
            }
        }
        let gitline = match g.below(4) {
            0 => format!("gitdir: ../main/.git/worktrees/{wt}\n"),
            1 => format!("gitdir:   {entry}\r\n"),
            2 => format!("gitdir: {entry}"),
            _ => format!("gitdir: {entry}\n"),
        };
        fs::write(format!("{w}/.git"), gitline).unwrap();
        let back = match g.below(6) {
            0 => format!("{w}/.git\r\n"),
            1 => String::new(),
            _ => format!("{w}/.git\n"),
        };
        fs::write(format!("{entry}/gitdir"), back).unwrap();
        if g.chance(85) {
            fs::write(
                format!("{entry}/commondir"),
                if g.chance(50) { "../..\n" } else { "../../\n" },
            )
            .unwrap();
        }
    }
    if g.chance(40) {
        fs::create_dir_all(format!("{m}/.git/worktrees/self")).unwrap();
        fs::write(
            format!("{m}/.git/worktrees/self/gitdir"),
            format!("{m}/.git\n"),
        )
        .unwrap();
    }
    if g.chance(40) {
        fs::create_dir_all(format!("{m}/.git/worktrees/gone")).unwrap();
        fs::write(
            format!("{m}/.git/worktrees/gone/gitdir"),
            format!("{r}/gone/.git\n"),
        )
        .unwrap();
    }
    if g.chance(30) {
        let _ = symlink(format!("{r}/wt0"), format!("{r}/wtlink"));
        fs::create_dir_all(format!("{m}/.git/worktrees/viaLink")).unwrap();
        fs::write(
            format!("{m}/.git/worktrees/viaLink/gitdir"),
            format!("{r}/wtlink/.git\n"),
        )
        .unwrap();
    }
    if g.chance(15) {
        fs::write(format!("{r}/broken-wt.git"), "garbage\n").unwrap();
        fs::create_dir_all(format!("{r}/broken")).unwrap();
        fs::write(format!("{r}/broken/.git"), "not a gitdir line\n").unwrap();
    }
    // Every file at one fixed time, so trees built a second apart compare equal (and copy2 keeps it).
    let _ = files;
    let mut stack = vec![r.to_string()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path().to_string_lossy().into_owned();
            match fs::symlink_metadata(&p) {
                Ok(md) if md.is_dir() => stack.push(p),
                Ok(md) if md.is_file() => fixed_time(&p),
                _ => {}
            }
        }
    }
    if underscore {
        fixed_time(&format!("{m}/.husky/_/nested"));
        fixed_time(&format!("{m}/.husky/_"));
    }
}

fn input(g: &mut Rng) -> String {
    let cwds = [
        json!("{R}/main"),
        json!("{R}/wt0"),
        json!("{R}/wt0/sub/deep"),
        json!("{R}/wt1"),
        json!("{R}/plain"),
        json!("{R}/gone"),
        json!("{R}/other"),
        json!("{R}"),
        json!("{R}/broken"),
        json!(""),
        Value::Null,
        json!(5),
        json!(true),
        json!(1.5),
        json!([1]),
        json!({}),
    ];
    let cmds = [
        "git worktree add ../wt9",
        "git worktree add {R}/wt5 -b x",
        "cd {R}/main && git worktree add x",
        "git -C {R}/wt0 worktree add y",
        "git -C main worktree add q",
        "git worktree list",
        "echo worktree add",
        "git worktree  add 'a b'",
        "git worktree add \"unterminated",
        "cd ~ && git worktree add z",
        "cd ~/x && git worktree add z",
        "git -C ~nosuchuser42/x worktree add z",
        "worktree add",
        "worktree addx",
        "git worktree\tadd x",
        "cd",
        "git -C",
        "cd {R}/wt1/sub; git worktree add a",
        "git worktree add",
    ];
    let mut v = json!({"session_id": "diff"});
    match g.below(10) {
        0..=3 => v["hook_event_name"] = json!("SessionStart"),
        4..=7 => {
            v["hook_event_name"] = json!("PostToolUse");
            v["tool_name"] = json!("Bash");
            v["tool_input"] = json!({"command": g.pick(&cmds)});
        }
        8 => {
            v["hook_event_name"] = json!("PostToolUse");
            v["tool_name"] = json!("EnterWorktree");
        }
        _ => {
            v["hook_event_name"] = g.pick(&[json!(5), Value::Null, json!("Stop")]).clone();
            if g.chance(50) {
                v["tool_name"] = json!("Bash");
                v["tool_input"] = g
                    .pick(&[
                        json!("x"),
                        json!([]),
                        Value::Null,
                        json!({"command": 5}),
                        json!({"command": null}),
                    ])
                    .clone();
            }
        }
    }
    let cwd = if g.chance(60) {
        g.pick(&cwds[..9]).clone()
    } else {
        g.pick(&cwds).clone()
    };
    if !cwd.is_null() {
        v["cwd"] = cwd;
    }
    if g.chance(3) {
        return g
            .pick(&[
                "not json",
                "[]",
                "null",
                "{\"hook_event_name\": \"SessionStart\", \"cwd\": \"{R}/main\"} x",
            ])
            .to_string();
    }
    v.to_string()
}

/// Every entry under `root`: kind, mode, contents (root normalised), file mtime, link target (root normalised).
fn snapshot(root: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_string()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path().to_string_lossy().into_owned();
            let rel = p.replacen(root, "{R}", 1);
            if rel.starts_with("{R}/home/.local") || rel.starts_with("{R}/home/Library") {
                continue; // Rust's error log, Python's bytecode cache (both under the test HOME)
            }
            let md = fs::symlink_metadata(&p).unwrap();
            let desc = if md.file_type().is_symlink() {
                format!(
                    "link -> {}",
                    fs::read_link(&p)
                        .unwrap()
                        .to_string_lossy()
                        .replace(root, "{R}")
                )
            } else if md.is_dir() {
                stack.push(p.clone());
                format!("dir {:o}", md.mode() & 0o7777)
            } else {
                let body =
                    String::from_utf8_lossy(&fs::read(&p).unwrap_or_default()).replace(root, "{R}");
                format!(
                    "file {:o} mtime={} {:?}",
                    md.mode() & 0o7777,
                    md.mtime(),
                    body
                )
            };
            out.insert(rel, desc);
        }
    }
    out
}

#[test]
fn rust_matches_python() {
    let reference = env_or(
        "CLAUDE_GUARD_REF_HUSKY",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/reference/husky-worktree-hooks.py"
        ),
    );
    if !std::path::Path::new(&reference).exists() {
        eprintln!("SKIPPED: reference hook not found ({reference})");
        return;
    }
    let n: usize = env_or("CLAUDE_GUARD_DIFF_CASES", "600").parse().unwrap();
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261124")
        .parse()
        .unwrap();
    let workers: usize = env_or("CLAUDE_GUARD_DIFF_WORKERS", "2").parse().unwrap();
    let base = fresh_dir("husky-diff");
    let mut g = Rng(seed | 1);
    let cases: Vec<(u64, String)> = (0..n).map(|_| (g.next(), input(&mut g))).collect();

    let results = parallel(&cases, workers, |i, (tree_seed, raw)| {
        let dir = format!("{base}/case{i}");
        let (a, b, py_dir) = (format!("{dir}/A"), format!("{dir}/B"), format!("{dir}/py"));
        build(&a, *tree_seed);
        build(&b, *tree_seed);
        fs::create_dir_all(&py_dir).unwrap();
        let script = format!("{py_dir}/husky-worktree-hooks.py");
        fs::copy(&reference, &script).unwrap();
        let py = run_in(
            &["/usr/bin/python3", "-I", &script],
            &raw.replace("{R}", &a),
            &[("HOME", &format!("{a}/home"))],
            Some(&a),
        );
        let rs = run_in(
            &[BIN, "husky"],
            &raw.replace("{R}", &b),
            &[("HOME", &format!("{b}/home"))],
            Some(&b),
        );
        let py_err = std::path::Path::new(&format!("{py_dir}/husky-worktree-hooks.log")).exists();
        let rs_err =
            std::path::Path::new(&format!("{b}/home/.local/state/claude-guard/husky.log")).exists();
        let (sa, sb) = (snapshot(&a), snapshot(&b));
        let pyo = py.stdout.replace(&a, "{R}");
        let rso = rs.stdout.replace(&b, "{R}");
        let copied = !pyo.is_empty();
        let mut problems = Vec::new();
        if (py.code, &pyo) != (rs.code, &rso) {
            problems.push(format!(
                "stdout/code: python {} {pyo:?} | rust {} {rso:?}",
                py.code, rs.code
            ));
        }
        if py_err != rs_err {
            problems.push(format!("error logged: python {py_err} rust {rs_err}"));
        }
        if sa != sb {
            let diff: Vec<String> = sa
                .keys()
                .chain(sb.keys())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .filter(|k| sa.get(*k) != sb.get(*k))
                .take(5)
                .map(|k| format!("{k}: python {:?} | rust {:?}", sa.get(k), sb.get(k)))
                .collect();
            problems.push(format!("trees differ: {}", diff.join("; ")));
        }
        let _ = fs::remove_dir_all(&dir);
        (problems, copied, py_err)
    });
    let bad: Vec<String> = results
        .iter()
        .zip(&cases)
        .filter(|(r, _)| !r.0.is_empty())
        .map(|(r, c)| format!("input: {}\n  {}", c.1, r.0.join("\n  ")))
        .collect();
    let copied = results.iter().filter(|r| r.1).count();
    let errored = results.iter().filter(|r| r.2).count();
    let _ = fs::remove_dir_all(&base);
    eprintln!(
        "differential husky: {n} cases, {copied} with copies, {errored} logged errors (both), {} unexpected",
        bad.len()
    );
    assert!(
        bad.is_empty(),
        "{} unexpected differences (first 10):\n{}",
        bad.len(),
        bad.iter().take(10).cloned().collect::<Vec<_>>().join("\n")
    );
}
