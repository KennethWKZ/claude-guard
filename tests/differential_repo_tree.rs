//! Differential test for the shared-working-tree rules of `claude-guard repo pre-bash` (`src/repo_tree.rs`): git
//! operations, shell writes, the ledger text check and interpreter writes, on generated commands, against a
//! repo's Python PreToolUse Bash hooks run together (`common::combine`). Exit code, stdout, stderr and "crashed"
//! must match exactly.
//!
//! Folder names, the ledger folder and its override variable come from the reference config, so nothing of the
//! private repo is in this file. Two fixtures: a plain repo, and one with an immediate prune saved in its git config.
//! Env (test only): CLAUDE_GUARD_REF_REPO_BASH, CLAUDE_GUARD_REF_REPO_CONFIG (as in differential_repo.rs),
//! CLAUDE_GUARD_DIFF_CASES (default 4000; the saved-prune fixture gets a sixth), CLAUDE_GUARD_DIFF_SEED,
//! CLAUDE_GUARD_DIFF_WORKERS.

mod common;
use common::*;
use serde_json::{Value, json};

struct Names {
    locked: Vec<String>,
    output: String,
    ledger: String,
    over: String,
    base: String,
}

fn names(config: &Value, d: &str) -> Names {
    let s = |p: &[&str]| {
        p.iter()
            .fold(config, |v, k| &v[*k])
            .as_str()
            .unwrap()
            .to_string()
    };
    let ledger_dir = s(&["pre_bash", "write_ledger", "dir"]);
    Names {
        locked: config["locked_dirs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect(),
        output: config["output_dirs"][0].as_str().unwrap().to_string(),
        ledger: ledger_dir.rsplit('/').next().unwrap().to_string(),
        over: s(&["pre_bash", "write_ledger", "override_env"]),
        base: d.rsplit('/').next().unwrap().to_string(),
    }
}

fn git(d: &str, args: &[&str]) {
    let ok = std::process::Command::new("git")
        .args(["-C", d])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

fn fixture(d: &str, config: &str, n: &Names, saved_prune: bool) {
    let l0 = &n.locked[0];
    for sub in [
        "sub".to_string(),
        "home".into(),
        ".claude".into(),
        "wt".into(),
        format!("wt/{l0}"),
        n.output.clone(),
        format!("{}/{}", n.output, n.ledger),
        "crash".into(),
    ]
    .into_iter()
    .chain(n.locked.iter().map(|l| format!("{l}/sub")))
    {
        std::fs::create_dir_all(format!("{d}/{sub}")).unwrap();
    }
    let w = |p: &str, s: &[u8]| std::fs::write(format!("{d}/{p}"), s).unwrap();
    w(".claude/repo-guard.json", config.as_bytes());
    w("wt/.git", b"gitdir: /nowhere\n");
    w("file.md", b"x\n");
    w("sub/file.md", b"x\n");
    for l in &n.locked {
        w(&format!("{l}/a.md"), b"x\n");
    }
    w("s.sh", b"#!/bin/bash\ngit commit -m x\n");
    w("ok.sh", b"#!/bin/bash\nls\n");
    w(
        "w.sh",
        format!("#!/bin/sh\necho x > {l0}/a.md\n").as_bytes(),
    );
    w("env.sh", b"#!/usr/bin/env bash\ngit stash\n");
    w("py.sh", b"#!/usr/bin/python3\ngit commit\n");
    w("crlf.sh", b"#!/bin/bash\r\ngit stash\r\n");
    w("bad.sh", b"#!/bin/bash\n\xff git commit\n");
    w("plain.sh", b"git commit\n");
    let mut big = b"#!/bin/bash\n".to_vec();
    big.extend(vec![b'#'; 300 * 1024]);
    big.extend(b"\ngit commit\n");
    w("big.sh", &big);
    git(d, &["init", "-q"]);
    if saved_prune {
        git(d, &["config", "gc.pruneExpire", "now"]);
    }
}

fn generate(rng: &mut Rng, n: &Names) -> String {
    let l0 = n.locked[0].as_str();
    let l1 = n.locked.get(1).unwrap_or(&n.locked[0]).as_str();
    let (out, ledger, over, base) = (
        n.output.as_str(),
        n.ledger.as_str(),
        n.over.as_str(),
        n.base.as_str(),
    );
    let prefixes: Vec<String> = vec![
        "".into(),
        "".into(),
        "".into(),
        "".into(),
        "cd sub && ".into(),
        format!("cd {l0} && "),
        format!("cd {l0}/sub; "),
        "cd wt && ".into(),
        "cd /tmp && ".into(),
        "(cd /tmp; ls); ".into(),
        "(cd sub && ".into(),
        "cd $NOPE && ".into(),
        format!("pushd {l1} >/dev/null && "),
        "cd ~ && ".into(),
        "cd $FIXTURE && ".into(),
        "cd \"$(pwd)\" && ".into(),
        "FOO=1 ".into(),
        "X=sub; cd $X && ".into(),
        "export Y=wt; cd $Y && ".into(),
        "GIT_INDEX_FILE=/tmp/idx ".into(),
        "GIT_INDEX_FILE=.git/index ".into(),
        "GIT_DIR=wt/.git ".into(),
        "GIT_WORK_TREE=/tmp ".into(),
        "GIT_CONFIG_PARAMETERS=\"'gc.pruneExpire'='now'\" ".into(),
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=gc.pruneExpire GIT_CONFIG_VALUE_0=now ".into(),
        "GIT_CONFIG_COUNT=x GIT_CONFIG_KEY_0=gc.pruneExpire GIT_CONFIG_VALUE_0=now ".into(),
        "NOW_VAR=now ".into(),
        "rtk ".into(),
        "env ".into(),
        "nice ".into(),
        "command ".into(),
        "time ".into(),
        "cd\n".into(),
        "cd .. && ".into(),
    ];
    let git_opts = [
        "",
        "",
        "",
        "",
        "-C sub ",
        "-C wt ",
        "-C /tmp ",
        "-C $NOPE ",
        "-c gc.pruneExpire=now ",
        "-c gc.reflogExpire= All ",
        "-c gc.x.reflogExpireUnreachable=0 ",
        "-c core.x=1 ",
        "--config-env=gc.pruneExpire=NOW_VAR ",
        "--config-env gc.pruneexpire=NOW_VAR ",
        "--git-dir=wt/.git ",
        "--work-tree=/tmp ",
        "--work-tree . ",
        "--no-pager ",
        "-p ",
        "--namespace x ",
        "-C ",
        "--git-dir=.git ",
        "--exec-path ",
    ];
    let git_cmds = [
        "commit -m x",
        "commit --amend",
        "commit --help",
        "commit -h --help",
        "add .",
        "add -p",
        "rm file.md",
        "mv a b",
        "apply --index p",
        "apply -3 p",
        "apply p",
        "update-index --refresh",
        "update-index --add x",
        "update-index",
        "read-tree HEAD",
        "stash",
        "stash list",
        "stash show",
        "stash pop",
        "stash ''",
        "reset --hard",
        "reset",
        "reset HEAD",
        "reset HEAD~1",
        "reset -- f",
        "reset file.md",
        "reset --soft HEAD",
        "reset main file.md",
        "clean -fd",
        "clean -n",
        "clean -fn",
        "clean",
        "clean --force",
        "checkout main",
        "checkout -- .",
        "checkout -- sub",
        "checkout -- file.md",
        "checkout file.md",
        "checkout -b x",
        "checkout -",
        "checkout -f",
        "checkout --orphan=x",
        "checkout '*.md'",
        "checkout main -- file.md",
        "restore .",
        "restore file.md",
        "restore --staged .",
        "restore -W --staged .",
        "restore -- sub",
        "checkout-index -a",
        "checkout-index x",
        "checkout-index -fu",
        "branch -f x",
        "branch -m x",
        "branch x",
        "branch -D x",
        "branch -Mv",
        "symbolic-ref HEAD",
        "symbolic-ref HEAD refs/heads/x",
        "symbolic-ref -d HEAD",
        "notes add",
        "notes list",
        "notes",
        "notes show",
        "prune",
        "prune -n",
        "prune --expire now",
        "gc",
        "gc --prune=now",
        "gc --prune=2.weeks",
        "gc --auto",
        "gc --prune=all",
        "maintenance run",
        "maintenance start",
        "repack -a -d",
        "repack -ad",
        "repack -Ad",
        "repack -a -d --cruft",
        "repack -d --unpack-unreachable=now",
        "repack -d --cruft-expiration NOW",
        "reflog expire --all",
        "reflog",
        "reflog delete x",
        "bisect start",
        "bisect log",
        "bisect",
        "sparse-checkout set x",
        "sparse-checkout list",
        "config core.x 1",
        "config --get x",
        "config --global x y",
        "config gc.pruneExpire now",
        "config --global gc.pruneexpire now",
        "config set gc.reflogExpire all",
        "config -l",
        "config --unset x",
        "config -e",
        "config x",
        "config --system gc.reflogExpire 0",
        "config --file f x y",
        "rebase main",
        "cherry-pick x",
        "revert x",
        "merge x",
        "pull",
        "am x",
        "filter-branch",
        "filter-repo",
        "update-ref x y",
        "switch x",
        "commit-tree x",
        "status",
        "log",
        "diff",
        "show",
        "worktree add ../x",
        "fetch",
        "push",
        "help commit",
        "",
    ];
    let writes: Vec<String> = vec![
        format!("echo x > {l0}/a.md"),
        format!("echo x >> {l1}/new.md"),
        format!("echo x 2>{l0}/e.log"),
        format!("printf x | tee {l0}/a.md"),
        format!("tee -a {out}/x.txt"),
        format!("sed -i '' s/a/b/ {l0}/a.md"),
        format!("sed -n p {l0}/a.md"),
        format!("gsed --in-place=.bak s/a/b/ {l1}/a.md"),
        format!("perl -pi -e s/a/b/ {l0}/a.md"),
        format!("perl -ne print {l0}/a.md"),
        format!("cp x {l0}/"),
        format!("cp x y {l0}/sub"),
        format!("cp x {l0}/a.md"),
        format!("mv {l0}/a.md /tmp/"),
        format!("install -m 644 x {l1}/b.md"),
        format!("truncate -s 0 {l0}/a.md"),
        "cat x > out.txt".into(),
        format!("echo > {l0}"),
        "echo 2>&1".into(),
        format!("echo x >| {l0}/a.md"),
        format!("cat {l0}/a.md > /dev/null"),
        format!("echo > ./{l0}/../{l0}/c.md"),
        format!("echo > wt/{l0}/a.md"),
        format!("echo > {out}/x"),
        format!("echo x > $FIXTURE/{l0}/a.md"),
        format!("echo x > ~/{l0}/a.md"),
        format!("echo x > \"{l0}/a b.md\""),
        format!("echo x > '{l0}'/a.md"),
        format!("echo x 1> {l0}/a.md"),
        format!("echo x > 2 {l0}/a.md"),
        format!("echo x >- {l0}/a.md"),
        format!("cat <<EOF > {l0}/a.md\nx\nEOF"),
        "echo x > a.md".into(),
    ];
    let ledger_cmds: Vec<String> = vec![
        format!("ls {out}/{ledger}"),
        format!("rm -rf {out}/{ledger}/*"),
        format!("{over}=1 git commit -m x"),
        format!("export {over}=1"),
        format!("git commit -m 'note on {ledger}'"),
        format!("git commit -m\"{over}=1\""),
        format!("git commit --message='{over}=1'"),
        format!("git commit --message {ledger}"),
        format!("echo {over}"),
        format!("echo \"{over}: 1\""),
        format!("echo {over}\\]=1"),
        format!("cat <<EOF\n{ledger}\nEOF"),
        format!("python3 - <<EOF\nimport os\nos.environ['{over}'] = '1'\nEOF"),
        format!("bash <<EOF\nls {ledger}\nEOF"),
        format!("echo $(ls {ledger})"),
        format!("# {ledger}"),
        format!("ls {ledger}x"),
        format!("ls {ledger}-old"),
        format!("ls {ledger}é"),
        format!("{over} =1"),
        format!("{over}\u{1c}=1"),
    ];
    let lit = |p: &str| -> String { p.to_string() };
    let targets: Vec<String> = vec![
        lit(&format!("'{l0}/a.md'")),
        lit(&format!("\"{l1}/sub/x.md\"")),
        lit(&format!("f'{{ROOT}}/{l0}/a.md'")),
        lit(&format!("`${{ROOT}}/{l1}/a.md`")),
        lit(&format!("'/x/{base}/{l0}/a.md'")),
        lit(&format!("'$FIXTURE/{l0}/a.md'")),
        lit("'a.md'"),
        lit(&format!("'{out}/{l0}-copy.md'")),
        lit(&format!("'/tmp/{l0}/a.md'")),
        lit(&format!("'~/{l0}/a.md'")),
        lit("'HOME'"),
        lit(&format!("os.path.join('{l0}', 'a.md')")),
        lit(&format!("os.path.join(ROOT, '{l0}', 'a.md')")),
        lit("p"),
        lit("f"),
        lit("out"),
        lit(&format!("'{l0}/a.md' if x else '{l1}/b.md'")),
        lit(&format!("'{l0}/a.md' + '/tmp/x'")),
        lit(&format!("r'{l0}\\a.md'")),
        lit(&format!("'{l0}/a\\'b.md'")),
        lit(&format!("x'{l0}/a.md'")),
    ];
    let py_writes = [
        "open({t}, 'w')",
        "open({t}, 'a').write('x')",
        "open({t}, mode='w', encoding='utf-8')",
        "open({t})",
        "open({t}, 'r')",
        "io.open({t}, 'w')",
        "os.open({t}, os.O_WRONLY | os.O_CREAT)",
        "x.open({t}, 'w')",
        "Path({t}).write_text('x')",
        "Path({t}).open('w')",
        "Path({t}).read_text()",
        "shutil.copy('/tmp/a', {t})",
        "shutil.move({t}, '/tmp/b')",
        "os.replace('/tmp/a', {t})",
        "os.rename({t}, '/tmp/b')",
        "{t}.touch()",
        "pathlib.Path({t}).rename('/tmp/x')",
        "fh = open({t}, 'x+')",
        "writeFileSync({t}, 'x')",
        "fs.writeFileSync({t}, 'x')",
        "require('fs').appendFileSync({t}, 'y')",
        "fs.renameSync('/tmp/x', {t})",
        "fs.open({t}, 'w', () => {})",
        "fs.openSync({t}, 'r')",
        "File.write({t}, 'x')",
        "File.open({t}, \"w\")",
        "IO.write({t}, 'x')",
        "Bun.write({t}, 'x')",
        "xwriteFileSync({t}, 'x')",
        "$writeFile({t})",
    ];
    let setups: Vec<String> = vec![
        "".into(),
        "".into(),
        format!("p = '{l0}/a.md'\n"),
        format!("p: str = '{l0}/a.md'\n"),
        format!("ROOT = '.'\np = os.path.join(ROOT, '{l0}', 'x.md')\n"),
        format!("for f in ['{l0}/a.md', '{l1}/b.md']:\n    pass\n"),
        format!("const f = '{l0}/a.md';\n"),
        format!("for (const f of ['{l0}/a.md']) {{}}\n"),
        format!("out = '/tmp/{l0}.md'\np = out\n"),
        format!("q = '{l0}/a.md'; p = q\n"),
        "p == 'x'\n".into(),
        format!("let p = `${{dir}}/{l0}/a.md`\n"),
    ];
    let interp = |rng: &mut Rng| -> String {
        let t = rng.pick(&targets).clone();
        let body = format!(
            "{}{}",
            rng.pick(&setups),
            rng.pick(&py_writes).replace("{t}", &t)
        );
        match rng.below(12) {
            0 => format!("python3 - <<'EOF'\n{body}\nEOF"),
            1 => format!("python3 <<EOF\n{body}\nEOF"),
            2 => format!("python3 -c \"{}\"", body.replace('"', "\\\"")),
            3 => format!("node -e \"{}\"", body.replace('"', "\\\"")),
            4 => format!("node --input-type=module <<'EOF'\n{body}\nEOF"),
            5 => format!("cat <<'EOF' | python3\n{body}\nEOF"),
            6 => format!("uv run --with x python - <<'EOF'\n{body}\nEOF"),
            7 => format!("ruby -e '{}'", body.replace('\'', "\"")),
            8 => format!("nice -n 10 python3 <<EOF\n{body}\nEOF"),
            9 => format!("perl -e 'open(my $fh, \">\", \"{l0}/a.md\")'"),
            10 => format!("perl -e 'open(F, \">>{l1}/a.md\")'"),
            _ => format!("cat <<'EOF' > /tmp/x.py\n{body}\nEOF"),
        }
    };
    let wrappers = [
        "{c}",
        "{c}",
        "{c}",
        "{c}",
        "{c}",
        "{c}",
        "bash -c '{c}'",
        "sh -c \"{c}\"",
        "zsh -x -c '{c}'",
        "eval '{c}'",
        "eval {c}",
        "echo $({c})",
        "echo \"$({c})\"",
        "`{c}`",
        "x=$({c})",
        "bash <<EOF\n{c}\nEOF",
        "cat <<EOF\n{c}\nEOF",
        "cat <<EOF | sh\n{c}\nEOF",
        "ssh host bash -c '{c}'",
        "xargs {c}",
        "xargs -n 1 {c}",
        "find . -exec {c} \\;",
        "{c} # x",
        "# {c}",
        "({c})",
        "{c} &",
        "true && {c}",
        "{c} | cat",
        "{c}; echo",
        "{c} || true",
        "echo '{c}'",
        "diff <({c}) x",
        "{{ {c}; }}",
        // a heredoc next to `-c` code is data for that shell, not its script
        "ssh host bash -c 'ls' <<EOF\n{c}\nEOF",
        "bash -lc x <<EOF\n{c}\nEOF",
        "sh -c 'cat' <<'E' | cat\n{c}\nE",
    ];
    let scripts = [
        "./s.sh",
        "bash s.sh",
        "source s.sh",
        ". ./s.sh",
        "sh ok.sh",
        "./w.sh",
        "./env.sh",
        "./py.sh",
        "./crlf.sh",
        "./bad.sh",
        "./plain.sh",
        "bash plain.sh",
        "./big.sh",
        "sub/../s.sh",
        "$FIXTURE/s.sh",
        "bash -x s.sh",
        "bash --norc s.sh",
        "./missing.sh",
    ];
    let noise = [
        "\u{1c}", "\u{a0}", "\t", "\r", "ı", "²", "\\", "'", "\"", "(", ")", "<<", "<<-", "<<<",
        "$(", "`", "\n", ";", "|", "&", "~", "$", "{", "}", "\u{2028}", "\u{85}", "#", ">", "2>",
        "-",
    ];
    let core = match rng.below(20) {
        0..=7 => format!("git {}{}", rng.pick(&git_opts), rng.pick(&git_cmds)),
        8..=10 => rng.pick(&writes).clone(),
        11..=12 => rng.pick(&ledger_cmds).clone(),
        13..=16 => interp(rng),
        17 => rng.pick(&scripts).to_string(),
        18 => format!("/usr/bin/git {}", rng.pick(&git_cmds)),
        _ => format!("echo {}", rng.pick(&git_cmds)),
    };
    let mut cmd = format!(
        "{}{}",
        rng.pick(&prefixes),
        rng.pick(&wrappers).replace("{c}", &core)
    );
    if rng.chance(12) {
        let joiner = *rng.pick(&["; ", " && ", "\n", " | ", " || "]);
        let more = format!("git {}", rng.pick(&git_cmds));
        cmd = format!("{cmd}{joiner}{more}");
    }
    if rng.chance(12) {
        let at = rng.below(cmd.chars().count() + 1);
        let i = cmd
            .char_indices()
            .nth(at)
            .map(|(i, _)| i)
            .unwrap_or(cmd.len());
        cmd.insert_str(i, rng.pick(&noise));
    }
    cmd
}

fn run_fixture(tag: &str, saved_prune: bool, n_cases: usize, seed: u64) -> (usize, Vec<String>) {
    let Some((refs, config_path)) = repo_references() else {
        return (0, Vec::new());
    };
    let workers: usize = env_or("CLAUDE_GUARD_DIFF_WORKERS", "2").parse().unwrap();
    let config = std::fs::read_to_string(&config_path).unwrap();
    let cv: Value = serde_json::from_str(&config).unwrap();
    let d = fresh_dir(tag);
    let n = names(&cv, &d);
    fixture(&d, &config, &n, saved_prune);
    let home = format!("{d}/home");
    let env: Vec<(&str, &str)> = vec![
        ("CLAUDE_PROJECT_DIR", &d),
        ("HOME", &home),
        ("FIXTURE", &d),
        ("EMPTY", ""),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
    ];
    let sub = format!("{d}/sub");
    let in_locked = format!("{d}/{}", n.locked[0]);
    let cwds = [
        json!(sub),
        json!(in_locked),
        json!(format!("{d}/wt")),
        json!(""),
        Value::Null,
        json!("/"),
        json!("relative"),
        json!(5),
        json!([1]),
        json!(0),
    ];
    let mut rng = Rng(seed | 1);
    let mut inputs: Vec<String> = Vec::new();
    for _ in 0..n_cases {
        let command = generate(&mut rng, &n);
        let mut v = json!({"tool_name": "Bash", "tool_input": {"command": command}});
        if rng.chance(75) {
            v["cwd"] = json!(d);
        } else {
            let c = rng.pick(&cwds).clone();
            if !c.is_null() {
                v["cwd"] = c;
            }
        }
        inputs.push(v.to_string());
    }
    for raw in [
        "not json",
        "[]",
        "{}",
        "{\"tool_name\": \"Read\", \"tool_input\": {\"command\": \"git commit\"}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": 5}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": [\"git\", \"commit\"]}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"git commit\"}, \"cwd\": 1.5}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"git commit\"}, \"cwd\": true}",
        "{\"tool_name\": \"Bash\", \"tool_input\": \"git commit\"}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"cd a\\u0000b && git commit\"}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"git -C a\\u0000b gc\"}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"cat ~\\u0000x/a\"}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"echo x > ~\\u0000x/a\"}}",
    ] {
        inputs.push(raw.to_string());
    }
    // Nesting: within Python's recursion limit (deeper differs by a few frames between the driver and a real run).
    for depth in [5, 50, 300] {
        inputs.push(
            json!({"tool_name": "Bash", "tool_input": {"command": format!("{}git commit{}", "$(".repeat(depth), ")".repeat(depth))}, "cwd": d})
                .to_string(),
        );
    }

    let per_hook = reference_runs(&refs, &inputs, &env, &d);
    let rust: Vec<(Out, bool)> = parallel(&inputs, workers, |i, input| {
        let log = format!("{d}/crash/{i}.log");
        let o = run_in(
            &[BIN, "repo", "pre-bash", "--crash-log", &log],
            input,
            &env,
            Some(&d),
        );
        (o, std::path::Path::new(&log).exists())
    });
    let spot = spot_check_driver(&refs, &per_hook, &inputs, &env, &d, workers);

    let mut bad = Vec::new();
    let mut rules = std::collections::BTreeMap::<String, usize>::new();
    for i in 0..inputs.len() {
        let p = combine(&per_hook, i);
        let (r, rcrash) = &rust[i];
        let rule = if r.code == 2 {
            // "Blocked: `git commit` in ..." -> "Blocked: `git commit`"; long op texts cut.
            r.stderr
                .split(" in ")
                .next()
                .unwrap_or("")
                .chars()
                .take(48)
                .collect()
        } else if *rcrash {
            "crash".into()
        } else {
            "allow".into()
        };
        *rules.entry(rule).or_default() += 1;
        if (r.code, r.stdout.as_str(), r.stderr.as_str(), *rcrash)
            != (p.code, p.stdout.as_str(), p.stderr.as_str(), p.crash)
        {
            bad.push(format!(
                "input: {}\n  python: {} crash={} {:?}\n  rust:   {} crash={rcrash} {:?} {:?}",
                inputs[i], p.code, p.crash, p.stderr, r.code, r.stderr, r.stdout
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&d);
    eprintln!(
        "differential repo tree ({tag}): {} inputs, {} unexpected, {spot} spot checks; outcomes {rules:#?}",
        inputs.len(),
        bad.len()
    );
    (inputs.len(), bad)
}

#[test]
fn rust_matches_python() {
    if repo_references().is_none() {
        eprintln!(
            "SKIPPED: set CLAUDE_GUARD_REF_REPO_BASH and CLAUDE_GUARD_REF_REPO_CONFIG to run it"
        );
        return;
    }
    let n: usize = env_or("CLAUDE_GUARD_DIFF_CASES", "4000").parse().unwrap();
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261126")
        .parse()
        .unwrap();
    let (_, mut bad) = run_fixture("tree-diff", false, n, seed);
    let (_, bad2) = run_fixture("tree-diff-saved", true, n / 6 + 1, seed ^ 0x5eed);
    bad.extend(bad2);
    assert!(
        bad.is_empty(),
        "{} unexpected differences (first 15):\n{}",
        bad.len(),
        bad.iter().take(15).cloned().collect::<Vec<_>>().join("\n")
    );
}
