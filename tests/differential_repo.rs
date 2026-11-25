//! Differential test: `claude-guard repo pre-bash` against a repo's Python PreToolUse Bash hook on generated
//! commands, script files and JSON edges. Exit code, stdout and stderr must match exactly, and both must crash on
//! the same inputs (the Python hook logs a crash and allows; the Rust one does the same).
//!
//! The reference hook and its config belong to a private repo, so nothing of theirs is in this one: the test runs
//! only when both paths are given, and skips otherwise.
//! Env (test only): CLAUDE_GUARD_REF_REPO_BASH (the Python hook), CLAUDE_GUARD_REF_REPO_CONFIG (that repo's
//! .claude/repo-guard.json), CLAUDE_GUARD_DIFF_CASES (default 4000), CLAUDE_GUARD_DIFF_SEED,
//! CLAUDE_GUARD_DIFF_WORKERS (default 2; pass "$(test-workers)").

mod common;
use common::*;
use serde_json::{Value, json};
use std::process::{Command, Stdio};

const UNGUARDED: &str = "import boto3\nboto3.client('logs').start_query(logGroupName='g')\n";

/// Scripts the generated commands run, and the guard module named in the config (`guard`).
fn fixture(d: &str, config: &str, guard: &str) {
    for sub in [
        "sub", "sub/deep", "home", "other", ".claude", "dir.py", "crash",
    ] {
        std::fs::create_dir_all(format!("{d}/{sub}")).unwrap();
    }
    let w = |p: &str, s: &[u8]| std::fs::write(format!("{d}/{p}"), s).unwrap();
    w(".claude/repo-guard.json", config.as_bytes());
    let guarded = format!("import {guard}\n{UNGUARDED}");
    for p in [
        "old.py",
        "sub/old.py",
        "sub/deep/old.py",
        "home/h.py",
        "other/o.py",
        "space name.py",
        "ı.py",
    ] {
        w(p, UNGUARDED.as_bytes());
    }
    for p in ["new.py", "sub/new.py", "home/g.py"] {
        w(p, guarded.as_bytes());
    }
    w(
        "shell.py",
        b"import os\nos.system('aws logs start-query --x 1')\n",
    );
    w(
        "popen.py",
        b"import os\nos.popen(\"aws  logs\\tstart-query\")\n",
    );
    w(
        "argv.py",
        b"import subprocess\nsubprocess.run(['aws', 'logs', 'start-query'])\n",
    );
    w(
        "mention.py",
        b"# aws logs start-query is not run here\nprint('start-query')\n",
    );
    w("dq.py", b"x = \"start-query\"\n");
    w("spaced.py", b"client.start_query  (x)\n");
    w("nospace.py", b"client.start_query\x1c(x)\n");
    w("bad-utf8.py", b"\xff\xfe start_query(\x80)\n");
    w(
        "crlf.py",
        b"import boto3\r\nboto3.client('logs').start_query()\r\n",
    );
    let mut big = "#".repeat(2 * 1024 * 1024 + 10);
    big.push_str("\n.start_query(\n");
    w("big.py", big.as_bytes());
    let mut edge = "é".repeat(2 * 1024 * 1024 - 20);
    edge.push_str(".start_query(");
    w("edge.py", edge.as_bytes());
}

fn generate(rng: &mut Rng, d: &str) -> String {
    let prefixes = [
        "",
        "",
        "",
        "cd sub && ",
        "cd sub; ",
        "cd sub\n",
        "cd sub/deep && ",
        "(cd sub && ls); ",
        "pushd sub >/dev/null && ",
        "cd .. && ",
        "cd ./sub && ",
        "cd $FIXTURE/sub && ",
        "cd ${FIXTURE} && ",
        "cd ~ && ",
        "cd $NOPE && ",
        "cd \"$(pwd)\" && ",
        "cd /nonexistent && ",
        "FOO=1 ",
        "cd sub && cd deep && ",
        "cd 'sub' && ",
        "cd sub || ",
        "cd sub & ",
        "cd\n",
        "cd && ",
        "(cd sub; python3 old.py) && ",
        "{ cd sub; } && ",
        "cd sub | ",
        "cd -P sub && ",
        "cd other && cd ../sub && ",
    ];
    let runners = [
        "python3 ",
        "python3 ",
        "python ",
        "python3.12 ",
        "/usr/bin/python3 ",
        "uv run python ",
        "uv run ",
        "env python3 ",
        "nice python3 ",
        "pythonw ",
        "ipython ",
        "python3 -u ",
        "python3 -X dev ",
        "./",
        "",
        "sudo python3 ",
        "py ",
        "PYTHONPATH=x python3 ",
        "time python3 ",
        "exec python3 ",
        "python3\t",
        "python3\u{a0}",
        "python3\u{1c}",
    ];
    let paths = [
        "old.py",
        "new.py",
        "sub/old.py",
        "./old.py",
        "../old.py",
        "~/h.py",
        "~/g.py",
        "~",
        "$HOME/h.py",
        "${HOME}/g.py",
        "${FIXTURE}/old.py",
        "$FIXTURE/sub/old.py",
        "$NOPE/old.py",
        "$EMPTY/old.py",
        "\"$(ls)\"/old.py",
        "`ls`.py",
        "'old.py'",
        "\"sub/old.py\"",
        "old.py;",
        "dir.py",
        "big.py",
        "edge.py",
        "bad-utf8.py",
        "crlf.py",
        "\"space name.py\"",
        "space name.py",
        "missing.py",
        "shell.py",
        "popen.py",
        "argv.py",
        "mention.py",
        "dq.py",
        "spaced.py",
        "nospace.py",
        "ı.py",
        "deep/old.py",
        "o.py",
        "other/o.py",
        "old.PY",
        "old.py.bak",
        "old.pyc",
        "-m old",
        "x.py\\;",
        "old.py#",
        "$FIXTURE/../x/../old.py",
        "/old.py",
        "sub//old.py",
        "~nobody/x.py",
        "~/../home/h.py",
        "\"$FIXTURE\"/old.py",
        "${FIXTURE:-x}/old.py",
        "$1/old.py",
        "$FIXTURE$NOPE/old.py",
    ];
    let suffixes = [
        "",
        "",
        "",
        "; echo done",
        " && echo ok",
        " | tee out",
        " > out.txt",
        " 2>&1",
        " &",
        "\n",
        " # old.py",
        "'",
        "`",
        "\\",
        " ; cd sub && python3 old.py",
        "\necho x",
        ")",
        "(",
        " <<<x",
        " && python3 new.py",
        ";;",
        "|&",
        "\n\n",
    ];
    let raw = [
        "aws logs start-query --query-string x",
        "aws --profile p logs start-query",
        "aws logs describe-queries",
        "echo 'aws logs start-query'",
        "bash -c 'aws logs start-query x'",
        "sh -c \"aws logs start-query\"",
        "zsh -x -c 'aws logs start-query'",
        "bash -lc 'aws logs start-query'",
        "echo $(aws logs start-query)",
        "echo \"$(aws logs start-query)\"",
        "`aws logs start-query`",
        "x=$(aws logs start-query)",
        "bash <<EOF\naws logs start-query\nEOF",
        "cat <<EOF\naws logs start-query\nEOF",
        "cat <<EOF | sh\naws logs start-query\nEOF",
        "sh <<-'END'\n\taws logs start-query\n\tEND",
        "/usr/local/bin/aws logs start-query",
        "aws logs  start-query",
        "aws\tlogs\tstart-query",
        "aws logs start-query; aws logs get-query-results",
        "AWS logs start-query",
        "aws logs start-querys",
        "aws logs 'start-query'",
        "aws log start-query",
        "aws logs --x start-query",
        "bash -c \"bash -c 'bash -c \\\"aws logs start-query\\\"'\"",
        "bash -c 'bash -c \"bash -c 'aws logs start-query'\"'",
        "env aws logs start-query",
        "(aws logs start-query)",
        "aws logs start-query&",
        "a=1 aws logs start-query",
        "python3 - <<'EOF'\nimport boto3\nboto3.client('logs').start_query()\nEOF",
        "python3 - <<'EOF'\nimport guard_x, boto3\nboto3.client('logs').start_query()\nEOF",
        "python3 -c \"import boto3; boto3.client('logs').start_query()\"",
        "python3 -c 'x' ; echo start-query",
        "python3 -c \"subprocess.run(['aws','logs','start-query'])\"",
        "python3 -c \"os.system('aws logs start-query')\"",
        "python3 -c\t\"x.start_query(\"",
        "uv run python -c 'a.start_query()'",
        "cat <<EOF > s.py\nimport boto3\nboto3.client('logs').start_query()\nEOF\npython3 s.py",
        "python3 <<EOF\nos.popen('aws logs start-query')\nEOF",
        "git commit -m 'python3 x.start_query()'",
    ];
    let noise = [
        "\u{1c}", "\u{a0}", "\t", "\r", "ı", "²", "\\", "'", "\"", "(", ")", "<<", "<<-", "<<<",
        "$(", "`", "\n", ";", "|", "&", "~", "$", "{", "}", "\u{2028}", "\u{85}", "\0",
    ];
    let mut cmd = match rng.below(10) {
        0..=2 => rng.pick(&raw).to_string(),
        _ => format!(
            "{}{}{}{}",
            rng.pick(&prefixes),
            rng.pick(&runners),
            rng.pick(&paths),
            rng.pick(&suffixes)
        ),
    };
    if rng.chance(15) {
        let joiner = *rng.pick(&["; ", " && ", "\n", " | ", " || "]);
        let more = format!("{}{}", rng.pick(&runners), rng.pick(&paths));
        cmd = format!("{cmd}{joiner}{more}");
    }
    if rng.chance(15) {
        let at = rng.below(cmd.chars().count() + 1);
        let i = cmd
            .char_indices()
            .nth(at)
            .map(|(i, _)| i)
            .unwrap_or(cmd.len());
        cmd.insert_str(i, rng.pick(&noise));
    }
    if rng.chance(5) {
        cmd = cmd.replace("$FIXTURE", d);
    }
    cmd
}

#[test]
fn rust_matches_python() {
    let (Ok(reference), Ok(config_path)) = (
        std::env::var("CLAUDE_GUARD_REF_REPO_BASH"),
        std::env::var("CLAUDE_GUARD_REF_REPO_CONFIG"),
    ) else {
        eprintln!(
            "SKIPPED: set CLAUDE_GUARD_REF_REPO_BASH and CLAUDE_GUARD_REF_REPO_CONFIG to run it"
        );
        return;
    };
    let config = std::fs::read_to_string(&config_path).unwrap();
    let guard = serde_json::from_str::<Value>(&config).unwrap()["pre_bash"]["logs_insights"]["guard_module"]
        .as_str()
        .unwrap()
        .to_string();
    let n: usize = env_or("CLAUDE_GUARD_DIFF_CASES", "4000").parse().unwrap();
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261125")
        .parse()
        .unwrap();
    let workers: usize = env_or("CLAUDE_GUARD_DIFF_WORKERS", "2").parse().unwrap();
    let d = fresh_dir("repo-diff");
    fixture(&d, &config, &guard);
    let home = format!("{d}/home");
    let env: Vec<(&str, &str)> = vec![
        ("CLAUDE_PROJECT_DIR", &d),
        ("HOME", &home),
        ("FIXTURE", &d),
        ("EMPTY", ""),
    ];

    let cwds = [
        json!(d),
        json!(format!("{d}/sub")),
        json!(""),
        Value::Null,
        json!("/"),
        json!("relative"),
        json!(5),
        json!(true),
        json!([1]),
        json!(0),
        json!({}),
    ];
    let mut rng = Rng(seed | 1);
    let mut inputs: Vec<String> = Vec::new();
    for _ in 0..n {
        let command = generate(&mut rng, &d);
        let mut v = json!({"tool_name": "Bash", "tool_input": {"command": command}});
        if rng.chance(70) {
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
        "",
        "not json",
        "[]",
        "{}",
        "null",
        "5",
        "\"Bash\"",
        "{\"tool_name\": \"Read\", \"tool_input\": {\"command\": \"aws logs start-query\"}}",
        "{\"tool_name\": \"Bash\"}",
        "{\"tool_name\": \"Bash\", \"tool_input\": null}",
        "{\"tool_name\": \"Bash\", \"tool_input\": []}",
        "{\"tool_name\": \"Bash\", \"tool_input\": [1]}",
        "{\"tool_name\": \"Bash\", \"tool_input\": \"x\"}",
        "{\"tool_name\": \"Bash\", \"tool_input\": 0}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": 5}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": []}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": [\"aws\"]}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": true}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": false}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"\"}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": NaN}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"python3 old.py\"}, \"cwd\": 1.5}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"cd $NOPE && python3 old.py\"}, \"cwd\": 1.5}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"python3 /old.py\"}, \"cwd\": [1]}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"python3 a\\u0000b.py\"}}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"aws logs start-query\"}, \"x\": Infinity}",
        "{\"tool_name\": \"Bash\", \"tool_name\": \"Read\", \"tool_input\": {\"command\": \"aws logs start-query\"}}",
    ] {
        inputs.push(raw.to_string());
    }
    for depth in [900, 993, 994, 1200] {
        inputs.push(format!(
            "{{\"tool_name\": \"Bash\", \"x\": {}{}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        ));
    }

    let driver = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference_driver.py");
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.args(["-I", driver, "repo-bash", &reference])
        .current_dir(&d)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    for (k, v) in &env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        let feed: String = inputs
            .iter()
            .map(|i| json!({"input": i}).to_string() + "\n")
            .collect();
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = stdin.write_all(feed.as_bytes());
        });
    }
    let py_out = child.wait_with_output().unwrap();
    let py: Vec<Value> = String::from_utf8_lossy(&py_out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        py.len(),
        inputs.len(),
        "driver answered {} of {}",
        py.len(),
        inputs.len()
    );

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

    // Spot-check the in-process driver against real runs of the hook (which log a crash instead of reporting it).
    let spot: Vec<usize> = (0..inputs.len())
        .step_by((inputs.len() / 60).max(1))
        .collect();
    let real: Vec<Out> = parallel(&spot, workers, |_, &i| {
        run_in(
            &["/usr/bin/python3", "-I", &reference],
            &inputs[i],
            &env,
            Some(&d),
        )
    });
    for (k, &i) in spot.iter().enumerate() {
        assert_eq!(
            (
                real[k].code,
                real[k].stdout.as_str(),
                real[k].stderr.as_str()
            ),
            (
                py[i]["code"].as_i64().unwrap() as i32,
                py[i]["stdout"].as_str().unwrap(),
                py[i]["stderr"].as_str().unwrap()
            ),
            "driver vs real on {}",
            inputs[i]
        );
    }

    let (mut same, mut known, mut bad, mut blocked, mut crashed) = (
        0,
        std::collections::BTreeMap::<&str, usize>::new(),
        Vec::new(),
        0,
        0,
    );
    for i in 0..inputs.len() {
        let (pc, po, pe, pcrash) = (
            py[i]["code"].as_i64().unwrap() as i32,
            py[i]["stdout"].as_str().unwrap_or(""),
            py[i]["stderr"].as_str().unwrap_or(""),
            py[i]["crash"].as_bool().unwrap(),
        );
        let (r, rcrash) = &rust[i];
        blocked += (r.code == 2) as usize;
        crashed += *rcrash as usize;
        if (r.code, r.stdout.as_str(), r.stderr.as_str(), *rcrash) == (pc, po, pe, pcrash) {
            same += 1;
        } else if inputs[i].contains("\\ud8") || inputs[i].contains("\\udc") {
            // A lone surrogate: Python keeps it (and can't open a path with one); hookio reads it as U+FFFD.
            *known.entry("lone-surrogate").or_default() += 1;
        } else {
            bad.push(format!(
                "input: {}\n  python: {pc} crash={pcrash} {pe:?}\n  rust:   {} crash={rcrash} {:?} {:?}",
                inputs[i], r.code, r.stderr, r.stdout
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&d);
    eprintln!(
        "differential repo pre-bash: {} inputs, {same} identical, known {known:?}, {} unexpected; {blocked} blocked, {crashed} crashed; {} spot checks",
        inputs.len(),
        bad.len(),
        spot.len()
    );
    assert!(
        bad.is_empty(),
        "{} unexpected differences (first 15):\n{}",
        bad.len(),
        bad.iter().take(15).cloned().collect::<Vec<_>>().join("\n")
    );
}
