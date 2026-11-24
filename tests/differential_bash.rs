//! Differential test: `claude-guard bash` against the hooks it replaces (guard-bash.py + block-pip.sh), on the
//! fixture cases plus thousands of generated commands, cwd values and JSON edge inputs. Any difference in
//! stdout, exit code or stderr fails, except the known ones listed in `known_difference`.
//!
//! Needs the reference hooks; skipped (with a message) when they are missing. Test-only settings come from the
//! environment: CLAUDE_GUARD_REF_BASH, CLAUDE_GUARD_REF_PIP (default ~/.claude/hooks/...),
//! CLAUDE_GUARD_DIFF_CASES (default 4000), CLAUDE_GUARD_DIFF_SEED, CLAUDE_GUARD_DIFF_WORKERS (default 2;
//! pass "$(test-workers)").

use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;

const BIN: &str = env!("CARGO_BIN_EXE_claude-guard");
const PIP_MSG: &str = "Do not use pip. Use uv instead. Example: uv add <packages>";

#[derive(Debug, Clone, PartialEq)]
struct Out {
    stdout: String,
    code: i32,
    stderr: String,
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, v: &'a [String]) -> &'a str {
        &v[self.below(v.len())]
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn sv(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// A folder with secrets files, templates, sub-folders, odd names and a link out of temp, for the glob and
/// realpath paths.
fn fixture_dir() -> String {
    let d = std::env::temp_dir().join(format!("claude-guard-diff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for sub in ["sub", ".hidden", "dir.env"] {
        std::fs::create_dir_all(d.join(sub)).unwrap();
    }
    for f in [
        ".env",
        ".env.local",
        ".env.example",
        "prod.env",
        "a.md",
        "b.md",
        "config.json",
        "x.json",
        "sub/.env.production",
        "sub/notes.md",
        ".hidden/.envrc",
        "[i-0]",
        "data[1].txt",
        "é.env",
        "a.envrc",
    ] {
        std::fs::write(d.join(f), "x\n").unwrap();
    }
    let _ = std::os::unix::fs::symlink("/Users", d.join("link"));
    let _ = std::os::unix::fs::symlink(d.join("sub"), d.join("sublink"));
    d.to_string_lossy().into_owned()
}

fn generate(rng: &mut Rng, dir: &str) -> String {
    let p = "pip";
    let verbs = sv(&[
        "cat",
        "rm",
        "git",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "jq",
        "yq",
        "gojq",
        "cp",
        "install",
        "sudo",
        "source",
        ".",
        "ls",
        "echo",
        "printf",
        "head",
        "sed",
        "test",
        "[",
        "ln",
        "chmod",
        "docker",
        "python3",
        p,
        "pip3",
        "python",
        "uv",
        "bash",
        "sh",
        "eval",
        "/usr/bin/cat",
        "./rm",
        "/bin/rm",
        "less",
        "base64",
        "tail",
        "sort",
        "touch",
    ]);
    let prefixes = sv(&[
        "FOO=1", "env", "xargs", "nice", "do", "then", "{", "command", "time", "if", "A_B=x",
    ]);
    let mut args = sv(&[
        ".env",
        ".env.local",
        ".env.production",
        ".env.example",
        ".env.sample",
        ".env.template",
        "prod.env",
        "x.env",
        ".envrc",
        ".envrc.example",
        "config/.env",
        "./.env",
        "../.env",
        "*.env",
        ".env*",
        ".env.?",
        "*",
        "*.md",
        ".env{,.prod}",
        "{a,.env}",
        "{a,{b,.env.production}}",
        "config{,.local}.json",
        ".env[.]local",
        ".env[i-0]",
        "[i-0]",
        "[!a].env",
        "[a-z].env",
        ".e[n]v",
        "[]].env",
        "[!]].env",
        "[a--b]",
        "-rf",
        "-r",
        "-f",
        "-fr",
        "-Rf",
        "-rR",
        "--recursive",
        "--force",
        "-rn",
        "-uf",
        "--force-with-lease",
        "push",
        "origin",
        "main",
        "--hidden",
        "--no-ignore",
        "--no-ignore-vcs",
        "-uu",
        "-.",
        "-g",
        "'!.env*'",
        "--glob=!**/.env*",
        "-g!.env*",
        "'!node_modules'",
        "--iglob",
        "'!*.env*'",
        "/tmp/x",
        "/private/tmp/y",
        "/srv/x",
        "/",
        "~",
        "~/x",
        "$HOME/x",
        "${HOME}/x",
        "\"$HOME\"",
        "$TMPDIR/x",
        "/tmp",
        "/tmp/../srv/x",
        "/private/var/folders/aa/bb/T/z",
        "/private/var/folders/aa/bb/T",
        "--",
        "-n",
        "-e",
        "'.env.X'",
        ".env.X",
        "'.'",
        "x.json",
        "--from-file=.env.local",
        "--arg",
        "k",
        "v",
        "--rawfile",
        "s",
        "--slurpfile",
        "--indent",
        "4",
        "eval",
        "-o",
        "json",
        "--env-file=.env",
        "--env-file",
        "-m",
        "644",
        "\"quoted .env\"",
        "'single .env'",
        "\\.env",
        "a\\ b",
        "#comment",
        "\"$f\"",
        "'{}'",
        "{}",
        "\"{} in the env\"",
        "i-0e2",
        "\"Reservations[].Instances[?InstanceId=='i-0e2']\"",
        "é",
        "日本.env",
        "--include=*.php",
        "-R",
        "--exclude=.env",
        "-L",
        "--library-path",
        "ea",
        "--expression",
        "-I",
        "--front-matter",
        "''",
        "\"\"",
        "-",
        "--from-file",
        "x=.env",
        "--opt=.env",
        "--opt=!x",
        "a,b",
        "{,}",
        "{.env}",
        "{x,y}{,.env}",
    ]);
    for a in [
        "{D}/.env*",
        "{D}/*",
        "{D}/sub/*",
        "{D}/*/.env*",
        "{D}/[.]env",
        "{D}/.e*",
        "{D}/*.md",
        "{D}/sub/.env{,.x}",
        "{D}/link/x",
        "{D}/sub/../x",
        "{D}/sublink/*",
        "{D}/.hidden/*",
        "{D}/*.env",
        "{D}/[i-0]*",
        "{D}/data[1].txt",
        "{D}/dir.env/*",
        "{D}/*/",
        "{D}/sub",
        "{D}",
        "{D}/link",
        "{D}/nope/*",
    ] {
        args.push(a.replace("{D}", dir));
    }
    let seps = sv(&[
        " ", " ", " ", " ", " ; ", ";", " && ", " || ", " | ", "|", " & ", "(", ")", " ! ", "\n",
        " > ", " >> ", " < ", " 2>&1 ", " &> ", " ;; ", " >| ", "\t",
    ]);
    let tails = sv(&[
        " <<EOF\nrm -rf /srv/x\nEOF\n",
        " <<'X'\ncat .env\nX\n",
        " <<-EOF\n\tsudo ls\n\tEOF\n",
        " <<< \"rm -rf /\"",
        " <<EOF\ncat .env",
        "\nEOF",
        " <<\"Q\"\ngit push -f\nQ\n",
        " <<'Q\nsudo x\nQ\n",
    ]);
    let noise = sv(&["\"", "'", "\\", "#", "`", "$(", "\r"]);
    let mut out = String::new();
    let segs = 1 + rng.below(4);
    for s in 0..segs {
        if s > 0 {
            out.push_str(rng.pick(&seps));
        }
        if rng.chance(15) {
            out.push_str(rng.pick(&prefixes));
            out.push(' ');
        }
        let verb = rng.pick(&verbs).to_string();
        out.push_str(&verb);
        if verb == p || verb == "pip3" || (verb.starts_with("python") && rng.chance(50)) {
            if verb.starts_with("python") {
                out.push_str(" -m pip");
            }
            out.push_str(if rng.chance(80) {
                " install x"
            } else {
                " list"
            });
        }
        if (verb == "bash" || verb == "sh") && rng.chance(40) {
            out.push_str(rng.pick(&tails));
            continue;
        }
        for _ in 0..rng.below(6) {
            out.push(' ');
            out.push_str(rng.pick(&args));
        }
        if rng.chance(8) {
            out.push_str(rng.pick(&tails));
        }
    }
    if rng.chance(5) {
        let at = rng.below(out.len() + 1);
        if out.is_char_boundary(at) {
            out.insert_str(at, rng.pick(&noise));
        }
    }
    out
}

fn hook_input(cmd: &str, cwd: &Value) -> String {
    let mut v = json!({"session_id": "diff", "tool_use_id": "toolu_diff", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}});
    if !cwd.is_null() {
        v["cwd"] = cwd.clone();
    }
    v.to_string()
}

fn run_with(cmd: &[&str], input: &str) -> Out {
    let mut child = Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    let o = child.wait_with_output().unwrap();
    Out {
        stdout: String::from_utf8_lossy(&o.stdout).into(),
        code: o.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&o.stderr).into(),
    }
}

fn parallel<T: Send + Sync, R: Send>(
    items: &[T],
    workers: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let next = Mutex::new(0usize);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..workers.max(1) {
            s.spawn(|| {
                loop {
                    let i = {
                        let mut n = next.lock().unwrap();
                        let i = *n;
                        *n += 1;
                        i
                    };
                    if i >= items.len() {
                        break;
                    }
                    let r = f(&items[i]);
                    results.lock().unwrap()[i] = Some(r);
                }
            });
        }
    });
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(Option::unwrap)
        .collect()
}

fn rule(stdout: &str) -> String {
    let v: Value = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
    let r = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    let r = r.strip_prefix("guard-bash: ").unwrap_or(r);
    r.split([' ', '(']).take(3).collect::<Vec<_>>().join(" ")
}

#[test]
fn rust_matches_python_and_dash() {
    let home = env_or("HOME", "/");
    let ref_bash = env_or(
        "CLAUDE_GUARD_REF_BASH",
        &format!("{home}/.claude/hooks/guard-bash.py"),
    );
    let ref_pip = env_or(
        "CLAUDE_GUARD_REF_PIP",
        &format!("{home}/.claude/hooks/block-pip.sh"),
    );
    if !std::path::Path::new(&ref_bash).exists() || !std::path::Path::new(&ref_pip).exists() {
        eprintln!("SKIPPED: reference hooks not found ({ref_bash}, {ref_pip})");
        return;
    }
    let n: usize = env_or("CLAUDE_GUARD_DIFF_CASES", "4000").parse().unwrap();
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261124")
        .parse()
        .unwrap();
    let workers: usize = env_or("CLAUDE_GUARD_DIFF_WORKERS", "2").parse().unwrap();
    let dir = fixture_dir();
    let tmp = std::env::var("TMPDIR")
        .unwrap_or_else(|_| "/tmp".into())
        .trim_end_matches('/')
        .to_string();

    // Inputs: fixture cases (no cwd), generated commands with assorted cwd values, raw JSON edge inputs.
    let mut inputs: Vec<String> = Vec::new();
    for line in include_str!("fixtures/guard_bash_cases.tsv").lines() {
        if let Some((_, cmd)) = line.split_once('\t').filter(|_| !line.starts_with('#')) {
            let cmd = cmd.replace("{TMPDIR}", &tmp).replace('⏎', "\n");
            inputs.push(hook_input(&cmd, &Value::Null));
            inputs.push(hook_input(&cmd, &json!(dir)));
        }
    }
    let cwds = [
        Value::Null,
        json!(""),
        json!(dir),
        json!(format!("{dir}/")),
        json!("/nonexistent"),
        json!("/tmp"),
        json!(0),
        json!(5),
        json!(["x"]),
        json!(false),
    ];
    let mut rng = Rng(seed | 1);
    for _ in 0..n {
        let cmd = generate(&mut rng, &dir);
        let cwd = if rng.chance(45) {
            json!(dir)
        } else {
            cwds[rng.below(cwds.len())].clone()
        };
        inputs.push(hook_input(&cmd, &cwd));
    }
    for raw in [
        "",
        "not json",
        "{}",
        "[]",
        "null",
        "5",
        "\"x\"",
        "{\"tool_input\": null}",
        "{\"tool_input\": \"x\"}",
        "{\"tool_input\": []}",
        "{\"tool_input\": {}}",
        "{\"tool_input\": {\"command\": null}}",
        "{\"tool_input\": {\"command\": 0}}",
        "{\"tool_input\": {\"command\": \"\"}}",
        "{\"tool_input\": {\"command\": [\"sudo\"]}}",
        "{\"tool_input\": {\"command\": 5}}",
        "{\"tool_input\": {\"command\": true}}",
        "{\"tool_input\": {\"command\": 1.5}}",
        "{\"tool_input\": {\"command\": {\"a\": 1}}}",
        "{\"tool_input\": {\"command\": []}}",
        "{\"tool_input\": {\"command\": \"sudo ls\"}, \"cwd\": {}}",
        "{\"tool_input\": {\"command\": \"cat *.env\"}, \"cwd\": {\"a\": 1}}",
        "{\"tool_input\": {\"command\": \"cat .env\"}} trailing",
        "{\"tool_input\": {\"command\": \"sudo ls\"}, \"x\": NaN}",
        "{\"tool_input\": {\"command\": \"sudo \\ud800\"}}",
        "{\"tool_input\": {\"command\": \"cat .env\\n\"}}",
        "{\"tool_input\": {\"command\": \"cat \\\".env\\n\\\"\"}}",
        "{\"tool_input\": {\"command\": \"sudo ls\"}, \"tool_input\": {\"command\": \"ls\"}}",
        "\u{feff}{\"tool_input\": {\"command\": \"sudo x\"}}",
    ] {
        inputs.push(raw.to_string());
    }

    // Reference: guard-bash.py in-process (driver), block-pip.sh per input.
    let driver = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference_driver.py");
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", driver, "bash", &ref_bash])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        let feed: String = inputs
            .iter()
            .map(|i| json!({"input": i}).to_string() + "\n")
            .collect();
        std::thread::spawn(move || {
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

    let pip: Vec<Out> = parallel(&inputs, workers, |i| run_with(&["/bin/dash", &ref_pip], i));
    let crash_log = format!(
        "{}/claude-guard-diff-bash-crash-{}.log",
        tmp,
        std::process::id()
    );
    let rust: Vec<Out> = parallel(&inputs, workers, |i| {
        run_with(&[BIN, "bash", "--crash-log", &crash_log], i)
    });

    // Spot check: the in-process driver gives what a real `python3 -I guard-bash.py` run prints.
    let spot: Vec<usize> = (0..inputs.len())
        .step_by((inputs.len() / 60).max(1))
        .collect();
    let real: Vec<Out> = parallel(&spot, workers, |&i| {
        run_with(&["/usr/bin/python3", "-I", &ref_bash], &inputs[i])
    });
    for (k, &i) in spot.iter().enumerate() {
        let d = py[i]["stdout"].as_str().unwrap_or("");
        // Crash texts name the crash log, which the driver points at a temp file.
        let both_crashed =
            d.contains("guard-bash crashed") && real[k].stdout.contains("guard-bash crashed");
        if py[i]["error"].is_null() && !both_crashed {
            assert_eq!(
                real[k].stdout, d,
                "driver vs real run differ on input {i}: {}",
                inputs[i]
            );
        }
    }

    let (mut same, mut known, mut bad) = (0, Vec::new(), Vec::new());
    let mut blocked = 0;
    for i in 0..inputs.len() {
        let p_err = py[i]["error"].as_str();
        let p_stdout = py[i]["stdout"].as_str().unwrap_or("").to_string();
        let reference = if !p_stdout.is_empty() {
            Out {
                stdout: p_stdout,
                code: 0,
                stderr: String::new(),
            }
        } else if pip[i].code == 2 {
            Out {
                stdout: String::new(),
                code: 2,
                stderr: format!("{PIP_MSG}\n"),
            }
        } else {
            Out {
                stdout: String::new(),
                code: 0,
                stderr: String::new(),
            }
        };
        let r = &rust[i];
        if r.code == 2 || !r.stdout.is_empty() {
            blocked += 1;
        }
        if p_err.is_none() && *r == reference {
            same += 1;
            continue;
        }
        match known_difference(p_err, &reference, r, &inputs[i]) {
            Some(why) => known.push(why),
            None => bad.push(format!(
                "input: {}\n  reference: {:?} (python error: {:?})\n  rust:      {:?}",
                inputs[i], reference, p_err, r
            )),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&crash_log);
    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for k in &known {
        *counts.entry(k).or_default() += 1;
    }
    eprintln!(
        "differential: {} inputs, {same} identical, {} known differences {:?}, {} unexpected; {blocked} blocked; {} driver spot checks",
        inputs.len(),
        known.len(),
        counts,
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

/// Differences that are intended. Anything else fails the test.
fn known_difference(
    _p_err: Option<&str>,
    reference: &Out,
    rust: &Out,
    input: &str,
) -> Option<&'static str> {
    // Both crashed and blocked; the texts name each guard's own crash log.
    if reference.stdout.contains("guard-bash crashed") && rust.stdout.contains("guard-bash crashed")
    {
        return Some("both-crashed");
    }
    // A lone surrogate escape: Python kept it, Rust reads it as U+FFFD (as jq does); same decision.
    if input.contains("\\ud800")
        && rule(&reference.stdout) == rule(&rust.stdout)
        && reference.code == rust.code
    {
        return Some("lone-surrogate-text");
    }
    None
}
