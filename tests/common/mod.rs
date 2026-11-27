//! Helpers shared by the read and husky tests.
#![allow(dead_code)]

pub mod dnsbl;

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;

pub const BIN: &str = env!("CARGO_BIN_EXE_claude-guard");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run `cmd` with `input` on stdin; `env` adds or replaces variables; `cwd` sets the working folder.
pub fn run_in(cmd: &[&str], input: &str, env: &[(&str, &str)], cwd: Option<&str>) -> Out {
    let mut c = Command::new(cmd[0]);
    c.args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        c.env(k, v);
    }
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    let mut child = c.spawn().unwrap();
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    let o = child.wait_with_output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into(),
        stderr: String::from_utf8_lossy(&o.stderr).into(),
    }
}

pub fn run(cmd: &[&str], input: &str) -> Out {
    run_in(cmd, input, &[], None)
}

pub fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

pub fn home() -> String {
    env_or("HOME", "/")
}

pub fn tmp() -> String {
    std::env::var("TMPDIR")
        .unwrap_or_else(|_| "/tmp".into())
        .trim_end_matches('/')
        .to_string()
}

/// A fresh empty folder under $TMPDIR.
pub fn fresh_dir(tag: &str) -> String {
    let d = format!("{}/claude-guard-{tag}-{}", tmp(), std::process::id());
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
    pub fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

pub fn parallel<T: Send + Sync, R: Send>(
    items: &[T],
    workers: usize,
    f: impl Fn(usize, &T) -> R + Sync,
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
                    let r = f(i, &items[i]);
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

/// Key header text built at run time, so no file in the repo holds one (secret scanners flag them).
pub fn header(kind: &str) -> String {
    format!("{}{} {}{}", "-----", "BEGIN", kind, "-----")
}

/// One repo hook's answer, or the combined answer of a repo's Python PreToolUse Bash hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefOut {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub crash: bool,
}

/// The reference hooks from `CLAUDE_GUARD_REF_REPO_BASH` (paths separated by ':', in the order the repo's settings
/// list them) and the config from `CLAUDE_GUARD_REF_REPO_CONFIG`; None when either is unset (the test skips).
pub fn repo_references() -> Option<(Vec<String>, String)> {
    let refs = std::env::var("CLAUDE_GUARD_REF_REPO_BASH").ok()?;
    let config = std::env::var("CLAUDE_GUARD_REF_REPO_CONFIG").ok()?;
    Some((refs.split(':').map(str::to_string).collect(), config))
}

/// Run every input through each reference hook in-process (`tests/reference_driver.py repo-bash`), per hook.
pub fn reference_runs(
    refs: &[String],
    inputs: &[String],
    env: &[(&str, &str)],
    cwd: &str,
) -> Vec<Vec<RefOut>> {
    let driver = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference_driver.py");
    refs.iter()
        .map(|reference| {
            let mut cmd = Command::new("/usr/bin/python3");
            cmd.args(["-I", driver, "repo-bash", reference])
                .current_dir(cwd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped());
            for (k, v) in env {
                cmd.env(k, v);
            }
            let mut child = cmd.spawn().unwrap();
            let mut stdin = child.stdin.take().unwrap();
            let feed: String = inputs
                .iter()
                .map(|i| serde_json::json!({ "input": i }).to_string() + "\n")
                .collect();
            let writer = std::thread::spawn(move || {
                let _ = stdin.write_all(feed.as_bytes());
            });
            let out = child.wait_with_output().unwrap();
            let _ = writer.join();
            let rows: Vec<RefOut> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|l| {
                    let v: serde_json::Value = serde_json::from_str(l).unwrap();
                    RefOut {
                        code: v["code"].as_i64().unwrap() as i32,
                        stdout: v["stdout"].as_str().unwrap_or("").into(),
                        stderr: v["stderr"].as_str().unwrap_or("").into(),
                        crash: v["crash"].as_bool().unwrap(),
                    }
                })
                .collect();
            assert_eq!(
                rows.len(),
                inputs.len(),
                "driver for {reference} answered {} of {}",
                rows.len(),
                inputs.len()
            );
            rows
        })
        .collect()
}

/// What Claude Code makes of the hooks run side by side, as `repo pre-bash` reports it: the first block (in the
/// settings' order) with its message, else an allow; a crash when any of them crashed.
pub fn combine(per_hook: &[Vec<RefOut>], i: usize) -> RefOut {
    let outs: Vec<&RefOut> = per_hook.iter().map(|h| &h[i]).collect();
    let crash = outs.iter().any(|o| o.crash);
    let stdout: String = outs.iter().map(|o| o.stdout.as_str()).collect();
    match outs.iter().find(|o| o.code == 2) {
        Some(b) => RefOut {
            code: 2,
            stdout,
            stderr: b.stderr.clone(),
            crash,
        },
        None => RefOut {
            code: outs.iter().map(|o| o.code).find(|c| *c != 0).unwrap_or(0),
            stdout,
            stderr: outs.iter().map(|o| o.stderr.as_str()).collect(),
            crash,
        },
    }
}

/// Real `python3 -I` runs of each reference hook on a sample, against the in-process driver's answers.
pub fn spot_check_driver(
    refs: &[String],
    per_hook: &[Vec<RefOut>],
    inputs: &[String],
    env: &[(&str, &str)],
    cwd: &str,
    workers: usize,
) -> usize {
    let spot: Vec<usize> = (0..inputs.len())
        .step_by((inputs.len() / 60).max(1))
        .collect();
    for (h, reference) in refs.iter().enumerate() {
        let real: Vec<Out> = parallel(&spot, workers, |_, &i| {
            run_in(
                &["/usr/bin/python3", "-I", reference],
                &inputs[i],
                env,
                Some(cwd),
            )
        });
        for (k, &i) in spot.iter().enumerate() {
            let d = &per_hook[h][i];
            assert_eq!(
                (
                    real[k].code,
                    real[k].stdout.as_str(),
                    real[k].stderr.as_str()
                ),
                (d.code, d.stdout.as_str(), d.stderr.as_str()),
                "driver vs real ({reference}) on {}",
                inputs[i]
            );
        }
    }
    spot.len()
}
