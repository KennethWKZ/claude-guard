//! Helpers shared by the read and husky tests.
#![allow(dead_code)]

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
