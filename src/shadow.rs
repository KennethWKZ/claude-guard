//! Shadow mode: run a Rust hook next to the hook it replaces, never block, and log whether they agree.
//!
//! `claude-guard <hook> --shadow` hands the work to a detached copy of itself (`<hook> --shadow-compare`, its
//! own process group) and exits at once: Claude Code waits for every hook, and the comparison runs Python, so
//! doing it inline made each call wait 100-200 ms longer. Neither process prints anything; both exit 0.
//!
//! - bash, read: the detached copy decides with the Rust code, runs the reference hook(s) on the same input and
//!   compares the verdicts.
//! - repo pre-bash: the detached copy decides with the Rust code and runs every reference hook given (a repo's
//!   Python Bash hooks, in its settings' order) side by side, as Claude Code does; the reference verdict is the
//!   first block among them, else an allow. A reference that crashes logs to the repo's own error log, as it does
//!   when it runs as the hook, so a crash shows there twice during the shadow week.
//! - repo post-read writes a record per session, so neither side may touch the live one. Each side keeps its own
//!   records under the shadow folder (`--records`, default `<record_dir>-shadow` in the repo): `py/` for the
//!   reference, `rs/` for Rust. One lock around each pair of runs feeds both the same calls in the same order, so
//!   the two folders must stay byte-identical. The reference is the repo's Python hook, loaded by a small shim
//!   (`POST_READ_SHIM`) that points its `record_path` at `py/` and reports a crash by exit code instead of writing
//!   the repo's error log; Rust's crash isn't logged either. When the records differ, `rs/` gets a copy of `py/`,
//!   so one difference is logged once, not again on every later call. This session's own Edits (which the repo's
//!   Edit hook records in the live folder) reach neither side, so both report them alike.
//! - husky copies files, so its reference can't be run a second time. The hook itself works out what it would
//!   copy (dry run) before detaching, which is before the Python hook (40 ms of start-up) copies anything; the
//!   detached copy waits for the Python hook and checks that it copied exactly those items. A worktree the
//!   Rust code doesn't find at all isn't seen here; the differential test covers that.
//!
//! Each log line holds rule ids, counts, timings and the session/tool-use ids to find the call in the
//! transcript, never a command, a path or file contents.

use crate::hookio::{self, py_str};
use crate::{bash, husky, prompt, pyfs, read, repo, repo_read, session_name, web};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Options {
    pub hook: String,
    pub reference: String,
    /// repo pre-bash: every reference hook, in the repo settings' order.
    pub references: Vec<String>,
    pub pip_reference: String,
    /// prompt: the blocked-terms file for both sides (default: the hooks' own default).
    pub terms: Option<String>,
    /// web: the URL policy file for both sides.
    pub policy: Option<String>,
    /// web: pre or post.
    pub web_mode: Option<String>,
    /// repo post-read: the shadow records folder (default `<record_dir>-shadow` in the repo).
    pub records: Option<String>,
    pub log: String,
}

impl Options {
    fn args(&self) -> Vec<String> {
        if self.hook == "repo-post-read" {
            let mut a: Vec<String> = vec![
                "repo".into(),
                "post-read".into(),
                "--shadow-compare".into(),
                "--reference".into(),
                self.reference.clone(),
                "--log".into(),
                self.log.clone(),
            ];
            if let Some(r) = &self.records {
                a.extend(["--records".into(), r.clone()]);
            }
            return a;
        }
        if self.hook == "repo" {
            let mut a: Vec<String> =
                vec!["repo".into(), "pre-bash".into(), "--shadow-compare".into()];
            for r in &self.references {
                a.extend(["--reference".into(), r.clone()]);
            }
            a.extend(["--log".into(), self.log.clone()]);
            return a;
        }
        let mut a = vec![self.hook.clone(), "--shadow-compare".into()];
        if let Some(m) = &self.web_mode {
            a.push(m.clone());
        }
        a.extend([
            "--reference".into(),
            self.reference.clone(),
            "--log".into(),
            self.log.clone(),
        ]);
        if self.hook == "bash" {
            a.extend(["--pip-reference".into(), self.pip_reference.clone()]);
        }
        if let Some(t) = &self.terms {
            a.extend(["--terms".into(), t.clone()]);
        }
        if let Some(p) = &self.policy {
            a.extend(["--policy".into(), p.clone()]);
        }
        a
    }
}

struct Ran {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    code: Option<i32>,
    timed_out: bool,
}

/// Run a reference hook with `input` on stdin, killing it after `limit`.
fn run(cmd: &[&str], input: &[u8], limit: Duration) -> Option<Ran> {
    let mut child = Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        let _ = stdin.write_all(input);
    }
    let mut out = child.stdout.take()?;
    let mut err = child.stderr.take()?;
    let ro = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut out, &mut b);
        b
    });
    let re = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = std::io::Read::read_to_end(&mut err, &mut b);
        b
    });
    let deadline = Instant::now() + limit;
    let (code, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(st)) => break (st.code(), false),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break (None, true);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(_) => break (None, false),
        }
    };
    Some(Ran {
        stdout: ro.join().unwrap_or_default(),
        stderr: re.join().unwrap_or_default(),
        code,
        timed_out,
    })
}

fn field(input: &[u8], key: &str) -> String {
    hookio::parse(input)
        .and_then(|v| v.get(key).and_then(|x| x.as_str()).map(str::to_string))
        .unwrap_or_default()
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

struct Line<'a> {
    hook: &'a str,
    input: &'a [u8],
    rust: String,
    reference: String,
    same: bool,
    same_reason: bool,
    rust_ms: f64,
    reference_ms: f64,
}

fn write_line(log: &str, l: Line) {
    append(log, &line_text(l));
}

fn line_text(l: Line) -> String {
    format!(
        "{{\"time\": {}, \"hook\": {}, \"session_id\": {}, \"tool_use_id\": {}, \"rust\": {}, \"reference\": {}, \"same\": {}, \"same_reason\": {}, \"rust_ms\": {:.1}, \"reference_ms\": {:.1}}}",
        py_str(&crate::now_utc()),
        py_str(l.hook),
        py_str(&field(l.input, "session_id")),
        py_str(&field(l.input, "tool_use_id")),
        py_str(&l.rust),
        py_str(&l.reference),
        l.same,
        l.same_reason,
        l.rust_ms,
        l.reference_ms
    )
}

fn append(path: &str, line: &str) {
    crate::logfile::append(path, line, crate::logfile::SHADOW_CAP);
}

/// The hook: (for husky, plan first,) start the comparison in the background and return without waiting.
pub fn start(opts: &Options) {
    use std::os::unix::process::CommandExt;
    let input = hookio::read_stdin();
    let mut payload = Vec::new();
    if opts.hook == "husky" {
        // First line: the dry-run plan and how long it took; then the hook input.
        let t = Instant::now();
        let plan = match husky::decide(&input, true) {
            husky::Outcome::Copied(_, done) => done
                .iter()
                .map(|c| serde_json::json!({"root": c.root, "items": c.items}))
                .collect::<Vec<_>>(),
            husky::Outcome::Quiet => Vec::new(),
            husky::Outcome::Error(_) => vec![serde_json::json!({"error": true})],
        };
        payload.extend(
            serde_json::json!({"plan": plan, "ms": ms(t)})
                .to_string()
                .into_bytes(),
        );
        payload.push(b'\n');
    }
    payload.extend_from_slice(&input);
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let child = Command::new(exe)
        .args(opts.args())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn();
    match child {
        Ok(mut c) => {
            if let Some(mut stdin) = c.stdin.take() {
                let _ = stdin.write_all(&payload);
            }
        }
        Err(e) => append(
            &opts.log,
            &format!(
                "{{\"time\": {}, \"hook\": {}, \"error\": {}}}",
                py_str(&crate::now_utc()),
                py_str(&opts.hook),
                py_str(&format!("shadow spawn failed: {e}"))
            ),
        ),
    }
}

/// The detached comparison (`<hook> --shadow-compare`).
pub fn compare(opts: &Options) {
    let payload = hookio::read_stdin();
    match opts.hook.as_str() {
        "bash" => compare_bash(opts, &payload),
        "read" => compare_read(opts, &payload),
        "husky" => compare_husky(opts, &payload),
        "prompt" => compare_prompt(opts, &payload),
        "web" => compare_web(opts, &payload),
        "session-name" => compare_session_name(opts, &payload),
        "repo" => compare_repo(opts, &payload),
        "repo-post-read" => compare_post_read(opts, &payload),
        _ => {}
    }
}

fn compare_bash(opts: &Options, input: &[u8]) {
    let t = Instant::now();
    let rust = bash::decide(input, &bash::default_crash_log());
    let rust_ms = ms(t);
    let t = Instant::now();
    let (py, pip) = std::thread::scope(|sc| {
        let a = sc.spawn(|| {
            run(
                &["/usr/bin/python3", "-I", &opts.reference],
                input,
                Duration::from_secs(4),
            )
        });
        let b = sc.spawn(|| {
            run(
                &["/bin/dash", &opts.pip_reference],
                input,
                Duration::from_secs(4),
            )
        });
        (a.join().ok().flatten(), b.join().ok().flatten())
    });
    let reference_ms = ms(t);
    let reference: Result<bash::Verdict, &str> = (|| {
        let py = py.as_ref().ok_or("reference-not-run")?;
        if py.timed_out {
            return Err("reference-timeout");
        }
        let out = String::from_utf8_lossy(&py.stdout).trim().to_string();
        if !out.is_empty() {
            let v: serde_json::Value =
                serde_json::from_str(&out).map_err(|_| "reference-bad-output")?;
            if v.get("systemMessage").is_some() && v.get("hookSpecificOutput").is_none() {
                return Ok(bash::Verdict::Warn(bash::NOT_TEXT));
            }
            let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let crash = bash::rule_of(&reason) == "crash";
            return Ok(bash::Verdict::Deny { reason, crash });
        }
        if py.code != Some(0) {
            return Err("reference-error");
        }
        let pip = pip.as_ref().ok_or("pip-reference-not-run")?;
        if pip.timed_out {
            return Err("pip-reference-timeout");
        }
        Ok(if pip.code == Some(2) {
            bash::Verdict::Pip
        } else {
            bash::Verdict::Allow
        })
    })();
    let (ref_rule, same, same_reason) = match &reference {
        Ok(r) => {
            let same = r.rule() == rust.rule();
            let same_reason = match (r, &rust) {
                (
                    bash::Verdict::Deny {
                        reason: a,
                        crash: false,
                    },
                    bash::Verdict::Deny {
                        reason: b,
                        crash: false,
                    },
                ) => a == b,
                _ => same,
            };
            (r.rule().to_string(), same, same_reason)
        }
        Err(e) => (e.to_string(), false, false),
    };
    write_line(
        &opts.log,
        Line {
            hook: "bash",
            input,
            rust: rust.rule().into(),
            reference: ref_rule,
            same,
            same_reason,
            rust_ms,
            reference_ms,
        },
    );
}

fn compare_read(opts: &Options, input: &[u8]) {
    let t = Instant::now();
    let rust = read::decide(input);
    let rust_ms = ms(t);
    let t = Instant::now();
    let py = run(
        &["/usr/bin/python3", "-I", &opts.reference],
        input,
        Duration::from_secs(4),
    );
    let reference_ms = ms(t);
    let (ref_rule, ref_msg) = match &py {
        None => ("reference-not-run".to_string(), String::new()),
        Some(r) if r.timed_out => ("reference-timeout".to_string(), String::new()),
        Some(r) => {
            let err = String::from_utf8_lossy(&r.stderr).trim().to_string();
            match r.code {
                Some(0) if err.is_empty() => ("allow".to_string(), err),
                Some(2) => (read::rule_of(&err).to_string(), err),
                _ => ("reference-error".to_string(), err),
            }
        }
    };
    let same = ref_rule == rust.rule();
    let same_reason = match &rust {
        read::Verdict::Block { message, .. } => same && *message == ref_msg,
        _ => same,
    };
    write_line(
        &opts.log,
        Line {
            hook: "read",
            input,
            rust: rust.rule().into(),
            reference: ref_rule,
            same,
            same_reason,
            rust_ms,
            reference_ms,
        },
    );
}

/// Both sides decide without writing the allow-name log (the live Python hook writes it): Rust with `dry`, the
/// reference with `--log /dev/null`. Both use the same terms file and run gitleaks the same way.
fn compare_prompt(opts: &Options, input: &[u8]) {
    let mut popts = prompt::Options::parse(&[]);
    popts.dry = true;
    let mut args = vec![
        "/usr/bin/python3",
        "-I",
        &opts.reference,
        "--log",
        "/dev/null",
    ];
    if let Some(t) = &opts.terms {
        popts.terms = t.clone();
        args.extend(["--terms", t]);
    }
    let t = Instant::now();
    let rust = prompt::decide(input, &popts);
    let rust_ms = ms(t);
    let t = Instant::now();
    let py = run(&args, input, Duration::from_secs(4));
    let reference_ms = ms(t);
    let (ref_rule, ref_line) = match &py {
        None => ("reference-not-run".to_string(), String::new()),
        Some(r) if r.timed_out => ("reference-timeout".to_string(), String::new()),
        Some(r) if r.code != Some(0) => ("reference-error".to_string(), String::new()),
        Some(r) => {
            let out = String::from_utf8_lossy(&r.stdout).trim_end().to_string();
            (prompt::rule_of(&out), out)
        }
    };
    // gitleaks lists several findings in a different order from run to run, and both hooks name the first:
    // two gitleaks blocks agree on the verdict even when the rule names differ.
    let gitleaks = |line: &str| line.contains("\"Blocked: looks like a secret (rule ");
    let same = ref_rule == rust.rule() || (gitleaks(&ref_line) && gitleaks(rust.line()));
    write_line(
        &opts.log,
        Line {
            hook: "prompt",
            input,
            rust: rust.rule(),
            reference: ref_rule,
            same,
            same_reason: ref_line == rust.line(),
            rust_ms,
            reference_ms,
        },
    );
}

/// Both sides decide without writing web.log (the live hook writes it): Rust dry, the reference (web-guard.sh,
/// fast path included) with `--log /dev/null`. Same policy and terms files on both sides.
fn compare_web(opts: &Options, input: &[u8]) {
    let mode = opts.web_mode.clone().unwrap_or_default();
    let mut wargs = vec![mode.clone()];
    let mut args = vec![
        "/bin/dash",
        opts.reference.as_str(),
        mode.as_str(),
        "--log",
        "/dev/null",
    ];
    for (flag, v) in [("--terms", &opts.terms), ("--policy", &opts.policy)] {
        if let Some(v) = v {
            args.extend([flag, v.as_str()]);
            wargs.extend([flag.to_string(), v.clone()]);
        }
    }
    let mut wopts = web::Options::parse(&wargs);
    wopts.dry = true;
    let t = Instant::now();
    let rust = web::decide(input, &wopts);
    let rust_ms = ms(t);
    let t = Instant::now();
    let py = run(&args, input, Duration::from_secs(4));
    let reference_ms = ms(t);
    let (ref_rule, ref_line) = match &py {
        None => ("reference-not-run".to_string(), String::new()),
        Some(r) if r.timed_out => ("reference-timeout".to_string(), String::new()),
        Some(r) if r.code != Some(0) => ("reference-error".to_string(), String::new()),
        Some(r) => {
            let out = String::from_utf8_lossy(&r.stdout).trim_end().to_string();
            (web::rule_of(&out, &mode), out)
        }
    };
    write_line(
        &opts.log,
        Line {
            hook: if mode == "post" {
                "web-post"
            } else {
                "web-pre"
            },
            input,
            same: ref_rule == rust.rule,
            same_reason: ref_line == rust.line,
            rust: rust.rule,
            reference: ref_rule,
            rust_ms,
            reference_ms,
        },
    );
}

/// Rust's decision (nothing logged) against the reference hooks run side by side. `same`: the same exit code;
/// `same_reason`: the same stderr too. The reference's rule is Rust's when the messages agree, else "block" or
/// "allow"; a reference crash looks like an allow (that is what Claude Code sees).
fn compare_repo(opts: &Options, input: &[u8]) {
    let t = Instant::now();
    let rust = repo::decide(input, None);
    let rust_ms = ms(t);
    if matches!(rust.verdict, repo::Verdict::NoConfig(_)) {
        // No config: nothing to compare (the hook is off for this repo).
        return;
    }
    let (rcode, rerr) = rust.outcome();
    let t = Instant::now();
    let runs: Vec<Option<Ran>> = std::thread::scope(|sc| {
        let hs: Vec<_> = opts
            .references
            .iter()
            .map(|r| {
                sc.spawn(move || {
                    run(
                        &["/usr/bin/python3", "-I", r.as_str()],
                        input,
                        Duration::from_secs(8),
                    )
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().ok().flatten()).collect()
    });
    let reference_ms = ms(t);
    let reference: Result<(i32, String), &str> = (|| {
        let mut allow = true;
        for r in &runs {
            let r = r.as_ref().ok_or("reference-not-run")?;
            if r.timed_out {
                return Err("reference-timeout");
            }
            match r.code {
                Some(2) => {
                    return Ok((2, String::from_utf8_lossy(&r.stderr).into_owned()));
                }
                Some(0) => {}
                _ => allow = false,
            }
        }
        if allow {
            Ok((0, String::new()))
        } else {
            Err("reference-error")
        }
    })();
    let rust_rule = rust.rule();
    let (ref_rule, same, same_reason) = match &reference {
        Ok((code, err)) => {
            let rule = if *code == rcode && *err == rerr {
                rust_rule.clone()
            } else if *code == 2 {
                "block".into()
            } else {
                "allow".into()
            };
            (rule, *code == rcode, *code == rcode && *err == rerr)
        }
        Err(e) => (e.to_string(), false, false),
    };
    write_line(
        &opts.log,
        Line {
            hook: "repo-pre-bash",
            input,
            rust: rust_rule,
            reference: ref_rule,
            same,
            same_reason,
            rust_ms,
            reference_ms,
        },
    );
}

/// The hook only prints a name, so both run as they are. The log says whether each gave a name, never the name
/// (it comes from Claude's title for the session).
fn compare_session_name(opts: &Options, input: &[u8]) {
    let t = Instant::now();
    let rust = session_name::decide(input, &session_name::registry_dir());
    let rust_ms = ms(t);
    let t = Instant::now();
    let py = run(
        &["/bin/dash", &opts.reference],
        input,
        Duration::from_secs(4),
    );
    let reference_ms = ms(t);
    let kind = |out: &str| if out.is_empty() { "none" } else { "name" };
    let rust_line = rust.unwrap_or_default();
    let (ref_rule, ref_line) = match &py {
        None => ("reference-not-run".to_string(), String::new()),
        Some(r) if r.timed_out => ("reference-timeout".to_string(), String::new()),
        Some(r) if r.code != Some(0) => ("reference-error".to_string(), String::new()),
        Some(r) => {
            let out = String::from_utf8_lossy(&r.stdout).trim_end().to_string();
            (kind(&out).to_string(), out)
        }
    };
    write_line(
        &opts.log,
        Line {
            hook: "session-name",
            input,
            rust: kind(&rust_line).into(),
            same: ref_rule == kind(&rust_line),
            same_reason: ref_line == rust_line,
            reference: ref_rule,
            rust_ms,
            reference_ms,
        },
    );
}

fn compare_husky(opts: &Options, payload: &[u8]) {
    let split = payload
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(payload.len());
    let head: serde_json::Value = serde_json::from_slice(&payload[..split]).unwrap_or_default();
    let input = payload.get(split + 1..).unwrap_or(&[]);
    let plan = head["plan"].as_array().cloned().unwrap_or_default();
    let rust_ms = head["ms"].as_f64().unwrap_or(0.0);
    if plan.iter().any(|p| p.get("error").is_some()) {
        write_line(
            &opts.log,
            Line {
                hook: "husky",
                input,
                rust: "error".into(),
                reference: "unknown".into(),
                same: false,
                same_reason: false,
                rust_ms,
                reference_ms: 0.0,
            },
        );
        return;
    }
    let planned: Vec<String> = plan
        .iter()
        .flat_map(|p| {
            let root = p["root"].as_str().unwrap_or("").to_string();
            p["items"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(move |i| {
                    i.as_str()
                        .map(|i| format!("{root}/.husky/{}", i.trim_start_matches(".husky/")))
                })
        })
        .collect();
    if planned.is_empty() {
        // Nothing missing in the Rust view, so the Python hook had nothing to copy either (it never overwrites),
        // unless it found a worktree the Rust code didn't.
        write_line(
            &opts.log,
            Line {
                hook: "husky",
                input,
                rust: "copy:0".into(),
                reference: "copy:0".into(),
                same: true,
                same_reason: true,
                rust_ms,
                reference_ms: 0.0,
            },
        );
        return;
    }
    let t = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut present = 0;
    while Instant::now() < deadline {
        present = planned.iter().filter(|p| crate::pyfs::lexists(p)).count();
        if present == planned.len() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let n = planned.len();
    write_line(
        &opts.log,
        Line {
            hook: "husky",
            input,
            rust: format!("copy:{n}"),
            reference: format!("copy:{present}"),
            same: present == n,
            same_reason: present == n,
            rust_ms,
            reference_ms: ms(t),
        },
    );
}

/// Runs a stale-read hook's `main()` with its records in another folder: `python3 -I -c SHIM <hook> <folder>`.
/// The hook must define `record_path(repo, session_id)` and `main()`. Exit 3: `main()` raised (the hook itself
/// would have logged it and let the call through). No bytecode is written next to the hook.
pub const POST_READ_SHIM: &str = r#"import importlib.util, os, sys
sys.dont_write_bytecode = True
hook, folder = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("stale_read_shadow", hook)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
live = g.record_path
def record_path(repo, session_id):
    p = live(repo, session_id)
    return os.path.join(folder, os.path.basename(p)) if p else None
g.record_path = record_path
try:
    g.main()
except Exception:
    sys.stdout.flush()
    sys.exit(3)
"#;

/// What a post-read output says: none, elsewhere, during, elsewhere+during, crash, warn (a systemMessage), or
/// notice (some other text). Kinds come from the config's message templates (their text before `{files}`).
fn post_read_rule(out: &str, crashed: bool, cfg: &repo_read::ReadConfig) -> String {
    if crashed {
        return "crash".into();
    }
    let out = out.trim();
    if out.is_empty() {
        return "none".into();
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(out) else {
        return "bad-output".into();
    };
    let Some(text) = v["hookSpecificOutput"]["additionalContext"].as_str() else {
        return if v.get("systemMessage").is_some() {
            "warn".into()
        } else {
            "bad-output".into()
        };
    };
    let has = |tpl: &str| {
        let head = tpl.split("{files}").next().unwrap_or("");
        !head.is_empty() && text.contains(head)
    };
    match (has(&cfg.msg_elsewhere), has(&cfg.msg_during)) {
        (true, true) => "elsewhere+during",
        (true, false) => "elsewhere",
        (false, true) => "during",
        (false, false) => "notice",
    }
    .into()
}

/// Make `rs` a copy of `py` (or remove it when `py` is gone), so one difference is logged once.
fn resync(py: &str, rs: &str) {
    match std::fs::read(py) {
        Ok(bytes) => {
            let tmp = format!("{rs}.{}.sync", std::process::id());
            if std::fs::write(&tmp, bytes).is_ok() {
                let _ = std::fs::rename(&tmp, rs);
            }
        }
        Err(_) => {
            let _ = std::fs::remove_file(rs);
        }
    }
}

fn compare_post_read(opts: &Options, input: &[u8]) {
    let project = std::env::var("CLAUDE_PROJECT_DIR").unwrap_or_default();
    if project.is_empty() {
        return;
    }
    let Ok((_, cfg)) = repo_read::load_config(&project) else {
        // No usable config: the hook is off for this repo (the live hook says so), nothing to compare.
        return;
    };
    let records = opts
        .records
        .clone()
        .unwrap_or_else(|| format!("{}-shadow", pyfs::join(&project, &cfg.record_dir)));
    let (py_dir, rs_dir) = (format!("{records}/py"), format!("{records}/rs"));
    let fail = |why: String| {
        append(
            &opts.log,
            &format!(
                "{{\"time\": {}, \"hook\": \"repo-post-read\", \"error\": {}}}",
                py_str(&crate::now_utc()),
                py_str(&why)
            ),
        )
    };
    for d in [&py_dir, &rs_dir] {
        if let Err(e) = std::fs::create_dir_all(d) {
            return fail(format!("shadow records folder: {e}"));
        }
    }
    // One pair at a time, so both folders see the calls in the same order.
    let _order = match repo_read::lock(&format!("{records}/order")) {
        Ok(l) => l,
        Err(e) => return fail(format!("shadow lock: {e}")),
    };
    let mut rcfg = cfg.clone();
    rcfg.record_dir = rs_dir.clone();
    let t = Instant::now();
    let rust = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        repo_read::run(input, &project, &rcfg)
    }))
    .unwrap_or_else(|_| Err("panic".into()));
    let rust_ms = ms(t);
    let t = Instant::now();
    let py = run(
        &[
            "/usr/bin/python3",
            "-I",
            "-c",
            POST_READ_SHIM,
            &opts.reference,
            &py_dir,
        ],
        input,
        Duration::from_secs(8),
    );
    let reference_ms = ms(t);
    let rust_out = match &rust {
        Ok(Some(s)) => s.clone(),
        _ => String::new(),
    };
    let rust_rule = post_read_rule(&rust_out, rust.is_err(), &cfg);
    let (ref_rule, ref_out) = match &py {
        None => ("reference-not-run".to_string(), String::new()),
        Some(r) if r.timed_out => ("reference-timeout".to_string(), String::new()),
        Some(r) => {
            let out = String::from_utf8_lossy(&r.stdout).into_owned();
            let out = out.strip_suffix('\n').unwrap_or(&out).to_string();
            match r.code {
                Some(0) => (post_read_rule(&out, false, &cfg), out),
                Some(3) => ("crash".to_string(), out),
                _ => ("reference-error".to_string(), String::new()),
            }
        }
    };
    let records_same = match repo_read::record_file(input, &project, &rcfg) {
        None => true,
        Some(rs) => {
            let py_rec = format!("{py_dir}/{}", pyfs::basename(&rs));
            let same = std::fs::read(&py_rec).ok() == std::fs::read(&rs).ok();
            if !same {
                resync(&py_rec, &rs);
            }
            same
        }
    };
    let same = ref_rule == rust_rule && records_same;
    let text = line_text(Line {
        hook: "repo-post-read",
        input,
        same,
        same_reason: same && ref_out == rust_out,
        rust: rust_rule,
        reference: ref_rule,
        rust_ms,
        reference_ms,
    });
    let text = format!(
        "{}, \"records_same\": {records_same}}}",
        text.strip_suffix('}').unwrap_or(&text)
    );
    append(&opts.log, &text);
}
