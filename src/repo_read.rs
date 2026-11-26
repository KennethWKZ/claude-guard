//! `claude-guard repo post-read`: tells a session when a file it read earlier has since been changed by someone
//! else (another session, a script, a person) in a working tree many sessions share. Ported from a repo's Python
//! PostToolUse hook for Read and Bash; the code is generic and every folder, command and message comes from the
//! `post_read` section of the repo's `.claude/repo-guard.json`.
//!
//! How: per session, a record of the tracked files it read (repo-relative path, mtime in ns, size, SHA-256) in
//! `<record_dir>/<session>.json`. A Read, or a Bash command that names files to readers (cat, head, tail, sed -n,
//! awk, jq, yq, diff, rg/grep given files, `<runner> <entity> <type>/<id>`), adds them. Each call compares the
//! record with the disk and reports a changed or deleted file once:
//! - "someone else" when the call could not have written it (a Read, or a Bash command made only of known readers
//!   with nothing redirected into a file), or it is a write tool on another file;
//! - "your command or another session" when a Bash command that can write ran meanwhile and doesn't name the file;
//! - not at all when the call read the new content, or wrote it (its own command names the file).
//!
//! The record format is shared with the repo's Edit hook (Python, `record_own_write`), so both can run side by side:
//! `{"<rel>": {"m": <int>, "s": <int>, "h": "<hex>"}}` written as Python's `json.dump` writes it, insertion
//! ordered (re-adding a path moves it last), at most 400 entries (the oldest drop), under an exclusive `flock` on
//! `<record>.lock` (mode 0600), replaced atomically through `<record>.<pid>.tmp`. Records untouched for 7 days are
//! removed when a session starts its record.
//!
//! Failure behaviour: fails open. A notice, never a block: any internal error (and unreadable input) prints nothing,
//! exits 0 and appends one line to the repo's error log, exactly where the Python hook raised (so a crash before the
//! record is saved leaves it as it was). A missing or invalid config prints a `systemMessage` warning. Panics are
//! caught. Python's quirks are kept on purpose (the differential test against the Python hook decides), e.g. the
//! `startswith("..")` check that also leaves out a top-level folder named `..x`.
//!
//! Overrides are arguments: `--crash-log F` (tests) replaces the config's error log.

use crate::hookio::{self, py_truthy};
use crate::pyre::py_word;
use crate::shell_words::{self as sw, Env};
use crate::{logfile, pyfs};
use serde_json::{Map, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

/// Files one glob can add (`cat people/*.md`).
const GLOB_MAX: usize = 50;
/// Entries per session record; the oldest drop out first.
const TRACK_MAX: usize = 400;
/// Session records (and anything else in the folder) untouched this long are removed.
const STATE_SECS: f64 = 7.0 * 86_400.0;
/// The error log's cap (256 KiB, then one `.1`), as the Python hook kept it.
const LOG_CAP: u64 = 256 * 1024;

const READ_TOOLS: &[&str] = &["Read"];
const WRITE_TOOLS: &[&str] = &["Edit", "MultiEdit", "Write", "NotebookEdit"];
/// Commands that print a file they are given.
const PRINTERS: &[&str] = &["cat", "head", "tail", "less", "more", "bat", "nl"];
const SEARCHERS: &[&str] = &["rg", "grep", "egrep", "fgrep"];
/// Readers besides PRINTERS and SEARCHERS (the config's runner is added).
const OTHER_READERS: &[&str] = &[
    "sed", "gsed", "awk", "gawk", "jq", "yq", "diff", "cmp", "rtk",
];
/// Commands that only read, besides PRINTERS and SEARCHERS.
const READ_ONLY: &[&str] = &[
    "ls", "wc", "pwd", "echo", "printf", "stat", "file", "diff", "cmp", "jq", "yq", "sort", "uniq",
    "cut", "tr", "awk", "date", "true", "test", "[", "which", "type", "basename", "dirname",
    "realpath", "du", "df", "uptime", "tree", "fd", "find",
];
const GIT_READS: &[&str] = &[
    "status",
    "log",
    "diff",
    "show",
    "rev-parse",
    "ls-files",
    "blame",
    "cat-file",
    "grep",
    "describe",
    "shortlog",
    "count-objects",
    "rev-list",
    "merge-base",
    "reflog",
];

/// Options that take a separate value (their value is not a file).
fn value_opts(name: &str) -> &'static [&'static str] {
    match name {
        "head" | "tail" => &["-n", "-c"],
        "rg" => &[
            "-e",
            "-f",
            "-g",
            "--glob",
            "-t",
            "--type",
            "-T",
            "--type-not",
            "-m",
            "--max-count",
            "-A",
            "-B",
            "-C",
            "-M",
            "-j",
            "--threads",
            "--context",
            "--after-context",
            "--before-context",
            "-r",
            "--replace",
        ],
        "grep" => &[
            "-e",
            "-f",
            "-m",
            "-A",
            "-B",
            "-C",
            "--max-count",
            "--context",
        ],
        "sed" => &["-e", "-f"],
        "awk" => &["-F", "-v", "-f"],
        "jq" => &["--indent", "-L", "--tab-width", "-f", "--from-file"],
        "yq" => &[
            "-o",
            "--output-format",
            "-p",
            "--input-format",
            "-I",
            "--indent",
            "--from-file",
        ],
        _ => &[],
    }
}

/// Options that take two values (`jq --arg name value`).
fn value_opts_2(name: &str) -> &'static [&'static str] {
    match name {
        "jq" => &["--arg", "--argjson", "--slurpfile", "--rawfile"],
        _ => &[],
    }
}

/// The options that say the program or expression is not the first plain argument.
fn program_first(name: &str) -> &'static [&'static str] {
    match name {
        "awk" => &["-f"],
        "jq" => &["-f", "--from-file"],
        "yq" => &["--from-file"],
        _ => &[],
    }
}

// ------------------------------------------------------------------------------------------------ config

/// `post_read` in `.claude/repo-guard.json`.
#[derive(Debug, Clone)]
pub struct ReadConfig {
    pub tracked_dirs: Vec<String>,
    /// Folders inside the tracked ones that are not followed (an append-only log).
    pub untracked_dirs: Vec<String>,
    pub generated: Vec<String>,
    /// Where the session records live, relative to the repo.
    pub record_dir: String,
    /// The file name endings of one record's layers (`.md`, `.team.md`, ...): stripped to get its id.
    pub layer_suffixes: Vec<String>,
    /// `<runner> <command> <type>/<id>` reads `<folder>/<id><suffix>`, `folder` from `<schema_dir>/<type>.yaml`.
    pub runner: String,
    pub entity: String,
    pub schema_dir: String,
    pub folder_key: String,
    /// `<runner> <x>` commands that only read.
    pub runner_reads: Vec<String>,
    pub msg_elsewhere: String,
    pub msg_during: String,
    pub msg_stale: String,
}

fn strings(v: &Value, key: &str) -> Result<Vec<String>, String> {
    let arr = v
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("post_read.{key} is not a list"))?;
    arr.iter()
        .map(|x| {
            x.as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    format!("post_read.{key} holds a value that is not a non-empty string")
                })
        })
        .collect()
}

fn text(v: &Value, path: &[&str]) -> Result<String, String> {
    let mut cur = v;
    for k in path {
        cur = cur
            .get(k)
            .ok_or_else(|| format!("post_read.{} is missing", path.join(".")))?;
    }
    cur.as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("post_read.{} is not a non-empty string", path.join(".")))
}

/// The config path, the repo's error log and its `post_read` rules.
pub fn load_config(project: &str) -> Result<(String, ReadConfig), String> {
    let path = format!("{}/.claude/repo-guard.json", project.trim_end_matches('/'));
    let raw = fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| format!("{path}: {e}"))?;
    if v.get("version").and_then(Value::as_i64) != Some(1) {
        return Err(format!("{path}: version is not 1"));
    }
    let error_log = v
        .get("error_log")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{path}: error_log is not a non-empty string"))?;
    let error_log = if error_log.starts_with('/') {
        error_log.to_string()
    } else {
        format!("{project}/{error_log}")
    };
    let p = v
        .get("post_read")
        .ok_or_else(|| format!("{path}: no post_read section"))?;
    let at = |e: String| format!("{path}: {e}");
    let cfg = ReadConfig {
        tracked_dirs: strings(p, "tracked_dirs").map_err(at)?,
        untracked_dirs: strings(p, "untracked_dirs").map_err(at)?,
        generated: strings(p, "generated").map_err(at)?,
        record_dir: text(p, &["record_dir"]).map_err(at)?,
        layer_suffixes: strings(p, "layer_suffixes").map_err(at)?,
        runner: text(p, &["entity_command", "runner"]).map_err(at)?,
        entity: text(p, &["entity_command", "command"]).map_err(at)?,
        schema_dir: text(p, &["entity_command", "schema_dir"]).map_err(at)?,
        folder_key: text(p, &["entity_command", "folder_key"]).map_err(at)?,
        runner_reads: strings(p, "read_only_runner_commands").map_err(at)?,
        msg_elsewhere: text(p, &["messages", "changed_elsewhere"]).map_err(at)?,
        msg_during: text(p, &["messages", "during_command"]).map_err(at)?,
        msg_stale: text(p, &["messages", "stale"]).map_err(at)?,
    };
    if cfg.tracked_dirs.is_empty() || cfg.layer_suffixes.is_empty() {
        return Err(format!(
            "{path}: post_read.tracked_dirs and post_read.layer_suffixes must not be empty"
        ));
    }
    Ok((error_log, cfg))
}

// ------------------------------------------------------------------------------------------------ Python values

/// `repr(float)` (and so `str()` and `json.dumps` of a finite float): shortest round-trip digits, scientific below
/// 1e-4 and from 1e16.
pub fn py_float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.into();
    }
    let sci = format!("{f:e}"); // e.g. "-1.5e16", "1e-5", "0e0"
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (sign, mant) = match mant.strip_prefix('-') {
        Some(m) => ("-", m),
        None => ("", mant),
    };
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    if (-4..16).contains(&exp) {
        let body = if exp >= 0 {
            let int_len = exp as usize + 1;
            if digits.len() <= int_len {
                format!("{digits}{}.0", "0".repeat(int_len - digits.len()))
            } else {
                format!("{}.{}", &digits[..int_len], &digits[int_len..])
            }
        } else {
            format!("0.{}{digits}", "0".repeat((-exp - 1) as usize))
        };
        format!("{sign}{body}")
    } else {
        let frac = if digits.len() > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        let esign = if exp < 0 { '-' } else { '+' };
        format!("{sign}{}{frac}e{esign}{:02}", &digits[..1], exp.abs())
    }
}

/// A float as loaded (inf, -inf and nan arrive as hookio's stand-ins).
fn py_float_value(f: f64) -> (String, Option<&'static str>) {
    (py_float_repr(f), hookio::py_float_name(f))
}

/// `repr(str)`.
fn py_repr_str(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f || (0x80..=0xa0).contains(&(c as u32)) => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

/// `repr()` of a loaded JSON value (inside a list or dict).
fn py_repr(v: &Value) -> String {
    match v {
        Value::String(s) => py_repr_str(s),
        Value::Array(a) => format!("[{}]", a.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", py_repr_str(k), py_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => py_str_of(other),
    }
}

/// `str()` of a loaded JSON value.
fn py_str_of(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => i.to_string(),
            (_, Some(u), _) => u.to_string(),
            (_, _, Some(f)) => {
                let (repr, name) = py_float_value(f);
                name.map_or(repr, str::to_string)
            }
            _ => n.to_string(),
        },
        Value::String(s) => s.clone(),
        other => py_repr(other),
    }
}

/// `json.dump` of a loaded value: Python's separators, ensure_ascii, floats as `repr`, NaN and Infinity by name.
fn py_dump(v: &Value) -> String {
    match v {
        Value::Number(n) if n.is_f64() => {
            let f = n.as_f64().unwrap_or(0.0);
            match hookio::py_float_name(f) {
                Some("inf") => "Infinity".into(),
                Some("-inf") => "-Infinity".into(),
                Some(_) => "NaN".into(),
                None => py_float_repr(f),
            }
        }
        Value::Array(a) => format!("[{}]", a.iter().map(py_dump).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", hookio::py_str(k), py_dump(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => hookio::py_dumps(other),
    }
}

/// Python's `n == value` for an int `n` and a loaded JSON value.
fn py_eq_int(v: Option<&Value>, n: i128) -> bool {
    match v {
        Some(Value::Number(x)) => {
            if let Some(i) = x.as_i64() {
                i as i128 == n
            } else if let Some(u) = x.as_u64() {
                u as i128 == n
            } else {
                x.as_f64().is_some_and(|f| {
                    hookio::py_float_name(f).is_none()
                        && f.fract() == 0.0
                        && f.abs() < 1.7e38
                        && f as i128 == n
                })
            }
        }
        Some(Value::Bool(b)) => (*b as i128) == n,
        _ => false,
    }
}

// ------------------------------------------------------------------------------------------------ SHA-256

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 of `data` as lowercase hex (`hashlib.sha256(data).hexdigest()`), FIPS 180-4.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    let mut w = [0u32; 64];
    for block in msg.chunks_exact(64) {
        for (i, c) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

// ------------------------------------------------------------------------------------------------ files

type Res<T> = Result<T, String>;

fn has_nul(p: &str) -> bool {
    p.contains('\0')
}

/// `{m: mtime_ns, s: size, h: sha256}` of a file, or None when it can't be read (gone, a folder). Err for a null
/// byte in the path, which `os.stat` raised as ValueError.
fn snapshot(full: &str) -> Res<Option<Value>> {
    if has_nul(full) {
        return Err("ValueError: embedded null byte".into());
    }
    let (Ok(st), Ok(data)) = (fs::metadata(full), fs::read(full)) else {
        return Ok(None);
    };
    let mut m = Map::new();
    m.insert("m".into(), Value::from(mtime_ns(&st) as i64));
    m.insert("s".into(), Value::from(st.size()));
    m.insert("h".into(), Value::from(sha256_hex(&data)));
    Ok(Some(Value::Object(m)))
}

fn mtime_ns(st: &fs::Metadata) -> i128 {
    st.mtime() as i128 * 1_000_000_000 + st.mtime_nsec() as i128
}

/// `os.path.exists`.
fn exists(p: &str) -> bool {
    !has_nul(p) && fs::metadata(p).is_ok()
}

/// The repo-relative path of a file this hook follows, or None (`tracked(repo, path)`). Err where Python raised
/// (a path that isn't a string).
fn tracked(cfg: &ReadConfig, repo: &str, path: Option<&Value>) -> Res<Option<String>> {
    let p = match path {
        Some(v) if py_truthy(v) => match v {
            Value::String(s) => s.as_str(),
            other => {
                return Err(format!(
                    "TypeError: expected str, bytes or os.PathLike object, not {}",
                    hookio::py_type_name(other)
                ));
            }
        },
        _ => return Ok(None),
    };
    tracked_str(cfg, repo, p)
}

fn tracked_str(cfg: &ReadConfig, repo: &str, p: &str) -> Res<Option<String>> {
    if p.is_empty() {
        return Ok(None);
    }
    let rel = pyfs::relpath(&pyfs::realpath(p)?, repo)?;
    if rel.starts_with("..")
        || !cfg
            .tracked_dirs
            .iter()
            .any(|d| rel.split('/').next() == Some(d.as_str()))
    {
        return Ok(None);
    }
    if cfg
        .untracked_dirs
        .iter()
        .any(|d| rel.starts_with(&format!("{}/", d.trim_end_matches('/'))))
        || cfg.generated.contains(&rel)
    {
        return Ok(None);
    }
    Ok(Some(rel))
}

/// `<repo>/<record_dir>/<session>.json`: the session id as Python's `str()`, every character outside
/// `[A-Za-z0-9_-]` as `_`, the first 80. None for no id.
fn record_path(cfg: &ReadConfig, repo: &str, session: Option<&Value>) -> Option<String> {
    let s = match session {
        Some(v) if py_truthy(v) => py_str_of(v),
        _ => String::new(),
    };
    let name: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    (!name.is_empty())
        .then(|| pyfs::join(&pyfs::join(repo, &cfg.record_dir), &format!("{name}.json")))
}

/// The file id: the base name without the longest layer suffix it ends with (`x.team.md` -> `x`), before one final
/// newline, as the Python hook's `<suffixes>$` regex did.
fn stem_of(cfg: &ReadConfig, rel: &str) -> String {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    let (body, nl) = match base.strip_suffix('\n') {
        Some(b) => (b, "\n"),
        None => (base, ""),
    };
    let cut = cfg
        .layer_suffixes
        .iter()
        .filter(|s| body.ends_with(s.as_str()))
        .map(String::len)
        .max();
    match cut {
        Some(n) => format!("{}{nl}", &body[..body.len() - n]),
        None => base.to_string(),
    }
}

/// The Bash command names this file: its path, or its id with no word character or `-` on either side.
fn names_file(cfg: &ReadConfig, command: &str, rel: &str) -> bool {
    if command.contains(rel) {
        return true;
    }
    let stem: Vec<char> = stem_of(cfg, rel).chars().collect();
    let c: Vec<char> = command.chars().collect();
    let edge = |ch: Option<&char>| ch.is_none_or(|&x| !(py_word(x) || x == '-'));
    (0..=c.len().saturating_sub(stem.len()))
        .filter(|&i| i + stem.len() <= c.len() && c[i..i + stem.len()] == stem[..])
        .any(|i| edge(i.checked_sub(1).and_then(|j| c.get(j))) && edge(c.get(i + stem.len())))
}

/// `READ_HINT.search(command)`: a reader word with a word boundary (Python's `\b`) on both sides.
fn read_hint(cfg: &ReadConfig, command: &str) -> bool {
    let c: Vec<char> = command.chars().collect();
    let words: Vec<Vec<char>> = PRINTERS
        .iter()
        .chain(SEARCHERS)
        .chain(OTHER_READERS)
        .map(|w| w.chars().collect())
        .chain(std::iter::once(cfg.runner.chars().collect()))
        .collect();
    let word_at = |i: usize| c.get(i).is_some_and(|&x| py_word(x));
    (0..c.len()).any(|i| {
        words.iter().any(|w| {
            !w.is_empty()
                && i + w.len() <= c.len()
                && c[i..i + w.len()] == w[..]
                && (py_word(w[0]) != (i > 0 && word_at(i - 1)))
                && (py_word(w[w.len() - 1]) != word_at(i + w.len()))
        })
    })
}

// ------------------------------------------------------------------------------------------------ Bash commands

/// (words, commands) of a Bash command line: heredoc bodies and comments dropped; a redirection's target is not a
/// command word; `;` `&&` `||` `|` `&` newline and parentheses separate commands.
fn commands_of(command: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let words = sw::words(&sw::strip_comments(&sw::heredocs(command, None, &|_| {
        false
    })));
    let (mut cmds, mut cur, mut skip) = (Vec::new(), Vec::<String>::new(), false);
    for w in &words {
        if skip {
            skip = false;
            continue;
        }
        if sw::is_operator(w) {
            if w.contains(['<', '>']) && !w.ends_with('(') {
                skip = true;
                continue;
            }
            if !cur.is_empty() {
                cmds.push(std::mem::take(&mut cur));
            }
            continue;
        }
        cur.push(w.clone());
    }
    if !cur.is_empty() {
        cmds.push(cur);
    }
    (words, cmds)
}

/// Wrappers (`env`, `nice`, `sudo`, ... and leading `NAME=value`) taken off; `rtk read` stays.
fn strip_wrappers(cmd: &[String]) -> &[String] {
    let mut cmd = cmd;
    while let Some(first) = cmd.first() {
        let wrapper = sw::PREFIXES.contains(&first.as_str()) || first == "sudo";
        if !(wrapper || sw::assign(first).is_some()) {
            break;
        }
        if first == "rtk" && cmd.get(1).map(String::as_str) == Some("read") {
            break;
        }
        cmd = &cmd[1..];
    }
    cmd
}

/// Arguments that are not options or option values.
fn plain_args(name: &str, args: &[String]) -> Vec<String> {
    let (one, two) = (value_opts(name), value_opts_2(name));
    let (mut out, mut skip) = (Vec::new(), 0);
    for a in args {
        if skip > 0 {
            skip -= 1;
            continue;
        }
        if two.contains(&a.as_str()) {
            skip = 2;
            continue;
        }
        if one.contains(&a.as_str()) {
            skip = 1;
            continue;
        }
        if a.starts_with('-') && a != "-" {
            continue;
        }
        out.push(a.clone());
    }
    out
}

/// The Bash command only reads: every command is a known reader and nothing is redirected into a file.
fn only_reads(cfg: &ReadConfig, command: &str) -> bool {
    let (words, cmds) = commands_of(command);
    for (n, w) in words.iter().enumerate() {
        if sw::is_operator(w) && w.contains('>') && !w.ends_with('(') {
            let target = words.get(n + 1).map(String::as_str).unwrap_or("");
            if !(target == "/dev/null" || sw::py_isdigit(target) || target.starts_with('&')) {
                return false;
            }
        }
    }
    for cmd in &cmds {
        let cmd = strip_wrappers(cmd);
        let Some(first) = cmd.first() else { continue };
        let (name, args) = (pyfs::basename(first), &cmd[1..]);
        let plain: Vec<&str> = args
            .iter()
            .map(String::as_str)
            .filter(|a| !a.starts_with('-'))
            .collect();
        if name == "rtk" && args.first().map(String::as_str) == Some("read") {
            continue;
        }
        let in_place_i = |a: &String| a.starts_with("-i") || a.starts_with("--in-place");
        if (name == "sed" || name == "gsed") && !args.iter().any(in_place_i) {
            continue;
        }
        if ["yq", "awk", "gawk"].contains(&name)
            && args.iter().any(|a| {
                ["-i", "--inplace", "--in-place"].contains(&a.as_str())
                    || (name != "yq" && a.starts_with("-i"))
            })
        {
            return false;
        }
        if name == "find"
            && args
                .iter()
                .any(|a| ["-delete", "-exec", "-execdir", "-ok", "-fprint"].contains(&a.as_str()))
        {
            return false;
        }
        if PRINTERS.contains(&name)
            || SEARCHERS.contains(&name)
            || READ_ONLY.contains(&name)
            || name == "cd"
        {
            continue;
        }
        if name == "git" && plain.first().is_some_and(|p| GIT_READS.contains(p)) {
            continue;
        }
        if name == cfg.runner {
            let rest: Vec<&str> = plain.iter().copied().filter(|a| *a != "run").collect();
            if rest
                .first()
                .is_some_and(|r| cfg.runner_reads.iter().any(|x| x == r))
            {
                continue;
            }
        }
        return false;
    }
    true
}

/// `open(path, encoding="utf-8").read()`: universal newlines; Ok(None) where Python raised OSError, Err where it
/// raised anything else (bad UTF-8, a null byte in the path).
fn read_utf8(path: &str) -> Res<Option<String>> {
    if has_nul(path) {
        return Err("ValueError: embedded null byte".into());
    }
    if fs::metadata(path).is_ok_and(|m| m.is_dir()) {
        return Ok(None);
    }
    let Ok(bytes) = fs::read(path) else {
        return Ok(None);
    };
    let s = String::from_utf8(bytes)
        .map_err(|_| "UnicodeDecodeError: 'utf-8' codec can't decode".to_string())?;
    Ok(Some(s.replace("\r\n", "\n").replace('\r', "\n")))
}

/// Python's `\s` (str patterns) and `\S`.
fn py_space(c: char) -> bool {
    pyfs::py_isspace(c)
}

/// `re.search(r"^<key>:\s*(\S+)", text, re.M)`.
fn schema_folder(text: &str, key: &str) -> Option<String> {
    let c: Vec<char> = text.chars().collect();
    let k: Vec<char> = format!("{key}:").chars().collect();
    let mut i = 0;
    loop {
        if c.len() >= i + k.len() && c[i..i + k.len()] == k[..] {
            let mut j = i + k.len();
            while j < c.len() && py_space(c[j]) {
                j += 1;
            }
            // \s* backtracks so that \S+ still finds a character: none left means no match here.
            let start = j;
            while j < c.len() && !py_space(c[j]) {
                j += 1;
            }
            if j > start {
                return Some(c[start..j].iter().collect());
            }
        }
        i += c[i..].iter().position(|&x| x == '\n')? + 1;
    }
}

/// The files of `<runner> <entity> <type>/<id>`: the record in each layer.
fn entity_files(cfg: &ReadConfig, repo: &str, r: &str) -> Res<Vec<String>> {
    let Some((kind, ident)) = r.split_once('/') else {
        return Ok(Vec::new());
    };
    let schema = pyfs::join(&pyfs::join(repo, &cfg.schema_dir), &format!("{kind}.yaml"));
    let Some(text) = read_utf8(&schema)? else {
        return Ok(Vec::new());
    };
    let Some(folder) = schema_folder(&text, &cfg.folder_key) else {
        return Ok(Vec::new());
    };
    Ok(cfg
        .layer_suffixes
        .iter()
        .map(|s| pyfs::join(&pyfs::join(repo, &folder), &format!("{ident}{s}")))
        .collect())
}

fn resolve(here: &str, p: &str, env: &Env) -> Res<Option<String>> {
    sw::resolve(Some(here), p, env)
}

/// Tracked files a Bash command reads by name, sorted. `cwd` is the hook input's.
fn bash_reads(
    cfg: &ReadConfig,
    command: &str,
    cwd: Option<&Value>,
    repo: &str,
) -> Res<Vec<String>> {
    let (_, cmds) = commands_of(command);
    let env: Env = std::env::vars().collect();
    let mut here = match cwd {
        Some(Value::String(s)) if !s.is_empty() => pyfs::realpath(s)?,
        Some(v) if py_truthy(v) => {
            return Err(format!(
                "TypeError: expected str, bytes or os.PathLike object, not {}",
                hookio::py_type_name(v)
            ));
        }
        _ => pyfs::realpath(repo)?,
    };
    let mut found: Vec<String> = Vec::new();
    for cmd in &cmds {
        let cmd = strip_wrappers(cmd);
        let Some(first) = cmd.first() else { continue };
        let (name, args) = (pyfs::basename(first), &cmd[1..]);
        let mut files: Vec<String> = Vec::new();
        let has = |set: &[&str]| args.iter().any(|a| set.contains(&a.as_str()));
        if name == "cd" {
            let to = args.first().map(String::as_str).unwrap_or("~");
            if let Some(h) = resolve(&here, to, &env)? {
                if !h.is_empty() {
                    here = h;
                }
            }
            continue;
        }
        if name == "rtk" && args.first().map(String::as_str) == Some("read") {
            files = plain_args("cat", &args[1..]);
        } else if PRINTERS.contains(&name) {
            files = plain_args(name, args);
        } else if name == "sed" || name == "gsed" {
            let quiet = args.iter().any(|a| {
                a == "-n"
                    || a == "--quiet"
                    || (a.starts_with('-') && !a.starts_with("--") && a[1..].contains('n'))
            });
            let in_place = args
                .iter()
                .any(|a| a.starts_with("-i") || a.starts_with("--in-place"));
            if quiet && !in_place {
                let plain = plain_args("sed", args);
                files = if has(&["-e", "-f"]) {
                    plain
                } else {
                    plain.into_iter().skip(1).collect()
                };
            }
        } else if ["awk", "gawk", "jq", "yq"].contains(&name) {
            let key = if name == "gawk" { "awk" } else { name };
            let in_place = args.iter().any(|a| {
                ["-i", "--inplace", "--in-place"].contains(&a.as_str())
                    || (key == "awk" && a.starts_with("-i"))
            });
            if !in_place {
                let mut plain = plain_args(key, args);
                if key == "yq"
                    && plain
                        .first()
                        .is_some_and(|p| ["e", "eval", "ea", "eval-all"].contains(&p.as_str()))
                {
                    plain.remove(0);
                }
                files = if has(program_first(key)) {
                    plain
                } else {
                    plain.into_iter().skip(1).collect()
                };
            }
        } else if name == "diff" || name == "cmp" {
            files = args
                .iter()
                .filter(|a| !a.starts_with('-'))
                .cloned()
                .collect();
        } else if SEARCHERS.contains(&name) {
            let plain = plain_args(if name == "rg" { "rg" } else { "grep" }, args);
            let paths: Vec<String> = if has(&["-e", "-f"]) {
                plain
            } else {
                plain.into_iter().skip(1).collect()
            };
            let mut resolved = Vec::new();
            for p in &paths {
                resolved.push(resolve(&here, p, &env)?);
            }
            if !paths.is_empty()
                && resolved.iter().all(|r| {
                    r.as_deref()
                        .is_some_and(|r| !r.is_empty() && pyfs::isfile(r))
                })
            {
                files = paths;
            }
        } else if name == cfg.runner {
            let rest: Vec<&String> = args
                .iter()
                .filter(|a| !a.starts_with('-') && *a != "run")
                .collect();
            if rest.first().is_some_and(|r| **r == cfg.entity) && rest.len() > 1 {
                found.extend(
                    entity_files(cfg, repo, rest[1])?
                        .into_iter()
                        .filter(|f| pyfs::isfile(f)),
                );
            }
        }
        for f in files {
            if f.contains(['*', '?', '[']) {
                let base = match resolve(&here, ".", &env)? {
                    Some(b) if !b.is_empty() => b,
                    _ => here.clone(),
                };
                let mut hits =
                    pyfs::glob(&pyfs::join(&base, &f)).map_err(|e| format!("{e:?} in glob"))?;
                hits.sort();
                found.extend(hits.into_iter().take(GLOB_MAX).filter(|m| pyfs::isfile(m)));
                continue;
            }
            if let Some(full) = resolve(&here, &f, &env)? {
                if !full.is_empty() && pyfs::isfile(&full) {
                    found.push(full);
                }
            }
        }
    }
    let mut out = Vec::new();
    for f in &found {
        if let Some(rel) = tracked_str(cfg, repo, f)? {
            out.push(rel);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

// ------------------------------------------------------------------------------------------------ records

/// The record file, locked (`flock`, exclusive) while it is read and written back: a session's tool calls run in
/// parallel. The folder is made first, as Python made it.
struct Locked(
    #[expect(dead_code, reason = "held for its lock; closing it releases the lock")] fs::File,
);

fn lock(path: &str) -> Res<Locked> {
    fs::create_dir_all(pyfs::dirname(path)).map_err(|e| format!("OSError: {e}"))?;
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(format!("{path}.lock"))
        .map_err(|e| format!("OSError: {e}"))?;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    const LOCK_EX: i32 = 2;
    use std::os::fd::AsRawFd;
    // SAFETY: flock(2) on a descriptor this function owns; blocks until the lock is free, as fcntl.flock did.
    if unsafe { flock(f.as_raw_fd(), LOCK_EX) } != 0 {
        return Err(format!("OSError: {}", std::io::Error::last_os_error()));
    }
    Ok(Locked(f))
}

/// The record as loaded: {} where Python's `load` caught the error (missing, unreadable, bad UTF-8, bad JSON);
/// Err where it didn't (nested too deep).
fn load(path: &str) -> Res<Value> {
    let Ok(bytes) = fs::read(path) else {
        return Ok(Value::Object(Map::new()));
    };
    match hookio::parse_py(&bytes) {
        Ok(v) => Ok(v),
        Err(hookio::ParseError::TooDeep(kind)) => Err(hookio::ParseError::too_deep_text(kind)),
        Err(hookio::ParseError::Invalid) => Ok(Value::Object(Map::new())),
    }
}

/// Write the record (the newest TRACK_MAX entries) through `<path>.<pid>.tmp`.
fn save(path: &str, state: &Map<String, Value>) -> Res<()> {
    fs::create_dir_all(pyfs::dirname(path)).map_err(|e| format!("OSError: {e}"))?;
    let skip = state.len().saturating_sub(TRACK_MAX);
    let body = format!(
        "{{{}}}",
        state
            .iter()
            .skip(skip)
            .map(|(k, v)| format!("{}: {}", hookio::py_str(k), py_dump(v)))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let tmp = format!("{path}.{}.tmp", std::process::id());
    let mut f = fs::File::create(&tmp).map_err(|e| format!("OSError: {e}"))?;
    f.write_all(body.as_bytes())
        .map_err(|e| format!("OSError: {e}"))?;
    drop(f);
    fs::rename(&tmp, path).map_err(|e| format!("OSError: {e}"))
}

/// Remove whatever in the record folder is untouched for 7 days; stop at the first error, as Python's loop in one
/// `try` did.
fn tidy(folder: &str) {
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
        - STATE_SECS;
    let Ok(rd) = fs::read_dir(folder) else { return };
    for e in rd {
        let Ok(e) = e else { return };
        let p = e.path();
        let Ok(m) = fs::metadata(&p) else { return };
        let t = m.mtime() as f64 + m.mtime_nsec() as f64 / 1e9;
        if t < cutoff && fs::remove_file(&p).is_err() {
            return;
        }
    }
}

// ------------------------------------------------------------------------------------------------ the hook

/// The tool name as Python held it: a string, another hashable value, or an unhashable one (list, dict) that
/// raises TypeError when looked up in a set.
enum Tool {
    Name(String),
    Hashable,
    Unhashable(&'static str),
}

impl Tool {
    fn is(&self, name: &str) -> bool {
        matches!(self, Tool::Name(n) if n == name)
    }

    fn in_set(&self, set: &[&str]) -> Res<bool> {
        match self {
            Tool::Name(n) => Ok(set.contains(&n.as_str())),
            Tool::Hashable => Ok(false),
            Tool::Unhashable(t) => Err(format!("TypeError: unhashable type: '{t}'")),
        }
    }
}

/// What one call did: the notice to print (if any). Err is an internal error (logged; the tool result passes).
pub fn run(input: &[u8], repo: &str, cfg: &ReadConfig) -> Res<Option<String>> {
    let data = match hookio::parse_py(input) {
        Ok(Value::Object(d)) => d,
        Ok(other) => {
            return Err(format!(
                "AttributeError: '{}' object has no attribute 'get'",
                hookio::py_type_name(&other)
            ));
        }
        Err(hookio::ParseError::TooDeep(kind)) => {
            return Err(hookio::ParseError::too_deep_text(kind));
        }
        Err(hookio::ParseError::Invalid) => return Err("JSONDecodeError".into()),
    };
    let tool = match data.get("tool_name") {
        Some(v) if py_truthy(v) => match v {
            Value::String(s) => Tool::Name(s.clone()),
            Value::Array(_) => Tool::Unhashable("list"),
            Value::Object(_) => Tool::Unhashable("dict"),
            _ => Tool::Hashable,
        },
        _ => Tool::Name(String::new()),
    };
    let empty = Value::Object(Map::new());
    let tool_input = match data.get("tool_input") {
        Some(v) if py_truthy(v) => v,
        _ => &empty,
    };
    let repo = pyfs::realpath(repo)?;
    let Some(path) = record_path(cfg, &repo, data.get("session_id")) else {
        return Ok(None);
    };
    let folder = pyfs::dirname(&path);
    let Value::Object(ti) = tool_input else {
        return Err(format!(
            "AttributeError: '{}' object has no attribute 'get'",
            hookio::py_type_name(tool_input)
        ));
    };
    let first = ti
        .get("file_path")
        .filter(|v| py_truthy(v))
        .or_else(|| ti.get("notebook_path"));
    let target = tracked(cfg, &repo, first)?;
    let command: String = if tool.is("Bash") {
        match ti.get("command") {
            Some(v) if py_truthy(v) => match v {
                Value::String(s) => s.clone(),
                other => {
                    return Err(format!(
                        "TypeError: expected string or bytes-like object, got '{}'",
                        hookio::py_type_name(other)
                    ));
                }
            },
            _ => String::new(),
        }
    } else {
        String::new()
    };
    let rw: Vec<&str> = READ_TOOLS.iter().chain(WRITE_TOOLS).copied().collect();
    let reads_target = target.is_some() && tool.in_set(&rw)?;
    let hint = !command.is_empty() && read_hint(cfg, &command);
    if !exists(&path) && !reads_target && !hint {
        return Ok(None); // nothing read yet, and this call reads nothing: stay out of the way
    }
    let read_now = if hint {
        bash_reads(cfg, &command, data.get("cwd"), &repo)?
    } else {
        Vec::new()
    };
    if !exists(&path) && read_now.is_empty() && !reads_target {
        return Ok(None);
    }
    // A call that cannot have written anything: whatever changed was someone else's. Asked only once a file the
    // session read has changed, so a Bash command is parsed for it only then.
    let mut memo: Option<bool> = None;
    let cannot_have_written = |memo: &mut Option<bool>| -> Res<bool> {
        if let Some(v) = *memo {
            return Ok(v);
        }
        let v = tool.in_set(READ_TOOLS)? || (tool.is("Bash") && only_reads(cfg, &command));
        *memo = Some(v);
        Ok(v)
    };
    // Only a call that can write gets the benefit of the doubt for a file it names.
    let own_change = |rel: &str, memo: &mut Option<bool>| -> Res<bool> {
        if target.as_deref() == Some(rel) && tool.in_set(WRITE_TOOLS)? {
            return Ok(true);
        }
        Ok(tool.is("Bash") && !cannot_have_written(memo)? && names_file(cfg, &command, rel))
    };

    let _held = lock(&path)?;
    let loaded = load(&path)?;
    if !py_truthy(&loaded) && read_now.is_empty() && !reads_target {
        return Ok(None);
    }
    let mut state = match loaded {
        Value::Object(m) => m,
        // `list(state)` of an empty list or string loops over nothing; `state.pop` then raises only if a read
        // lands, and otherwise Python saved the value back as it was.
        Value::Array(a) if a.is_empty() => {
            return empty_record(&path, "[]", &repo, &target, reads_target, &read_now);
        }
        Value::String(t) if t.is_empty() => {
            return empty_record(&path, "\"\"", &repo, &target, reads_target, &read_now);
        }
        other => {
            return Err(format!(
                "TypeError: '{}' object is not iterable or not a record",
                hookio::py_type_name(&other)
            ));
        }
    };
    let (mut elsewhere, mut during) = (Vec::new(), Vec::new());
    let keys: Vec<String> = state.keys().cloned().collect();
    for rel in keys {
        let full = pyfs::join(&repo, &rel);
        if has_nul(&full) {
            return Err("ValueError: embedded null byte".into());
        }
        let st = match fs::metadata(&full) {
            Ok(st) => st,
            Err(_) => {
                state.shift_remove(&rel);
                if !own_change(&rel, &mut memo)? {
                    let line = format!("{rel} (deleted)");
                    if cannot_have_written(&mut memo)? {
                        elsewhere.push(line);
                    } else {
                        during.push(line);
                    }
                }
                continue;
            }
        };
        let rec = &state[&rel];
        let Value::Object(rec) = rec else {
            return Err(format!(
                "AttributeError: '{}' object has no attribute 'get'",
                hookio::py_type_name(rec)
            ));
        };
        if py_eq_int(rec.get("m"), mtime_ns(&st)) && py_eq_int(rec.get("s"), st.size() as i128) {
            continue;
        }
        let now = snapshot(&full)?;
        let same_hash = now.as_ref().is_some_and(|n| Some(&n["h"]) == rec.get("h"));
        if now.is_none() || same_hash {
            if let Some(n) = now {
                state.insert(rel.clone(), n);
            }
            continue;
        }
        if let Some(n) = now {
            state.insert(rel.clone(), n);
        }
        if (target.as_deref() == Some(rel.as_str()) && reads_target) || read_now.contains(&rel) {
            continue; // this call read the new content, or wrote it
        }
        if own_change(&rel, &mut memo)? {
            continue; // this session's own command names the file
        }
        if cannot_have_written(&mut memo)? || tool.in_set(WRITE_TOOLS)? {
            elsewhere.push(rel);
        } else {
            during.push(rel);
        }
    }
    let new_session = !exists(&path);
    let reads = target
        .iter()
        .filter(|_| reads_target)
        .chain(read_now.iter());
    for rel in reads {
        if let Some(now) = snapshot(&pyfs::join(&repo, rel))? {
            state.shift_remove(rel);
            state.insert(rel.clone(), now);
        }
    }
    save(&path, &state)?;
    if new_session {
        tidy(&folder);
    }
    let mut lines = Vec::new();
    if !elsewhere.is_empty() {
        lines.push(cfg.msg_elsewhere.replace("{files}", &elsewhere.join(", ")));
    }
    if !during.is_empty() {
        lines.push(cfg.msg_during.replace("{files}", &during.join(", ")));
    }
    if lines.is_empty() {
        return Ok(None);
    }
    lines.push(cfg.msg_stale.clone());
    Ok(Some(format!(
        "{{\"hookSpecificOutput\": {{\"hookEventName\": \"PostToolUse\", \"additionalContext\": {}}}}}",
        hookio::py_str(&lines.join(" "))
    )))
}

/// A record holding `[]` or `""`: a read that lands raises (no `pop` on it); otherwise it is written back unchanged.
fn empty_record(
    path: &str,
    dumped: &str,
    repo: &str,
    target: &Option<String>,
    reads_target: bool,
    read_now: &[String],
) -> Res<Option<String>> {
    for rel in target.iter().filter(|_| reads_target).chain(read_now) {
        if snapshot(&pyfs::join(repo, rel))?.is_some() {
            return Err("AttributeError: the session record has no pop".into());
        }
    }
    fs::create_dir_all(pyfs::dirname(path)).map_err(|e| format!("OSError: {e}"))?;
    let tmp = format!("{path}.{}.tmp", std::process::id());
    fs::write(&tmp, dumped).map_err(|e| format!("OSError: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("OSError: {e}"))?;
    Ok(None)
}

/// The hook: read stdin, print the notice; always exit 0.
pub fn main(crash_log: Option<&str>) -> i32 {
    let project = std::env::var("CLAUDE_PROJECT_DIR").unwrap_or_default();
    let warn = |why: String| {
        let msg = format!(
            "claude-guard repo post-read: no usable config ({why}); this repo's stale-read notice is off for this call."
        );
        println!(
            "{}",
            hookio::py_dumps(&serde_json::json!({ "systemMessage": msg }))
        );
        0
    };
    if project.is_empty() {
        return warn("CLAUDE_PROJECT_DIR is not set".into());
    }
    let (error_log, cfg) = match load_config(&project) {
        Ok(c) => c,
        Err(e) => return warn(e),
    };
    let input = hookio::read_stdin();
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&input, &project, &cfg)))
            .unwrap_or_else(|_| Err("panic".into()));
    match result {
        Ok(Some(out)) => println!("{out}"),
        Ok(None) => {}
        Err(e) => {
            let first = e.lines().next().unwrap_or("");
            logfile::append(
                crash_log.unwrap_or(&error_log),
                &format!("{} repo-post-read {first}", crate::now_utc()),
                LOG_CAP,
            );
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_fips_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        for n in [55, 56, 63, 64, 65, 119, 120] {
            assert_eq!(sha256_hex(&vec![0u8; n]).len(), 64, "padding at {n} bytes");
        }
    }

    #[test]
    fn floats_print_as_python_repr() {
        for (f, want) in [
            (1.0, "1.0"),
            (-0.0, "-0.0"),
            (0.1, "0.1"),
            (1e16, "1e+16"),
            (1.5e16, "1.5e+16"),
            (123456789012345.6, "123456789012345.6"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.7e18, "1.7e+18"),
            (2.5e-300, "2.5e-300"),
            (f64::NAN, "nan"),
        ] {
            assert_eq!(py_float_repr(f), want, "{f}");
        }
    }

    #[test]
    fn session_ids_as_python_str() {
        let j = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        assert_eq!(py_str_of(&j("12")), "12");
        assert_eq!(py_str_of(&j("1.5")), "1.5");
        assert_eq!(py_str_of(&j("true")), "True");
        assert_eq!(py_str_of(&j("[1, \"a\", null]")), "[1, 'a', None]");
        assert_eq!(py_str_of(&j("{\"k\": \"it's\"}")), "{'k': \"it's\"}");
    }

    #[test]
    fn python_int_equality() {
        let j = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        assert!(py_eq_int(Some(&j("5")), 5));
        assert!(py_eq_int(Some(&j("5.0")), 5));
        assert!(!py_eq_int(Some(&j("5.5")), 5));
        assert!(py_eq_int(Some(&j("true")), 1));
        assert!(!py_eq_int(Some(&j("\"5\"")), 5));
        assert!(!py_eq_int(None, 0));
    }

    #[test]
    fn schema_folder_like_the_regex() {
        assert_eq!(
            schema_folder("a: 1\nfolder: people\n", "folder").as_deref(),
            Some("people")
        );
        assert_eq!(
            schema_folder("folder:\n  x y", "folder").as_deref(),
            Some("x"),
            "\\s crosses lines"
        );
        assert_eq!(
            schema_folder(" folder: x", "folder"),
            None,
            "anchored at a line start"
        );
        assert_eq!(schema_folder("folder:   ", "folder"), None);
        assert_eq!(
            schema_folder("xfolder: a\nfolder:b", "folder").as_deref(),
            Some("b")
        );
    }
}
