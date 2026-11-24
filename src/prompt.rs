//! `claude-guard prompt`: the UserPromptSubmit guard, ported from guard-prompt.py.
//!
//! Checks the hook input's `prompt`, in order:
//! 1. Secrets: built-in rules, then gitleaks (default rules) when the prompt holds a long run of mixed letters and
//!    digits. gitleaks runs in `/` (nobody can plant a .gitleaks.toml there) with a clean environment, /dev/null as
//!    its ignore file and a 1 s timeout; if it is missing, fails or times out, the built-in rules stand.
//! 2. Malaysian IC numbers: YYMMDD-PB-###G, all dashes or none, real month and day, a place-of-birth code JPN issues.
//! 3. Names from ~/.config/claude-guard/blocked-terms.txt (`--terms <file>`): case-insensitive, whole words.
//!
//! A secret or an IC number blocks ({"decision": "block"}) with the rule name only, never the matched text. A
//! name only warns: the prompt goes through, a notice is shown and one line goes to
//! ~/.local/state/claude-guard/allow-name.log (`--log <file>`; time, session id, folder, marker; never the name).
//! `--strict` (GraphMind's wrapper): a name blocks and nothing is logged. Any internal error allows the prompt with
//! one warning (fail open). Output is byte-for-byte guard-prompt.py's.
//!
//! The regex crate has no lookaround or backreferences, so the boundaries Python's patterns wrote as `\b`,
//! `(?<!...)` and `(?!...)`, and the IC number's `\4`, are checked in code, with Python's meaning of `\w`, `\s`
//! and `\d` (str patterns: Unicode).

use crate::hookio::{self, py_str};
use crate::pyfs;
use crate::pyre::{self, PyText};
use regex::Regex;
use serde_json::Value;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

const GITLEAKS_PATHS: &[&str] = &["/opt/homebrew/bin/gitleaks", "/usr/local/bin/gitleaks"];
const GITLEAKS_TIMEOUT: Duration = Duration::from_millis(1000);
const ALLOW_NAME_MARKER: &str = "[allow-name]";

#[derive(Clone, Copy)]
enum Bound {
    None,
    /// `(?<![A-Z0-9]) ... (?![A-Z0-9])`
    UpperAlnum,
    /// `\b` at the start, and at the end when `end` (only on fixed-length patterns, so one match per position).
    Word {
        end: bool,
    },
}

struct Rule {
    id: &'static str,
    what: &'static str,
    rx: Regex,
    bound: Bound,
}

static SECRET_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let r = |id, what, p: &str, bound| Rule {
        id,
        what,
        rx: Regex::new(p).unwrap(),
        bound,
    };
    let w = |end| Bound::Word { end };
    vec![
        r(
            "aws-access-key-id",
            "an AWS access key",
            r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}",
            Bound::UpperAlnum,
        ),
        r(
            "private-key",
            "a private key",
            r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----",
            Bound::None,
        ),
        // Python's one github-pat pattern has two branches; at a given position at most one can match.
        r(
            "github-pat",
            "a GitHub token",
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",
            w(true),
        ),
        r(
            "atlassian-api-token",
            "an Atlassian or Bitbucket API token",
            r"ATATT3[A-Za-z0-9_=-]{100,}",
            w(false),
        ),
        r(
            "bitbucket-app-password",
            "a Bitbucket app password",
            r"ATBB[A-Za-z0-9_=.-]{28,}",
            w(false),
        ),
        r(
            "slack-token",
            "a Slack token",
            r"xox[abposr]-[A-Za-z0-9-]{10,}",
            w(false),
        ),
        r(
            "slack-webhook-url",
            "a Slack webhook",
            r"hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_-]{20,}",
            Bound::None,
        ),
        r(
            "stripe-secret-key",
            "a Stripe secret key",
            r"[sr]k_live_[A-Za-z0-9]{20,}",
            w(false),
        ),
        r(
            "gcp-api-key",
            "a Google API key",
            r"AIza[A-Za-z0-9_-]{35}",
            w(true),
        ),
        r(
            "jwt",
            "a JSON web token",
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            w(false),
        ),
    ]
});

/// Python's `\s` (str.isspace) as a class body: Unicode White_Space plus U+001C..U+001F.
const PY_WS: &str = r"\s\x1C-\x1F";

// `password = <value>` style assignments: guard-prompt.py's ASSIGN_RE without its (?<![A-Za-z0-9]) lookbehind,
// which is checked in code. The regex crate's leftmost-first matching picks the same match (lazy prefix, keyword
// order, value alternatives) a backtracking engine does.
static ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)[A-Za-z0-9_.-]*?(?:password|passwd|secret|secret[_-]?key|api[_-]?key|access[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)["']?[{ws}]*[:=][{ws}]*(?:"(?P<dq>[^"{ws}]{{8,200}})"|'(?P<sq>[^'{ws}]{{8,200}})'|(?P<bare>[A-Za-z0-9!@\#%^&*+/=_~-]{{8,200}}))"#,
        ws = PY_WS
    ))
    .unwrap()
});
static PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(?:\$|<|\{|%|\*{3}|x{3}|\.{3}|/|\./|~/)|^(?:changeme|password|secret|example|placeholder|redacted|null|none|undefined|your[_-].*|my[_-].*|test[_-]?.*|dummy.*|sample.*|fake.*)$|\(|process\.env|env\(|getenv",
    )
    .unwrap()
});
static TOKENISH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/=_-]{20,}").unwrap());
/// Python's `\d` for str patterns: Unicode decimal digits.
static PY_DIGIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\p{Nd}$").unwrap());

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block {
        rule: String,
        line: String,
    },
    /// A blocked name let through with a notice (and a log line unless dry).
    Warn {
        marker: bool,
        line: String,
    },
    /// Fail open: the guard broke; the prompt goes through with a warning.
    Failed {
        error: String,
        line: String,
    },
}

impl Verdict {
    pub fn rule(&self) -> String {
        match self {
            Verdict::Allow => "allow".into(),
            Verdict::Block { rule, .. } => format!("block:{rule}"),
            Verdict::Warn { marker: false, .. } => "warn-name".into(),
            Verdict::Warn { marker: true, .. } => "warn-name-marker".into(),
            Verdict::Failed { error, .. } => format!("failed:{error}"),
        }
    }

    /// The line printed on stdout, "" for none.
    pub fn line(&self) -> &str {
        match self {
            Verdict::Allow => "",
            Verdict::Block { line, .. }
            | Verdict::Warn { line, .. }
            | Verdict::Failed { line, .. } => line,
        }
    }
}

/// The rule id of a guard-prompt output (works for the Python hook's stdout too).
pub fn rule_of(stdout: &str) -> String {
    let out = stdout.trim();
    if out.is_empty() {
        return "allow".into();
    }
    let v: Value = serde_json::from_str(out).unwrap_or(Value::Null);
    let between = |s: &str, a: &str, b: char| {
        s.split(a)
            .nth(1)
            .and_then(|x| x.split(b).next())
            .unwrap_or("?")
            .to_string()
    };
    if let Some(r) = v.get("reason").and_then(Value::as_str) {
        return format!("block:{}", between(r, "(rule ", ')'));
    }
    match v.get("systemMessage").and_then(Value::as_str) {
        Some(m) if m.contains("let a blocked name through") => "warn-name-marker".into(),
        Some(m) if m.contains("name on your blocked list") => "warn-name".into(),
        Some(m) if m.contains(" failed (") => format!("failed:{}", between(m, " failed (", ')')),
        _ => "other".into(),
    }
}

fn block(rule: &str, what: &str) -> Verdict {
    let reason = format!("Blocked: looks like {what} (rule {rule}). Remove it and send again.");
    Verdict::Block {
        rule: rule.into(),
        line: format!(
            "{{\"decision\": \"block\", \"reason\": {}}}",
            py_str(&reason)
        ),
    }
}

fn char_before(s: &str, i: usize) -> Option<char> {
    s[..i].chars().next_back()
}

fn char_after(s: &str, i: usize) -> Option<char> {
    s[i..].chars().next()
}

/// The byte index just past the character that starts at `i`.
fn next_char(s: &str, i: usize) -> usize {
    i + s[i..].chars().next().map_or(1, char::len_utf8)
}

fn py_is_word(c: Option<char>) -> bool {
    c.is_some_and(pyre::py_word)
}

fn py_is_digit(c: char) -> bool {
    c.is_ascii_digit() || (!c.is_ascii() && PY_DIGIT.is_match(c.encode_utf8(&mut [0; 4])))
}

/// `int()` of one decimal digit. Unicode lists decimal digits as complete runs 0..9 in code-point order, so a
/// digit's value is its place in its run.
fn py_digit_value(c: char) -> u32 {
    if let Some(d) = c.to_digit(10) {
        return d;
    }
    let mut k = 0;
    let mut cp = c as u32;
    while k < 100 {
        let Some(prev) = cp.checked_sub(1).and_then(char::from_u32) else {
            break;
        };
        if !py_is_digit(prev) {
            break;
        }
        k += 1;
        cp -= 1;
    }
    k % 10
}

fn bounds_ok(s: &str, start: usize, end: usize, bound: Bound) -> bool {
    let upper_alnum =
        |c: Option<char>| c.is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
    match bound {
        Bound::None => true,
        Bound::UpperAlnum => {
            !upper_alnum(char_before(s, start)) && !upper_alnum(char_after(s, end))
        }
        // `\b`: the characters on either side differ in being word characters. The patterns start with a
        // letter, but can end with `-`, which is not a word character.
        Bound::Word { end: e } => {
            let edge = |a: Option<char>, b: Option<char>| py_is_word(a) != py_is_word(b);
            edge(char_before(s, start), char_after(s, start))
                && (!e || edge(char_before(s, end), char_after(s, end)))
        }
    }
}

fn is_literal_secret(value: &str) -> bool {
    // PLACEHOLDER_RE is IGNORECASE; the two letter and digit searches after it are not.
    if PLACEHOLDER_RE.is_match(&PyText::new(value, true).t) {
        return false;
    }
    value.chars().any(|c| c.is_ascii_alphabetic())
        && value
            .chars()
            .any(|c| c.is_ascii_digit() || "!@#%^&*+/=_~-".contains(c))
}

pub(crate) fn builtin_secret(prompt: &str) -> Option<(&'static str, &'static str)> {
    for rule in SECRET_RULES.iter() {
        let mut at = 0;
        while at <= prompt.len() {
            let Some(m) = rule.rx.find_at(prompt, at) else {
                break;
            };
            if bounds_ok(prompt, m.start(), m.end(), rule.bound) {
                return Some((rule.id, rule.what));
            }
            at = next_char(prompt, m.start());
        }
    }
    // finditer: a match whose value isn't a literal is passed over, and the search goes on after it. A position
    // that fails the lookbehind is tried again one character later. ASSIGN_RE is IGNORECASE, so it runs on the
    // Python view of the prompt (İ, ı, ſ, K read as ASCII letters there, also in the lookbehind).
    let view = PyText::new(prompt, true);
    let t = view.t.as_str();
    let mut at = 0;
    while at <= t.len() {
        let Some(c) = ASSIGN_RE.captures_at(t, at) else {
            break;
        };
        let m = c.get(0).unwrap();
        if char_before(t, m.start()).is_some_and(|c| c.is_ascii_alphanumeric()) {
            at = next_char(t, m.start());
            continue;
        }
        let value = c
            .name("dq")
            .or(c.name("sq"))
            .or(c.name("bare"))
            .map_or("", |x| view.orig(x.start(), x.end()));
        if is_literal_secret(value) {
            return Some(("secret-assignment", "a password or secret value"));
        }
        at = m.end();
    }
    None
}

fn needs_gitleaks(prompt: &str) -> bool {
    TOKENISH_RE.find_iter(prompt).any(|m| {
        let s = m.as_str();
        s.bytes().any(|c| c.is_ascii_alphabetic()) && s.bytes().any(|c| c.is_ascii_digit())
    })
}

/// `str()` of a loaded JSON value, as far as a hook input can need it (strings, numbers, booleans).
pub(crate) fn py_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        Value::Number(n) if n.is_f64() => {
            let f = n.as_f64().unwrap_or(0.0);
            if let Some(name) = hookio::py_float_name(f) {
                name.into()
            } else if f.fract() == 0.0 && f.abs() < 1e16 {
                format!("{f:.1}")
            } else {
                f.to_string()
            }
        }
        other => other.to_string(),
    }
}

/// First gitleaks rule id that matches, or None. Never fails.
fn gitleaks_rule(prompt: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let exe = GITLEAKS_PATHS.iter().find(|p| {
        std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o111 != 0 && !m.is_dir())
    })?;
    let home = pyfs::expanduser("~").ok()?;
    let mut child = Command::new(exe)
        .args([
            "stdin",
            "--no-banner",
            "--log-level",
            "error",
            "--redact",
            "--exit-code",
            "0",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--gitleaks-ignore-path",
            "/dev/null",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    let input = prompt.as_bytes().to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut out = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let deadline = Instant::now() + GITLEAKS_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(_) => return None,
        }
    }
    let _ = writer.join();
    let out = reader.join().ok()?;
    let findings = hookio::parse(String::from_utf8_lossy(&out).as_bytes())?;
    findings.as_array()?.iter().find_map(|item| {
        let rid = item.as_object()?.get("RuleID")?;
        hookio::py_truthy(rid).then(|| py_display(rid))
    })
}

const DAYS: [u32; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

fn pb_code_ok(pb: &[char]) -> bool {
    if !pb.iter().all(char::is_ascii_digit) {
        return false; // PB_CODES holds ASCII strings
    }
    let n = pb[0].to_digit(10).unwrap() * 10 + pb[1].to_digit(10).unwrap();
    matches!(n, 1..=16 | 21..=68 | 71 | 72 | 74..=79 | 82..=93 | 98 | 99)
}

/// guard-prompt's IC_RE `(?<![\d-])(\d{2})(\d{2})(\d{2})(-?)(\d{2})\4(\d{4})(?![\d-])` run with finditer, then
/// the month, day and place-of-birth check on each match.
pub(crate) fn malaysian_ic(prompt: &str) -> bool {
    let c: Vec<char> = prompt.chars().collect();
    let n = c.len();
    let d = |i: usize| i < n && py_is_digit(c[i]);
    let edge = |i: usize| py_is_digit(c[i]) || c[i] == '-';
    let mut s = 0;
    while s + 12 <= n {
        let matched = (|| {
            if s > 0 && edge(s - 1) {
                return None;
            }
            if !(0..6).all(|k| d(s + k)) {
                return None;
            }
            // `(-?)` tries the dash first; without one, position s+6 must be a digit, so only one way can match.
            let dash = c[s + 6] == '-';
            let pb = s + 6 + dash as usize;
            if !(d(pb) && d(pb + 1)) {
                return None;
            }
            if dash && c.get(pb + 2) != Some(&'-') {
                return None;
            }
            let g = pb + 2 + dash as usize;
            if !(0..4).all(|j| d(g + j)) {
                return None;
            }
            let end = g + 4;
            if end < n && edge(end) {
                return None;
            }
            Some((pb, end))
        })();
        let Some((pb, end)) = matched else {
            s += 1;
            continue;
        };
        let month = py_digit_value(c[s + 2]) * 10 + py_digit_value(c[s + 3]);
        let day = py_digit_value(c[s + 4]) * 10 + py_digit_value(c[s + 5]);
        if (1..=12).contains(&month)
            && day >= 1
            && day <= DAYS[month as usize - 1]
            && pb_code_ok(&c[pb..pb + 2])
        {
            return true;
        }
        s = end; // finditer goes on after the match
    }
    false
}

/// Python's `str.splitlines()`.
fn py_splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, ch) in s.char_indices() {
        if matches!(
            ch,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            out.push(&s[start..i]);
            start = i + ch.len_utf8();
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `load_terms`: a missing file is no terms; any other read error is an error (Python raised).
pub(crate) fn load_terms(path: &str) -> Result<Vec<String>, String> {
    if path.contains('\0') {
        return Err("ValueError".into());
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(match e.kind() {
                std::io::ErrorKind::PermissionDenied => "PermissionError",
                std::io::ErrorKind::IsADirectory => "IsADirectoryError",
                std::io::ErrorKind::NotADirectory => "NotADirectoryError",
                _ => "OSError",
            }
            .into());
        }
    };
    let text = String::from_utf8(bytes).map_err(|_| "UnicodeDecodeError".to_string())?;
    // Text mode reads \r\n and \r as \n.
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    Ok(py_splitlines(&text)
        .into_iter()
        .map(pyfs::py_strip)
        .filter(|t| !t.is_empty() && !t.starts_with('#') && t.chars().count() >= 2)
        .map(str::to_string)
        .collect())
}

/// `blocked_term`: one alternation of every term (words joined by `\s+`), case-insensitive, with no word
/// character just before or after the match. Python tries the terms longest first at each position; whether
/// any term fits anywhere doesn't depend on that order, so each term is searched on its own.
pub(crate) fn blocked_term(prompt: &str, terms: &[String]) -> Result<bool, String> {
    // IGNORECASE: İ, ı, ſ and K read as ASCII letters, in the prompt and in the terms alike.
    let view = PyText::case_only(prompt);
    let p = view.t.as_str();
    for t in terms {
        let words: Vec<String> = t
            .split(pyfs::py_isspace)
            .filter(|w| !w.is_empty())
            .map(|w| regex::escape(&PyText::case_only(w).t))
            .collect();
        let rx = Regex::new(&format!("(?i){}", words.join(&format!("[{PY_WS}]+"))))
            .map_err(|_| "error".to_string())?;
        let mut at = 0;
        while at <= p.len() {
            let Some(m) = rx.find_at(p, at) else {
                break;
            };
            if !py_is_word(char_before(p, m.start())) && !py_is_word(char_after(p, m.end())) {
                return Ok(true);
            }
            at = next_char(p, m.start());
        }
    }
    Ok(false)
}

/// `time.strftime("%Y-%m-%dT%H:%M:%S%z")` in local time.
pub(crate) fn local_time() -> String {
    #[repr(C)]
    struct Tm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
        tm_gmtoff: i64,
        tm_zone: *const std::ffi::c_char,
    }
    unsafe extern "C" {
        fn time(t: *mut i64) -> i64;
        fn localtime_r(t: *const i64, out: *mut Tm) -> *mut Tm;
        fn strftime(s: *mut u8, max: usize, fmt: *const std::ffi::c_char, tm: *const Tm) -> usize;
    }
    let mut buf = [0u8; 64];
    // SAFETY: libc calls with a zeroed `struct tm` (macOS arm64 layout) and the buffer's real length.
    let n = unsafe {
        let now = time(std::ptr::null_mut());
        let mut tm: Tm = std::mem::zeroed();
        if localtime_r(&now, &mut tm).is_null() {
            return String::new();
        }
        strftime(
            buf.as_mut_ptr(),
            buf.len(),
            c"%Y-%m-%dT%H:%M:%S%z".as_ptr(),
            &tm,
        )
    };
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// One audit line per prompt let through with a blocked name; never the name. Never fails. Same file handling
/// as Python: parent folder made 0700, file opened for append 0600, one write.
fn log_allow_name(path: &str, data: &serde_json::Map<String, Value>, marker: bool) {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let field = |k: &str| match data.get(k) {
        Some(v) if hookio::py_truthy(v) => py_display(v),
        _ => String::new(),
    };
    let line = format!(
        "{{\"time\": {}, \"session_id\": {}, \"cwd\": {}, \"rule\": \"blocked-term\", \"marker\": {}}}\n",
        py_str(&local_time()),
        py_str(&field("session_id")),
        py_str(&field("cwd")),
        if marker { "true" } else { "false" }
    );
    let dir = std::path::Path::new(path)
        .parent()
        .map(|p| p.as_os_str().to_owned())
        .unwrap_or_default();
    if dir.is_empty() {
        return; // os.makedirs("") raised, so Python logged nothing
    }
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .is_err()
    {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

pub struct Options {
    pub terms: String,
    pub log: String,
    pub strict: bool,
    /// Shadow: decide without writing the allow-name log.
    pub dry: bool,
}

impl Options {
    /// guard-prompt.py's options(): `--strict`, `--terms F` and `--log F`, in any order; parsing stops at the
    /// first argument that is none of them (later ones are ignored, as Python did).
    pub fn parse(mut args: &[String]) -> Options {
        let home = std::env::var("HOME").unwrap_or_default();
        let ex = |p: &str| pyfs::expanduser(p).unwrap_or_else(|_| p.replacen('~', &home, 1));
        let mut o = Options {
            terms: ex("~/.config/claude-guard/blocked-terms.txt"),
            log: ex("~/.local/state/claude-guard/allow-name.log"),
            strict: false,
            dry: false,
        };
        loop {
            match args {
                [flag, rest @ ..] if flag == "--strict" => {
                    o.strict = true;
                    args = rest;
                }
                [flag, value, rest @ ..] if flag == "--terms" => {
                    o.terms = value.clone();
                    args = rest;
                }
                [flag, value, rest @ ..] if flag == "--log" => {
                    o.log = value.clone();
                    args = rest;
                }
                _ => break,
            }
        }
        o
    }
}

fn failed(error: &str) -> Verdict {
    let msg = format!("guard-prompt.py failed ({error}); prompt allowed unchecked.");
    Verdict::Failed {
        error: error.into(),
        line: format!("{{\"systemMessage\": {}}}", py_str(&msg)),
    }
}

fn run(
    data: &serde_json::Map<String, Value>,
    prompt: &str,
    opts: &Options,
) -> Result<Verdict, String> {
    if let Some((rid, what)) = builtin_secret(prompt) {
        return Ok(block(rid, what));
    }
    if needs_gitleaks(prompt) {
        if let Some(rid) = gitleaks_rule(prompt) {
            return Ok(block(&rid, "a secret"));
        }
    }
    // IC before names, so a prompt blocked for an IC number never logs a name as let through.
    if malaysian_ic(prompt) {
        return Ok(block("malaysian-ic", "a Malaysian IC number"));
    }
    if blocked_term(prompt, &load_terms(&opts.terms)?)? {
        if opts.strict {
            return Ok(block("blocked-term", "a name on your blocked list"));
        }
        let marker = prompt.starts_with(ALLOW_NAME_MARKER);
        if !opts.dry {
            log_allow_name(&opts.log, data, marker);
        }
        let notice = if marker {
            format!(
                "guard-prompt: {ALLOW_NAME_MARKER} let a blocked name through for this prompt (logged)."
            )
        } else {
            "guard-prompt: this prompt has a name on your blocked list. It was sent to Claude (logged); GraphMind skips it.".to_string()
        };
        return Ok(Verdict::Warn {
            marker,
            line: format!("{{\"systemMessage\": {}}}", py_str(&notice)),
        });
    }
    Ok(Verdict::Allow)
}

/// The verdict for one hook input (raw stdin bytes). Fails open on any internal error.
pub fn decide(input: &[u8], opts: &Options) -> Verdict {
    if std::str::from_utf8(input).is_err() {
        return failed("UnicodeDecodeError");
    }
    let v = match hookio::parse_py(input) {
        Ok(v) => v,
        Err(hookio::ParseError::Invalid) => return failed("JSONDecodeError"),
        Err(hookio::ParseError::TooDeep(_)) => return failed("RecursionError"),
    };
    let Value::Object(data) = v else {
        return Verdict::Allow;
    };
    let Some(Value::String(prompt)) = data.get("prompt") else {
        return Verdict::Allow;
    };
    if prompt.is_empty() {
        return Verdict::Allow;
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&data, prompt, opts))) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => failed(&e),
        Err(_) => failed("panic"),
    }
}

/// Print the verdict as guard-prompt.py did; always exit 0.
pub fn emit(v: &Verdict) -> i32 {
    let line = v.line();
    if !line.is_empty() {
        println!("{line}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_boundary_after_a_dash() {
        let key = format!("AIza{}abcdefg-", "SyD3x8kLm".repeat(3));
        assert_eq!(builtin_secret(&format!("{key} x")), None);
        assert_eq!(builtin_secret(&format!("{key}\u{1c}x")), None);
        assert_eq!(
            builtin_secret(&format!("{key}x")).map(|h| h.0),
            Some("gcp-api-key")
        );
        assert_eq!(
            builtin_secret(&format!("٣{key}x")),
            None,
            "an Arabic-Indic digit is a word character"
        );
    }

    #[test]
    fn ignorecase_letters() {
        assert!(builtin_secret("apİ_key=Xk29pq0zA!").is_some());
        assert!(builtin_secret("password=undefİned").is_none());
        let terms = vec!["Zorbenta Quillfeather".to_string()];
        assert!(blocked_term("ZORBENTA QUıLLFEATHER", &terms).unwrap());
    }
}
