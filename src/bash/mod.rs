//! `claude-guard bash`: the PreToolUse guard for Bash commands, ported from guard-bash.py (and block-pip.sh).
//!
//! Blocks, before the command runs:
//!   1. rm with recursive+force flags on an absolute path, unless the target is inside $TMPDIR or /tmp.
//!   2. Commands that name a secrets env file (.env, .env.local, .env.production, prod.env, direnv's .envrc, ...)
//!      directly or through a glob or brace expansion; recursive grep; rg --hidden/--no-ignore without
//!      excluding .env files. Templates (.env.example, ...) stay readable; jq/yq filters are not files.
//!   3. git push with --force or -f.
//!   4. sudo.
//!   5. `pip install` (from block-pip.sh): exit 2 with a message on stderr, after the rules above.
//!   6. rust-anything subcommands other than the read-only ones (analyze, map, doctor, help): the rest build or
//!      run the code being ported, or edit its sources, and its MCP tools for them are denied, so the CLI must not
//!      be the way round. Rust only (the Python guard never had it); also through wrappers.
//!
//! Every rule also holds inside strings run as commands, nested or not: `bash -c STRING` (sh, zsh, dash, ksh; `-lc`,
//! `-ec` too; after env, timeout or xargs options), `eval ARG...`, here-strings fed to a shell, `source` or `.`, and
//! `source <(echo STRING)`, and echo or printf output piped into a shell or `source /dev/stdin` (line by line). Rust only: the Python guard read the string as one word. Those strings are checked
//! after the rest of the command passed, so a command the Python guard blocked gets the same reason. Heredocs fed
//! to a shell, `source`, `.` or eval were already checked by the Python guard.
//!
//! A newline outside quotes and heredoc bodies ends a command, as `;` does (`cd x⏎sudo ls`); backslash-newline
//! continues the line. Rust only: the Python guard's shlex read a newline as a space, so a verb on a later line was
//! an argument of the first line's command.
//!
//! Same contract as the Python guard: a parse error allows the command (a quoting mistake never locks the
//! shell); any other failure blocks it (fail closed) and is logged. It only sees what is written in the command.

use crate::hookio::{self, py_truthy, py_type_name};
use crate::{pyfs, shlex};
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::LazyLock;

const SEPARATORS: &[&str] = &[";", "&&", "||", "|", "&", "(", ")", "!"];
const PREFIXES: &[&str] = &[
    "command", "builtin", "exec", "nohup", "time", "env", "xargs", "nice",
];
const KEYWORDS: &[&str] = &[
    "do", "then", "else", "elif", "if", "while", "until", "{", "}",
];
const ENV_SAFE_VERBS: &[&str] = &[
    "ls", "test", "[", "stat", "touch", "rm", "chmod", "mkdir", "echo", "printf", "ln",
];
const WRITE_REDIRECTS: &[&str] = &[">", ">>", ">|", "&>", "&>>"];
const JQ_VERBS: &[&str] = &["jq", "gojq", "jaq", "yq"];
const JQ_VALUE_OPTS: &[(&str, usize)] = &[
    ("--arg", 2),
    ("--argjson", 2),
    ("--slurpfile", 2),
    ("--rawfile", 2),
    ("--indent", 1),
    ("-L", 1),
    ("--library-path", 1),
];
const YQ_VALUE_OPTS: &[(&str, usize)] = &[
    ("-o", 1),
    ("--output-format", 1),
    ("-p", 1),
    ("--input-format", 1),
    ("-I", 1),
    ("--front-matter", 1),
    ("--expression", 1),
];
const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "eval", "source", "."];
const ENV_PROBES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".envrc",
    "prod.env",
];
const ENV_EXCLUDES: &[&str] = &["!.env*", "!*.env*", "!**/.env*", "!**/*.env*"];
/// rust-anything subcommands that only read (the MCP tools left allowed are analyze and map). Anything else,
/// including subcommands added later, is blocked.
const RUST_ANYTHING_READ_ONLY: &[&str] = &["analyze", "map", "doctor", "help"];
/// Commands that run the command after their own options. `segments_with_seps` already drops a leading
/// env/xargs/nice/nohup/time/command/builtin/exec, but their options (`nice -n 5`) stay behind as the verb.
const RUN_WRAPPERS: &[&str] = &[
    "timeout",
    "gtimeout",
    "caffeinate",
    "stdbuf",
    "arch",
    "nice",
    "env",
    "xargs",
    "nohup",
    "time",
    "command",
    "builtin",
    "exec",
];
/// Shells whose `-c` string is a command to check.
const C_SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh"];
/// What runs a here-string or process substitution fed to it as commands.
const STDIN_SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "source", "."];

// Python's `$` (no MULTILINE) also matches just before a final newline: `\n?\z` here.
static ENV_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|/)(?:\.env(?:\.[^/]+)?|\.envrc|[^/]+\.env)\n?\z").unwrap());
static ENV_TEMPLATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(?:example|sample|template|dist|defaults)\n?\z").unwrap());
static TEMP_ITEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:/private/tmp/[^/]+|/private/var/folders/[^/]+/[^/]+/T/[^/]+)").unwrap()
});
// block-pip.sh: grep -E '(^|[;&|][[:space:]]*)(python3? -m )?pip3? install' on each line of the command.
static PIP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?:^|[;&|][ \t\x0B\x0C\r]*)(?:python3? -m )?pip3? install").unwrap()
});

pub const NOT_TEXT: &str = "guard-bash: couldn't check this command (input not text); allowed.";
pub const PIP_MESSAGE: &str = "Do not use pip. Use uv instead. Example: uv add <packages>";
/// Python's recursion limit made deep nesting a RecursionError (a crash: blocked). Rust would overflow its stack
/// and abort, which Claude Code treats as a non-blocking error, so deep nesting is a crash here too.
const MAX_DEPTH: usize = 400;

/// A failure that blocks the command (Python: any exception other than the parse error).
#[derive(Debug)]
pub struct Crash(pub String);

/// The `cwd` field, as guard-bash used it: only its truthiness and, when it is a string, its value.
pub enum Cwd {
    Falsy,
    Path(String),
    NotStr(&'static str),
}

impl Cwd {
    pub fn from_value(v: Option<&Value>) -> Cwd {
        match v {
            Some(v) if py_truthy(v) => match v {
                Value::String(s) => Cwd::Path(s.clone()),
                other => Cwd::NotStr(py_type_name(other)),
            },
            _ => Cwd::Falsy,
        }
    }
}

fn contains(set: &[&str], s: &str) -> bool {
    set.contains(&s)
}

use crate::pyfs::py_isspace;

fn is_assignment(t: &str) -> bool {
    // ^[A-Za-z_][A-Za-z0-9_]*=
    let mut it = t.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    for c in it {
        if c == '=' {
            return true;
        }
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    false
}

/// re.match(r"^-[a-zA-Z]*<one of `wanted`>", a)
fn dash_letters_contain(a: &str, wanted: &[char]) -> bool {
    let mut it = a.chars();
    if it.next() != Some('-') {
        return false;
    }
    it.take_while(|c| c.is_ascii_alphabetic())
        .any(|c| wanted.contains(&c))
}

fn jq_filter_index(verb: &str, args: &[String]) -> Option<usize> {
    if !contains(JQ_VERBS, verb) {
        return None;
    }
    let value_opt = |a: &str| -> Option<usize> {
        let mut n = JQ_VALUE_OPTS.iter().find(|(o, _)| *o == a).map(|(_, n)| *n);
        if verb == "yq" {
            if let Some((_, m)) = YQ_VALUE_OPTS.iter().find(|(o, _)| *o == a) {
                n = Some(*m);
            }
        }
        n
    };
    let mut i = if verb == "yq"
        && args
            .first()
            .is_some_and(|a| ["eval", "e", "eval-all", "ea"].contains(&a.as_str()))
    {
        1
    } else {
        0
    };
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-f" || a == "--from-file" || a.starts_with("--from-file=") {
            return None;
        }
        if a == "--" {
            return if i + 1 < args.len() {
                Some(i + 1)
            } else {
                None
            };
        }
        if let Some(n) = value_opt(a) {
            i += 1 + n;
            continue;
        }
        if a.starts_with('-') && a != "-" {
            i += 1;
            continue;
        }
        return Some(i);
    }
    None
}

/// Heredoc starts on one line: (char index of `<<`, `<<-`?, delimiter), like guard-bash's regex
/// `(?<!<)<<(-?)[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2` with finditer.
fn heredoc_starts(line: &[char]) -> Vec<(usize, bool, String)> {
    let n = line.len();
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 1 < n {
        if line[pos] == '<' && line[pos + 1] == '<' && (pos == 0 || line[pos - 1] != '<') {
            let mut k = pos + 2;
            let tabs = k < n && line[k] == '-';
            if tabs {
                k += 1;
            }
            while k < n && (line[k] == ' ' || line[k] == '\t') {
                k += 1;
            }
            let quote = if k < n && (line[k] == '\'' || line[k] == '"') {
                k += 1;
                Some(line[k - 1])
            } else {
                None
            };
            if k < n && (line[k].is_ascii_alphabetic() || line[k] == '_') {
                let start = k;
                while k < n && (line[k].is_ascii_alphanumeric() || line[k] == '_') {
                    k += 1;
                }
                let ident: String = line[start..k].iter().collect();
                let closed = match quote {
                    None => true,
                    Some(q) => {
                        if k < n && line[k] == q {
                            k += 1;
                            true
                        } else {
                            false
                        }
                    }
                };
                if closed {
                    out.push((pos, tabs, ident));
                    pos = k;
                    continue;
                }
            }
        }
        pos += 1;
    }
    out
}

/// Remove heredoc bodies (data for the command that reads them); bodies a shell reads come back to be checked.
fn split_heredocs(command: &str) -> (String, Vec<String>) {
    let lines: Vec<&str> = command.split('\n').collect();
    let mut out: Vec<&str> = Vec::new();
    let mut run_as_shell = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        out.push(line);
        i += 1;
        let chars: Vec<char> = line.chars().collect();
        for (start, tabs, delim) in heredoc_starts(&chars) {
            let mut body: Vec<&str> = Vec::new();
            while i < lines.len() {
                let body_line = lines[i];
                i += 1;
                let cmp = if tabs {
                    body_line.trim_start_matches('\t')
                } else {
                    body_line
                };
                if cmp == delim {
                    break;
                }
                body.push(body_line);
            }
            let before: String = chars[..start].iter().collect();
            let last = before.rsplit([';', '&', '|', '(']).next().unwrap_or("");
            let first_word = last.split(py_isspace).find(|w| !w.is_empty());
            if let Some(w) = first_word {
                if contains(SHELLS, pyfs::basename(w)) {
                    run_as_shell.push(body.join("\n"));
                }
            }
        }
    }
    (out.join("\n"), run_as_shell)
}

/// Split into simple commands: [verb, args...], skipping prefixes like `env`, `xargs`, keywords, VAR=value; each
/// with the separator that ended it (`;` for the last).
fn segments_with_seps(tokens: Vec<String>) -> Vec<(Vec<String>, String)> {
    let mut out = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    for t in tokens.into_iter().chain(std::iter::once(";".to_string())) {
        // "\n": an unquoted newline (`shlex::split_lines`) ends a command as `;` does.
        if contains(SEPARATORS, &t) || t == "\n" {
            let skip = cur
                .iter()
                .take_while(|w| contains(PREFIXES, w) || contains(KEYWORDS, w) || is_assignment(w))
                .count();
            cur.drain(..skip);
            if !cur.is_empty() {
                out.push((std::mem::take(&mut cur), t));
            }
            cur.clear();
        } else {
            cur.push(t);
        }
    }
    out
}

/// Where a shell, `source` or `.` sits in a simple command: the verb, or after a wrapper and its options.
fn stdin_shell_at(seg: &[String]) -> Option<usize> {
    let verb = pyfs::basename(&seg[0]);
    if contains(STDIN_SHELLS, verb) {
        Some(0)
    } else if contains(RUN_WRAPPERS, verb) || verb.starts_with('-') {
        seg.iter()
            .position(|a| contains(STDIN_SHELLS, pyfs::basename(a)))
    } else {
        None
    }
}

/// True if the simple command runs its standard input as a script: `bash`, `sh -s`, `bash -x /dev/stdin`,
/// `source /dev/stdin`, `. /dev/fd/0`. Not with `-c` (stdin is then data) or a script file.
fn runs_stdin(seg: &[String]) -> bool {
    let Some(at) = stdin_shell_at(seg) else {
        return false;
    };
    let rest = &seg[at + 1..];
    let stdin_file = |a: &String| a == "/dev/stdin" || a == "/dev/fd/0";
    if !contains(C_SHELLS, pyfs::basename(&seg[at])) {
        return rest.first().is_some_and(stdin_file); // source, .
    }
    let short = |a: &&String| !a.starts_with("--") && a.starts_with('-');
    if rest
        .iter()
        .filter(short)
        .any(|a| dash_letters_contain(a, &['c']))
    {
        return false;
    }
    if rest
        .iter()
        .filter(short)
        .any(|a| dash_letters_contain(a, &['s']))
    {
        return true;
    }
    match rest.iter().find(|a| !a.starts_with('-')) {
        None => true,
        Some(a) => stdin_file(a),
    }
}

/// The script echo or printf writes, line by line: its arguments joined with spaces (echo's -n/-e/-E dropped, a
/// printf format with `%` dropped when arguments follow it), with `\n` read as a newline for printf and echo -e.
/// Lines, because the guard reads a newline as a space, and a script's lines are separate commands.
fn printed_lines(seg: &[String]) -> Option<Vec<String>> {
    let verb = pyfs::basename(&seg[0]);
    let args = &seg[1..];
    let (text, escapes) = match verb {
        "echo" => {
            let flags = args
                .iter()
                .take_while(|a| {
                    a.len() > 1 && a.starts_with('-') && a[1..].chars().all(|c| "neE".contains(c))
                })
                .count();
            let escapes = args[..flags].iter().any(|a| a.contains('e'));
            (args[flags..].join(" "), escapes)
        }
        "printf" => {
            let args = match args.first() {
                Some(a) if a == "--" => &args[1..],
                _ => args,
            };
            let args = match args.first() {
                Some(f) if f.contains('%') && args.len() > 1 => &args[1..],
                _ => args,
            };
            (args.join(" "), true)
        }
        _ => return None,
    };
    let text = if escapes {
        text.replace("\\n", "\n")
    } else {
        text
    };
    Some(
        text.split('\n')
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// Scripts piped into something that runs stdin: `echo 'sudo ls' | bash`, `printf ... | source /dev/stdin`.
fn piped_scripts(segs: &[(Vec<String>, String)]) -> Vec<String> {
    segs.windows(2)
        .filter(|w| w[0].1 == "|" && runs_stdin(&w[1].0))
        .filter_map(|w| printed_lines(&w[0].0))
        .flatten()
        .collect()
}

fn is_secret_env(token: &str) -> bool {
    let path = if token.starts_with("--") && token.contains('=') {
        token.split_once('=').unwrap().1
    } else {
        token
    };
    if path.contains(['*', '?', '[']) {
        return false; // globs are judged by what they expand to (glob_hits_secret)
    }
    ENV_FILE.is_match(path) && !ENV_TEMPLATE.is_match(path)
}

/// Split on commas that are not inside nested braces.
fn split_top(text: &[char]) -> Vec<Vec<char>> {
    let mut parts = Vec::new();
    let mut depth: i64 = 0;
    let mut cur = Vec::new();
    for &c in text {
        if c == ',' && depth == 0 {
            parts.push(std::mem::take(&mut cur));
            continue;
        }
        depth += (c == '{') as i64 - (c == '}') as i64;
        cur.push(c);
    }
    parts.push(cur);
    parts
}

/// Shell brace expansion for comma lists, nested included; a group without a comma stays literal.
fn expand_braces(word: &[char], limit: usize, depth: usize) -> Result<Vec<Vec<char>>, Crash> {
    if depth > MAX_DEPTH {
        return Err(Crash(
            "RecursionError: maximum recursion depth exceeded".into(),
        ));
    }
    let mut level = 0usize;
    let mut start = 0usize;
    for (i, &c) in word.iter().enumerate() {
        if c == '{' {
            if level == 0 {
                start = i;
            }
            level += 1;
        } else if c == '}' && level > 0 {
            level -= 1;
            if level == 0 {
                let parts = split_top(&word[start + 1..i]);
                if parts.len() > 1 {
                    let mut out = Vec::new();
                    for p in parts {
                        let mut w = word[..start].to_vec();
                        w.extend_from_slice(&p);
                        w.extend_from_slice(&word[i + 1..]);
                        out.extend(expand_braces(&w, limit, depth + 1)?);
                        if out.len() >= limit {
                            out.truncate(limit);
                            return Ok(out);
                        }
                    }
                    return Ok(out);
                }
            }
        }
    }
    Ok(vec![word.to_vec()])
}

fn s(chars: &[char]) -> String {
    chars.iter().collect()
}

/// True if a shell glob or brace expansion in `token` would produce a secrets env file.
fn glob_hits_secret(token: &str, cwd: &Cwd, depth: usize) -> Result<bool, Crash> {
    if depth > MAX_DEPTH {
        return Err(Crash(
            "RecursionError: maximum recursion depth exceeded".into(),
        ));
    }
    let chars: Vec<char> = token.chars().collect();
    let words = expand_braces(&chars, 256, depth + 1)?;
    if words.len() > 1 {
        for w in &words {
            let w = s(w);
            if is_secret_env(&w) || glob_hits_secret(&w, cwd, depth + 1)? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if !token.contains(['*', '?', '[']) {
        return Ok(false);
    }
    let fallback = || is_secret_env(&token.replace(['[', ']'], ""));
    let is_abs = token.starts_with('/');
    let has_cwd = !matches!(cwd, Cwd::Falsy);
    if has_cwd || is_abs {
        let pattern = if is_abs {
            token.to_string()
        } else {
            match cwd {
                Cwd::Path(c) => pyfs::join(c, token),
                // os.path.join(<int>, token): TypeError, which guard-bash didn't catch.
                Cwd::NotStr(t) => {
                    return Err(Crash(format!(
                        "TypeError: expected str, bytes or os.PathLike object, not {t}"
                    )));
                }
                Cwd::Falsy => unreachable!(),
            }
        };
        return Ok(match pyfs::glob(&pattern) {
            Ok(hits) => hits.iter().take(500).any(|m| is_secret_env(m)),
            Err(_) => fallback(),
        });
    }
    let base = pyfs::basename(token);
    for p in ENV_PROBES {
        match pyfs::fnmatchcase(p, base) {
            Ok(true) if is_secret_env(p) => return Ok(true),
            Ok(_) => {}
            Err(_) => return Ok(fallback()),
        }
    }
    Ok(false)
}

fn rg_excludes_env(args: &[String]) -> bool {
    let mut globs: Vec<String> = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if ["-g", "--glob", "--iglob"].contains(&a.as_str()) && i + 1 < args.len() {
            globs.push(args[i + 1].clone());
        } else if a.starts_with("--glob=") || a.starts_with("--iglob=") {
            globs.push(a.split_once('=').unwrap().1.to_string());
        } else if a.starts_with("-g") && a.chars().count() > 2 {
            globs.push(a.chars().skip(2).collect());
        }
    }
    globs.iter().any(|g| contains(ENV_EXCLUDES, g))
}

/// os.path.expanduser("~"): $HOME (trailing slashes removed), else the account's home.
fn home() -> String {
    let h = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::home_dir().map(|p| p.to_string_lossy().into_owned()))
        .unwrap_or_default();
    let h = h.trim_end_matches('/').to_string();
    if h.is_empty() { "/".into() } else { h }
}

/// arg with a leading ~, $HOME or ${HOME} replaced by the home folder; other args unchanged.
fn home_path(arg: &str) -> String {
    for start in ["~", "$HOME", "${HOME}"] {
        if arg == start || arg.starts_with(&format!("{start}/")) {
            return home() + &arg[start.len()..];
        }
    }
    arg.to_string()
}

fn is_rust_anything(token: &str) -> bool {
    pyfs::basename(token.trim_start_matches('`')) == "rust-anything"
}

/// The command lines a simple command runs from strings:
/// - `bash -c STRING` (also `sh -lc`, `zsh -ec`, `bash -o pipefail -c`): the argument after the first short option
///   that holds a `c`.
/// - A here-string fed to a shell, `source` or `.`: `bash <<< STRING`, `source /dev/stdin <<< STRING`.
/// - echo or printf output fed to one through process substitution: `source <(echo STRING)`, `bash <(printf ...)`:
///   the arguments joined with spaces (echo's -n/-e/-E dropped; printf's format is taken as text).
/// - `eval ARG...`: its arguments joined with spaces, as eval joins them (a leading `--` dropped). eval is a shell
///   builtin, so it only counts as the verb (`command eval` and `builtin eval` reach it through `segments_with_seps`).
///
/// The shell may sit after a wrapper (`/usr/bin/env bash -c`, `timeout 9 sh -c`, `xargs -I{} sh -c`: `segments_with_seps`
/// drops a leading xargs and leaves its options as the verb). Heredocs fed to these are `split_heredocs`' job.
fn nested_commands(seg: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if seg[0] == "eval" {
        let args = match seg.get(1) {
            Some(a) if a == "--" => &seg[2..],
            _ => &seg[1..],
        };
        if !args.is_empty() {
            out.push(args.join(" "));
        }
        return out;
    }
    let Some(shell) = stdin_shell_at(seg) else {
        return out;
    };
    let rest = &seg[shell + 1..];
    if contains(C_SHELLS, pyfs::basename(&seg[shell])) {
        if let Some(i) = rest
            .iter()
            .position(|a| !a.starts_with("--") && dash_letters_contain(a, &['c']))
        {
            out.extend(rest.get(i + 1).cloned());
        }
    }
    for w in rest.windows(2) {
        if w[0] == "<<<" {
            out.push(w[1].clone());
        }
    }
    if let Some(i) = rest.iter().position(|a| a == "<(") {
        if let Some(producer) = rest.get(i + 1) {
            let producer = pyfs::basename(producer);
            if producer == "echo" || producer == "printf" {
                let args: Vec<&str> = rest[i + 2..]
                    .iter()
                    .map(String::as_str)
                    .skip_while(|a| {
                        producer == "echo" && ["-n", "-e", "-E", "-ne", "-en"].contains(a)
                    })
                    .collect();
                if !args.is_empty() {
                    out.push(args.join(" "));
                }
            }
        }
    }
    out
}

/// True if a string `nested_commands` finds in `command`, at any depth, holds a `pip install` (block-pip's rule
/// only read the command's own lines).
fn pip_in_nested(command: &str, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false; // check() already crashed (blocked) at this depth
    }
    let (command, bodies) = split_heredocs(command);
    if bodies.iter().any(|b| pip_in_nested(b, depth + 1)) {
        return true;
    }
    let Ok(raw) = shlex::split_lines(&command) else {
        return false;
    };
    let segs = segments_with_seps(raw);
    segs.iter()
        .flat_map(|(s, _)| nested_commands(s))
        .chain(piped_scripts(&segs))
        .any(|inner| PIP.is_match(&inner) || pip_in_nested(&inner, depth + 1))
}

/// The reason to block the rust-anything run in one simple command, if it runs one that isn't read-only.
/// Finds it as the verb and after a wrapper (`timeout 60 rust-anything go`); `bash -c '...'` strings go
/// through `check` like every other rule.
fn rust_anything_reason(seg: &[String]) -> Option<String> {
    let verb = pyfs::basename(&seg[0]);
    let args: &[String] = if is_rust_anything(&seg[0]) {
        &seg[1..]
    } else if contains(RUN_WRAPPERS, verb) || verb.starts_with('-') {
        let i = seg.iter().position(|a| is_rust_anything(a))?;
        &seg[i + 1..]
    } else {
        // Backtick substitution: `echo `rust-anything build x``.
        let i = seg
            .iter()
            .position(|a| a.starts_with('`') && is_rust_anything(a))?;
        &seg[i + 1..]
    };
    // `rust-anything build --help` only prints help; a --help after `--` belongs to the workload instead.
    if args
        .iter()
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "-h" || a == "--help")
    {
        return None;
    }
    let sub = args.iter().find(|a| !a.starts_with('-'));
    let what = match sub {
        Some(s) if contains(RUST_ANYTHING_READ_ONLY, s) => return None,
        Some(s) => format!("rust-anything {s}"),
        // The version flag stops before any subcommand. Without it, the subcommand may come from elsewhere
        // (`... | xargs rust-anything`), so a bare run is blocked too.
        None if args.iter().any(|a| a == "-V" || a == "--version") => return None,
        None => "rust-anything without a subcommand".to_string(),
    };
    Some(format!(
        "{what} can build, run or edit the code being ported, and its MCP tool is denied. Claude may run only rust-anything analyze, map, doctor and help; run the rest yourself with !."
    ))
}

/// The reason to block `command`, if any. Err is a crash (blocks).
///
/// Two passes over the whole command: first reading a newline as a space, as the Python guard did, so a command it
/// blocked keeps its reason; then, if that passed, with newlines as separators. Each pass recurses in its own mode,
/// so nesting never multiplies the work.
pub fn check(command: &str, cwd: &Cwd, depth: usize) -> Result<Option<String>, Crash> {
    if let Some(r) = check_mode(command, cwd, depth, false)? {
        return Ok(Some(r));
    }
    check_mode(command, cwd, depth, true)
}

fn check_mode(
    command: &str,
    cwd: &Cwd,
    depth: usize,
    lines: bool,
) -> Result<Option<String>, Crash> {
    if depth > MAX_DEPTH {
        return Err(Crash(
            "RecursionError: maximum recursion depth exceeded".into(),
        ));
    }
    let (command, shell_bodies) = split_heredocs(command);
    for body in shell_bodies {
        if let Some(r) = check_mode(&body, cwd, depth + 1, lines)? {
            return Ok(Some(r));
        }
    }
    let lexed = if lines {
        shlex::split_lines(&command)
    } else {
        shlex::split_python(&command)
    };
    let Ok(raw) = lexed else {
        return Ok(None);
    };
    // Strings run as commands (`bash -c`, eval, here-strings, `source <(echo ...)`, `echo ... | bash`), checked
    // with every rule once the whole command has passed: a command the Python guard blocked keeps its verdict and
    // reason.
    let segs = segments_with_seps(raw);
    let mut nested: Vec<String> = piped_scripts(&segs);
    for (seg, _) in segs {
        nested.extend(nested_commands(&seg));
        let verb = pyfs::basename(&seg[0]).to_string();
        let args = &seg[1..];
        if verb == "sudo" {
            return Ok(Some(
                "sudo is blocked: Claude never needs admin rights. Run it yourself if you must."
                    .into(),
            ));
        }
        if let Some(r) = rust_anything_reason(&seg) {
            return Ok(Some(r));
        }
        if verb == "rm" {
            let flags: Vec<&String> = args.iter().filter(|a| a.starts_with('-')).collect();
            let short: String = flags
                .iter()
                .filter(|f| !f.starts_with("--"))
                .map(|f| f.chars().skip(1).collect::<String>())
                .collect();
            let has = |f: &str| flags.iter().any(|x| x.as_str() == f);
            if (short.contains('r') || short.contains('R') || has("--recursive"))
                && (short.contains('f') || has("--force"))
            {
                let mut seen = HashSet::new();
                let mut bad = Vec::new();
                for a in args {
                    if !seen.insert(a.clone()) {
                        continue;
                    }
                    let p = home_path(a);
                    if p.starts_with('/') {
                        let real = pyfs::realpath(&p).map_err(Crash)?;
                        if !TEMP_ITEM.is_match(&real) {
                            bad.push(a.clone());
                        }
                    }
                }
                if !bad.is_empty() {
                    return Ok(Some(format!(
                        "recursive force delete outside temp dirs ({}). Only items inside $TMPDIR or /tmp are allowed; run it yourself after checking the path.",
                        bad.join(", ")
                    )));
                }
            }
        }
        if verb == "git"
            && args.iter().any(|a| a == "push")
            && (args.iter().any(|a| a == "--force" || a == "-f")
                || args
                    .iter()
                    .filter(|a| !a.starts_with("--"))
                    .any(|a| dash_letters_contain(a, &['f'])))
        {
            return Ok(Some(
                "git push --force is blocked. Use --force-with-lease, or run it yourself.".into(),
            ));
        }
        if ["grep", "egrep", "fgrep"].contains(&verb.as_str())
            && args
                .iter()
                .filter(|a| {
                    a.starts_with('-') && !a.starts_with("--include") && !a.starts_with("--exclude")
                })
                .any(|a| {
                    ["-r", "-R", "--recursive", "--dereference-recursive"].contains(&a.as_str())
                        || dash_letters_contain(a, &['r', 'R'])
                })
        {
            return Ok(Some("recursive grep also reads .env files. Use rg (skips hidden and gitignored files) or the Grep tool.".into()));
        }
        if verb == "rg"
            && args.iter().any(|a| {
                ["--hidden", "--no-ignore", "-uu", "-uuu", "-."].contains(&a.as_str())
                    || a.starts_with("--no-ignore")
            })
            && !rg_excludes_env(args)
        {
            return Ok(Some("rg with --hidden/--no-ignore also reads .env files. Run plain rg, or exclude them with -g '!.env*'.".into()));
        }
        if !contains(ENV_SAFE_VERBS, &verb) {
            let mut written: HashSet<usize> = args
                .iter()
                .enumerate()
                .filter(|(_, a)| contains(WRITE_REDIRECTS, a))
                .map(|(i, _)| i + 1)
                .collect();
            if let Some(f) = jq_filter_index(&verb, args) {
                written.insert(f);
            }
            let mut secret: Vec<String> = Vec::new();
            for (i, a) in args.iter().enumerate() {
                if written.contains(&i) {
                    continue;
                }
                let after_eq = a.split_once('=').map(|(_, v)| v).unwrap_or(a);
                if after_eq.starts_with('!') {
                    continue;
                }
                if is_secret_env(a) || glob_hits_secret(a, cwd, depth + 1)? {
                    secret.push(a.clone());
                }
            }
            // Creating a .env from a template (`cp .env.example .env`) writes it without reading it.
            if (verb == "cp" || verb == "install")
                && !args.is_empty()
                && secret.len() == 1
                && secret[0] == args[args.len() - 1]
            {
                let last: Vec<char> = args[args.len() - 1].chars().collect();
                if expand_braces(&last, 256, depth + 1)?.len() == 1 {
                    secret.clear();
                }
            }
            if !secret.is_empty() {
                return Ok(Some(format!(
                    "reading a secrets file ({}) would put its values in Claude's context. Templates like .env.example are fine; read the real file yourself.",
                    secret.join(", ")
                )));
            }
        }
    }
    // A string that doesn't parse is allowed, as the whole command is.
    for inner in nested {
        if let Some(r) = check_mode(&inner, cwd, depth + 1, lines)? {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// What the hook does with one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// guard-bash's deny (JSON on stdout, exit 0); `crash` marks the fail-closed case.
    Deny {
        reason: String,
        crash: bool,
    },
    /// block-pip's block (message on stderr, exit 2).
    Pip,
    /// Allowed with a warning (a command that isn't text).
    Warn(&'static str),
}

impl Verdict {
    /// A short rule id for logs: never the command or a path.
    pub fn rule(&self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Pip => "pip",
            Verdict::Warn(_) => "warn-not-text",
            Verdict::Deny { crash: true, .. } => "crash",
            Verdict::Deny { reason, .. } => rule_of(reason),
        }
    }
}

/// Rule id from a guard-bash reason text (works for the Python guard's output too).
pub fn rule_of(reason: &str) -> &'static str {
    let r = reason.strip_prefix("guard-bash: ").unwrap_or(reason);
    if r.starts_with("sudo is blocked") {
        "sudo"
    } else if r.starts_with("recursive force delete") {
        "rm-rf"
    } else if r.starts_with("git push --force") {
        "git-force-push"
    } else if r.starts_with("recursive grep") {
        "grep-recursive"
    } else if r.starts_with("rg with --hidden") {
        "rg-hidden"
    } else if r.starts_with("reading a secrets file") {
        "secret-file"
    } else if r.starts_with("rust-anything ") {
        "rust-anything"
    } else if r.starts_with("guard-bash crashed") {
        "crash"
    } else {
        "other"
    }
}

/// The default crash log (`--crash-log` overrides it; tests point it at a temp file).
pub fn default_crash_log() -> String {
    format!("{}/.local/state/claude-guard/bash-crash.log", home())
}

/// Append the error and the start of the command (it may hold secrets: cut to 500 characters, mode 600).
fn log_crash(path: &str, command: &str, error: &str) {
    let head: String = command.chars().take(500).collect();
    let record = format!(
        "--- {} claude-guard {}\n{:?}\n{}\n",
        crate::now_utc(),
        env!("CARGO_PKG_VERSION"),
        head,
        error
    );
    crate::logfile::append(path, &record, crate::logfile::CRASH_CAP);
}

fn crash_reason(path: &str, error: &str) -> String {
    format!(
        "guard-bash crashed ({error}); command blocked. Details in {path}. Report it so the guard can be fixed."
    )
}

/// The verdict for one hook input (raw stdin bytes). Never panics: a panic inside the check is a crash.
pub fn decide(input: &[u8], crash_log: &str) -> Verdict {
    let payload = match hookio::parse_py(input) {
        Ok(v) => v,
        Err(hookio::ParseError::Invalid) => return Verdict::Allow,
        // JSON nested too deep to read blocks, like a command too deep to check: anyone can pad input that way.
        Err(hookio::ParseError::TooDeep(kind)) => {
            let e = hookio::ParseError::too_deep_text(kind);
            log_crash(crash_log, "", &e);
            return Verdict::Deny {
                reason: format!("guard-bash: {}", crash_reason(crash_log, &e)),
                crash: true,
            };
        }
    };
    let Value::Object(obj) = &payload else {
        return Verdict::Allow;
    };
    let empty = Value::Object(Default::default());
    let tool_input = obj.get("tool_input").unwrap_or(&empty);
    let Value::Object(ti) = tool_input else {
        return Verdict::Allow;
    };
    let command = ti
        .get("command")
        .cloned()
        .unwrap_or(Value::String(String::new()));
    let cwd = Cwd::from_value(obj.get("cwd"));

    let result: Result<Option<String>, Crash> = if !py_truthy(&command) {
        Ok(None)
    } else {
        match &command {
            Value::String(c) => {
                let c = c.clone();
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&c, &cwd, 0)))
                {
                    Ok(r) => r,
                    Err(p) => {
                        let msg = p
                            .downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| p.downcast_ref::<String>().cloned())
                            .unwrap_or_default();
                        Err(Crash(format!("panic: {msg}")))
                    }
                }
            }
            // A command that isn't text (Claude Code always sends text) can't hide a shell command: allow it with a
            // warning. Too-deep input still blocks (a crash): anyone can pad a command that way.
            _ => return Verdict::Warn(NOT_TEXT),
        }
    };
    match result {
        Ok(Some(reason)) => {
            return Verdict::Deny {
                reason: format!("guard-bash: {reason}"),
                crash: false,
            };
        }
        Err(Crash(e)) => {
            let text = if let Value::String(c) = &command {
                c.clone()
            } else {
                command.to_string()
            };
            log_crash(crash_log, &text, &e);
            return Verdict::Deny {
                reason: format!("guard-bash: {}", crash_reason(crash_log, &e)),
                crash: true,
            };
        }
        Ok(None) => {}
    }
    // block-pip.sh read `.tool_input.command` with jq -r; only a string can match.
    if let Value::String(c) = &command {
        if PIP.is_match(c) || pip_in_nested(c, 0) {
            return Verdict::Pip;
        }
    }
    Verdict::Allow
}

/// Print the verdict the way the hooks did; returns the exit code.
pub fn emit(v: &Verdict) -> i32 {
    match v {
        Verdict::Allow => 0,
        Verdict::Deny { reason, .. } => {
            println!("{}", hookio::deny_line(reason));
            0
        }
        Verdict::Pip => {
            eprintln!("{PIP_MESSAGE}");
            2
        }
        Verdict::Warn(msg) => {
            println!("{{\"systemMessage\": {}}}", hookio::py_str(msg));
            0
        }
    }
}
