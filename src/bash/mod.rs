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
//! In that newline pass a heredoc starts only where bash starts one: outside quotes and comments, or inside `$(...)`
//! and backticks. A heredoc inside a quoted `bash -c '...'` string stays in the string and is checked with it; the
//! Python guard's reading cut the "body" out of the string, which then failed to parse and was allowed.
//! A heredoc whose command's output is piped into a shell that runs its stdin (`cat <<EOF | bash`, `sed ... <<EOF |
//! sh`, `cat <<EOF |` with `bash` on the line after the body) has its body checked too, as written and as sed, awk
//! or `perl -pe` filters on the way would turn it (`filters`); the Python guard read it as data. Heredocs behind a wrapper (`timeout 9 bash <<EOF`, `ssh host <<EOF`) or whose output is run
//! (`eval "$(cat <<EOF`, `bash <(cat <<EOF`) count as fed to a shell; a `case` pattern's `)` doesn't end `$(...)`.
//!
//! The rules also hold for what a wrapper runs (`wrappers`: argv wrappers with options, ssh, containers, su/runuser/
//! sg, find -exec, watch/script/flock/env -S), for the command again with the values of variables it sets put in
//! (`c='sudo ls'; bash -c "$c"`), for scripts it writes and then runs (`cat > run.sh <<EOF ...; bash run.sh`), and
//! for script files on disk it runs inside the project or a temp folder (`scripts`: `bash scripts/x.sh`,
//! `cat x | bash`, 256 KiB cap). Rust only, all checked after the rest of the command passed.
//!
//! Commands run by interpreter code (perl, python, node/bun/deno, ruby, php, lua, osascript), inline, on stdin or
//! in a script file, are checked too (`interp`).
//!
//! Command substitutions inside double quotes and backticks are checked too (`substitutions`); `[[ ... ]]`,
//! `[ ! ... ]` and `test ! ...` stay one test command (`test_word`), so naming a `.env` there only tests it; pip is
//! also matched per simple command (`then pip install`). Rust only.
//!
//! Same contract as the Python guard: a parse error allows the command (a quoting mistake never locks the
//! shell); any other failure blocks it (fail closed) and is logged. Besides the command text, it reads only the
//! script files the command runs (see `scripts`).

mod context;
mod filters;
mod interp;
mod scripts;
mod values;
mod wrappers;

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
    "ls", "test", "[", "[[", "stat", "touch", "rm", "chmod", "mkdir", "echo", "printf", "ln",
    // Print a path, or change an owner, without reading the file (Rust only).
    "readlink", "realpath", "chown", "chgrp",
];
const GREP_VERBS: &[&str] = &["grep", "egrep", "fgrep"];
/// Options that take a value in the next word (or glued: `-m1`, `--max-count=1`), so the word after isn't the
/// pattern. `e`/`regexp` give a pattern and `f`/`file` a pattern file; both are handled on their own.
const GREP_VALUE_SHORT: &str = "efmABCdD";
const GREP_VALUE_LONG: &[&str] = &[
    "regexp",
    "file",
    "max-count",
    "after-context",
    "before-context",
    "context",
    "directories",
    "devices",
    "label",
    "include",
    "exclude",
    "exclude-dir",
    "exclude-from",
    "binary-files",
    "group-separator",
];
const RG_VALUE_SHORT: &str = "efgtTmABCjMErd";
const RG_VALUE_LONG: &[&str] = &[
    "regexp",
    "file",
    "glob",
    "iglob",
    "type",
    "type-not",
    "type-add",
    "type-clear",
    "max-count",
    "after-context",
    "before-context",
    "context",
    "threads",
    "max-columns",
    "encoding",
    "replace",
    "max-depth",
    "maxdepth",
    "max-filesize",
    "pre",
    "pre-glob",
    "sort",
    "sortr",
    "path-separator",
    "colors",
    "color",
    "context-separator",
    "field-context-separator",
    "field-match-separator",
    "engine",
    "dfa-size-limit",
    "regex-size-limit",
    "ignore-file",
    "hyperlink-format",
    "hostname-bin",
    "generate",
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
    LazyLock::new(|| re(r"(?:^|/)(?:\.env(?:\.[^/]+)?|\.envrc|[^/]+\.env)\n?\z"));
static ENV_TEMPLATE: LazyLock<Regex> =
    LazyLock::new(|| re(r"\.(?:example|sample|template|dist|defaults)\n?\z"));
static TEMP_ITEM: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(?:/private/tmp/[^/]+|/private/var/folders/[^/]+/[^/]+/T/[^/]+)"));
// block-pip.sh: grep -E '(^|[;&|][[:space:]]*)(python3? -m )?pip3? install' on each line of the command.
static PIP: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?m)(?:^|[;&|][ \t\x0B\x0C\r]*)(?:python3? -m )?pip3? install"));

pub const NOT_TEXT: &str = "guard-bash: couldn't check this command (input not text); allowed.";
pub const PIP_MESSAGE: &str = "Do not use pip. Use uv instead. Example: uv add <packages>";
/// Python's recursion limit made deep nesting a RecursionError (a crash: blocked). Rust would overflow its stack
/// and abort, which Claude Code treats as a non-blocking error, so deep nesting is a crash here too.
const MAX_DEPTH: usize = 400;
/// The most pieces (the command, nested strings, heredoc bodies, scripts) one check reads before it blocks.
const MAX_CHECKS: usize = 20_000;

thread_local! {
    static CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

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

/// A guard regex, compiled once per process and shared (one check compiles the same patterns many times).
pub(super) fn re(pattern: &str) -> Regex {
    // INFALLIBLE: every pattern given here is a literal in this crate or built with `regex::escape`; the table tests
    // compile each of them.
    re_try(pattern).expect("guard regex")
}

/// A regex from text the command supplies (a sed script's pattern), cached like `re`; None if it doesn't compile.
pub(super) fn re_try(pattern: &str) -> Option<Regex> {
    thread_local! {
        static CACHE: std::cell::RefCell<std::collections::HashMap<String, Option<Regex>>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }
    CACHE.with(|c| {
        if let Some(r) = c.borrow().get(pattern) {
            return r.clone();
        }
        let r = Regex::new(pattern).ok();
        let mut c = c.borrow_mut();
        if c.len() < 4096 {
            c.insert(pattern.to_string(), r.clone());
        }
        r
    })
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

/// Which arguments of a grep or rg call are search patterns, not files it reads (Rust only): each `-e`/`--regexp`
/// value, else the first argument that isn't an option or an option's value (also after `--`). A pattern file
/// (`-f F`, `--file F`) is read, so it isn't one; with `-f`, or `rg --files`, no plain argument is a pattern.
fn search_pattern_indices(verb: &str, args: &[String]) -> Vec<usize> {
    let (short_val, long_val) = if contains(GREP_VERBS, verb) {
        (GREP_VALUE_SHORT, GREP_VALUE_LONG)
    } else if verb == "rg" {
        (RG_VALUE_SHORT, RG_VALUE_LONG)
    } else {
        return Vec::new();
    };
    let mut pats = Vec::new();
    let mut given = verb == "rg" && args.iter().any(|a| a == "--files" || a == "--type-list");
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            if !given && i + 1 < args.len() {
                pats.push(i + 1);
            }
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((n, _)) => (n, true),
                None => (long, false),
            };
            match name {
                "regexp" => {
                    given = true;
                    pats.push(if glued { i } else { i + 1 });
                }
                "file" => given = true,
                _ => {}
            }
            if !glued && contains(long_val, name) {
                i += 1;
            }
        } else if a.len() > 1 && a.starts_with('-') {
            let letters: Vec<char> = a[1..].chars().collect();
            if let Some(k) = letters.iter().position(|c| short_val.contains(*c)) {
                let glued = k + 1 < letters.len();
                match letters[k] {
                    'e' => {
                        given = true;
                        pats.push(if glued { i } else { i + 1 });
                    }
                    'f' => given = true,
                    _ => {}
                }
                if !glued {
                    i += 1;
                }
            }
        } else {
            if !given {
                pats.push(i);
            }
            break;
        }
        i += 1;
    }
    // A glob or brace word is expanded by the shell first (`grep .env* x` is `grep .env .env.local x`, which reads
    // .env.local), so it stays checked like any other argument.
    pats.retain(|&p| {
        args.get(p)
            .is_some_and(|a| !a.contains(['*', '?', '[', '{']))
    });
    pats
}

/// Words a substitution's body only prints, for the command around it (Rust only): `$(readlink -f .env)`,
/// `$(echo .env)`, `$(ls x)`, `$(realpath x)`, `$(printf %s x)` read as those words (`cat $(readlink -f .env)`
/// reads .env). None for anything else, or a body that prints no arguments.
fn printed_words(body: &str) -> Option<String> {
    const PRINTERS: &[&str] = &["echo", "printf", "ls", "readlink", "realpath"];
    let tokens = lex_lines(body).ok()?;
    let segs = segments_with_seps(tokens);
    let [(seg, _)] = segs.as_slice() else {
        return None;
    };
    if !contains(PRINTERS, pyfs::basename(&seg[0])) {
        return None;
    }
    let words: Vec<String> = strip_redirs(&seg[1..])
        .into_iter()
        .filter(|a| !a.starts_with('-'))
        .collect();
    (!words.is_empty()).then(|| words.join(" "))
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

/// Where the scanner is, for `split_heredocs`' quote-aware reading: code (top level, inside `$(...)`, or inside
/// backticks), or inside '...', "...", $'...'. A code frame counts its open `(` and `case ... esac` blocks, so a
/// `)` that closes either (`$(case $x in a) ...;; esac)`) doesn't end the substitution, and knows whether the
/// next word is in command position (where `case` and `esac` are keywords).
#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    Code { parens: u32, cases: u32, cmd: bool },
    Backtick,
    Single,
    Double,
    AnsiC,
}

const CODE: Ctx = Ctx::Code {
    parens: 0,
    cases: 0,
    cmd: true,
};

/// Keywords after which the next word is a command again.
const LEAD_KEYWORDS: &[&str] = &[
    "do", "then", "else", "elif", "if", "while", "until", "!", "{", "time",
];

/// Which chars of one line are code (outside quotes and comments), given the contexts open at its start; updates
/// them for the next line. Also returns whether the line ends in a backslash continuation.
fn code_mask(line: &[char], stack: &mut Vec<Ctx>) -> (Vec<bool>, bool) {
    let n = line.len();
    let mut mask = vec![false; n];
    // A new line starts a command (unless the last one ended in `|`, `&&`: still command position).
    if let Some(Ctx::Code { cmd, .. }) = stack.last_mut() {
        *cmd = true;
    }
    let set_cmd = |stack: &mut Vec<Ctx>, v: bool| {
        if let Some(Ctx::Code { cmd, .. }) = stack.last_mut() {
            *cmd = v;
        }
    };
    let mut i = 0;
    while i < n {
        let c = line[i];
        let next = line.get(i + 1).copied();
        match *stack.last().unwrap_or(&CODE) {
            Ctx::Single => {
                if c == '\'' {
                    stack.pop();
                }
            }
            Ctx::AnsiC => {
                if c == '\\' {
                    i += 1;
                } else if c == '\'' {
                    stack.pop();
                }
            }
            Ctx::Double => {
                if c == '\\' {
                    i += 1;
                } else if c == '"' {
                    stack.pop();
                } else if c == '$' && next == Some('(') {
                    stack.push(CODE);
                    i += 1;
                } else if c == '`' {
                    stack.push(Ctx::Backtick);
                }
            }
            top @ (Ctx::Code { .. } | Ctx::Backtick) => {
                mask[i] = true;
                let word_start =
                    i == 0 || line[i - 1].is_whitespace() || ";&|()<>".contains(line[i - 1]);
                match c {
                    '\\' if i + 1 == n => return (mask, true),
                    '\\' => {
                        set_cmd(stack, false);
                        i += 1;
                    }
                    '#' if word_start => break,
                    '\'' => {
                        set_cmd(stack, false);
                        stack.push(Ctx::Single);
                    }
                    '"' => {
                        set_cmd(stack, false);
                        stack.push(Ctx::Double);
                    }
                    '$' if next == Some('\'') => {
                        set_cmd(stack, false);
                        stack.push(Ctx::AnsiC);
                        i += 1;
                    }
                    '$' if next == Some('(') => {
                        set_cmd(stack, false);
                        stack.push(CODE);
                        i += 1;
                    }
                    '`' if top == Ctx::Backtick => {
                        stack.pop();
                    }
                    '`' => stack.push(Ctx::Backtick),
                    ';' | '&' | '|' => set_cmd(stack, true),
                    '(' => {
                        if let Some(Ctx::Code { parens, cmd, .. }) = stack.last_mut() {
                            *parens += 1;
                            *cmd = true;
                        }
                    }
                    ')' => {
                        let depth = stack.len();
                        match stack.last_mut() {
                            Some(Ctx::Code { parens, cmd, .. }) if *parens > 0 => {
                                *parens -= 1;
                                *cmd = true;
                            }
                            // A case pattern's `)`: the arm's command follows.
                            Some(Ctx::Code { cases, cmd, .. }) if *cases > 0 => *cmd = true,
                            Some(Ctx::Code { .. }) if depth > 1 => {
                                stack.pop();
                            }
                            _ => {}
                        }
                    }
                    c if word_start && !c.is_whitespace() && !"<>".contains(c) => {
                        // A plain word: `case`/`esac` in command position open and close a case block.
                        let end = (i + 1..n)
                            .find(|&k| {
                                line[k].is_whitespace() || ";&|()<>'\"`$\\".contains(line[k])
                            })
                            .unwrap_or(n);
                        let word: String = line[i..end].iter().collect();
                        let boundary = end == n || !"'\"`$\\".contains(line[end]);
                        if let Some(Ctx::Code { cases, cmd, .. }) = stack.last_mut() {
                            if *cmd && boundary && word == "case" {
                                *cases += 1;
                                *cmd = false;
                            } else if *cmd && boundary && word == "esac" && *cases > 0 {
                                *cases -= 1;
                                *cmd = false;
                            } else if !(*cmd && boundary && contains(LEAD_KEYWORDS, &word)) {
                                *cmd = false;
                            }
                        }
                        for m in mask.iter_mut().take(end).skip(i) {
                            *m = true;
                        }
                        i = end;
                        continue;
                    }
                    _ => {}
                }
            }
        }
        i += 1;
    }
    (mask, false)
}

/// Where a pipeline carrying a heredoc's body ends up: in a shell that runs its stdin, somewhere else, or not yet
/// known because the line ends in `|` and the pipeline goes on after the heredoc bodies.
#[derive(PartialEq)]
enum Pipe {
    /// Reaches a shell, through these filters.
    Shell(Vec<Vec<String>>),
    /// Ends elsewhere, after these filters.
    Data(Vec<Vec<String>>),
    /// Goes on after the bodies, through these filters so far.
    NextLine(Vec<Vec<String>>),
}

/// Follows a pipeline through its segments: any filter on the way (`sed`, `grep`, `tr`) passes the body on.
/// `from_first`: the first segment is already a pipe target (a line continuing a pipeline), not the producer.
fn pipe_walk(text: &str, from_first: bool) -> Pipe {
    let Ok(tokens) = lex_lines(text) else {
        return Pipe::Data(Vec::new());
    };
    let segs = segments_with_seps(tokens);
    let mut chain: Vec<Vec<String>> = Vec::new();
    for (k, (seg, sep)) in segs.iter().enumerate() {
        if (k > 0 || from_first) && runs_stdin(seg) {
            return Pipe::Shell(chain);
        }
        if k > 0 || from_first {
            chain.push(seg.clone());
        }
        if sep != "|" {
            return Pipe::Data(chain);
        }
    }
    // Ended in `|`, or a blank or comment-only line: the pipeline goes on.
    Pipe::NextLine(chain)
}

/// Remove heredoc bodies (data for the command that reads them); bodies a shell reads come back to be checked.
///
/// `quoted` false reads `<<WORD` anywhere, as the Python guard's regex did. `quoted` true (the newline pass) reads
/// it only as code, outside quotes and comments, and starts the bodies after the first line that ends outside
/// quotes, as bash does: a heredoc written inside a quoted `bash -c '...'` string stays in that string, which is
/// then checked on its own, and a quoted `<<WORD` no longer hides the lines after it.
/// It also counts a heredoc whose command's output is piped into a shell that runs its stdin as fed to that shell
/// (`cat <<EOF | bash`, `sed s/a/b/ <<EOF | sh`, or `cat <<EOF |` with `bash` on the line after the bodies). Heredocs inside `"$(...)"`
/// and backticks are code, so `git commit -m "$(cat <<'EOF' ...)"` still drops its message.
fn split_heredocs(command: &str, quoted: bool) -> (String, Vec<String>, Vec<(String, String)>) {
    let lines: Vec<&str> = command.split('\n').collect();
    let mut out: Vec<&str> = Vec::new();
    let mut run_as_shell = Vec::new();
    let mut stack = vec![CODE];
    // Bodies written to a file (`cat > run.sh <<EOF`): (file, body), for a later `bash run.sh` in the command.
    let mut written: Vec<(String, String)> = Vec::new();
    // (strip leading tabs, delimiter, fed to a shell through these filters, pipeline goes on after the bodies
    // through these filters, file written)
    type Chain = Vec<Vec<String>>;
    // ... and the commands reading it on the way (sed `e`, awk `system`).
    type Pending = (
        bool,
        String,
        Option<Chain>,
        Option<Chain>,
        Option<String>,
        Chain,
    );
    let mut pending: Vec<Pending> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        out.push(line);
        i += 1;
        let chars: Vec<char> = line.chars().collect();
        let (mask, continued) = if quoted {
            code_mask(&chars, &mut stack)
        } else {
            (vec![true; chars.len()], false)
        };
        for (start, tabs, delim) in heredoc_starts(&chars) {
            if !mask[start] {
                continue;
            }
            let before: String = chars[..start].iter().collect();
            let last = before.rsplit([';', '&', '|', '(']).next().unwrap_or("");
            let mut first_word = last.split(py_isspace).find(|w| !w.is_empty());
            // The newline pass also ends a command at `)` (a case pattern, `(a) bash <<EOF`) and skips keywords
            // and assignments (`then bash <<EOF`, `X=1 bash <<EOF`).
            if quoted {
                let last = before
                    .rsplit([';', '&', '|', '(', ')'])
                    .next()
                    .unwrap_or("");
                first_word = last
                    .split(py_isspace)
                    .find(|w| !w.is_empty() && !contains(KEYWORDS, w) && !is_assignment(w));
            }
            let mut shell_reads = first_word.is_some_and(|w| contains(SHELLS, pyfs::basename(w)));
            let mut target = None;
            // The command reading the heredoc, a filter itself when its output goes on (`sed ... <<EOF | bash`).
            let mut producer: Vec<String> = Vec::new();
            if quoted {
                let piece = before
                    .rsplit([';', '&', '|', '(', ')'])
                    .next()
                    .unwrap_or("");
                // Behind a wrapper: `timeout 9 bash <<EOF`, `ssh host <<EOF`, `docker exec -i c sh <<EOF`.
                // Lexed whole first, so quoted `;`, `&` or `(` in its arguments (`sed 's/.*/x &/'`) stay in them;
                // the split piece when the line doesn't lex alone (`x="$(cat <<EOF`).
                let tokens = lex_lines(&before).or_else(|_| lex_lines(piece));
                if let Ok(tokens) = tokens {
                    if let Some(seg) = raw_segments(&tokens).pop() {
                        shell_reads |= runs_stdin(&seg);
                        producer = seg;
                    }
                }
                // Its output run as commands: `eval "$(cat <<EOF`, `bash <(cat <<EOF`.
                shell_reads |= output_runs(&before);
                let rest: String = chars[start..].iter().collect();
                target = heredoc_target(&format!("{piece}{rest}"));
            }
            // The newline pass also follows the command's output: piped into a shell that runs its stdin (on this
            // line, or on the line after the bodies when this one ends in `|`), the body is checked as written.
            let pipe = if quoted && !shell_reads && first_word.is_some() {
                let rest: String = chars[start..].iter().collect();
                pipe_walk(&rest, false)
            } else {
                Pipe::Data(Vec::new())
            };
            let with_producer = |mut filters: Chain| {
                if !producer.is_empty() {
                    filters.insert(0, producer.clone());
                }
                filters
            };
            let readers = match &pipe {
                Pipe::Shell(f) | Pipe::Data(f) | Pipe::NextLine(f) => with_producer(f.clone()),
            };
            let (feed, next) = match pipe {
                _ if shell_reads => (Some(Vec::new()), None),
                Pipe::Shell(filters) => (Some(with_producer(filters)), None),
                Pipe::NextLine(filters) => (None, Some(with_producer(filters))),
                Pipe::Data(_) => (None, None),
            };
            pending.push((tabs, delim, feed, next, target, readers));
        }
        let ready = !quoted
            || (!continued && matches!(stack.last(), Some(Ctx::Code { .. } | Ctx::Backtick)));
        if !ready {
            continue;
        }
        let mut pipe_next: Vec<(String, Chain)> = Vec::new();
        for (tabs, delim, feed, next, target, readers) in pending.drain(..) {
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
            if let Some(f) = target {
                written.push((f, body.join("\n")));
            }
            let body = body.join("\n");
            // Commands sed or awk run on the way (`sed 's/^/sudo /e' <<EOF`), shell or not at the end.
            for stage in &readers {
                run_as_shell.extend(filters::executed(stage, Some(&body)));
            }
            if let Some(chain) = feed {
                run_as_shell.extend(filters::outputs(&chain, &body));
            } else if let Some(chain) = next {
                pipe_next.push((body, chain));
            }
        }
        // `cat <<EOF |`: the pipeline goes on at the first command line after the bodies.
        if !pipe_next.is_empty() {
            for later in &lines[i..] {
                match pipe_walk(later, true) {
                    Pipe::Shell(more) => {
                        for (body, mut chain) in pipe_next.drain(..) {
                            chain.extend(more.iter().cloned());
                            run_as_shell.extend(filters::outputs(&chain, &body));
                        }
                        break;
                    }
                    Pipe::Data(_) => break,
                    Pipe::NextLine(more) => {
                        for (_, chain) in pipe_next.iter_mut() {
                            chain.extend(more.iter().cloned());
                        }
                    }
                }
            }
        }
    }
    (out.join("\n"), run_as_shell, written)
}

/// True if the heredoc whose line runs up to `before` (ending just before `<<`) has its output run as commands:
/// `$(cat <<EOF ...)` as a command, `eval "$(cat <<EOF`, `bash -c "$(cat <<EOF`, `bash <(cat <<EOF`,
/// `source <(cat <<EOF`. An assignment or argument (`x=$(cat <<EOF`, `echo "$(cat <<EOF`) is data.
fn output_runs(before: &str) -> bool {
    let Some(cut) = before.rfind('(') else {
        return false;
    };
    let (opener, inside) = (&before[..cut], &before[cut + 1..]);
    if inside.contains([')', ';', '&', '|']) {
        return false;
    }
    let dollar = opener.ends_with('$');
    if !dollar && !opener.ends_with('<') {
        return false;
    }
    let consumer = &opener[..opener.len() - 1];
    let consumer = consumer.strip_suffix('"').unwrap_or(consumer);
    if consumer
        .chars()
        .last()
        .is_some_and(|c| !c.is_whitespace() && !";&|()".contains(c))
    {
        return false; // part of a word: `x=$(`, `--opt=$(`
    }
    let piece = consumer
        .rsplit([';', '&', '|', '(', ')'])
        .next()
        .unwrap_or("");
    let Ok(tokens) = lex_lines(piece) else {
        return false;
    };
    match raw_segments(&tokens).into_iter().next() {
        None => dollar,
        Some(seg) if !dollar => stdin_shell_at(&seg).is_some(),
        Some(seg) => {
            seg[0] == "eval"
                || (contains(C_SHELLS, pyfs::basename(&seg[0]))
                    && seg.last().is_some_and(|a| dash_letters_contain(a, &['c'])))
        }
    }
}

/// Commands run by the code of interpreter scripts these simple commands run from disk: `python3 x.py`,
/// `node x.js`, `ruby x.rb`, `perl x.pl`, `php x.php`, `lua x.lua`, `osascript x.applescript`, or `./x` with such a
/// shebang (also behind argv wrappers). Same reading rules as shell scripts, except that a file over the size cap
/// is skipped rather than blocked (built bundles such as `node dist/server.js` are often that big).
fn interp_file_commands(raw_segs: &[Vec<String>], cwd: &Cwd) -> Vec<String> {
    let mut out = Vec::new();
    for rs in raw_segs {
        let mut seg = rs.clone();
        while let Some(inner) = wrappers::argv_wrapper_inner(&seg) {
            seg = inner;
        }
        let seg = strip_redirs(&seg);
        let Some(first) = seg.first() else { continue };
        let (lang, file) = match interp::source(&seg) {
            Some((lang, interp::Source::File(f))) => (Some(lang), f),
            Some(_) => continue,
            None if first.contains('/') => (None, first.clone()),
            None => continue,
        };
        let scripts::Script::Text(text, canon) = scripts::read_script(&file, cwd_str(cwd), true)
        else {
            continue;
        };
        // Run as the command: the shebang names the interpreter.
        let lang = lang.or_else(|| {
            let line = text.lines().next()?.strip_prefix("#!")?;
            let mut words = line.split_whitespace();
            let mut prog = words.next()?;
            if pyfs::basename(prog) == "env" {
                prog = words.find(|w| !w.starts_with('-'))?;
            }
            interp::lang_of(prog)
        });
        let Some(lang) = lang else { continue };
        if scripts::enter(&canon) {
            out.extend(interp::code_commands(lang, &text));
            scripts::leave(&canon);
        }
    }
    out
}

/// The file a heredoc's command writes its body to: `cat > f <<EOF`, `cat <<EOF >> f`, `tee [-a] f <<EOF`.
fn heredoc_target(command: &str) -> Option<String> {
    let tokens = lex_lines(command).ok()?;
    let seg = raw_segments(&tokens).into_iter().next()?;
    if pyfs::basename(&seg[0]) == "tee" {
        let args = strip_redirs(&seg[1..]);
        return args.get(wrappers::skip_opts(&args, "", &[])).cloned();
    }
    let i = seg
        .iter()
        .position(|w| w == ">" || w == ">>" || w == ">|")?;
    seg.get(i + 1).cloned()
}

/// bash's control and redirection operators (and process substitution's `<(` / `>(`), longest first.
const OPERATORS: &[&str] = &[
    "<(", ">(", ";;&", "&>>", "<<<", "<<-", "&&", "||", ";;", ";&", "|&", ">>", ">|", ">&", "<&",
    "<<", "<>", "&>", ";", "&", "|", "(", ")", "!", "<", ">",
];

/// `shlex::split_lines`, then each run of punctuation the lexer kept as one token (`);`, `)&&`, `))|`) split into
/// bash's operators, as bash reads it: `x=$(date); sudo ls` is two commands. The Python guard's shlex (and the first
/// pass) read `);` as one word, so the command after it was an argument. A case arm's end (`;;`) reads as `;`.
/// Newline pass only.
fn lex_lines(text: &str) -> Result<Vec<String>, shlex::LexError> {
    let tokens = shlex::split_lines(text)?;
    let mut out = Vec::with_capacity(tokens.len());
    for t in tokens {
        if t.len() < 2
            || OPERATORS.contains(&t.as_str())
            || !t.chars().all(|c| ";&|()!<>".contains(c))
        {
            out.push(t);
            continue;
        }
        let mut rest = t.as_str();
        while !rest.is_empty() {
            let op = OPERATORS
                .iter()
                .find(|op| rest.starts_with(**op))
                .copied()
                .unwrap_or(&rest[..1]);
            out.push(op.to_string());
            rest = &rest[op.len()..];
        }
    }
    // A case arm's end (`;;`, `;&`, `;;&`) ends the command before it, as `;` does.
    for t in out.iter_mut() {
        if matches!(t.as_str(), ";;" | ";&" | ";;&") {
            *t = ";".to_string();
        }
    }
    Ok(out)
}

/// True if separator token `t` is a word of the test command being collected in `cur`: inside `[[ ... ]]`,
/// `&&`, `||`, `|`, `!`, `(` and `)` are its operators; in `[ ... ]` and `test ...`, `!`, `(` and `)` are (Rust only:
/// the Python guard split `[[ -f .env && -s .env ]]` and `[ ! -f .env ]` there and read the rest as a command).
fn test_word(cur: &[String], t: &str) -> bool {
    let Some(at) = cur
        .iter()
        .position(|w| !(contains(PREFIXES, w) || contains(KEYWORDS, w) || is_assignment(w)))
    else {
        return false;
    };
    let rest = &cur[at + 1..];
    match cur[at].as_str() {
        "[[" => !rest.iter().any(|w| w == "]]") && ["&&", "||", "|", "!", "(", ")"].contains(&t),
        "[" => !rest.iter().any(|w| w == "]") && ["!", "(", ")"].contains(&t),
        "test" => ["!", "(", ")"].contains(&t),
        _ => false,
    }
}

/// Split into simple commands: [verb, args...], skipping prefixes like `env`, `xargs`, keywords, VAR=value; each
/// with the separator that ended it (`;` for the last).
fn segments_with_seps(tokens: Vec<String>) -> Vec<(Vec<String>, String)> {
    split_simple(&tokens, true)
        .into_iter()
        .map(|s| (s.words, s.sep))
        .collect()
}

/// A simple command from `split_simple`: its words, the separator that ended it, and the value of a `HOME=` it was
/// run with (`HOME=/tmp/h bash -c ...`, `env HOME=/tmp/h bash x.sh`), as written.
struct Simple {
    words: Vec<String>,
    sep: String,
    home: Option<String>,
}

/// Split at separators and newlines (`;` ends the last), dropping leading keywords and assignments, and wrappers
/// too when `drop_wrappers` (`segments_with_seps`; `raw_segments` keeps them).
fn split_simple(tokens: &[String], drop_wrappers: bool) -> Vec<Simple> {
    let mut out = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    for t in tokens.iter().chain(std::iter::once(&";".to_string())) {
        // "\n": an unquoted newline (`shlex::split_lines`) ends a command as `;` does.
        if (contains(SEPARATORS, t) || t == "\n") && !test_word(&cur, t) {
            let home = home_prefix(&cur);
            let skip = cur
                .iter()
                .take_while(|w| {
                    (drop_wrappers && contains(PREFIXES, w))
                        || contains(KEYWORDS, w)
                        || is_assignment(w)
                })
                .count();
            cur.drain(..skip);
            if !cur.is_empty() {
                out.push(Simple {
                    words: std::mem::take(&mut cur),
                    sep: t.clone(),
                    home,
                });
            }
            cur.clear();
        } else {
            cur.push(t.clone());
        }
    }
    out
}

/// The value of the last `HOME=` among a simple command's leading keywords, assignments and wrappers (`env`, `nice`,
/// ...: `env HOME=x cmd`), as written.
fn home_prefix(words: &[String]) -> Option<String> {
    words
        .iter()
        .take_while(|w| contains(PREFIXES, w) || contains(KEYWORDS, w) || is_assignment(w))
        .filter_map(|w| w.strip_prefix("HOME="))
        .last()
        .map(str::to_string)
}

/// Whether `text` names the home: `$HOME`/`${HOME}`, and `~` at the start of a word.
fn names_home(text: &str) -> (bool, bool) {
    static VAR: LazyLock<Regex> = LazyLock::new(|| re(r"\$HOME\b|\$\{HOME\}"));
    static TILDE: LazyLock<Regex> = LazyLock::new(|| re(r#"(?:^|[\s=:;&|('"])~(?:/|$|\s)"#));
    (VAR.is_match(text), TILDE.is_match(text))
}

/// Whether string `s`, which `command` runs (`bash -c S`, `eval S`), may take the `HOME=` its simple command set.
/// Where `command`'s own shell expands `$HOME` or `~` in it, before the prefix applies (`HOME=/tmp/h bash -c "rm -rf
/// $HOME/x"`, `HOME=/tmp/h eval rm -rf ~/x`), they mean the real home. So `$HOME` must sit in single quotes and `~` in
/// quotes: `s` found inside such a span of `command`. Without either, it may.
fn home_applies(command: &str, s: &str) -> bool {
    let (var, tilde) = names_home(s);
    if !var && !tilde {
        return true;
    }
    let chars: Vec<char> = command.chars().collect();
    let (mut single, mut double) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            q @ ('\'' | '"') => {
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && chars[j] != q {
                    if q == '"' && chars[j] == '\\' {
                        j += 1;
                    }
                    j += 1;
                }
                let span: String = chars[start..j.min(chars.len())].iter().collect();
                if q == '\'' {
                    single.push(span);
                } else {
                    double.push(span);
                }
                i = j;
            }
            _ => {}
        }
        i += 1;
    }
    let inside = |spans: &[String]| spans.iter().any(|sp| sp.contains(s));
    if var {
        inside(&single)
    } else {
        inside(&single) || inside(&double)
    }
}

/// How a nested check gets its home (Rust only).
enum RunHome {
    /// Run with `HOME` set to this (resolved): `~` and `$HOME` in it mean it.
    Set(String),
    /// A wrapper's command line, rebuilt from its words (`timeout 9 bash -c ...`), which lost their quoting: its own
    /// words keep the home around them (that shell expanded them). What it runs takes `home` (or a `HOME=` among its
    /// words), judged against `command`, the text as first written.
    Rebuilt {
        home: Option<String>,
        command: String,
    },
}

thread_local! {
    /// Handed from a check to the one it starts on a rebuilt wrapper line: (inherited home, text as first written).
    static REBUILT: std::cell::RefCell<Option<(Option<String>, String)>> =
        const { std::cell::RefCell::new(None) };
}

/// The home a command run with `HOME=raw` sees, for `~` and `$HOME` in what it runs (Rust only): `raw` with a
/// leading `~`/`$HOME` or a variable the command sets resolved. A value built by a substitution (`$(mktemp -d)`)
/// can't be known here, so None: the real home stays, and a delete there stays blocked. A value naming a variable the
/// command doesn't set stays as written, read like any unknown variable (`rm -rf "$x/y"` isn't blocked either).
fn resolve_home(raw: &str) -> Option<String> {
    if raw.contains("$(") || raw.contains('`') || raw.contains("__substitution__") {
        return None;
    }
    let mut v = home_path(raw);
    if let Some(rest) = v.strip_prefix('$') {
        let (name, after) = match rest.strip_prefix('{') {
            Some(r) => match r.split_once('}') {
                Some((n, a)) => (n.to_string(), a.to_string()),
                None => (String::new(), String::new()),
            },
            None => {
                let end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                (rest[..end].to_string(), rest[end..].to_string())
            }
        };
        if let Some(val) = (!name.is_empty()).then(|| context::var(&name)).flatten() {
            v = home_path(&val) + &after;
        }
    }
    // `HOME=/` stays `/` (`rm -rf ~` is then `rm -rf /`); an empty HOME stays empty, as bash expands `~` then.
    let trimmed = v.trim_end_matches('/');
    Some(if trimmed.is_empty() && !v.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    })
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
/// True if a simple command runs its stdin as commands: a shell with no script (or `-s`, `/dev/stdin`), `source` or
/// `.` of `/dev/stdin`, also behind wrappers (`timeout 9 bash`, `ssh HOST`, `docker exec -i C sh`). Redirections
/// (`< file`, `> out`, `<<<`, `<<EOF`) are left out first.
fn runs_stdin(seg: &[String]) -> bool {
    let seg = strip_redirs(seg);
    !seg.is_empty() && (shell_runs_stdin(&seg) || wrappers::runs_stdin_through(&seg))
}

/// Redirection operators (`<`, `>`, `>>`, `<<<`, `<<`, `>&`, `&>`) and the word each takes.
fn strip_redirs(seg: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for w in seg {
        if skip {
            skip = false;
            continue;
        }
        if !w.is_empty() && w.chars().all(|c| "<>&".contains(c)) {
            skip = true;
            continue;
        }
        out.push(w.clone());
    }
    out
}

/// Simple commands as written: split at separators and newlines, leading keywords and assignments dropped, but
/// wrappers (`env`, `nice`, `xargs`) kept with their options, unlike `segments_with_seps`.
fn raw_segments(tokens: &[String]) -> Vec<Vec<String>> {
    split_simple(tokens, false)
        .into_iter()
        .map(|s| s.words)
        .collect()
}

fn shell_runs_stdin(seg: &[String]) -> bool {
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
    let mut out = Vec::new();
    for (i, (seg, sep)) in segs.iter().enumerate() {
        if sep != "|" {
            continue;
        }
        let Some(lines) = printed_lines(seg) else {
            continue;
        };
        // Through filters (`echo ls | sed 's/^/sudo /' | bash`) to a shell that runs its stdin; sed `e` and awk
        // `system` on the way run commands themselves.
        let mut chain: Vec<Vec<String>> = Vec::new();
        for (next, next_sep) in &segs[i + 1..] {
            out.extend(filters::executed(next, Some(&lines.join("\n"))));
            if runs_stdin(next) {
                for text in filters::outputs(&chain, &lines.join("\n")) {
                    out.extend(
                        text.split('\n')
                            .filter(|l| !l.trim().is_empty())
                            .map(str::to_string),
                    );
                }
                break;
            }
            if next_sep != "|" {
                break;
            }
            chain.push(next.clone());
        }
    }
    out.dedup();
    out
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

/// True for a redirection operator token (`>`, `>>`, `>|`, `<`, `&>`, `&>>`, `>&`, `<&`): the next token is the file
/// or descriptor it redirects to. `2>` lexes as `2` then `>`.
fn is_redirect_op(t: &str) -> bool {
    matches!(
        t,
        ">" | ">>" | ">|" | "<" | "&>" | "&>>" | ">&" | "<&" | "<>"
    )
}

/// arg with a leading ~, $HOME or ${HOME} replaced by the home folder; other args unchanged.
fn home_path(arg: &str) -> String {
    for start in ["~", "$HOME", "${HOME}"] {
        if arg == start || arg.starts_with(&format!("{start}/")) {
            // The `HOME=` the command around this one ran it with (Rust only), else the real home.
            return context::home().unwrap_or_else(home) + &arg[start.len()..];
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
        // A here-string fed through a wrapper that hands stdin to a shell (`ssh HOST <<< STRING`).
        if runs_stdin(seg) {
            for w in seg.windows(2) {
                if w[0] == "<<<" {
                    out.push(w[1].clone());
                }
            }
        }
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
fn pip_in_nested(command: &str, cwd: &Cwd, depth: usize) -> bool {
    pip_in_nested_mode(command, cwd, depth, true)
}

fn pip_in_nested_mode(command: &str, cwd: &Cwd, depth: usize, expand: bool) -> bool {
    if depth > MAX_DEPTH {
        return false; // check() already crashed (blocked) at this depth
    }
    let _frame = context::push(command, cwd_str(cwd));
    let (command, bodies, mut written) = split_heredocs(command, true);
    context::add_written(&written);
    if bodies.iter().any(|b| pip_in_nested(b, cwd, depth + 1)) {
        return true;
    }
    // Its substitutions as single words (as check_mode does).
    if let Some(flat) = flatten_substitutions(&command) {
        if pip_in_nested_mode(&flat, cwd, depth + 1, expand) {
            return true;
        }
    }
    let Ok(raw) = lex_lines(&command) else {
        return false;
    };
    // Variables set in the command, once (as check_mode does).
    if expand {
        if let Some(x) = expand_vars(&command, &raw) {
            if PIP.is_match(&x) || pip_in_nested_mode(&x, cwd, depth + 1, false) {
                return true;
            }
        }
    }
    let raw_segs = raw_segments(&raw);
    for rs in &raw_segs {
        if let Some(w) = printed_to_file(rs) {
            context::add_written(&[w]);
        }
    }
    let mut more: Vec<String> = raw_segs
        .iter()
        .flat_map(|s| wrappers::wrapped_commands(s))
        .collect();
    // pip doesn't depend on HOME: no homes.
    more.extend(
        scripts_run(&raw_segs, &[], &mut written)
            .into_iter()
            .map(|(s, _)| s),
    );
    more.extend(substitutions(&command));
    more.extend(interp_file_commands(&raw_segs, cwd));
    let segs = segments_with_seps(raw);
    let disk = files_run(&raw_segs, &[], &segs, &[], &written);
    // Each simple command with its keywords, wrappers and assignments dropped (`then pip install`, `X=1 pip
    // install`, `{ pip install`): block-pip's pattern only matched at a line start or after ; & |.
    if segs.iter().any(|(s, _)| PIP.is_match(&s.join(" "))) {
        return true;
    }
    if segs
        .iter()
        .flat_map(|(s, _)| nested_commands(s))
        .chain(piped_scripts(&segs))
        .chain(more)
        .any(|inner| PIP.is_match(&inner) || pip_in_nested(&inner, cwd, depth + 1))
    {
        return true;
    }
    disk.iter().any(|(file, explicit, chain, _)| {
        let scripts::Script::Text(text, canon) =
            scripts::read_script(file, cwd_str(cwd), *explicit)
        else {
            return false;
        };
        if !scripts::enter(&canon) {
            return false;
        }
        let hit = filters::outputs(chain, &text)
            .iter()
            .any(|t| PIP.is_match(t) || pip_in_nested(t, cwd, depth + 1));
        scripts::leave(&canon);
        hit
    })
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

/// `echo ... > FILE` / `printf ... >> FILE`: (FILE, the lines written).
fn printed_to_file(seg: &[String]) -> Option<(String, String)> {
    let i = seg
        .iter()
        .position(|w| w == ">" || w == ">>" || w == ">|")?;
    let file = seg.get(i + 1)?.clone();
    let words = strip_redirs(seg);
    if words.is_empty() {
        return None; // only a redirection: `> file`
    }
    let text = printed_lines(&words)?.join("\n");
    Some((file, text))
}

/// The script file a simple command runs: `bash FILE`, `sh -x FILE`, `source FILE`, `. FILE`, `./FILE` or
/// `/path/FILE` as the verb, also behind argv wrappers (`timeout 9 bash FILE`).
fn runs_file(seg: &[String]) -> Option<(String, bool)> {
    let mut seg = seg.to_vec();
    while let Some(inner) = wrappers::argv_wrapper_inner(&seg) {
        seg = inner;
    }
    let seg = strip_redirs(&seg);
    let verb = pyfs::basename(seg.first()?);
    if contains(C_SHELLS, verb) {
        let args = &seg[1..];
        // `-c` runs a string, not the file; `-n` only reads it for syntax errors.
        if args
            .iter()
            .any(|a| !a.starts_with("--") && dash_letters_contain(a, &['c', 'n']))
        {
            return None;
        }
        return args
            .iter()
            .find(|a| !a.starts_with('-'))
            .map(|a| (a.clone(), true));
    }
    if verb == "source" || verb == "." {
        return seg.get(1).map(|a| (a.clone(), true));
    }
    seg[0].contains('/').then(|| (seg[0].clone(), false))
}

/// Bodies of scripts written in this command (heredocs in `written`, plus `echo`/`printf` to a file) that a later
/// simple command runs.
/// Each with the `HOME=` its simple command ran it with (`homes`, one per simple command; empty: none).
fn scripts_run(
    raw_segs: &[Vec<String>],
    homes: &[Option<String>],
    written: &mut Vec<(String, String)>,
) -> Vec<(String, Option<String>)> {
    for rs in raw_segs {
        if let Some(w) = printed_to_file(rs) {
            written.push(w);
        }
    }
    let mut out = Vec::new();
    for (i, rs) in raw_segs.iter().enumerate() {
        if let Some((f, _)) = runs_file(rs) {
            for (w, body) in written.iter() {
                if same_path(w, &f) {
                    out.push((body.clone(), homes.get(i).cloned().flatten()));
                }
            }
        }
    }
    out
}

/// Script files on disk a command runs: (path as written, fed to a shell explicitly). `bash FILE`, `source FILE`,
/// `./FILE` (`runs_file`), `cat FILE... | bash`, `bash < FILE`; files written in the same command are left to
/// `scripts_run`.
/// (path as written, fed to a shell explicitly, filters on the way: `cat x | sed ... | bash`)
/// And the `HOME=` the simple command that runs it set (`HOME=/tmp/h bash x.sh`), as written.
type FileRun = (String, bool, Vec<Vec<String>>, Option<String>);

fn files_run(
    raw_segs: &[Vec<String>],
    raw_homes: &[Option<String>],
    segs: &[(Vec<String>, String)],
    seg_homes: &[Option<String>],
    written: &[(String, String)],
) -> Vec<FileRun> {
    let home = |homes: &[Option<String>], i: usize| homes.get(i).cloned().flatten();
    let mut out: Vec<FileRun> = raw_segs
        .iter()
        .enumerate()
        .filter_map(|(i, s)| runs_file(s).map(|(f, e)| (f, e, Vec::new(), home(raw_homes, i))))
        .collect();
    // `cat FILE | [filters |] bash`.
    for (i, (seg, sep)) in segs.iter().enumerate() {
        if sep != "|" || pyfs::basename(&seg[0]) != "cat" {
            continue;
        }
        let mut chain: Vec<Vec<String>> = Vec::new();
        for (k, (next, next_sep)) in segs[i + 1..].iter().enumerate() {
            if runs_stdin(next) {
                let h = home(seg_homes, i + 1 + k);
                out.extend(
                    strip_redirs(&seg[1..])
                        .into_iter()
                        .filter(|a| !a.starts_with('-'))
                        .map(|a| (a, true, chain.clone(), h.clone())),
                );
                break;
            }
            if next_sep != "|" {
                break;
            }
            chain.push(next.clone());
        }
    }
    for (k, rs) in raw_segs.iter().enumerate() {
        if let Some(i) = rs.iter().position(|w| w == "<") {
            if runs_stdin(rs) {
                if let Some(f) = rs.get(i + 1) {
                    out.push((f.clone(), true, Vec::new(), home(raw_homes, k)));
                }
            }
        }
    }
    out.retain(|(f, ..)| !written.iter().any(|(w, _)| same_path(w, f)));
    out
}

fn cwd_str(cwd: &Cwd) -> Option<&str> {
    match cwd {
        Cwd::Path(c) => Some(c.as_str()),
        _ => None,
    }
}

fn same_path(a: &str, b: &str) -> bool {
    a.trim_start_matches("./") == b.trim_start_matches("./")
}

/// The command with the values of variables it assigns (`NAME=value` in command position, also after export,
/// local, declare, readonly, typeset) put in for `$NAME` and `${NAME}`; None if nothing changes.
fn expand_vars(command: &str, tokens: &[String]) -> Option<String> {
    const DECLARE: &[&str] = &["export", "local", "declare", "readonly", "typeset"];
    let mut vars: Vec<(String, String)> = Vec::new();
    let mut at_cmd = true;
    let mut after_declare = false;
    let mut skip = 0;
    for (k, t) in tokens.iter().enumerate() {
        if skip > 0 {
            skip -= 1;
            continue;
        }
        // `for NAME in WORDS` (also select): NAME takes the word the body would read, so `for f in .env; do cat
        // "$f"; done` reads .env. The first word that names a secrets file or holds a glob, else the first word;
        // a `$VAR` word the command set earlier is expanded first (Rust only).
        if at_cmd && (t == "for" || t == "select") && tokens.get(k + 2).is_some_and(|w| w == "in") {
            let name = &tokens[k + 1];
            let words: Vec<String> = tokens[k + 3..]
                .iter()
                .take_while(|w| !(contains(SEPARATORS, w) || *w == "\n" || *w == "do"))
                .flat_map(|w| {
                    let var = w
                        .strip_prefix("${")
                        .and_then(|r| r.strip_suffix('}'))
                        .or_else(|| w.strip_prefix('$'));
                    match var.and_then(|v| vars.iter().find(|(n, _)| n == v)) {
                        Some((_, val)) => val.split_whitespace().map(str::to_string).collect(),
                        None => vec![w.clone()],
                    }
                })
                .collect();
            skip = 2 + tokens[k + 3..]
                .iter()
                .take_while(|w| !(contains(SEPARATORS, w) || *w == "\n" || *w == "do"))
                .count();
            if is_assignment(&format!("{name}=")) {
                if let Some(v) = words
                    .iter()
                    .find(|w| is_secret_env(w) || w.contains(['*', '?', '[']))
                    .or(words.first())
                {
                    vars.retain(|(n, _)| n != name);
                    vars.push((name.clone(), v.clone()));
                }
            }
            at_cmd = false;
            continue;
        }
        if contains(SEPARATORS, t) || t == "\n" {
            at_cmd = true;
            after_declare = false;
            continue;
        }
        if at_cmd && (contains(KEYWORDS, t) || contains(DECLARE, t)) {
            after_declare = contains(DECLARE, t);
            continue;
        }
        if at_cmd && after_declare && t.starts_with('-') {
            continue;
        }
        if at_cmd && is_assignment(t) {
            if let Some((name, value)) = t.split_once('=') {
                vars.retain(|(k, _)| k != name);
                vars.push((name.to_string(), value.to_string()));
            }
            continue;
        }
        at_cmd = false;
    }
    if vars.is_empty() {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' {
            let (name, end) = if chars.get(i + 1) == Some(&'{') {
                let close = (i + 2..chars.len()).find(|&k| chars[k] == '}');
                match close {
                    Some(c) => (chars[i + 2..c].iter().collect::<String>(), c + 1),
                    None => (String::new(), i + 1),
                }
            } else {
                let e = (i + 1..chars.len())
                    .find(|&k| !ident(chars[k]))
                    .unwrap_or(chars.len());
                (chars[i + 1..e].iter().collect::<String>(), e)
            };
            if let Some((_, v)) = vars.iter().find(|(k, _)| *k == name) {
                out.push_str(v);
                i = end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    (out != command).then_some(out)
}

/// The bodies of `$(...)` and backtick substitutions, also inside double quotes, where the lexer reads
/// `"$(cat .env)"` as one word (the Python guard never checked them). Single quotes, `$'...'` and comments hold none.
fn substitutions(command: &str) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    let mut out: Vec<String> = substitution_spans(&chars)
        .into_iter()
        .map(|s| chars[s.body.clone()].iter().collect())
        .collect();
    out.retain(|b: &String| !b.trim().is_empty());
    out.dedup();
    out
}

/// The command with each outermost substitution (`$(...)`, backticks) replaced by one placeholder word, or None
/// when it has none. The lexers read an unquoted `$(` ... `)` as words and operators, so the simple command around
/// it ended at the `)`: `cat $(true) .env` and `rm -rf $(true) /srv/x` left their last arguments unchecked (in the
/// Python guard too). Its bodies are checked on their own (`substitutions`). A body that only prints words
/// (`printed_words`) is replaced by them instead. Newline pass only.
fn flatten_substitutions(command: &str) -> Option<String> {
    let chars: Vec<char> = command.chars().collect();
    let spans = substitution_spans(&chars);
    if spans.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(command.len());
    let mut at = 0;
    for s in spans {
        out.extend(&chars[at..s.whole.start]);
        let body: String = chars[s.body.clone()].iter().collect();
        match printed_words(&body) {
            Some(words) => out.push_str(&words),
            None => out.push_str("__substitution__"),
        }
        at = s.whole.end;
    }
    out.extend(&chars[at..]);
    Some(out)
}

/// Where an outermost substitution sits: the whole `$(...)` or `` `...` ``, and its body (char indices).
struct SubSpan {
    whole: std::ops::Range<usize>,
    body: std::ops::Range<usize>,
}

/// The outermost substitutions in `chars`, in order (see `substitutions`). An unclosed one is left out.
fn substitution_spans(chars: &[char]) -> Vec<SubSpan> {
    #[derive(Clone, Copy, PartialEq)]
    enum F {
        Code,
        /// Start, open `(` count, open `case` count.
        Sub(usize, u32, u32),
        Tick(usize),
        Single,
        Double,
        AnsiC,
    }
    // Only the outermost substitutions: checking one finds those nested in it, so returning every level would check
    // each nested body once per level around it (work doubling per level).
    let outermost = |stack: &[F]| !stack.iter().any(|f| matches!(f, F::Sub(..) | F::Tick(_)));
    let mut stack = vec![F::Code];
    let mut out: Vec<SubSpan> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match *stack.last().unwrap_or(&F::Code) {
            F::Single => {
                if c == '\'' {
                    stack.pop();
                }
            }
            F::AnsiC => {
                if c == '\\' {
                    i += 1;
                } else if c == '\'' {
                    stack.pop();
                }
            }
            F::Double => {
                if c == '\\' {
                    i += 1;
                } else if c == '"' {
                    stack.pop();
                } else if c == '$' && next == Some('(') {
                    stack.push(F::Sub(i + 2, 0, 0));
                    i += 1;
                } else if c == '`' {
                    stack.push(F::Tick(i + 1));
                }
            }
            top => {
                let word_start =
                    i == 0 || chars[i - 1].is_whitespace() || ";&|()<>".contains(chars[i - 1]);
                match c {
                    '\\' => i += 1,
                    '#' if word_start => {
                        while i < chars.len() && chars[i] != '\n' {
                            i += 1;
                        }
                        continue;
                    }
                    '\'' => stack.push(F::Single),
                    '"' => stack.push(F::Double),
                    '$' if next == Some('\'') => {
                        stack.push(F::AnsiC);
                        i += 1;
                    }
                    '$' if next == Some('(') => {
                        stack.push(F::Sub(i + 2, 0, 0));
                        i += 1;
                    }
                    '`' => {
                        if let F::Tick(start) = top {
                            stack.pop();
                            if outermost(&stack) {
                                out.push(SubSpan {
                                    whole: start - 1..i + 1,
                                    body: start..i,
                                });
                            }
                        } else {
                            stack.push(F::Tick(i + 1));
                        }
                    }
                    '(' => {
                        if let Some(F::Sub(_, depth, _)) = stack.last_mut() {
                            *depth += 1;
                        }
                    }
                    ')' => match stack.last_mut() {
                        Some(F::Sub(_, depth, _)) if *depth > 0 => *depth -= 1,
                        // A case pattern's `)` (`$(case $x in a) ...;; esac)`), not the end of the substitution.
                        Some(F::Sub(_, _, cases)) if *cases > 0 => {}
                        Some(F::Sub(start, _, _)) => {
                            let start = *start;
                            stack.pop();
                            if outermost(&stack) {
                                out.push(SubSpan {
                                    whole: start - 2..i + 1,
                                    body: start..i,
                                });
                            }
                        }
                        _ => {}
                    },
                    c if c.is_ascii_alphabetic()
                        && (i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_')) =>
                    {
                        // `case` and `esac` words inside a `$(...)`: a pattern's `)` doesn't close it.
                        let end = (i..chars.len())
                            .find(|&k| !(chars[k].is_alphanumeric() || chars[k] == '_'))
                            .unwrap_or(chars.len());
                        let word: String = chars[i..end].iter().collect();
                        if let Some(F::Sub(_, _, cases)) = stack.last_mut() {
                            if word == "case" {
                                *cases += 1;
                            } else if word == "esac" && *cases > 0 {
                                *cases -= 1;
                            }
                        }
                        i = end;
                        continue;
                    }
                    _ => {}
                }
            }
        }
        i += 1;
    }
    out
}

/// The reason to block `command`, if any. Err is a crash (blocks).
///
/// Two passes over the whole command: first reading a newline as a space, as the Python guard did, so a command it
/// blocked keeps its reason; then, if that passed, with newlines as separators. Each pass recurses in its own mode,
/// and a work budget (`MAX_CHECKS`) bounds the whole check.
pub fn check(command: &str, cwd: &Cwd, depth: usize) -> Result<Option<String>, Crash> {
    if depth == 0 {
        CHECKS.with(|c| c.set(0));
    }
    if let Some(r) = check_mode(command, cwd, depth, false, true)? {
        return Ok(Some(r));
    }
    check_mode(command, cwd, depth, true, true)
}

fn check_mode(
    command: &str,
    cwd: &Cwd,
    depth: usize,
    lines: bool,
    expand: bool,
) -> Result<Option<String>, Crash> {
    // Set when this check runs a rebuilt wrapper line (`RunHome::Rebuilt`); taken first, so it reaches this check only.
    let rebuilt = REBUILT.with(|r| r.borrow_mut().take());
    if depth > MAX_DEPTH {
        return Err(Crash(
            "RecursionError: maximum recursion depth exceeded".into(),
        ));
    }
    // A work budget for the whole check, so no input can make it slow enough for the hook to time out (a timed-out
    // hook doesn't block).
    let checks = CHECKS.with(|c| {
        c.set(c.get() + 1);
        c.get()
    });
    if checks > MAX_CHECKS {
        return Ok(Some(format!(
            "the command holds more nested commands, strings and scripts than the guard checks ({MAX_CHECKS}). Run it yourself with ! after reading it."
        )));
    }
    // What interpreter code in this command can read: its variables, the cwd, files it writes.
    let _frame = context::push(command, cwd_str(cwd));
    let (command, shell_bodies, mut written) = split_heredocs(command, lines);
    context::add_written(&written);
    for body in shell_bodies {
        if let Some(r) = check_mode(&body, cwd, depth + 1, lines, true)? {
            return Ok(Some(r));
        }
    }
    let lexed = if lines {
        lex_lines(&command)
    } else {
        shlex::split_python(&command)
    };
    let Ok(raw) = lexed else {
        return Ok(None);
    };
    // Strings run as commands (`bash -c`, eval, here-strings, `source <(echo ...)`, `echo ... | bash`), checked
    // with every rule once the whole command has passed: a command the Python guard blocked keeps its verdict and
    // reason.
    let raw_segs = raw_segments(&raw);
    // Variables set in the command (`c='sudo ls'; bash -c "$c"`): the command once more with their values in,
    // checked without expanding again (newline pass).
    let expanded = if lines && expand {
        expand_vars(&command, &raw)
    } else {
        None
    };
    // The `HOME=` each simple command runs what it runs with (`HOME=/tmp/h bash -c ...`; Rust only), per raw
    // segment and per segment.
    let raw_homes: Vec<Option<String>> = split_simple(&raw, false)
        .into_iter()
        .map(|s| s.home)
        .collect();
    let seg_homes: Vec<Option<String>> = split_simple(&raw, true)
        .into_iter()
        .map(|s| s.home)
        .collect();
    let segs = segments_with_seps(raw);
    // The home what a simple command runs takes: its own `HOME=` (resolved here), else the one a rebuilt wrapper line
    // inherited; and the text that tells where this shell expanded `$HOME` and `~` first (`home_applies`).
    let home_of = |raw_home: Option<String>| -> Option<String> {
        match raw_home {
            Some(r) => resolve_home(&r),
            None => rebuilt.as_ref().and_then(|(h, _)| h.clone()),
        }
    };
    let judged_by: String = rebuilt
        .as_ref()
        .map(|(_, c)| c.clone())
        .unwrap_or_else(|| command.clone());
    // A string from this command takes the home only where this shell left `$HOME` and `~` in it alone.
    let in_command = |s: String, raw_home: Option<String>| {
        let h = home_of(raw_home)
            .filter(|_| home_applies(&judged_by, &s))
            .map(RunHome::Set);
        (s, h)
    };
    let mut nested: Vec<(String, Option<RunHome>)> = piped_scripts(&segs)
        .into_iter()
        .map(|s| (s, None))
        .collect();
    // `$(...)` and backticks, also inside double quotes (`echo "$(cat .env)"`). They run before a `HOME=` prefix
    // applies.
    nested.extend(substitutions(&command).into_iter().map(|s| (s, None)));
    // Files echo/printf write, for interpreter code that reads them later in the command.
    for rs in &raw_segs {
        if let Some(w) = printed_to_file(rs) {
            context::add_written(&[w]);
        }
    }
    // What wrappers run: `timeout 9 CMD`, `ssh HOST CMD`, `docker exec C CMD`, `su -c STRING`, `find -exec CMD`.
    for (i, rs) in raw_segs.iter().enumerate() {
        let h = home_of(raw_homes.get(i).cloned().flatten());
        nested.extend(wrappers::wrapped_commands(rs).into_iter().map(|s| {
            let r = RunHome::Rebuilt {
                home: h.clone(),
                command: judged_by.clone(),
            };
            (s, Some(r))
        }));
    }
    // Scripts written and run in the same command (newline pass): `cat > run.sh <<EOF ...; bash run.sh`,
    // `echo '...' > run.sh && ./run.sh`.
    let mut disk: Vec<FileRun> = Vec::new();
    if lines {
        // A script written in this command may hold this shell's expansion of `$HOME` or `~` (an unquoted heredoc,
        // `printf ~/x`): the home only applies when it names neither.
        nested.extend(
            scripts_run(&raw_segs, &raw_homes, &mut written)
                .into_iter()
                .map(|(s, h)| {
                    let h = home_of(h)
                        .filter(|_| names_home(&s) == (false, false))
                        .map(RunHome::Set);
                    (s, h)
                }),
        );
        // Script files on disk it runs (`bash scripts/x.sh`, `cat x | bash`), checked last. Their text is the
        // running shell's to expand.
        disk = files_run(&raw_segs, &raw_homes, &segs, &seg_homes, &written)
            .into_iter()
            .map(|(f, e, c, h)| (f, e, c, home_of(h)))
            .collect();
        // Interpreter scripts on disk (`python3 x.py`, `node x.js`, `./x.rb`): the commands their code runs.
        for (i, rs) in raw_segs.iter().enumerate() {
            let h = home_of(raw_homes.get(i).cloned().flatten());
            nested.extend(
                interp_file_commands(std::slice::from_ref(rs), cwd)
                    .into_iter()
                    .map(|s| (s, h.clone().map(RunHome::Set))),
            );
        }
    }
    for (k, (seg, _)) in segs.into_iter().enumerate() {
        let h = seg_homes.get(k).cloned().flatten();
        nested.extend(
            nested_commands(&seg)
                .into_iter()
                .map(|s| in_command(s, h.clone())),
        );
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
                for (i, a) in args.iter().enumerate() {
                    // A redirect's target (`2>/dev/null`, `> out.log`) is a file the shell opens, not one rm
                    // deletes (Rust only: the Python guard listed it as a path).
                    if i > 0 && is_redirect_op(&args[i - 1]) {
                        continue;
                    }
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
        // `case WORD in PATTERN)`: the word and patterns are matched as text, not read; `for NAME in WORDS` (and
        // select) only names them, and what the body does with NAME is checked through `expand_vars` (Rust only).
        if !contains(ENV_SAFE_VERBS, &verb) && !matches!(verb.as_str(), "case" | "for" | "select") {
            let mut written: HashSet<usize> = args
                .iter()
                .enumerate()
                .filter(|(_, a)| contains(WRITE_REDIRECTS, a))
                .map(|(i, _)| i + 1)
                .collect();
            if let Some(f) = jq_filter_index(&verb, args) {
                written.insert(f);
            }
            // Search patterns (`rg 'process\.env' src`) aren't files (Rust only).
            written.extend(search_pattern_indices(&verb, args));
            // The first pass reads a case arm's end (`;;`) as a word: what follows it, up to the `)`, is the next
            // arm's pattern (Rust only).
            if let Some(end) = args
                .iter()
                .position(|a| matches!(a.as_str(), ";;" | ";&" | ";;&"))
            {
                written.extend(end..args.len());
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
    for (inner, home) in nested {
        // `~` and `$HOME` in it mean the home its simple command set; a rebuilt wrapper line hands it on.
        let _home = match home {
            Some(RunHome::Set(h)) => Some(context::push_home(h)),
            Some(RunHome::Rebuilt { home, command }) => {
                REBUILT.with(|r| *r.borrow_mut() = Some((home, command)));
                None
            }
            None => None,
        };
        if let Some(r) = check_mode(&inner, cwd, depth + 1, lines, true)? {
            return Ok(Some(r));
        }
    }
    if let Some(x) = expanded {
        if let Some(r) = check_mode(&x, cwd, depth + 1, lines, false)? {
            return Ok(Some(r));
        }
    }
    // The command with its substitutions as single words, so the words after one stay in its simple command
    // (`cat $(true) .env`). Rust only.
    if lines {
        if let Some(flat) = flatten_substitutions(&command) {
            if let Some(r) = check_mode(&flat, cwd, depth + 1, lines, expand)? {
                return Ok(Some(r));
            }
        }
    }
    for (file, explicit, chain, home) in disk {
        let _home = home.map(context::push_home);
        match scripts::read_script(&file, cwd_str(cwd), explicit) {
            scripts::Script::Text(text, canon) => {
                if !scripts::enter(&canon) {
                    continue; // already being checked
                }
                let mut r = Ok(None);
                for t in filters::outputs(&chain, &text) {
                    r = check_mode(&t, cwd, depth + 1, lines, true);
                    if !matches!(r, Ok(None)) {
                        break;
                    }
                }
                scripts::leave(&canon);
                if let Some(r) = r? {
                    return Ok(Some(r));
                }
            }
            scripts::Script::TooBig(f) => return Ok(Some(scripts::too_big_reason(&f))),
            scripts::Script::Skip => {}
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
        if PIP.is_match(c) || pip_in_nested(c, &cwd, 0) {
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
