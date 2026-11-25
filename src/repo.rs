//! `claude-guard repo pre-bash`: per-repo PreToolUse Bash guards. The code is generic; everything a repo names
//! (messages, the guard module, where errors are logged) comes from that repo's `.claude/repo-guard.json`, found
//! through `CLAUDE_PROJECT_DIR`.
//!
//! Two rule sets, each on when its config section is there, both run on every call (as the two Python hooks they
//! replace ran side by side; a block from the first, in this order, is the one shown):
//!
//! 1. The Logs Insights cost guard (`pre_bash.logs_insights`), ported from a repo's Python hook that blocks
//! - a raw `aws ... logs ... start-query` the command runs itself (also through `bash -c`, a heredoc fed to a
//!   shell, `$(...)` and backticks, three levels deep), and
//! - Python that starts a query without the repo's guard module: a `.py` file the command runs (found where it
//!   runs: after a `cd`, with `~` and `$VAR` expanded) or inline Python (`-c`, a heredoc).
//! 2. The shared-working-tree guard (`pre_bash.git` and its sibling sections): `repo_tree.rs`.
//!
//! Failure behaviour (written here on purpose; see the porting rules):
//! - Unreadable hook input and any internal error let the command through and append one line per rule set to the
//!   repo's error log, exactly where the Python hooks let it through (`Decision::crashes`). `FAIL_CLOSED` turns internal errors into blocks;
//!   it stays off until the shadow week shows Rust and Python agree.
//! - A missing or invalid config lets the command through with a `systemMessage` warning: the guard is off, and
//!   the session should know.
//! - Recursion is capped (three levels, as in Python), and `decide` runs under `catch_unwind`.
//!
//! Overrides are arguments: `--crash-log F` (tests) replaces the config's error log.

use crate::hookio::{self, py_truthy};
use crate::repo_tree::{Guard, TreeConfig};
use crate::shell_words::{heredoc_marks, py_split};
use crate::{logfile, pyfs, pyre::PyText, shlex};
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

/// Internal errors block once this is on (after the shadow week); until then they allow, as the Python hook did.
const FAIL_CLOSED: bool = false;
/// Python's error log cap (256 KiB, then one `.1`).
const LOG_CAP: u64 = 256 * 1024;
/// `MAX_READ`: characters of a script read.
const MAX_READ: usize = 2 * 1024 * 1024;
const SHELLS: &[&str] = &["bash", "sh", "zsh"];
const SEPARATORS: &[&str] = &[";", "&&", "||", "|", "&", "(", ")", "|&", "`"];
/// Python's `punctuation_chars=True`.
const PUNCT: &str = "();<>|&";
const PATH_PUNCT: &str = "();<>|&\n";

static QUERY_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["']start-query["']|\.start_query\s*\("#).unwrap());
static SHELL_CMD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"aws\s+(?:\S+\s+)*?logs\s+start-query").unwrap());
static SHELL_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\(").unwrap());
static PYTHON: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|[\s;&|(/])(python[0-9.]*|uv run)\b").unwrap());
static INLINE_C: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s-c\s").unwrap());
static PATH_VAR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))").unwrap()
});
static ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=").unwrap());

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block {
        message: String,
        rule: String,
    },
    /// No usable config: allowed, with this warning.
    NoConfig(String),
}

/// A verdict, the internal errors met on the way (one per rule set that raised where its Python hook did; for the
/// error log only) and where to log them.
#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub crashes: Vec<String>,
    pub log: Option<String>,
}

impl Decision {
    /// The rule id for logs: the block's rule, "crash" for an allow after an internal error, else "allow".
    pub fn rule(&self) -> String {
        match &self.verdict {
            Verdict::Block { rule, .. } => rule.clone(),
            Verdict::NoConfig(_) => "no-config".into(),
            Verdict::Allow if !self.crashes.is_empty() => "crash".into(),
            Verdict::Allow => "allow".into(),
        }
    }

    /// (exit code, stderr) as `emit` would give them.
    pub fn outcome(&self) -> (i32, String) {
        match &self.verdict {
            Verdict::Block { message, .. } => (2, format!("{message}\n")),
            _ if FAIL_CLOSED && !self.crashes.is_empty() => (2, crash_block(&self.crashes[0])),
            _ => (0, String::new()),
        }
    }
}

fn crash_block(e: &str) -> String {
    format!(
        "claude-guard repo pre-bash failed, so the command is blocked: {}\n",
        e.lines().next().unwrap_or("")
    )
}

/// `.claude/repo-guard.json`: the error log and the rule sets it turns on.
#[derive(Debug, Clone)]
pub struct Config {
    pub error_log: String,
    pub logs: Option<LogsConfig>,
    pub tree: Option<TreeConfig>,
}

/// `pre_bash.logs_insights`.
#[derive(Debug, Clone)]
pub struct LogsConfig {
    pub guard_module: String,
    pub raw_cli_reason: String,
    pub script_reason: String,
    pub inline_reason: String,
    pub block_message: String,
}

fn field<'v>(v: &'v Value, path: &[&str]) -> Result<&'v str, String> {
    let mut cur = v;
    for k in path {
        cur = cur
            .get(k)
            .ok_or_else(|| format!("{} is missing", path.join(".")))?;
    }
    cur.as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{} is not a non-empty string", path.join(".")))
}

impl Config {
    /// `<project>/.claude/repo-guard.json`, version 1.
    pub fn load(project: &str) -> Result<Config, String> {
        let path = format!("{}/.claude/repo-guard.json", project.trim_end_matches('/'));
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
        if v.get("version").and_then(Value::as_i64) != Some(1) {
            return Err(format!("{path}: version is not 1"));
        }
        let li = ["pre_bash", "logs_insights"];
        let at = |k: &str| field(&v, &[li[0], li[1], k]).map(str::to_string);
        let error_log = field(&v, &["error_log"])?;
        let logs = match v.get(li[0]).and_then(|p| p.get(li[1])) {
            None => None,
            Some(_) => Some(LogsConfig {
                guard_module: at("guard_module")?,
                raw_cli_reason: at("raw_cli_reason")?,
                script_reason: at("script_reason")?,
                inline_reason: at("inline_reason")?,
                block_message: at("block_message")?,
            }),
        };
        let tree = TreeConfig::load(&v).map_err(|e| format!("{path}: {e}"))?;
        if logs.is_none() && tree.is_none() {
            return Err(format!(
                "{path}: no rules (pre_bash.logs_insights or pre_bash.git)"
            ));
        }
        Ok(Config {
            error_log: if error_log.starts_with('/') {
                error_log.to_string()
            } else {
                format!("{project}/{error_log}")
            },
            logs,
            tree,
        })
    }
}

// ------------------------------------------------------------------ shell words, as the Python hook splits them

/// `words()`: shlex with `punctuation_chars=True`, no comments; `str.split()` on a ValueError.
fn words(command: &str) -> Vec<String> {
    shlex::split_with(command, PUNCT, " \t\r\n").unwrap_or_else(|_| py_split(command))
}

fn is_sep(w: &str) -> bool {
    SEPARATORS.contains(&w)
}

/// `first_program(text)`: the program of the last command in `text`, env assignments skipped.
fn first_program(text: &str) -> String {
    let mut seg = words(text);
    while seg.last().is_some_and(|w| is_sep(w)) {
        seg.pop();
    }
    let cut = seg
        .iter()
        .rposition(|w| is_sep(w))
        .map(|i| i + 1)
        .unwrap_or(0);
    seg[cut..]
        .iter()
        .find(|w| !ASSIGNMENT.is_match(w))
        .map(|w| pyfs::basename(w).to_string())
        .unwrap_or_default()
}

/// `split_heredocs(command)`: the command without heredoc bodies, and the bodies fed to a shell.
fn split_heredocs(command: &str) -> (String, Vec<String>) {
    let mut kept: Vec<&str> = Vec::new();
    let mut shell_bodies = Vec::new();
    let mut pending: Vec<(bool, String, bool, Vec<&str>)> = Vec::new();
    for line in command.split('\n') {
        if let Some((strip, delim, to_shell, body)) = pending.first_mut() {
            let cmp = if *strip {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if cmp == delim {
                if *to_shell {
                    shell_bodies.push(body.join("\n"));
                }
                pending.remove(0);
            } else {
                body.push(line);
            }
            continue;
        }
        kept.push(line);
        for (start, _, dash, name) in heredoc_marks(line) {
            let to_shell = SHELLS.contains(&first_program(&line[..start]).as_str());
            pending.push((dash, name, to_shell, Vec::new()));
        }
    }
    (kept.join("\n"), shell_bodies)
}

/// `raw_start_query(command, depth)`.
fn raw_start_query(command: &str, depth: u32) -> bool {
    let (command, shell_bodies) = split_heredocs(command);
    if depth < 3 && shell_bodies.iter().any(|b| raw_start_query(b, depth + 1)) {
        return true;
    }
    let mut segment: Vec<String> = Vec::new();
    let mut ws = words(&command.replace('`', " ` "));
    ws.push(";".into());
    for w in ws {
        if depth < 3 && (w.contains("$(") || w.contains('`')) && w.chars().count() > 2 {
            // Python: .replace("$(", " ; ").replace("`", " ; ").replace(")", " ; "); the last two in one pass is the
            // same, since " ; " holds neither character.
            let inner = w.replace("$(", " ; ").replace(['`', ')'], " ; ");
            if raw_start_query(&inner, depth + 1) {
                return true;
            }
        }
        if !is_sep(&w) {
            segment.push(w);
            continue;
        }
        for (i, x) in segment.iter().enumerate() {
            let name = pyfs::basename(x);
            if name == "aws" {
                let rest = &segment[i + 1..];
                if let Some(l) = rest.iter().position(|w| w == "logs") {
                    if rest[l + 1..].iter().any(|w| w == "start-query") {
                        return true;
                    }
                }
            }
            if SHELLS.contains(&name)
                && depth < 3
                && segment[i + 1..(i + 3).min(segment.len())]
                    .iter()
                    .any(|w| w == "-c")
            {
                let k = i + 1 + segment[i + 1..].iter().position(|w| w == "-c").unwrap();
                if k + 1 < segment.len() && raw_start_query(&segment[k + 1], depth + 1) {
                    return true;
                }
            }
        }
        segment.clear();
    }
    false
}

fn search(rx: &Regex, text: &str) -> bool {
    rx.is_match(&PyText::new(text, false).t)
}

fn unguarded(text: &str, guard: &str) -> bool {
    let calls = search(&QUERY_CALL, text) || (search(&SHELL_CMD, text) && search(&SHELL_RUN, text));
    calls && !text.contains(guard)
}

// ------------------------------------------------------------------ scripts a command runs

/// The folder a command runs in: known, unknown (Python's None), or a non-string `cwd` from the hook input, which
/// Python could not join a path onto (a TypeError where it is used).
#[derive(Clone, Debug)]
enum Here {
    Dir(String),
    Unknown,
    NotAString,
}

/// `expand(word, env)`: `~` and `$VAR`/`${VAR}`; None for `$(...)`, a backtick or an unset (or empty) variable.
fn expand(word: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    if word.contains("$(") || word.contains('`') {
        return None;
    }
    let mut word = word.to_string();
    if word == "~" || word.starts_with("~/") {
        let home = env("HOME").filter(|h| !h.is_empty())?;
        word = format!("{home}{}", &word[1..]);
    }
    let mut missing = false;
    let out = PATH_VAR.replace_all(&word, |c: &regex::Captures| {
        let name = c.get(1).or_else(|| c.get(2)).unwrap().as_str();
        match env(name).filter(|v| !v.is_empty()) {
            Some(v) => v,
            None => {
                missing = true;
                String::new()
            }
        }
    });
    if missing {
        None
    } else {
        Some(out.into_owned())
    }
}

fn joined(here: &Here, path: &str) -> Result<Option<String>, String> {
    match here {
        Here::Dir(d) => Ok(Some(pyfs::join(d, path))),
        Here::Unknown => Ok(None),
        Here::NotAString => Err("TypeError: expected str, bytes or os.PathLike object".into()),
    }
}

/// `script_paths(command, cwd, env)`: (word, full path) for each `.py` word, resolved where it runs.
fn script_paths(
    command: &str,
    cwd: Here,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<(String, String)>, String> {
    let (command, _) = split_heredocs(command);
    let mut tokens =
        shlex::split_with(&command, PATH_PUNCT, " \t\r").unwrap_or_else(|_| py_split(&command));
    tokens.push(";".into());
    let (mut found, mut here, mut stack, mut segment) =
        (Vec::new(), cwd, Vec::new(), Vec::<String>::new());
    for tok in tokens {
        if !tok.is_empty() && tok.chars().all(|c| PATH_PUNCT.contains(c)) {
            if segment.len() > 1 && (segment[0] == "cd" || segment[0] == "pushd") {
                here = match (expand(&segment[1], env), &here) {
                    (None, _) | (_, Here::Unknown) => Here::Unknown,
                    (Some(t), h) => Here::Dir(pyfs::normpath(&joined(h, &t)?.unwrap())),
                };
            }
            segment.clear();
            for ch in tok.chars() {
                if ch == '(' {
                    stack.push(here.clone());
                } else if ch == ')' {
                    if let Some(h) = stack.pop() {
                        here = h;
                    }
                }
            }
            continue;
        }
        let is_py = tok.ends_with(".py");
        segment.push(tok.clone());
        if is_py && segment[0] != "cd" && segment[0] != "pushd" {
            if let Some(path) = expand(&tok, env) {
                if path.starts_with('/') || !matches!(here, Here::Unknown) {
                    let base = match &here {
                        Here::Unknown => Here::Dir("/".into()),
                        h => h.clone(),
                    };
                    found.push((tok, pyfs::normpath(&joined(&base, &path)?.unwrap())));
                }
            }
        }
    }
    Ok(found)
}

/// `reason(command, cwd)`: why the command is blocked, if it is.
fn reason(
    command: &str,
    cwd: Here,
    cfg: &LogsConfig,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<String>, String> {
    if raw_start_query(command, 0) {
        return Ok(Some(cfg.raw_cli_reason.clone()));
    }
    if !search(&PYTHON, command) {
        return Ok(None);
    }
    for (path, full) in script_paths(command, cwd, env)? {
        let text = pyfs::read_text(&full, MAX_READ)?;
        if unguarded(&text, &cfg.guard_module) {
            return Ok(Some(cfg.script_reason.replace("{path}", &path)));
        }
    }
    let inline = command.contains("<<") || search(&INLINE_C, command);
    if inline && unguarded(command, &cfg.guard_module) {
        return Ok(Some(cfg.inline_reason.clone()));
    }
    Ok(None)
}

/// The hook input's `command` as both Python hooks read it: `(data.get("tool_input") or {}).get("command") or ""`.
fn command_of(data: &serde_json::Map<String, Value>) -> Result<Value, String> {
    match data.get("tool_input") {
        Some(t) if py_truthy(t) => match t {
            Value::Object(m) => Ok(m
                .get("command")
                .filter(|c| py_truthy(c))
                .cloned()
                .unwrap_or_else(|| Value::String(String::new()))),
            other => Err(format!(
                "AttributeError: '{}' object has no attribute 'get'",
                hookio::py_type_name(other)
            )),
        },
        _ => Ok(Value::String(String::new())),
    }
}

fn is_bash(data: &serde_json::Map<String, Value>) -> bool {
    data.get("tool_name") == Some(&Value::String("Bash".into()))
}

/// The shared-tree rules: (message, rule) or None.
fn check_tree(
    data: &serde_json::Map<String, Value>,
    cfg: &TreeConfig,
    project: &str,
) -> Result<Option<(String, String)>, String> {
    if !is_bash(data) {
        return Ok(None);
    }
    let command = command_of(data)?;
    let repo = pyfs::realpath(project)?;
    let cwd = data.get("cwd").filter(|c| py_truthy(c));
    Guard::new(repo, cfg).check(&command, cwd)
}

/// The Logs Insights rule: the block message or None.
fn check_logs(
    data: &serde_json::Map<String, Value>,
    cfg: &LogsConfig,
) -> Result<Option<String>, String> {
    if !is_bash(data) {
        return Ok(None);
    }
    let command = match data.get("tool_input") {
        Some(t) if py_truthy(t) => match t {
            Value::Object(m) => match m.get("command") {
                Some(Value::String(s)) => s.clone(),
                Some(c) if py_truthy(c) => {
                    return Err(format!(
                        "AttributeError: '{}' object has no attribute 'split'",
                        hookio::py_type_name(c)
                    ));
                }
                _ => String::new(),
            },
            other => {
                return Err(format!(
                    "AttributeError: '{}' object has no attribute 'get'",
                    hookio::py_type_name(other)
                ));
            }
        },
        _ => String::new(),
    };
    let env = |k: &str| std::env::var(k).ok();
    let cwd = match data.get("cwd") {
        Some(Value::String(s)) if !s.is_empty() => Here::Dir(s.clone()),
        Some(c) if py_truthy(c) => Here::NotAString,
        _ => match env("CLAUDE_PROJECT_DIR").filter(|p| !p.is_empty()) {
            Some(p) => Here::Dir(p),
            None => Here::Dir(pyfs::cwd()?),
        },
    };
    Ok(reason(&command, cwd, cfg, &env)?.map(|why| cfg.block_message.replace("{why}", &why)))
}

/// The verdict for one hook input. Nothing is written here (`emit` logs the crashes), so shadow mode can call it.
pub fn decide(input: &[u8], crash_log: Option<&str>) -> Decision {
    let project = std::env::var("CLAUDE_PROJECT_DIR").unwrap_or_default();
    let no_config = |why: String| Decision {
        verdict: Verdict::NoConfig(why),
        crashes: Vec::new(),
        log: None,
    };
    if project.is_empty() {
        return no_config("CLAUDE_PROJECT_DIR is not set".into());
    }
    let cfg = match Config::load(&project) {
        Ok(c) => c,
        Err(e) => return no_config(e),
    };
    let log = Some(
        crash_log
            .map(str::to_string)
            .unwrap_or_else(|| cfg.error_log.clone()),
    );
    let parts: Vec<&str> = [
        cfg.logs.as_ref().map(|_| "logs-insights"),
        cfg.tree.as_ref().map(|_| "tree"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let every = |e: String| Decision {
        verdict: Verdict::Allow,
        crashes: parts.iter().map(|p| format!("{p} {e}")).collect(),
        log: log.clone(),
    };
    // The Python hooks let json.load raise, and logged it: bad JSON, bad UTF-8 and too deep all count as crashes.
    let data = match hookio::parse_py(input) {
        Ok(Value::Object(d)) => d,
        Ok(other) => {
            return every(format!(
                "AttributeError: '{}' object has no attribute 'get'",
                hookio::py_type_name(&other)
            ));
        }
        Err(hookio::ParseError::TooDeep(kind)) => {
            return every(hookio::ParseError::too_deep_text(kind));
        }
        Err(hookio::ParseError::Invalid) => return every("JSONDecodeError".into()),
    };
    let mut crashes = Vec::new();
    let mut block: Option<(String, String)> = None;
    let mut run = |name: &str, f: &dyn Fn() -> Result<Option<(String, String)>, String>| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
            Ok(Ok(Some(b))) => {
                block.get_or_insert(b);
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => crashes.push(format!("{name} {e}")),
            Err(_) => crashes.push(format!("{name} panic")),
        }
    };
    if let Some(l) = &cfg.logs {
        run("logs-insights", &|| {
            Ok(check_logs(&data, l)?.map(|m| (m, "logs-insights".to_string())))
        });
    }
    if let Some(t) = &cfg.tree {
        run("tree", &|| check_tree(&data, t, &project));
    }
    Decision {
        verdict: match block {
            Some((message, rule)) => Verdict::Block { message, rule },
            None => Verdict::Allow,
        },
        crashes,
        log,
    }
}

/// Act on the decision; returns the exit code.
pub fn emit(d: &Decision) -> i32 {
    if let Some(path) = &d.log {
        for e in &d.crashes {
            let first = e.lines().next().unwrap_or("");
            logfile::append(
                path,
                &format!("{} repo-pre-bash {first}", crate::now_utc()),
                LOG_CAP,
            );
        }
    }
    if let Verdict::NoConfig(why) = &d.verdict {
        let msg = format!(
            "claude-guard repo pre-bash: no usable config ({why}); this repo's Bash guards are off for this call."
        );
        println!(
            "{}",
            hookio::py_dumps(&serde_json::json!({ "systemMessage": msg }))
        );
        return 0;
    }
    let (code, stderr) = d.outcome();
    eprint!("{stderr}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heredoc_marks_follow_python() {
        let names = |l: &str| {
            heredoc_marks(l)
                .into_iter()
                .map(|(_, _, d, n)| (d, n))
                .collect::<Vec<_>>()
        };
        assert_eq!(names("cat <<EOF"), [(false, "EOF".to_string())]);
        assert_eq!(names("cat <<-'END' | sh"), [(true, "END".to_string())]);
        assert_eq!(names("cat << \"X1\""), [(false, "X1".to_string())]);
        assert_eq!(
            names("cat <<'EOF"),
            Vec::<(bool, String)>::new(),
            "unclosed quote: no match"
        );
        assert_eq!(
            names("cat <<<EOF"),
            Vec::<(bool, String)>::new(),
            "a here-string"
        );
        assert_eq!(
            names("a <<A b <<B"),
            [(false, "A".to_string()), (false, "B".to_string())]
        );
        assert_eq!(
            names("x <<\u{1c}EOF"),
            [(false, "EOF".to_string())],
            "Python \\s"
        );
    }

    #[test]
    fn raw_queries_and_data() {
        assert!(raw_start_query("aws logs start-query --x 1", 0));
        assert!(raw_start_query("aws --profile p logs start-query", 0));
        assert!(raw_start_query("bash -c 'aws logs start-query'", 0));
        assert!(raw_start_query("echo \"$(aws logs start-query)\"", 0));
        assert!(raw_start_query("bash <<EOF\naws logs start-query\nEOF", 0));
        assert!(!raw_start_query("cat <<EOF\naws logs start-query\nEOF", 0));
        assert!(!raw_start_query("git commit -m 'aws logs start-query'", 0));
        assert!(!raw_start_query("aws logs describe-queries", 0));
    }

    #[test]
    fn script_paths_follow_cd_and_expansion() {
        let env = |k: &str| match k {
            "HOME" => Some("/h".to_string()),
            "P" => Some("/p".to_string()),
            _ => None,
        };
        let paths = |c: &str| {
            script_paths(c, Here::Dir("/r".into()), &env)
                .unwrap()
                .into_iter()
                .map(|p| p.1)
                .collect::<Vec<_>>()
        };
        assert_eq!(paths("cd sub && python3 old.py"), ["/r/sub/old.py"]);
        assert_eq!(paths("python3 ~/x.py"), ["/h/x.py"]);
        assert_eq!(paths("python3 $P/x.py; echo"), ["/p/x.py"]);
        assert_eq!(paths("python3 ${P}/a/../x.py"), ["/p/x.py"]);
        assert_eq!(paths("(cd sub && ls); python3 x.py"), ["/r/x.py"]);
        assert_eq!(paths("python3 $NOPE/x.py"), Vec::<String>::new());
        assert_eq!(paths("cd $NOPE && python3 x.py"), Vec::<String>::new());
        assert_eq!(paths("cd $NOPE && python3 /abs/x.py"), ["/abs/x.py"]);
        assert!(script_paths("python3 x.py", Here::NotAString, &env).is_err());
        assert!(
            script_paths("cd $NOPE && echo", Here::NotAString, &env).is_ok(),
            "an unknown cd target never joins"
        );
    }
}
