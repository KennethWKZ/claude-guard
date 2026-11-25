//! The shared-working-tree rules of `claude-guard repo pre-bash`, ported function for function from a repo's
//! Python PreToolUse hook. For repos where several Claude sessions share one working tree, one git index and one
//! branch, it blocks Bash commands that would take, wipe or rewrite other sessions' work:
//!
//! - git operations that stage or commit outside the repo's commit queue, rewrite history, move the branch or HEAD,
//!   throw away uncommitted work, prune unreachable objects at once (also through `-c`, `--config-env`, the
//!   `GIT_CONFIG_*` variables or a value already saved in git config), or write the repo's own git config;
//! - shell writes (redirects, `tee`, `sed -i`, `perl -i`, `cp`/`mv`/`install`, `truncate`) onto files in the
//!   config's `locked_dirs`, which the repo's scripts write under a per-file lock;
//! - any use of the repo's write ledger folder or its override variable in what the command runs;
//! - python, node, perl or ruby code (a heredoc fed to the interpreter, or `-c`/`-e` code) that writes a file in the
//!   locked folders.
//!
//! Where commands run follows `cd`/`pushd` (undone at the end of a subshell), `git -C`, `--work-tree`/`--git-dir`
//! and their variables; `bash -c`, `eval`, substitutions, heredocs fed to a shell, shell scripts run by path,
//! `xargs` and `find -exec` are read too. Every message comes from the config (`pre_bash.git`, `shell_writes`,
//! `interpreter_writes`, `write_ledger`); the code names nothing of any repo.
//!
//! Reads only: the hook input, the shell scripts a command runs (in the repo or a temp folder, 256 KiB at most) and,
//! for `git gc`/`maintenance run` only, the saved gc settings through `git config --get-regexp`. Errors are returned
//! where the Python hook raised (the caller logs them and lets the command through, as Python did).

use crate::pyfs;
use crate::pyre::{PyText, py_word};
use crate::shell_words::{self as sw, Env};
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

type R<T> = Result<T, String>;

const DECLARE: &[&str] = &["export", "local", "declare", "typeset", "readonly"];
const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash"];
const GIT_OPT_WITH_VALUE: &[&str] = &[
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--config-env",
];
const XARGS_OPT_WITH_VALUE: &[&str] = &[
    "-I", "-J", "-L", "-n", "-P", "-s", "-E", "-d", "-a", "-R", "-S",
];
const STASH_READS: &[&str] = &["list", "show", "create"];
const HELP: &[&str] = &["-h", "--help"];
const HEAD_WORDS: &[&str] = &["HEAD", "@"];
const CONFIG_READS: &[&str] = &[
    "--get",
    "--get-all",
    "--get-regexp",
    "--get-urlmatch",
    "--list",
    "-l",
    "--get-color",
    "--get-colorbool",
];
const CONFIG_WRITES: &[&str] = &[
    "--unset",
    "--add",
    "--replace-all",
    "--rename-section",
    "--remove-section",
    "--edit",
];
const INDEX_REFRESH: &[&str] = &[
    "-q",
    "--refresh",
    "--really-refresh",
    "--ignore-missing",
    "--unmerged",
    "--ignore-submodules",
];
const IMMEDIATE_PRUNE: &[&str] = &["now", "all", "0", "today"];
const NOTES_READS: &[&str] = &["list", "show", "get-ref"];
const BISECT_READS: &[&str] = &["log", "visualize", "view", "terms", "help"];
const SPARSE_WRITES: &[&str] = &["set", "add", "init", "disable", "reapply"];
const CHECKOUT_SWITCH_FLAGS: &[&str] = &["-b", "-B", "--orphan", "--detach", "-t", "--track"];
const FILE_WRITERS: &[&str] = &[
    "tee", "sed", "gsed", "perl", "cp", "mv", "install", "truncate",
];
const STAGING_ONLY: &[&str] = &[
    "add",
    "rm",
    "mv",
    "read-tree",
    "update-index",
    "apply --index",
];
const MAX_DEPTH: usize = 4;
const MAX_SCRIPT_BYTES: u64 = 256 * 1024;
/// Python's recursion limit, roughly: where its unbounded recursion (nested substitutions) raised RecursionError.
const MAX_NESTING: usize = 990;
const INLINE_CODE_OPTS: &[&str] = &["-c", "-e", "-E", "-p", "--eval", "--print"];
const MODULES: &[&str] = &["io", "codecs", "builtins", "os", "fs", "fsp", "promises"];

fn re(p: &str) -> Regex {
    // INFALLIBLE: constant patterns, all exercised by the unit tests.
    Regex::new(p).unwrap()
}

static PRUNE_KEY: LazyLock<Regex> =
    LazyLock::new(|| re(r"^gc\.(?:pruneexpire|(?:.+\.)?reflogexpire(?:unreachable)?)\n?\z"));
static CONFIG_PARAM: LazyLock<Regex> =
    LazyLock::new(|| re(r"'((?:[^']|'\\'')*)'(?:=('(?:[^']|'\\'')*'))?"));
static INTERP_FEED: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?:^|[|;&(])\s*(?:[A-Za-z_]\w*=\S*\s+)*",
        r"(?:(?:rtk|command|exec|nice|time|env|nohup|uv\s+run)\s+(?:-\S+(?:\s+[^-\s]\S*)?\s+)*)*",
        r"(?:\S*/)?(?:bash|sh|zsh|dash|python[0-9.]*|node|deno|bun|perl|ruby|php|osascript)\b"
    ))
});
static ASSIGN_JS: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)"));
static FOR_PY: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?m)^[ \t]*(?:async[ \t]+)?for[ \t]+([A-Za-z_]\w*)[ \t]+in[ \t]+(.+):"));
static FOR_JS: LazyLock<Regex> =
    LazyLock::new(|| re(r"\bfor\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+([^)]+)\)"));
static TARGET_FIRST: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|truncateSync|",
        r"truncate|openSync|outputFileSync|outputFile|writeJsonSync|writeJson|Bun\.write|File\.write|",
        r"File\.binwrite|IO\.write)\s*\("
    ))
});
static TARGET_SECOND: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?:shutil\.(?:copy|copy2|copyfile|copytree|move)|os\.(?:rename|replace|link|symlink)|",
        r"copyFileSync|copyFile|renameSync|rename|cpSync|linkSync|symlinkSync|",
        r"FileUtils\.(?:cp|mv|copy|move))\s*\("
    ))
});
static FUNC_OPEN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?:(?:io|codecs|builtins|os)\.)?open\s*\("));
static METHOD_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\.(?:write_text|write_bytes|touch|rename|replace|symlink_to|hardlink_to|open)\s*\(")
});
static PERL_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"\bopen\s*\(?\s*(?:my\s+)?[$\w]+\s*,\s*["']\+?(?:>>?|\+<)["']\s*,\s*([^)\n;]+)"#)
});
/// `open(F, ">path")`: Python's `(["'])...\1` as two alternatives (the path can hold neither quote).
static PERL_WRITE2: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r#"\bopen\s*\(?\s*(?:my\s+)?[$\w]+\s*,\s*"#,
        r#"(?:"\+?(?:>>?|\+<)\s*([^"']+)"|'\+?(?:>>?|\+<)\s*([^"']+)')"#
    ))
});
static MODE: LazyLock<Regex> =
    LazyLock::new(|| re(r#"^(?:mode\s*=\s*|flags?\s*:\s*)?["'`]([rwabxt+]{1,4})["'`]\z"#));
static OS_FLAGS: LazyLock<Regex> =
    LazyLock::new(|| re(r"\bO_(?:WRONLY|RDWR|CREAT|APPEND|TRUNC)\b"));

// ------------------------------------------------------------------ config

/// `pre_bash.git`, `shell_writes`, `interpreter_writes` and `write_ledger`, plus the top-level folder lists.
#[derive(Debug, Clone)]
pub struct TreeConfig {
    repo_label: String,
    locked: Vec<String>,
    output: Vec<String>,
    git_block: String,
    git_messages: HashMap<String, String>,
    git_advice: HashMap<String, String>,
    git_default_message: String,
    git_default_advice: String,
    saved_prune: String,
    write_block: String,
    write_message: String,
    interp_block: String,
    interp_message: String,
    ledger_block: String,
    ledger_message: String,
    ledger: Regex,
}

fn text(v: &Value, path: &[&str]) -> R<String> {
    let mut cur = v;
    for k in path {
        cur = cur
            .get(k)
            .ok_or_else(|| format!("{} is missing", path.join(".")))?;
    }
    cur.as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("{} is not a non-empty string", path.join(".")))
}

fn texts(v: &Value, path: &[&str]) -> R<Vec<String>> {
    let a = path
        .iter()
        .try_fold(v, |cur, k| cur.get(k))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{} is not a list", path.join(".")))?;
    a.iter()
        .map(|x| {
            x.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{} holds a non-string", path.join(".")))
        })
        .collect()
}

fn table(v: &Value, path: &[&str]) -> R<HashMap<String, String>> {
    let m = path
        .iter()
        .try_fold(v, |cur, k| cur.get(k))
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{} is not an object", path.join(".")))?;
    m.iter()
        .map(|(k, x)| {
            x.as_str()
                .map(|s| (k.clone(), s.to_string()))
                .ok_or_else(|| format!("{}.{k} is not a string", path.join(".")))
        })
        .collect()
}

impl TreeConfig {
    /// None when the config has no `pre_bash.git` section (the rules are off for that repo).
    pub fn load(v: &Value) -> R<Option<TreeConfig>> {
        if v.get("pre_bash").and_then(|p| p.get("git")).is_none() {
            return Ok(None);
        }
        let pb = |sec: &str, k: &str| text(v, &["pre_bash", sec, k]);
        let ledger_dir = pb("write_ledger", "dir")?;
        let override_env = pb("write_ledger", "override_env")?;
        let ledger = Regex::new(&format!(
            r#"{}\b|{}['"\]]*\s*[=:,]"#,
            regex::escape(pyfs::basename(ledger_dir.trim_end_matches('/'))),
            regex::escape(&override_env)
        ))
        .map_err(|e| format!("pre_bash.write_ledger: {e}"))?;
        Ok(Some(TreeConfig {
            repo_label: text(v, &["repo_label"])?,
            locked: texts(v, &["locked_dirs"])?,
            output: texts(v, &["output_dirs"])?,
            git_block: pb("git", "block_message")?,
            git_messages: table(v, &["pre_bash", "git", "messages"])?,
            git_advice: table(v, &["pre_bash", "git", "advice"])?,
            git_default_message: pb("git", "default_message")?,
            git_default_advice: pb("git", "default_advice")?,
            saved_prune: pb("git", "saved_prune_message")?,
            write_block: pb("shell_writes", "block_message")?,
            write_message: pb("shell_writes", "message")?,
            interp_block: pb("interpreter_writes", "block_message")?,
            interp_message: pb("interpreter_writes", "message")?,
            ledger_block: pb("write_ledger", "block_message")?,
            ledger_message: pb("write_ledger", "message")?,
            ledger,
        }))
    }
}

/// `{name}` placeholders filled in one pass (a value holding braces stays as it is); unknown ones are kept.
pub fn render(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 256);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) => {
                let key = &after[..close];
                match values.iter().find(|(k, _)| *k == key) {
                    Some((_, v)) => out.push_str(v),
                    None => {
                        out.push('{');
                        out.push_str(key);
                        out.push('}');
                    }
                }
                rest = &after[close + 1..];
            }
            None => {
                out.push_str(&rest[open..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

// ------------------------------------------------------------------ small helpers

fn has(rest: &[String], x: &str) -> bool {
    rest.iter().any(|a| a == x)
}

fn any_of(rest: &[String], xs: &[&str]) -> bool {
    rest.iter().any(|a| xs.contains(&a.as_str()))
}

fn plain(rest: &[String]) -> Vec<&String> {
    rest.iter().filter(|a| !a.starts_with('-')).collect()
}

fn first_plain(rest: &[String]) -> Option<&str> {
    rest.iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
}

/// Letters of clustered short options (-fdx -> f, d, x).
fn short_flags(rest: &[String]) -> BTreeSet<char> {
    rest.iter()
        .filter(|a| a.starts_with('-') && !a.starts_with("--"))
        .flat_map(|a| a.chars().skip(1))
        .collect()
}

/// `text.partition(sep)`.
fn partition(t: &str, sep: char) -> (&str, &str) {
    t.split_once(sep).unwrap_or((t, ""))
}

/// `key=value` as `git -c` takes it: (stripped lowercased key, stripped value).
fn config_pair(t: &str) -> (String, String) {
    let (k, v) = partition(t, '=');
    (
        pyfs::py_strip(k).to_lowercase(),
        pyfs::py_strip(v).to_string(),
    )
}

/// Config set for one command through the environment: GIT_CONFIG_PARAMETERS, then GIT_CONFIG_COUNT/KEY_n/VALUE_n.
fn env_config(env: &Env) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let unq = |s: &str| s.replace("'\\''", "'");
    let params = env
        .get("GIT_CONFIG_PARAMETERS")
        .map(String::as_str)
        .unwrap_or("");
    for c in CONFIG_PARAM.captures_iter(params) {
        // INFALLIBLE: group 1 is not optional.
        let g1 = c.get(1).unwrap().as_str();
        match c.get(2) {
            None => pairs.push(config_pair(&unq(g1))),
            Some(g2) => {
                let v: Vec<char> = g2.as_str().chars().collect();
                let inner: String = v[1..v.len() - 1].iter().collect();
                pairs.push((unq(g1).to_lowercase(), unq(&inner)));
            }
        }
    }
    let count =
        sw::py_int_small(env.get("GIT_CONFIG_COUNT").map_or("0", String::as_str)).unwrap_or(0);
    for n in 0..count.clamp(0, 100) {
        let get = |k: String| env.get(&k).cloned().unwrap_or_default();
        pairs.push((
            get(format!("GIT_CONFIG_KEY_{n}")).to_lowercase(),
            get(format!("GIT_CONFIG_VALUE_{n}")),
        ));
    }
    pairs
}

/// A config override that makes gc delete unreachable objects or reflog entries at once.
fn prunes_now(pairs: &[(String, String)]) -> bool {
    pairs.iter().any(|(k, v)| {
        PRUNE_KEY.is_match(k)
            && IMMEDIATE_PRUNE.contains(&pyfs::py_strip(v).to_lowercase().as_str())
    })
}

fn value_of<'a>(rest: &'a [String], option: &str) -> Option<&'a str> {
    let eq = format!("{option}=");
    for (i, a) in rest.iter().enumerate() {
        if let Some(v) = a.strip_prefix(&eq) {
            return Some(v);
        }
        if a == option && i + 1 < rest.len() {
            return Some(&rest[i + 1]);
        }
    }
    None
}

/// git repack that deletes unreachable packed objects.
fn repack_drops(rest: &[String]) -> bool {
    let flags = short_flags(rest);
    if !flags.contains(&'d') {
        return false;
    }
    for option in ["--unpack-unreachable", "--cruft-expiration"] {
        if let Some(v) = value_of(rest, option) {
            if IMMEDIATE_PRUNE.contains(&pyfs::py_strip(v).to_lowercase().as_str()) {
                return true;
            }
        }
    }
    flags.contains(&'a')
        && !flags.contains(&'A')
        && !any_of(rest, &["--keep-unreachable", "--cruft"])
}

fn config_writes(rest: &[String]) -> bool {
    if rest
        .iter()
        .any(|a| a == "--global" || a == "--system" || a == "-f" || a.starts_with("--file"))
    {
        return false;
    }
    let sub = first_plain(rest);
    if matches!(sub, Some("get" | "list")) {
        return false;
    }
    if matches!(
        sub,
        Some("set" | "unset" | "rename-section" | "remove-section" | "edit")
    ) {
        return true;
    }
    if any_of(rest, CONFIG_READS) {
        return false;
    }
    if rest
        .iter()
        .any(|a| CONFIG_WRITES.iter().any(|w| a.starts_with(w)) || a == "-e")
    {
        return true;
    }
    plain(rest).len() >= 2
}

/// `shutil.which("git")` on the hook's own PATH.
fn which_git() -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".into());
    if path.is_empty() {
        return None;
    }
    let mut seen = BTreeSet::new();
    for dir in path.split(':') {
        if !seen.insert(dir) {
            continue;
        }
        let name = pyfs::join(dir, "git");
        let ok = std::fs::metadata(&name)
            .is_ok_and(|m| !m.is_dir() && m.permissions().mode() & 0o111 != 0);
        if ok {
            return Some(name);
        }
    }
    None
}

/// `str.splitlines()`.
fn py_splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let brk = matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if brk {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' && it.peek().is_some_and(|&(_, n)| n == '\n') {
                it.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// An immediate prune already saved in git config (read with git itself): "<file> <key>=<value>".
fn saved_prune(d: Option<&str>) -> R<Option<String>> {
    let (Some(git), Some(d)) = (which_git(), d) else {
        return Ok(None);
    };
    if d.contains('\0') {
        return Err("ValueError: embedded null byte".into());
    }
    let mut child = match std::process::Command::new(&git)
        .args(["-C", d, "config", "--show-origin", "--get-regexp", r"^gc\."])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let mut out = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(o) = out.as_mut() {
            let _ = std::io::Read::read_to_end(o, &mut b);
        }
        b
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(None);
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(2)),
            Err(_) => return Ok(None),
        }
    }
    let bytes = reader.join().unwrap_or_default();
    let text = String::from_utf8(bytes).map_err(|_| "UnicodeDecodeError".to_string())?;
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    for line in py_splitlines(&text) {
        let (origin, setting) = partition(line, '\t');
        let (key, value) = partition(setting, ' ');
        if prunes_now(&[(key.to_lowercase(), value.to_string())]) {
            let origin = origin.strip_prefix("file:").unwrap_or(origin);
            return Ok(Some(format!("{origin} {key}={value}")));
        }
    }
    Ok(None)
}

/// `open(path, encoding="utf-8").read()` for a script under 256 KiB, newlines translated; None where Python got
/// None (outside the script folders, missing, too big, not UTF-8).
fn read_script(path: &str) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_SCRIPT_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let t = String::from_utf8(bytes).ok()?;
    Some(t.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `re.search(rf"\b{name}\b", text)` for a name of word characters.
fn has_word(text: &str, name: &str) -> bool {
    let c: Vec<char> = text.chars().collect();
    let n: Vec<char> = name.chars().collect();
    (0..c.len()).any(|p| {
        p + n.len() <= c.len()
            && c[p..p + n.len()] == n[..]
            && (p == 0 || !py_word(c[p - 1]))
            && (p + n.len() == c.len() || !py_word(c[p + n.len()]))
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Locked,
    Elsewhere,
}

/// One rule check over one command: the repo it guards and the config.
pub struct Guard<'a> {
    repo: String,
    cfg: &'a TreeConfig,
}

impl<'a> Guard<'a> {
    /// `repo`: the real path of the project folder.
    pub fn new(repo: String, cfg: &'a TreeConfig) -> Guard<'a> {
        Guard { repo, cfg }
    }

    fn is_locked(&self, seg: &str) -> bool {
        self.cfg.locked.iter().any(|d| d == seg)
    }

    /// `inside(path, repo)`: in this repo's own working tree, not in a nested worktree or clone.
    fn inside(&self, path: Option<&str>) -> bool {
        let repo = self.repo.as_str();
        let Some(path) = path else { return false };
        if !(path == repo || path.starts_with(&format!("{repo}/"))) {
            return false;
        }
        let mut p = path.to_string();
        while p != repo {
            if pyfs::lexists(&pyfs::join(&p, ".git")) {
                return false;
            }
            let up = pyfs::dirname(&p);
            if up == p {
                break;
            }
            p = up;
        }
        true
    }

    /// `locked_file(path, repo)`: the repo-relative path when path is (or would be) a locked file.
    fn locked_file(&self, path: Option<String>) -> Option<String> {
        let path = path?;
        if pyfs::isdir(&path) || !self.inside(Some(&pyfs::dirname(&path))) {
            return None;
        }
        let rel = pyfs::relpath(&path, &self.repo).ok()?;
        let first = rel.split('/').next().unwrap_or("");
        self.is_locked(first).then_some(rel)
    }

    fn broad_path(&self, p: &str, d: Option<&str>, env: &Env) -> R<bool> {
        if [".", "./", "*", ":/", ":"].contains(&p)
            || p.starts_with(":(")
            || p.starts_with(":/")
            || p.contains(['*', '?', '['])
        {
            return Ok(true);
        }
        let full = sw::resolve(d, p, env)?;
        Ok(full.is_none_or(|f| pyfs::isdir(&f)))
    }

    /// git checkout / restore that would overwrite working-tree changes across more than one named file.
    fn discards_tree(&self, rest: &[String], d: Option<&str>, env: &Env) -> R<bool> {
        let paths: Vec<&String> = match rest.iter().position(|a| a == "--") {
            Some(i) => rest[i + 1..].iter().collect(),
            None => rest
                .iter()
                .filter(|a| {
                    !a.starts_with('-')
                        && (["." as &str, "./", ":/"].contains(&a.as_str())
                            || a.contains(['*', '?', '[']))
                })
                .collect(),
        };
        for p in paths {
            if self.broad_path(p, d, env)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_file(&self, word: &str, d: Option<&str>, env: &Env) -> R<bool> {
        Ok(sw::resolve(d, word, env)?.is_some_and(|f| pyfs::isfile(&f)))
    }

    fn switches_branch(&self, rest: &[String], d: Option<&str>, env: &Env) -> R<bool> {
        let dd = rest.iter().position(|a| a == "--");
        let before = &rest[..dd.unwrap_or(rest.len())];
        if has(before, "-")
            || before.iter().any(|a| {
                CHECKOUT_SWITCH_FLAGS.contains(&a.as_str())
                    || a.starts_with("--orphan=")
                    || a.starts_with("--track=")
            })
        {
            return Ok(true);
        }
        if dd.is_some() {
            return Ok(false);
        }
        let p = plain(before);
        Ok(p.len() == 1 && !self.is_file(p[0], d, env)?)
    }

    fn moves_branch_by_reset(&self, rest: &[String], d: Option<&str>, env: &Env) -> R<bool> {
        if any_of(rest, &["--soft", "--mixed", "--keep", "--merge"]) {
            return Ok(true);
        }
        if has(rest, "--") {
            return Ok(false);
        }
        let p = plain(rest);
        if p.len() != 1 {
            return Ok(false);
        }
        Ok(!HEAD_WORDS.contains(&p[0].as_str()) && !self.is_file(p[0], d, env)?)
    }

    fn private_index(&self, index_file: Option<&String>, d: Option<&str>, env: &Env) -> R<bool> {
        let Some(f) = index_file.filter(|f| !f.is_empty()) else {
            return Ok(false);
        };
        let p = sw::resolve(d, f, env)?;
        let shared = pyfs::join(&pyfs::join(&self.repo, ".git"), "index");
        Ok(p.is_some_and(|p| p != shared))
    }

    /// Which blocked git operation `args` (subcommand first) is, or None.
    fn git_hit(
        &self,
        args: &[String],
        d: Option<&str>,
        env: &Env,
        overrides: &[(String, String)],
    ) -> R<Option<String>> {
        let Some(sub) = args.first().map(String::as_str) else {
            return Ok(None);
        };
        let rest = &args[1..];
        let all_help = !rest.is_empty() && rest.iter().all(|a| HELP.contains(&a.as_str()));
        if all_help {
            return Ok(None);
        }
        let some = |s: &str| Ok(Some(s.to_string()));
        if sub == "commit" && has(rest, "--amend") {
            return some("commit --amend");
        }
        if [
            "commit",
            "add",
            "rm",
            "mv",
            "read-tree",
            "rebase",
            "cherry-pick",
            "revert",
            "merge",
            "pull",
            "am",
            "filter-branch",
            "filter-repo",
            "update-ref",
            "switch",
            "commit-tree",
        ]
        .contains(&sub)
        {
            return some(sub);
        }
        if sub == "apply"
            && any_of(
                rest,
                &[
                    "--index",
                    "--cached",
                    "--3way",
                    "-3",
                    "--intent-to-add",
                    "-N",
                ],
            )
        {
            return some("apply --index");
        }
        if sub == "update-index" && !rest.iter().all(|a| INDEX_REFRESH.contains(&a.as_str())) {
            return some("update-index");
        }
        if sub == "stash" {
            return if STASH_READS.contains(
                &first_plain(rest)
                    .filter(|f| !f.is_empty())
                    .unwrap_or("push"),
            ) {
                Ok(None)
            } else {
                some("stash")
            };
        }
        if sub == "reset" {
            if has(rest, "--hard") {
                return some("reset --hard");
            }
            return if self.moves_branch_by_reset(rest, d, env)? {
                some("reset <commit>")
            } else {
                Ok(None)
            };
        }
        if sub == "clean" {
            let flags: Vec<String> = rest
                .iter()
                .filter(|a| a.starts_with('-') && *a != "--")
                .cloned()
                .collect();
            let sf = short_flags(&flags);
            let dry = has(&flags, "--dry-run") || sf.contains(&'n');
            let force = has(&flags, "--force") || sf.contains(&'f');
            return if force && !dry {
                some("clean -f")
            } else {
                Ok(None)
            };
        }
        if sub == "checkout" {
            if has(rest, "-f") || has(rest, "--force") {
                return some("checkout --force");
            }
            if self.discards_tree(rest, d, env)? {
                return some("checkout -- <folder>");
            }
            if self.switches_branch(rest, d, env)? {
                return some("checkout <branch>");
            }
            return Ok(None);
        }
        if sub == "restore" {
            let staged_only =
                any_of(rest, &["--staged", "-S"]) && !any_of(rest, &["--worktree", "-W"]);
            let paths: Vec<String> = if has(rest, "--") {
                rest.to_vec()
            } else {
                std::iter::once("--".to_string())
                    .chain(plain(rest).into_iter().cloned())
                    .collect()
            };
            return if !staged_only && self.discards_tree(&paths, d, env)? {
                some("restore <folder>")
            } else {
                Ok(None)
            };
        }
        let sf = short_flags(rest);
        if sub == "checkout-index"
            && (any_of(rest, &["--all", "--force"]) || sf.contains(&'a') || sf.contains(&'f'))
        {
            return some("checkout-index -f");
        }
        if sub == "branch"
            && (any_of(rest, &["-f", "--force", "--move"])
                || sf.contains(&'m')
                || sf.contains(&'M'))
        {
            return some("branch -f/-m");
        }
        if sub == "symbolic-ref" && (any_of(rest, &["-d", "--delete"]) || plain(rest).len() >= 2) {
            return some("symbolic-ref");
        }
        if sub == "notes"
            && !NOTES_READS.contains(
                &first_plain(rest)
                    .filter(|f| !f.is_empty())
                    .unwrap_or("list"),
            )
        {
            return some("notes");
        }
        if sub == "prune" && !(any_of(rest, &["-n", "--dry-run"]) || sf.contains(&'n')) {
            return some("prune");
        }
        if sub == "gc"
            && rest.iter().any(|a| {
                a.strip_prefix("--prune=")
                    .is_some_and(|v| IMMEDIATE_PRUNE.contains(&v))
            })
        {
            return some("gc --prune=now");
        }
        let runs_gc = sub == "gc" || (sub == "maintenance" && first_plain(rest) == Some("run"));
        if runs_gc && prunes_now(overrides) {
            return some("gc --prune=now");
        }
        if sub == "repack" && repack_drops(rest) {
            return some("repack -a -d");
        }
        if runs_gc && !all_help {
            if let Some(saved) = saved_prune(d)? {
                return Ok(Some(format!("saved-prune:{saved}")));
            }
        }
        if sub == "config" {
            let mut p = plain(rest);
            if p.first().is_some_and(|a| *a == "set" || *a == "add") {
                p.remove(0);
            }
            if p.len() >= 2 && prunes_now(&[config_pair(&format!("{}={}", p[0], p[1]))]) {
                return some("gc --prune=now");
            }
        }
        if sub == "reflog" && matches!(first_plain(rest), Some("expire" | "delete")) {
            return some("reflog expire");
        }
        if sub == "bisect" && !first_plain(rest).is_some_and(|f| BISECT_READS.contains(&f)) {
            return some("bisect");
        }
        if sub == "sparse-checkout" && first_plain(rest).is_some_and(|f| SPARSE_WRITES.contains(&f))
        {
            return some("sparse-checkout");
        }
        if sub == "config" && config_writes(rest) {
            return some("config");
        }
        Ok(None)
    }

    /// `tee`, `sed -i`, `perl -i`, `cp`/`mv`/`install`, `truncate` onto a locked file: its repo-relative path.
    fn writes_locked_file(
        &self,
        cmd: &str,
        args: &[String],
        here: Option<&str>,
        env: &Env,
    ) -> R<Option<String>> {
        let p = plain(args);
        let targets: Vec<&String> = if ["sed", "gsed", "perl"].contains(&cmd) {
            let in_place = |a: &str| {
                if cmd == "perl" {
                    // re.match(r"^-[0-9lnpaFsw]*i", a)
                    let mut cs = a.chars();
                    cs.next() == Some('-')
                        && cs
                            .find(|c| !(c.is_ascii_digit() || "lnpaFsw".contains(*c)))
                            .is_some_and(|c| c == 'i')
                } else {
                    !a.starts_with("--") && a[1..].contains('i')
                }
            };
            let any = args
                .iter()
                .filter(|a| a.starts_with('-'))
                .any(|a| a == "--in-place" || a.starts_with("--in-place=") || in_place(a));
            if !any {
                return Ok(None);
            }
            p
        } else if ["cp", "mv", "install"].contains(&cmd) {
            if p.len() < 2 {
                return Ok(None);
            }
            let dest = sw::resolve(here, p[p.len() - 1], env)?;
            if let Some(dest) = dest.filter(|d| pyfs::isdir(d)) {
                return Ok(p[..p.len() - 1]
                    .iter()
                    .find_map(|s| self.locked_file(Some(pyfs::join(&dest, pyfs::basename(s))))));
            }
            vec![p[p.len() - 1]]
        } else {
            p
        };
        for t in targets {
            if let Some(rel) = self.locked_file(sw::resolve(here, t, env)?) {
                return Ok(Some(rel));
            }
        }
        Ok(None)
    }

    /// Where a session writes a throwaway script: the repo and the temp folders.
    fn script_dirs(&self) -> Option<Vec<String>> {
        let tmp = std::env::var("TMPDIR")
            .ok()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| "/tmp".into());
        let mut out = vec![self.repo.clone()];
        for p in [tmp.as_str(), "/tmp", "/private/var/folders"] {
            out.push(pyfs::realpath(p).ok()?);
        }
        Some(out)
    }

    /// The text of a shell script a command runs, or None.
    fn script_text(&self, path: Option<String>) -> Option<String> {
        let path = path?;
        let dirs = self.script_dirs()?;
        if !dirs.iter().any(|d| path.starts_with(&format!("{d}/"))) || !pyfs::isfile(&path) {
            return None;
        }
        read_script(&path)
    }

    /// A command word that is a path to a shell script (its shebang names a shell): its text.
    fn runs_shell_script(&self, word: &str, here: Option<&str>, env: &Env) -> R<Option<String>> {
        if !word.contains('/') {
            return Ok(None);
        }
        let Some(text) = self.script_text(sw::resolve(here, word, env)?) else {
            return Ok(None);
        };
        if !text.starts_with("#!") {
            return Ok(None);
        }
        let first = text.split('\n').next().unwrap_or("");
        Ok(SHELLS.iter().any(|s| has_word(first, s)).then_some(text))
    }

    /// `analyze()`: the first blocked operation that would run inside the repo: a git operation name,
    /// "write:<path>" or "saved-prune:<where>".
    fn analyze(
        &self,
        command: &str,
        here: Option<String>,
        mut env: Env,
        depth: usize,
    ) -> R<Option<String>> {
        if depth > MAX_DEPTH {
            return Ok(None);
        }
        let mut fed = Vec::new();
        let command = sw::strip_comments(&sw::heredocs(command, Some(&mut fed), &sw::shell_feed));
        fed.extend(sw::substitutions(&command, "`"));
        for inner in fed {
            if let Some(h) = self.analyze(&inner, here.clone(), env.clone(), depth + 1)? {
                return Ok(Some(h));
            }
        }
        let w = sw::words(&sw::mark_single_quoted(&command));
        let mut here = here;
        let mut stack: Vec<Option<String>> = Vec::new();
        let mut at_start = true;
        let mut i = 0;
        while i < w.len() {
            let word = w[i].as_str();
            if sw::is_operator(word) {
                for ch in word.chars() {
                    if ch == '(' {
                        stack.push(here.clone());
                    } else if ch == ')' {
                        if let Some(h) = stack.pop() {
                            here = h;
                        }
                    }
                }
                if word.contains('>')
                    && i + 1 < w.len()
                    && !sw::is_operator(&w[i + 1])
                    && !sw::py_isdigit(&w[i + 1])
                    && w[i + 1] != "-"
                    && !word.ends_with('(')
                {
                    if let Some(rel) =
                        self.locked_file(sw::resolve(here.as_deref(), &w[i + 1], &env)?)
                    {
                        return Ok(Some(format!("write:{rel}")));
                    }
                }
                at_start =
                    word.ends_with('(') || (!word.contains(['<', '>']) && !word.ends_with(')'));
                i += 1;
                continue;
            }
            if word.contains('(') {
                for inner in sw::substitutions(word, "$<>") {
                    if let Some(h) = self.analyze(&inner, here.clone(), env.clone(), depth + 1)? {
                        return Ok(Some(h));
                    }
                }
            }
            if ["-exec", "-execdir", "-ok"].contains(&word) {
                at_start = true;
                i += 1;
                continue;
            }
            if !at_start {
                i += 1;
                continue;
            }
            // A command starts here.
            if let Some((name, value)) = sw::assign(word) {
                match sw::expand(value, &env)? {
                    Some(v) => {
                        env.insert(name.to_string(), v);
                    }
                    None => {
                        env.remove(name);
                    }
                }
                i += 1;
                continue;
            }
            if DECLARE.contains(&word) || sw::PREFIXES.contains(&word) {
                i += 1;
                continue;
            }
            at_start = false;
            let mut k = i + 1;
            while k < w.len() && !sw::is_operator(&w[k]) {
                k += 1;
            }
            let args = &w[i + 1..k];
            let name = pyfs::basename(word);

            if word == "cd" || word == "pushd" {
                let target = args
                    .first()
                    .filter(|a| !a.is_empty())
                    .map_or("~", String::as_str);
                here = sw::resolve(here.as_deref(), target, &env)?;
                i = k;
                continue;
            }
            if word == "eval" {
                if let Some(h) = self.analyze(
                    &sw::unmark(&args.join(" ")),
                    here.clone(),
                    env.clone(),
                    depth + 1,
                )? {
                    return Ok(Some(h));
                }
                i = k;
                continue;
            }
            if SHELLS.contains(&name) || word == "source" || word == "." {
                let sourced = word == "source" || word == ".";
                let mut j = 0;
                let mut broke = false;
                while j < args.len() && args[j].starts_with('-') && !sourced {
                    if !args[j].starts_with("--") && args[j][1..].contains('c') {
                        let inner = args.get(j + 1).map(|a| sw::unmark(a)).unwrap_or_default();
                        if let Some(h) =
                            self.analyze(&inner, here.clone(), env.clone(), depth + 1)?
                        {
                            return Ok(Some(h));
                        }
                        broke = true;
                        break;
                    }
                    j += 1;
                }
                if !broke && j < args.len() {
                    let text = self.script_text(sw::resolve(here.as_deref(), &args[j], &env)?);
                    if let Some(text) = text.filter(|t| !t.is_empty()) {
                        if let Some(h) =
                            self.analyze(&text, here.clone(), env.clone(), depth + 1)?
                        {
                            return Ok(Some(h));
                        }
                    }
                }
                i = k;
                continue;
            }
            if word == "xargs" {
                let mut j = i + 1;
                while j < w.len() && w[j].starts_with('-') {
                    j += if XARGS_OPT_WITH_VALUE.contains(&w[j].as_str()) {
                        2
                    } else {
                        1
                    };
                }
                at_start = true;
                i = j;
                continue;
            }
            if FILE_WRITERS.contains(&name) {
                if let Some(rel) = self.writes_locked_file(name, args, here.as_deref(), &env)? {
                    return Ok(Some(format!("write:{rel}")));
                }
                i = k;
                continue;
            }
            if let Some(text) = self.runs_shell_script(word, here.as_deref(), &env)? {
                if let Some(h) = self.analyze(&text, here.clone(), env.clone(), depth + 1)? {
                    return Ok(Some(h));
                }
                i = k;
                continue;
            }
            if name != "git" {
                i += 1;
                continue;
            }
            let mut d = here.clone();
            let mut git_dir = env.get("GIT_DIR").cloned();
            let mut work_tree = env.get("GIT_WORK_TREE").cloned();
            let mut overrides = env_config(&env);
            let mut j = i + 1;
            while j < w.len() && w[j].starts_with('-') {
                let opt = w[j].as_str();
                if opt.starts_with("--git-dir=") || opt.starts_with("--work-tree=") {
                    let (key, value) = partition(opt, '=');
                    if key == "--git-dir" {
                        git_dir = Some(value.to_string());
                    } else {
                        work_tree = Some(value.to_string());
                    }
                    j += 1;
                } else if ["-C", "--git-dir", "--work-tree"].contains(&opt) && j + 1 < w.len() {
                    match opt {
                        "-C" => d = sw::resolve(d.as_deref(), &w[j + 1], &env)?,
                        "--git-dir" => git_dir = Some(w[j + 1].clone()),
                        _ => work_tree = Some(w[j + 1].clone()),
                    }
                    j += 2;
                } else if opt == "-c" && j + 1 < w.len() {
                    overrides.push(config_pair(&w[j + 1]));
                    j += 2;
                } else if opt.starts_with("--config-env=")
                    || (opt == "--config-env" && j + 1 < w.len())
                {
                    let attached = opt.contains('=');
                    let spec = if attached {
                        partition(opt, '=').1
                    } else {
                        w[j + 1].as_str()
                    };
                    let (name, var) = spec.rsplit_once('=').unwrap_or(("", spec));
                    overrides.push((
                        name.to_lowercase(),
                        env.get(var).cloned().unwrap_or_default(),
                    ));
                    j += if attached { 1 } else { 2 };
                } else if GIT_OPT_WITH_VALUE.contains(&opt) && j + 1 < w.len() {
                    j += 2;
                } else {
                    j += 1;
                }
            }
            if let Some(wt) = work_tree.filter(|x| !x.is_empty()) {
                d = sw::resolve(d.as_deref(), &wt, &env)?;
            } else if let Some(gd) = git_dir.filter(|x| !x.is_empty()) {
                let g = sw::resolve(d.as_deref(), &gd, &env)?;
                if let Some(g) = g.filter(|g| !g.is_empty() && pyfs::basename(g) == ".git") {
                    d = Some(pyfs::dirname(&g));
                }
            }
            let sub: &[String] = if j < k { &w[j..k] } else { &[] };
            let mut hit = self.git_hit(sub, d.as_deref(), &env, &overrides)?;
            if hit.as_deref().is_some_and(|h| STAGING_ONLY.contains(&h))
                && self.private_index(env.get("GIT_INDEX_FILE"), d.as_deref(), &env)?
            {
                hit = None;
            }
            let machine_wide =
                j < k && w[j] == "config" && any_of(&w[j..k], &["--global", "--system"]);
            if let Some(h) = hit {
                if self.inside(d.as_deref()) || (h == "gc --prune=now" && machine_wide) {
                    return Ok(Some(h));
                }
            }
            i = k;
        }
        Ok(None)
    }

    // -------------------------------------------------------------- the write ledger

    /// `ledger_hit(command)`: the first use of the ledger folder or its override in what the command runs.
    fn ledger_hit(&self, command: &str, depth: usize) -> R<Option<String>> {
        if depth > MAX_NESTING {
            return Err("RecursionError: maximum recursion depth exceeded".into());
        }
        let mut code = Vec::new();
        let rest = sw::strip_comments(&sw::heredocs(command, Some(&mut code), &interp_feed));
        for body in &code {
            if let Some(m) = self.ledger_search(body) {
                return Ok(Some(m));
            }
        }
        for inner in sw::substitutions(&rest, "`$<>") {
            if let Some(h) = self.ledger_hit(&inner, depth + 1)? {
                return Ok(Some(h));
            }
        }
        let w = sw::words(&rest);
        let mut i = 0;
        while i < w.len() {
            let word = w[i].as_str();
            if word == "-m" || word == "--message" {
                i += 2;
                continue;
            }
            if !(word.starts_with("--message=") || (word.starts_with("-m") && word.len() > 2)) {
                if let Some(m) = self.ledger_search(word) {
                    return Ok(Some(m));
                }
            }
            i += 1;
        }
        Ok(None)
    }

    fn ledger_search(&self, text: &str) -> Option<String> {
        let pt = PyText::exact(text);
        self.cfg
            .ledger
            .find(&pt.t)
            .map(|m| pt.orig(m.start(), m.end()).to_string())
    }

    // -------------------------------------------------------------- interpreter writes

    /// `classify_literal(s, here, repo)`.
    fn classify_literal(&self, s: &str, here: &str) -> R<Option<Kind>> {
        let s = if s.starts_with("~/") {
            pyfs::expanduser(s)?
        } else {
            s.to_string()
        };
        let norm = s.replace('\\', "/");
        let segs: Vec<&str> = norm.split('/').filter(|x| !x.is_empty()).collect();
        let name = pyfs::basename(&self.repo);
        if segs.len() > 1 {
            if let Some(idx) = segs[..segs.len() - 1].iter().position(|x| *x == name) {
                if self.is_locked(segs[idx + 1]) {
                    return Ok(Some(Kind::Locked));
                }
            }
        }
        if s.starts_with("${") || s.starts_with('{') {
            return Ok(segs
                .iter()
                .any(|x| self.is_locked(x))
                .then_some(Kind::Locked));
        }
        let full = pyfs::normpath(&if s.starts_with('/') {
            s.clone()
        } else {
            pyfs::join(here, &s)
        });
        let rel = pyfs::relpath(&full, &self.repo)?;
        if !rel.starts_with("..") {
            let first = rel.split('/').next().unwrap_or("");
            if self.is_locked(first) {
                return Ok(Some(Kind::Locked));
            }
            if self.cfg.output.iter().any(|o| o == first) {
                return Ok(Some(Kind::Elsewhere));
            }
        }
        if !s.starts_with('/')
            && segs.first().is_some_and(|x| self.is_locked(x))
            && self.inside(Some(here))
        {
            return Ok(Some(Kind::Locked));
        }
        Ok(
            (rel.starts_with("..")
                && (s.starts_with('/') || s.starts_with('.') || s.contains('/')))
            .then_some(Kind::Elsewhere),
        )
    }

    /// `kinds(expr, here, repo)`: the path literals in expr, in order, each once.
    fn kinds(&self, expr: &str, here: &str) -> R<Vec<(Kind, String)>> {
        let mut out: Vec<(Kind, String)> = Vec::new();
        for lit in string_literals(expr) {
            if let Some(k) = self.classify_literal(&lit, here)? {
                if !out.iter().any(|(k2, l2)| *k2 == k && *l2 == lit) {
                    out.push((k, lit));
                }
            }
        }
        Ok(out)
    }

    /// (locked, elsewhere): variables holding a path in the locked folders, and variables holding an output path.
    fn path_names(&self, code: &str, here: &str) -> R<(BTreeSet<String>, BTreeSet<String>)> {
        let flat = code.replace(';', "\n");
        let mut pairs = assign_py(&flat);
        let pt = PyText::exact(&flat);
        for rx in [&*ASSIGN_JS, &*FOR_PY, &*FOR_JS] {
            for c in rx.captures_iter(&pt.t) {
                // INFALLIBLE: both groups are not optional in these patterns.
                let (a, b) = (c.get(1).unwrap(), c.get(2).unwrap());
                pairs.push((
                    pt.orig(a.start(), a.end()).to_string(),
                    pt.orig(b.start(), b.end()).to_string(),
                ));
            }
        }
        let (mut locked, mut elsewhere) = (BTreeSet::new(), BTreeSet::new());
        let mut changed = true;
        while changed {
            changed = false;
            for (name, rhs) in &pairs {
                if locked.contains(name) || elsewhere.contains(name) {
                    continue;
                }
                let ks: Vec<Kind> = self.kinds(rhs, here)?.into_iter().map(|k| k.0).collect();
                if ks.contains(&Kind::Elsewhere) || mentions(rhs, &elsewhere).is_some() {
                    elsewhere.insert(name.clone());
                    changed = true;
                } else if ks.contains(&Kind::Locked) || mentions(rhs, &locked).is_some() {
                    locked.insert(name.clone());
                    changed = true;
                }
            }
        }
        Ok((locked, elsewhere))
    }

    /// The locked literal or variable a write target names, unless it also names an output place.
    fn target_hit(
        &self,
        expr: &str,
        names: &(BTreeSet<String>, BTreeSet<String>),
        here: &str,
    ) -> R<Option<String>> {
        let ks = self.kinds(expr, here)?;
        if ks.iter().any(|(k, _)| *k == Kind::Elsewhere) || mentions(expr, &names.1).is_some() {
            return Ok(None);
        }
        Ok(ks
            .into_iter()
            .find(|(k, _)| *k == Kind::Locked)
            .map(|(_, l)| l)
            .or_else(|| mentions(expr, &names.0)))
    }

    /// What a piece of interpreter code writes in the locked folders (the literal or variable it writes through).
    fn interp_code_write(&self, code: &str, here: &str) -> R<Option<String>> {
        let names = self.path_names(code, here)?;
        let chars: Vec<char> = code.chars().collect();
        let pt = PyText::exact(code);
        let char_at = char_index(code);
        let not_ident = |prev: Option<char>| !prev.is_some_and(|c| py_word(c) || c == '$');
        for (_, end) in guarded_matches(&TARGET_FIRST, &pt, &not_ident) {
            let args = call_args(&chars, char_at[end]);
            if let Some(a) = args.first() {
                if let Some(h) = self.target_hit(a, &names, here)? {
                    return Ok(Some(h));
                }
            }
        }
        for (_, end) in guarded_matches(&TARGET_SECOND, &pt, &not_ident) {
            let args = call_args(&chars, char_at[end]);
            if args.len() > 1 {
                if let Some(h) = self.target_hit(&args[1], &names, here)? {
                    return Ok(Some(h));
                }
            }
        }
        let not_attr =
            |prev: Option<char>| !prev.is_some_and(|c| py_word(c) || c == '$' || c == '.');
        for (_, end) in guarded_matches(&FUNC_OPEN, &pt, &not_attr) {
            let args = call_args(&chars, char_at[end]);
            if !args.is_empty() && args[1..].iter().any(|a| is_write_mode(a)) {
                if let Some(h) = self.target_hit(&args[0], &names, here)? {
                    return Ok(Some(h));
                }
            }
        }
        for m in METHOD_WRITE.find_iter(&pt.t) {
            let (s, e) = (pt.pos(m.start()), pt.pos(m.end()));
            let matched = &code[s..e];
            let recv = receiver(&chars, char_at[s]);
            let args = call_args(&chars, char_at[e]);
            let hit = if matched.starts_with(".open") {
                let target = if args.len() > 1 && args[1..].iter().any(|a| is_write_mode(a)) {
                    args[0].clone()
                } else if !args.is_empty() && is_write_mode(&args[0]) {
                    recv
                } else {
                    continue;
                };
                self.target_hit(&target, &names, here)?
            } else if MODULES.contains(&recv.rsplit('.').next().unwrap_or("")) {
                continue;
            } else {
                match self.target_hit(&recv, &names, here)? {
                    Some(h) => Some(h),
                    None if (matched.starts_with(".rename") || matched.starts_with(".replace"))
                        && !args.is_empty() =>
                    {
                        self.target_hit(&args[0], &names, here)?
                    }
                    None => None,
                }
            };
            if hit.is_some() {
                return Ok(hit);
            }
        }
        for c in PERL_WRITE.captures_iter(&pt.t) {
            // INFALLIBLE: group 1 is not optional.
            let g = c.get(1).unwrap();
            if let Some(h) = self.target_hit(pt.orig(g.start(), g.end()), &names, here)? {
                return Ok(Some(h));
            }
        }
        for c in PERL_WRITE2.captures_iter(&pt.t) {
            // INFALLIBLE: one of the two alternatives' groups took part in the match.
            let g = c.get(1).or_else(|| c.get(2)).unwrap();
            let target = format!("\"{}\"", pyfs::py_strip(pt.orig(g.start(), g.end())));
            if let Some(h) = self.target_hit(&target, &names, here)? {
                return Ok(Some(h));
            }
        }
        Ok(None)
    }

    /// `interp_codes(command, here)`: (code, folder it runs in) for the interpreter code a command runs.
    fn interp_codes(&self, command: &str, here: &str, depth: usize) -> R<Vec<(String, String)>> {
        if depth > MAX_NESTING {
            return Err("RecursionError: maximum recursion depth exceeded".into());
        }
        let mut bodies = Vec::new();
        let rest = sw::strip_comments(&sw::heredocs(command, Some(&mut bodies), &|_| true));
        let mut out = Vec::new();
        for inner in sw::substitutions(&rest, "`$<>") {
            out.extend(self.interp_codes(&inner, here, depth + 1)?);
        }
        let w = sw::words(&rest);
        let marks: usize = w
            .iter()
            .filter(|t| sw::is_operator(t) && !t.contains("<<<"))
            .map(|t| t.matches("<<").count())
            .sum();
        let mut bodies = Some(bodies);
        if bodies.as_ref().is_some_and(|b| b.len() != marks) {
            // A heredoc the word splitter reads differently: every interpreter-fed body, from the starting folder.
            let mut fed = Vec::new();
            sw::heredocs(command, Some(&mut fed), &interp_feed);
            out.extend(fed.into_iter().map(|b| (b, here.to_string())));
            bodies = None;
        }
        let mut st = Codes {
            here: here.to_string(),
            parts: vec![Vec::new()],
            part_bodies: Vec::new(),
            out,
        };
        let mut stack: Vec<String> = Vec::new();
        let mut k = 0;
        for tok in w {
            if !sw::is_operator(&tok) {
                // INFALLIBLE: parts always holds at least one part.
                st.parts.last_mut().unwrap().push(tok);
                continue;
            }
            if let Some(b) = &bodies {
                if !tok.contains("<<<") {
                    for _ in 0..tok.matches("<<").count() {
                        st.part_bodies.push(b.get(k).cloned().unwrap_or_default());
                        k += 1;
                    }
                }
            }
            if sw::has_separator(&tok) || tok.contains(['\n', '(', ')']) {
                st.finish()?;
            } else if tok.contains('|') {
                st.parts.push(Vec::new());
            }
            for ch in tok.chars() {
                if ch == '(' {
                    stack.push(st.here.clone());
                } else if ch == ')' {
                    if let Some(h) = stack.pop() {
                        st.here = h;
                    }
                }
            }
        }
        st.finish()?;
        Ok(st.out)
    }

    /// The locked path or variable an interpreter in the command writes to.
    fn interp_write_hit(&self, command: &str, here: &str) -> R<Option<String>> {
        for (code, folder) in self.interp_codes(command, here, 0)? {
            if let Some(h) = self.interp_code_write(&code, &folder)? {
                return Ok(Some(h));
            }
        }
        Ok(None)
    }

    // -------------------------------------------------------------- the hook

    /// The block message and rule id for one Bash command, or None. `command` is the hook input's `command` after
    /// Python's `or ""`; `cwd` its `cwd` (None when missing or falsy).
    pub fn check(&self, command: &Value, cwd: Option<&Value>) -> R<Option<(String, String)>> {
        let cfg = self.cfg;
        let label = cfg.repo_label.as_str();
        if let Value::String(c) = command {
            if let Some(hit) = self.ledger_hit(c, 0)? {
                let msg = render(
                    &cfg.ledger_block,
                    &[
                        ("hit", &hit),
                        ("repo_label", label),
                        ("message", &cfg.ledger_message),
                    ],
                );
                return Ok(Some((msg, "ledger".into())));
            }
        }
        let cwd = match cwd {
            None => self.repo.clone(),
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err("TypeError: expected str, bytes or os.PathLike object".into()),
        };
        let here = pyfs::realpath(&cwd)?;
        let Value::String(command) = command else {
            return Err(format!(
                "AttributeError: '{}' object has no attribute 'split'",
                crate::hookio::py_type_name(command)
            ));
        };
        let env: Env = std::env::vars_os()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect();
        let Some(hit) = self.analyze(command, Some(here.clone()), env, 0)? else {
            if let Some(target) = self.interp_write_hit(command, &here)? {
                let msg = render(
                    &cfg.interp_block,
                    &[
                        ("target", &target),
                        ("repo_label", label),
                        ("message", &cfg.interp_message),
                    ],
                );
                return Ok(Some((msg, "interp".into())));
            }
            return Ok(None);
        };
        let prune = cfg
            .git_messages
            .get("gc --prune=now")
            .unwrap_or(&cfg.git_default_message);
        Ok(Some(if let Some(path) = hit.strip_prefix("write:") {
            (
                render(
                    &cfg.write_block,
                    &[
                        ("path", path),
                        ("repo_label", label),
                        ("message", &cfg.write_message),
                    ],
                ),
                "write".into(),
            )
        } else if let Some(at) = hit.strip_prefix("saved-prune:") {
            (
                render(
                    &cfg.saved_prune,
                    &[
                        ("repo_label", label),
                        ("where", at),
                        ("prune_message", prune),
                    ],
                ),
                "git:saved-prune".into(),
            )
        } else {
            let message = cfg
                .git_messages
                .get(&hit)
                .unwrap_or(&cfg.git_default_message);
            let advice = cfg.git_advice.get(&hit).unwrap_or(&cfg.git_default_advice);
            (
                render(
                    &cfg.git_block,
                    &[
                        ("op", &hit),
                        ("repo_label", label),
                        ("message", message),
                        ("advice", advice),
                    ],
                ),
                format!("git:{hit}"),
            )
        }))
    }
}

/// `interp_codes`' running state: the folder, the pipeline being read and the heredoc bodies it took.
struct Codes {
    here: String,
    parts: Vec<Vec<String>>,
    part_bodies: Vec<String>,
    out: Vec<(String, String)>,
}

impl Codes {
    fn finish(&mut self) -> R<()> {
        let first = &self.parts[0];
        if self.parts.len() == 1 && first.len() > 1 && (first[0] == "cd" || first[0] == "pushd") {
            let target = &first[1];
            if !target.contains(['$', '`', '*', '?']) {
                self.here = pyfs::realpath(&pyfs::join(&self.here, &pyfs::expanduser(target)?))?;
            }
        } else {
            let runs: Vec<(usize, Option<usize>)> = self
                .parts
                .iter()
                .enumerate()
                .map(|(n, p)| (n, interp_at(p)))
                .collect();
            if runs.iter().any(|(_, i)| i.is_some()) {
                for b in &self.part_bodies {
                    self.out.push((b.clone(), self.here.clone()));
                }
                for (n, i) in runs {
                    if let Some(i) = i {
                        if let Some(c) = inline_code(&self.parts[n], i).filter(|c| !c.is_empty()) {
                            self.out.push((c, self.here.clone()));
                        }
                    }
                }
            }
        }
        self.parts = vec![Vec::new()];
        self.part_bodies.clear();
        Ok(())
    }
}

/// `INTERP_FEED.search(seg)`: a shell or an interpreter runs the heredoc.
fn interp_feed(seg: &str) -> bool {
    INTERP_FEED.is_match(&PyText::exact(seg).t)
}

/// `INTERP.match(name)` for `^(?:python[0-9.]*|node|deno|bun|perl|ruby)$`.
fn is_interp(name: &str) -> bool {
    let n = name.strip_suffix('\n').unwrap_or(name);
    ["node", "deno", "bun", "perl", "ruby"].contains(&n)
        || n.strip_prefix("python")
            .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// Index of the interpreter in one pipeline part when it is the command, else None.
fn interp_at(part: &[String]) -> Option<usize> {
    let mut skip_next = false;
    for (i, x) in part.iter().enumerate() {
        if skip_next
            || sw::assign(x).is_some()
            || sw::PREFIXES.contains(&x.as_str())
            || x == "uv"
            || x == "run"
            || x.starts_with('-')
            || sw::py_isdigit(x)
        {
            skip_next = ["--with", "--python", "-p"].contains(&x.as_str()) && !skip_next;
            continue;
        }
        return is_interp(pyfs::basename(x)).then_some(i);
    }
    None
}

/// The -c/-e/--eval code given to the interpreter at part[i].
fn inline_code(part: &[String], i: usize) -> Option<String> {
    for j in i + 1..part.len() {
        let w = &part[j];
        if INLINE_CODE_OPTS.contains(&w.as_str()) && j + 1 < part.len() {
            return Some(part[j + 1].clone());
        }
        if w.starts_with("--eval=") || w.starts_with("--print=") {
            return Some(partition(w, '=').1.to_string());
        }
        if !w.starts_with('-') {
            return None;
        }
    }
    None
}

/// ASSIGN_PY (`^[ \t]*([A-Za-z_]\w*)(?:[ \t]*:[^=\n]+)?[ \t]*=(?!=)[ \t]*(.+)$`, re.M) line by line, with the
/// backtracking worked out: (name, value).
fn assign_py(flat: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in flat.split('\n') {
        let c: Vec<char> = line.chars().collect();
        let n = c.len();
        let mut i = 0;
        while i < n && (c[i] == ' ' || c[i] == '\t') {
            i += 1;
        }
        if !(i < n && (c[i].is_ascii_alphabetic() || c[i] == '_')) {
            continue;
        }
        let start = i;
        i += 1;
        while i < n && py_word(c[i]) {
            i += 1;
        }
        let name: String = c[start..i].iter().collect();
        let mut j = i;
        while j < n && (c[j] == ' ' || c[j] == '\t') {
            j += 1;
        }
        let eq = if j < n && c[j] == ':' {
            // the annotation runs to the first '=', at least one character
            match c[j + 1..].iter().position(|&x| x == '=') {
                Some(p) if p >= 1 => j + 1 + p,
                _ => continue,
            }
        } else if j < n && c[j] == '=' {
            j
        } else {
            continue;
        };
        if c.get(eq + 1) == Some(&'=') {
            continue;
        }
        let rest = &c[eq + 1..];
        if rest.is_empty() {
            continue;
        }
        let lead = rest.iter().take_while(|&&x| x == ' ' || x == '\t').count();
        let value: String = if lead < rest.len() {
            rest[lead..].iter().collect()
        } else {
            rest[rest.len() - 1..].iter().collect()
        };
        out.push((name, value));
    }
    out
}

/// STRING (`(?<![\w$])(?:[rRbBuUfF]{1,2})?("|'|`)((?:\\.|(?!\1)[^\\])*)\1`, re.S) finditer: the bodies.
fn string_literals(expr: &str) -> Vec<String> {
    let c: Vec<char> = expr.chars().collect();
    let n = c.len();
    let mut out = Vec::new();
    let mut p = 0;
    while p < n {
        if p > 0 && (py_word(c[p - 1]) || c[p - 1] == '$') {
            p += 1;
            continue;
        }
        let mut k = 0;
        while k < 2 && p + k < n && "rRbBuUfF".contains(c[p + k]) {
            k += 1;
        }
        let qpos = p + k;
        if qpos < n && "\"'`".contains(c[qpos]) {
            let q = c[qpos];
            let mut j = qpos + 1;
            let mut closed = None;
            while j < n {
                if c[j] == '\\' {
                    if j + 1 < n {
                        j += 2;
                        continue;
                    }
                    break;
                }
                if c[j] == q {
                    closed = Some(j);
                    break;
                }
                j += 1;
            }
            if let Some(e) = closed {
                out.push(c[qpos + 1..e].iter().collect());
                p = e + 1;
                continue;
            }
        }
        p += 1;
    }
    out
}

/// `mentions(expr, names)`: the first name (sorted) used as a whole identifier in expr.
fn mentions(expr: &str, names: &BTreeSet<String>) -> Option<String> {
    let c: Vec<char> = expr.chars().collect();
    names
        .iter()
        .find(|n| {
            let nc: Vec<char> = n.chars().collect();
            !nc.is_empty()
                && (0..c.len()).any(|p| {
                    p + nc.len() <= c.len()
                        && c[p..p + nc.len()] == nc[..]
                        && !(p > 0 && (py_word(c[p - 1]) || c[p - 1] == '$' || c[p - 1] == '.'))
                        && !c.get(p + nc.len()).is_some_and(|&x| py_word(x) || x == '$')
                })
        })
        .cloned()
}

/// Byte offset -> character index for `s` (one past the end included).
fn char_index(s: &str) -> Vec<usize> {
    let mut map = vec![0; s.len() + 1];
    let mut n = 0;
    for (i, ch) in s.char_indices() {
        for b in 0..ch.len_utf8() {
            map[i + b] = n;
        }
        n += 1;
    }
    map[s.len()] = n;
    map
}

/// `finditer` for a pattern that starts with a lookbehind: matches whose preceding character `ok` accepts, as
/// byte ranges of the original; a refused start is retried one character later, as Python's scan does.
fn guarded_matches(
    rx: &Regex,
    pt: &PyText,
    ok: &dyn Fn(Option<char>) -> bool,
) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at <= pt.t.len() {
        let Some(m) = rx.find_at(&pt.t, at) else {
            break;
        };
        let s = pt.pos(m.start());
        if ok(pt.orig[..s].chars().next_back()) {
            out.push((s, pt.pos(m.end())));
            at = m.end().max(m.start() + 1);
        } else {
            at = m.start() + pt.t[m.start()..].chars().next().map_or(1, char::len_utf8);
        }
    }
    out
}

/// Top-level arguments of the call whose "(" ends at code[start].
fn call_args(code: &[char], start: usize) -> Vec<String> {
    let mut args = Vec::new();
    let (mut depth, mut cur, mut i, mut q) = (0usize, String::new(), start, None::<char>);
    while i < code.len() {
        let c = code[i];
        if let Some(qc) = q {
            cur.push(c);
            if c == '\\' && i + 1 < code.len() {
                cur.push(code[i + 1]);
                i += 1;
            } else if c == qc {
                q = None;
            }
        } else if "'\"`".contains(c) {
            q = Some(c);
            cur.push(c);
        } else if "([{".contains(c) {
            depth += 1;
            cur.push(c);
        } else if ")]}".contains(c) {
            if depth == 0 {
                break;
            }
            depth -= 1;
            cur.push(c);
        } else if c == ',' && depth == 0 {
            args.push(pyfs::py_strip(&cur).to_string());
            cur.clear();
        } else {
            cur.push(c);
        }
        i += 1;
    }
    args.push(pyfs::py_strip(&cur).to_string());
    args.into_iter().filter(|a| !a.is_empty()).collect()
}

/// The expression a method is called on.
fn receiver(code: &[char], dot: usize) -> String {
    let (mut i, mut depth) = (dot, 0usize);
    while i > 0 {
        let c = code[i - 1];
        if ")]".contains(c) {
            depth += 1;
        } else if "([".contains(c) {
            if depth == 0 {
                break;
            }
            depth -= 1;
        } else if depth == 0 && !(py_word(c) || "_.$".contains(c)) {
            break;
        }
        i -= 1;
    }
    code[i..dot].iter().collect()
}

fn is_write_mode(arg: &str) -> bool {
    let s = pyfs::py_strip(arg);
    let pt = PyText::exact(s);
    let mode = MODE.captures(&pt.t).is_some_and(|c| {
        // INFALLIBLE: group 1 is not optional.
        let g = c.get(1).unwrap();
        pt.orig(g.start(), g.end()).contains(['w', 'a', 'x', '+'])
    });
    mode || OS_FLAGS.is_match(&PyText::exact(arg).t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_assignments() {
        assert_eq!(
            string_literals("open('a', \"b\") x'c' f'd' $'e' rb'g'"),
            ["a", "b", "d", "g"]
        );
        assert_eq!(string_literals("'a\\'b' 'open"), ["a\\'b"]);
        assert_eq!(
            assign_py("x = 'a'\ny: str = b\nz == 1\nw =   \nv=\n  u=1"),
            [
                ("x".to_string(), "'a'".to_string()),
                ("y".into(), "b".into()),
                ("w".into(), " ".into()),
                ("u".into(), "1".into())
            ]
        );
        let names: BTreeSet<String> = ["p".to_string(), "q".into()].into_iter().collect();
        assert_eq!(mentions("open(q, 'w')", &names).as_deref(), Some("q"));
        assert_eq!(mentions("x.p + $p + pp", &names), None);
    }

    #[test]
    fn calls_modes_and_receivers() {
        let c: Vec<char> = "f(a, g(b, c), 'x,y', )".chars().collect();
        assert_eq!(call_args(&c, 2), ["a", "g(b, c)", "'x,y'"]);
        let c: Vec<char> = "Path(p).write_text(x)".chars().collect();
        assert_eq!(receiver(&c, 7), "Path(p)");
        assert!(is_write_mode("'w'") && is_write_mode("mode='a+'") && is_write_mode("flags: 'w'"));
        assert!(!is_write_mode("'r'") && !is_write_mode("encoding='utf-8'"));
        assert!(is_write_mode("os.O_WRONLY | os.O_CREAT"));
        assert!(is_interp("python3.12") && is_interp("node\n") && !is_interp("pythonw"));
    }

    #[test]
    fn git_config_overrides() {
        let mut env = Env::new();
        env.insert(
            "GIT_CONFIG_PARAMETERS".into(),
            "'gc.pruneExpire'='now' 'core.x=1'".into(),
        );
        env.insert("GIT_CONFIG_COUNT".into(), "1".into());
        env.insert("GIT_CONFIG_KEY_0".into(), "GC.ReflogExpire".into());
        env.insert("GIT_CONFIG_VALUE_0".into(), " All ".into());
        let p = env_config(&env);
        assert_eq!(p[0], ("gc.pruneexpire".to_string(), "now".to_string()));
        assert_eq!(p[1], ("core.x".to_string(), "1".to_string()));
        assert!(prunes_now(&p[2..]));
        assert!(prunes_now(&[(
            "gc.foo.reflogexpireunreachable".into(),
            "0".into()
        )]));
        assert!(!prunes_now(&[("gc.auto".into(), "now".into())]));
    }

    #[test]
    fn render_is_one_pass() {
        assert_eq!(
            render("a {x} {y} {z}", &[("x", "{y}"), ("y", "2")]),
            "a {y} 2 {z}"
        );
    }

    #[test]
    fn splitlines_like_python() {
        assert_eq!(py_splitlines("a\r\nb\x1cc\n"), ["a", "b", "c"]);
        assert_eq!(py_splitlines(""), Vec::<&str>::new());
    }
}
