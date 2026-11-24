//! `claude-guard husky`: copy husky's .husky/_ and graphmind's git hook files into git worktrees, ported from
//! husky-worktree-hooks.py.
//!
//! In a husky repo, .husky/_ is git-ignored, so a new worktree doesn't get it and its hooks silently don't run.
//! Where graphmind is set up, its hooks are untracked files in the main checkout's .husky/ (post-commit,
//! post-checkout, post-merge, post-rewrite, pre-push, each holding a "# graphmind:" line). Runs as:
//!   PostToolUse  Bash|EnterWorktree  after a command that mentions "worktree add"
//!   SessionStart                     for the repo the session starts in
//! For every repo it finds from the hook input it reads the worktree list from <common git dir>/worktrees/*/gitdir
//! and copies into each worktree that lacks them: the main checkout's .husky/_ and its graphmind hook files.
//!
//! It never runs git, project code or anything from the repo; it only reads and copies files, never overwrites
//! one, and always exits 0. Errors go to ~/.local/state/claude-guard/husky.log. `plan` does the same walk
//! without copying (shadow mode).

use crate::hookio::{self, py_truthy, py_type_name};
use crate::{pyfs, shlex};
use regex::Regex;
use serde_json::Value;
use std::fs;
use std::sync::LazyLock;

const HOOKS: &[&str] = &[
    "post-commit",
    "post-checkout",
    "post-merge",
    "post-rewrite",
    "pre-push",
];
const MARKER: &str = "# graphmind:";

static WORKTREE_ADD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bworktree\s+add\b").unwrap());
static GITDIR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^gitdir:\s*(.+)").unwrap());

type R<T> = Result<T, String>;

/// One copy the hook makes (or would make): the worktree root and what goes into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Copy {
    pub root: String,
    pub items: Vec<String>, // ".husky/_" and/or hook names
}

fn read(path: &str) -> R<String> {
    pyfs::read_text(path, 4096)
}

/// Walk up from start to the repo's common git dir, by reading files only.
fn common_git_dir(start: &str) -> R<Option<String>> {
    let mut d = pyfs::abspath(start)?;
    loop {
        let dot = pyfs::join(&d, ".git");
        if pyfs::isdir(&dot) {
            return Ok(Some(dot));
        }
        if pyfs::isfile(&dot) {
            let text = read(&dot)?;
            let Some(m) = GITDIR.captures(pyfs::py_strip(&text)) else {
                return Ok(None);
            };
            let mut gitdir = pyfs::py_strip(m.get(1).unwrap().as_str()).to_string();
            if !gitdir.starts_with('/') {
                gitdir = pyfs::normpath(&pyfs::join(&d, &gitdir));
            }
            let common = read(&pyfs::join(&gitdir, "commondir"))?;
            let common = pyfs::py_strip(&common);
            if !common.is_empty() {
                return Ok(Some(pyfs::normpath(&pyfs::join(&gitdir, common))));
            }
            return Ok(Some(gitdir));
        }
        let parent = pyfs::dirname(&d);
        if parent == d {
            return Ok(None);
        }
        d = parent;
    }
}

fn worktree_roots(common: &str) -> R<Vec<String>> {
    let base = pyfs::join(common, "worktrees");
    if base.contains('\0') {
        return Err("ValueError: embedded null byte".into());
    }
    let Ok(rd) = fs::read_dir(&base) else {
        return Ok(Vec::new());
    };
    let mut roots = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let gitfile = read(&pyfs::join(&pyfs::join(&base, &name), "gitdir"))?;
        let gitfile = pyfs::py_strip(&gitfile);
        if !gitfile.is_empty() {
            let root = pyfs::dirname(gitfile);
            if pyfs::isdir(&root) {
                roots.push(root);
            }
        }
    }
    Ok(roots)
}

/// shutil.copystat for what matters here: permission bits and access/modify times.
fn copystat(src: &str, dst: &str) -> R<()> {
    // Times first, then the mode (Python's order), so a mode without read access can't stop the time change.
    let m = fs::metadata(src).map_err(|e| format!("OSError: {e}"))?;
    let times = fs::FileTimes::new()
        .set_accessed(m.accessed().map_err(|e| e.to_string())?)
        .set_modified(m.modified().map_err(|e| e.to_string())?);
    fs::File::open(dst)
        .and_then(|f| f.set_times(times))
        .map_err(|e| format!("OSError: {e}"))?;
    fs::set_permissions(dst, m.permissions()).map_err(|e| format!("OSError: {e}"))
}

/// shutil.copy2: data (no extended attributes, as Python's copyfile on macOS), then mode and times.
fn copy2(src: &str, dst: &str) -> R<()> {
    let mut from = fs::File::open(src).map_err(|e| format!("OSError: {e}"))?;
    let mut to = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)
        .map_err(|e| format!("OSError: {e}"))?;
    std::io::copy(&mut from, &mut to).map_err(|e| format!("OSError: {e}"))?;
    drop(to);
    copystat(src, dst)
}

/// shutil.copytree(src, dst, symlinks=True): links copied as links; errors collected, raised at the end.
fn copytree(src: &str, dst: &str) -> R<()> {
    fs::create_dir_all(dst).map_err(|e| format!("OSError: {e}"))?;
    let mut errors = Vec::new();
    let rd = fs::read_dir(src).map_err(|e| format!("OSError: {e}"))?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let (s, d) = (pyfs::join(src, &name), pyfs::join(dst, &name));
        let ft = match e.file_type() {
            Ok(t) => t,
            Err(err) => {
                errors.push(err.to_string());
                continue;
            }
        };
        let r = if ft.is_symlink() {
            fs::read_link(&s)
                .and_then(|t| std::os::unix::fs::symlink(t, &d))
                .map_err(|e| e.to_string())
        } else if fs::metadata(&s).is_ok_and(|m| m.is_dir()) {
            copytree(&s, &d)
        } else {
            copy2(&s, &d)
        };
        if let Err(err) = r {
            errors.push(err);
        }
    }
    if let Err(err) = copystat(src, dst) {
        errors.push(err);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("shutil.Error: {}", errors.join("; ")))
    }
}

/// Copy (or, with `dry`, list) .husky/_ and graphmind hook files into worktrees missing them.
fn sync_repo(common: &str, dry: bool) -> R<Vec<Copy>> {
    let main = pyfs::dirname(common);
    let src_husky = pyfs::join(&main, ".husky");
    let src_underscore = pyfs::join(&src_husky, "_");
    let has_underscore = pyfs::isdir(&src_underscore);
    let mut hooks = Vec::new();
    for h in HOOKS {
        if read(&pyfs::join(&src_husky, h))?.contains(MARKER) {
            hooks.push(*h);
        }
    }
    if hooks.is_empty() && !has_underscore {
        return Ok(Vec::new());
    }
    let mut done = Vec::new();
    for root in worktree_roots(common)? {
        let dst_husky = pyfs::join(&root, ".husky");
        if pyfs::realpath(&root)? == pyfs::realpath(&main)? || !pyfs::isdir(&dst_husky) {
            continue;
        }
        let mut items = Vec::new();
        let dst_underscore = pyfs::join(&dst_husky, "_");
        if has_underscore && !pyfs::lexists(&dst_underscore) {
            if !dry {
                copytree(&src_underscore, &dst_underscore)?;
            }
            items.push(".husky/_".to_string());
        }
        for h in &hooks {
            let dst = pyfs::join(&dst_husky, h);
            if !pyfs::lexists(&dst) {
                if !dry {
                    copy2(&pyfs::join(&src_husky, h), &dst)?;
                }
                items.push(h.to_string());
            }
        }
        if !items.is_empty() {
            done.push(Copy { root, items });
        }
    }
    Ok(done)
}

/// A candidate folder: a path, or a non-string `cwd` as Python saw it (os.path.isdir on an int checks a file
/// descriptor and says no; on a float, list or dict it raises).
enum Dir {
    Path(String),
    NotStr(&'static str),
}

/// `(data.get("tool_input") or {}).get("command") or ""`
fn command_of(data: &serde_json::Map<String, Value>) -> R<String> {
    let ti = data.get("tool_input").filter(|v| py_truthy(v));
    let cmd = match ti {
        None => return Ok(String::new()),
        Some(Value::Object(o)) => o.get("command").cloned().unwrap_or(Value::Null),
        Some(other) => {
            return Err(format!(
                "AttributeError: '{}' object has no attribute 'get'",
                py_type_name(other)
            ));
        }
    };
    match cmd {
        Value::String(s) => Ok(s),
        v if !py_truthy(&v) => Ok(String::new()),
        other => Err(format!(
            "TypeError: expected string or bytes-like object, got {}",
            py_type_name(&other)
        )),
    }
}

fn candidate_dirs(data: &serde_json::Map<String, Value>) -> R<Vec<Dir>> {
    let cwd = match data.get("cwd").filter(|v| py_truthy(v)) {
        Some(Value::String(s)) => Dir::Path(s.clone()),
        Some(other) => Dir::NotStr(py_type_name(other)),
        None => Dir::Path(pyfs::cwd()?),
    };
    let is_bash = data.get("hook_event_name").and_then(Value::as_str) == Some("PostToolUse")
        && data.get("tool_name").and_then(Value::as_str) == Some("Bash");
    let mut extra = Vec::new();
    if is_bash {
        let cmd = command_of(data)?;
        let words: Vec<String> = match shlex::split_plain(&cmd) {
            Ok(w) => w,
            Err(_) => cmd
                .split(pyfs::py_isspace)
                .filter(|w| !w.is_empty())
                .map(str::to_string)
                .collect(),
        };
        for i in 0..words.len().saturating_sub(1) {
            let w = words[i].as_str();
            if w == "-C" || w == "cd" || (w == "add" && i > 0 && words[i - 1] == "worktree") {
                let p = pyfs::expanduser(&words[i + 1])?;
                if p.starts_with('/') {
                    extra.push(Dir::Path(p));
                } else {
                    match &cwd {
                        Dir::Path(c) => extra.push(Dir::Path(pyfs::join(c, &p))),
                        Dir::NotStr(t) => {
                            return Err(format!(
                                "TypeError: expected str, bytes or os.PathLike object, not {t}"
                            ));
                        }
                    }
                }
            }
        }
    }
    let mut dirs = vec![cwd];
    dirs.extend(extra);
    Ok(dirs)
}

fn run(data: &serde_json::Map<String, Value>, dry: bool) -> R<Vec<Copy>> {
    if data.get("hook_event_name").and_then(Value::as_str) == Some("PostToolUse")
        && data.get("tool_name").and_then(Value::as_str) == Some("Bash")
    {
        let cmd = command_of(data)?;
        if !WORKTREE_ADD.is_match(&cmd) {
            return Ok(Vec::new());
        }
    }
    let mut seen: Vec<String> = Vec::new();
    let mut done = Vec::new();
    for d in candidate_dirs(data)? {
        let d = match d {
            Dir::Path(p) => p,
            Dir::NotStr("int") | Dir::NotStr("bool") => continue,
            Dir::NotStr(t) => {
                return Err(format!(
                    "TypeError: stat: path should be string, bytes, os.PathLike or integer, not {t}"
                ));
            }
        };
        if !pyfs::isdir(&d) {
            continue;
        }
        if let Some(common) = common_git_dir(&d)? {
            if !seen.contains(&common) {
                seen.push(common.clone());
                done.extend(sync_repo(&common, dry)?);
            }
        }
    }
    Ok(done)
}

pub enum Outcome {
    /// Nothing to report (no copies, or not a worktree command).
    Quiet,
    /// Copies made: the JSON line to print.
    Copied(String, Vec<Copy>),
    /// Python's hook raised: logged, nothing printed.
    Error(String),
}

fn message(event: &Value, done: &[Copy]) -> String {
    let parts: Vec<String> = done
        .iter()
        .map(|c| format!("{} ({})", c.root, c.items.join(", ")))
        .collect();
    let msg = format!(
        "husky/graphmind hooks copied into worktree(s): {}",
        parts.join("; ")
    );
    format!(
        "{{\"hookSpecificOutput\": {{\"hookEventName\": {}, \"additionalContext\": {}}}}}",
        hookio::py_dumps(event),
        hookio::py_str(&msg)
    )
}

/// Run the hook for one input. `dry`: report what would be copied without copying.
pub fn decide(input: &[u8], dry: bool) -> Outcome {
    let Some(v) = hookio::parse(input) else {
        return Outcome::Error("JSONDecodeError".into());
    };
    let Value::Object(data) = v else {
        return Outcome::Error(format!(
            "AttributeError: '{}' object has no attribute 'get'",
            py_type_name(&v)
        ));
    };
    let event = data
        .get("hook_event_name")
        .cloned()
        .unwrap_or(Value::String(String::new()));
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&data, dry))) {
        Ok(Ok(done)) if done.is_empty() => Outcome::Quiet,
        Ok(Ok(done)) => Outcome::Copied(message(&event, &done), done),
        Ok(Err(e)) => Outcome::Error(e),
        Err(_) => Outcome::Error("panic".into()),
    }
}

fn log(error: &str) {
    let path = format!(
        "{}/.local/state/claude-guard/husky.log",
        std::env::var("HOME").unwrap_or_else(|_| "/".into())
    );
    crate::logfile::append(
        &path,
        &format!(
            "--- {} claude-guard {}\n{}\n",
            crate::now_utc(),
            env!("CARGO_PKG_VERSION"),
            error
        ),
        crate::logfile::CRASH_CAP,
    );
}

/// Print and log the way husky-worktree-hooks.py did; always exit 0.
pub fn emit(o: &Outcome) -> i32 {
    match o {
        Outcome::Quiet => {}
        Outcome::Copied(line, _) => println!("{line}"),
        Outcome::Error(e) => log(e),
    }
    0
}
