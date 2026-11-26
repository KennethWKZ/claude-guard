//! Script files a command runs, read from disk so every rule holds inside them (Rust only, newline pass):
//! `bash|sh|zsh|dash|ksh FILE`, `source FILE`, `. FILE`, `./FILE` or `/path/FILE` as the command (also behind argv
//! wrappers), `cat FILE... | bash`, `bash < FILE`.
//!
//! - A path is read relative to the hook's `cwd`, with `~` and `$HOME` expanded. A missing file, a directory, or a
//!   relative path with no text `cwd` is not read (the command is checked as written).
//! - Only scripts Claude could have written are read: inside `cwd` (the project) or a temp folder (`/tmp`,
//!   `$TMPDIR`). Tools and dotfiles elsewhere (`/opt/homebrew/bin/brew`, `~/.zshrc`) are not, so their own internals
//!   don't trip the rules. A `cwd` of the home folder or `/` is too broad to count; then only temp folders do.
//! - Binaries are not scripts: ELF and Mach-O headers, or a NUL byte in the first 8 KiB.
//! - Run as the command itself (`./x`), a file counts only with a shell shebang (`#!/bin/bash`,
//!   `#!/usr/bin/env -S zsh -e`) or none (the kernel hands it to sh); `#!/usr/bin/env node` is not a shell script.
//!   Fed to a shell explicitly (`bash x.py`, `cat x | sh`), any text file counts.
//! - Over `MAX_SCRIPT` bytes, the command is blocked (fail closed) rather than checked in part.
//! - A file already being checked (`a.sh` sources `b.sh`, which sources `a.sh`) is not read again.
//!
//! The file can change between this check and the run; the guard checks what is on disk when the command is sent.

use std::cell::RefCell;
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

pub(super) const MAX_SCRIPT: u64 = 256 * 1024;
const SNIFF: usize = 8 * 1024;
const SHELL_NAMES: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];

pub(super) enum Script {
    /// The text to check, and the canonical path (for `enter`/`leave`).
    Text(String, PathBuf),
    /// Too big to check: the path as written.
    TooBig(String),
    Skip,
}

thread_local! {
    static OPEN: RefCell<HashSet<PathBuf>> = RefCell::new(HashSet::new());
}

/// Marks `path` as being checked; false if it already is (a cycle).
pub(super) fn enter(path: &Path) -> bool {
    OPEN.with(|o| o.borrow_mut().insert(path.to_path_buf()))
}

pub(super) fn leave(path: &Path) {
    OPEN.with(|o| {
        o.borrow_mut().remove(path);
    });
}

fn is_binary(head: &[u8]) -> bool {
    const MAGICS: &[&[u8]] = &[
        b"\x7fELF",
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xfe\xed\xfa\xce",
        b"\xca\xfe\xba\xbe",
    ];
    MAGICS.iter().any(|m| head.starts_with(m)) || head.contains(&0)
}

/// True if the first line names a shell, or there is no shebang.
fn shell_shebang(head: &[u8]) -> bool {
    let Some(rest) = head.strip_prefix(b"#!") else {
        return true;
    };
    let line = String::from_utf8_lossy(rest.split(|b| *b == b'\n').next().unwrap_or(b""));
    let mut words = line.split_whitespace();
    let Some(first) = words.next() else {
        return true;
    };
    let mut prog = first.rsplit('/').next().unwrap_or(first);
    if prog == "env" {
        prog = words.find(|w| !w.starts_with('-')).unwrap_or("");
        prog = prog.rsplit('/').next().unwrap_or(prog);
    }
    SHELL_NAMES.contains(&prog)
}

/// Reads `file` as a script to check. `explicit`: fed to a shell by name or on stdin, so any text file counts;
/// otherwise run as the command, so only a shell script does.
pub(super) fn read_script(file: &str, cwd: Option<&str>, explicit: bool) -> Script {
    let expanded = super::home_path(file);
    let path = if expanded.starts_with('/') {
        PathBuf::from(&expanded)
    } else {
        match cwd {
            Some(c) => Path::new(c).join(&expanded),
            None => return Script::Skip,
        }
    };
    let Ok(meta) = std::fs::metadata(&path) else {
        return Script::Skip;
    };
    if !meta.is_file() {
        return Script::Skip;
    }
    let Ok(mut f) = std::fs::File::open(&path) else {
        return Script::Skip;
    };
    let mut head = vec![0u8; SNIFF];
    let n = f.read(&mut head).unwrap_or(0);
    head.truncate(n);
    if is_binary(&head) || (!explicit && !shell_shebang(&head)) {
        return Script::Skip;
    }
    let canon = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    if !in_allowed_root(&canon, cwd) {
        return Script::Skip;
    }
    if meta.len() > MAX_SCRIPT {
        return Script::TooBig(file.to_string());
    }
    let mut rest = Vec::new();
    if f.take(MAX_SCRIPT).read_to_end(&mut rest).is_err() {
        return Script::Skip;
    }
    head.extend(rest);
    Script::Text(String::from_utf8_lossy(&head).into_owned(), canon)
}

/// True if `canon` is inside the project (`cwd`, unless it is the home folder or `/`) or a temp folder.
fn in_allowed_root(canon: &Path, cwd: Option<&str>) -> bool {
    let canon_of = |p: &str| std::fs::canonicalize(p).ok();
    let mut roots: Vec<PathBuf> = [
        "/tmp".to_string(),
        std::env::var("TMPDIR").unwrap_or_default(),
    ]
    .iter()
    .filter(|p| !p.is_empty())
    .filter_map(|p| canon_of(p))
    .collect();
    if let Some(c) = cwd.and_then(canon_of) {
        let home = canon_of(&super::home());
        if c != Path::new("/") && Some(&c) != home.as_ref() {
            roots.push(c);
        }
    }
    roots.iter().any(|r| canon.starts_with(r))
}

/// The reason to block a script too big to check.
pub(super) fn too_big_reason(file: &str) -> String {
    format!(
        "{file} is a script over {} KiB, too big for the guard to check. Run it yourself with ! after reading it.",
        MAX_SCRIPT / 1024
    )
}
