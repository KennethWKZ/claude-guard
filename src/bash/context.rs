//! What a check knows about the command around the code it reads, for interpreter code that takes values from the
//! environment or from files (`os.environ["CMD"]`, `open("cmd.txt").read()`).
//!
//! A frame per check (`push`, popped when the guard drops): the variables the command assigns (`CMD=... python3`,
//! `export CMD=...`, `CMD=...;`), the hook's `cwd`, and files written earlier in the same command (`echo ... >
//! cmd.txt`, `cat > cmd.txt <<EOF`). Nested checks see their outer frames too.
//!
//! The hook can't see the environment the command will really run in, so a variable the command doesn't set is
//! unknown (no value), not a guess.

use regex::Regex;
use std::cell::RefCell;
use std::sync::LazyLock;

#[derive(Default)]
struct Frame {
    vars: Vec<(String, String)>,
    cwd: Option<String>,
    written: Vec<(String, String)>,
}

thread_local! {
    static FRAMES: RefCell<Vec<Frame>> = const { RefCell::new(Vec::new()) };
}

/// Pops its frame when dropped.
pub(super) struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        FRAMES.with(|f| {
            f.borrow_mut().pop();
        });
    }
}

static ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
    super::re(
        r#"(?:^|[\s;&|(])(?:export\s+)?([A-Za-z_]\w*)=(?:'([^']*)'|"((?:[^"\\]|\\.)*)"|([^\s;&|)]*))"#,
    )
});

/// A frame for checking `command` (its variable assignments) in `cwd`.
pub(super) fn push(command: &str, cwd: Option<&str>) -> Guard {
    let vars = ASSIGN
        .captures_iter(command)
        .map(|c| {
            let v = c
                .get(2)
                .or_else(|| c.get(3))
                .or_else(|| c.get(4))
                .map(|m| m.as_str())
                .unwrap_or("");
            (c[1].to_string(), v.to_string())
        })
        .collect();
    FRAMES.with(|f| {
        f.borrow_mut().push(Frame {
            vars,
            cwd: cwd.map(str::to_string),
            written: Vec::new(),
        })
    });
    Guard
}

/// Files the command writes (`echo ... > f`, `cat > f <<EOF`), for later reads in the same command.
pub(super) fn add_written(files: &[(String, String)]) {
    FRAMES.with(|f| {
        if let Some(top) = f.borrow_mut().last_mut() {
            for w in files {
                if !top.written.contains(w) {
                    top.written.push(w.clone());
                }
            }
        }
    });
}

/// The value the command gives environment variable `name`, innermost frame first.
pub(super) fn var(name: &str) -> Option<String> {
    FRAMES.with(|f| {
        f.borrow().iter().rev().find_map(|fr| {
            fr.vars
                .iter()
                .rev()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        })
    })
}

/// The text of file `path`: written earlier in the command, else read from disk under the script rules (project
/// or temp folder, not third-party, at most 256 KiB, text).
pub(super) fn file(path: &str) -> Option<String> {
    let (written, cwd) = FRAMES.with(|f| {
        let f = f.borrow();
        let w = f.iter().rev().find_map(|fr| {
            fr.written
                .iter()
                .rev()
                .find(|(p, _)| p.trim_start_matches("./") == path.trim_start_matches("./"))
                .map(|(_, t)| t.clone())
        });
        let cwd = f.iter().rev().find_map(|fr| fr.cwd.clone());
        (w, cwd)
    });
    if written.is_some() {
        return written;
    }
    match super::scripts::read_script(path, cwd.as_deref(), true) {
        super::scripts::Script::Text(t, _) => Some(t),
        _ => None,
    }
}
