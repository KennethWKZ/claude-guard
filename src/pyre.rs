//! Python `re` semantics on top of the `regex` crate, for patterns ported from the Python hooks.
//!
//! Python's str patterns and Rust's `regex` disagree on a few character classes:
//! - `\w` (and so `\b`): Python's is letters, numbers and `_` (str.isalnum); Rust's adds combining marks,
//!   connector punctuation, ZWJ/ZWNJ and Alphabetic symbols (Ⓐ), and leaves out numbers such as `²` and `½`.
//! - `\s`: Python's adds U+001C..U+001F.
//! - IGNORECASE: Python matches İ and ı for `i`; Rust doesn't (both match ſ for `s` and K for `k`).
//!
//! `PyText` is a copy of the text where every character whose class differs is replaced by a stand-in that Rust
//! classes the way Python classes the original (`ª` for a Python word character, `§` for a non-word one, a space
//! for U+001C..U+001F, and with `ci` the ASCII letter for İ, ı, ſ and K). A regex with `\w`, `\b`, `\s` and `(?i)`
//! run on that copy finds what the Python pattern finds in the original; `orig` maps a match back. Patterns that
//! name one of the replaced characters literally (the zero-width check) run on the original instead.

use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

static PY_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\p{L}\p{N}_]$").unwrap());
static RUST_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\w$").unwrap());

/// Python's `\w` for one character (str patterns).
pub fn py_word(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphanumeric() || c == '_';
    }
    PY_WORD.is_match(c.encode_utf8(&mut [0; 4]))
}

fn rust_word(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphanumeric() || c == '_';
    }
    RUST_WORD.is_match(c.encode_utf8(&mut [0; 4]))
}

pub struct PyText<'a> {
    pub orig: &'a str,
    /// The text as Rust's regex should see it.
    pub t: String,
    /// Byte offset in `orig` for each byte offset in `t` (one past the end included).
    map: Vec<usize>,
}

impl<'a> PyText<'a> {
    /// `ci`: the pattern is IGNORECASE.
    pub fn new(orig: &'a str, ci: bool) -> PyText<'a> {
        Self::build(orig, ci, true)
    }

    /// Only the IGNORECASE letters (and U+001C..U+001F) replaced: for patterns built from the text's own
    /// characters (a blocked term), where two different characters must not become the same stand-in. `\w` and
    /// `\b` are then checked in code with `py_word`.
    pub fn case_only(orig: &'a str) -> PyText<'a> {
        Self::build(orig, true, false)
    }

    fn build(orig: &'a str, ci: bool, words: bool) -> PyText<'a> {
        let mut t = String::with_capacity(orig.len());
        let mut map = Vec::with_capacity(orig.len() + 1);
        let mut memo: HashMap<char, char> = HashMap::new();
        for (i, c) in orig.char_indices() {
            let s = if c.is_ascii() {
                c
            } else if ci && matches!(c, '\u{130}' | '\u{131}') {
                'i'
            } else if ci && c == '\u{17f}' {
                's'
            } else if ci && c == '\u{212a}' {
                'k'
            } else if !words {
                c
            } else {
                *memo
                    .entry(c)
                    .or_insert_with(|| match (py_word(c), rust_word(c)) {
                        (true, false) => 'ª',
                        (false, true) => '§',
                        _ => c,
                    })
            };
            let s = if ('\u{1c}'..='\u{1f}').contains(&s) {
                ' '
            } else {
                s
            };
            for _ in 0..s.len_utf8() {
                map.push(i);
            }
            t.push(s);
        }
        map.push(orig.len());
        PyText { orig, t, map }
    }

    /// The original text for a byte range of `t` (on character boundaries).
    pub fn orig(&self, start: usize, end: usize) -> &'a str {
        &self.orig[self.map[start]..self.map[end]]
    }

    /// Byte offset in the original for a byte offset in `t`.
    pub fn pos(&self, i: usize) -> usize {
        self.map[i]
    }
}

/// `findall` for a pattern with no groups (whole matches) or one group (that group), mapped to the original.
pub fn findall<'a>(rx: &Regex, text: &PyText<'a>) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut at = 0;
    while at <= text.t.len() {
        let Some(c) = rx.captures_at(&text.t, at) else {
            break;
        };
        let m = c.get(0).unwrap();
        let g = if rx.captures_len() > 1 {
            c.get(1)
        } else {
            Some(m)
        };
        match g {
            Some(g) => out.push(text.orig(g.start(), g.end())),
            None => out.push(""),
        }
        at = if m.end() > m.start() {
            m.end()
        } else {
            m.end() + text.t[m.end()..].chars().next().map_or(1, char::len_utf8)
        };
    }
    out
}

/// `rx.sub("", text)` for an IGNORECASE pattern with no empty matches: the original with every match removed.
pub fn remove_all_ci(rx: &Regex, orig: &str) -> String {
    let text = PyText::new(orig, true);
    let mut out = String::with_capacity(orig.len());
    let mut last = 0;
    for m in rx.find_iter(&text.t) {
        out.push_str(&orig[last..text.pos(m.start())]);
        last = text.pos(m.end());
    }
    out.push_str(&orig[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_match_python() {
        let t = PyText::new("a\u{301}b ² x\u{200d}y İ\u{1c}", true);
        assert_eq!(t.t, "a§b ª x§y i ");
        assert_eq!(t.orig(0, t.t.len()), "a\u{301}b ² x\u{200d}y İ\u{1c}");
        let t = PyText::new("İ", false);
        assert_eq!(t.t, "İ");
    }
}
