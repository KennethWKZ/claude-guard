//! Shell command parsing for the per-repo guards, ported from a repo's Python `shell_words.py` function for
//! function. Not a full shell: enough to find the commands a Bash tool call runs and the words they get, with
//! quoting honoured, heredoc bodies set aside, comments dropped, command and process substitutions found, and paths
//! resolved against the folder a `cd` moved to. Python's quirks are kept on purpose (the differential test against
//! the Python module decides): character-level scans work on code points, `\s` and `str.split()` include
//! U+001C..U+001F, `str.isdigit()` and `int()` use Python 3.9's Unicode tables.

use crate::{pyfs, shlex};
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

/// The command's variables: the hook's environment plus assignments earlier in the command.
pub type Env = HashMap<String, String>;

pub const PREFIXES: &[&str] = &[
    "rtk", "command", "exec", "nice", "time", "env", "noglob", "nohup", "builtin",
];
/// Operator characters (`PUNCT`): a token made only of these is an operator.
pub const PUNCT: &str = "();<>|&\n";
/// Stands for "(" inside single quotes, where the shell runs nothing.
pub const INERT: char = '\u{1}';

static VAR: LazyLock<Regex> = LazyLock::new(|| {
    // INFALLIBLE: a constant pattern, covered by the unit tests.
    Regex::new(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))").unwrap()
});

/// `ASSIGN.match(word)` for `^([A-Za-z_][A-Za-z0-9_]*)=(.*)$` (re.S): (name, value).
pub fn assign(word: &str) -> Option<(&str, &str)> {
    let b = word.as_bytes();
    if !b
        .first()
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
    {
        return None;
    }
    let mut i = 1;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
        i += 1;
    }
    (b.get(i) == Some(&b'=')).then(|| (&word[..i], &word[i + 1..]))
}

/// `str.split()`: runs of Python whitespace.
pub fn py_split(s: &str) -> Vec<String> {
    s.split(pyfs::py_isspace)
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// Python 3.9's `str.isdigit()` (Numeric_Type Digit or Decimal), generated from `/usr/bin/python3`.
const DIGITS: &[(u32, u32)] = &[
    (0x30, 0x39),
    (0xB2, 0xB3),
    (0xB9, 0xB9),
    (0x660, 0x669),
    (0x6F0, 0x6F9),
    (0x7C0, 0x7C9),
    (0x966, 0x96F),
    (0x9E6, 0x9EF),
    (0xA66, 0xA6F),
    (0xAE6, 0xAEF),
    (0xB66, 0xB6F),
    (0xBE6, 0xBEF),
    (0xC66, 0xC6F),
    (0xCE6, 0xCEF),
    (0xD66, 0xD6F),
    (0xDE6, 0xDEF),
    (0xE50, 0xE59),
    (0xED0, 0xED9),
    (0xF20, 0xF29),
    (0x1040, 0x1049),
    (0x1090, 0x1099),
    (0x1369, 0x1371),
    (0x17E0, 0x17E9),
    (0x1810, 0x1819),
    (0x1946, 0x194F),
    (0x19D0, 0x19DA),
    (0x1A80, 0x1A89),
    (0x1A90, 0x1A99),
    (0x1B50, 0x1B59),
    (0x1BB0, 0x1BB9),
    (0x1C40, 0x1C49),
    (0x1C50, 0x1C59),
    (0x2070, 0x2070),
    (0x2074, 0x2079),
    (0x2080, 0x2089),
    (0x2460, 0x2468),
    (0x2474, 0x247C),
    (0x2488, 0x2490),
    (0x24EA, 0x24EA),
    (0x24F5, 0x24FD),
    (0x24FF, 0x24FF),
    (0x2776, 0x277E),
    (0x2780, 0x2788),
    (0x278A, 0x2792),
    (0xA620, 0xA629),
    (0xA8D0, 0xA8D9),
    (0xA900, 0xA909),
    (0xA9D0, 0xA9D9),
    (0xA9F0, 0xA9F9),
    (0xAA50, 0xAA59),
    (0xABF0, 0xABF9),
    (0xFF10, 0xFF19),
    (0x104A0, 0x104A9),
    (0x10A40, 0x10A43),
    (0x10D30, 0x10D39),
    (0x10E60, 0x10E68),
    (0x11052, 0x1105A),
    (0x11066, 0x1106F),
    (0x110F0, 0x110F9),
    (0x11136, 0x1113F),
    (0x111D0, 0x111D9),
    (0x112F0, 0x112F9),
    (0x11450, 0x11459),
    (0x114D0, 0x114D9),
    (0x11650, 0x11659),
    (0x116C0, 0x116C9),
    (0x11730, 0x11739),
    (0x118E0, 0x118E9),
    (0x11950, 0x11959),
    (0x11C50, 0x11C59),
    (0x11D50, 0x11D59),
    (0x11DA0, 0x11DA9),
    (0x16A60, 0x16A69),
    (0x16B50, 0x16B59),
    (0x1D7CE, 0x1D7FF),
    (0x1E140, 0x1E149),
    (0x1E2F0, 0x1E2F9),
    (0x1E950, 0x1E959),
    (0x1F100, 0x1F10A),
    (0x1FBF0, 0x1FBF9),
];

/// The first code point of each run of Unicode decimal digits 0..9 (Python 3.9's `unicodedata.decimal`).
const DECIMAL_ZEROS: &[u32] = &[
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
    0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x16A60, 0x16B50, 0x1D7CE,
    0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E950, 0x1FBF0,
];

/// `s.isdigit()`: non-empty and every character a Python digit.
pub fn py_isdigit(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            let u = c as u32;
            DIGITS.iter().any(|&(a, b)| (a..=b).contains(&u))
        })
}

fn decimal(c: char) -> Option<u32> {
    let u = c as u32;
    DECIMAL_ZEROS
        .iter()
        .find(|&&z| (z..z + 10).contains(&u))
        .map(|z| u - z)
}

/// `int(s)` (base 10), clamped to -1..=101 (callers only compare with small bounds); None on a ValueError.
pub fn py_int_small(s: &str) -> Option<i64> {
    let t = pyfs::py_strip(s);
    let (neg, digits) = match t.chars().next() {
        Some('-') => (true, &t[1..]),
        Some('+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut value: i64 = 0;
    let (mut any, mut last_underscore) = (false, false);
    for c in digits.chars() {
        if c == '_' {
            if !any || last_underscore {
                return None;
            }
            last_underscore = true;
            continue;
        }
        let d = decimal(c)?;
        value = (value * 10 + d as i64).min(1_000);
        any = true;
        last_underscore = false;
    }
    if !any || last_underscore {
        return None;
    }
    Some(if neg { -value.min(1) } else { value.min(101) })
}

/// `HEREDOC.finditer(line)` for `(?<!<)<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2`: (start, end, strip tabs,
/// delimiter), byte offsets.
pub fn heredoc_marks(line: &str) -> Vec<(usize, usize, bool, String)> {
    let cs: Vec<(usize, char)> = line.char_indices().collect();
    let at = |k: usize| cs.get(k).map_or(line.len(), |c| c.0);
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < cs.len() {
        if cs[i].1 == '<' && cs[i + 1].1 == '<' && (i == 0 || cs[i - 1].1 != '<') {
            let mut j = i + 2;
            let dash = j < cs.len() && cs[j].1 == '-';
            if dash {
                j += 1;
            }
            while j < cs.len() && pyfs::py_isspace(cs[j].1) {
                j += 1;
            }
            let quote = if j < cs.len() && (cs[j].1 == '\'' || cs[j].1 == '"') {
                Some(cs[j].1)
            } else {
                None
            };
            let try_at = |start: usize, q: Option<char>| -> Option<(usize, String)> {
                let first = cs.get(start)?.1;
                if !(first.is_ascii_alphabetic() || first == '_') {
                    return None;
                }
                let mut k = start + 1;
                while k < cs.len() && (cs[k].1.is_ascii_alphanumeric() || cs[k].1 == '_') {
                    k += 1;
                }
                let name: String = cs[start..k].iter().map(|c| c.1).collect();
                match q {
                    Some(q) if cs.get(k).map(|c| c.1) == Some(q) => Some((k + 1, name)),
                    Some(_) => None,
                    None => Some((k, name)),
                }
            };
            // With a quote, the name must close with the same quote; without one, the name starts right there. A
            // dash or spaces given back never lead to a match.
            let hit = quote
                .and_then(|q| try_at(j + 1, Some(q)))
                .or_else(|| try_at(j, None));
            if let Some((end, name)) = hit {
                out.push((cs[i].0, at(end), dash, name));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Matches of `SEPARATORS` (`;|&&|\|\||(?<![<>&])&(?![>&])`) in `s`, as byte ranges, left to right.
fn separator_spans(s: &str) -> Vec<(usize, usize)> {
    let cs: Vec<(usize, char)> = s.char_indices().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i].1;
        let next = cs.get(i + 1).map(|x| x.1);
        let len = if c == ';' {
            1
        } else if (c == '&' && next == Some('&')) || (c == '|' && next == Some('|')) {
            2
        } else if c == '&'
            && (i == 0 || !"<>&".contains(cs[i - 1].1))
            && !next.is_some_and(|n| ">&".contains(n))
        {
            1
        } else {
            0
        };
        if len > 0 {
            let end = cs.get(i + len).map_or(s.len(), |x| x.0);
            out.push((cs[i].0, end));
            i += len;
        } else {
            i += 1;
        }
    }
    out
}

/// `SEPARATORS.search(s)`.
pub fn has_separator(s: &str) -> bool {
    !separator_spans(s).is_empty()
}

/// `SEPARATORS.split(s)[-1]`.
fn after_last_separator(s: &str) -> &str {
    separator_spans(s).last().map_or(s, |&(_, e)| &s[e..])
}

/// `SEPARATORS.split(s)[0]`.
fn before_first_separator(s: &str) -> &str {
    separator_spans(s).first().map_or(s, |&(b, _)| &s[..b])
}

/// `heredocs(command, fed, feed)`: the command without heredoc bodies. Bodies whose command `feed` accepts (the
/// text of that command around the `<<`, pipes kept) are appended to `fed`.
pub fn heredocs(
    command: &str,
    mut fed: Option<&mut Vec<String>>,
    feed: &dyn Fn(&str) -> bool,
) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut pending: std::collections::VecDeque<(bool, String, Vec<&str>, bool)> =
        std::collections::VecDeque::new();
    for line in command.split('\n') {
        if let Some(front) = pending.front_mut() {
            let cmp = if front.0 {
                line.trim_start_matches('\t')
            } else {
                line
            };
            if cmp == front.1 {
                if let Some((_, _, body, run)) = pending.pop_front() {
                    if run {
                        if let Some(f) = fed.as_deref_mut() {
                            f.push(body.join("\n"));
                        }
                    }
                }
            } else {
                front.2.push(line);
            }
            continue;
        }
        out.push(line);
        for (start, end, dash, name) in heredoc_marks(line) {
            let seg = format!(
                "{}{}",
                after_last_separator(&line[..start]),
                before_first_separator(&line[end..])
            );
            pending.push_back((dash, name, Vec::new(), feed(&seg)));
        }
    }
    out.join("\n")
}

/// `SHELL_FEED.search(seg)` for `(?:^|[|;&(])\s*(?:\S*/)?(?:bash|sh|zsh|dash)\b(?![^|;&]*\s-\w*c\b)`: a local shell
/// runs the heredoc (`bash <<EOF`, `cat <<EOF | sh`), unless it got `-c` code (`ssh h bash -c ...`).
pub fn shell_feed(seg: &str) -> bool {
    let c: Vec<char> = seg.chars().collect();
    let n = c.len();
    let word = crate::pyre::py_word;
    // (?![^|;&]*\s-\w*c\b) at e: no `<space>-…c` option before the next | ; or &.
    let dash_c_follows = |e: usize| {
        let mut k = e;
        while k < n && !"|;&".contains(c[k]) {
            if pyfs::py_isspace(c[k]) && c.get(k + 1) == Some(&'-') {
                let r = k + 2;
                let mut end = r;
                while end < n && word(c[end]) {
                    end += 1;
                }
                if end > r && c[end - 1] == 'c' {
                    return true;
                }
            }
            k += 1;
        }
        false
    };
    for s in 0..=n {
        let mut starts = Vec::new();
        if s == 0 {
            starts.push(0);
        }
        if s < n && "|;&(".contains(c[s]) {
            starts.push(s + 1);
        }
        for t0 in starts {
            let mut t = t0;
            while t < n && pyfs::py_isspace(c[t]) {
                t += 1;
            }
            let mut names = vec![t];
            let mut u = t;
            while u < n && !pyfs::py_isspace(c[u]) {
                if c[u] == '/' {
                    names.push(u + 1);
                }
                u += 1;
            }
            for &at in &names {
                for shell in ["bash", "sh", "zsh", "dash"] {
                    let len = shell.len();
                    if at + len <= n
                        && c[at..at + len].iter().copied().eq(shell.chars())
                        && (at + len == n || !word(c[at + len]))
                        && !dash_c_follows(at + len)
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// `strip_comments(command)`: a `#` that starts a word, outside quotes, to the end of its line.
pub fn strip_comments(command: &str) -> String {
    let c: Vec<char> = command.chars().collect();
    let n = c.len();
    let mut out = String::with_capacity(command.len());
    let (mut i, mut q) = (0, None::<char>);
    while i < n {
        let ch = c[i];
        if let Some(qc) = q {
            out.push(ch);
            if ch == '\\' && qc == '"' && i + 1 < n {
                out.push(c[i + 1]);
                i += 1;
            } else if ch == qc {
                q = None;
            }
        } else if ch == '\\' && i + 1 < n {
            out.push(ch);
            out.push(c[i + 1]);
            i += 1;
        } else if ch == '\'' || ch == '"' {
            q = Some(ch);
            out.push(ch);
        } else if ch == '#' && (i == 0 || " \t\n;&|()".contains(c[i - 1])) {
            i = c[i..].iter().position(|&x| x == '\n').map_or(n, |k| i + k);
            continue;
        } else {
            out.push(ch);
        }
        i += 1;
    }
    out
}

/// `mark_single_quoted(command)`: "(" inside single quotes becomes `INERT`.
pub fn mark_single_quoted(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    let mut q = None::<char>;
    for c in command.chars() {
        if q == Some('\'') {
            out.push(if c == '(' { INERT } else { c });
            if c == '\'' {
                q = None;
            }
        } else {
            if c == '\'' && q.is_none() {
                q = Some('\'');
            } else if c == '"' {
                q = if q == Some('"') { None } else { Some('"') };
            }
            out.push(c);
        }
    }
    out
}

pub fn unmark(text: &str) -> String {
    text.replace(INERT, "(")
}

/// `substitutions(command, kinds)`: bodies of `$(...)`, backticks, `<(...)` and `>(...)` outside single quotes.
pub fn substitutions(command: &str, kinds: &str) -> Vec<String> {
    let c: Vec<char> = command.chars().collect();
    let n = c.len();
    let slice = |a: usize, b: usize| -> String {
        let b = b.min(n);
        if a >= b {
            String::new()
        } else {
            c[a..b].iter().collect()
        }
    };
    let mut out = Vec::new();
    let (mut i, mut dq) = (0, false);
    while i < n {
        let ch = c[i];
        if ch == '\\' {
            i += 2;
            continue;
        }
        if ch == '\'' && !dq {
            i = c[i + 1..]
                .iter()
                .position(|&x| x == '\'')
                .map_or(n, |k| i + 1 + k + 1);
            continue;
        }
        if ch == '"' {
            dq = !dq;
            i += 1;
            continue;
        }
        if ch == '`' && kinds.contains('`') {
            let mut j = i + 1;
            while j < n && c[j] != '`' {
                j += if c[j] == '\\' { 2 } else { 1 };
            }
            out.push(slice(i + 1, j));
            i = j + 1;
            continue;
        }
        if "$<>".contains(ch)
            && kinds.contains(ch)
            && c.get(i + 1) == Some(&'(')
            && c.get(i + 2) != Some(&'(')
        {
            let (mut depth, mut j, mut q) = (1, i + 2, None::<char>);
            while j < n && depth > 0 {
                let x = c[j];
                if let Some(qc) = q {
                    if x == qc {
                        q = None;
                    } else if x == '\\' && qc == '"' {
                        j += 1;
                    }
                } else if x == '\'' || x == '"' {
                    q = Some(x);
                } else if x == '\\' {
                    j += 1;
                } else if x == '(' {
                    depth += 1;
                } else if x == ')' {
                    depth -= 1;
                }
                j += 1;
            }
            out.push(slice(i + 2, j - 1));
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// `words(command)`: shell words with quoting honoured, operators as their own tokens (an unquoted newline is one
/// too); `str.split()` where shlex raised.
pub fn words(command: &str) -> Vec<String> {
    shlex::split_with(command, PUNCT, " \t\r").unwrap_or_else(|_| py_split(command))
}

pub fn is_operator(tok: &str) -> bool {
    !tok.is_empty() && tok.chars().all(|c| PUNCT.contains(c))
}

/// `expand(word, env)`: `~`, `$VAR` and `${VAR}`; None when something can't be known (an unset variable, a command
/// substitution, a glob). Err where Python raised (`~` + a name with a null byte).
pub fn expand(word: &str, env: &Env) -> Result<Option<String>, String> {
    if ["$(", "`", "*", "?"].iter().any(|s| word.contains(s)) {
        return Ok(None);
    }
    let mut missing = false;
    let out = VAR.replace_all(word, |caps: &regex::Captures| {
        // INFALLIBLE: one of the two alternatives' groups took part in the match.
        let name = caps.get(1).or_else(|| caps.get(2)).unwrap().as_str();
        match env.get(name) {
            Some(v) => v.clone(),
            None => {
                missing = true;
                String::new()
            }
        }
    });
    if missing || out.contains('$') {
        return Ok(None);
    }
    pyfs::expanduser(&out).map(Some)
}

/// `resolve(base, path, env)`: the real path of `path` from `base`, or None when either can't be known.
pub fn resolve(base: Option<&str>, path: &str, env: &Env) -> Result<Option<String>, String> {
    let Some(base) = base else { return Ok(None) };
    let Some(p) = expand(path, env)? else {
        return Ok(None);
    };
    let full = if p.starts_with('/') {
        p
    } else {
        pyfs::join(base, &p)
    };
    pyfs::realpath(&full).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(_: &str) -> bool {
        true
    }

    #[test]
    fn heredoc_bodies_set_aside_and_fed() {
        let mut fed = Vec::new();
        let rest = heredocs(
            "cat <<EOF | sh\nrm x\nEOF\ncat <<-'A'\n\tdata\n\tA\necho",
            Some(&mut fed),
            &shell_feed,
        );
        assert_eq!(rest, "cat <<EOF | sh\ncat <<-'A'\necho");
        assert_eq!(fed, ["rm x"]);
        let mut fed = Vec::new();
        heredocs("python3 - <<E\nx\nE", Some(&mut fed), &all);
        assert_eq!(fed, ["x"]);
    }

    #[test]
    fn shell_feed_follows_python() {
        assert!(shell_feed("bash "));
        assert!(shell_feed("cat  | sh"));
        assert!(shell_feed("x; /bin/zsh -s"));
        assert!(!shell_feed("bash -c "));
        assert!(!shell_feed("ssh h bash -lc"));
        assert!(shell_feed("bash -c x | sh"), "a later shell without -c");
        assert!(!shell_feed("bashful"));
        assert!(!shell_feed("cat"));
        assert!(shell_feed("(sh"));
    }

    #[test]
    fn separators() {
        assert_eq!(after_last_separator("a; b && c"), " c");
        assert_eq!(before_first_separator(" x | y & z"), " x | y ");
        assert_eq!(after_last_separator("a 2>&1"), "a 2>&1");
        assert_eq!(after_last_separator("a &>x"), "a &>x");
        assert!(!has_separator("a | b"));
    }

    #[test]
    fn comments_marks_and_substitutions() {
        assert_eq!(strip_comments("a # x\nb '#c' d#e"), "a \nb '#c' d#e");
        assert_eq!(mark_single_quoted("'$(x)' \"$(y)\""), "'$\u{1}x)' \"$(y)\"");
        assert_eq!(
            substitutions("a $(b $(c)) `d` <(e) '$(f)' $((1))", "`$<>"),
            ["b $(c)", "d", "e"]
        );
        assert_eq!(substitutions("x $(", "`$<>"), [""]);
        assert_eq!(substitutions("`a\\", "`"), ["a\\"]);
    }

    #[test]
    fn expansion_and_numbers() {
        let env: Env = [("A".to_string(), "/a".to_string()), ("E".into(), "".into())]
            .into_iter()
            .collect();
        assert_eq!(expand("$A/x", &env).unwrap().as_deref(), Some("/a/x"));
        assert_eq!(expand("${E}x", &env).unwrap().as_deref(), Some("x"));
        assert_eq!(expand("$B/x", &env).unwrap(), None);
        assert_eq!(expand("*.md", &env).unwrap(), None);
        assert_eq!(expand("$1", &env).unwrap(), None);
        assert!(py_isdigit("2") && py_isdigit("²") && !py_isdigit("") && !py_isdigit("½"));
        assert_eq!(py_int_small(" 1_0 "), Some(10));
        assert_eq!(py_int_small("٣"), Some(3));
        assert_eq!(py_int_small("-5"), Some(-1));
        assert_eq!(py_int_small("999999999999999999999"), Some(101));
        assert_eq!(py_int_small("1__0"), None);
        assert_eq!(py_int_small("x"), None);
        assert_eq!(assign("A_1=x=y"), Some(("A_1", "x=y")));
        assert_eq!(assign("1A=x"), None);
    }
}
