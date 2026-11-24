//! The parts of Python 3.9's `posixpath`, `fnmatch` and `glob` that guard-bash used, ported so a pattern matches
//! (or fails) exactly as it did there. Notably `fnmatch` builds a Python regex and lets `re` reject bad bracket
//! ranges such as `[i-0]` with `re.error`; guard-bash catches that and falls back to a plain-text check, so the
//! error cases matter as much as the matches.

use std::collections::HashMap;
use std::fs;

/// The exceptions guard-bash's `glob_hits_secret` catches.
#[derive(Debug, PartialEq, Eq)]
pub enum PyError {
    ReError,    // re.error from fnmatch's compiled pattern
    ValueError, // embedded null byte in a path
}

// ---------------------------------------------------------------- posixpath

pub fn basename(p: &str) -> &str {
    match p.rfind('/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// posixpath.split
pub fn split(p: &str) -> (String, String) {
    let i = p.rfind('/').map(|i| i + 1).unwrap_or(0);
    let (head, tail) = (&p[..i], &p[i..]);
    let mut head = head.to_string();
    if !head.is_empty() && head.chars().any(|c| c != '/') {
        head = head.trim_end_matches('/').to_string();
    }
    (head, tail.to_string())
}

/// posixpath.join(a, b)
pub fn join(a: &str, b: &str) -> String {
    if b.starts_with('/') {
        b.to_string()
    } else if a.is_empty() || a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// posixpath.normpath
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let mut initial = if path.starts_with('/') { 1 } else { 0 };
    if initial == 1 && path.starts_with("//") && !path.starts_with("///") {
        initial = 2;
    }
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".." || (initial == 0 && comps.is_empty()) || comps.last() == Some(&"..") {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let joined = comps.join("/");
    let out = format!("{}{}", "/".repeat(initial), joined);
    if out.is_empty() { ".".into() } else { out }
}

fn has_nul(p: &str) -> bool {
    p.contains('\0')
}

/// os.path.lexists (errors, including a null byte, are "no")
pub fn lexists(p: &str) -> bool {
    !has_nul(p) && fs::symlink_metadata(p).is_ok()
}

/// os.path.isdir (follows links; errors are "no")
pub fn isdir(p: &str) -> bool {
    !p.is_empty() && !has_nul(p) && fs::metadata(p).is_ok_and(|m| m.is_dir())
}

fn islink(p: &str) -> bool {
    !has_nul(p) && fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
}

/// os.path.realpath (Python 3.9, not strict): symlinks resolved as far as the path exists.
/// Err when a link can't be read (Python raised OSError there, which guard-bash didn't catch).
pub fn realpath(filename: &str) -> Result<String, String> {
    let mut seen: HashMap<String, Option<String>> = HashMap::new();
    let (path, _) = join_realpath(String::new(), filename, &mut seen, 0)?;
    let abs = if path.starts_with('/') {
        path
    } else {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/".into());
        join(&cwd, &path)
    };
    Ok(normpath(&abs))
}

fn join_realpath(
    mut path: String,
    rest: &str,
    seen: &mut HashMap<String, Option<String>>,
    depth: usize,
) -> Result<(String, bool), String> {
    if depth > 200 {
        return Err("RecursionError: maximum recursion depth exceeded".into());
    }
    let mut rest = rest.to_string();
    if rest.starts_with('/') {
        rest = rest[1..].to_string();
        path = "/".into();
    }
    while !rest.is_empty() {
        let (name, tail) = match rest.find('/') {
            Some(i) => (rest[..i].to_string(), rest[i + 1..].to_string()),
            None => (rest.clone(), String::new()),
        };
        rest = tail;
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            if !path.is_empty() {
                let (head, last) = split(&path);
                path = head;
                if last == ".." {
                    path = join(&join(&path, ".."), "..");
                }
            } else {
                path = "..".into();
            }
            continue;
        }
        let newpath = join(&path, &name);
        if !islink(&newpath) {
            path = newpath;
            continue;
        }
        if let Some(resolved) = seen.get(&newpath) {
            match resolved {
                Some(p) => {
                    path = p.clone();
                    continue;
                }
                None => return Ok((join(&newpath, &rest), false)),
            }
        }
        seen.insert(newpath.clone(), None);
        let target = fs::read_link(&newpath).map_err(|e| format!("OSError: {e}"))?;
        let (p, ok) = join_realpath(path, &target.to_string_lossy(), seen, depth + 1)?;
        path = p;
        if !ok {
            return Ok((join(&path, &rest), false));
        }
        seen.insert(newpath, Some(path.clone()));
    }
    Ok((path, true))
}

/// posixpath.dirname
pub fn dirname(p: &str) -> String {
    split(p).0
}

/// os.path.isfile (follows links; errors are "no")
pub fn isfile(p: &str) -> bool {
    !p.is_empty() && !has_nul(p) && fs::metadata(p).is_ok_and(|m| m.is_file())
}

fn getcwd() -> Result<String, String> {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| format!("FileNotFoundError: {e}"))
}

/// os.path.abspath
pub fn abspath(p: &str) -> Result<String, String> {
    if p.starts_with('/') {
        Ok(normpath(p))
    } else {
        Ok(normpath(&join(&getcwd()?, p)))
    }
}

/// os.getcwd(), as the hooks used it for a missing cwd.
pub fn cwd() -> Result<String, String> {
    getcwd()
}

/// os.path.relpath(path, start)
pub fn relpath(path: &str, start: &str) -> Result<String, String> {
    if path.is_empty() {
        return Err("ValueError: no path specified".into());
    }
    let s = abspath(start)?;
    let p = abspath(path)?;
    let sl: Vec<&str> = s.split('/').filter(|x| !x.is_empty()).collect();
    let pl: Vec<&str> = p.split('/').filter(|x| !x.is_empty()).collect();
    let i = sl.iter().zip(pl.iter()).take_while(|(a, b)| a == b).count();
    let mut rel: Vec<&str> = vec![".."; sl.len() - i];
    rel.extend_from_slice(&pl[i..]);
    if rel.is_empty() {
        return Ok(".".into());
    }
    Ok(rel.join("/"))
}

/// os.path.expanduser (Python 3.9): `~` from $HOME (else the user database), `~name` from the user database;
/// an unknown name leaves the path as it is. Err where Python raised (a null byte in the name).
pub fn expanduser(path: &str) -> Result<String, String> {
    if !path.starts_with('~') {
        return Ok(path.to_string());
    }
    let i = path[1..].find('/').map(|k| k + 1).unwrap_or(path.len());
    let home = if i == 1 {
        match std::env::var("HOME") {
            Ok(h) => h,
            Err(_) => match crate::pwd::own_home() {
                Some(h) => h,
                None => return Ok(path.to_string()),
            },
        }
    } else {
        match crate::pwd::home_of(&path[1..i])? {
            Some(h) => h,
            None => return Ok(path.to_string()),
        }
    };
    let home = home.trim_end_matches('/');
    let out = format!("{home}{}", &path[i..]);
    Ok(if out.is_empty() { "/".into() } else { out })
}

/// Python's `str.isspace` (Unicode White_Space plus U+001C..U+001F).
pub fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python's `str.strip()`.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(py_isspace)
}

/// `open(path, "r", encoding="utf-8", errors="replace").read(limit)`: text with \r\n and \r read as \n, at most
/// `limit` characters; "" when the file can't be opened (OSError). Err where Python raised ValueError (a null
/// byte in the path).
pub fn read_text(path: &str, limit: usize) -> Result<String, String> {
    use std::io::Read;
    if has_nul(path) {
        return Err("ValueError: embedded null byte".into());
    }
    let Ok(f) = fs::File::open(path) else {
        return Ok(String::new());
    };
    if f.metadata().is_ok_and(|m| m.is_dir()) {
        return Ok(String::new()); // IsADirectoryError
    }
    let mut buf = Vec::new();
    // Enough bytes for `limit` characters even at 4 bytes each, plus \r\n pairs.
    if f.take((limit as u64 + 1) * 8)
        .read_to_end(&mut buf)
        .is_err()
    {
        return Ok(String::new());
    }
    let text = String::from_utf8_lossy(&buf)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    Ok(text.chars().take(limit).collect())
}

// ---------------------------------------------------------------- fnmatch

#[derive(Debug, Clone)]
enum Tok {
    Star,
    Any,
    Lit(char),
    Class {
        negate: bool,
        items: Vec<(char, char)>,
    },
}

pub struct Pattern(Vec<Tok>);

/// One item of a Python regex character class as fnmatch.translate writes it: a literal or an escape (the only
/// escapes translate produces are of `\ - & ~ | ^ [`, all literal characters).
fn class_item(s: &[char], k: &mut usize) -> Option<(char, bool)> {
    let c = *s.get(*k)?;
    if c == '\\' {
        let e = *s.get(*k + 1)?;
        *k += 2;
        Some((e, true))
    } else {
        *k += 1;
        Some((c, false))
    }
}

/// Parse `[` + stuff + `]` the way Python 3.9's sre_parse does (stuff is translate's output). Err on a bad range.
fn parse_class(stuff: &[char]) -> Result<(bool, Vec<(char, char)>), PyError> {
    let mut src: Vec<char> = stuff.to_vec();
    src.push(']');
    let mut k = 0;
    let negate = src.first() == Some(&'^');
    if negate {
        k = 1;
    }
    let mut set: Vec<(char, char)> = Vec::new();
    loop {
        let (this, escaped) = class_item(&src, &mut k).ok_or(PyError::ReError)?;
        if this == ']' && !escaped && !set.is_empty() {
            break;
        }
        if src.get(k) == Some(&'-') {
            k += 1;
            let (that, that_escaped) = class_item(&src, &mut k).ok_or(PyError::ReError)?;
            if that == ']' && !that_escaped {
                set.push((this, this));
                set.push(('-', '-'));
                break;
            }
            if that < this {
                return Err(PyError::ReError);
            }
            set.push((this, that));
        } else {
            set.push((this, this));
        }
    }
    Ok((negate, set))
}

/// fnmatch's compiled pattern (translate, then Python's regex rules for the bracket classes).
pub fn compile(pat: &str) -> Result<Pattern, PyError> {
    let p: Vec<char> = pat.chars().collect();
    let n = p.len();
    let mut res: Vec<Tok> = Vec::new();
    let mut i = 0;
    while i < n {
        let c = p[i];
        i += 1;
        match c {
            '*' => {
                if !matches!(res.last(), Some(Tok::Star)) {
                    res.push(Tok::Star);
                }
            }
            '?' => res.push(Tok::Any),
            '[' => {
                let mut j = i;
                if j < n && p[j] == '!' {
                    j += 1;
                }
                if j < n && p[j] == ']' {
                    j += 1;
                }
                while j < n && p[j] != ']' {
                    j += 1;
                }
                if j >= n {
                    res.push(Tok::Lit('['));
                    continue;
                }
                let raw: String = p[i..j].iter().collect();
                let mut stuff: String = if !raw.contains("--") {
                    raw.replace('\\', "\\\\")
                } else {
                    let mut chunks: Vec<String> = Vec::new();
                    let mut ii = i;
                    let mut k = if p[i] == '!' { i + 2 } else { i + 1 };
                    loop {
                        // pat.find('-', k, j)
                        let found = (k..j).find(|&x| p[x] == '-');
                        match found {
                            None => break,
                            Some(f) => {
                                chunks.push(p[ii..f].iter().collect());
                                ii = f + 1;
                                k = f + 3;
                            }
                        }
                    }
                    chunks.push(p[ii..j].iter().collect());
                    chunks
                        .iter()
                        .map(|s| s.replace('\\', "\\\\").replace('-', "\\-"))
                        .collect::<Vec<_>>()
                        .join("-")
                };
                // Escape set operations (&&, ~~ and ||).
                let mut esc = String::with_capacity(stuff.len());
                for ch in stuff.chars() {
                    if matches!(ch, '&' | '~' | '|') {
                        esc.push('\\');
                    }
                    esc.push(ch);
                }
                stuff = esc;
                i = j + 1;
                let first = stuff.chars().next();
                if first == Some('!') {
                    stuff = format!("^{}", &stuff[1..]);
                } else if matches!(first, Some('^') | Some('[')) {
                    stuff = format!("\\{stuff}");
                }
                let chars: Vec<char> = stuff.chars().collect();
                let (negate, items) = parse_class(&chars)?;
                res.push(Tok::Class { negate, items });
            }
            c => res.push(Tok::Lit(c)),
        }
    }
    Ok(Pattern(res))
}

impl Pattern {
    fn one(t: &Tok, c: char) -> bool {
        match t {
            Tok::Any => true,
            Tok::Lit(l) => *l == c,
            Tok::Class { negate, items } => {
                items.iter().any(|&(lo, hi)| lo <= c && c <= hi) != *negate
            }
            Tok::Star => false,
        }
    }

    /// Whole-name match. Leftmost-first matching of each fixed piece is what translate's lookahead trick does,
    /// and is exact for `*`-separated fixed-width pieces.
    pub fn matches(&self, name: &str) -> bool {
        let s: Vec<char> = name.chars().collect();
        let t = &self.0;
        let (mut si, mut ti) = (0usize, 0usize);
        let mut star: Option<(usize, usize)> = None;
        while si < s.len() {
            if ti < t.len() && !matches!(t[ti], Tok::Star) && Self::one(&t[ti], s[si]) {
                si += 1;
                ti += 1;
            } else if ti < t.len() && matches!(t[ti], Tok::Star) {
                star = Some((ti, si));
                ti += 1;
            } else if let Some((st, ss)) = star {
                ti = st + 1;
                si = ss + 1;
                star = Some((st, ss + 1));
            } else {
                return false;
            }
        }
        while ti < t.len() && matches!(t[ti], Tok::Star) {
            ti += 1;
        }
        ti == t.len()
    }
}

/// fnmatch.fnmatchcase
pub fn fnmatchcase(name: &str, pat: &str) -> Result<bool, PyError> {
    Ok(compile(pat)?.matches(name))
}

// ---------------------------------------------------------------- glob

pub fn has_magic(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

fn is_hidden(s: &str) -> bool {
    s.starts_with('.')
}

/// os.scandir names (dironly: only directories, links followed). Python raised ValueError on a null byte.
fn listdir(dirname: &str, dironly: bool) -> Result<Vec<String>, PyError> {
    let d = if dirname.is_empty() { "." } else { dirname };
    if has_nul(d) {
        return Err(PyError::ValueError);
    }
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(d) {
        for e in rd.flatten() {
            if dironly && !fs::metadata(e.path()).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            out.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(out)
}

fn glob1(dirname: &str, pattern: &str, dironly: bool) -> Result<Vec<String>, PyError> {
    let mut names = listdir(dirname, dironly)?;
    if !is_hidden(pattern) {
        names.retain(|x| !is_hidden(x));
    }
    let pat = compile(pattern)?;
    Ok(names.into_iter().filter(|n| pat.matches(n)).collect())
}

fn glob0(dirname: &str, basename: &str) -> Vec<String> {
    if basename.is_empty() {
        if isdir(dirname) {
            return vec![String::new()];
        }
    } else if lexists(&join(dirname, basename)) {
        return vec![basename.to_string()];
    }
    Vec::new()
}

fn iglob(pathname: &str, dironly: bool) -> Result<Vec<String>, PyError> {
    let (dirname, base) = split(pathname);
    if !has_magic(pathname) {
        let hit = if !base.is_empty() {
            lexists(pathname)
        } else {
            isdir(&dirname)
        };
        return Ok(if hit {
            vec![pathname.to_string()]
        } else {
            Vec::new()
        });
    }
    if dirname.is_empty() {
        return glob1(&dirname, &base, dironly);
    }
    let dirs = if dirname != pathname && has_magic(&dirname) {
        iglob(&dirname, true)?
    } else {
        vec![dirname.clone()]
    };
    let mut out = Vec::new();
    for d in dirs {
        let names = if has_magic(&base) {
            glob1(&d, &base, dironly)?
        } else {
            glob0(&d, &base)
        };
        for name in names {
            out.push(join(&d, &name));
        }
    }
    Ok(out)
}

/// glob.glob(pathname) (not recursive)
pub fn glob(pathname: &str) -> Result<Vec<String>, PyError> {
    iglob(pathname, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatch_like_python() {
        assert!(fnmatchcase(".env", ".env*").unwrap());
        assert!(fnmatchcase(".envrc", ".envr?").unwrap());
        assert!(fnmatchcase("prod.env", "*.env").unwrap());
        assert!(fnmatchcase(".env", "*.env").unwrap());
        assert!(fnmatchcase("a", "[!b]").unwrap());
        assert!(fnmatchcase("]", "[]]").unwrap());
        assert_eq!(compile("[i-0]").err(), Some(PyError::ReError));
        assert_eq!(compile("[a--b]").err(), Some(PyError::ReError));
        assert!(fnmatchcase("[", "[").unwrap());
        assert!(fnmatchcase("x.local", "x[.]local").unwrap());
    }

    #[test]
    fn paths_like_python() {
        assert_eq!(split("/a/b/"), ("/a/b".into(), "".into()));
        assert_eq!(split("//x"), ("//".into(), "x".into()));
        assert_eq!(normpath("/tmp/../srv/x"), "/srv/x");
        assert_eq!(normpath("//a//b"), "//a/b");
        assert_eq!(join("a", ""), "a/");
    }
}
