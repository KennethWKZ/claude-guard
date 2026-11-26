//! The values of string expressions in interpreter code, so a command built from variables or pieces is checked
//! too: `cmd = "sud" + "o ls"; os.system(cmd)`, `` const c = `git ${"push"} -f`; execSync(c) ``,
//! `my @a = ("sudo", "ls"); system(@a)`.
//!
//! - `env_of` collects the code's assignments in order (`x = ...`, `const|let|var x = ...`, `my $x = ...`,
//!   `$x = ...`, `local x = ...`, `set x to ...`, and `+=` / `.=` appends); every value a name gets is kept
//!   (at most `MAX_PER_NAME`), so a command assigned on any branch is checked.
//! - `eval` reads an expression: literals (with escapes), known variables, concatenation (`+`, `.`, `..`, `&`),
//!   lists, interpolation (`${x}`, `#{x}`, f-string `{x}`, perl and php `"$x"`), `" ".join([...])`, `[...].join(" ")`,
//!   perl `join`, python `%` and `.format()`. An unknown name inside a concatenation or interpolation reads as the
//!   word `x` (a path built on it stays relative); an unknown expression on its own has no value.
//!
//! - Environment lookups (`os.environ`, `process.env`, `ENV`, `$ENV`, `getenv`) take the value the command
//!   itself gives the variable, and file reads (`open(p).read()`, `fs.readFileSync`, `File.read`,
//!   `file_get_contents`, `io.open(p):read`) the file's text (`context`).
//!
//! A heuristic: there is no scoping, control flow or function call; values come from the program's text.

use super::interp::{Lang, top_level_split};
use regex::Regex;
use std::sync::LazyLock;

const MAX_VARIANTS: usize = 8;
const MAX_PER_NAME: usize = 4;
const MAX_DEPTH: usize = 6;

#[derive(Clone, PartialEq, Debug)]
pub(super) enum Val {
    Str(String),
    List(Vec<String>),
}

impl Val {
    pub(super) fn text(&self) -> String {
        match self {
            Val::Str(s) => s.clone(),
            Val::List(v) => v.join(" "),
        }
    }
}

#[derive(Default)]
pub(super) struct Env {
    vars: Vec<(String, Vec<Val>)>,
}

impl Env {
    /// The string values `name` holds.
    pub(super) fn texts(&self, name: &str) -> Vec<String> {
        self.get(name)
            .map(|v| v.iter().map(Val::text).collect())
            .unwrap_or_default()
    }

    fn get(&self, name: &str) -> Option<&Vec<Val>> {
        self.vars.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    fn add(&mut self, name: &str, vals: Vec<Val>) {
        if let Some((_, v)) = self.vars.iter_mut().find(|(n, _)| n == name) {
            for x in vals {
                if !v.contains(&x) && v.len() < MAX_PER_NAME {
                    v.push(x);
                }
            }
        } else {
            let mut vals = vals;
            vals.truncate(MAX_PER_NAME);
            self.vars.push((name.to_string(), vals));
        }
    }
}

/// Statements: lines, and `;`-separated parts of a line, outside strings and brackets.
fn statements(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut q: Option<char> = None;
    let mut depth = 0i32;
    let mut esc = false;
    for c in code.chars() {
        if esc {
            esc = false;
            cur.push(c);
            continue;
        }
        match q {
            Some(o) => {
                if c == '\\' && o != '\'' {
                    esc = true;
                } else if c == o {
                    q = None;
                }
                cur.push(c);
            }
            None => {
                match c {
                    '"' | '\'' | '`' => q = Some(c),
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth -= 1,
                    ';' | '\n' if depth <= 0 => {
                        out.push(std::mem::take(&mut cur));
                        continue;
                    }
                    _ => {}
                }
                cur.push(c);
            }
        }
    }
    out.push(cur);
    out
}

static ASSIGN: LazyLock<[(Lang, Regex); 7]> = LazyLock::new(|| {
    let r = |s: &str| super::re(s);
    [
        (Lang::Python, r(r"^([A-Za-z_]\w*)\s*(\+?=)\s*([^=].*)$")),
        (
            Lang::Node,
            r(r"^(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(\+?=)\s*([^=>].*)$"),
        ),
        (Lang::Ruby, r(r"^([a-z_]\w*)\s*(\+?=)\s*([^=~].*)$")),
        (
            Lang::Perl,
            r(r"^(?:(?:my|our|local)\s+)?([$@]\w+)\s*(\.?=)\s*([^=~].*)$"),
        ),
        (Lang::Php, r(r"^(\$\w+)\s*(\.?=)\s*([^=].*)$")),
        (
            Lang::Lua,
            r(r"^(?:local\s+)?([A-Za-z_]\w*)\s*(=)\s*([^=].*)$"),
        ),
        (Lang::Osa, r(r"^set\s+(\w+)\s+to\s+()(.+)$")),
    ]
});

/// The code's variables and every value assigned to them, in program order.
pub(super) fn env_of(code: &str, lang: Lang) -> Env {
    let mut env = Env::default();
    let Some((_, re)) = ASSIGN.iter().find(|(l, _)| *l == lang) else {
        return env;
    };
    for st in statements(code) {
        let st = st.trim().trim_end_matches(';').trim();
        let Some(c) = re.captures(st) else { continue };
        let name = c[1].to_string();
        let append = c[2].starts_with('+') || c[2].starts_with('.');
        let mut vals = eval(&c[3], lang, &env, 0);
        if append {
            let old: Vec<String> = env
                .get(&name)
                .map(|v| v.iter().map(Val::text).collect())
                .unwrap_or_default();
            vals = product(&[old, vals.iter().map(Val::text).collect()])
                .into_iter()
                .map(Val::Str)
                .collect();
        }
        if !vals.is_empty() {
            env.add(&name, vals);
        }
    }
    env
}

/// Every combination of one text from each list, joined (at most `MAX_VARIANTS`).
fn product(lists: &[Vec<String>]) -> Vec<String> {
    let mut out = vec![String::new()];
    for l in lists {
        let l: Vec<String> = if l.is_empty() {
            vec![String::new()]
        } else {
            l.clone()
        };
        let mut next = Vec::new();
        for a in &out {
            for b in &l {
                if next.len() < MAX_VARIANTS {
                    next.push(format!("{a}{b}"));
                }
            }
        }
        out = next;
    }
    out
}

fn trim_parens(t: &str) -> &str {
    let t = t.trim();
    if t.starts_with('(') && t.ends_with(')') {
        let inner = &t[1..t.len() - 1];
        // Only when the parentheses wrap the whole expression.
        let mut depth = 0i32;
        let balanced = inner.chars().all(|c| {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            depth >= 0
        });
        if balanced && depth == 0 && top_level_split(inner).len() == 1 {
            return inner.trim();
        }
    }
    t
}

/// Splits on a concatenation operator outside strings and brackets.
fn split_concat(t: &str, lang: Lang) -> Vec<String> {
    let ops: &[&str] = match lang {
        Lang::Python | Lang::Node | Lang::Ruby => &["+"],
        Lang::Perl | Lang::Php => &["."],
        Lang::Lua => &[".."],
        Lang::Osa => &["&"],
    };
    let chars: Vec<char> = t.chars().collect();
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut q: Option<char> = None;
    let mut depth = 0i32;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(o) = q {
            cur.push(c);
            if c == '\\' && o != '\'' && i + 1 < chars.len() {
                cur.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == o {
                q = None;
            }
            i += 1;
            continue;
        }
        match c {
            '"' | '\'' | '`' => q = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
        if depth == 0 {
            let rest: String = chars[i..].iter().collect();
            if let Some(op) = ops.iter().find(|op| rest.starts_with(**op)) {
                // Perl/PHP `.`: not inside a number or a method arrow; Lua `..` only.
                let is_op = match lang {
                    Lang::Perl | Lang::Php => {
                        let prev = cur.trim_end().chars().last();
                        let next = chars.get(i + 1).copied();
                        !(prev.is_some_and(|p| p.is_ascii_digit())
                            && next.is_some_and(|n| n.is_ascii_digit()))
                            && next != Some('=')
                    }
                    Lang::Lua => true,
                    _ => chars.get(i + 1) != Some(&'='),
                };
                if is_op {
                    parts.push(std::mem::take(&mut cur));
                    i += op.len();
                    continue;
                }
            }
        }
        cur.push(c);
        i += 1;
    }
    parts.push(cur);
    parts.into_iter().map(|p| p.trim().to_string()).collect()
}

/// The items of a list literal: `[...]`, perl `(..., ...)`, `qw(...)`, ruby `%w(...)`.
fn list_items(t: &str, lang: Lang) -> Option<Vec<String>> {
    for p in ["qw(", "%w(", "%w[", "qw["] {
        if let Some(rest) = t.strip_prefix(p) {
            let words = rest.trim_end_matches([')', ']']);
            return Some(words.split_whitespace().map(|w| format!("'{w}'")).collect());
        }
    }
    let list = (t.starts_with('[') && t.ends_with(']'))
        || (lang == Lang::Perl && t.starts_with('(') && t.ends_with(')'))
        || (lang == Lang::Lua && t.starts_with('{') && t.ends_with('}'));
    list.then(|| top_level_split(&t[1..t.len() - 1]))
}

fn is_var(t: &str, lang: Lang) -> bool {
    static PLAIN: LazyLock<Regex> = LazyLock::new(|| super::re(r"^[A-Za-z_$][\w$]*$"));
    static SIGIL: LazyLock<Regex> = LazyLock::new(|| super::re(r"^[$@]\w+$"));
    match lang {
        Lang::Perl | Lang::Php => SIGIL.is_match(t),
        _ => PLAIN.is_match(t),
    }
}

/// The values of an expression (none when it can't be read).
pub(super) fn eval(expr: &str, lang: Lang, env: &Env, depth: usize) -> Vec<Val> {
    if depth > MAX_DEPTH {
        return Vec::new();
    }
    let t = trim_parens(expr);
    if t.is_empty() {
        return Vec::new();
    }
    if let Some(items) = list_items(t, lang) {
        if !(lang == Lang::Perl && t.starts_with('(') && items.len() < 2) {
            let mut words = Vec::new();
            for item in items {
                for v in eval(&item, lang, env, depth + 1).into_iter().take(1) {
                    match v {
                        Val::List(l) => words.extend(l),
                        Val::Str(s) => words.push(s),
                    }
                }
            }
            return vec![Val::List(words)];
        }
    }
    if let Some(v) = joins_and_formats(t, lang, env, depth) {
        return v;
    }
    if let Some(v) = env_or_file(t, lang, env, depth) {
        return v;
    }
    let pieces = split_concat(t, lang);
    if pieces.len() > 1 {
        let texts: Vec<Vec<String>> = pieces
            .iter()
            .map(|p| {
                let v: Vec<String> = eval(p, lang, env, depth + 1)
                    .iter()
                    .map(Val::text)
                    .collect();
                if v.is_empty() { vec![String::new()] } else { v }
            })
            .collect();
        return product(&texts).into_iter().map(Val::Str).collect();
    }
    if let Some(s) = render(t, lang, env, depth) {
        return vec![Val::Str(s)];
    }
    if is_var(t, lang) {
        return env.get(t).cloned().unwrap_or_default();
    }
    Vec::new()
}

/// Environment lookups and file reads with a value the check knows: the command's own variables
/// (`CMD=... python3 -c 'os.environ["CMD"]'`) and files in the project, a temp folder, or written earlier in the
/// same command (`open("cmd.txt").read()`). None when `t` is neither; an empty list when its value is unknown.
fn env_or_file(t: &str, lang: Lang, env: &Env, depth: usize) -> Option<Vec<Val>> {
    static PATTERNS: LazyLock<Vec<(Lang, bool, Regex)>> = LazyLock::new(|| {
        let r = |s: &str| super::re(s);
        vec![
            // (language, is a file read, pattern with the argument list in group 1)
            (Lang::Python, false, r(r"(?s)^(?:os\.)?environ\s*\[(.+)\]$")),
            (
                Lang::Python,
                false,
                r(r"(?s)^(?:os\.)?environ\.get\s*\((.*)\)$"),
            ),
            (Lang::Python, false, r(r"(?s)^os\.getenv\s*\((.*)\)$")),
            (
                Lang::Python,
                true,
                r(r"(?s)^(?:io\.)?open\s*\((.*)\)\s*\.\s*read\s*\(\s*\)$"),
            ),
            (
                Lang::Python,
                true,
                r(r"(?s)^(?:pathlib\.)?Path\s*\((.*?)\)\s*\.\s*read_text\s*\(.*\)$"),
            ),
            (Lang::Node, false, r(r"^process\.env\.(\w+)$")),
            (Lang::Node, false, r(r"(?s)^process\.env\s*\[(.+)\]$")),
            (
                Lang::Node,
                true,
                r(
                    r#"(?s)^(?:require\(\s*["'](?:node:)?fs["']\s*\)|fs)\s*\.\s*readFileSync\s*\((.*?)\)(?:\s*\.\s*toString\s*\(\s*\))?$"#,
                ),
            ),
            (Lang::Ruby, false, r(r"(?s)^ENV\s*\[(.+)\]$")),
            (Lang::Ruby, false, r(r"(?s)^ENV\.fetch\s*\((.*)\)$")),
            (Lang::Ruby, true, r(r"(?s)^(?:File|IO)\.read\s*\((.*)\)$")),
            (Lang::Perl, false, r(r"(?s)^\$ENV\{(.+)\}$")),
            (Lang::Php, false, r(r"(?s)^getenv\s*\((.*)\)$")),
            (Lang::Php, false, r(r"(?s)^\$_(?:ENV|SERVER)\s*\[(.+)\]$")),
            (Lang::Php, true, r(r"(?s)^file_get_contents\s*\((.*)\)$")),
            (Lang::Lua, false, r(r"(?s)^os\.getenv\s*\((.*)\)$")),
            (
                Lang::Lua,
                true,
                r(r"(?s)^io\.open\s*\((.*?)\)\s*:\s*read\s*\(.*\)$"),
            ),
        ]
    });
    let (file, args) = PATTERNS
        .iter()
        .filter(|(l, _, _)| *l == lang)
        .find_map(|(_, file, re)| re.captures(t).map(|c| (*file, c[1].to_string())))?;
    let parts = top_level_split(&args);
    let first = parts.first().map(|p| p.trim()).unwrap_or("");
    // A bare word names the variable itself (`process.env.CMD`, `$ENV{CMD}`).
    let key = if first.chars().all(|c| c.is_alphanumeric() || c == '_') && !first.is_empty() {
        first.to_string()
    } else {
        eval(first, lang, env, depth + 1).first().map(Val::text)?
    };
    let value = if file {
        super::context::file(&key)
    } else {
        super::context::var(&key)
    };
    Some(match value {
        Some(v) => vec![Val::Str(v)],
        // `os.environ.get("X", "default")`, `ENV.fetch("X", "default")`: the default when the command doesn't set X.
        None if !file && parts.len() > 1 => eval(&parts[1], lang, env, depth + 1),
        None => Vec::new(),
    })
}

fn first_text(expr: &str, lang: Lang, env: &Env, depth: usize) -> String {
    eval(expr, lang, env, depth + 1)
        .first()
        .map(Val::text)
        .unwrap_or_else(|| "x".to_string())
}

/// `" ".join(xs)`, `xs.join(" ")`, perl `join(" ", ...)`, python `"%s" % x` and `"{}".format(x)`.
fn joins_and_formats(t: &str, lang: Lang, env: &Env, depth: usize) -> Option<Vec<Val>> {
    static PY_JOIN: LazyLock<Regex> = LazyLock::new(|| {
        super::re(r#"(?s)^((?:[rRbBuU]?)(?:"[^"]*"|'[^']*'))\s*\.\s*join\s*\((.*)\)$"#)
    });
    static METHOD_JOIN: LazyLock<Regex> =
        LazyLock::new(|| super::re(r"(?s)^(.+?)\s*\.\s*join\s*(?:\((.*)\))?$"));
    static PERL_JOIN: LazyLock<Regex> = LazyLock::new(|| super::re(r"(?s)^join\s*\(?(.*?)\)?$"));
    static PY_PERCENT: LazyLock<Regex> =
        LazyLock::new(|| super::re(r#"(?s)^((?:"[^"]*"|'[^']*'))\s*%\s*(.+)$"#));
    static PY_FORMAT: LazyLock<Regex> =
        LazyLock::new(|| super::re(r#"(?s)^((?:"[^"]*"|'[^']*'))\s*\.\s*format\s*\((.*)\)$"#));
    let list_words = |e: &str| -> Vec<String> {
        eval(e, lang, env, depth + 1)
            .into_iter()
            .next()
            .map(|v| match v {
                Val::List(l) => l,
                Val::Str(s) => vec![s],
            })
            .unwrap_or_default()
    };
    match lang {
        Lang::Python => {
            if let Some(c) = PY_JOIN.captures(t) {
                let sep = render(&c[1], lang, env, depth).unwrap_or_default();
                return Some(vec![Val::Str(list_words(&c[2]).join(&sep))]);
            }
            let fill = |fmt: &str, args: Vec<String>, brace: bool| {
                let mut s = fmt.to_string();
                for a in args {
                    let re = if brace { r"\{[^}]*\}" } else { r"%[sdr]" };
                    s = super::re(re).replace(&s, a.as_str()).into_owned();
                }
                s
            };
            if let Some(c) = PY_FORMAT.captures(t) {
                let fmt = render(&c[1], lang, env, depth).unwrap_or_default();
                let args = top_level_split(&c[2])
                    .iter()
                    .map(|a| first_text(a, lang, env, depth))
                    .collect();
                return Some(vec![Val::Str(fill(&fmt, args, true))]);
            }
            if let Some(c) = PY_PERCENT.captures(t) {
                let fmt = render(&c[1], lang, env, depth).unwrap_or_default();
                let a = trim_parens(&c[2]);
                let args = top_level_split(a)
                    .iter()
                    .map(|a| first_text(a, lang, env, depth))
                    .collect();
                return Some(vec![Val::Str(fill(&fmt, args, false))]);
            }
        }
        Lang::Node | Lang::Ruby => {
            if let Some(c) = METHOD_JOIN.captures(t) {
                let sep = c
                    .get(2)
                    .map(|s| render(s.as_str().trim(), lang, env, depth).unwrap_or_default())
                    .unwrap_or_else(|| {
                        if lang == Lang::Node {
                            ",".into()
                        } else {
                            String::new()
                        }
                    });
                return Some(vec![Val::Str(list_words(&c[1]).join(&sep))]);
            }
        }
        Lang::Perl => {
            if let Some(c) = PERL_JOIN.captures(t) {
                let parts = top_level_split(&c[1]);
                let sep = parts
                    .first()
                    .map(|s| first_text(s, lang, env, depth))
                    .unwrap_or_default();
                let words: Vec<String> = parts.iter().skip(1).flat_map(|p| list_words(p)).collect();
                return Some(vec![Val::Str(words.join(&sep))]);
            }
        }
        _ => {}
    }
    None
}

/// The text of a single string literal (escapes read, interpolations filled in), if `t` is exactly one.
pub(super) fn render(t: &str, lang: Lang, env: &Env, depth: usize) -> Option<String> {
    let chars: Vec<char> = t.chars().collect();
    let mut i = 0;
    let (mut fstring, mut raw) = (false, false);
    if lang == Lang::Python {
        while i < chars.len() && i < 2 && "rRbBuUfF".contains(chars[i]) {
            fstring |= matches!(chars[i], 'f' | 'F');
            raw |= matches!(chars[i], 'r' | 'R');
            i += 1;
        }
    }
    // Delimited forms: perl q() qq(), ruby %q() %Q() %(), lua [[...]].
    let rest: String = chars[i..].iter().collect();
    let pair = |o: char| match o {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        '<' => '>',
        c => c,
    };
    let (open, close, interpolate, start) = if lang == Lang::Lua && rest.starts_with("[[") {
        ('[', ']', false, i + 2)
    } else if lang == Lang::Perl
        && (rest.starts_with("qq") || rest.starts_with('q'))
        && chars.len() > i + 1
    {
        let qq = rest.starts_with("qq");
        let at = i + if qq { 2 } else { 1 };
        let o = *chars.get(at)?;
        if o.is_alphanumeric() || o.is_whitespace() {
            return None;
        }
        (o, pair(o), qq, at + 1)
    } else if lang == Lang::Ruby && rest.starts_with('%') && chars.len() > i + 2 {
        let kind = chars[i + 1];
        let (at, interp) = match kind {
            'q' => (i + 2, false),
            'Q' => (i + 2, true),
            c if !c.is_alphanumeric() => (i + 1, true),
            _ => return None,
        };
        let o = *chars.get(at)?;
        (o, pair(o), interp, at + 1)
    } else {
        let q = *chars.get(i)?;
        let ok = match lang {
            Lang::Node => matches!(q, '"' | '\'' | '`'),
            Lang::Osa => q == '"',
            _ => matches!(q, '"' | '\''),
        };
        if !ok {
            return None;
        }
        let interp = match lang {
            Lang::Python => fstring,
            Lang::Node => q == '`',
            Lang::Ruby | Lang::Perl | Lang::Php => q == '"',
            _ => false,
        };
        // Python triple quotes.
        if lang == Lang::Python
            && rest.len() >= 3
            && (rest.starts_with("\"\"\"") || rest.starts_with("'''"))
        {
            let body = &rest[3..];
            let end = body.find(&rest[..3])?;
            if i + 3 + body[..end].chars().count() + 3 != chars.len() {
                return None;
            }
            return Some(fill_interp(&body[..end], lang, env, depth, interp, raw));
        }
        (q, q, interp, i + 1)
    };
    // Find the closing delimiter; it must end the expression.
    let mut j = start;
    let mut body = String::new();
    let lua_long = lang == Lang::Lua && open == '[' && close == ']';
    while j < chars.len() {
        let c = chars[j];
        if lua_long {
            if c == ']' && chars.get(j + 1) == Some(&']') {
                break;
            }
        } else if c == '\\' && j + 1 < chars.len() {
            body.push(c);
            body.push(chars[j + 1]);
            j += 2;
            continue;
        } else if c == close {
            break;
        }
        body.push(c);
        j += 1;
    }
    let end = if lua_long { j + 2 } else { j + 1 };
    if end != chars.len() {
        return None; // more than one literal
    }
    let single = open == '\'' && close == '\'';
    Some(fill_interp(
        &body,
        lang,
        env,
        depth,
        interpolate,
        raw || single,
    ))
}

/// A literal's body with escapes read and interpolations filled in (unknown ones as `x`).
fn fill_interp(
    body: &str,
    lang: Lang,
    env: &Env,
    depth: usize,
    interpolate: bool,
    raw: bool,
) -> String {
    let chars: Vec<char> = body.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            let n = chars[i + 1];
            if raw {
                if matches!(n, '\'' | '\\') {
                    out.push(n);
                } else {
                    out.push(c);
                    out.push(n);
                }
            } else {
                out.push(match n {
                    'n' => '\n',
                    't' => '\t',
                    o => o,
                });
            }
            i += 2;
            continue;
        }
        if interpolate {
            let rest: String = chars[i..].iter().collect();
            // ${expr} (node, perl, php), #{expr} (ruby), {expr} (python f-strings), {$x} (php).
            let open = match lang {
                Lang::Node | Lang::Perl | Lang::Php if rest.starts_with("${") => Some(2),
                Lang::Ruby if rest.starts_with("#{") => Some(2),
                Lang::Python if rest.starts_with("{{") => {
                    out.push('{');
                    i += 2;
                    continue;
                }
                Lang::Python if rest.starts_with('{') => Some(1),
                Lang::Php if rest.starts_with("{$") => Some(1),
                _ => None,
            };
            if let Some(skip) = open {
                let inner_start = i + skip;
                let close = (inner_start..chars.len()).find(|&k| chars[k] == '}');
                if let Some(close) = close {
                    let inner: String = chars[inner_start..close].iter().collect();
                    let inner = inner.split(':').next().unwrap_or("").trim().to_string();
                    let name = match lang {
                        Lang::Perl if !inner.starts_with('$') => format!("${inner}"),
                        _ => inner,
                    };
                    out.push_str(&first_text(&name, lang, env, depth));
                    i = close + 1;
                    continue;
                }
            }
            // perl/php "$name", perl "@name".
            if matches!(lang, Lang::Perl | Lang::Php)
                && (c == '$' || (c == '@' && lang == Lang::Perl))
            {
                let end = (i + 1..chars.len())
                    .find(|&k| !(chars[k].is_alphanumeric() || chars[k] == '_'))
                    .unwrap_or(chars.len());
                if end > i + 1 {
                    let name: String = chars[i..end].iter().collect();
                    out.push_str(&first_text(&name, lang, env, depth));
                    i = end;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// A template's interpolations filled in (backticks, `qx`, `%x`, `$\`...\``).
pub(super) fn interpolate(text: &str, lang: Lang, env: &Env) -> String {
    fill_interp(text, lang, env, 0, true, false)
}
