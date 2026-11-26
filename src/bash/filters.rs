//! What a filter on the way to a shell turns a script into: `sed 's/^/sudo /' <<EOF | bash` runs `sudo` plus each
//! body line, which the body as written doesn't show. `outputs` gives the texts to check: the text as written (so a
//! filter that drops a line still fails closed) and what the filters would make of it.
//!
//! - sed (gsed): `s/PATTERN/REPLACEMENT/FLAGS` with basic or `-E`/`-r` regexes, `&`, `\1`..`\9` and `g`; `i`, `a`
//!   and `c` text; several `-e` scripts and `;`-separated commands. Addresses are ignored (every line counts). A
//!   pattern that won't translate counts as `^`, with the replacement also checked on its own line.
//! - awk (gawk, mawk, nawk): each `print` list of string literals, `$0`, `$N`, `$NF` and commas; anything else adds
//!   "every literal, then the line".
//! - `perl -pe`/`-ne`: its `s///` commands, read like sed `-E`.
//! - Any other command passes the text on unchanged (grep, sort, tr, cat, tee, head).
//!
//! A heuristic: a filter can build a command in ways no static reading follows (variables, `y///`, `tr`, `rev`).

use crate::pyfs;
use regex::Regex;

/// The most texts kept per pipeline, so many filters can't multiply the work.
const MAX_VARIANTS: usize = 8;

/// The texts to check for `text` sent through `chain` (each a simple command, in pipeline order).
pub(super) fn outputs(chain: &[Vec<String>], text: &str) -> Vec<String> {
    let mut texts = vec![text.to_string()];
    for seg in chain {
        let mut next: Vec<String> = Vec::new();
        for t in &texts {
            for v in apply(seg, t) {
                if !next.contains(&v) {
                    next.push(v);
                }
            }
        }
        next.truncate(MAX_VARIANTS);
        texts = next;
    }
    if !texts.iter().any(|t| t == text) {
        texts.push(text.to_string());
    }
    texts
}

/// What one filter could make of `text`.
fn apply(seg: &[String], text: &str) -> Vec<String> {
    let Some(verb) = seg.first() else {
        return vec![text.to_string()];
    };
    let args = &seg[1..];
    match pyfs::basename(verb) {
        "sed" | "gsed" => sed(args, text),
        "awk" | "gawk" | "mawk" | "nawk" => awk(args, text),
        "perl" => perl(args, text),
        _ => vec![text.to_string()],
    }
}

enum SedCmd {
    Sub {
        pat: String,
        repl: String,
        global: bool,
    },
    Insert(String),
    Append(String),
    Change(String),
}

fn sed(args: &[String], text: &str) -> Vec<String> {
    let mut scripts: Vec<String> = Vec::new();
    let mut ere = false;
    let mut k = 0;
    let mut positional: Option<String> = None;
    while k < args.len() {
        let a = args[k].as_str();
        if let Some(v) = a.strip_prefix("--expression=") {
            scripts.push(v.to_string());
        } else if a == "--expression" || a == "-e" {
            k += 1;
            if let Some(v) = args.get(k) {
                scripts.push(v.clone());
            }
        } else if a == "--regexp-extended" {
            ere = true;
        } else if a == "-f" || a.starts_with("--file") {
            return vec![text.to_string()]; // script in a file: not read
        } else if a.starts_with("--") {
            // --quiet, --in-place, --null-data, ...
        } else if a.starts_with('-') && a.len() > 1 {
            let letters = &a[1..];
            if letters.contains('E') || letters.contains('r') {
                ere = true;
            }
            if letters.contains('f') {
                return vec![text.to_string()];
            }
            if letters.ends_with('e') {
                k += 1;
                if let Some(v) = args.get(k) {
                    scripts.push(v.clone());
                }
            }
        } else if positional.is_none() {
            positional = Some(a.to_string());
        }
        k += 1;
    }
    if scripts.is_empty() {
        scripts.extend(positional);
    }
    let cmds: Vec<SedCmd> = scripts.iter().flat_map(|s| parse_sed(s)).collect();
    if cmds.is_empty() {
        return vec![text.to_string()];
    }
    let mut out = vec![run_sed(&cmds, text, ere, false)];
    if cmds
        .iter()
        .any(|c| matches!(c, SedCmd::Sub { pat, .. } if to_regex(pat, ere).is_none()))
    {
        out.push(run_sed(&cmds, text, ere, true));
    }
    out
}

/// Reads up to an unescaped `delim`; returns (text, index after the delimiter).
fn until_delim(chars: &[char], mut i: usize, delim: char) -> (String, usize) {
    let mut s = String::new();
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            if chars[i + 1] == delim {
                s.push(delim);
            } else {
                s.push(c);
                s.push(chars[i + 1]);
            }
            i += 2;
            continue;
        }
        if c == delim {
            return (s, i + 1);
        }
        s.push(c);
        i += 1;
    }
    (s, i)
}

fn parse_sed(script: &str) -> Vec<SedCmd> {
    let chars: Vec<char> = script.chars().collect();
    let mut cmds = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() || c == ';' || c == '{' || c == '}' || c == '!' {
            i += 1;
            continue;
        }
        // Addresses: line numbers, `$`, ranges, /regex/, \cREGEXc.
        if c.is_ascii_digit() || c == '$' || c == ',' || c == '~' || c == '+' {
            i += 1;
            continue;
        }
        if c == '/' {
            i = until_delim(&chars, i + 1, '/').1;
            continue;
        }
        if c == '\\' && i + 1 < chars.len() {
            let d = chars[i + 1];
            i = until_delim(&chars, i + 2, d).1;
            continue;
        }
        match c {
            's' if i + 1 < chars.len() => {
                let d = chars[i + 1];
                let (pat, j) = until_delim(&chars, i + 2, d);
                let (repl, j) = until_delim(&chars, j, d);
                let mut j = j;
                let mut global = false;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric()) {
                    global |= chars[j] == 'g';
                    j += 1;
                }
                cmds.push(SedCmd::Sub { pat, repl, global });
                i = j;
            }
            'y' if i + 1 < chars.len() => {
                let d = chars[i + 1];
                let (_, j) = until_delim(&chars, i + 2, d);
                i = until_delim(&chars, j, d).1;
            }
            'i' | 'a' | 'c' => {
                let mut j = i + 1;
                if chars.get(j) == Some(&'\\') {
                    j += 1;
                    if chars.get(j) == Some(&'\n') {
                        j += 1;
                    }
                }
                let end = (j..chars.len())
                    .find(|&k| chars[k] == '\n')
                    .unwrap_or(chars.len());
                let t: String = chars[j..end]
                    .iter()
                    .collect::<String>()
                    .trim_start()
                    .to_string();
                cmds.push(match c {
                    'i' => SedCmd::Insert(t),
                    'a' => SedCmd::Append(t),
                    _ => SedCmd::Change(t),
                });
                i = end;
            }
            _ => {
                // Another command (d, p, q, n, ...): skip to its end.
                while i < chars.len() && chars[i] != ';' && chars[i] != '\n' {
                    i += 1;
                }
            }
        }
    }
    cmds
}

/// A sed regex as a Rust one (None if it won't translate).
fn to_regex(pat: &str, ere: bool) -> Option<Regex> {
    if ere {
        return Regex::new(pat).ok();
    }
    let chars: Vec<char> = pat.chars().collect();
    let mut s = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            let n = chars[i + 1];
            match n {
                '(' | ')' | '{' | '}' | '+' | '?' | '|' => s.push(n),
                _ => {
                    s.push('\\');
                    s.push(n);
                }
            }
            i += 2;
            continue;
        }
        match c {
            '(' | ')' | '{' | '}' | '+' | '?' | '|' => {
                s.push('\\');
                s.push(c);
            }
            _ => s.push(c),
        }
        i += 1;
    }
    Regex::new(&s).ok()
}

/// A sed replacement in the regex crate's syntax: `&` the match, `\1` a group, `\n` a newline.
fn to_replacement(repl: &str) -> String {
    let chars: Vec<char> = repl.chars().collect();
    let mut s = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            let n = chars[i + 1];
            match n {
                '1'..='9' => s.push_str(&format!("${{{n}}}")),
                'n' => s.push('\n'),
                't' => s.push('\t'),
                '&' => s.push('&'),
                _ => s.push(n),
            }
            i += 2;
            continue;
        }
        match c {
            '&' => s.push_str("${0}"),
            '$' => s.push_str("$$"),
            _ => s.push(c),
        }
        i += 1;
    }
    s
}

/// The sed script applied to every line. `as_prefix`: a pattern that won't translate counts as `^`, and its
/// replacement also gets a line of its own.
fn run_sed(cmds: &[SedCmd], text: &str, ere: bool, as_prefix: bool) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let mut before: Vec<String> = Vec::new();
        let mut after: Vec<String> = Vec::new();
        let mut cur = line.to_string();
        for cmd in cmds {
            match cmd {
                SedCmd::Sub { pat, repl, global } => match to_regex(pat, ere) {
                    Some(re) => {
                        let r = to_replacement(repl);
                        cur = if *global {
                            re.replace_all(&cur, r.as_str()).into_owned()
                        } else {
                            re.replace(&cur, r.as_str()).into_owned()
                        };
                    }
                    None if as_prefix => {
                        let plain = repl.replace(['&', '\\'], "");
                        before.push(plain.clone());
                        cur = format!("{plain}{cur}");
                    }
                    None => {}
                },
                SedCmd::Insert(t) => before.push(t.clone()),
                SedCmd::Append(t) => after.push(t.clone()),
                SedCmd::Change(t) => cur = t.clone(),
            }
        }
        out.extend(before);
        out.push(cur);
        out.extend(after);
    }
    out.join("\n")
}

/// awk: the program's `print` lists evaluated for each line.
fn awk(args: &[String], text: &str) -> Vec<String> {
    let mut k = 0;
    let mut program: Option<&str> = None;
    while k < args.len() {
        let a = args[k].as_str();
        if a == "-f" || a.starts_with("--file") {
            return vec![text.to_string()];
        }
        if a == "-F" || a == "-v" {
            k += 2;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            k += 1;
            continue;
        }
        program = Some(a);
        break;
    }
    let Some(program) = program else {
        return vec![text.to_string()];
    };
    let prints: Vec<String> = Regex::new(r"\bprint\b([^;}\n]*)")
        .map(|re| {
            re.captures_iter(program)
                .map(|c| c[1].to_string())
                .collect()
        })
        .unwrap_or_default();
    let literals = string_literals(program);
    let mut out = Vec::new();
    if !prints.is_empty() {
        let lines: Vec<String> = text
            .split('\n')
            .flat_map(|line| prints.iter().map(move |p| eval_print(p, line)))
            .collect();
        out.push(lines.join("\n"));
    }
    if prints.is_empty() || program.contains("printf") || program.contains("$(") {
        let joined = literals.concat();
        out.push(
            text.split('\n')
                .map(|l| format!("{joined}{l}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    out
}

/// The double-quoted string literals of an awk program, unescaped.
fn string_literals(program: &str) -> Vec<String> {
    let chars: Vec<char> = program.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '"' {
            let mut s = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    s.push(match chars[i + 1] {
                        'n' => '\n',
                        't' => '\t',
                        o => o,
                    });
                    i += 2;
                    continue;
                }
                s.push(chars[i]);
                i += 1;
            }
            out.push(s);
        }
        i += 1;
    }
    out
}

/// One awk `print` list for one input line: literals, `$0`, `$N`, `$NF`; commas print a space.
fn eval_print(expr: &str, line: &str) -> String {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let chars: Vec<char> = expr.chars().collect();
    let mut out = String::new();
    let mut any = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            let end = (i + 1..chars.len()).find(|&k| chars[k] == '"' && chars[k - 1] != '\\');
            let end = end.unwrap_or(chars.len());
            out.push_str(
                &string_literals(
                    &chars[i..(end + 1).min(chars.len())]
                        .iter()
                        .collect::<String>(),
                )
                .concat(),
            );
            any = true;
            i = end + 1;
            continue;
        }
        if c == '$' {
            let rest: String = chars[i + 1..].iter().collect();
            if rest.starts_with("NF") {
                out.push_str(fields.last().copied().unwrap_or(""));
                i += 3;
            } else {
                let digits: String = rest.chars().take_while(|d| d.is_ascii_digit()).collect();
                let n: usize = digits.parse().unwrap_or(0);
                out.push_str(if n == 0 {
                    line
                } else {
                    fields.get(n - 1).copied().unwrap_or("")
                });
                i += 1 + digits.len().max(1);
            }
            any = true;
            continue;
        }
        if c == ',' {
            out.push(' ');
        }
        i += 1;
    }
    if any {
        out
    } else {
        line.to_string() // a bare `print`
    }
}

/// `perl -pe 's/../../'`: its substitutions, read like sed -E.
fn perl(args: &[String], text: &str) -> Vec<String> {
    let looping = args.iter().any(|a| {
        a.starts_with('-') && !a.starts_with("--") && (a.contains('p') || a.contains('n'))
    });
    let script = args
        .iter()
        .position(|a| a.starts_with('-') && !a.starts_with("--") && a.ends_with('e'))
        .and_then(|i| args.get(i + 1));
    match script {
        Some(s) if looping => {
            let cmds: Vec<SedCmd> = parse_sed(s)
                .into_iter()
                .filter(|c| matches!(c, SedCmd::Sub { .. }))
                .collect();
            if cmds.is_empty() {
                vec![text.to_string()]
            } else {
                vec![run_sed(&cmds, text, true, false)]
            }
        }
        _ => vec![text.to_string()],
    }
}
