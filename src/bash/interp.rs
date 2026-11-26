//! Commands run by code given to an interpreter, so every rule holds inside them (Rust only):
//!
//! | Interpreter | Code from | Commands |
//! | --- | --- | --- |
//! | perl | `-e`/`-E` (also `-ne`, `-lane`), stdin, a file | `system`, `exec`, `readpipe`, backticks, `qx`, pipe `open` |
//! | python (`python3.12`, pypy) | `-c`, stdin, a file | `os.system`, `os.popen`, `subprocess.*`, `os.exec*`, `os.spawn*` |
//! | node, bun, deno | `-e`/`--eval`/`-p`, `deno eval`, stdin, a file | `child_process` `exec*`/`spawn*`/`execFile*`, `Bun.spawn`, Bun `` $`...` ``, `Deno.Command`, `Deno.run` |
//! | ruby | `-e`, stdin, a file | `system`, `exec`, `spawn`, backticks, `%x{}`, `IO.popen`, `Open3.*` |
//! | php | `-r`/`-R`/`-B`/`-E`, stdin, a file | `exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`, backticks |
//! | lua | `-e`, stdin, a file | `os.execute`, `io.popen` |
//! | osascript | `-e`, stdin, a file | `do shell script` |
//!
//! Indirect calls count too (`indirect_calls`: getattr, aliases, bracket access, send, call_user_func, variable
//! functions), and environment lookups and file reads take what the command around the code gives them
//! (`context`).
//!
//! Arguments are evaluated with the code's variables (`values`), and built code run through eval/exec (python
//! `exec`/`eval`/`compile`, node `eval`/`new Function`/`vm.*`, ruby `eval`/`instance_eval`, perl string `eval`, php
//! `eval`, lua `load`) is read again as code, up to `MAX_CODE_DEPTH` levels.
//!
//! A call's argument is read from its string literals: one string is a command line; a list (`["git", "push"]`) or
//! several arguments are an argv. Literals joined with `.`, `+` or `&` count as one, and variables between them
//! drop out (`"rm -rf " . $dir` reads as `rm -rf `); interpolations (`${x}`, `#{x}`, f-string `{x}`) read as the word
//! `x`, so `/srv/${name}` stays absolute and `${dir}/build` stays relative. A heuristic: code that builds a command
//! any other way (eval, variables, ffi) isn't followed.

use super::values::{self, Env, Val};
use super::wrappers::shell_join;
use crate::pyfs;
use regex::Regex;
use std::sync::LazyLock;

static INTERP: LazyLock<Regex> = LazyLock::new(|| super::re(r"[$#]\{[^}]*\}"));

#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum Lang {
    Perl,
    Python,
    Node,
    Ruby,
    Php,
    Lua,
    Osa,
}

/// Where an interpreter takes its code from.
pub(super) enum Source {
    Inline(String),
    Stdin,
    File(String),
    None,
}

pub(super) fn lang_of(verb: &str) -> Option<Lang> {
    let b = pyfs::basename(verb);
    let python = b == "python"
        || b == "pypy"
        || b == "pypy3"
        || (b.starts_with("python") && b[6..].chars().all(|c| c.is_ascii_digit() || c == '.'));
    Some(match b {
        "perl" | "perl5" => Lang::Perl,
        "node" | "nodejs" | "bun" | "deno" => Lang::Node,
        "ruby" | "jruby" => Lang::Ruby,
        "php" => Lang::Php,
        "osascript" => Lang::Osa,
        _ if b == "lua"
            || b == "luajit"
            || (b.starts_with("lua") && b[3..].chars().all(|c| c.is_ascii_digit() || c == '.')) =>
        {
            Lang::Lua
        }
        _ if python => Lang::Python,
        _ => return None,
    })
}

/// The code an interpreter command runs: inline options, stdin, or a file.
pub(super) fn source(seg: &[String]) -> Option<(Lang, Source)> {
    let lang = lang_of(seg.first()?)?;
    let mut args: &[String] = &seg[1..];
    let verb = pyfs::basename(&seg[0]);
    if verb == "deno" {
        match args.first().map(String::as_str) {
            Some("eval") => {
                let code = args[1..].iter().find(|a| !a.starts_with('-'))?;
                return Some((lang, Source::Inline(code.clone())));
            }
            Some("run") => args = &args[1..],
            _ => return Some((lang, Source::None)),
        }
    }
    if verb == "bun" && args.first().is_some_and(|a| a == "run") {
        args = &args[1..];
    }
    // (letters whose code follows, long forms, letters that take a value)
    let (code_letters, code_long, value_letters): (&str, &[&str], &str) = match lang {
        // perl's -l, -0, -i and -x take only an attached value; -I may take the next argument.
        Lang::Perl => ("eE", &[], "I"),
        Lang::Python => ("c", &[], "WXQ"),
        Lang::Node => ("ep", &["--eval", "--print"], "r"),
        Lang::Ruby => ("e", &[], "IrECFTxW"),
        Lang::Php => ("rRBE", &[], "cdzF"),
        Lang::Lua => ("e", &[], "l"),
        Lang::Osa => ("e", &[], "ls"),
    };
    let mut inline: Vec<String> = Vec::new();
    let mut k = 0;
    while k < args.len() {
        let a = args[k].as_str();
        if a == "--" {
            k += 1;
            break;
        }
        if let Some((opt, v)) = a.split_once('=') {
            if code_long.contains(&opt) {
                inline.push(v.to_string());
                k += 1;
                continue;
            }
        }
        if code_long.contains(&a) {
            if let Some(v) = args.get(k + 1) {
                inline.push(v.clone());
            }
            k += 2;
            continue;
        }
        if lang == Lang::Python && a == "-m" {
            return Some((lang, Source::None)); // a module, not code
        }
        if a.starts_with("--") {
            k += 1;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            let letters: Vec<char> = a[1..].chars().collect();
            let mut took_next = false;
            for (li, c) in letters.iter().enumerate() {
                if code_letters.contains(*c) {
                    let attached: String = letters[li + 1..].iter().collect();
                    if attached.is_empty() {
                        if let Some(v) = args.get(k + 1) {
                            inline.push(v.clone());
                        }
                        took_next = true;
                    } else {
                        inline.push(attached);
                    }
                    break;
                }
                if value_letters.contains(*c) {
                    if li + 1 == letters.len() {
                        took_next = true; // its value is the next argument
                    }
                    break;
                }
            }
            k += if took_next { 2 } else { 1 };
            continue;
        }
        break;
    }
    if !inline.is_empty() {
        return Some((lang, Source::Inline(inline.join("\n"))));
    }
    Some((
        lang,
        match args.get(k).map(String::as_str) {
            None | Some("-") => Source::Stdin,
            Some(f) => Source::File(f.to_string()),
        },
    ))
}

/// The commands an interpreter command runs, for its inline code, or for `input` when it reads its code from stdin
/// and the input is known (a heredoc or `echo` feeding it).
pub(super) fn commands(seg: &[String], input: Option<&str>) -> Vec<String> {
    match source(seg) {
        Some((lang, Source::Inline(code))) => code_commands(lang, &code),
        Some((lang, Source::Stdin)) => input.map(|c| code_commands(lang, c)).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// How a call's argument becomes a command line.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// One string is a command line; a list or several arguments are an argv.
    Cmd,
    /// The program, then an argv list (or more arguments): `spawn("git", ["push"])`, `os.execvp(...)`.
    ProgArgs,
    /// Python `os.spawn*`: a mode first, then the program and its argv.
    Spawn,
    /// eval/exec of a built string: the first argument is more code in the same language.
    Code,
    /// `new Function(..., body)`: the last argument is the code.
    CodeLast,
}

/// How deep eval of built code is followed.
const MAX_CODE_DEPTH: usize = 4;

/// The commands in one piece of code.
pub(super) fn code_commands(lang: Lang, code: &str) -> Vec<String> {
    code_commands_at(lang, code, 0)
}

fn code_commands_at(lang: Lang, code: &str, depth: usize) -> Vec<String> {
    let env = values::env_of(code, lang);
    let in_str = string_mask(code, lang);
    let mut calls: Vec<(&str, Kind)> = match lang {
        Lang::Perl => vec![
            (r"\bsystem\b", Kind::Cmd),
            (r"\bexec\b", Kind::Cmd),
            (r"\breadpipe\b", Kind::Cmd),
            (r"\beval\b", Kind::Code),
        ],
        Lang::Python => vec![
            (r"\bos\.system\b", Kind::Cmd),
            (r"\bos\.popen\b", Kind::Cmd),
            (
                r"\bsubprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\b",
                Kind::Cmd,
            ),
            (r"\bcommands\.getoutput\b", Kind::Cmd),
            (r"\bos\.exec\w+\b", Kind::ProgArgs),
            (r"\bos\.spawn\w+\b", Kind::Spawn),
            (
                r#"\b__import__\(\s*["'](?:os|subprocess)["']\s*\)\.(?:system|popen|run|call|check_call|check_output|Popen|getoutput)\b"#,
                Kind::Cmd,
            ),
            (r"(?:^|[^.\w])(?:exec|eval|compile)\b", Kind::Code),
        ],
        Lang::Node => vec![
            (r"\bBun\.spawn(?:Sync)?\b", Kind::Cmd),
            (r"\bDeno\.run\b", Kind::Cmd),
            (r"\bnew\s+Deno\.Command\b", Kind::ProgArgs),
            (r"(?:^|[^.\w])eval\b", Kind::Code),
            (r"\bnew\s+Function\b", Kind::CodeLast),
            (
                r"\bvm\.(?:runInNewContext|runInThisContext|runInContext)\b",
                Kind::Code,
            ),
            (r"\bnew\s+vm\.Script\b", Kind::Code),
        ],
        Lang::Ruby => vec![
            (r"\bsystem\b", Kind::Cmd),
            (r"\bexec\b", Kind::Cmd),
            (r"\bspawn\b", Kind::Cmd),
            (r"\bIO\.popen\b", Kind::Cmd),
            (
                r"\bOpen3\.(?:capture2e?|capture3|popen2e?|popen3|pipeline\w*)\b",
                Kind::Cmd,
            ),
            (
                r"\b(?:eval|instance_eval|class_eval|module_eval)\b",
                Kind::Code,
            ),
        ],
        Lang::Php => vec![
            (
                r"\b(?:exec|shell_exec|system|passthru|popen|proc_open)\b",
                Kind::Cmd,
            ),
            (r"\beval\b", Kind::Code),
        ],
        Lang::Lua => vec![
            (r"\bos\.execute\b", Kind::Cmd),
            (r"\bio\.popen\b", Kind::Cmd),
            (r"\b(?:load|loadstring)\b", Kind::Code),
        ],
        Lang::Osa => vec![(r"\bdo\s+shell\s+script\b", Kind::Cmd)],
    };
    // Python: modules imported under another name (`import subprocess as sp`).
    let alias_pats: Vec<String> = if lang == Lang::Python {
        super::re(r"\bimport\s+(os|subprocess)\s+as\s+(\w+)")
            .captures_iter(code)
            .map(|c| {
                if &c[1] == "os" {
                    format!(r"\b{}\.(?:system|popen)\b", &c[2])
                } else {
                    format!(
                        r"\b{}\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\b",
                        &c[2]
                    )
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    for p in &alias_pats {
        calls.push((p.as_str(), Kind::Cmd));
    }
    // Python: names imported from os or subprocess (`from subprocess import run`).
    if lang == Lang::Python
        && (code.contains("from subprocess import") || code.contains("from os import"))
    {
        calls.push((
            r"(?:^|[^.\w])(?:run|call|check_call|check_output|Popen|getoutput|system|popen)\b",
            Kind::Cmd,
        ));
    }
    // Node: child_process functions, called through the module or destructured.
    if lang == Lang::Node && code.contains("child_process") {
        calls.push((r"\b(?:exec|execSync)\b", Kind::Cmd));
        calls.push((
            r"\b(?:spawn|spawnSync|execFile|execFileSync)\b",
            Kind::ProgArgs,
        ));
    }
    let mut out = Vec::new();
    for (pat, kind) in calls {
        let re = super::re(pat);
        for m in re.find_iter(code) {
            if in_str.get(m.start()).copied().unwrap_or(false)
                || not_a_call(code, m.start(), m.end(), lang)
            {
                continue;
            }
            let Some(args) = call_args(code, m.end(), lang) else {
                continue;
            };
            match kind {
                Kind::Code | Kind::CodeLast => {
                    if depth >= MAX_CODE_DEPTH || args.trim_start().starts_with('{') {
                        continue; // too deep, or perl/ruby `eval { block }` (already read as code)
                    }
                    let parts = top_level_split(&args);
                    let part = if matches!(kind, Kind::CodeLast) {
                        parts.last()
                    } else {
                        parts.first()
                    };
                    for v in part
                        .map(|p| values::eval(p, lang, &env, 0))
                        .unwrap_or_default()
                    {
                        out.extend(code_commands_at(lang, &v.text(), depth + 1));
                    }
                }
                _ => out.extend(command_of(&args, kind, lang, &env)),
            }
        }
    }
    // Backtick and %x / qx substitutions.
    // Calls reached indirectly: getattr, aliases, bracket access, send, call_user_func, variable functions.
    for (args, kind) in indirect_calls(code, lang, &env) {
        out.extend(command_of(&args, kind, lang, &env));
    }
    let fill = |t: String| values::interpolate(&t, lang, &env);
    match lang {
        Lang::Perl | Lang::Ruby | Lang::Php => out.extend(backticks(code).into_iter().map(fill)),
        _ => {}
    }
    if lang == Lang::Perl {
        out.extend(quoted_forms(code, "qx").into_iter().map(fill));
        out.extend(perl_pipe_opens(code, &env));
    }
    if lang == Lang::Ruby {
        out.extend(quoted_forms(code, "%x").into_iter().map(fill));
    }
    if lang == Lang::Node {
        // Bun shell and zx: $`cmd`. The `$` starts an expression (after a blank or `(`, `=`, `,`, ...), so a
        // regex's end anchor before a template literal's closing backtick (`` `^${k}\\s*$` ``) isn't one.
        {
            let re = super::re(r"(?:^|[\s(=,;:!?&|{\[+])\$`((?:[^`\\]|\\.)*)`");
            out.extend(re.captures_iter(code).map(|c| fill(c[1].to_string())));
        }
    }
    out.retain(|c| !c.trim().is_empty());
    out.dedup();
    out
}

const PY_OS: &[&str] = &["system", "popen"];
const PY_SUBPROCESS: &[&str] = &[
    "run",
    "call",
    "check_call",
    "check_output",
    "Popen",
    "getoutput",
    "getstatusoutput",
];
const NODE_CMD: &[&str] = &["exec", "execSync"];
const RUBY_CMD: &[&str] = &["system", "exec", "spawn"];
const PHP_CMD: &[&str] = &[
    "system",
    "exec",
    "shell_exec",
    "passthru",
    "popen",
    "proc_open",
];

/// The argument text after the first argument (`send(:system, "ls")` -> `"ls"`).
fn rest_args(args: &str) -> String {
    top_level_split(args)
        .into_iter()
        .skip(1)
        .collect::<Vec<_>>()
        .join(",")
}

/// Calls to a command-running function reached indirectly, as (argument text, kind):
/// - python `getattr(os, "system")(...)`, `getattr(__import__("os"), "system")(...)`, aliases `f = os.system`,
///   `from subprocess import run as r`;
/// - node `cp["execSync"](...)`, `const run = cp.execSync`, `const {execSync: run} = require(...)`;
/// - ruby `send(:system, ...)` (also `public_send`, `__send__`), `method(:system).call(...)`;
/// - php `call_user_func("system", ...)`, `call_user_func_array("system", [...])`, `$f = "system"; $f(...)`.
fn indirect_calls(code: &str, lang: Lang, env: &Env) -> Vec<(String, Kind)> {
    let in_str = string_mask(code, lang);
    let mut out = Vec::new();
    let r = |s: &str| super::re(s);
    // Calls of these names (aliases) anywhere in the code.
    let mut aliases: Vec<(String, Kind)> = Vec::new();
    match lang {
        Lang::Python => {
            let re = r(
                r#"\bgetattr\s*\(\s*(?:os|subprocess|__import__\(\s*["'](?:os|subprocess)["']\s*\))\s*,\s*([^)]*)\)\s*\("#,
            );
            for c in re.captures_iter(code) {
                let name = values::eval(&c[1], lang, env, 0)
                    .first()
                    .map(Val::text)
                    .unwrap_or_default();
                if PY_OS.contains(&name.as_str()) || PY_SUBPROCESS.contains(&name.as_str()) {
                    let at = c.get(0).map(|m| m.end() - 1).unwrap_or(0);
                    out.extend(call_args(code, at, lang).map(|a| (a, Kind::Cmd)));
                }
            }
            let alias = r(
                r"(?m)(?:^|;)\s*(\w+)\s*=\s*(?:os\.(?:system|popen)|subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput))\s*(?:$|;)",
            );
            aliases.extend(
                alias
                    .captures_iter(code)
                    .map(|c| (c[1].to_string(), Kind::Cmd)),
            );
            let from = r(r"\bfrom\s+(?:os|subprocess)\s+import\s+([^\n;]+)");
            for c in from.captures_iter(code) {
                for item in c[1].split(',') {
                    if let Some((orig, new)) = item.split_once(" as ") {
                        let orig = orig.trim();
                        if PY_OS.contains(&orig) || PY_SUBPROCESS.contains(&orig) {
                            aliases
                                .push((new.trim().trim_matches(['(', ')']).to_string(), Kind::Cmd));
                        }
                    }
                }
            }
        }
        Lang::Node if code.contains("child_process") => {
            let bracket = r(
                r#"\[\s*["'`](exec|execSync|spawn|spawnSync|execFile|execFileSync)["'`]\s*\]\s*\("#,
            );
            for c in bracket.captures_iter(code) {
                let kind = if NODE_CMD.contains(&&c[1]) {
                    Kind::Cmd
                } else {
                    Kind::ProgArgs
                };
                let at = c.get(0).map(|m| m.end() - 1).unwrap_or(0);
                out.extend(call_args(code, at, lang).map(|a| (a, kind)));
            }
            let assign = r(
                r"\b(?:const|let|var)\s+(\w+)\s*=\s*[\w.$]*\.(exec|execSync|spawn|spawnSync|execFile|execFileSync)\b\s*(?:;|$|\n)",
            );
            let rename = r(r"\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*:\s*(\w+)");
            for c in assign.captures_iter(code) {
                let kind = if NODE_CMD.contains(&&c[2]) {
                    Kind::Cmd
                } else {
                    Kind::ProgArgs
                };
                aliases.push((c[1].to_string(), kind));
            }
            for c in rename.captures_iter(code) {
                let kind = if NODE_CMD.contains(&&c[1]) {
                    Kind::Cmd
                } else {
                    Kind::ProgArgs
                };
                aliases.push((c[2].to_string(), kind));
            }
        }
        Lang::Ruby => {
            let send = r(r"\b(?:send|public_send|__send__)\s*\(\s*:(\w+)\s*,");
            for c in send.captures_iter(code) {
                if RUBY_CMD.contains(&&c[1]) {
                    let open = code[..c.get(0).map(|m| m.start()).unwrap_or(0)].len()
                        + c[0].find('(').unwrap_or(0);
                    if let Some(a) = call_args(code, open, lang) {
                        out.push((rest_args(&a), Kind::Cmd));
                    }
                }
            }
            let method = r(r"\bmethod\s*\(\s*:(\w+)\s*\)\s*\.\s*call\b");
            for c in method.captures_iter(code) {
                if RUBY_CMD.contains(&&c[1]) {
                    let at = c.get(0).map(|m| m.end()).unwrap_or(0);
                    out.extend(call_args(code, at, lang).map(|a| (a, Kind::Cmd)));
                }
            }
        }
        Lang::Php => {
            let cuf = r(r#"\bcall_user_func(?:_array)?\s*\(\s*["'](\w+)["']\s*,"#);
            for c in cuf.captures_iter(code) {
                if PHP_CMD.contains(&&c[1]) {
                    let open =
                        c.get(0).map(|m| m.start()).unwrap_or(0) + c[0].find('(').unwrap_or(0);
                    if let Some(a) = call_args(code, open, lang) {
                        let rest = rest_args(&a);
                        // call_user_func_array: the array is the function's argument list.
                        let rest = if c[0].contains("_array") {
                            let t = rest.trim();
                            t.strip_prefix('[')
                                .and_then(|x| x.strip_suffix(']'))
                                .unwrap_or(t)
                                .to_string()
                        } else {
                            rest
                        };
                        out.push((rest, Kind::Cmd));
                    }
                }
            }
            // `$f = "system"; $f("...")`.
            let varcall = r(r"\$(\w+)\s*\(");
            for c in varcall.captures_iter(code) {
                let name = format!("${}", &c[1]);
                if env
                    .texts(&name)
                    .iter()
                    .any(|v| PHP_CMD.contains(&v.as_str()))
                {
                    let at = c.get(0).map(|m| m.end() - 1).unwrap_or(0);
                    out.extend(call_args(code, at, lang).map(|a| (a, Kind::Cmd)));
                }
            }
        }
        _ => {}
    }
    for (name, kind) in aliases {
        let re = super::re(&format!(r"(?:^|[^.\w$]){}\s*\(", regex::escape(&name)));
        for m in re.find_iter(code) {
            if in_str.get(m.start()).copied().unwrap_or(false) {
                continue;
            }
            out.extend(call_args(code, m.end() - 1, lang).map(|a| (a, kind)));
        }
    }
    out
}

/// True if the name at `start..end` is a variable (`$exec`, `@system`), assigned to (`$system = ...`), or a method
/// on some other object (`$pdo->exec(...)` runs SQL; ruby `obj.system`), not the call that runs a command.
fn not_a_call(code: &str, start: usize, end: usize, lang: Lang) -> bool {
    let before = &code[..start];
    if before.ends_with(['$', '@', '%']) || before.ends_with("->") || before.ends_with("::") {
        return true;
    }
    if lang == Lang::Ruby
        && before.ends_with('.')
        && !(before.ends_with("Kernel.") || before.ends_with("Process."))
    {
        return true;
    }
    let after = code[end..].trim_start();
    after.starts_with('=') && !after.starts_with("==") && !after.starts_with("=>")
}

/// For each byte of `code`, whether it sits inside a string literal (a call name in text, not code). One pass per
/// piece of code, so checking every match stays linear.
fn string_mask(code: &str, lang: Lang) -> Vec<bool> {
    let mut mask = vec![false; code.len()];
    let mut q: Option<char> = None;
    let mut esc = false;
    for (i, c) in code.char_indices() {
        mask[i] = q.is_some();
        if esc {
            esc = false;
            continue;
        }
        match q {
            Some(open) => {
                if c == '\\' && open != '\'' {
                    esc = true;
                } else if c == open {
                    q = None;
                }
            }
            None => {
                if c == '"' || c == '\'' || (c == '`' && lang != Lang::Python) {
                    q = Some(c);
                }
            }
        }
    }
    mask
}

/// The argument text of a call whose name ends at byte `at`: inside its parentheses, or (perl, ruby, lua,
/// osascript, php) to the end of the statement when there are none. Reads only as far as the call goes.
fn call_args(code: &str, at: usize, lang: Lang) -> Option<String> {
    let rest = code.get(at..)?;
    let s = rest.trim_start_matches([' ', '\t']);
    if s.starts_with('(') {
        return Some(balanced(s, '(', ')', lang));
    }
    if matches!(lang, Lang::Python | Lang::Node) {
        return None; // a name, not a call
    }
    // Paren-less: to `;`, a newline or a closing brace, outside strings.
    let mut q: Option<char> = None;
    let mut esc = false;
    let mut end = s.len();
    for (i, c) in s.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        match q {
            Some(open) => {
                if c == '\\' && open != '\'' {
                    esc = true;
                } else if c == open {
                    q = None;
                }
            }
            None => {
                if c == '"' || c == '\'' || c == '`' {
                    q = Some(c);
                } else if c == ';' || c == '\n' || c == '}' {
                    end = i;
                    break;
                }
            }
        }
    }
    let text = &s[..end];
    (!text.trim().is_empty()).then(|| text.to_string())
}

/// The text between the `open` that starts `s` and its matching `close`, quote-aware; the rest of `s` if it never
/// closes.
fn balanced(s: &str, open: char, close: char, lang: Lang) -> String {
    let mut depth = 0;
    let mut q: Option<char> = None;
    let mut esc = false;
    for (i, c) in s.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        match q {
            Some(o) => {
                if c == '\\' && o != '\'' {
                    esc = true;
                } else if c == o {
                    q = None;
                }
            }
            None => {
                if c == '"' || c == '\'' || (c == '`' && lang != Lang::Python) {
                    q = Some(c);
                } else if c == open {
                    depth += 1;
                } else if c == close {
                    depth -= 1;
                    if depth == 0 {
                        return s[open.len_utf8()..i].to_string();
                    }
                }
            }
        }
    }
    s.get(open.len_utf8()..).unwrap_or("").to_string()
}

/// Splits on commas outside strings and brackets.
pub(super) fn top_level_split(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut q: Option<char> = None;
    let mut esc = false;
    for c in text.chars() {
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
                    ',' if depth == 0 => {
                        parts.push(std::mem::take(&mut cur));
                        continue;
                    }
                    _ => {}
                }
                cur.push(c);
            }
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

/// `${...}`, `#{...}` read as the placeholder word `x`: a path built on one stays relative (`${dir}/node_modules` is
/// `x/node_modules`), one that was absolute before it stays absolute (`/srv/${name}` is `/srv/x`).
fn strip_interp(s: &str) -> String {
    INTERP.replace_all(s, "x").into_owned()
}

/// The command lines a call runs, from its argument text: each argument's values (literals, variables,
/// concatenation), one string as a command line, a list or several arguments as an argv.
fn command_of(args: &str, kind: Kind, lang: Lang, env: &Env) -> Vec<String> {
    static KEY_LIST: LazyLock<Regex> =
        LazyLock::new(|| super::re(r#"["']?(?:cmd|args)["']?\s*:\s*(\[[^\]]*\])"#));
    static KEYWORD: LazyLock<Regex> = LazyLock::new(|| super::re(r"^\w+\s*[=:]\s*[^=]"));
    // Objects: the list under `cmd:` or `args:` (`Deno.run({cmd: [...]})`, `{args: [...]}`); other objects (an env
    // hash, options) and keyword arguments (`shell=True`, `cwd: x`) aren't part of the command.
    let parts: Vec<String> = top_level_split(args)
        .iter()
        .filter_map(|p| {
            let t = p.trim();
            if t.starts_with('{') {
                return KEY_LIST.captures(t).map(|c| c[1].to_string());
            }
            (!KEYWORD.is_match(t)).then(|| t.to_string())
        })
        .collect();
    let parts: Vec<String> = match kind {
        Kind::Spawn => parts.into_iter().skip(1).collect(),
        _ => parts,
    };
    // Each argument's values; the command lines are their combinations (at most 8).
    let values: Vec<Vec<Val>> = parts
        .iter()
        .map(|p| values::eval(p, lang, env, 0))
        .filter(|v| !v.is_empty())
        .collect();
    let mut combos: Vec<Vec<Val>> = vec![Vec::new()];
    for vals in &values {
        let mut next = Vec::new();
        for c in &combos {
            for v in vals {
                if next.len() < 8 {
                    let mut c = c.clone();
                    c.push(v.clone());
                    next.push(c);
                }
            }
        }
        combos = next;
    }
    let mut out = Vec::new();
    for combo in combos {
        if combo.is_empty() {
            continue;
        }
        if combo.len() == 1 && matches!(kind, Kind::Cmd) {
            if let Val::Str(s) = &combo[0] {
                out.push(s.clone()); // one string: a command line
                continue;
            }
        }
        let mut argv: Vec<String> = Vec::new();
        for v in combo {
            match v {
                Val::List(l) => argv.extend(l),
                Val::Str(s) => argv.push(s),
            }
        }
        // `os.execvp("sudo", ["sudo", "ls"])`: argv[0] repeats the program.
        if argv.len() > 1 && argv[0] == argv[1] {
            argv.remove(1);
        }
        if !argv.is_empty() {
            out.push(shell_join(&argv));
        }
    }
    out
}

/// Backtick substitutions in perl, ruby and php code.
fn backticks(code: &str) -> Vec<String> {
    let re = super::re(r"`((?:[^`\\]|\\.)*)`");
    re.captures_iter(code)
        .map(|c| strip_interp(&c[1]))
        .collect()
}

/// `qx{...}` (perl) or `%x(...)` (ruby) with any delimiter.
fn quoted_forms(code: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = code.chars().collect();
    let p: Vec<char> = prefix.chars().collect();
    let mut i = 0;
    while i + p.len() < chars.len() {
        let word_start = i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
        if word_start && chars[i..i + p.len()] == p[..] {
            let open = chars[i + p.len()];
            let close = match open {
                '(' => ')',
                '{' => '}',
                '[' => ']',
                '<' => '>',
                c if !c.is_alphanumeric() && !c.is_whitespace() => c,
                _ => {
                    i += 1;
                    continue;
                }
            };
            let start = i + p.len() + 1;
            let end = (start..chars.len())
                .find(|&k| chars[k] == close)
                .unwrap_or(chars.len());
            out.push(strip_interp(&chars[start..end].iter().collect::<String>()));
            i = end;
        }
        i += 1;
    }
    out
}

/// perl `open(FH, "cmd |")`, `open(FH, "| cmd")`, `open(my $f, "-|", "cmd", @args)`.
fn perl_pipe_opens(code: &str, env: &Env) -> Vec<String> {
    let mut out = Vec::new();
    let re = super::re(r"\bopen\b");
    for m in re.find_iter(code) {
        let Some(args) = call_args(code, m.end(), Lang::Perl) else {
            continue;
        };
        let lits: Vec<String> = top_level_split(&args)
            .iter()
            .filter_map(|p| values::eval(p, Lang::Perl, env, 0).first().map(Val::text))
            .collect();
        if let Some(i) = lits.iter().position(|l| l == "-|" || l == "|-") {
            if lits.len() > i + 1 {
                out.push(shell_join(&lits[i + 1..]));
            }
            continue;
        }
        for l in &lits {
            let t = l.trim();
            if let Some(c) = t.strip_suffix('|').or_else(|| t.strip_prefix('|')) {
                out.push(c.trim().to_string());
            }
        }
    }
    out
}
