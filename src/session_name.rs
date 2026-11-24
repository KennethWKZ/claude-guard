//! `claude-guard session-name`: UserPromptSubmit / SessionStart hook, ported from session-name-from-title.sh.
//!
//! Gives a session that still has its default "<folder>-<hex>" name a readable name taken from Claude's own
//! ai-title, so the @ list in other sessions shows what each one is doing. Leaves any name already set (-n,
//! /rename, an earlier run) alone, and never blocks: every failure prints nothing and exits 0. A name another live
//! session holds gets this session's own suffix (Claude doesn't de-duplicate names set by hooks).
//!
//! Same output as the dash script, byte for byte: its jq calls run through `jqlite` (jq's stream parsing, `-r`
//! output and escaping), its tr/grep/head/paste/cut/sed pipeline is spelled out below, the live check is
//! `kill(pid, 0)`, and the registry is `${CLAUDE_CONFIG_DIR:-$HOME/.claude}/sessions/*.json` as the script reads
//! it (Claude Code's own setting, not a test override). The tr step follows the UTF-8 locale Claude Code runs in:
//! İ and K (Kelvin sign) lowercase to i and k there.

use crate::jqlite::{self, Jv};

/// `$(cmd)`: the output with every trailing newline removed.
fn subst(s: String) -> String {
    s.trim_end_matches('\n').to_string()
}

/// `jq -r '.<key> // empty'` on the hook input, through `$( )`.
fn field(input: &str, key: &str) -> String {
    subst(jqlite::field_lines(input, key))
}

/// The slug pipeline: tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '\n' | grep -Ev '<filler>' | head -n 4 |
/// paste -sd- - | cut -c1-29 | sed 's/-*$//; s/^[^a-z]*//'.
pub fn slug(title: &str) -> String {
    let lower: String = title
        .chars()
        .flat_map(|c| match c {
            '\u{130}' => vec!['i'],
            '\u{212a}' => vec!['k'],
            c if c.is_ascii() => vec![c.to_ascii_lowercase()],
            c => c.to_lowercase().collect(),
        })
        .collect();
    // tr -cs: each run of other characters becomes one newline; a leading run makes an empty first line, a
    // trailing one only ends the last line.
    let mut lines: Vec<String> = vec![String::new()];
    let mut in_sep = false;
    for c in lower.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            if in_sep {
                lines.push(String::new());
                in_sep = false;
            }
            lines.last_mut().unwrap().push(c);
        } else {
            in_sep = true;
        }
    }
    if lines.len() == 1 && lines[0].is_empty() && !in_sep {
        lines.clear(); // no output at all
    }
    const FILLER: &[&str] = &[
        "a", "an", "the", "and", "or", "of", "in", "on", "for", "to", "with", "from", "via",
    ];
    let kept: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|l| {
            !(FILLER.contains(l) || (!l.is_empty() && l.bytes().all(|b| b.is_ascii_digit())))
        })
        .take(4)
        .collect();
    let joined: String = kept.join("-").chars().take(29).collect();
    let trimmed = joined.trim_end_matches('-');
    trimmed
        .trim_start_matches(|c: char| !c.is_ascii_lowercase())
        .to_string()
}

/// dash's `number()`: strtoimax in base 10 (leading whitespace, an optional sign, digits), then only
/// whitespace, and a result from 0 to INT_MAX; anything else is "Illegal number" (kill fails).
fn dash_number(s: &str) -> Option<i64> {
    let sp = |c: char| matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r');
    let t = s.trim_start_matches(sp);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    if end == 0 || !digits[end..].chars().all(sp) {
        return None;
    }
    let mag: i64 = digits[..end].parse().ok()?; // overflow: ERANGE
    let n = if neg { -mag } else { mag };
    (0..=i32::MAX as i64).contains(&n).then_some(n)
}

/// `kill -0 "$pid"` in dash: `-number(rest)` for an argument starting with `-`, else `number(pid)`; alive when
/// kill(2) succeeds.
fn alive(pid: &str) -> bool {
    let n = match pid.strip_prefix('-') {
        Some(rest) => dash_number(rest).map(|n| -n),
        None => dash_number(pid),
    };
    let Some(n) = n else {
        return false;
    };
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    // SAFETY: signal 0 only checks that the process exists and may be signalled.
    unsafe { kill(n as i32, 0) == 0 }
}

/// `read -r`: the line without leading and trailing spaces and tabs.
fn read_r(line: Option<&str>) -> String {
    line.unwrap_or("").trim_matches([' ', '\t']).to_string()
}

struct Registry {
    files: Vec<(String, String)>, // (path, contents)
}

impl Registry {
    /// `"$registry"/*.json`, sorted by bytes as dash sorts a glob; files that can't be read are skipped (grep
    /// can't read them either).
    fn load(dir: &str) -> Registry {
        let mut paths: Vec<String> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
                    .map(|n| format!("{dir}/{n}"))
                    .collect()
            })
            .unwrap_or_default();
        paths.sort();
        let files = paths
            .into_iter()
            .filter_map(|p| {
                let b = std::fs::read(&p).ok()?;
                Some((p, String::from_utf8_lossy(&b).into_owned()))
            })
            .collect();
        Registry { files }
    }

    /// taken(): another live session holds `name`.
    fn taken(&self, name: &str, session_id: &str) -> bool {
        let rx = regex::Regex::new(&format!("\"name\": *\"{}\"", regex::escape(name))).unwrap();
        for (_, text) in self.files.iter().filter(|(_, t)| rx.is_match(t)) {
            // jq -r '.name // "", .sessionId // "", (.pid // "" | tostring)'; a parse error skips the file.
            let (values, parsed) = jqlite::stream_ok(text);
            let mut out = String::new();
            let mut failed = false;
            for v in &values {
                let mut part = String::new();
                for key in ["name", "sessionId", "pid"] {
                    match v.get(key) {
                        Ok(f) => {
                            let f = if f.truthy() {
                                f.clone()
                            } else {
                                Jv::Str(String::new())
                            };
                            part.push_str(&if key == "pid" { f.tostring() } else { f.raw() });
                            part.push('\n');
                        }
                        Err(()) => {
                            failed = true;
                            break;
                        }
                    }
                }
                out.push_str(&part);
            }
            if failed || !parsed {
                continue; // jq exited non-zero: `|| continue`
            }
            let out = subst(out);
            let mut lines = out.split('\n');
            let (n, sid, pid) = (
                read_r(lines.next()),
                read_r(lines.next()),
                read_r(lines.next()),
            );
            if n != name {
                continue;
            }
            if !session_id.is_empty() && sid == session_id {
                continue;
            }
            if !pid.is_empty() && alive(&pid) {
                return true;
            }
        }
        false
    }

    /// The name Claude derived for this session ("mmt-0c"), from the first file that has one.
    fn own_name(&self, session_id: &str) -> String {
        let needle = format!("\"{session_id}\"");
        for (_, text) in self.files.iter().filter(|(_, t)| t.contains(&needle)) {
            let mut out = String::new();
            for v in jqlite::stream(text) {
                let (Ok(sid), Ok(src)) = (v.get("sessionId"), v.get("nameSource")) else {
                    continue;
                };
                if *sid == Jv::Str(session_id.into()) && *src == Jv::Str("derived".into()) {
                    if let Ok(n) = v.get("name") {
                        if n.truthy() {
                            out.push_str(&n.raw());
                            out.push('\n');
                        }
                    }
                }
            }
            let out = subst(out);
            if !out.is_empty() {
                return out;
            }
        }
        String::new()
    }
}

/// `sed -n 's/.*-\([a-z0-9]\{2,4\}\)$/\1/p'` on each line.
fn suffix_of(own: &str) -> String {
    static RX: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^.*-([a-z0-9]{2,4})$").unwrap());
    let out: Vec<&str> = own
        .split('\n')
        .filter_map(|l| RX.captures(l).map(|c| c.get(1).unwrap().as_str()))
        .collect();
    subst(out.iter().map(|s| format!("{s}\n")).collect())
}

/// `tr -cd 'a-z0-9' | cut -c1-<n>`.
fn id_chars(id: &str, n: usize) -> String {
    id.chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        .take(n)
        .collect()
}

/// The name this session should get, or None for no output.
pub fn decide(input: &[u8], registry_dir: &str) -> Option<String> {
    let input = String::from_utf8_lossy(input);
    let input = input.trim_end_matches('\n');
    if !field(input, "session_title").is_empty() {
        return None;
    }
    let event = field(input, "hook_event_name");
    let transcript = field(input, "transcript_path");
    let session_id = field(input, "session_id");
    if event.is_empty() || transcript.is_empty() || !std::path::Path::new(&transcript).is_file() {
        return None;
    }
    let text = String::from_utf8_lossy(&std::fs::read(&transcript).ok()?).into_owned();
    if text.contains("\"type\":\"custom-title\"") {
        return None;
    }
    let last = text
        .split('\n')
        .rfind(|l| l.contains("\"type\":\"ai-title\""))?;
    let title = field(last, "aiTitle");
    if title.is_empty() {
        return None;
    }
    let slug = slug(&title);
    if slug.is_empty() {
        return None;
    }
    let reg = Registry::load(registry_dir);
    let mut name = slug.clone();
    if reg.taken(&name, &session_id) {
        let own = if !session_id.is_empty()
            && session_id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            reg.own_name(&session_id)
        } else {
            String::new()
        };
        let mut suffix = suffix_of(&own);
        if suffix.is_empty() {
            suffix = id_chars(&session_id, 2);
        }
        if suffix.is_empty() {
            return None;
        }
        name = format!("{slug}-{suffix}");
        if reg.taken(&name, &session_id) {
            let long = id_chars(&session_id, 4);
            if long.is_empty() {
                return None;
            }
            let short: String = slug.chars().take(27).collect();
            name = format!("{}-{long}", short.trim_end_matches('-'));
            if reg.taken(&name, &session_id) {
                return None;
            }
        }
    }
    Some(format!(
        "{{\"hookSpecificOutput\":{{\"hookEventName\":{},\"sessionTitle\":{}}}}}",
        jqlite::quote(&event),
        jqlite::quote(&name)
    ))
}

/// `${CLAUDE_CONFIG_DIR:-$HOME/.claude}/sessions`.
pub fn registry_dir() -> String {
    let base = match std::env::var("CLAUDE_CONFIG_DIR") {
        Ok(d) if !d.is_empty() => d,
        _ => format!("{}/.claude", std::env::var("HOME").unwrap_or_default()),
    };
    format!("{base}/sessions")
}

/// Print the line, if any; always exit 0.
pub fn emit(line: &Option<String>) -> i32 {
    if let Some(l) = line {
        println!("{l}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_like_the_pipeline() {
        assert_eq!(slug("Herdr tab agent tags"), "herdr-tab-agent-tags");
        assert_eq!(
            slug("Fix OAuth 2.0 redirect loop in billing_api login"),
            "fix-oauth-redirect-loop"
        );
        assert_eq!(slug("2026 Q4 deck update"), "q4-deck-update");
        assert_eq!(
            slug("Supercalifragilisticexpialidocious internationalization"),
            "supercalifragilisticexpialido"
        );
        assert_eq!(slug("The 42"), "");
        assert_eq!(slug("  a b c d e"), "b-c-d");
        assert_eq!(slug("İstanbul KELVİN"), "istanbul-kelvin");
        assert_eq!(slug("ÉCOLE École"), "cole-cole");
        assert_eq!(suffix_of("mmt-0c"), "0c");
        assert_eq!(suffix_of("a-bcdef"), "");
        for (p, want) in [
            ("+5", Some(5)),
            (" 5 ", Some(5)),
            ("05", Some(5)),
            ("5x", None),
            ("++5", None),
            ("+-1", None),
            ("2147483648", None),
            ("-5", None),
            ("", None),
            ("+", None),
        ] {
            assert_eq!(dash_number(p), want, "{p:?}");
        }
    }
}
