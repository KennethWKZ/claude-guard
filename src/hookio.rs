//! Hook input and output: reading the hook JSON the way Python's `json.load` accepts it, and writing JSON the
//! way Python's `json.dumps` does, so the Rust hooks print byte-for-byte what the Python hooks printed.

use serde_json::Value;
use std::io::Read;

/// All of stdin. A read error gives what was read so far (the caller treats bad JSON as "no input").
pub fn read_stdin() -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);
    buf
}

/// Parse hook input. None when Python's `json.load` would have raised (bad UTF-8, bad JSON).
///
/// Python accepts two things serde_json rejects, and a parse error means "allow", so leaving them would let a
/// command through that the Python guard blocked:
/// - unpaired surrogate escapes (`"\ud800"`): replaced with U+FFFD, as jq does;
/// - `NaN`, `Infinity`, `-Infinity` and numbers past f64's range (`1e400`): replaced with truthy stand-ins.
pub fn parse(bytes: &[u8]) -> Option<Value> {
    parse_py(bytes).ok()
}

/// How deep `json.load` nests arrays and objects inside these hooks (Python's recursion limit of 1000, less the
/// frames below it; measured 2026-11-24 on /usr/bin/python3 3.9 for guard-bash, guard-read-keys and
/// guard-prompt alike: 993 levels load, 994 raise RecursionError). serde_json's own limit is 128, which made the
/// Rust hooks treat inputs 129 to 993 levels deep as bad JSON.
pub const PY_JSON_MAX_DEPTH: usize = 993;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Python raised ValueError (bad UTF-8, bad JSON).
    Invalid,
    /// Python raised RecursionError entering this kind of container ("array" or "object").
    TooDeep(&'static str),
}

impl ParseError {
    /// `f"{type(e).__name__}: {e}"` for the RecursionError.
    pub fn too_deep_text(kind: &str) -> String {
        format!(
            "RecursionError: maximum recursion depth exceeded while decoding a JSON {kind} from a unicode string"
        )
    }
}

/// Byte offset and kind of the first array or object nested deeper than Python loads, if any.
fn first_too_deep(text: &str) -> Option<(usize, &'static str)> {
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    for (i, b) in text.bytes().enumerate() {
        if in_str {
            match (esc, b) {
                (true, _) => esc = false,
                (false, b'\\') => esc = true,
                (false, b'"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > PY_JSON_MAX_DEPTH {
                    return Some((i, if b == b'[' { "array" } else { "object" }));
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

/// One JSON value and nothing after it but whitespace, at any depth (the caller has bounded it).
/// Err carries serde_json's error category, None for a second value after the first.
fn parse_unbounded(text: &str) -> Result<Value, Option<serde_json::error::Category>> {
    let mut de = serde_json::Deserializer::from_str(text);
    de.disable_recursion_limit();
    let mut values = de.into_iter::<Value>();
    match (values.next(), values.next()) {
        (Some(Ok(v)), None) => Ok(v),
        (Some(Err(e)), _) | (_, Some(Err(e))) => Err(Some(e.classify())),
        _ => Err(None),
    }
}

/// Parse hook input as `json.load` would, telling bad JSON apart from JSON nested too deep. Python reads left to
/// right, so a syntax error before the too-deep container is bad JSON, and one after it is never reached.
pub fn parse_py(bytes: &[u8]) -> Result<Value, ParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError::Invalid)?;
    let cleaned = sanitize(text);
    if let Some((at, kind)) = first_too_deep(&cleaned) {
        return match parse_unbounded(&cleaned[..at]) {
            Err(Some(serde_json::error::Category::Eof)) => Err(ParseError::TooDeep(kind)),
            _ => Err(ParseError::Invalid),
        };
    }
    parse_unbounded(&cleaned).map_err(|_| ParseError::Invalid)
}

fn hex4(s: &[u8]) -> Option<u32> {
    let h = s.get(..4)?;
    if !h.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()
}

/// Stand-ins for the floats Python's json reads and serde_json can't hold (inf, -inf, nan): the largest finite
/// floats, so they stay truthy numbers, and `py_float_name` gives back Python's `str()` of them.
const PY_INF: &str = "1.7976931348623157e308";
const PY_NEG_INF: &str = "-1.7976931348623157e308";
/// Far enough below `PY_INF` that serde_json's default (lossy, up to 1 ulp) float parser can't read it as `PY_INF`:
/// the 17-digit `1.7976931348623155e308` did, so NaN read as inf.
const PY_NAN: &str = "1.79769313486231e308";

/// Python's `str()` of a float that stood in for inf, -inf or nan; None for any other value.
pub fn py_float_name(f: f64) -> Option<&'static str> {
    // Parsed the way `parse_py` parsed the stand-in (serde_json), so the comparison is exact.
    [(PY_INF, "inf"), (PY_NEG_INF, "-inf"), (PY_NAN, "nan")]
        .into_iter()
        .find(|(s, _)| serde_json::from_str::<f64>(s).ok() == Some(f))
        .map(|(_, name)| name)
}

/// Rewrite unpaired surrogate escapes and Python's non-standard number literals (NaN, Infinity, -Infinity and
/// numbers past f64's range become the stand-ins above). Everything else is copied.
fn sanitize(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            if c == b'\\' && i + 1 < b.len() {
                if b[i + 1] == b'u' {
                    if let Some(u) = hex4(&b[i + 2..]) {
                        let high = (0xD800..0xDC00).contains(&u);
                        let low = (0xDC00..0xE000).contains(&u);
                        if high {
                            let pair = b.get(i + 6) == Some(&b'\\')
                                && b.get(i + 7) == Some(&b'u')
                                && hex4(b.get(i + 8..).unwrap_or(&[]))
                                    .is_some_and(|l| (0xDC00..0xE000).contains(&l));
                            if pair {
                                out.push_str(&text[i..i + 12]);
                                i += 12;
                                continue;
                            }
                        }
                        if high || low {
                            out.push_str("\\ufffd");
                            i += 6;
                            continue;
                        }
                    }
                }
                if b[i + 1].is_ascii() {
                    out.push_str(&text[i..i + 2]);
                    i += 2;
                } else {
                    out.push('\\');
                    i += 1;
                }
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
        } else {
            if c == b'"' {
                in_str = true;
            }
            let rest = &text[i..];
            let lit = [
                ("-Infinity", PY_NEG_INF),
                ("Infinity", PY_INF),
                ("NaN", PY_NAN),
            ]
            .into_iter()
            .find(|(l, _)| rest.starts_with(l));
            if let Some((l, stand_in)) = lit {
                out.push_str(stand_in);
                i += l.len();
                continue;
            }
            // A number too big for f64 (1e400): Python reads inf, serde_json refuses the whole input.
            if c == b'-' || c.is_ascii_digit() {
                let len = rest
                    .bytes()
                    .take_while(|b| b.is_ascii_digit() || b"+-.eE".contains(b))
                    .count();
                let num = &rest[..len];
                match num.parse::<f64>() {
                    Ok(f) if f.is_infinite() => {
                        out.push_str(if f > 0.0 { PY_INF } else { PY_NEG_INF })
                    }
                    _ => out.push_str(num),
                }
                i += len;
                continue;
            }
        }
        let ch = text[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// A JSON string literal as Python's `json.dumps` writes it (ensure_ascii: every non-ASCII character escaped).
pub fn py_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `json.dumps(value)` with Python's separators and ensure_ascii. Object keys come out sorted (serde_json's map),
/// where Python kept the input order; the hooks only dump strings and small scalars this way.
pub fn py_dumps(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => {
            if *b {
                "true".into()
            } else {
                "false".into()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => py_str(s),
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(py_dumps).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", py_str(k), py_dumps(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The PreToolUse deny line, exactly as `json.dumps` printed it in the Python guards.
pub fn deny_line(reason: &str) -> String {
    format!(
        "{{\"hookSpecificOutput\": {{\"hookEventName\": \"PreToolUse\", \"permissionDecision\": \"deny\", \"permissionDecisionReason\": {}}}}}",
        py_str(reason)
    )
}

/// Python's name for a JSON value's type once loaded (`type(x).__name__`).
pub fn py_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// Python truthiness of a loaded JSON value.
pub fn py_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nan_and_infinities_keep_their_names() {
        let v = parse_py(b"[NaN, Infinity, -Infinity, 1e400, -1e400, 1.5]").unwrap();
        let names: Vec<_> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|x| py_float_name(x.as_f64().unwrap()))
            .collect();
        assert_eq!(
            names,
            [
                Some("nan"),
                Some("inf"),
                Some("-inf"),
                Some("inf"),
                Some("-inf"),
                None
            ]
        );
        assert!(
            v.as_array().unwrap().iter().all(py_truthy),
            "stand-ins stay truthy"
        );
    }
}
