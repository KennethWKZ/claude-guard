//! Just enough of jq 1.7.1 (macOS /usr/bin/jq) to port shell hooks that call it: parsing a stream of JSON
//! values the way jq does (values emitted until the first parse error, number literals kept as written, NaN
//! accepted, an unpaired surrogate escape is an error), `-r` output (raw strings, other values pretty-printed with
//! two-space indent) and `--arg` / `-c` string escaping.

#[derive(Debug, Clone, PartialEq)]
pub enum Jv {
    Null,
    Bool(bool),
    /// The literal as written (`nan` for NaN).
    Num(String),
    Str(String),
    Arr(Vec<Jv>),
    /// Insertion order; a repeated key replaces the value in place.
    Obj(Vec<(String, Jv)>),
}

impl Jv {
    pub fn get(&self, key: &str) -> Result<&Jv, ()> {
        match self {
            Jv::Obj(m) => Ok(m
                .iter()
                .find(|(k, _)| k == key)
                .map_or(&Jv::Null, |(_, v)| v)),
            Jv::Null => Ok(&Jv::Null),
            _ => Err(()), // jq: "Cannot index <type> with string"
        }
    }

    /// `// empty`: null and false give nothing.
    pub fn truthy(&self) -> bool {
        !matches!(self, Jv::Null | Jv::Bool(false))
    }

    /// `-r` output of one value, without the newline jq adds.
    pub fn raw(&self) -> String {
        match self {
            Jv::Str(s) => s.clone(),
            _ => self.dump(Some(0)),
        }
    }

    /// `tostring`.
    pub fn tostring(&self) -> String {
        match self {
            Jv::Str(s) => s.clone(),
            _ => self.dump(None),
        }
    }

    /// jq's JSON text: compact when `indent` is None, else pretty at that depth.
    pub fn dump(&self, indent: Option<usize>) -> String {
        let mut out = String::new();
        self.dump_into(&mut out, indent);
        out
    }

    fn dump_into(&self, out: &mut String, indent: Option<usize>) {
        let nl = |out: &mut String, d: usize| {
            out.push('\n');
            out.push_str(&"  ".repeat(d));
        };
        match self {
            Jv::Null => out.push_str("null"),
            Jv::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Jv::Num(n) => out.push_str(&number_text(n)),
            Jv::Str(s) => out.push_str(&quote(s)),
            Jv::Arr(a) if a.is_empty() => out.push_str("[]"),
            Jv::Obj(m) if m.is_empty() => out.push_str("{}"),
            Jv::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if let Some(d) = indent {
                        nl(out, d + 1);
                    }
                    v.dump_into(out, indent.map(|d| d + 1));
                }
                if let Some(d) = indent {
                    nl(out, d);
                }
                out.push(']');
            }
            Jv::Obj(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if let Some(d) = indent {
                        nl(out, d + 1);
                    }
                    out.push_str(&quote(k));
                    out.push(':');
                    if indent.is_some() {
                        out.push(' ');
                    }
                    v.dump_into(out, indent.map(|d| d + 1));
                }
                if let Some(d) = indent {
                    nl(out, d);
                }
                out.push('}');
            }
        }
    }
}

/// jq's string escaping (`-c`, `--arg` values in output): JSON escapes, other controls and DEL as \u00XX,
/// everything else (non-ASCII included) as is.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A number literal as jq 1.7.1 prints it (decNumber's to-scientific-string); NaN prints as null.
fn number_text(lit: &str) -> String {
    if lit.eq_ignore_ascii_case("nan") {
        return "null".into();
    }
    let (neg, body) = match lit.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, lit),
    };
    let (mant, exp) = match body.find(['e', 'E']) {
        Some(i) => (&body[..i], body[i + 1..].parse::<i64>().unwrap_or(0)),
        None => (body, 0),
    };
    let (int, frac) = mant.split_once('.').unwrap_or((mant, ""));
    let digits = format!("{int}{frac}");
    let coeff = digits.trim_start_matches('0');
    let coeff = if coeff.is_empty() { "0" } else { coeff };
    let exp = exp - frac.len() as i64;
    let n = coeff.len() as i64;
    let adjusted = exp + n - 1;
    let text = if exp <= 0 && adjusted >= -6 {
        if exp == 0 {
            coeff.to_string()
        } else if n > -exp {
            let cut = (n + exp) as usize;
            format!("{}.{}", &coeff[..cut], &coeff[cut..])
        } else {
            format!("0.{}{coeff}", "0".repeat((-exp - n) as usize))
        }
    } else {
        let rest = if n > 1 {
            format!(".{}", &coeff[1..])
        } else {
            String::new()
        };
        let sign = if adjusted >= 0 { "+" } else { "" };
        format!("{}{rest}E{sign}{adjusted}", &coeff[..1])
    };
    if neg { format!("-{text}") } else { text }
}

/// The values of a JSON text stream, up to the first parse error (jq prints those, then fails).
pub fn stream(text: &str) -> Vec<Jv> {
    stream_ok(text).0
}

/// The values, and whether the whole text parsed (false: jq stopped at a parse error and exits non-zero).
pub fn stream_ok(text: &str) -> (Vec<Jv>, bool) {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
        text,
    };
    let mut out = Vec::new();
    loop {
        p.ws();
        if p.i >= p.s.len() {
            return (out, true);
        }
        match p.value(0) {
            Some(v) => out.push(v),
            None => return (out, false),
        }
    }
}

/// `jq -r '<path> // empty'` over a text stream: one line per value that has a non-null, non-false field.
/// Values that can't be indexed are skipped (jq reports them and goes on).
pub fn field_lines(text: &str, key: &str) -> String {
    let mut out = String::new();
    for v in stream(text) {
        if let Ok(f) = v.get(key) {
            if f.truthy() {
                out.push_str(&f.raw());
                out.push('\n');
            }
        }
    }
    out
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    text: &'a str,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Option<Jv> {
        if depth > 10_000 {
            return None;
        }
        self.ws();
        match *self.s.get(self.i)? {
            b'{' => {
                self.i += 1;
                let mut m: Vec<(String, Jv)> = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Some(Jv::Obj(m));
                }
                loop {
                    self.ws();
                    if self.s.get(self.i) != Some(&b'"') {
                        return None;
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.s.get(self.i) != Some(&b':') {
                        return None;
                    }
                    self.i += 1;
                    let v = self.value(depth + 1)?;
                    match m.iter_mut().find(|(x, _)| *x == k) {
                        Some(slot) => slot.1 = v,
                        None => m.push((k, v)),
                    }
                    self.ws();
                    match self.s.get(self.i)? {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            return Some(Jv::Obj(m));
                        }
                        _ => return None,
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Some(Jv::Arr(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.s.get(self.i)? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Some(Jv::Arr(a));
                        }
                        _ => return None,
                    }
                }
            }
            b'"' => self.string().map(Jv::Str),
            _ => {
                // A literal: jq collects the characters up to a delimiter and then decides what it is.
                let start = self.i;
                while self.i < self.s.len()
                    && !matches!(
                        self.s[self.i],
                        b' ' | b'\t'
                            | b'\n'
                            | b'\r'
                            | b','
                            | b':'
                            | b'['
                            | b']'
                            | b'{'
                            | b'}'
                            | b'"'
                    )
                {
                    self.i += 1;
                }
                let lit = &self.text[start..self.i];
                match lit {
                    "true" => Some(Jv::Bool(true)),
                    "false" => Some(Jv::Bool(false)),
                    "null" => Some(Jv::Null),
                    "nan" | "NaN" => Some(Jv::Num("nan".into())),
                    _ if is_number(lit) => Some(Jv::Num(lit.to_string())),
                    _ => None,
                }
            }
        }
    }

    fn string(&mut self) -> Option<String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let c = *self.s.get(self.i)?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Some(out);
                }
                b'\\' => {
                    let e = *self.s.get(self.i + 1)?;
                    self.i += 2;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let u = self.hex4()?;
                            if (0xD800..0xDC00).contains(&u) {
                                if self.s.get(self.i) != Some(&b'\\')
                                    || self.s.get(self.i + 1) != Some(&b'u')
                                {
                                    return None;
                                }
                                self.i += 2;
                                let l = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&l) {
                                    return None;
                                }
                                out.push(char::from_u32(
                                    0x10000 + ((u - 0xD800) << 10) + (l - 0xDC00),
                                )?);
                            } else if (0xDC00..0xE000).contains(&u) {
                                return None;
                            } else {
                                out.push(char::from_u32(u)?);
                            }
                        }
                        _ => return None,
                    }
                }
                _ => {
                    let ch = self.text[self.i..].chars().next()?;
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let h = self.s.get(self.i..self.i + 4)?;
        if !h.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        self.i += 4;
        u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()
    }
}

/// A JSON number (jq rejects the other literals it collects, such as `01x` or `+`).
fn is_number(s: &str) -> bool {
    static RX: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$").unwrap()
    });
    RX.is_match(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_jq() {
        assert_eq!(
            field_lines(r#"{"a":"x"} {"a":"y"} nope {"a":"z"}"#, "a"),
            "x\ny\n"
        );
        assert_eq!(field_lines(r#"5 {"a":"y"}"#, "a"), "y\n");
        assert_eq!(field_lines(r#"{"a":NaN}"#, "a"), "null\n");
        assert_eq!(field_lines(r#"{"a":"\ud800x"}"#, "a"), "");
        assert_eq!(field_lines(r#"{"a":1}{"a":2}"#, "a"), "1\n2\n");
        assert_eq!(field_lines(r#"{"a":1,"a":2}"#, "a"), "2\n");
        assert_eq!(
            field_lines(r#"{"a":{"x":[1,2]},"b":1.0,"c":1e2}"#, "a"),
            "{\n  \"x\": [\n    1,\n    2\n  ]\n}\n"
        );
        for (lit, want) in [
            ("1.0", "1.0"),
            ("1e2", "1E+2"),
            ("100", "100"),
            ("1e-7", "1E-7"),
            ("0.00", "0.00"),
            ("-1.5e1", "-15"),
            ("12e-1", "1.2"),
        ] {
            assert_eq!(number_text(lit), want, "{lit}");
        }
        assert_eq!(
            quote("a\u{1}b\u{7f}c\"\\é\tz"),
            "\"a\\u0001b\\u007fc\\\"\\\\é\\tz\""
        );
    }
}
