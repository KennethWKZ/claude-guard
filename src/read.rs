//! `claude-guard read`: the PreToolUse guard for the Read tool, ported from guard-read-keys.py.
//!
//! Refuses key and certificate-store files by name (the requested path and the path a symlink resolves to,
//! case-insensitively), a few machine keys by the end of their path, tools' credential files in the real home
//! folder (from the user database, not `$HOME`), and any regular file whose first 4 KiB has a line starting a
//! private key (PEM or OpenSSH, PGP, PuTTY). Nothing it reads is shown to Claude.
//!
//! Exit 0 allows the read, exit 2 blocks it with the message on stderr. Unreadable hook input allows; any other
//! failure blocks. Messages are word for word guard-read-keys.py's.

use crate::hookio::{self, py_truthy};
use crate::pyfs;
use regex::Regex;
use regex::bytes::Regex as BytesRegex;
use serde_json::Value;
use std::io::Read;
use std::sync::LazyLock;

const KEY_SUFFIXES: &[&str] = &[
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    "_deploy_key",
    "_private_key",
];
const KEY_PREFIXES: &[&str] = &["private_key_"];
const KEY_NAMES: &[&str] = &[
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ecdsa_sk",
    "id_ed25519_sk",
    "private_key",
];
const KEY_PATH_ENDINGS: &[&str] = &["/.lima/_config/user", "/_lima/_config/user"];
const SNIFF_BYTES: u64 = 4096;
const HOME_CREDENTIALS: &[&str] = &[
    ".npmrc",
    ".yarnrc.yml",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".pgpass",
    ".my.cnf",
    ".vault-token",
    ".docker/config.json",
    ".kube/config",
    ".config/gh/hosts.yml",
    ".claude/.credentials.json",
    ".codex/auth.json",
    ".local/share/opencode/auth.json",
    ".graphmind/config.json",
    ".config/stripe/config.toml",
    ".config/auth0/config.json",
    ".config/configstore/firebase-tools.json",
    ".terraform.d/credentials.tfrc.json",
    ".composer/auth.json",
    ".config/composer/auth.json",
    ".cargo/credentials.toml",
    ".cargo/credentials",
    ".gem/credentials",
    ".gnupg/private-keys-v1.d/",
];

static KEY_NAME_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^id_(?:rsa|dsa|ecdsa|ed25519|ecdsa_sk|ed25519_sk)[-_.]").unwrap()
});
static KEY_HEADER: LazyLock<BytesRegex> = LazyLock::new(|| {
    BytesRegex::new(
        r"(?m-u)^(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-)",
    )
    .unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block { message: String, rule: &'static str },
    Crash(String),
}

impl Verdict {
    pub fn rule(&self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Block { rule, .. } => rule,
            Verdict::Crash(_) => "crash",
        }
    }
}

/// Rule id from a guard-read-keys message (works for the Python hook's stderr too).
pub fn rule_of(stderr: &str) -> &'static str {
    if stderr.contains("crashed, so the read is blocked") {
        "crash"
    } else if stderr.contains("looks like a private key or certificate store") {
        "key-name"
    } else if stderr.contains("is a credential file") {
        "credential"
    } else if stderr.contains("contains a private key") {
        "key-header"
    } else if stderr.is_empty() {
        "allow"
    } else {
        "other"
    }
}

fn is_key_file(path: &str) -> bool {
    let path = path.to_lowercase();
    let name = pyfs::basename(&path);
    KEY_SUFFIXES.iter().any(|s| name.ends_with(s))
        || KEY_PREFIXES.iter().any(|p| name.starts_with(p))
        || KEY_NAMES.contains(&name)
        || (KEY_NAME_PATTERN.is_match(name) && !name.ends_with(".pub"))
        || KEY_PATH_ENDINGS.iter().any(|e| path.ends_with(e))
}

/// The real home folder (user database), not $HOME, which a caller can override.
fn is_home_credential(path: &str) -> Result<bool, String> {
    let pw_dir = crate::pwd::own_home().ok_or("KeyError: getpwuid(): uid not found")?;
    let home = pyfs::realpath(&pw_dir)?;
    let mut bases = vec![home];
    if !bases.contains(&pw_dir) {
        bases.push(pw_dir);
    }
    for base in &bases {
        if !path.starts_with(&format!("{base}/")) {
            continue;
        }
        let rel = pyfs::relpath(path, base)?;
        if !rel.is_empty()
            && HOME_CREDENTIALS
                .iter()
                .any(|c| rel == *c || (c.ends_with('/') && rel.starts_with(c)))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// True if the file starts a private key near its top. Missing, unreadable and special files are left alone.
fn has_key_header(path: &str) -> bool {
    if !pyfs::isfile(path) {
        return false;
    }
    let Ok(f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = Vec::new();
    if f.take(SNIFF_BYTES).read_to_end(&mut head).is_err() {
        return false;
    }
    KEY_HEADER.is_match(&head)
}

fn block(path: &str, why: &str, rule: &'static str) -> Verdict {
    Verdict::Block {
        message: format!(
            "Blocked by guard-read-keys.py: {} {}. Don't read key or credential files; work from the path, and ask the user if the task needs the contents.",
            pyfs::basename(path),
            why
        ),
        rule,
    }
}

fn check(data: &serde_json::Map<String, Value>, path: &str) -> Result<Verdict, String> {
    let mut path = pyfs::expanduser(path)?;
    if !path.starts_with('/') {
        let cwd = match data.get("cwd") {
            Some(v) if py_truthy(v) => match v {
                Value::String(s) => s.clone(),
                other => {
                    return Err(format!(
                        "TypeError: expected str, bytes or os.PathLike object, not {}",
                        hookio::py_type_name(other)
                    ));
                }
            },
            _ => pyfs::cwd()?,
        };
        path = pyfs::join(&cwd, &path);
    }
    let real = pyfs::realpath(&path)?;
    for candidate in [&path, &real] {
        if is_key_file(candidate) {
            return Ok(block(
                candidate,
                "looks like a private key or certificate store",
                "key-name",
            ));
        }
        if is_home_credential(candidate)? {
            return Ok(block(candidate, "is a credential file", "credential"));
        }
    }
    if has_key_header(&real) {
        return Ok(block(&path, "contains a private key", "key-header"));
    }
    Ok(Verdict::Allow)
}

/// The verdict for one hook input (raw stdin bytes). A panic inside the check is a crash (blocks).
pub fn decide(input: &[u8]) -> Verdict {
    let data = match hookio::parse_py(input) {
        Ok(Value::Object(data)) => data,
        // guard-read-keys.py caught only ValueError around json.load; RecursionError crashed it, which blocks.
        Err(hookio::ParseError::TooDeep(kind)) => {
            return Verdict::Crash(hookio::ParseError::too_deep_text(kind));
        }
        _ => return Verdict::Allow,
    };
    let Some(Value::Object(tool_input)) = data.get("tool_input") else {
        return Verdict::Allow;
    };
    let Some(Value::String(path)) = tool_input.get("file_path") else {
        return Verdict::Allow;
    };
    if path.is_empty() {
        return Verdict::Allow;
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&data, path))) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => Verdict::Crash(e),
        Err(_) => Verdict::Crash("panic".into()),
    }
}

/// Print the verdict the way guard-read-keys.py did; returns the exit code.
pub fn emit(v: &Verdict) -> i32 {
    match v {
        Verdict::Allow => 0,
        Verdict::Block { message, .. } => {
            eprintln!("{message}");
            2
        }
        Verdict::Crash(e) => {
            eprintln!("claude-guard read crashed, so the read is blocked:\n{e}");
            2
        }
    }
}
