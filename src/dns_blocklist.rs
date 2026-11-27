//! `claude-guard dns <command>`: the DNS blocklist. Port of the team runbook's `dns-blocklist` bash script
//! (`tests/reference/dns-blocklist`): one /etc/resolver file per blocked domain, pointing at the `dns-nxdomain`
//! responder agent, so canary and callback domains resolve nowhere for every program that asks macOS.
//!
//! Translated branch by branch, with the script's messages (still `dns-blocklist: ...`, the command people type),
//! exit codes and external commands: `sudo` for every write under /etc/resolver and for the cache flush,
//! `launchctl` for the agent, `scutil --dns` for what macOS loaded and `dig` for the responder check, all found on
//! the script's own PATH (`/usr/bin:/bin:/usr/sbin:/sbin`). The domain list is claude-guard's own built-in list
//! (`web --list-hosts`) plus `block_hosts` from the web guard's policy file, read with Python's `json.load`,
//! `str()`, `lower()` and `strip(".")` semantics, where the script ran an inline `/usr/bin/python3`. A name
//! resolves when `getaddrinfo(name, 443)` succeeds, as the script's Python check did.
//!
//! Where the script stopped (`set -e`), the port stops with the failed command's exit code; where it carried on
//! (`|| true`, a failure inside `$( )`), the port carries on. Accepted differences, each tested:
//! - The list comes from this binary, not from running `~/.local/bin/claude-guard web --list-hosts`; the script's
//!   "no block list" error still applies when that file isn't executable.
//! - A policy file Python couldn't read gave a traceback; the port prints one line naming the file and the reason.
//! - `check` stops with exit 1 when the policy file can't be read, as `list`, `status` and `install` do. The script
//!   carried on with an empty list there and could report "ok: 0 domains" (a bug, fixed on purpose).
//! - The script's unquoted `for d in $(ours)` also expanded `*`, `?` and `[` in a resolver file's name against the
//!   current folder; the port only splits at whitespace (a file this script wrote is always a plain domain name).
//!
//! Test-only arguments, before the command (never environment variables): `--resolver-dir DIR` (/etc/resolver),
//! `--real-home DIR` (the user database's home folder, where the policy file lives), `--path PATH` (the PATH
//! external commands are found on), `--resolve-with PROG` (run `PROG <name>` instead of getaddrinfo; exit 0 means
//! the name resolves), `--no-sleep`.

use crate::hookio::{self, ParseError};
use serde_json::Value;
use std::ffi::CString;
use std::io::Write;
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const SELFTEST: &str = "selftest.192-0-2-1.sslip.io";
const RELAY: [&str; 2] = ["mask.icloud.com", "mask-h2.icloud.com"];
const BODY: &str = "nameserver 127.0.0.1\nport 10053";
const OLD_BODY: &str = "nameserver 127.0.0.1\nport 5\ntimeout 1";
const LABEL: &str = "local.claude-guard.dns-nxdomain";
const SCRIPT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The script's header comment, which its `help` (and any unknown command) prints: lines 2 to "remove them
/// (sudo)" with the leading `# ` removed.
const HELP: &str = r##"dns-blocklist: make the web guard's canary and callback hosts resolve nowhere, for every program that looks names
up through macOS (Playwright, Chrome, curl, Node's fetch, MCP servers, scripts), not only the tool calls Claude
Code's hooks see. Programs that send DNS themselves get past it: dig, nslookup, Node's dns.resolve*, Go with
GODEBUG=netdns=go, DNS-over-HTTPS. It stops callbacks tripped by accident, not code written to get out.

How: one macOS per-domain resolver file per host, /etc/resolver/<domain>, pointing at a local port where
nothing listens. macOS applies such a file to the domain and all its subdomains, so x7q2.canarytokens.com
fails to resolve too, at once: the files point at dns-nxdomain, a local responder that answers every query with
"no such domain" (a launchd agent for your user, 127.0.0.1:10053; it forwards nothing). If the agent isn't
running, those lookups still fail, after about 30 s of retries (fail closed). Nothing leaves the Mac. macOS reads the folder when it rebuilds its DNS
settings, which a network change does (VPN reconnect, Wi-Fi off and on), not a change to the folder itself.
The list comes from claude-guard (`claude-guard web --list-hosts`, the hook's own built-in list) plus block_hosts
in ~/.config/claude-guard/url-policy.json (in the real home folder from the user database, as the web guard reads
it, not $HOME), so the
hook and the DNS layer can't drift apart: after changing either, run `dns-blocklist install` again.

Usage:
  dns-blocklist list       the domains it would block
  dns-blocklist install    start the responder agent, write /etc/resolver files (sudo; asks for your password),
                           remove ones no longer listed
  dns-blocklist agent      start (or restart) only the responder agent (no sudo)
  dns-blocklist check      prove each domain and a random subdomain fail to resolve (no sudo)
  dns-blocklist status     one line: how many domains macOS has loaded, whether the responder answers, and
                           whether the self-test name is blocked (BYPASSED: something answers DNS around
                           the blocklist, such as iCloud Private Relay), and whether the Private Relay files
                           are in place
  dns-blocklist remove     delete every file this script wrote (sudo)
  dns-blocklist diagnose   write 4 throwaway variants for made-up .invalid domains, report which macOS loads,
                           remove them (sudo)
"##;

unsafe extern "C" {
    fn getuid() -> u32;
    fn access(path: *const c_char, mode: c_int) -> c_int;
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
    fn strcoll(a: *const c_char, b: *const c_char) -> c_int;
}
const X_OK: c_int = 1;
const LC_COLLATE: c_int = 1; // macOS <locale.h>

/// Stop with this exit code (the message, if any, is already on stderr).
#[derive(Debug)]
pub struct Exit(pub i32);

type R<T> = Result<T, Exit>;

pub struct Ctx {
    dir: String,
    home: String,
    real_home: Option<String>,
    path: String,
    resolve_with: Option<String>,
    sleep: bool,
    help: String,
}

impl Ctx {
    fn cg(&self) -> String {
        format!("{}/.local/bin/claude-guard", self.home)
    }
    fn plist(&self) -> String {
        format!("{}/Library/LaunchAgents/{LABEL}.plist", self.home)
    }
    fn old_responder(&self) -> String {
        format!("{}/.local/share/claude-guard/dns-nxdomain.py", self.home)
    }
    fn policy(&self) -> String {
        let base = match &self.real_home {
            Some(h) if !h.is_empty() => h.clone(),
            _ => self.home.clone(),
        };
        format!("{base}/.config/claude-guard/url-policy.json")
    }
    fn cmd(&self, prog: &str) -> Command {
        let mut c = Command::new(prog);
        c.env("PATH", &self.path);
        c
    }
    fn nap(&self, secs: u64) {
        if self.sleep {
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
    }
}

fn die(msg: &str) -> Exit {
    eprintln!("dns-blocklist: {msg}");
    Exit(1)
}

fn flush_out() {
    let _ = std::io::stdout().flush();
}

/// bash's exit code for a command it couldn't start: 126 when the file was found but couldn't be run (no execute
/// permission, or the system refused it), 127 when there was nothing to run.
fn exec_failure_code(e: &std::io::Error) -> i32 {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        126
    } else {
        127
    }
}

/// Run a command with stdout and stderr passed through; a failure stops the run, as `set -e` did.
fn must(mut c: Command) -> R<()> {
    flush_out();
    match c.status() {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(Exit(s.code().unwrap_or(1))),
        Err(e) => {
            eprintln!("dns-blocklist: {}: {e}", c.get_program().to_string_lossy());
            Err(Exit(exec_failure_code(&e)))
        }
    }
}

/// Run a command whose failure the script ignored.
fn quiet(mut c: Command) {
    flush_out();
    let _ = c.status();
}

/// `$(cat file)`: NUL bytes dropped (bash 3.2) and trailing newlines removed.
fn subst(bytes: &[u8]) -> String {
    let mut v: Vec<u8> = bytes.iter().copied().filter(|&b| b != 0).collect();
    while v.last() == Some(&b'\n') {
        v.pop();
    }
    String::from_utf8_lossy(&v).into_owned()
}

/// `for d in $(ours)`: bash splits the lines into words at spaces, tabs and newlines.
fn words(names: &[String]) -> Vec<String> {
    names
        .iter()
        .flat_map(|n| {
            n.split([' ', '\t', '\n'])
                .filter(|w| !w.is_empty())
                .map(str::to_string)
        })
        .collect()
}

/// `$(cat "$path")` with cat's error line on stderr when it can't read the file.
fn cat_loud(path: &str) -> Option<String> {
    match std::fs::read(path) {
        Ok(b) => Some(subst(&b)),
        Err(e) => {
            let why = match e.kind() {
                std::io::ErrorKind::NotFound => "No such file or directory",
                std::io::ErrorKind::PermissionDenied => "Permission denied",
                _ if std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false) => {
                    "Is a directory"
                }
                _ => "Input/output error",
            };
            eprintln!("cat: {path}: {why}");
            None
        }
    }
}

fn cat(path: &str) -> Option<String> {
    std::fs::read(path).ok().map(|b| subst(&b))
}

fn executable(path: &str) -> bool {
    let Ok(c) = CString::new(path) else {
        return false;
    };
    // SAFETY: `c` is a valid C string for the call.
    unsafe { access(c.as_ptr(), X_OK) == 0 }
}

fn is_file(p: &str) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

fn exists(p: &str) -> bool {
    std::fs::metadata(p).is_ok()
}

fn uid() -> u32 {
    // SAFETY: getuid can't fail.
    unsafe { getuid() }
}

/// bash's `$RANDOM`: 0 to 32767.
fn random() -> u32 {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32))
        .unwrap_or(0);
    (n ^ std::process::id().rotate_left(7)).wrapping_mul(2_654_435_761) % 32_768
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Python's `repr(float)`: the shortest round-trip digits, fixed notation for exponents -4 to 15, otherwise
/// `d.ddde+XX` with at least two exponent digits.
fn py_float_repr(f: f64) -> String {
    let sci = format!("{f:e}");
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (neg, mant) = match mant.strip_prefix('-') {
        Some(m) => (true, m),
        None => (false, mant),
    };
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let sign = if neg { "-" } else { "" };
    if (-4..16).contains(&exp) {
        let body = if exp >= 0 {
            let int_len = exp as usize + 1;
            let mut d = digits.clone();
            while d.len() < int_len {
                d.push('0');
            }
            let (i, frac) = d.split_at(int_len);
            format!("{i}.{}", if frac.is_empty() { "0" } else { frac })
        } else {
            format!("0.{}{digits}", "0".repeat((-exp - 1) as usize))
        };
        format!("{sign}{body}")
    } else {
        let (first, rest) = digits.split_at(1);
        let rest = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let es = if exp < 0 { '-' } else { '+' };
        format!("{sign}{first}{rest}e{es}{:02}", exp.abs())
    }
}

/// Python's `str()` of a JSON value from `json.load`.
fn py_str_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => {
            if let Some(f) = n.as_f64().filter(|_| n.is_f64()) {
                hookio::py_float_name(f)
                    .map(str::to_string)
                    .unwrap_or_else(|| py_float_repr(f))
            } else {
                n.to_string()
            }
        }
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        // A list or dict's str() has brackets or braces, which the domain filter never passes.
        Value::Array(_) => "[...]".into(),
        Value::Object(_) => "{...}".into(),
    }
}

/// `re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", n)`.
fn resolver_name(n: &str) -> bool {
    let label = |l: &str| {
        !l.is_empty()
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let parts: Vec<&str> = n.split('.').collect();
    parts.len() >= 2 && parts.iter().all(|l| label(l))
}

/// The policy file's extra names, as the script's Python read them. Err: the line to print where Python raised.
fn policy_names(path: &str) -> Result<Vec<String>, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("can't read {path}: {e}")),
    };
    let v = match hookio::parse_py(&bytes) {
        Ok(v) => v,
        Err(ParseError::TooDeep(_)) => return Err(format!("can't read {path}: nested too deep")),
        Err(ParseError::Invalid) => return Err(format!("can't read {path}: not valid JSON")),
    };
    let Value::Object(o) = v else {
        return Err(format!("can't read {path}: not a JSON object"));
    };
    let items: Vec<String> = match o.get("block_hosts") {
        None => Vec::new(),
        Some(Value::Array(a)) => a.iter().map(py_str_of).collect(),
        Some(Value::String(s)) => s.chars().map(|c| c.to_string()).collect(),
        Some(Value::Object(m)) => m.keys().cloned().collect(),
        Some(_) => return Err(format!("can't read {path}: block_hosts isn't a list")),
    };
    Ok(items
        .iter()
        .map(|h| h.to_lowercase().trim_matches('.').to_string())
        .collect())
}

/// `domains`: Err(Exit(1)) where the script's Python exited 1, after printing why.
fn domains(ctx: &Ctx) -> R<Vec<String>> {
    if !executable(&ctx.cg()) {
        eprintln!("dns-blocklist: no block list: install claude-guard (Step 16, claude-guard)");
        return Err(Exit(1));
    }
    let mut names: Vec<String> = crate::web::list_hosts()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    match policy_names(&ctx.policy()) {
        Ok(extra) => names.extend(extra),
        Err(msg) => {
            eprintln!("dns-blocklist: {msg}");
            return Err(Exit(1));
        }
    }
    names.sort();
    names.dedup();
    Ok(names.into_iter().filter(|n| resolver_name(n)).collect())
}

/// `$(domains)` where the script ignored a failure: the names, or none.
fn domains_or_none(ctx: &Ctx) -> Vec<String> {
    domains(ctx).unwrap_or_default()
}

/// bash 3.2's glob order: the locale's collation (`strcoll` under LC_COLLATE from the environment).
fn collate_sort(names: &mut [String]) {
    // SAFETY: setlocale with an empty string reads the environment; called before any other thread exists.
    unsafe {
        let empty = CString::new("").unwrap_or_default();
        setlocale(LC_COLLATE, empty.as_ptr());
    }
    names.sort_by(|a, b| {
        let (ca, cb) = (
            CString::new(a.as_str()).unwrap_or_default(),
            CString::new(b.as_str()).unwrap_or_default(),
        );
        // SAFETY: both are valid C strings.
        let r = unsafe { strcoll(ca.as_ptr(), cb.as_ptr()) };
        r.cmp(&0).then_with(|| a.cmp(b))
    });
}

/// `ours`: files in the resolver folder this script wrote (BODY or OLD_BODY), in glob order.
fn ours(ctx: &Ctx) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(&ctx.dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect();
    collate_sort(&mut names);
    names
        .into_iter()
        .filter(|n| {
            let p = format!("{}/{n}", ctx.dir);
            is_file(&p) && matches!(cat(&p).as_deref(), Some(BODY) | Some(OLD_BODY))
        })
        .collect()
}

fn agent_up(ctx: &Ctx) -> bool {
    let mut c = ctx.cmd("dig");
    c.args([
        "+time=1",
        "+tries=1",
        "@127.0.0.1",
        "-p",
        "10053",
        "dns-blocklist-check.invalid",
    ]);
    flush_out();
    c.stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("status: NXDOMAIN"))
        .unwrap_or(false)
}

fn agent_old(ctx: &Ctx) -> bool {
    std::fs::read(ctx.plist())
        .map(|b| b.windows(15).any(|w| w == b"dns-nxdomain.py"))
        .unwrap_or(false)
}

fn start_agent(ctx: &Ctx) -> R<()> {
    let cg = ctx.cg();
    if !executable(&cg) {
        return Err(die(&format!(
            "no {cg} (install claude-guard first: Step 16, claude-guard)"
        )));
    }
    let plist = ctx.plist();
    let parent = Path::new(&plist).parent().map(Path::to_path_buf);
    if let Some(p) = parent {
        let mut c = ctx.cmd("mkdir");
        c.arg("-p").arg(p);
        must(c)?;
    }
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\"><dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{cg}</string><string>dns-nxdomain</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
"
    );
    if let Err(e) = std::fs::write(&plist, body) {
        eprintln!("dns-blocklist: {plist}: {e}");
        return Err(Exit(1));
    }
    let target = format!("gui/{}/{LABEL}", uid());
    let mut c = ctx.cmd("launchctl");
    c.args(["bootout", &target]);
    flush_out();
    let _ = c.stderr(Stdio::null()).status();
    let mut c = ctx.cmd("launchctl");
    c.args(["bootstrap", &format!("gui/{}", uid()), &plist]);
    must(c)?;
    for _ in 0..5 {
        if agent_up(ctx) {
            let mut c = ctx.cmd("rm");
            c.args(["-f", &ctx.old_responder()]);
            quiet(c);
            println!("dns-blocklist: responder agent answering on 127.0.0.1:10053");
            return Ok(());
        }
        ctx.nap(1);
    }
    Err(die(&format!(
        "responder agent didn't answer on 127.0.0.1:10053 (launchctl print {target})"
    )))
}

fn flush(ctx: &Ctx) -> R<()> {
    let mut c = ctx.cmd("sudo");
    c.args(["dscacheutil", "-flushcache"]);
    must(c)?;
    let mut c = ctx.cmd("sudo");
    c.args(["killall", "-HUP", "mDNSResponder"]);
    flush_out();
    let _ = c.stderr(Stdio::null()).status();
    Ok(())
}

fn scutil_dns(ctx: &Ctx) -> (String, i32) {
    let mut c = ctx.cmd("scutil");
    c.arg("--dns");
    flush_out();
    match c.stdin(Stdio::null()).stderr(Stdio::inherit()).output() {
        Ok(o) => (subst(&o.stdout), o.status.code().unwrap_or(1)),
        Err(_) => (String::new(), 127),
    }
}

/// `grep -qE "^  domain   : $d\$"` on each line: the name's dots match any character, as in the script.
fn conf_has(conf: &str, d: &str) -> bool {
    let pat = format!("^  domain   : {d}$");
    let Ok(re) = regex::Regex::new(&pat) else {
        return false;
    };
    conf.split('\n').any(|l| re.is_match(l))
}

fn loaded(ctx: &Ctx) -> usize {
    let (conf, _) = scutil_dns(ctx);
    domains_or_none(ctx)
        .iter()
        .filter(|d| conf_has(&conf, d))
        .count()
}

fn resolves(ctx: &Ctx, name: &str) -> bool {
    if let Some(prog) = &ctx.resolve_with {
        let mut c = ctx.cmd(prog);
        c.arg(name);
        flush_out();
        return c
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    use std::net::ToSocketAddrs;
    (name, 443u16).to_socket_addrs().is_ok()
}

fn extras_missing(ctx: &Ctx) -> Vec<&'static str> {
    std::iter::once(SELFTEST)
        .chain(RELAY)
        .filter(|d| !is_file(&format!("{}/{d}", ctx.dir)))
        .collect()
}

fn selftest(ctx: &Ctx) -> &'static str {
    if !is_file(&format!("{}/{SELFTEST}", ctx.dir)) {
        return "missing";
    }
    if resolves(ctx, &format!("probe-{}{}.{SELFTEST}", random(), random())) {
        "BYPASSED"
    } else {
        "blocked"
    }
}

fn sudo(ctx: &Ctx, args: &[&str]) -> R<()> {
    let mut c = ctx.cmd("sudo");
    c.args(args);
    must(c)
}

/// `printf '%s\n' "$text" | sudo tee "$path" >/dev/null`
fn sudo_write(ctx: &Ctx, path: &str, text: &str) -> R<()> {
    let mut c = ctx.cmd("sudo");
    c.args(["tee", path])
        .stdin(Stdio::piped())
        .stdout(Stdio::null());
    flush_out();
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => {
            eprintln!("dns-blocklist: sudo: {e}");
            return Err(Exit(exec_failure_code(&e)));
        }
    };
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(format!("{text}\n").as_bytes());
    }
    match child.wait() {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(Exit(s.code().unwrap_or(1))),
        Err(_) => Err(Exit(1)),
    }
}

/// `head -n 1 "$path" | grep -q '^# dns-blocklist'`, with head's own error lines.
fn first_line_ours(path: &str) -> bool {
    match std::fs::read(path) {
        Ok(b) => {
            let line = b.split(|&c| c == b'\n').next().unwrap_or(&[]);
            line.starts_with(b"# dns-blocklist")
        }
        Err(e) => {
            if std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false) {
                eprintln!("head: Error reading {path}");
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("head: {path}: Permission denied");
            }
            false
        }
    }
}

fn status(ctx: &Ctx) -> R<i32> {
    let total = domains(ctx)?.len();
    let have = ours(ctx).len();
    let got = loaded(ctx);
    let a = if agent_up(ctx) { "answering" } else { "down" };
    let incomplete_extras = |got: usize| {
        format!(
            "INCOMPLETE ({got} of {total} loaded, responder answering, missing self-test or Private Relay file: run dns-blocklist install)"
        )
    };
    if have == 0 {
        println!("MISSING");
    } else if agent_old(ctx) {
        println!(
            "INCOMPLETE (the responder agent still runs the old Python script: run dns-blocklist agent)"
        );
    } else if got == total && a == "answering" && !extras_missing(ctx).is_empty() {
        println!("{}", incomplete_extras(got));
    } else if got == total && a == "answering" {
        match selftest(ctx) {
            "blocked" => {
                println!("ok ({got} of {total} loaded, responder answering, self-test blocked)")
            }
            "BYPASSED" => println!(
                "BYPASSED ({got} of {total} loaded, responder answering, but the self-test name resolves: something answers DNS around the blocklist, such as iCloud Private Relay)"
            ),
            _ => println!("{}", incomplete_extras(got)),
        }
    } else {
        println!("INCOMPLETE ({have} files, {got} of {total} loaded, responder {a})");
    }
    Ok(0)
}

fn install(ctx: &Ctx) -> R<i32> {
    let listed = domains(ctx)?;
    if listed.is_empty() {
        return Err(die("empty list"));
    }
    let mut want: Vec<String> = listed;
    want.push(SELFTEST.to_string());
    want.extend(RELAY.iter().map(|s| s.to_string()));
    start_agent(ctx)?;
    println!(
        "dns-blocklist: writing {} files in {} (sudo)",
        want.len(),
        ctx.dir
    );
    sudo(ctx, &["mkdir", "-p", &ctx.dir])?;
    for d in &want {
        let p = format!("{}/{d}", ctx.dir);
        let c = cat(&p).unwrap_or_default();
        if exists(&p) && c != BODY && c != OLD_BODY && !first_line_ours(&p) {
            println!("  skip {d}: {p} exists and isn't ours");
            continue;
        }
        let tmp = format!("{}/.dns-blocklist-{d}", ctx.dir);
        sudo_write(ctx, &tmp, BODY)?;
        sudo(ctx, &["chmod", "644", &tmp])?;
        sudo(ctx, &["mv", "-f", &tmp, &p])?;
    }
    for d in words(&ours(ctx)) {
        if !want.contains(&d) {
            sudo(ctx, &["rm", "-f", &format!("{}/{d}", ctx.dir)])?;
            println!("  removed {d} (no longer listed)");
        }
    }
    flush(ctx)?;
    ctx.nap(2);
    flush(ctx)?;
    let total = domains(ctx)?.len();
    let got = loaded(ctx);
    println!("dns-blocklist: installed; macOS loaded {got} of {total} (scutil --dns).");
    println!(
        "Private Relay is blocked too: if it's on, macOS asks once per network whether to use the network without it. Choose 'Use Without Private Relay'."
    );
    if got == 0 {
        println!(
            "macOS hasn't read the files yet: it rebuilds its DNS settings (and reads {}) when the network changes,",
            ctx.dir
        );
        println!(
            "not when the folder does. Reconnect the VPN, or turn Wi-Fi off and on, then run 'dns-blocklist check'."
        );
    } else if got != total {
        println!("Only some loaded: testing which file format macOS accepts...");
        return diagnose(ctx);
    } else {
        match selftest(ctx) {
            "blocked" => println!("Self-test: blocked. Run 'dns-blocklist check'"),
            "BYPASSED" => println!(
                "Self-test: BYPASSED: the files are loaded, but something answers DNS around them. Turn off iCloud Private Relay (System Settings, your name, iCloud), then run 'dns-blocklist status'"
            ),
            _ => println!("Self-test file not loaded yet; run 'dns-blocklist check'"),
        }
    }
    Ok(0)
}

fn check(ctx: &Ctx) -> R<i32> {
    let have = ours(ctx);
    if have.is_empty() {
        return Err(die(&format!(
            "not installed (no files in {} with this script's content)",
            ctx.dir
        )));
    }
    // A list it can't build stops here, as in list, status and install. (The script carried on with no domains
    // and could end with "ok: 0 domains"; changed on purpose, 2026-11-27.)
    let total = domains(ctx)?.len();
    let got = loaded(ctx);
    println!("macOS has loaded {got} of {total} domains (scutil --dns)");
    let mut bad_agent = false;
    if agent_up(ctx) {
        println!("responder agent: answering");
    } else {
        println!(
            "responder agent: NOT answering (lookups hang ~30 s, still fail): dns-blocklist agent"
        );
        bad_agent = true;
    }
    let old = words(&have)
        .iter()
        .filter(|d| cat_loud(&format!("{}/{d}", ctx.dir)).as_deref() == Some(OLD_BODY))
        .count();
    if old != 0 {
        println!(
            "{old} files still point at the old port 5 (every lookup hangs ~30 s): run dns-blocklist install, then reconnect the network"
        );
        return Ok(1);
    }
    let mut bad = 0;
    let mut n = 0;
    let mut slow = false;
    for d in domains_or_none(ctx) {
        n += 1;
        if !have.contains(&d) {
            println!("MISSING {d}");
            bad = 1;
            continue;
        }
        for name in [d.clone(), format!("probe-{}.{d}", random())] {
            let s = now_secs();
            if resolves(ctx, &name) {
                println!("RESOLVES {name}");
                bad = 1;
            } else if now_secs() - s > 3 {
                println!("SLOW {name} (blocked, but took {} s)", now_secs() - s);
                slow = true;
            }
        }
        if slow && bad_agent {
            println!("stopping: every lookup takes ~30 s while the agent is down");
            return Ok(1);
        }
    }
    match selftest(ctx) {
        "blocked" => {}
        "BYPASSED" => {
            println!(
                "BYPASSED: a name under {SELFTEST} resolves although its resolver file blocks it: something answers DNS around the blocklist (turn off iCloud Private Relay)"
            );
            bad = 1;
        }
        _ => {
            println!(
                "MISSING self-test file {}/{SELFTEST}: run dns-blocklist install",
                ctx.dir
            );
            bad = 1;
        }
    }
    for d in RELAY {
        if !have.iter().any(|h| h == d) {
            println!(
                "MISSING Private Relay file {}/{d}: run dns-blocklist install",
                ctx.dir
            );
            bad = 1;
            continue;
        }
        if resolves(ctx, d) {
            println!(
                "RESOLVES {d} (an answer cached from before: run dns-blocklist install again, or sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder)"
            );
            bad = 1;
        }
    }
    if !resolves(ctx, "example.com") {
        println!("WARNING: example.com doesn't resolve either: no network, or DNS is broken");
        bad = 1;
    }
    if bad == 0 {
        println!(
            "ok: {n} domains and their subdomains resolve nowhere, self-test blocked, Private Relay blocked; example.com still resolves"
        );
    }
    Ok(bad)
}

fn diagnose(ctx: &Ctx) -> R<i32> {
    sudo(ctx, &["mkdir", "-p", &ctx.dir])?;
    let v1 = "nameserver 127.0.0.1".to_string();
    let variants = [
        v1.clone(),
        format!("{v1}\nport 5"),
        format!("{v1}\ntimeout 1"),
        BODY.to_string(),
    ];
    for (i, b) in variants.iter().enumerate() {
        sudo_write(ctx, &format!("{}/dnsdiag-{}.invalid", ctx.dir, i + 1), b)?;
    }
    let mut c = ctx.cmd("sudo");
    c.args(["killall", "-HUP", "mDNSResponder"]);
    flush_out();
    let _ = c.stderr(Stdio::null()).status();
    ctx.nap(3);
    let (conf, code) = scutil_dns(ctx);
    if code != 0 {
        return Err(Exit(code));
    }
    for (i, b) in variants.iter().enumerate() {
        let n = i + 1;
        let pat = format!("^  domain   : dnsdiag-{n}\\.invalid$");
        let re = regex::Regex::new(&pat).map_err(|_| Exit(1))?;
        let s = if conf.split('\n').any(|l| re.is_match(l)) {
            "loaded"
        } else {
            "NOT loaded"
        };
        println!("variant {n} ({}): {s}", b.replace('\n', ";"));
    }
    for n in 1..=4 {
        sudo(
            ctx,
            &["rm", "-f", &format!("{}/dnsdiag-{n}.invalid", ctx.dir)],
        )?;
    }
    let mut c = ctx.cmd("sudo");
    c.args(["killall", "-HUP", "mDNSResponder"]);
    flush_out();
    let _ = c.stderr(Stdio::null()).status();
    println!("(test files removed)");
    Ok(0)
}

fn remove(ctx: &Ctx) -> R<i32> {
    for d in words(&ours(ctx)) {
        sudo(ctx, &["rm", "-f", &format!("{}/{d}", ctx.dir)])?;
        println!("  removed {d}");
    }
    let mut c = ctx.cmd("launchctl");
    c.args(["bootout", &format!("gui/{}/{LABEL}", uid())]);
    flush_out();
    let _ = c.stderr(Stdio::null()).status();
    let mut c = ctx.cmd("rm");
    c.args(["-f", &ctx.plist(), &ctx.old_responder()]);
    must(c)?;
    println!("  responder agent stopped and removed");
    flush(ctx)?;
    println!("dns-blocklist: removed");
    Ok(0)
}

fn list(ctx: &Ctx) -> R<i32> {
    for d in domains(ctx)? {
        println!("{d}");
    }
    Ok(0)
}

/// `claude-guard dns [test options] <command> [ignored...]`. Returns the exit code.
pub fn run(args: &[String]) -> i32 {
    let mut ctx = Ctx {
        dir: "/etc/resolver".into(),
        home: std::env::var("HOME").unwrap_or_default(),
        real_home: crate::pwd::own_home(),
        path: SCRIPT_PATH.into(),
        resolve_with: None,
        sleep: true,
        help: HELP.into(),
    };
    let mut i = 0;
    while i < args.len() {
        let has = i + 1 < args.len();
        match args[i].as_str() {
            "--resolver-dir" if has => ctx.dir = args[i + 1].clone(),
            "--real-home" if has => ctx.real_home = Some(args[i + 1].clone()),
            "--path" if has => ctx.path = args[i + 1].clone(),
            "--resolve-with" if has => ctx.resolve_with = Some(args[i + 1].clone()),
            "--no-sleep" => {
                ctx.sleep = false;
                i += 1;
                continue;
            }
            _ => break,
        }
        i += 2;
    }
    let command = args.get(i).map(String::as_str).unwrap_or("");
    let r = match command {
        "list" => list(&ctx),
        "agent" => start_agent(&ctx).map(|_| 0),
        "status" => status(&ctx),
        "install" => install(&ctx),
        "check" => check(&ctx),
        "diagnose" => diagnose(&ctx),
        "remove" => remove(&ctx),
        other => {
            print!("{}", ctx.help);
            Ok(if other.is_empty() { 0 } else { 2 })
        }
    };
    flush_out();
    match r {
        Ok(code) => code,
        Err(Exit(code)) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_float_repr() {
        for (f, want) in [
            (1.5, "1.5"),
            (1.0, "1.0"),
            (-0.0, "-0.0"),
            (123456789.0, "123456789.0"),
            (1e16, "1e+16"),
            (1.5e16, "1.5e+16"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.25e-7, "1.25e-07"),
            (0.1, "0.1"),
            (1e100, "1e+100"),
        ] {
            assert_eq!(py_float_repr(f), want, "{f}");
        }
    }

    #[test]
    fn exec_failure_codes() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            exec_failure_code(&Error::from(ErrorKind::PermissionDenied)),
            126
        );
        assert_eq!(exec_failure_code(&Error::from(ErrorKind::NotFound)), 127);
    }

    #[test]
    fn resolver_names() {
        for (n, ok) in [
            ("a.b", true),
            ("a-b.c-d", true),
            ("-.-", true),
            ("1.5", true),
            ("a", false),
            ("a.", false),
            (".a", false),
            ("a..b", false),
            ("A.b", false),
            ("a_b.c", false),
            ("a.b\n", false),
            ("é.b", false),
        ] {
            assert_eq!(resolver_name(n), ok, "{n:?}");
        }
    }
}
