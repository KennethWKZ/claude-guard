//! A fake Mac for `claude-guard dns` and its reference, the team runbook's `dns-blocklist` bash script
//! (`tests/reference/dns-blocklist`). Each case gets its own root folder:
//!
//! - `resolver/`: stands in for /etc/resolver;
//! - `home/`: HOME, with `.local/bin/claude-guard` (this test binary, or missing), the agent's plist and the old
//!   Python responder;
//! - `realhome/`: the user database's home folder, holding the web guard's policy file;
//! - `stubs/`: `sudo` (runs the rest of its command), `launchctl`, `dig`, `scutil`, `dscacheutil`, `killall`,
//!   and `resolve` (the name lookup), each logging its call to `state/log` and answering from `state/`;
//! - `ref.sh`: the reference with only these lines changed: its PATH (stubs first), DIR, REAL_HOME, and, just
//!   before the command dispatch, `resolves` running `stubs/resolve` and `sleep` doing nothing.
//!
//! Nothing here can reach the real /etc/resolver, launchd or sudo: both sides find every external command on the
//! stub PATH, and `run_rust` refuses to run without it.

use super::BIN;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::{Command, Stdio};

pub const REFERENCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference/dns-blocklist");
pub const BODY: &str = "nameserver 127.0.0.1\nport 10053";
pub const OLD_BODY: &str = "nameserver 127.0.0.1\nport 5\ntimeout 1";
pub const SELFTEST: &str = "selftest.192-0-2-1.sslip.io";
pub const RELAY: [&str; 2] = ["mask.icloud.com", "mask-h2.icloud.com"];

#[derive(Clone, Debug)]
pub enum Entry {
    File(Vec<u8>),
    Dir,
    /// A symlink to another entry's name in the same folder (or a missing one).
    Link(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Cg {
    Binary,
    Missing,
    NotExecutable,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Plist {
    Absent,
    OldPython,
    New,
}

#[derive(Clone, Debug)]
pub struct Scenario {
    pub command: String,
    pub cg: Cg,
    /// None: no policy file. Some(None): a folder where the file should be.
    pub policy: Option<Option<Vec<u8>>>,
    /// None: no resolver folder.
    pub resolver: Option<Vec<(String, Entry)>>,
    pub plist: Plist,
    pub old_responder: bool,
    pub agent_up: bool,
    pub up_after_bootstrap: bool,
    pub bootstrap_exit: i32,
    pub scutil: String,
    pub scutil_exit: i32,
    pub dscache_exit: i32,
    /// Shell `case` patterns: a name that matches one resolves.
    pub resolves: Vec<String>,
}

impl Scenario {
    pub fn new(command: &str) -> Scenario {
        Scenario {
            command: command.into(),
            cg: Cg::Binary,
            policy: None,
            resolver: None,
            plist: Plist::Absent,
            old_responder: false,
            agent_up: false,
            up_after_bootstrap: false,
            bootstrap_exit: 0,
            scutil: String::new(),
            scutil_exit: 0,
            dscache_exit: 0,
            resolves: vec!["example.com".into()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub log: String,
    pub tree: String,
}

/// The built-in list (`claude-guard web --list-hosts`).
pub fn builtin() -> Vec<String> {
    let o = Command::new(BIN)
        .args(["web", "--list-hosts"])
        .stdin(Stdio::null())
        .output()
        .expect("list-hosts");
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// scutil --dns text listing these domains, the way macOS prints per-domain resolvers.
pub fn scutil_text(domains: &[String]) -> String {
    let mut s = String::from("DNS configuration\n\nresolver #1\n  nameserver[0] : 192.168.1.1\n");
    for (i, d) in domains.iter().enumerate() {
        s.push_str(&format!(
            "\nresolver #{}\n  domain   : {d}\n  nameserver[0] : 127.0.0.1\n  port     : 10053\n",
            i + 2
        ));
    }
    s
}

fn write(path: &str, bytes: &[u8]) {
    if let Some(p) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(p).expect("mkdir");
    }
    std::fs::write(path, bytes).expect("write");
}

fn exe(path: &str, text: &str) {
    write(path, text.as_bytes());
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

const STUB_PATH_TAIL: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Build the case's root folder.
pub fn build(root: &str, sc: &Scenario) {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root).expect("root");
    let st = format!("{root}/state");
    std::fs::create_dir_all(&st).expect("state");
    write(
        &format!("{st}/agent"),
        if sc.agent_up { b"up" } else { b"down" },
    );
    if sc.up_after_bootstrap {
        write(&format!("{st}/up-after-bootstrap"), b"");
    }
    write(
        &format!("{st}/bootstrap-exit"),
        sc.bootstrap_exit.to_string().as_bytes(),
    );
    write(&format!("{st}/scutil"), sc.scutil.as_bytes());
    write(
        &format!("{st}/scutil-exit"),
        sc.scutil_exit.to_string().as_bytes(),
    );
    write(
        &format!("{st}/dscache-exit"),
        sc.dscache_exit.to_string().as_bytes(),
    );
    // One pattern per line, each ending in a newline (`read` drops an unterminated last line).
    write(
        &format!("{st}/resolves"),
        sc.resolves
            .iter()
            .map(|p| format!("{p}\n"))
            .collect::<String>()
            .as_bytes(),
    );
    write(&format!("{st}/log"), b"");
    let s = format!("{root}/stubs");
    let log = format!("printf '%s\\n' \"${{0##*/}} $*\" >> {st}/log");
    // The stub PATH is pinned here too, so the command sudo runs is always a stub or a harmless /bin tool.
    exe(
        &format!("{s}/sudo"),
        &format!("#!/bin/bash\n{log}\nPATH={s}:{STUB_PATH_TAIL} exec \"$@\"\n"),
    );
    exe(
        &format!("{s}/launchctl"),
        &format!(
            "#!/bin/bash\n{log}\ncase \"$1\" in\n  bootstrap) [ -e {st}/up-after-bootstrap ] && echo up > {st}/agent; exit $(cat {st}/bootstrap-exit) ;;\n  bootout) [ \"$(cat {st}/agent)\" = up ] && echo down > {st}/agent && exit 0; exit 3 ;;\nesac\nexit 0\n"
        ),
    );
    exe(
        &format!("{s}/dig"),
        &format!(
            "#!/bin/bash\n{log}\nif [ \"$(cat {st}/agent)\" = up ]; then echo ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1'; exit 0; fi\necho ';; connection timed out; no servers could be reached'; exit 9\n"
        ),
    );
    exe(
        &format!("{s}/scutil"),
        &format!("#!/bin/bash\n{log}\ncat {st}/scutil\nexit $(cat {st}/scutil-exit)\n"),
    );
    exe(
        &format!("{s}/dscacheutil"),
        &format!("#!/bin/bash\n{log}\nexit $(cat {st}/dscache-exit)\n"),
    );
    exe(
        &format!("{s}/killall"),
        &format!("#!/bin/bash\n{log}\nexit 0\n"),
    );
    exe(
        &format!("{s}/resolve"),
        &format!(
            "#!/bin/bash\nwhile IFS= read -r p; do [ -n \"$p\" ] || continue; case \"$1\" in $p) exit 0 ;; esac; done < {st}/resolves\nexit 1\n"
        ),
    );
    let home = format!("{root}/home");
    std::fs::create_dir_all(format!("{home}/.local/bin")).expect("home");
    match sc.cg {
        Cg::Binary => symlink(BIN, format!("{home}/.local/bin/claude-guard")).expect("link"),
        Cg::NotExecutable => write(&format!("{home}/.local/bin/claude-guard"), b"#!/bin/sh\n"),
        Cg::Missing => {}
    }
    let pol = format!("{root}/realhome/.config/claude-guard/url-policy.json");
    match &sc.policy {
        None => std::fs::create_dir_all(format!("{root}/realhome")).expect("realhome"),
        Some(None) => std::fs::create_dir_all(&pol).expect("policy dir"),
        Some(Some(b)) => write(&pol, b),
    }
    if let Some(entries) = &sc.resolver {
        let d = format!("{root}/resolver");
        std::fs::create_dir_all(&d).expect("resolver");
        for (name, e) in entries {
            let p = format!("{d}/{name}");
            match e {
                Entry::File(b) => {
                    write(&p, b);
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644))
                        .expect("chmod");
                }
                Entry::Dir => std::fs::create_dir_all(&p).expect("dir"),
                Entry::Link(t) => {
                    let _ = symlink(t, &p);
                }
            }
        }
    }
    let plist = format!("{home}/Library/LaunchAgents/local.claude-guard.dns-nxdomain.plist");
    match sc.plist {
        Plist::Absent => {}
        Plist::OldPython => write(
            &plist,
            format!("<plist><array><string>/usr/bin/python3</string><string>-I</string><string>{home}/.local/share/claude-guard/dns-nxdomain.py</string></array></plist>\n").as_bytes(),
        ),
        Plist::New => write(
            &plist,
            format!("<plist><array><string>{home}/.local/bin/claude-guard</string><string>dns-nxdomain</string></array></plist>\n").as_bytes(),
        ),
    }
    if sc.old_responder {
        write(
            &format!("{home}/.local/share/claude-guard/dns-nxdomain.py"),
            b"# old\n",
        );
    }
    // The reference, pointed at the fakes.
    let text = std::fs::read_to_string(REFERENCE).expect("reference");
    let mut out = String::new();
    let mut hooked = 0;
    for line in text.lines() {
        if line == "PATH=/usr/bin:/bin:/usr/sbin:/sbin" {
            out.push_str(&format!("PATH={s}:{STUB_PATH_TAIL}\n"));
            hooked += 1;
        } else if line == "DIR=/etc/resolver" {
            out.push_str(&format!("DIR={root}/resolver\n"));
            hooked += 1;
        } else if line.starts_with("REAL_HOME=$(id -P") {
            out.push_str(&format!("REAL_HOME={root}/realhome\n"));
            hooked += 1;
        } else if line == "case \"${1:-}\" in" {
            out.push_str(&format!(
                "resolves() {{ {s}/resolve \"$1\"; }}\nsleep() {{ :; }}\n{line}\n"
            ));
            hooked += 1;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert_eq!(
        hooked, 4,
        "the reference changed: update the hooks in tests/common/dnsbl.rs"
    );
    exe(&format!("{root}/ref.sh"), &out);
}

fn env(c: &mut Command, root: &str) {
    // PATH must be in the environment: the script's `PATH=` line only exports it when it already is.
    c.env_clear()
        .env("PATH", STUB_PATH_TAIL)
        .env("HOME", format!("{root}/home"))
        .env("LANG", "en_US.UTF-8")
        .env("TMPDIR", format!("{root}/state"))
        .stdin(Stdio::null());
}

fn tree(root: &str) -> String {
    let mut out = String::new();
    for base in [
        format!("{root}/resolver"),
        format!("{root}/home/Library/LaunchAgents"),
        format!("{root}/home/.local/share/claude-guard"),
    ] {
        let Ok(rd) = std::fs::read_dir(&base) else {
            out.push_str(&format!("{base}: none\n"));
            continue;
        };
        let mut names: Vec<String> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for n in names {
            let p = format!("{base}/{n}");
            let md = std::fs::symlink_metadata(&p).expect("md");
            if md.file_type().is_symlink() {
                out.push_str(&format!(
                    "{p} -> {}\n",
                    std::fs::read_link(&p).expect("link").display()
                ));
            } else if md.is_dir() {
                out.push_str(&format!("{p}/\n"));
            } else {
                let b = std::fs::read(&p).unwrap_or_default();
                out.push_str(&format!(
                    "{p} {:o} {:?}\n",
                    md.permissions().mode() & 0o777,
                    String::from_utf8_lossy(&b)
                ));
            }
        }
    }
    out
}

fn finish(o: std::process::Output, root: &str) -> Outcome {
    Outcome {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        log: std::fs::read_to_string(format!("{root}/state/log")).unwrap_or_default(),
        tree: tree(root),
    }
}

/// Run the bash reference on a built root.
pub fn run_bash(root: &str, command: &str) -> Outcome {
    let mut c = Command::new("/bin/bash");
    c.arg(format!("{root}/ref.sh"));
    if !command.is_empty() {
        c.arg(command);
    }
    env(&mut c, root);
    finish(c.output().expect("bash"), root)
}

/// Run `claude-guard dns` on a built root, with every external command on the stub PATH.
pub fn run_rust(root: &str, command: &str) -> Outcome {
    let stubs = format!("{root}/stubs");
    assert!(
        std::path::Path::new(&format!("{stubs}/sudo")).exists(),
        "no stubs: refusing to run"
    );
    let mut c = Command::new(BIN);
    c.args([
        "dns",
        "--resolver-dir",
        &format!("{root}/resolver"),
        "--real-home",
        &format!("{root}/realhome"),
        "--path",
        &format!("{stubs}:{STUB_PATH_TAIL}"),
        "--resolve-with",
        &format!("{stubs}/resolve"),
        "--no-sleep",
    ]);
    if !command.is_empty() {
        c.arg(command);
    }
    env(&mut c, root);
    finish(c.output().expect("claude-guard"), root)
}

/// Accepted differences, by name, each counted where it changed something.
#[derive(Default, Debug)]
pub struct Normalised {
    pub policy_error: usize,
}

/// Paths, random probe names, and the one accepted difference: Python's traceback for a policy file it
/// couldn't read against the port's one-line reason.
pub fn normalise(o: &Outcome, root: &str, n: &mut Normalised) -> Outcome {
    let probe = regex::Regex::new(r"probe-\d+").expect("re");
    let tb = regex::Regex::new(
        r"(?s)Traceback \(most recent call last\):\n.*?\n[A-Za-z_][\w.]*(?:Error|Exception)\b[^\n]*\n",
    )
    .expect("re");
    let ours = regex::Regex::new(r"(?m)^dns-blocklist: can't read [^\n]*\n").expect("re");
    let f = |s: &str, n: &mut Normalised| {
        let s = s.replace(root, "<root>");
        let s = probe.replace_all(&s, "probe-N").into_owned();
        let c1 = tb.find_iter(&s).count();
        let s = tb.replace_all(&s, "<policy error>\n").into_owned();
        let c2 = ours.find_iter(&s).count();
        let s = ours.replace_all(&s, "<policy error>\n").into_owned();
        n.policy_error += c1 + c2;
        s
    };
    Outcome {
        code: o.code,
        stdout: f(&o.stdout, n),
        stderr: f(&o.stderr, n),
        log: f(&o.log, n),
        tree: f(&o.tree, n),
    }
}
