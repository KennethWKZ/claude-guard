//! claude-guard: Claude Code hooks in Rust, one binary with one subcommand per hook.
//!
//!   claude-guard bash [--crash-log F]  PreToolUse Bash guard (was guard-bash.py + block-pip.sh)
//!   claude-guard read     PreToolUse Read guard (was guard-read-keys.py)
//!   claude-guard husky    PostToolUse Bash|EnterWorktree and SessionStart hook (was husky-worktree-hooks.py)
//!   claude-guard prompt [--strict] [--terms F] [--log F]
//!                         UserPromptSubmit guard (was guard-prompt.py; --strict for GraphMind's prompt hook)
//!   claude-guard web pre|post [--policy F] [--log F] [--guard F] [--terms F]
//!                         PreToolUse/PostToolUse web guard (was web-guard.sh + web-guard.py)
//!   claude-guard session-name   UserPromptSubmit/SessionStart naming hook (was session-name-from-title.sh)
//!   claude-guard repo pre-bash [--crash-log F]
//!                         PreToolUse Bash guards a repo configures in .claude/repo-guard.json (was a repo's Python hooks)
//!   claude-guard repo pre-bash --shadow --reference F [--reference F ...] [--log F]
//!                         shadow mode against the repo's Python hooks, given in its settings' order
//!   claude-guard repo post-read [--crash-log F]
//!                         PostToolUse Read|Bash: tells a session a file it read was changed by someone else since
//!   claude-guard dns-nxdomain [--port N] [--log F]
//!                         launchd daemon: NXDOMAIN for every DNS query on 127.0.0.1:10053 (was dns-nxdomain.py)
//!   claude-guard <hook> --shadow [pre|post] [--reference F] [--pip-reference F] [--terms F] [--policy F] [--log F]
//!                         run next to the old hook: never blocks or copies, logs agreement
//!                         (starts `<hook> --shadow-compare` detached and returns at once)
//!   claude-guard --version
//!
//! Overrides are arguments, never environment variables: a repo's settings `env` reaches hooks and could
//! switch a check off.

mod bash;
mod dns;
mod hookio;
mod husky;
mod jqlite;
mod logfile;
mod prompt;
mod pwd;
mod pyfs;
mod pyre;
mod read;
mod repo;
mod repo_read;
mod repo_tree;
mod session_name;
mod shadow;
mod shell_words;
mod shlex;
mod web;

use std::time::{SystemTime, UNIX_EPOCH};

/// UTC time as `YYYY-MM-DDTHH:MM:SSZ` (no date crate).
pub fn now_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".into())
}

fn usage() -> ! {
    eprintln!(
        "usage: claude-guard bash [--crash-log F] | read | husky | prompt [--strict] [--terms F] [--log F] | web pre|post [--policy F] [--log F] [--guard F] [--terms F] | web --list-hosts | session-name | repo pre-bash [--crash-log F] | repo pre-bash --shadow --reference F [--reference F ...] [--log F] | repo post-read [--crash-log F] | dns-nxdomain [--port N] [--log F] | <hook> --shadow [pre|post] [--reference F] [--pip-reference F] [--terms F] [--policy F] [--log F] | --version"
    );
    std::process::exit(64);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        usage()
    };
    if cmd == "dns-nxdomain" {
        std::process::exit(dns::serve(&args[1..]));
    }
    if cmd == "--version" {
        println!(
            "claude-guard {} ({})",
            env!("CARGO_PKG_VERSION"),
            option_env!("CLAUDE_GUARD_COMMIT").unwrap_or("unknown commit")
        );
        return;
    }
    if cmd == "repo"
        && matches!(
            args.get(2).map(String::as_str),
            Some("--shadow" | "--shadow-compare")
        )
    {
        // `repo pre-bash --shadow --reference <hook> [--reference <hook> ...] [--log F]`.
        if args[1] != "pre-bash" {
            usage();
        }
        let mut opts = shadow::Options {
            hook: "repo".into(),
            reference: String::new(),
            references: Vec::new(),
            pip_reference: String::new(),
            terms: None,
            policy: None,
            web_mode: None,
            log: format!("{}/.local/state/claude-guard/shadow.log", home()),
        };
        let mut it = args[3..].iter();
        while let Some(a) = it.next() {
            let v = it.next().cloned().unwrap_or_else(|| usage());
            match a.as_str() {
                "--reference" => opts.references.push(v),
                "--log" => opts.log = v,
                _ => usage(),
            }
        }
        if opts.references.is_empty() {
            usage();
        }
        let compare = args[2] == "--shadow-compare";
        let _ = std::panic::catch_unwind(|| {
            if compare {
                shadow::compare(&opts)
            } else {
                shadow::start(&opts)
            }
        });
        std::process::exit(0);
    }
    if cmd == "repo" && args.get(1).map(String::as_str) == Some("post-read") {
        // `repo post-read [--crash-log <file>]`: the stale-read notice; always exits 0.
        let crash_log = match &args[2..] {
            [] => None,
            [flag, path] if flag == "--crash-log" => Some(path.clone()),
            _ => usage(),
        };
        std::process::exit(repo_read::main(crash_log.as_deref()));
    }
    if cmd == "repo" {
        // `repo pre-bash [--crash-log <file>]`: the log override is for tests; the default comes from the config.
        let crash_log = match &args[1..] {
            [m] if m == "pre-bash" => None,
            [m, flag, path] if m == "pre-bash" && flag == "--crash-log" => Some(path.clone()),
            _ => usage(),
        };
        let input = hookio::read_stdin();
        std::process::exit(repo::emit(&repo::decide(&input, crash_log.as_deref())));
    }
    if cmd == "web" && args[1..] == ["--list-hosts"] {
        // The built-in block list for dns-blocklist; reads no stdin.
        print!("{}", web::list_hosts());
        return;
    }
    if !["bash", "read", "husky", "prompt", "web", "session-name"].contains(&cmd) {
        usage();
    }
    let rest = &args[1..];
    let mode = rest.first().map(String::as_str);
    if mode == Some("--shadow") || mode == Some("--shadow-compare") {
        let h = home();
        let mut opts = shadow::Options {
            hook: cmd.to_string(),
            references: Vec::new(),
            reference: match cmd {
                "bash" => format!("{h}/.claude/hooks/guard-bash.py"),
                "read" => format!("{h}/.claude/hooks/guard-read-keys.py"),
                "prompt" => format!("{h}/.claude/hooks/guard-prompt.py"),
                "web" => format!("{h}/.claude/hooks/web-guard.sh"),
                "session-name" => format!("{h}/.claude/hooks/session-name-from-title.sh"),
                _ => format!("{h}/.claude/hooks/husky-worktree-hooks.py"),
            },
            pip_reference: format!("{h}/.claude/hooks/block-pip.sh"),
            terms: None,
            policy: None,
            web_mode: None,
            log: format!("{h}/.local/state/claude-guard/shadow.log"),
        };
        let mut flags = &rest[1..];
        if cmd == "web" {
            // `web --shadow pre|post ...`: the mode comes first.
            match flags.first().map(String::as_str) {
                Some(m @ ("pre" | "post")) => opts.web_mode = Some(m.to_string()),
                _ => usage(),
            }
            flags = &flags[1..];
        }
        let mut it = flags.iter();
        while let Some(a) = it.next() {
            let v = it.next().cloned().unwrap_or_else(|| usage());
            match a.as_str() {
                "--reference" => opts.reference = v,
                "--pip-reference" => opts.pip_reference = v,
                "--terms" if cmd == "prompt" || cmd == "web" => opts.terms = Some(v),
                "--policy" if cmd == "web" => opts.policy = Some(v),
                "--log" => opts.log = v,
                _ => usage(),
            }
        }
        // Shadow never blocks and never fails the hook: whatever happens, exit 0 with no output.
        let _ = std::panic::catch_unwind(|| {
            if mode == Some("--shadow") {
                shadow::start(&opts)
            } else {
                shadow::compare(&opts)
            }
        });
        std::process::exit(0);
    }
    if cmd == "session-name" && rest.is_empty() {
        let input = hookio::read_stdin();
        let line = session_name::decide(&input, &session_name::registry_dir());
        std::process::exit(session_name::emit(&line));
    }
    if cmd == "web" {
        let opts = web::Options::parse(rest);
        let input = hookio::read_stdin();
        std::process::exit(web::emit(&web::decide(&input, &opts), &opts));
    }
    if cmd == "prompt" {
        // guard-prompt.py's own options; anything after an unknown argument is ignored, as Python did.
        let opts = prompt::Options::parse(rest);
        let input = hookio::read_stdin();
        std::process::exit(prompt::emit(&prompt::decide(&input, &opts)));
    }
    // `bash --crash-log <file>`: where a crash is logged (tests; the default is under ~/.local/state).
    let mut crash_log = bash::default_crash_log();
    match rest {
        [] => {}
        [flag, path] if cmd == "bash" && flag == "--crash-log" => crash_log = path.clone(),
        _ => usage(),
    }
    let input = hookio::read_stdin();
    let code = match cmd {
        "bash" => bash::emit(&bash::decide(&input, &crash_log)),
        "read" => read::emit(&read::decide(&input)),
        _ => husky::emit(&husky::decide(&input, false)),
    };
    std::process::exit(code);
}
