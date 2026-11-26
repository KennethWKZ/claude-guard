//! What a wrapper runs, so every rule holds inside it (Rust only; the Python guard saw only the wrapper):
//! - argv wrappers with their options: `timeout -s KILL 9 CMD`, `nice -n 5 CMD`, `env -i X=1 CMD`, `xargs -I{} CMD`,
//!   `caffeinate -i`, `stdbuf -oL`, `setsid`, `ionice -c3`, `arch -arm64`, `chroot DIR`, `taskset MASK`, `chrt PRIO`,
//!   `unbuffer`, `sandbox-exec -p PROFILE`, `doas`, `pkexec`;
//! - remote and container commands: `ssh [opts] HOST CMD...` (joined with spaces, as ssh sends them),
//!   `docker|podman|nerdctl exec|run [opts] NAME CMD...` (`--entrypoint` included), `docker compose exec|run`,
//!   `docker-compose`, `kubectl|oc exec ... -- CMD...`;
//! - user switches: `su -c STRING`, `runuser -c STRING`, `runuser -u USER -- CMD...`, `sg GROUP -c STRING`;
//! - `find ... -exec|-execdir|-ok|-okdir CMD... {} +|;`, with `{}` read as each start path;
//! - string runners: `watch [opts] CMD...` (run by sh -c), `script -c STRING` and macOS `script FILE CMD...`,
//!   `flock FILE -c STRING` and `flock FILE CMD...`, `env -S STRING`;
//! - commands sed and awk run themselves (`sed 'e CMD'`, `s///e`, awk `system("CMD")`; see `filters::executed`).
//!
//! Each comes back as a command line for the nested check. `runs_stdin_through` says whether the wrapper hands its
//! stdin to a shell that runs it (`ssh HOST`, `docker exec -i C sh`, `timeout 9 bash`), for heredocs, here-strings
//! and pipes.

use super::{dash_letters_contain, runs_stdin, segments_with_seps};
use crate::pyfs;

/// One word of a command line: as is when it needs no quoting, else in single quotes.
pub(super) fn shell_quote(w: &str) -> String {
    if !w.is_empty()
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%^".contains(c))
    {
        w.to_string()
    } else {
        format!("'{}'", w.replace('\'', "'\\''"))
    }
}

pub(super) fn shell_join(words: &[String]) -> String {
    words
        .iter()
        .map(|w| shell_quote(w))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Index of the first argument that isn't an option (after a `--`, the one after it). `short_val`: letters whose
/// value is the rest of their cluster or the next argument; `long_val`: whole options (`--signal`, `-arch`) whose
/// value is the next argument (`--signal=KILL` is one argument anyway).
pub(super) fn skip_opts(args: &[String], short_val: &str, long_val: &[&str]) -> usize {
    let mut k = 0;
    while k < args.len() {
        let a = args[k].as_str();
        if a == "--" {
            return k + 1;
        }
        if !a.starts_with('-') || a == "-" {
            return k;
        }
        if long_val.contains(&a) {
            k += 2;
            continue;
        }
        if !a.starts_with("--") {
            let letters: Vec<char> = a[1..].chars().collect();
            if let Some(li) = letters.iter().position(|c| short_val.contains(*c)) {
                if li + 1 == letters.len() {
                    k += 1; // the value is the next argument
                }
            }
        }
        k += 1;
    }
    k
}

/// The value of option `-L` (in a cluster, attached or the next argument) or `--long VALUE` / `--long=VALUE`.
fn opt_value(args: &[String], letter: char, long: &str) -> Option<(usize, String)> {
    for (k, a) in args.iter().enumerate() {
        if a == "--" {
            return None;
        }
        if !long.is_empty() {
            if a == long {
                return args.get(k + 1).map(|v| (k + 1, v.clone()));
            }
            if let Some(v) = a.strip_prefix(&format!("{long}=")) {
                return Some((k, v.to_string()));
            }
        }
        if a.starts_with('-') && !a.starts_with("--") && dash_letters_contain(a, &[letter]) {
            let at = a.find(letter).unwrap_or(a.len());
            let attached = &a[at + 1..];
            return if attached.is_empty() {
                args.get(k + 1).map(|v| (k + 1, v.clone()))
            } else {
                Some((k, attached.to_string()))
            };
        }
    }
    None
}

/// (name, letters with a value, whole options with a value, positional arguments before the command)
const ARGV_WRAPPERS: &[(&str, &str, &[&str], usize)] = &[
    ("timeout", "sk", &["--signal", "--kill-after"], 1),
    ("gtimeout", "sk", &["--signal", "--kill-after"], 1),
    ("caffeinate", "tw", &[], 0),
    ("stdbuf", "ioe", &["--input", "--output", "--error"], 0),
    ("arch", "", &["-arch", "-e", "-d"], 0),
    ("nice", "n", &["--adjustment"], 0),
    ("env", "uCSP", &["--unset", "--chdir", "--split-string"], 0),
    (
        "xargs",
        "InPLsdEa",
        &[
            "--max-args",
            "--max-procs",
            "--max-lines",
            "--max-chars",
            "--delimiter",
            "--eof",
            "--arg-file",
            "--replace",
        ],
        0,
    ),
    ("nohup", "", &[], 0),
    ("time", "", &[], 0),
    ("command", "", &[], 0),
    ("builtin", "", &[], 0),
    ("exec", "a", &[], 0),
    ("setsid", "", &[], 0),
    ("ionice", "cnp", &["--class", "--classdata", "--pid"], 0),
    ("chrt", "", &[], 1),
    ("taskset", "", &[], 1),
    ("unbuffer", "", &[], 0),
    ("chroot", "", &["--userspec", "--groups"], 1),
    ("sandbox-exec", "fnpD", &[], 0),
    ("doas", "uC", &[], 0),
    ("pkexec", "", &["--user"], 0),
];

/// The command an argv wrapper runs (`timeout 9 sudo ls` -> `sudo ls`), if any.
pub(super) fn argv_wrapper_inner(seg: &[String]) -> Option<Vec<String>> {
    let verb = pyfs::basename(&seg[0]);
    let &(_, short_val, long_val, positional) = ARGV_WRAPPERS.iter().find(|w| w.0 == verb)?;
    let args = &seg[1..];
    // `command -v X` only looks X up; `env -S STRING` is a string runner (`string_runs`).
    if verb == "command" && args.iter().any(|a| a == "-v" || a == "-V") {
        return None;
    }
    if verb == "env" && opt_value(args, 'S', "--split-string").is_some() {
        return None;
    }
    let mut k = skip_opts(args, short_val, long_val) + positional;
    if verb == "env" {
        while args.get(k).is_some_and(|a| super::is_assignment(a)) {
            k += 1;
        }
    }
    let inner = args.get(k..)?.to_vec();
    (!inner.is_empty()).then_some(inner)
}

const SSH_VALUE: &str = "BbcDEeFIiJLlmOoPpQRSWw";

/// `ssh [opts] HOST CMD...`: Some(CMD words) (empty: a remote shell reading stdin).
fn ssh_remote(seg: &[String]) -> Option<Vec<String>> {
    if pyfs::basename(&seg[0]) != "ssh" {
        return None;
    }
    let args = &seg[1..];
    let k = skip_opts(args, SSH_VALUE, &[]);
    args.get(k)?;
    Some(args[k + 1..].to_vec())
}

const DOCKER_GLOBAL_VALUE: (&str, &[&str]) =
    ("cHl", &["--context", "--host", "--config", "--log-level"]);
const COMPOSE_GLOBAL_VALUE: (&str, &[&str]) = (
    "fp",
    &[
        "--file",
        "--project-name",
        "--env-file",
        "--profile",
        "--project-directory",
        "--ansi",
        "--progress",
        "--parallel",
    ],
);
const EXEC_VALUE: (&str, &[&str]) = (
    "ewu",
    &[
        "--env",
        "--env-file",
        "--user",
        "--workdir",
        "--detach-keys",
        "--index",
    ],
);
const RUN_VALUE: (&str, &[&str]) = (
    "acehlmpuvw",
    &[
        "--add-host",
        "--annotation",
        "--attach",
        "--blkio-weight",
        "--cap-add",
        "--cap-drop",
        "--cgroup-parent",
        "--cgroupns",
        "--cidfile",
        "--cpu-period",
        "--cpu-quota",
        "--cpu-shares",
        "--cpus",
        "--cpuset-cpus",
        "--cpuset-mems",
        "--device",
        "--dns",
        "--dns-option",
        "--dns-search",
        "--domainname",
        "--entrypoint",
        "--env",
        "--env-file",
        "--expose",
        "--gpus",
        "--group-add",
        "--health-cmd",
        "--health-interval",
        "--health-retries",
        "--health-start-period",
        "--health-timeout",
        "--hostname",
        "--ip",
        "--ip6",
        "--ipc",
        "--isolation",
        "--label",
        "--label-file",
        "--link",
        "--log-driver",
        "--log-opt",
        "--mac-address",
        "--memory",
        "--memory-reservation",
        "--memory-swap",
        "--mount",
        "--name",
        "--network",
        "--network-alias",
        "--pid",
        "--platform",
        "--publish",
        "--pull",
        "--restart",
        "--runtime",
        "--security-opt",
        "--shm-size",
        "--stop-signal",
        "--stop-timeout",
        "--storage-opt",
        "--sysctl",
        "--tmpfs",
        "--ulimit",
        "--user",
        "--userns",
        "--uts",
        "--volume",
        "--volumes-from",
        "--workdir",
    ],
);

/// The command a container runs: `docker exec -it C CMD...`, `docker run [opts] IMAGE CMD...` (with
/// `--entrypoint`), `docker compose exec|run SVC CMD...`, `kubectl exec POD -- CMD...`.
fn container_inner(seg: &[String]) -> Option<Vec<String>> {
    let verb = pyfs::basename(&seg[0]);
    let args = &seg[1..];
    match verb {
        "kubectl" | "oc" => {
            let i = args.iter().position(|a| a == "exec")?;
            let d = args[i..].iter().position(|a| a == "--")?;
            let inner = args[i + d + 1..].to_vec();
            (!inner.is_empty()).then_some(inner)
        }
        "docker" | "podman" | "nerdctl" | "docker-compose" => {
            let mut k = if verb == "docker-compose" {
                skip_opts(args, COMPOSE_GLOBAL_VALUE.0, COMPOSE_GLOBAL_VALUE.1)
            } else {
                skip_opts(args, DOCKER_GLOBAL_VALUE.0, DOCKER_GLOBAL_VALUE.1)
            };
            if verb != "docker-compose" && args.get(k)? == "compose" {
                k += 1;
                k += skip_opts(&args[k..], COMPOSE_GLOBAL_VALUE.0, COMPOSE_GLOBAL_VALUE.1);
            }
            if args.get(k)? == "container" {
                k += 1;
            }
            let sub = args.get(k)?.as_str();
            let (short_val, long_val) = match sub {
                "exec" => EXEC_VALUE,
                "run" => RUN_VALUE,
                _ => return None,
            };
            let rest = &args[k + 1..];
            let j = skip_opts(rest, short_val, long_val);
            rest.get(j)?; // container, image or service
            let mut inner = rest[j + 1..].to_vec();
            if sub == "run" {
                if let Some((_, ep)) = opt_value(&rest[..j], '\0', "--entrypoint") {
                    inner.insert(0, ep);
                }
            }
            (!inner.is_empty()).then_some(inner)
        }
        _ => None,
    }
}

/// `find ... -exec CMD... {} +`: each command, `{}` read as each start path.
fn find_execs(seg: &[String]) -> Vec<String> {
    if pyfs::basename(&seg[0]) != "find" {
        return Vec::new();
    }
    let args = &seg[1..];
    let starts: Vec<&String> = args
        .iter()
        .take_while(|a| !a.starts_with('-') && *a != "(" && *a != "!")
        .collect();
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if !["-exec", "-execdir", "-ok", "-okdir"].contains(&a.as_str()) {
            continue;
        }
        let words: Vec<String> = args[i + 1..]
            .iter()
            .take_while(|w| *w != "+" && *w != ";")
            .cloned()
            .collect();
        if words.is_empty() {
            continue;
        }
        if starts.is_empty() || !words.iter().any(|w| w.contains("{}")) {
            out.push(shell_join(&words));
            continue;
        }
        for s in &starts {
            let w: Vec<String> = words.iter().map(|w| w.replace("{}", s)).collect();
            out.push(shell_join(&w));
        }
    }
    out
}

/// Command strings a user switch or string runner runs, and the argv of `runuser -u`, macOS `script`, `flock`.
fn string_runs(seg: &[String]) -> Vec<String> {
    let verb = pyfs::basename(&seg[0]);
    let args = &seg[1..];
    let mut out = Vec::new();
    match verb {
        "su" | "runuser" => {
            if let Some((_, v)) = opt_value(args, 'c', "--command") {
                out.push(v);
            } else if verb == "runuser" {
                let k = skip_opts(args, "ugGw", &["--user", "--group", "--supp-group"]);
                if args.len() > k {
                    out.push(shell_join(&args[k..]));
                }
            }
        }
        "sg" => {
            let rest: Vec<&String> = args.iter().filter(|a| *a != "-").collect();
            match rest.as_slice() {
                [_group, c, cmd, ..] if c.as_str() == "-c" => out.push((*cmd).clone()),
                [_group, cmd @ ..] if !cmd.is_empty() => {
                    out.push(cmd.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "))
                }
                _ => {}
            }
        }
        "watch" => {
            let k = skip_opts(args, "n", &["--interval"]);
            if args.len() > k {
                out.push(args[k..].join(" "));
            }
        }
        "script" => {
            if let Some((_, v)) = opt_value(args, 'c', "--command") {
                out.push(v);
            } else {
                let k = skip_opts(args, "FtT", &[]);
                if args.len() > k + 1 {
                    out.push(shell_join(&args[k + 1..]));
                }
            }
        }
        "flock" => {
            if let Some((_, v)) = opt_value(args, 'c', "--command") {
                out.push(v);
            } else {
                let k = skip_opts(args, "wE", &["--timeout", "--conflict-exit-code"]);
                if args.len() > k + 1 {
                    out.push(shell_join(&args[k + 1..]));
                }
            }
        }
        "env" => {
            if let Some((at, v)) = opt_value(args, 'S', "--split-string") {
                let mut line = v;
                for a in &args[at + 1..] {
                    line.push(' ');
                    line.push_str(&shell_quote(a));
                }
                out.push(line);
            }
        }
        _ => {}
    }
    out
}

/// Every command line a wrapper in this simple command runs.
pub(super) fn wrapped_commands(seg: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(inner) = argv_wrapper_inner(seg) {
        out.push(shell_join(&inner));
    }
    if let Some(cmd) = ssh_remote(seg) {
        if !cmd.is_empty() {
            out.push(cmd.join(" "));
        }
    }
    if let Some(inner) = container_inner(seg) {
        out.push(shell_join(&inner));
    }
    out.extend(find_execs(seg));
    out.extend(string_runs(seg));
    // sed `e COMMAND` / `s///e`, awk `system(...)`: with no known input, from the program alone.
    out.extend(super::filters::executed(seg, None));
    out
}

/// True if the wrapper hands its stdin to a shell that runs it: `ssh HOST` (no command, or `bash -s`),
/// `docker exec -i C sh`, `kubectl exec -i P -- bash`, `timeout 9 bash`, macOS `script -q FILE` with no command.
pub(super) fn runs_stdin_through(seg: &[String]) -> bool {
    if let Some(cmd) = ssh_remote(seg) {
        if cmd.is_empty() {
            return true;
        }
        let Ok(tokens) = super::lex_lines(&cmd.join(" ")) else {
            return false;
        };
        return segments_with_seps(tokens)
            .first()
            .is_some_and(|(s, _)| runs_stdin(s));
    }
    if let Some(inner) = container_inner(seg).or_else(|| argv_wrapper_inner(seg)) {
        return runs_stdin(&inner);
    }
    if pyfs::basename(&seg[0]) == "script" {
        let args = &seg[1..];
        return opt_value(args, 'c', "--command").is_none()
            && args.len() == skip_opts(args, "FtT", &[]) + 1;
    }
    false
}
