//! Differential test: `claude-guard dns` against the team runbook's `dns-blocklist` bash script
//! (`tests/reference/dns-blocklist`) on generated fake Macs (`common::dnsbl`): policy files, resolver folders,
//! agent and launchd states, what `scutil --dns` lists and which names resolve. Each case runs the script twice
//! (its own two runs must agree once paths and random probe names are normalised), then the port, and compares
//! stdout, stderr, exit code, every stubbed command it ran and the files it left.
//!
//! Env (test only): CLAUDE_GUARD_DNSBL_CASES (default CLAUDE_GUARD_DIFF_CASES / 5, else 300),
//! CLAUDE_GUARD_DIFF_SEED, CLAUDE_GUARD_DIFF_WORKERS (default 2; pass "$(test-workers)").

mod common;
use common::dnsbl::*;
use common::*;
use std::collections::BTreeMap;

const COMMANDS: &[(&str, usize)] = &[
    ("list", 25),
    ("status", 20),
    ("install", 14),
    ("check", 15),
    ("remove", 7),
    ("agent", 6),
    ("diagnose", 6),
    ("help", 2),
    ("", 2),
    ("bogus", 2),
    ("lis", 1),
];

fn command(rng: &mut Rng) -> String {
    let total: usize = COMMANDS.iter().map(|c| c.1).sum();
    let mut k = rng.below(total);
    for (c, w) in COMMANDS {
        if k < *w {
            return c.to_string();
        }
        k -= w;
    }
    "list".into()
}

fn label(rng: &mut Rng) -> String {
    const PARTS: &[&str] = &[
        "a", "b", "evil", "x-y", "0", "9z", "-", "Up", "UPPER", "a_b", "é", "\u{212a}", "\u{130}",
        "ß", "1", "zz", "mDNS", "",
    ];
    (0..1 + rng.below(3)).map(|_| *rng.pick(PARTS)).collect()
}

fn name(rng: &mut Rng, builtin: &[String]) -> String {
    match rng.below(8) {
        0 => rng.pick(builtin).clone(),
        1 => rng.pick(builtin).to_uppercase(),
        2 => format!(".{}.", rng.pick(builtin)),
        _ => {
            let n = 1 + rng.below(3);
            let mut s: Vec<String> = (0..n).map(|_| label(rng)).collect();
            if rng.chance(20) {
                s.push(String::new());
            }
            let mut out = s.join(".");
            if rng.chance(10) {
                out = format!("..{out}");
            }
            out
        }
    }
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("json")
}

fn item(rng: &mut Rng, builtin: &[String]) -> String {
    match rng.below(14) {
        0 => rng
            .pick(&[
                "1.5", "-0.0", "1e16", "1.25e-7", "123.0", "1E400", "-1E400", "0.1",
            ])
            .to_string(),
        1 => rng.pick(&["1", "-3", "100000000000000000000"]).to_string(),
        2 => rng.pick(&["true", "false", "null"]).to_string(),
        3 => format!("[{}]", json_str(&name(rng, builtin))),
        4 => format!("{{{}: 1}}", json_str(&name(rng, builtin))),
        5 => "NaN".into(),
        _ => json_str(&name(rng, builtin)),
    }
}

fn policy(rng: &mut Rng, builtin: &[String]) -> Option<Option<Vec<u8>>> {
    let items = |rng: &mut Rng| -> String {
        let n = rng.below(6);
        (0..n)
            .map(|_| item(rng, builtin))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let text = match rng.below(20) {
        0..=5 => return None,
        6 => return Some(None),
        7 => format!("{{\"block_hosts\": {}}}", json_str(&name(rng, builtin))),
        8 => format!(
            "{{\"block_hosts\": {{{}: 1, {}: [2]}}}}",
            json_str(&name(rng, builtin)),
            json_str(&name(rng, builtin))
        ),
        9 => format!(
            "{{\"block_hosts\": {}}}",
            rng.pick(&["null", "3", "true", "1.5"])
        ),
        10 => rng
            .pick(&["[]", "\"x\"", "null", "3", "[\"a.example\"]"])
            .to_string(),
        11 => rng
            .pick(&[
                "{",
                "",
                "{\"block_hosts\": [",
                "not json",
                "{\"block_hosts\": [1,]}",
                "\u{feff}{}",
            ])
            .to_string(),
        12 => {
            let mut b = format!("{{\"block_hosts\": [{}]}}", items(rng)).into_bytes();
            b.insert(b.len() / 2, 0xff);
            return Some(Some(b));
        }
        13 => format!("{{\"allow_hosts\": [{}]}}", items(rng)),
        14 => format!(
            "{{\"block_hosts\": [{}], \"block_hosts\": [{}]}}",
            items(rng),
            items(rng)
        ),
        15 => format!("{}{{}}{}", "[".repeat(1100), "]".repeat(1100)),
        _ => format!("{{\"block_hosts\": [{}], \"warn_hosts\": []}}", items(rng)),
    };
    Some(Some(text.into_bytes()))
}

fn entries(rng: &mut Rng, builtin: &[String]) -> Option<Vec<(String, Entry)>> {
    if rng.chance(18) {
        return None;
    }
    let mut pool: Vec<String> = builtin.to_vec();
    pool.push(SELFTEST.into());
    pool.extend(RELAY.iter().map(|s| s.to_string()));
    let all = rng.chance(45);
    let mut out: Vec<(String, Entry)> = Vec::new();
    for n in &pool {
        if !all && !rng.chance(50) {
            continue;
        }
        out.push((n.clone(), content(rng)));
    }
    for _ in 0..rng.below(5) {
        let n = rng
            .pick(&[
                "zz.example",
                "a_b.example",
                "a-b.example",
                "A.example",
                "0.example",
                "_x.example",
                "b c.example",
                "Zed.example",
                "old.example",
            ])
            .to_string();
        if !out.iter().any(|(m, _)| *m == n) {
            out.push((n, content(rng)));
        }
    }
    if rng.chance(10) {
        out.push((
            ".dns-blocklist-left.example".into(),
            Entry::File(b"x".to_vec()),
        ));
    }
    Some(out)
}

fn content(rng: &mut Rng) -> Entry {
    let nl = "\n".repeat(rng.below(3));
    match rng.below(30) {
        0 => Entry::Dir,
        1 => Entry::Link(
            rng.pick(&["zz.example", "missing.example", "canarytokens.com"])
                .to_string(),
        ),
        2..=4 => Entry::File(format!("{OLD_BODY}{nl}").into_bytes()),
        5 => Entry::File(b"nameserver 1.1.1.1\n".to_vec()),
        6 => Entry::File(b"# dns-blocklist old\nnameserver 127.0.0.1\n".to_vec()),
        7 => Entry::File(Vec::new()),
        8 => Entry::File(format!("nameserver 127.0.0.1\n\0port 10053{nl}").into_bytes()),
        9 => Entry::File(format!("{BODY} \n").into_bytes()),
        _ => Entry::File(format!("{BODY}{nl}").into_bytes()),
    }
}

fn scenario(rng: &mut Rng, builtin: &[String]) -> Scenario {
    let mut sc = Scenario::new(&command(rng));
    sc.cg = match rng.below(25) {
        0 => Cg::Missing,
        1 => Cg::NotExecutable,
        _ => Cg::Binary,
    };
    sc.policy = policy(rng, builtin);
    sc.resolver = entries(rng, builtin);
    sc.plist = match rng.below(5) {
        0 => Plist::Absent,
        1 | 2 => Plist::OldPython,
        _ => Plist::New,
    };
    sc.old_responder = rng.chance(30);
    sc.agent_up = rng.chance(60);
    sc.up_after_bootstrap = rng.chance(75);
    sc.bootstrap_exit = if rng.chance(8) { 5 } else { 0 };
    let mut listed: Vec<String> = Vec::new();
    let mode = rng.below(5);
    for b in builtin {
        if mode == 0 || (mode < 3 && rng.chance(85)) || (mode == 3 && rng.chance(30)) {
            listed.push(if rng.chance(3) {
                b.replacen('.', "X", 1)
            } else {
                b.clone()
            });
        }
    }
    for i in 1..=4 {
        if rng.chance(40) {
            listed.push(format!("dnsdiag-{i}.invalid"));
        }
    }
    for _ in 0..rng.below(3) {
        listed.push(name(rng, builtin).to_lowercase());
    }
    sc.scutil = scutil_text(&listed);
    sc.scutil_exit = if rng.chance(5) { *rng.pick(&[1, 3]) } else { 0 };
    sc.dscache_exit = if rng.chance(5) { 1 } else { 0 };
    sc.resolves = Vec::new();
    if rng.chance(85) {
        sc.resolves.push("example.com".into());
    }
    if rng.chance(15) {
        sc.resolves.push("*.sslip.io".into());
    }
    if rng.chance(10) {
        sc.resolves.push(rng.pick(&RELAY).to_string());
    }
    if rng.chance(10) {
        sc.resolves.push(format!("probe-*.{}", rng.pick(builtin)));
    }
    if rng.chance(5) {
        sc.resolves.push(rng.pick(builtin).clone());
    }
    sc
}

fn first_diff(a: &Outcome, b: &Outcome) -> Option<String> {
    if a.code != b.code {
        return Some(format!("exit {} vs {}", a.code, b.code));
    }
    for (field, x, y) in [
        ("stdout", &a.stdout, &b.stdout),
        ("stderr", &a.stderr, &b.stderr),
        ("log", &a.log, &b.log),
        ("tree", &a.tree, &b.tree),
    ] {
        if x != y {
            let xl: Vec<&str> = x.lines().collect();
            let yl: Vec<&str> = y.lines().collect();
            let i = xl
                .iter()
                .zip(&yl)
                .position(|(p, q)| p != q)
                .unwrap_or(xl.len().min(yl.len()));
            return Some(format!(
                "{field} line {i}: {:?} vs {:?}",
                xl.get(i),
                yl.get(i)
            ));
        }
    }
    None
}

#[test]
fn rust_matches_bash() {
    let n: usize = std::env::var("CLAUDE_GUARD_DNSBL_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            std::env::var("CLAUDE_GUARD_DIFF_CASES")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .map(|c| (c / 5).max(20))
        })
        .unwrap_or(300);
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261127")
        .parse()
        .expect("seed");
    let workers: usize = env_or("CLAUDE_GUARD_DIFF_WORKERS", "2")
        .parse()
        .expect("workers");
    let builtin = builtin();
    let mut rng = Rng(seed | 1);
    let cases: Vec<Scenario> = (0..n).map(|_| scenario(&mut rng, &builtin)).collect();
    let base = fresh_dir("dnsbl-diff");
    let results = parallel(&cases, workers, |i, sc| {
        let (a1, a2, b) = (
            format!("{base}/{i}-a1"),
            format!("{base}/{i}-a2"),
            format!("{base}/{i}-b"),
        );
        for r in [&a1, &a2, &b] {
            build(r, sc);
        }
        let mut norm = Normalised::default();
        let x1 = normalise(&run_bash(&a1, &sc.command), &a1, &mut norm);
        let x2 = normalise(&run_bash(&a2, &sc.command), &a2, &mut Normalised::default());
        let y = normalise(&run_rust(&b, &sc.command), &b, &mut norm);
        // Accepted difference (Kenneth, 2026-11-27): check stops at a policy file it can't read, where the script
        // carried on with no domains. Where bash hit that, the port must print exactly the one reason and exit 1.
        // The same goes for a list it can't build because claude-guard itself is missing ("no block list").
        let list_error = x1
            .stderr
            .lines()
            .find(|l| *l == "<policy error>" || l.starts_with("dns-blocklist: no block list"))
            .map(str::to_string);
        let check_policy = sc.command == "check"
            && x1.stdout.starts_with("macOS has loaded 0 of 0")
            && list_error.is_some();
        let x1 = if check_policy {
            Outcome {
                code: 1,
                stdout: String::new(),
                stderr: format!("{}\n", list_error.clone().unwrap_or_default()),
                log: y.log.clone(),
                tree: y.tree.clone(),
            }
        } else {
            x1
        };
        for r in [&a1, &a2, &b] {
            let _ = std::fs::remove_dir_all(r);
        }
        // Named noise in the reference: its `loaded` counts with `printf | grep -q` under `set -o pipefail`, so when
        // grep exits at the first match while printf is still writing, printf's SIGPIPE fails the pipeline and a
        // loaded domain goes uncounted (seen under load). Its two runs can then disagree; the port, which counts
        // without that race, must match one of them.
        let d1 = first_diff(&x1, &y);
        let (diff, race) = match (check_policy, first_diff(&x1, &x2)) {
            (false, Some(n12)) => match (d1, first_diff(&x2, &y)) {
                (None, _) | (_, None) => (None, true),
                (Some(a), Some(_)) => (
                    Some(format!("{a} (and the reference's own runs differ: {n12})")),
                    false,
                ),
            },
            _ => (d1, false),
        };
        (x1.code, diff, norm.policy_error, check_policy, race)
    });
    let _ = std::fs::remove_dir_all(&base);
    let mut codes: BTreeMap<(String, i32), usize> = BTreeMap::new();
    let mut diffs = Vec::new();
    let mut normalised = 0;
    let mut check_policy = 0;
    let mut races = 0;
    for (i, (code, d, p, cp, race)) in results.iter().enumerate() {
        check_policy += usize::from(*cp);
        races += usize::from(*race);
        *codes.entry((cases[i].command.clone(), *code)).or_default() += 1;
        normalised += p;
        if let Some(m) = d {
            diffs.push(format!("case {i} ({}): {m}", cases[i].command));
        }
    }
    eprintln!(
        "dns blocklist differential: {n} cases, seed {seed}; outcomes {codes:?}; policy-error lines normalised: {normalised}; check stopped at a bad policy: {check_policy}; reference runs that disagreed (grep -q race), port matched one: {races}"
    );
    assert!(
        diffs.is_empty(),
        "{} of {n} cases differ:\n{}",
        diffs.len(),
        diffs
            .iter()
            .take(15)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        normalised > 0 || n < 100,
        "the policy-error normaliser changed nothing: drop it or add cases"
    );
    for c in ["list", "status", "install", "check"] {
        assert!(codes.keys().any(|(k, _)| k == c) || n < 100, "no {c} case");
    }
}
