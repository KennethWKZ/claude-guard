//! Differential test: `claude-guard repo post-read` against a repo's Python stale-read hook. Each scenario builds
//! twin temp repos (identical files and mtimes; names from the repo's config) and runs the same steps on both:
//! hook calls (Read, Bash, write and unknown tools, broken input), file changes, deletions and permission changes,
//! the Edit hook's own-write records (the Python `record_own_write` on both, as the two hooks share the records),
//! corrupt records and old files for the 7-day tidy. After every step stdout, the crash flag and every byte of the
//! record folder must match. The Python side runs in-process (`tests/reference_driver.py repo-read`); some
//! scenarios are replayed with real `python3 -I` runs to check the driver.
//! Env (test only): CLAUDE_GUARD_REF_REPO_READ (the hook) and CLAUDE_GUARD_REF_REPO_CONFIG (the repo's
//! `.claude/repo-guard.json`); skipped when either is unset. CLAUDE_GUARD_DIFF_CASES (scenarios, default 250),
//! CLAUDE_GUARD_DIFF_SEED.

mod common;
use common::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, SystemTime};

const STEPS: usize = 24;

/// The in-process Python hook.
struct Driver {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
}

impl Driver {
    fn new(reference: &str) -> Driver {
        let driver = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference_driver.py");
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", driver, "repo-read", reference])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Driver { child, stdin, out }
    }

    fn ask(&mut self, req: Value) -> (String, bool) {
        writeln!(self.stdin, "{req}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.out.read_line(&mut line).unwrap();
        let v: Value =
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("driver said {line:?}: {e}"));
        (
            v["stdout"].as_str().unwrap_or("").to_string(),
            v["crash"].as_bool().unwrap(),
        )
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Names the fixture takes from the repo's config.
struct Names {
    tracked: Vec<String>,
    untracked: String,
    generated: Vec<String>,
    record_dir: String,
    suffixes: Vec<String>,
    runner: String,
    entity: String,
    schema_dir: String,
    folder_key: String,
    runner_reads: Vec<String>,
}

impl Names {
    fn from(cfg: &Value) -> Names {
        let p = &cfg["post_read"];
        let list = |k: &str| -> Vec<String> {
            p[k].as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect()
        };
        let s = |a: &str, b: &str| p[a][b].as_str().unwrap().to_string();
        Names {
            tracked: list("tracked_dirs"),
            untracked: list("untracked_dirs")[0].clone(),
            generated: list("generated"),
            record_dir: p["record_dir"].as_str().unwrap().to_string(),
            suffixes: list("layer_suffixes"),
            runner: s("entity_command", "runner"),
            entity: s("entity_command", "command"),
            schema_dir: s("entity_command", "schema_dir"),
            folder_key: s("entity_command", "folder_key"),
            runner_reads: list("read_only_runner_commands"),
        }
    }

    /// Repo-relative files of the fixture.
    fn files(&self) -> Vec<String> {
        let (t0, t1, t2) = (
            &self.tracked[0],
            &self.tracked[1 % self.tracked.len()],
            self.tracked.last().unwrap(),
        );
        let mut f = vec![
            format!("{t0}/people/ana.md"),
            format!("{t0}/people/ana-2.md"),
            format!("{t0}/people/ben.md"),
            format!("{t0}/people/zoë.md"),
            format!("{t0}/people/with space.md"),
            format!("{t0}/teams/core.md"),
            format!("{t0}/standards/rules.md"),
            format!("{t1}/x.yaml"),
            format!("{t1}/y.json"),
            format!("{t2}/2026-01-01/cycle.yaml"),
            format!("{}/2026.md", self.untracked),
            "other/o.md".to_string(),
            "notes/n.md".to_string(),
        ];
        for s in &self.suffixes[1..] {
            f.push(format!("{t0}/people/ben{s}"));
        }
        f.extend(self.generated.iter().cloned());
        f
    }
}

struct Scenario<'a> {
    names: &'a Names,
    roots: Vec<String>,
    clock: u64,
}

fn set_mtime(path: &str, secs: u64) {
    if let Ok(f) = fs::File::options().write(true).open(path) {
        let _ = f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
    }
}

impl Scenario<'_> {
    fn each(&self, f: impl Fn(&str)) {
        for r in &self.roots {
            f(r);
        }
    }

    fn write(&mut self, rel: &str, text: &str) {
        self.clock += 7;
        let t = self.clock;
        self.each(|r| {
            let p = format!("{r}/{rel}");
            if let Some(dir) = std::path::Path::new(&p).parent() {
                let _ = fs::create_dir_all(dir);
            }
            if fs::write(&p, text).is_ok() {
                set_mtime(&p, t);
            }
        });
    }

    fn build(&mut self, config: &str) {
        let n = self.names;
        let (k, t0) = (&n.folder_key, &n.tracked[0]);
        self.each(|r| {
            fs::create_dir_all(format!("{r}/.claude")).unwrap();
            fs::write(format!("{r}/.claude/repo-guard.json"), config).unwrap();
            let s = format!("{r}/{}", n.schema_dir);
            fs::create_dir_all(&s).unwrap();
            fs::write(
                format!("{s}/person.yaml"),
                format!("title: x\n{k}: {t0}/people\n"),
            )
            .unwrap();
            fs::write(
                format!("{s}/team.yaml"),
                format!("{k}:\n  {t0}/teams extra\r\n"),
            )
            .unwrap();
            fs::write(format!("{s}/none.yaml"), "title: x\n").unwrap();
            fs::write(format!("{s}/abs.yaml"), format!("{k}: /nonexistent-abs\n")).unwrap();
            fs::write(format!("{s}/bad.yaml"), [0xff, 0xfe, b'\n']).unwrap();
            fs::create_dir_all(format!("{s}/dir.yaml")).unwrap();
        });
        for f in n.files() {
            self.write(&f, &format!("{f}\n"));
        }
        let t0 = t0.clone();
        self.each(|r| {
            let _ = std::os::unix::fs::symlink(
                format!("{r}/{t0}/people/ana.md"),
                format!("{r}/{t0}/people/link.md"),
            );
            let _ = std::os::unix::fs::symlink(format!("{r}/{t0}"), format!("{r}/tree-link"));
            let _ = fs::create_dir_all(format!("{r}/{t0}/people/folder.md"));
        });
    }

    /// Every file under the record folder: name -> bytes (lock files are empty; a leftover tmp would show).
    fn records(&self, root: &str) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        let dir = format!("{root}/{}", self.names.record_dir);
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let bytes = fs::read(e.path()).unwrap_or_else(|_| b"<unreadable>".to_vec());
                out.insert(name, bytes);
            }
        } else {
            out.insert("<no folder>".into(), Vec::new());
        }
        out
    }
}

/// A file argument: tracked, untracked, missing, a folder, a glob, quoted, through `~`, `$VAR` or a link.
fn file_word(rng: &mut Rng, n: &Names, files: &[String]) -> String {
    let t0 = &n.tracked[0];
    let f = rng.pick(files).clone();
    match rng.below(20) {
        0 => format!("{t0}/people/a*.md"),
        1 => format!("{t0}/people/*.md"),
        2 => "*.md".into(),
        3 => format!("{t0}/people/[ab]*.md"),
        4 => format!("{t0}/people/nope.md"),
        5 => format!("{t0}/people"),
        6 => format!("'{f}'"),
        7 => format!("\"$CLAUDE_PROJECT_DIR/{f}\""),
        8 => "$NOPE/x.md".into(),
        9 => "tree-link/people/ben.md".to_string(),
        10 => format!("{t0}/people/link.md"),
        11 => format!("./{t0}/../{f}"),
        12 if rng.chance(25) => format!("{t0}/people/[i-0].md"),
        13 => format!("{t0}/people/folder.md"),
        14 => "~/nope.md".into(),
        _ if f.contains(' ') => format!("\"{f}\""),
        _ => f,
    }
}

fn segment(rng: &mut Rng, n: &Names, files: &[String]) -> String {
    let t0 = &n.tracked[0];
    let fw = |rng: &mut Rng| file_word(rng, n, files);
    let s = match rng.below(14) {
        0..=4 => {
            let prog = *rng.pick(&[
                "cat",
                "head -n 3",
                "tail -c 5",
                "less",
                "more",
                "bat",
                "nl",
                "rtk read",
                "sed -n 1p",
                "sed -n",
                "sed -n -e 1p",
                "sed -ne 1p",
                "sed --quiet -f p",
                "sed -i s/a/b/",
                "sed 1p",
                "awk 1",
                "awk -F: 1",
                "awk -f prog",
                "gawk -i inplace 1",
                "awk -iinplace 1",
                "jq .",
                "jq --arg a b .",
                "jq -f f",
                "jq --slurpfile a b .",
                "yq e .",
                "yq eval-all .",
                "yq -i .a",
                "yq --from-file p",
                "yq -o json .",
                "diff -u",
                "cmp",
                "rg x",
                "rg -e x",
                "rg -g '*.md' x",
                "grep -n x",
                "egrep x",
                "fgrep -f p",
                "grep -r x",
                "head -",
                "cat -",
            ]);
            let k = 1 + rng.below(3);
            let args: Vec<String> = (0..k).map(|_| fw(rng)).collect();
            format!("{prog} {}", args.join(" "))
        }
        5 => format!(
            "cd {}",
            rng.pick(&[
                t0.as_str(),
                &format!("{t0}/people"),
                "..",
                "~",
                "",
                "$NOPE",
                "nope",
                "-",
                "tree-link",
                "$CLAUDE_PROJECT_DIR",
            ])
        ),
        6 => {
            let ro = rng.pick(&n.runner_reads).clone();
            rng.pick(&[
                "ls -la".to_string(),
                "wc -l x".into(),
                "git status --short".into(),
                "git log -1".into(),
                "git -C x status".into(),
                "git commit -m x".into(),
                "find . -name x".into(),
                "find . -delete".into(),
                "find . -exec ls {} +".into(),
                "echo hi".into(),
                format!("{} --silent {ro}", n.runner),
                format!("{} run {ro}", n.runner),
                format!("{} test", n.runner),
                "true".into(),
                "[ -f x ]".into(),
            ])
            .clone()
        }
        7 => {
            let kind = rng.pick(&[
                "person/ben",
                "person/ana",
                "team/core",
                "bad/x",
                "none/x",
                "person",
                "nokind/x",
                "abs/x",
                "person//etc/x",
                "dir/x",
                "person/../people/ben",
            ]);
            format!(
                "{} {}{} {kind}",
                n.runner,
                rng.pick(&["", "--silent ", "run ", "-s run "]),
                n.entity
            )
        }
        8 => {
            let (fa, fb) = (fw(rng), fw(rng));
            let id = rng.pick(&["ana", "ana-2", "ben", "zoë", "core", "x", "rules"]);
            rng.pick(&[
                format!("node x.js {id}"),
                "python3 -c pass".into(),
                format!("touch {}", fa),
                "rm -f nothing".into(),
                format!("{} observe person/{id}", n.runner),
                format!("./fix {}", fb),
                format!("echo {id}_old"),
                format!("echo x{id}"),
            ])
            .clone()
        }
        9 => format!("cat <<EOF\n{}\nEOF", fw(rng)),
        10 => format!("cat <<'X' | sh\nrm {}\nX", fw(rng)),
        11 => format!("echo $(cat {})", fw(rng)),
        12 => format!("cat '{}", fw(rng)),
        _ => format!("{} -- {}", rng.pick(&["cat", "rg x", "diff"]), fw(rng)),
    };
    let wrapped = match rng.below(10) {
        0 => format!("sudo {s}"),
        1 => format!("env A=1 {s}"),
        2 => format!("FOO=bar nice {s}"),
        3 => format!("command time {s}"),
        _ => s,
    };
    let redirect = match rng.below(12) {
        0 => " > /dev/null",
        1 => " 2>&1",
        2 => " >&2",
        3 => " > out.txt",
        4 => " >",
        5 => " < in.txt",
        6 => " 2> err",
        7 => " # cat notes",
        8 => " >> 1",
        9 => " > &",
        10 => " >& 1",
        _ => "",
    };
    format!("{wrapped}{redirect}")
}

fn command(rng: &mut Rng, n: &Names, files: &[String]) -> String {
    let k = 1 + rng.below(3);
    let mut out = segment(rng, n, files);
    for _ in 1..k {
        out.push_str(rng.pick(&[" && ", "; ", " | ", " || ", "\n", " & ", " |& "]));
        out.push_str(&segment(rng, n, files));
    }
    match rng.below(80) {
        0 => out.push('\u{1c}'),
        1 => out = out.replacen(' ', "\u{1f}", 1),
        2 => out.push_str(" \u{0}x"),
        3 | 4 => out = format!("({out})"),
        _ => {}
    }
    out
}

/// One step: a hook call (the input, with @R@ for the repo root, and the folder it runs in), or a change made to
/// every twin.
enum Step {
    Hook { input: String, cwd: String },
    OwnWrite { sid: Value, rel: String },
    Change(Box<dyn Fn(&mut Scenario)>),
}

fn sid(rng: &mut Rng) -> Value {
    match rng.below(60) {
        0 => json!(""),
        1 => json!(null),
        2 => json!(42),
        3 => json!("a/b c.é"),
        4 => json!("x".repeat(90)),
        5 => json!(1.5),
        6 => json!(["s", 1]),
        7..=11 => json!("s2"),
        _ => json!("s1"),
    }
}

fn step(rng: &mut Rng, n: &Names, files: &[String]) -> Step {
    let fw_rel = |rng: &mut Rng| -> String {
        let f = rng.pick(files).clone();
        match rng.below(8) {
            0 => format!("@R@/{f}"),
            1 => format!("{}/people/nope.md", n.tracked[0]),
            2 => format!("{}/people/link.md", n.tracked[0]),
            3 => format!("{}/people/folder.md", n.tracked[0]),
            _ => f,
        }
    };
    let cwd = match rng.below(12) {
        0 => "@R@/notes".to_string(),
        _ => "@R@".to_string(),
    };
    let hook = |v: Value| Step::Hook {
        input: v.to_string(),
        cwd: cwd.clone(),
    };
    match rng.below(100) {
        0..=21 => {
            let key = if rng.chance(10) {
                "notebook_path"
            } else {
                "file_path"
            };
            let path: Value = match rng.below(60) {
                0 => json!(5),
                1 => json!(""),
                2 => json!(null),
                _ => json!(fw_rel(rng)),
            };
            hook(json!({"session_id": sid(rng), "tool_name": "Read", "tool_input": {key: path}}))
        }
        22..=56 => {
            let cmd = command(rng, n, files);
            let cwd_v = match rng.below(40) {
                0..=1 => json!("@R@/nope"),
                2 => json!(""),
                3 => json!(7),
                4..=6 => json!(format!("@R@/{}/people", n.tracked[0])),
                7 => Value::Null,
                _ => json!("@R@"),
            };
            let command_v = if rng.chance(1) { json!(42) } else { json!(cmd) };
            hook(
                json!({"session_id": sid(rng), "tool_name": "Bash", "tool_input": {"command": command_v}, "cwd": cwd_v}),
            )
        }
        57..=61 => {
            let tool = rng.pick(&["Edit", "Write", "MultiEdit", "NotebookEdit"]);
            hook(
                json!({"session_id": sid(rng), "tool_name": tool, "tool_input": {"file_path": fw_rel(rng)}}),
            )
        }
        62..=64 => {
            let tool = rng
                .pick(&[
                    json!("Grep"),
                    json!(""),
                    json!(["Read"]),
                    json!({"a": 1}),
                    json!(3),
                ])
                .clone();
            hook(
                json!({"session_id": sid(rng), "tool_name": tool, "tool_input": {"file_path": fw_rel(rng)}}),
            )
        }
        65..=71 => Step::OwnWrite {
            sid: sid(rng),
            rel: fw_rel(rng),
        },
        72 => {
            let raw = rng
                .pick(&[
                    "not json".to_string(),
                    "[]".into(),
                    json!({"session_id": "s1", "tool_name": "Bash", "tool_input": "cat x"}).to_string(),
                    json!({"session_id": "s1", "tool_name": "Read", "tool_input": [1]}).to_string(),
                    "{\"session_id\": \"s1\", \"tool_name\": \"Read\", \"tool_input\": {\"file_path\": NaN}}".into(),
                ])
                .clone();
            Step::Hook { input: raw, cwd }
        }
        73..=89 => {
            let rel = rng.pick(files).clone();
            let what = rng.below(8);
            Step::Change(Box::new(move |s: &mut Scenario| match what {
                0..=2 => {
                    let old =
                        fs::read_to_string(format!("{}/{rel}", s.roots[0])).unwrap_or_default();
                    s.write(&rel, &format!("{old}more\n"));
                }
                3 => {
                    s.clock += 3;
                    let t = s.clock;
                    s.each(|r| set_mtime(&format!("{r}/{rel}"), t));
                }
                4 => s.each(|r| {
                    let _ = fs::remove_file(format!("{r}/{rel}"));
                }),
                5 => s.write(&rel, "recreated\n"),
                6 => s.each(|r| {
                    let p = format!("{r}/{rel}");
                    if let Ok(m) = fs::metadata(&p) {
                        let mut perm = m.permissions();
                        perm.set_mode(if perm.mode() & 0o777 == 0 { 0o644 } else { 0 });
                        let _ = fs::set_permissions(&p, perm);
                    }
                }),
                _ => s.each(|r| {
                    let p = format!("{r}/{rel}");
                    let _ = fs::remove_file(&p);
                    let _ = fs::create_dir_all(&p);
                }),
            }))
        }
        90..=91 => {
            // The record's mtimes written as floats (what another JSON writer may do): equal to the int in Python.
            let dir = n.record_dir.clone();
            Step::Change(Box::new(move |s: &mut Scenario| {
                s.each(|r| {
                    let p = format!("{r}/{dir}/s1.json");
                    let Ok(text) = fs::read_to_string(&p) else {
                        return;
                    };
                    let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&text) else {
                        return;
                    };
                    let out: Vec<String> = m
                        .iter()
                        .map(
                            |(k, v)| match (v.get("m").and_then(Value::as_i64), v.as_object()) {
                                (Some(mt), Some(o)) => {
                                    let mut parts = vec![format!("\"m\": {:e}", mt as f64)];
                                    parts.extend(
                                        o.iter()
                                            .filter(|(k, _)| *k != "m")
                                            .map(|(k, v)| format!("{}: {v}", json!(k))),
                                    );
                                    format!("{}: {{{}}}", json!(k), parts.join(", "))
                                }
                                _ => format!("{}: {v}", json!(k)),
                            },
                        )
                        .collect();
                    let _ = fs::write(&p, format!("{{{}}}", out.join(", ")));
                })
            }))
        }
        92..=95 => {
            let session = rng.pick(&["s1", "s2"]).to_string();
            let body = rng
                .pick(&[
                    "{not json".to_string(),
                    "[]".into(),
                    "\"\"".into(),
                    "[\"a\"]".into(),
                    "5".into(),
                    "null".into(),
                    "{}".into(),
                    "\u{feff}{}".into(),
                    format!("{{\"{}/x.yaml\": 5}}", n.tracked[1 % n.tracked.len()]),
                    format!("{{\"{}/people/ana.md\": {{\"m\": 1.5e18, \"s\": 1.0, \"h\": \"x\", \"e\": [NaN, 1e400, -0.0, 1e16]}}}}", n.tracked[0]),
                    "{\"/etc/hosts\": {\"m\": 0, \"s\": 0, \"h\": \"\"}, \"/nonexistent\": {}}".into(),
                    format!("{{\"a\": 1, \"a\": {{\"m\": 2}}, \"{}/people/ben.md\": {{}}}}", n.tracked[0]),
                    "{\"x\\u0000y\": {}}".into(),
                ])
                .clone();
            let dir = n.record_dir.clone();
            Step::Change(Box::new(move |s: &mut Scenario| {
                s.each(|r| {
                    let d = format!("{r}/{dir}");
                    let _ = fs::create_dir_all(&d);
                    let _ = fs::write(format!("{d}/{session}.json"), &body);
                })
            }))
        }
        _ => {
            let dir = n.record_dir.clone();
            let name = rng
                .pick(&["old.json", "old.json.lock", "x.json.1.tmp", "sub"])
                .to_string();
            Step::Change(Box::new(move |s: &mut Scenario| {
                s.each(|r| {
                    let d = format!("{r}/{dir}");
                    let _ = fs::create_dir_all(&d);
                    let p = format!("{d}/{name}");
                    if name == "sub" {
                        let _ = fs::create_dir_all(&p);
                    } else {
                        let _ = fs::write(&p, "{}");
                        set_mtime(&p, 1_000_000_000);
                    }
                })
            }))
        }
    }
}

fn rust_hook(root: &str, cwd: &str, input: &str, crash_log: &str) -> (String, bool) {
    let before = fs::read_to_string(crash_log).map_or(0, |t| t.lines().count());
    let o = run_in(
        &[BIN, "repo", "post-read", "--crash-log", crash_log],
        input,
        &[("CLAUDE_PROJECT_DIR", root)],
        Some(cwd),
    );
    assert_eq!((o.code, o.stderr.as_str()), (0, ""), "exit 0, no stderr");
    let after = fs::read_to_string(crash_log).map_or(0, |t| t.lines().count());
    (o.stdout, after > before)
}

/// A real `python3 -I` run; its crashes go to the config's `error_log` (where the reference hook logs them).
fn real_python(
    reference: &str,
    root: &str,
    cwd: &str,
    input: &str,
    error_log: &str,
) -> (String, bool) {
    let log = format!("{root}/{error_log}");
    let before = fs::read_to_string(&log).map_or(0, |t| t.lines().count());
    let o = run_in(
        &["/usr/bin/python3", "-I", reference],
        input,
        &[("CLAUDE_PROJECT_DIR", root)],
        Some(cwd),
    );
    let after = fs::read_to_string(&log).map_or(0, |t| t.lines().count());
    (o.stdout, after > before)
}

#[test]
fn differential_repo_read() {
    let (Ok(reference), Ok(config_path)) = (
        std::env::var("CLAUDE_GUARD_REF_REPO_READ"),
        std::env::var("CLAUDE_GUARD_REF_REPO_CONFIG"),
    ) else {
        eprintln!(
            "differential repo read: skipped (CLAUDE_GUARD_REF_REPO_READ / CLAUDE_GUARD_REF_REPO_CONFIG unset)"
        );
        return;
    };
    let config = fs::read_to_string(&config_path).unwrap();
    let names = Names::from(&serde_json::from_str(&config).unwrap());
    let files = names.files();
    let n: usize = env_or("CLAUDE_GUARD_DIFF_CASES", "250").parse().unwrap();
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261126")
        .parse()
        .unwrap();
    let mut rng = Rng(seed | 1);
    let base = fresh_dir("post-read-diff");
    let base = fs::canonicalize(&base)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let mut driver = Driver::new(&reference);
    let (mut calls, mut notices, mut crashes, mut spot, mut bad) = (0, 0, 0, 0, Vec::new());
    let cfg_v: Value = serde_json::from_str(&config).unwrap();
    let error_log = cfg_v["error_log"].as_str().unwrap().to_string();
    let lead = |k: &str| {
        let m = cfg_v["post_read"]["messages"][k].as_str().unwrap();
        m[..m.find("{files}").unwrap_or(m.len())].to_string()
    };
    let (elsewhere_lead, during_lead) = (lead("changed_elsewhere"), lead("during_command"));
    let (mut elsewhere, mut during, mut deleted) = (0, 0, 0);
    for sc in 0..n {
        let real = sc % 25 == 0;
        let tag = format!("{base}/{sc}");
        let mut roots = vec![format!("{tag}/py"), format!("{tag}/rs")];
        if real {
            roots.push(format!("{tag}/real"));
        }
        let mut s = Scenario {
            names: &names,
            roots,
            clock: 1_700_000_000,
        };
        s.build(&config);
        // Most steps work on four files the session reads first.
        let mut pool: Vec<String> = files.clone();
        let followed: Vec<String> = files
            .iter()
            .filter(|f| {
                names
                    .tracked
                    .iter()
                    .any(|t| f.starts_with(&format!("{t}/")))
                    && !f.starts_with(&format!("{}/", names.untracked))
                    && !names.generated.contains(f)
            })
            .cloned()
            .collect();
        let hot: Vec<String> = (0..4).map(|_| rng.pick(&followed).clone()).collect();
        for _ in 0..6 {
            pool.extend(hot.iter().cloned());
        }
        let mut first: Vec<Step> = hot
            .iter()
            .map(|f| {
                let input = if rng.chance(50) {
                    json!({"session_id": "s1", "tool_name": "Read", "tool_input": {"file_path": f}})
                } else {
                    json!({"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": format!("cat '{f}'")}, "cwd": "@R@"})
                };
                Step::Hook { input: input.to_string(), cwd: "@R@".into() }
            })
            .collect();
        first.reverse();
        for k in 0..STEPS {
            let st = first.pop().unwrap_or_else(|| step(&mut rng, &names, &pool));
            let what = match st {
                Step::Change(f) => {
                    f(&mut s);
                    if std::env::var("CLAUDE_GUARD_DIFF_TRACE").is_ok_and(|t| t == sc.to_string()) {
                        eprintln!("step {k}: change");
                    }
                    // Often the session looks next, so the change is reported (or absorbed) right away.
                    if rng.chance(60) {
                        let stem = {
                            let base = rng.pick(&hot).rsplit('/').next().unwrap_or("").to_string();
                            base.split('.').next().unwrap_or("").to_string()
                        };
                        let cmd = rng
                            .pick(&[
                                "ls".to_string(),
                                "git status --short".into(),
                                "node build.js".into(),
                                "ls > out.txt".into(),
                                format!("node fix.js {stem}-2"),
                                format!("node fix.js {stem}_old"),
                                format!("node fix.js x-{stem}"),
                                format!("node fix.js {stem}"),
                                "ls > &".into(),
                            ])
                            .clone();
                        let input = if rng.chance(30) {
                            json!({"session_id": "s1", "tool_name": "Read", "tool_input": {"file_path": rng.pick(&pool)}})
                        } else {
                            json!({"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": "@R@"})
                        };
                        first.push(Step::Hook {
                            input: input.to_string(),
                            cwd: "@R@".into(),
                        });
                    }
                    continue;
                }
                Step::OwnWrite { sid, rel } => {
                    let mut seen = Vec::new();
                    for r in &s.roots {
                        let real_root = fs::canonicalize(r).unwrap().to_string_lossy().into_owned();
                        let path = if rel.starts_with("@R@") {
                            rel.replace("@R@", r)
                        } else {
                            format!("{r}/{rel}")
                        };
                        seen.push(driver.ask(json!({"own_write": [real_root, sid, path]})).1);
                    }
                    assert!(
                        seen.iter().all(|c| *c == seen[0]),
                        "own write crashed on one twin only"
                    );
                    format!("own write {sid} {rel}")
                }
                Step::Hook { input, cwd } => {
                    calls += 1;
                    let at = |r: &str| (input.replace("@R@", r), cwd.replace("@R@", r));
                    let (pin, pcwd) = at(&s.roots[0]);
                    let _ = fs::create_dir_all(&pcwd);
                    let py = driver.ask(json!({"input": pin, "project": s.roots[0], "cwd": pcwd}));
                    let (rin, rcwd) = at(&s.roots[1]);
                    let _ = fs::create_dir_all(&rcwd);
                    let rs = rust_hook(&s.roots[1], &rcwd, &rin, &format!("{tag}/rs-crash.log"));
                    if py != rs {
                        bad.push(format!(
                            "scenario {sc} step {k}: {pin}\n  python: {py:?}\n  rust:   {rs:?}"
                        ));
                    }
                    if real {
                        let (qin, qcwd) = at(&s.roots[2]);
                        let _ = fs::create_dir_all(&qcwd);
                        let q = real_python(&reference, &s.roots[2], &qcwd, &qin, &error_log);
                        assert_eq!(
                            q, py,
                            "driver vs real python3 -I, scenario {sc} step {k}: {pin}"
                        );
                        spot += 1;
                    }
                    if std::env::var("CLAUDE_GUARD_DIFF_TRACE").is_ok_and(|t| t == sc.to_string()) {
                        eprintln!("step {k}: {pin}\n   -> {py:?}");
                    }
                    notices += usize::from(!py.0.is_empty());
                    elsewhere += usize::from(py.0.contains(&elsewhere_lead));
                    during += usize::from(py.0.contains(&during_lead));
                    deleted += usize::from(py.0.contains(" (deleted)"));
                    crashes += usize::from(py.1);
                    pin
                }
            };
            let want = s.records(&s.roots[0]);
            let got = s.records(&s.roots[1]);
            if want != got {
                let show = |m: &BTreeMap<String, Vec<u8>>| {
                    m.iter()
                        .map(|(k, v)| {
                            format!(
                                "{k}: {}",
                                String::from_utf8_lossy(v)
                                    .chars()
                                    .take(300)
                                    .collect::<String>()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n      ")
                };
                bad.push(format!(
                    "scenario {sc} step {k} records differ after {what}\n  python:\n      {}\n  rust:\n      {}",
                    show(&want),
                    show(&got)
                ));
            }
            if s.roots.len() == 3 {
                let r3 = s.records(&s.roots[2]);
                let txt = |m: &BTreeMap<String, Vec<u8>>| {
                    m.iter()
                        .map(|(k, v)| format!("{k}: {}", String::from_utf8_lossy(v)))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                assert_eq!(
                    txt(&r3),
                    txt(&want),
                    "driver vs real records, scenario {sc} step {k} after {what}"
                );
            }
            if bad.len() > 20 {
                break;
            }
        }
        if bad.len() > 20 {
            break;
        }
        // Restore permissions so the folder can be removed.
        for r in &s.roots {
            let _ = Command::new("chmod").args(["-R", "u+rwX", r]).status();
        }
        let _ = fs::remove_dir_all(&tag);
    }
    eprintln!(
        "differential repo read: {n} scenarios, {calls} hook calls ({notices} notices: {elsewhere} someone else, {during} maybe your command, {deleted} with a deletion; {crashes} crashes), {spot} real python3 -I checks, {} unexpected",
        bad.len()
    );
    assert!(
        bad.is_empty(),
        "{} different (first 8):\n{}",
        bad.len(),
        bad.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
    );
    assert!(
        notices > n / 2 && elsewhere > 0 && during > 0 && deleted > 0 && crashes > 10,
        "the scenarios reach every kind of notice, and crashes"
    );
}
