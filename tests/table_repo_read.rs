//! Table tests for `claude-guard repo post-read` (the stale-read notice), with a generic fixture config. Each test
//! builds its own repo under $TMPDIR; files get fixed, distinct mtimes so a change is always seen.

mod common;
use common::*;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime};

const CONFIG: &str = r#"{
  "version": 1,
  "repo_label": "fixture",
  "error_log": "out/errors.log",
  "locked_dirs": ["records", "data"],
  "output_dirs": ["out"],
  "post_read": {
    "tracked_dirs": ["records", "data"],
    "untracked_dirs": ["records/journal"],
    "generated": ["records/index.md"],
    "record_dir": "state/reads",
    "layer_suffixes": [".md", ".team.md", ".secret.md"],
    "entity_command": {"runner": "tool", "command": "show", "schema_dir": "kinds", "folder_key": "dir"},
    "read_only_runner_commands": ["show", "status"],
    "messages": {
      "changed_elsewhere": "OTHER: {files}.",
      "during_command": "MAYBE: {files}.",
      "stale": "STALE."
    }
  }
}"#;

const FILES: &[&str] = &[
    "records/people/ana.md",
    "records/people/ana-2.md",
    "records/people/ben.md",
    "records/people/ben.team.md",
    "records/journal/2026.md",
    "records/index.md",
    "data/x.yaml",
    "other/o.md",
];

struct Repo {
    d: String,
    tick: std::sync::atomic::AtomicU64,
}

fn set_mtime(path: &str, secs: u64) {
    let f = fs::File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
        .unwrap();
}

impl Repo {
    fn new(tag: &str) -> Repo {
        let d = fresh_dir(&format!("post-read-{tag}"));
        let d = fs::canonicalize(&d).unwrap().to_string_lossy().into_owned();
        fs::create_dir_all(format!("{d}/.claude")).unwrap();
        fs::write(format!("{d}/.claude/repo-guard.json"), CONFIG).unwrap();
        fs::create_dir_all(format!("{d}/kinds")).unwrap();
        fs::write(
            format!("{d}/kinds/person.yaml"),
            "title: x\ndir: records/people\n",
        )
        .unwrap();
        let r = Repo {
            d,
            tick: std::sync::atomic::AtomicU64::new(1_700_000_000),
        };
        for f in FILES {
            r.write(f, &format!("{f}\n"));
        }
        r
    }

    fn p(&self, rel: &str) -> String {
        format!("{}/{rel}", self.d)
    }

    /// Write a file with the next mtime.
    fn write(&self, rel: &str, text: &str) {
        let p = self.p(rel);
        fs::create_dir_all(std::path::Path::new(&p).parent().unwrap()).unwrap();
        fs::write(&p, text).unwrap();
        let t = self.tick.fetch_add(5, std::sync::atomic::Ordering::SeqCst) + 5;
        set_mtime(&p, t);
    }

    fn change(&self, rel: &str) {
        let old = fs::read_to_string(self.p(rel)).unwrap_or_default();
        self.write(rel, &format!("{old}more\n"));
    }

    fn run(&self, input: &str) -> Out {
        run_in(
            &[
                BIN,
                "repo",
                "post-read",
                "--crash-log",
                &self.p("crash.log"),
            ],
            input,
            &[("CLAUDE_PROJECT_DIR", &self.d)],
            Some(&self.d),
        )
    }

    fn hook(&self, v: Value) -> String {
        let o = self.run(&v.to_string());
        assert_eq!(o.code, 0, "always exits 0");
        assert_eq!(o.stderr, "", "never writes stderr");
        if o.stdout.is_empty() {
            return String::new();
        }
        let out: Value = serde_json::from_str(&o.stdout).unwrap();
        assert_eq!(out["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        out["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn read(&self, sid: &str, rel: &str) -> String {
        self.hook(json!({"session_id": sid, "tool_name": "Read", "tool_input": {"file_path": self.p(rel)}}))
    }

    fn bash(&self, sid: &str, cmd: &str) -> String {
        self.hook(json!({"session_id": sid, "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": self.d}))
    }

    fn record_path(&self, sid: &str) -> String {
        self.p(&format!("state/reads/{sid}.json"))
    }

    fn record(&self, sid: &str) -> Option<Value> {
        fs::read_to_string(self.record_path(sid))
            .ok()
            .map(|t| serde_json::from_str(&t).unwrap())
    }

    fn keys(&self, sid: &str) -> Vec<String> {
        self.record(sid)
            .and_then(|v| v.as_object().map(|o| o.keys().cloned().collect()))
            .unwrap_or_default()
    }

    fn crash_log(&self) -> String {
        fs::read_to_string(self.p("crash.log")).unwrap_or_default()
    }
}

#[test]
fn a_change_by_someone_else_is_reported_once() {
    let r = Repo::new("once");
    assert_eq!(r.read("s1", "records/people/ana.md"), "");
    r.change("records/people/ana.md");
    assert_eq!(
        r.bash("s1", "ls -la"),
        "OTHER: records/people/ana.md. STALE."
    );
    assert_eq!(r.bash("s1", "ls"), "", "reported once");
    r.change("records/people/ana.md");
    assert_eq!(
        r.hook(json!({"session_id": "s1", "tool_name": "Read", "tool_input": {"file_path": r.p("data/x.yaml")}})),
        "OTHER: records/people/ana.md. STALE.",
        "a Read cannot write: someone else"
    );
}

#[test]
fn the_record_format_is_pinned() {
    let r = Repo::new("format");
    r.read("s1", "records/people/ana.md");
    r.read("s1", "data/x.yaml");
    let text = fs::read_to_string(r.record_path("s1")).unwrap();
    let m = |rel: &str| {
        let st = fs::metadata(r.p(rel)).unwrap();
        use std::os::unix::fs::MetadataExt;
        st.mtime() as i128 * 1_000_000_000 + st.mtime_nsec() as i128
    };
    let want = format!(
        "{{\"records/people/ana.md\": {{\"m\": {}, \"s\": 22, \"h\": \"{}\"}}, \"data/x.yaml\": {{\"m\": {}, \"s\": 12, \"h\": \"{}\"}}}}",
        m("records/people/ana.md"),
        "9b6c1148bd49f64fcfceca41caa6c337629628a0e5914d7ecbb8e773e47d2986",
        m("data/x.yaml"),
        "6812defecadf360f798a879a2994f8d42355d22a2573de80b2d9b0f16ae289a1"
    );
    assert_eq!(
        text, want,
        "Python's json.dump: separators, ints, insertion order, no trailing newline"
    );
    let mode = |p: &str| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode(&format!("{}.lock", r.record_path("s1"))),
        0o600,
        "lock file mode"
    );
    let umask = {
        let probe = r.p("umask-probe");
        fs::write(&probe, "").unwrap();
        0o666 & !mode(&probe)
    };
    assert_eq!(
        mode(&r.record_path("s1")),
        0o666 & !umask,
        "record mode follows the umask"
    );
    let leftovers: Vec<_> = fs::read_dir(r.p("state/reads"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "atomic replace leaves no tmp: {leftovers:?}"
    );
}

#[test]
fn a_python_written_record_is_read_and_its_values_kept() {
    let r = Repo::new("py-record");
    r.read("s1", "records/people/ben.md");
    // What the Edit hook (record_own_write) writes, with an extra key and a float a later save must keep as Python
    // would print them.
    let rec = r.record("s1").unwrap();
    let ben = &rec["records/people/ben.md"];
    let text = format!(
        "{{\"records/people/ben.md\": {{\"m\": {}, \"s\": {}, \"h\": {}, \"x\": [1.5e16, -0.0, \"\\u00e9\", null]}}}}",
        ben["m"], ben["s"], ben["h"]
    );
    fs::write(r.record_path("s1"), &text).unwrap();
    r.read("s1", "data/x.yaml");
    let after = fs::read_to_string(r.record_path("s1")).unwrap();
    let kept = text.replace("1.5e16", "1.5e+16");
    assert!(
        after.starts_with(&kept[..kept.len() - 1]),
        "unchanged entries are written back as Python prints them:\n{after}"
    );
    assert!(
        after.contains("[1.5e+16, -0.0, \"\\u00e9\", null]"),
        "{after}"
    );
}

#[test]
fn own_commands_and_maybe_commands() {
    let r = Repo::new("own");
    r.read("s1", "records/people/ana.md");
    r.change("records/people/ana.md");
    assert_eq!(
        r.bash("s1", "tool edit person/ana --set x=1"),
        "",
        "names the id: its own"
    );
    r.change("records/people/ana.md");
    assert_eq!(
        r.bash("s1", "./fix records/people/ana.md"),
        "",
        "names the path: its own"
    );
    r.change("records/people/ana.md");
    assert_eq!(
        r.bash("s1", "tool edit person/ana-2"),
        "MAYBE: records/people/ana.md. STALE.",
        "ana-2 is another id"
    );
    r.change("records/people/ana.md");
    assert_eq!(
        r.bash("s1", "tool --quiet status 2>&1 | tail -1"),
        "OTHER: records/people/ana.md. STALE.",
        "a read-only runner command"
    );
    r.change("records/people/ana.md");
    assert_eq!(
        r.bash("s1", "ls > /tmp/listing.txt"),
        "MAYBE: records/people/ana.md. STALE."
    );
    r.change("records/people/ana.md");
    assert_eq!(
        r.bash("s1", "rg -n ana records/people/ben.md"),
        "OTHER: records/people/ana.md. STALE.",
        "a read-only command that only mentions the id does not hide the change"
    );
    for (cmd, other) in [
        ("ls >/dev/null 2>&1", true),
        ("ls >&2", true),
        ("ls > &", true),
        ("ls > 1", true),
        ("ls >", false),
        ("git status --short", true),
        ("git -C x status", false),
        ("find records -name '*.md'", true),
        ("find records -delete", false),
        ("find . -exec cat {} +", false),
        ("sed -n 1p data/x.yaml", true),
        ("sed -i s/a/b/ data/x.yaml", false),
        ("yq -i .a data/x.yaml", false),
        ("gawk -i inplace 1 data/x.yaml", false),
        ("jq . data/x.yaml", true),
        ("tool test", false),
        ("tool run show person/ben", true),
        ("FOO=1 nice env sudo cat data/x.yaml", true),
        ("python3 -c pass", false),
    ] {
        r.change("records/people/ana.md");
        let want = if other { "OTHER" } else { "MAYBE" };
        assert_eq!(
            r.bash("s1", cmd),
            format!("{want}: records/people/ana.md. STALE."),
            "{cmd}"
        );
    }
}

#[test]
fn reads_by_bash_count_and_take_the_new_content() {
    let r = Repo::new("bash-reads");
    for (cmd, rel) in [
        ("cat records/people/ana.md", "records/people/ana.md"),
        ("rtk read data/x.yaml", "data/x.yaml"),
        ("head -n 5 records/people/ben.md", "records/people/ben.md"),
        (
            "cd records/people && tail -c 3 ana-2.md",
            "records/people/ana-2.md",
        ),
        ("sed -n 1p records/people/ana.md", "records/people/ana.md"),
        (
            "sed -ne 1p -e 2p records/people/ana.md",
            "records/people/ana.md",
        ),
        ("rg -e x records/people/ana.md data/x.yaml", "data/x.yaml"),
        (
            "grep -f pats records/people/ben.md",
            "records/people/ben.md",
        ),
        (
            "awk -F: '{print}' records/people/ana.md",
            "records/people/ana.md",
        ),
        ("awk -f prog records/people/ben.md", "records/people/ben.md"),
        ("jq --arg a b . data/x.yaml", "data/x.yaml"),
        ("jq -f prog data/x.yaml", "data/x.yaml"),
        ("yq e .a data/x.yaml", "data/x.yaml"),
        ("yq --from-file p data/x.yaml | head", "data/x.yaml"),
        (
            "diff -u records/people/ana.md records/people/ben.md",
            "records/people/ben.md",
        ),
        (
            "tool --silent show person/ben",
            "records/people/ben.team.md",
        ),
        ("cat records/people/a*.md", "records/people/ana-2.md"),
    ] {
        let sid = format!("r{}", cmd.len());
        let _ = fs::remove_file(r.record_path(&sid));
        assert_eq!(r.bash(&sid, cmd), "", "{cmd}");
        assert!(
            r.keys(&sid).contains(&rel.to_string()),
            "{cmd}: {:?}",
            r.keys(&sid)
        );
    }
    // sed's first plain word is its script, even when it names a file.
    r.bash(
        "sed",
        "sed -n records/people/ana-2.md records/people/ben.md",
    );
    assert_eq!(r.keys("sed"), ["records/people/ben.md"]);
    // Reading the changed file takes the new content without a notice.
    r.read("s1", "records/people/ana.md");
    r.change("records/people/ana.md");
    assert_eq!(r.bash("s1", "cat records/people/ana.md"), "");
    assert_eq!(r.bash("s1", "ls"), "");
}

#[test]
fn folder_searches_in_place_edits_and_scripts_are_not_reads() {
    let r = Repo::new("not-reads");
    for cmd in [
        "rg ana records/",
        "grep -r ana records",
        "rg ana records/people/ana.md records/people",
        "sed -i s/a/b/ records/people/ana.md",
        "yq -i .a data/x.yaml",
        "gawk -i inplace 1 records/people/ana.md",
        "awk 1 records/people",
        "python3 -c \"open('records/people/ana.md')\"",
        "cat other/o.md records/index.md records/journal/2026.md",
        "cat 'records/people/ana.md",
        "cat records/people/nope.md",
        "tool show person",
        "tool show nokind/ana",
        "cat ../x/records/people/ana.md",
    ] {
        assert_eq!(r.bash("n", cmd), "", "{cmd}");
        assert_eq!(r.keys("n"), Vec::<String>::new(), "{cmd}");
    }
    assert!(
        !std::path::Path::new(&r.p("state")).exists(),
        "nothing read: no record folder"
    );
}

#[test]
fn deleted_files_and_separate_sessions() {
    let r = Repo::new("deleted");
    r.read("s1", "records/people/ana.md");
    r.read("s2", "records/people/ana.md");
    fs::remove_file(r.p("records/people/ana.md")).unwrap();
    assert_eq!(
        r.bash("s1", "ls"),
        "OTHER: records/people/ana.md (deleted). STALE."
    );
    assert_eq!(r.bash("s1", "ls"), "");
    assert_eq!(
        r.bash("s2", "rm -f nothing"),
        "MAYBE: records/people/ana.md (deleted). STALE."
    );
    r.read("s3", "records/people/ben.md");
    fs::remove_file(r.p("records/people/ben.md")).unwrap();
    assert_eq!(
        r.bash("s3", "rm records/people/ben.md"),
        "",
        "its own command named it"
    );
}

#[test]
fn a_float_mtime_equal_to_the_file_counts_as_unchanged() {
    let r = Repo::new("float-m");
    r.read("s1", "data/x.yaml");
    let rec = r.record("s1").unwrap();
    let e = &rec["data/x.yaml"];
    let text = format!(
        "{{\"data/x.yaml\": {{\"m\": {:e}, \"s\": {}, \"h\": \"other\"}}}}",
        e["m"].as_i64().unwrap() as f64,
        e["s"]
    );
    fs::write(r.record_path("s1"), &text).unwrap();
    assert_eq!(r.bash("s1", "ls"), "");
    assert!(
        fs::read_to_string(r.record_path("s1"))
            .unwrap()
            .contains("\"h\": \"other\""),
        "1.7e18 == 1700000000000000000 in Python: not re-hashed"
    );
}

#[test]
fn a_re_read_moves_last_and_a_write_tool_sees_a_deletion_as_maybe() {
    let r = Repo::new("order");
    r.read("s1", "records/people/ana.md");
    r.read("s1", "data/x.yaml");
    r.read("s1", "records/people/ana.md");
    assert_eq!(
        r.keys("s1"),
        ["data/x.yaml", "records/people/ana.md"],
        "most recent last, for the 400 cap"
    );
    fs::remove_file(r.p("data/x.yaml")).unwrap();
    assert_eq!(
        r.hook(json!({"session_id": "s1", "tool_name": "Edit", "tool_input": {"file_path": r.p("records/people/ben.md")}})),
        "MAYBE: data/x.yaml (deleted). STALE.",
        "unlike a changed file, a deleted one is not blamed on someone else for a write tool"
    );
}

#[test]
fn mtime_only_changes_refresh_silently() {
    let r = Repo::new("touch");
    r.read("s1", "data/x.yaml");
    let before = r.record("s1").unwrap()["data/x.yaml"].clone();
    set_mtime(&r.p("data/x.yaml"), 1_800_000_000);
    assert_eq!(r.bash("s1", "ls"), "");
    let after = r.record("s1").unwrap()["data/x.yaml"].clone();
    assert_ne!(before["m"], after["m"]);
    assert_eq!(before["h"], after["h"]);
}

#[test]
fn tools_paths_and_session_names() {
    let r = Repo::new("tools");
    // notebook_path counts like file_path; a write tool's own target is its own, another file is someone else's.
    r.hook(json!({"session_id": "s1", "tool_name": "Read", "tool_input": {"file_path": "", "notebook_path": r.p("data/x.yaml")}}));
    assert_eq!(r.keys("s1"), ["data/x.yaml"]);
    r.read("s1", "records/people/ana.md");
    for tool in ["Edit", "MultiEdit", "Write", "NotebookEdit"] {
        r.change("data/x.yaml");
        r.change("records/people/ana.md");
        assert_eq!(
            r.hook(json!({"session_id": "s1", "tool_name": tool, "tool_input": {"file_path": r.p("data/x.yaml")}})),
            "OTHER: records/people/ana.md. STALE.",
            "{tool}"
        );
    }
    r.change("records/people/ana.md");
    assert_eq!(
        r.hook(json!({"session_id": "s1", "tool_name": "Grep", "tool_input": {}})),
        "MAYBE: records/people/ana.md. STALE.",
        "an unknown tool may have written"
    );
    // Relative paths are from the hook's own folder; symlinks are followed; a top folder named `..x` is outside.
    std::os::unix::fs::symlink(r.p("records/people"), r.p("people-link")).unwrap();
    r.hook(json!({"session_id": "s4", "tool_name": "Read", "tool_input": {"file_path": "people-link/ben.md"}}));
    assert_eq!(r.keys("s4"), ["records/people/ben.md"]);
    // Session ids: Python's str(), then [A-Za-z0-9_-] kept, the rest `_`, the first 80 characters.
    for (sid, file) in [
        (json!("a/b c.é"), "a_b_c__"),
        (json!(42), "42"),
        (json!(1.5), "1_5"),
        (json!(true), "True"),
        (json!("x".repeat(100)), &"x".repeat(80)[..]),
    ] {
        r.hook(json!({"session_id": sid, "tool_name": "Read", "tool_input": {"file_path": r.p("data/x.yaml")}}));
        assert!(
            std::path::Path::new(&r.p(&format!("state/reads/{file}.json"))).exists(),
            "{sid} -> {file}"
        );
    }
    for sid in [json!(""), json!(null), json!(0), json!([])] {
        let before = fs::read_dir(r.p("state/reads")).unwrap().count();
        r.hook(json!({"session_id": sid, "tool_name": "Read", "tool_input": {"file_path": r.p("data/x.yaml")}}));
        assert_eq!(
            fs::read_dir(r.p("state/reads")).unwrap().count(),
            before,
            "{sid}: no record"
        );
    }
}

#[test]
fn non_ascii_names_are_escaped_in_the_notice() {
    let r = Repo::new("unicode");
    r.write("records/people/zoë.md", "z\n");
    r.read("s1", "records/people/zoë.md");
    r.change("records/people/zoë.md");
    let o = r.run(
        &json!({"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "ls"}})
            .to_string(),
    );
    assert!(
        o.stdout.contains("records/people/zo\\u00eb.md"),
        "{}",
        o.stdout
    );
    assert!(
        fs::read_to_string(r.record_path("s1"))
            .unwrap()
            .contains("zo\\u00eb.md")
    );
}

#[test]
fn limits_track_400_glob_50_and_tidy_7_days() {
    let r = Repo::new("limits");
    for i in 0..60 {
        r.write(&format!("data/g/{i:03}.txt"), "g\n");
    }
    r.bash("s1", "cat data/g/*.txt");
    let keys = r.keys("s1");
    assert_eq!(keys.len(), 50, "a glob adds at most 50");
    assert_eq!(keys[0], "data/g/000.txt");
    // 401 entries of files that are there and unchanged, plus one read: the two oldest drop.
    let mut big = serde_json::Map::new();
    for i in 0..401 {
        let rel = format!("data/old/{i}.txt");
        r.write(&rel, "o\n");
        let st = fs::metadata(r.p(&rel)).unwrap();
        use std::os::unix::fs::MetadataExt;
        let m = st.mtime() * 1_000_000_000 + st.mtime_nsec();
        big.insert(rel, json!({"m": m, "s": st.size(), "h": "x"}));
    }
    fs::write(r.record_path("s1"), Value::Object(big).to_string()).unwrap();
    r.read("s1", "data/x.yaml");
    let keys = r.keys("s1");
    assert_eq!(keys.len(), 400);
    assert_eq!(keys.last().unwrap(), "data/x.yaml");
    assert_eq!(keys[0], "data/old/2.txt", "the oldest dropped");
    // Tidy: a new session removes anything in the folder untouched for 7 days, and nothing newer.
    let old = r.p("state/reads/old.json");
    fs::write(&old, "{}").unwrap();
    set_mtime(&old, 1_000_000_000);
    let fresh = r.p("state/reads/fresh.json");
    fs::write(&fresh, "{}").unwrap();
    r.read("s1", "data/x.yaml");
    assert!(
        std::path::Path::new(&old).exists(),
        "an existing session does not tidy"
    );
    r.read("new-session", "data/x.yaml");
    assert!(!std::path::Path::new(&old).exists(), "a new session tidies");
    assert!(std::path::Path::new(&fresh).exists());
}

#[test]
fn broken_input_and_records_never_block() {
    let r = Repo::new("broken");
    assert_eq!(r.run("not json").stdout, "");
    assert!(
        r.crash_log().contains("repo-post-read JSONDecodeError"),
        "{}",
        r.crash_log()
    );
    r.read("s1", "data/x.yaml");
    let o = r.run(
        &json!({"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": 42}})
            .to_string(),
    );
    assert_eq!((o.code, o.stdout.as_str()), (0, ""));
    assert!(r.crash_log().contains("TypeError"), "{}", r.crash_log());
    // A corrupt record starts over; an empty list is written back when the read finds nothing.
    fs::write(r.record_path("s1"), "{not json").unwrap();
    assert_eq!(r.read("s1", "data/x.yaml"), "");
    assert_eq!(r.keys("s1"), ["data/x.yaml"]);
    fs::write(r.record_path("s1"), "[]").unwrap();
    r.read("s1", "records/people/missing.md");
    assert_eq!(fs::read_to_string(r.record_path("s1")).unwrap(), "[]");
    let lines = r.crash_log().lines().count();
    r.read("s1", "data/x.yaml");
    assert_eq!(
        r.crash_log().lines().count(),
        lines + 1,
        "a read into a list record raises"
    );
    // A record entry that is not an object raises once its file is there.
    fs::write(r.record_path("s1"), "{\"data/x.yaml\": 5}").unwrap();
    r.bash("s1", "ls");
    assert_eq!(r.crash_log().lines().count(), lines + 2);
    // A session that has read nothing is left alone.
    assert_eq!(r.bash("quiet", "git status"), "");
    assert!(!std::path::Path::new(&r.record_path("quiet")).exists());
}

#[test]
fn a_missing_config_warns() {
    let r = Repo::new("no-config");
    fs::write(
        r.p(".claude/repo-guard.json"),
        "{\"version\": 1, \"error_log\": \"x\"}",
    )
    .unwrap();
    let o = r.run(
        &json!({"session_id": "s1", "tool_name": "Read", "tool_input": {"file_path": "x"}})
            .to_string(),
    );
    assert_eq!(o.code, 0);
    assert!(
        o.stdout.contains("systemMessage") && o.stdout.contains("no post_read section"),
        "{}",
        o.stdout
    );
}

#[test]
fn parallel_calls_keep_every_read() {
    let r = Repo::new("parallel");
    for i in 0..16 {
        r.write(&format!("data/p/{i}.txt"), "p\n");
    }
    std::thread::scope(|s| {
        for i in 0..16 {
            let r = &r;
            s.spawn(move || r.read("s1", &format!("data/p/{i}.txt")));
        }
    });
    assert_eq!(
        r.keys("s1").len(),
        16,
        "the record is locked across processes"
    );
}

#[test]
fn the_entity_command_follows_the_schema() {
    let r = Repo::new("entity");
    r.bash("e1", "tool show person/ben");
    assert_eq!(
        r.keys("e1"),
        ["records/people/ben.md", "records/people/ben.team.md"],
        "only the layers there"
    );
    fs::write(r.p("kinds/person.yaml"), "title: x\n").unwrap();
    r.bash("e2", "tool show person/ben");
    assert_eq!(r.keys("e2"), Vec::<String>::new(), "no folder line");
    fs::write(r.p("kinds/person.yaml"), [0xff, 0xfe]).unwrap();
    let before = r.crash_log().lines().count();
    r.bash("e3", "tool show person/ben");
    assert_eq!(
        r.crash_log().lines().count(),
        before + 1,
        "a schema that is not UTF-8 raises"
    );
}
