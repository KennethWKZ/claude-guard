//! Differential test: `claude-guard bash` against the hooks it replaces (guard-bash.py + block-pip.sh), on the
//! fixture cases plus thousands of generated commands, cwd values and JSON edge inputs. Any difference in
//! stdout, exit code or stderr fails, except the known ones listed in `known_difference`.
//!
//! Needs the reference hooks; skipped (with a message) when they are missing. Test-only settings come from the
//! environment: CLAUDE_GUARD_REF_BASH, CLAUDE_GUARD_REF_PIP (default ~/.claude/hooks/...),
//! CLAUDE_GUARD_DIFF_CASES (default 4000), CLAUDE_GUARD_DIFF_SEED, CLAUDE_GUARD_DIFF_WORKERS (default 2;
//! pass "$(test-workers)").

use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;

const BIN: &str = env!("CARGO_BIN_EXE_claude-guard");
const PIP_MSG: &str = "Do not use pip. Use uv instead. Example: uv add <packages>";

#[derive(Debug, Clone, PartialEq)]
struct Out {
    stdout: String,
    code: i32,
    stderr: String,
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, v: &'a [String]) -> &'a str {
        &v[self.below(v.len())]
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn sv(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// A folder with secrets files, templates, sub-folders, odd names and a link out of temp, for the glob and
/// realpath paths.
fn fixture_dir() -> String {
    let d = std::env::temp_dir().join(format!("claude-guard-diff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for sub in ["sub", ".hidden", "dir.env"] {
        std::fs::create_dir_all(d.join(sub)).unwrap();
    }
    for f in [
        ".env",
        ".env.local",
        ".env.example",
        "prod.env",
        "a.md",
        "b.md",
        "config.json",
        "x.json",
        "sub/.env.production",
        "sub/notes.md",
        ".hidden/.envrc",
        "[i-0]",
        "data[1].txt",
        "é.env",
        "a.envrc",
    ] {
        std::fs::write(d.join(f), "x\n").unwrap();
    }
    // Script files a command runs (read from disk by Rust only).
    std::fs::create_dir_all(d.join("run")).unwrap();
    for (f, text) in [
        ("run/sudo.sh", "#!/bin/bash\nsudo ls\n"),
        ("run/push.sh", "git push -f\n"),
        ("run/env.sh", "#!/bin/sh\ncat .env\n"),
        ("run/ok.sh", "#!/bin/sh\nls -la\n"),
        ("run/pip.sh", "pip install x\n"),
        ("run/r.py", "import os\nos.system(\"sudo ls\")\n"),
        ("run/nul.sh", "#!/bin/bash\ngit push -f\n#\0x\n"),
        (
            "run/r.js",
            "require('child_process').execSync('git push -f')\n",
        ),
    ] {
        std::fs::write(d.join(f), text).unwrap();
    }
    let _ = std::os::unix::fs::symlink("/Users", d.join("link"));
    let _ = std::os::unix::fs::symlink(d.join("sub"), d.join("sublink"));
    d.to_string_lossy().into_owned()
}

/// Commands that run the fixture folder's script files (`run/`).
const SCRIPT_RUNS: &[&str] = &[
    "bash run/sudo.sh",
    "source run/push.sh",
    ". ./run/env.sh",
    "./run/sudo.sh",
    "./run/push.sh",
    "cat run/push.sh | bash",
    "sh < run/env.sh",
    "timeout 9 bash run/sudo.sh",
    "bash run/pip.sh",
    "bash run/ok.sh",
    "bash -n run/sudo.sh",
    "cat run/sudo.sh",
    "cat run/ok.sh | sed 's/^/sudo /' | bash",
    "python3 run/r.py",
    "bash run/nul.sh",
    "node run/r.js",
];

const WRAPPED_TEMPLATES: &[&str] = &[
    "timeout 9 @@",
    "timeout -s KILL 9 @@",
    "nice -n 5 @@",
    "env -i X=1 @@",
    "caffeinate -i @@",
    "xargs -I{} @@",
    "setsid @@",
    "ssh host '@@'",
    "ssh -p 22 host @@",
    "ssh host <<EOF\n@@\nEOF\n",
    "echo '@@' | ssh host",
    "find . -exec @@ {} +",
    r"find . -exec sh -c '@@' \;",
    "su -c '@@'",
    "runuser -u app -- @@",
    "sg docker -c '@@'",
    "docker exec -it web sh -c '@@'",
    "docker run --rm -e A=1 img @@",
    "kubectl exec pod -- @@",
    "docker compose exec app @@",
    "watch -n 1 '@@'",
    "script -q /dev/null @@",
    "flock /tmp/l -c '@@'",
    "env -S '@@'",
    "eval \"$(cat <<EOF\n@@\nEOF\n)\"",
    "bash <(cat <<EOF\n@@\nEOF\n)",
    "c='@@'; bash -c \"$c\"",
    "c='@@'; $c",
    "cat > run.sh <<EOF\n@@\nEOF\nbash run.sh",
    "echo '@@' > run.sh; sh run.sh",
    "x=\"$(case $y in a) bash <<EOF;; esac\n@@\nEOF\n)\"",
    "echo $(echo $(echo $(echo $(@@))))",
    "echo \"$(case a in a) @@;; esac)\"",
    "echo `@@`",
    "rm -rf build 2>/dev/null",
    "rm -rf dist >/dev/null 2>&1",
    "rm -rf /srv/x 2>/dev/null",
    "cat $(true) .env",
    "rm -rf $(true) /srv/x",
    "rm -rf $(mktemp -d)/x",
    "x=$(date); @@",
    "echo $(pwd)&& @@",
    "echo \"$(@@)\"",
    "x=`@@`",
    "echo \"a `@@` b\"",
    "[[ -f .env ]] && echo y",
    "[[ -f .env && -s .env.local ]]",
    "[ ! -f .env ] && touch .env",
    "test ! -e .envrc",
    "if true; then @@; fi",
    "sed 's#^#@@ #' <<EOF | bash\nx\nEOF\n",
    "sed -E 's#(.*)#@@#' <<'EOF' | sh\nls\nEOF\n",
    "sed '1i @@' <<EOF | bash\nls\nEOF\n",
    "cat <<EOF | sed 's#^#@@ #' | bash\nx\nEOF\n",
    "echo x | sed 's#^#@@ #' | bash",
    "awk '{print \"@@ \" $0}' <<EOF | sh\nx\nEOF\n",
    "perl -pe 's#^#@@ #' <<EOF | bash\nx\nEOF\n",
    "awk 'BEGIN{system(\"@@\")}'",
    "awk '{system(\"@@ \" $1)}' f.txt",
    "awk 'BEGIN { \"@@\" | getline x }'",
    "sed 'e @@' f.txt",
    "sed 's#.*#@@#e' f.txt",
    "echo x | sed 's#^#@@ #e'",
    "sed 's#^#@@ #e' <<EOF\nx\nEOF\n",
    "perl -e 'system(\"@@\")'",
    "python3 -c 'import os; os.system(\"@@\")'",
    "python3 - <<EOF\nimport subprocess\nsubprocess.run(\"@@\", shell=True)\nEOF\n",
    "node -e 'require(\"child_process\").execSync(\"@@\")'",
    "ruby -e 'puts `@@`'",
    "php -r 'shell_exec(\"@@\");'",
    "lua -e 'os.execute(\"@@\")'",
    "osascript -e 'do shell script \"@@\"'",
    "bun -e 'await $`@@`'",
    "python3 -c 'import os; c = \"@@\"; os.system(c)'",
    "python3 -c 'exec(\"import os; os.system(\\\"@@\\\")\")'",
    "node -e 'const cp = require(\"child_process\"); const c = \"@@\"; cp.execSync(c)'",
    "ruby -e 'eval(\"system(\\\"@@\\\")\")'",
    "perl -e 'my $c = \"@@\"; system($c)'",
    "php -r '$c = \"@@\"; shell_exec($c);'",
    "CMD='@@' python3 -c 'import os; os.system(os.environ[\"CMD\"])'",
    "CMD='@@' node -e 'require(\"child_process\").execSync(process.env.CMD)'",
    "python3 -c 'import os; getattr(os, \"system\")(\"@@\")'",
    "ruby -e 'send(:system, \"@@\")'",
    "php -r 'call_user_func(\"system\", \"@@\");'",
    "echo '@@' > cmd.txt; python3 -c 'import os; os.system(open(\"cmd.txt\").read())'",
    "{ @@; }",
];

fn generate(rng: &mut Rng, dir: &str) -> String {
    let p = "pip";
    let verbs = sv(&[
        "cat",
        "rm",
        "git",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "jq",
        "yq",
        "gojq",
        "cp",
        "install",
        "sudo",
        "source",
        ".",
        "ls",
        "echo",
        "printf",
        "head",
        "sed",
        "test",
        "[",
        "ln",
        "chmod",
        "docker",
        "python3",
        p,
        "pip3",
        "python",
        "uv",
        "bash",
        "sh",
        "eval",
        "/usr/bin/cat",
        "./rm",
        "/bin/rm",
        "less",
        "base64",
        "tail",
        "sort",
        "touch",
    ]);
    let prefixes = sv(&[
        "FOO=1", "env", "xargs", "nice", "do", "then", "{", "command", "time", "if", "A_B=x",
    ]);
    let mut args = sv(&[
        ".env",
        ".env.local",
        ".env.production",
        ".env.example",
        ".env.sample",
        ".env.template",
        "prod.env",
        "x.env",
        ".envrc",
        ".envrc.example",
        "config/.env",
        "./.env",
        "../.env",
        "*.env",
        ".env*",
        ".env.?",
        "*",
        "*.md",
        ".env{,.prod}",
        "{a,.env}",
        "{a,{b,.env.production}}",
        "config{,.local}.json",
        ".env[.]local",
        ".env[i-0]",
        "[i-0]",
        "[!a].env",
        "[a-z].env",
        ".e[n]v",
        "[]].env",
        "[!]].env",
        "[a--b]",
        "-rf",
        "-r",
        "-f",
        "-fr",
        "-Rf",
        "-rR",
        "--recursive",
        "--force",
        "-rn",
        "-uf",
        "--force-with-lease",
        "push",
        "origin",
        "main",
        "--hidden",
        "--no-ignore",
        "--no-ignore-vcs",
        "-uu",
        "-.",
        "-g",
        "'!.env*'",
        "--glob=!**/.env*",
        "-g!.env*",
        "'!node_modules'",
        "--iglob",
        "'!*.env*'",
        "/tmp/x",
        "/private/tmp/y",
        "/srv/x",
        "/",
        "~",
        "~/x",
        "$HOME/x",
        "${HOME}/x",
        "\"$HOME\"",
        "$TMPDIR/x",
        "/tmp",
        "/tmp/../srv/x",
        "/private/var/folders/aa/bb/T/z",
        "/private/var/folders/aa/bb/T",
        "--",
        "-n",
        "-e",
        "'.env.X'",
        ".env.X",
        "'.'",
        "x.json",
        "--from-file=.env.local",
        "--arg",
        "k",
        "v",
        "--rawfile",
        "s",
        "--slurpfile",
        "--indent",
        "4",
        "eval",
        "-o",
        "json",
        "--env-file=.env",
        "--env-file",
        "-m",
        "644",
        "\"quoted .env\"",
        "'single .env'",
        "\\.env",
        "a\\ b",
        "#comment",
        "\"$f\"",
        "'{}'",
        "{}",
        "\"{} in the env\"",
        "i-0e2",
        "\"Reservations[].Instances[?InstanceId=='i-0e2']\"",
        "é",
        "日本.env",
        "--include=*.php",
        "-R",
        "--exclude=.env",
        "-L",
        "--library-path",
        "ea",
        "--expression",
        "-I",
        "--front-matter",
        "''",
        "\"\"",
        "-",
        "--from-file",
        "x=.env",
        "--opt=.env",
        "--opt=!x",
        "a,b",
        "{,}",
        "{.env}",
        "{x,y}{,.env}",
    ]);
    for a in [
        "{D}/.env*",
        "{D}/*",
        "{D}/sub/*",
        "{D}/*/.env*",
        "{D}/[.]env",
        "{D}/.e*",
        "{D}/*.md",
        "{D}/sub/.env{,.x}",
        "{D}/link/x",
        "{D}/sub/../x",
        "{D}/sublink/*",
        "{D}/.hidden/*",
        "{D}/*.env",
        "{D}/[i-0]*",
        "{D}/data[1].txt",
        "{D}/dir.env/*",
        "{D}/*/",
        "{D}/sub",
        "{D}",
        "{D}/link",
        "{D}/nope/*",
    ] {
        args.push(a.replace("{D}", dir));
    }
    let seps = sv(&[
        " ", " ", " ", " ", " ; ", ";", " && ", " || ", " | ", "|", " & ", "(", ")", " ! ", "\n",
        " > ", " >> ", " < ", " 2>&1 ", " &> ", " ;; ", " >| ", "\t",
    ]);
    let tails = sv(&[
        " <<EOF\nrm -rf /srv/x\nEOF\n",
        " <<'X'\ncat .env\nX\n",
        " <<-EOF\n\tsudo ls\n\tEOF\n",
        " <<< \"rm -rf /\"",
        " <<EOF\ncat .env",
        "\nEOF",
        " <<\"Q\"\ngit push -f\nQ\n",
        " <<'Q\nsudo x\nQ\n",
    ]);
    let noise = sv(&["\"", "'", "\\", "#", "`", "$(", "\r"]);
    let c_opts = sv(&[" -c ", " -lc ", " -ec ", " -o pipefail -c ", " -x -c "]);
    let c_strings: Vec<String> = [
        "'ls -la'",
        "'sudo ls'",
        "'rm -rf /srv/x'",
        "'rm -rf /tmp/x'",
        "'cat .env'",
        "'cat .env.example'",
        "'grep -r x .'",
        "'rg --hidden x'",
        "'git push -f'",
        "'git push --force-with-lease'",
        "'rust-anything build x'",
        "'rust-anything map'",
        "\"sh -c 'sudo ls'\"",
        "'echo \"unterminated'",
        "'PIP install x'",
        "'cd x && python3 -m PIP install y'",
    ]
    .iter()
    .map(|c| c.replace("PIP", p))
    .collect();
    let heredoc_bodies = [
        "ls -la",
        "sudo ls",
        "rm -rf /srv/x",
        "rm -rf /tmp/x",
        "cat .env",
        "grep -r x .",
        "rg --hidden x",
        "git push -f",
        "rust-anything build x",
        "PIP install x",
    ];
    let mut out = String::new();
    let segs = 1 + rng.below(4);
    for s in 0..segs {
        if s > 0 {
            out.push_str(rng.pick(&seps));
        }
        // Commands run by wrappers, remote and container commands, user switches, find -exec, string runners,
        // heredoc output, variables, scripts written and run, case patterns: `@@` is a rule's command.
        if rng.chance(3) {
            out.push_str(SCRIPT_RUNS[rng.below(SCRIPT_RUNS.len())]);
            continue;
        }
        if rng.chance(8) {
            let t = WRAPPED_TEMPLATES[rng.below(WRAPPED_TEMPLATES.len())];
            let body = heredoc_bodies[rng.below(heredoc_bodies.len())].replace("PIP", p);
            out.push_str(&t.replace("@@", &body));
            continue;
        }
        if rng.chance(15) {
            out.push_str(rng.pick(&prefixes));
            out.push(' ');
        }
        let verb = rng.pick(&verbs).to_string();
        out.push_str(&verb);
        if verb == p || verb == "pip3" || (verb.starts_with("python") && rng.chance(50)) {
            if verb.starts_with("python") {
                out.push_str(" -m pip");
            }
            out.push_str(if rng.chance(80) {
                " install x"
            } else {
                " list"
            });
        }
        // Strings run as commands: checked with every rule in Rust, one word to the Python guard (known_difference).
        if (verb == "bash" || verb == "sh") && rng.chance(30) {
            if rng.chance(70) {
                out.push_str(rng.pick(&c_opts));
            } else {
                out.push_str(" <<< ");
            }
            out.push_str(rng.pick(&c_strings));
            continue;
        }
        if (verb == "echo" || verb == "printf") && rng.chance(25) {
            let to = [
                "bash",
                "sh",
                "sh -s",
                "zsh",
                "source /dev/stdin",
                ". /dev/stdin",
                "bash -c cat",
            ];
            out.push(' ');
            out.push_str(rng.pick(&c_strings));
            out.push_str(" | ");
            out.push_str(to[rng.below(to.len())]);
            continue;
        }
        // A heredoc inside a quoted `-c` string, or a `<<WORD` in quotes or a comment before a later line.
        if (verb == "bash" || verb == "sh") && rng.chance(15) {
            let readers = ["bash", "sh", "cat", "source /dev/stdin", "cat > notes.md"];
            let body = heredoc_bodies[rng.below(heredoc_bodies.len())].replace("PIP", p);
            let after = heredoc_bodies[rng.below(heredoc_bodies.len())].replace("PIP", p);
            let (q, delim) = if rng.chance(50) {
                ('\'', "EOF")
            } else {
                ('"', "'X'")
            };
            let end = delim.trim_matches('\'');
            out.push_str(&format!(
                " -c {q}{} <<{delim}\n{body}\n{end}",
                readers[rng.below(readers.len())]
            ));
            if rng.chance(50) {
                out.push_str(&format!("\n{after}"));
            }
            out.push(q);
            continue;
        }
        // A heredoc read by cat or a filter (grep -v), through more filters (sed), piped into a shell or into
        // something else, on its own line or on the line after the body (`cat <<EOF |`).
        if (verb == "cat" || verb == "tee" || verb == "grep") && rng.chance(20) {
            let to = [
                "bash",
                "sh -s",
                "zsh",
                "source /dev/stdin",
                ". /dev/stdin",
                "timeout 9 bash",
                "bash -c cat",
                "grep x",
                "wc -l",
            ];
            let body = heredoc_bodies[rng.below(heredoc_bodies.len())].replace("PIP", p);
            let delim = ["EOF", "'EOF'", "\"EOF\""][rng.below(3)];
            let target = to[rng.below(to.len())];
            if verb == "grep" {
                out.push_str(" -v zz");
            }
            let filter = if rng.chance(30) { " | sed s/a/b/" } else { "" };
            if rng.chance(40) {
                let gap = ["", "\n", "\n# then\n"][rng.below(3)];
                out.push_str(&format!(
                    " <<{delim}{filter} |\n{body}\nEOF\n{gap}{target}\n"
                ));
            } else {
                out.push_str(&format!(" <<{delim}{filter} | {target}\n{body}\nEOF\n"));
            }
            continue;
        }
        if verb == "echo" && rng.chance(10) {
            let body = heredoc_bodies[rng.below(heredoc_bodies.len())].replace("PIP", p);
            let hide = ["'a <<EOF'", "\"see <<EOF\"", "x # <<EOF"];
            out.push_str(&format!(" {}\n{body}", hide[rng.below(hide.len())]));
            continue;
        }
        if verb == "eval" && rng.chance(40) {
            out.push(' ');
            out.push_str(rng.pick(&c_strings));
            continue;
        }
        if (verb == "source" || verb == ".") && rng.chance(40) {
            let c = rng.pick(&c_strings).to_string();
            if rng.chance(50) {
                out.push_str(&format!(" /dev/stdin <<< {c}"));
            } else {
                out.push_str(&format!(" <(echo {c})"));
            }
            continue;
        }
        if (verb == "bash" || verb == "sh") && rng.chance(40) {
            out.push_str(rng.pick(&tails));
            continue;
        }
        for _ in 0..rng.below(6) {
            out.push(' ');
            out.push_str(rng.pick(&args));
        }
        if rng.chance(8) {
            out.push_str(rng.pick(&tails));
        }
    }
    if rng.chance(5) {
        let at = rng.below(out.len() + 1);
        if out.is_char_boundary(at) {
            out.insert_str(at, rng.pick(&noise));
        }
    }
    out
}

fn hook_input(cmd: &str, cwd: &Value) -> String {
    let mut v = json!({"session_id": "diff", "tool_use_id": "toolu_diff", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}});
    if !cwd.is_null() {
        v["cwd"] = cwd.clone();
    }
    v.to_string()
}

fn run_with(cmd: &[&str], input: &str) -> Out {
    let mut child = Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    let o = child.wait_with_output().unwrap();
    Out {
        stdout: String::from_utf8_lossy(&o.stdout).into(),
        code: o.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&o.stderr).into(),
    }
}

fn parallel<T: Send + Sync, R: Send>(
    items: &[T],
    workers: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let next = Mutex::new(0usize);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..workers.max(1) {
            s.spawn(|| {
                loop {
                    let i = {
                        let mut n = next.lock().unwrap();
                        let i = *n;
                        *n += 1;
                        i
                    };
                    if i >= items.len() {
                        break;
                    }
                    let r = f(&items[i]);
                    results.lock().unwrap()[i] = Some(r);
                }
            });
        }
    });
    results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(Option::unwrap)
        .collect()
}

/// Which string-run-as-command form the hook input's command holds, if any: `bash -c`, eval, a here-string fed
/// to a shell, `source` or `.`, or process substitution.
fn nested_kind(input: &str) -> Option<&'static str> {
    let v: Value = serde_json::from_str(input).unwrap_or(Value::Null);
    let cmd = v["tool_input"]["command"].as_str().unwrap_or("");
    let words: Vec<&str> = cmd
        .split(|c: char| c.is_whitespace() || ";&|()".contains(c))
        .filter(|w| !w.is_empty())
        .collect();
    // A backslash inside a word only quotes the next letter (`e\\val` is eval).
    let base = |w: &str| unquoted_base(w).replace('\\', "");
    let shells = ["bash", "sh", "zsh", "dash", "ksh"];
    let shell_c = words.iter().enumerate().any(|(i, w)| {
        shells.contains(&base(w).as_str())
            && words[i + 1..].iter().any(|a| {
                a.starts_with('-')
                    && !a.starts_with("--")
                    && a[1..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphabetic())
                        .any(|c| c == 'c')
            })
    });
    let stdin_shell = words.iter().any(|w| {
        let b = base(w);
        shells.contains(&b.as_str()) || b == "source" || b == "."
    });
    if shell_c {
        Some("shell-c-string")
    } else if words.iter().any(|w| base(w) == "eval") {
        Some("eval-string")
    } else if stdin_shell && cmd.contains("<<<") {
        Some("here-string")
    } else if stdin_shell && cmd.contains("<(") {
        Some("process-substitution")
    } else if piped_into_shell(cmd) {
        Some("piped-script")
    } else {
        None
    }
}

/// A command name in command position: at the start, after an operator, `$(`, a backtick, or the noise prefixes
/// the generator puts in front of a verb (`FOO=1`, `env`, `nice`, `then`, ...).
/// A cached regex for the classifiers (they run on every input).
fn rx(pattern: &str) -> regex::Regex {
    thread_local! {
        static CACHE: std::cell::RefCell<std::collections::HashMap<String, regex::Regex>> = Default::default();
    }
    CACHE.with(|c| {
        c.borrow_mut()
            .entry(pattern.to_string())
            .or_insert_with(|| regex::Regex::new(pattern).unwrap())
            .clone()
    })
}

fn at_command(names: &str) -> regex::Regex {
    rx(&format!(
        r#"(?:^|[;&|()\n`!]|\$\()\s*(?:(?:[A-Za-z_]\w*=(?:'[^']*'|"[^"]*"|\S*)|env|xargs|nice|do|then|else|\{{|command|time|if|!|exec|builtin|nohup)\s+)*(?:\S*/)?(?:{names})\b"#
    ))
}

/// Which Rust-only reading of a wrapped command the hook input's command holds, if any (all after the Python
/// reading passed). Each kind needs its own construct in command position, not just a word somewhere, so a block
/// on an unrelated command isn't excused.
fn wrapped_kind(input: &str) -> Option<&'static str> {
    let v: Value = serde_json::from_str(input).unwrap_or(Value::Null);
    let raw = v["tool_input"]["command"].as_str().unwrap_or("");
    // A backslash inside a word only quotes the next letter (`do\\cker` is docker, `./ru\\n/x` is ./run/x).
    let cmd = raw.replace('\\', "");
    let cmd = cmd.as_str();
    let m = |re: &str| rx(re).is_match(cmd);
    let interp = "python[\\d.]*|pypy3|perl|node|bun|deno|ruby|php|lua|osascript";
    let interp_at = at_command(interp).is_match(cmd);
    let assigned = rx(r"(?:^|[;&|(\n]\s*|export\s+|local\s+)([A-Za-z_]\w*)=")
        .captures_iter(cmd)
        .any(|c| cmd.contains(&format!("${}", &c[1])) || cmd.contains(&format!("${{{}}}", &c[1])));
    if m(r"(?:^|[\s;&|(<]|\./)run/[a-z]+\.(?:sh|py|js)\b") {
        Some("script-on-disk")
    } else if interp_at
        && [
            "environ", "getenv", "process.env", "ENV[", "$ENV{", "getattr", "readFileSync", "File.read",
            "file_get_contents", "io.open", "open(", "call_user_func", "send(:", "method(:", "[\"exec",
        ]
        .iter()
        .any(|k| cmd.contains(k))
    {
        // Interpreter code taking the command from the environment the command sets, a file, or an indirect call.
        Some("interpreter-dynamic")
    } else if interp_at
        && (cmd.contains(" = ") || cmd.contains("eval") || cmd.contains("exec(") || cmd.contains("set c to"))
    {
        // A command an interpreter's code builds from variables or runs through eval/exec of a built string.
        Some("interpreter-built")
    } else if interp_at {
        // Commands an interpreter's code runs (`python3 -c 'os.system(...)'`, `node -e`, code on stdin).
        Some("interpreter-command")
    } else if at_command("awk|gawk").is_match(cmd)
        && (cmd.contains("system(") || cmd.contains("getline") || m(r#"\|\s*""#))
    {
        // Commands awk runs itself.
        Some("awk-command")
    } else if at_command("sed|gsed").is_match(cmd) && m(r#"(?:'|;|\d|\$)e\s|[/#]e(?:\W|$)|\bsed\s+e\b"#) {
        // Commands sed runs itself (`e CMD`, `s///e`).
        Some("sed-exec")
    } else if m(r"(?s)\b(?:sed|awk|perl)\b.*\|\s*(?:\S*/)?(?:bash|sh|zsh|dash|source|\.)\b") {
        // A filter on the way to a shell builds the command (`sed 's/^/sudo /' <<EOF | bash`).
        Some("filter-built")
    } else if cmd.contains("$(case") {
        Some("case-in-substitution")
    } else if m(r"(?:\$\(|<\()\s*\w+[^)]*<<") {
        Some("heredoc-output-run")
    } else if assigned {
        Some("variable-expansion")
    } else if m(r"(?:>|\btee)\s*\S*\.sh\b") {
        Some("script-file")
    } else if at_command("ssh").is_match(cmd) {
        Some("ssh-command")
    } else if m(r"\bfind\b.*\s-(?:exec|execdir|ok|okdir)\b") {
        Some("find-exec")
    } else if at_command("su|runuser|sg").is_match(cmd) {
        Some("user-switch")
    } else if at_command("docker|podman|nerdctl|docker-compose|kubectl|oc").is_match(cmd) {
        Some("container-command")
    } else if at_command("watch|script|flock").is_match(cmd) || m(r"\benv\s+-S") {
        Some("string-runner")
    } else if at_command(
        "timeout|gtimeout|caffeinate|stdbuf|arch|nice|env|xargs|setsid|ionice|chroot|taskset|chrt|unbuffer|sandbox-exec|doas|pkexec|exec|time|command|nohup|builtin",
    )
    .is_match(cmd)
    {
        Some("argv-wrapper")
    } else {
        None
    }
}

fn input_command(input: &str) -> String {
    let v: Value = serde_json::from_str(input).unwrap_or(Value::Null);
    v["tool_input"]["command"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

/// True if the command has a `)` glued to an operator (`);`, `)&&`, `)|`), or one glued to `(` (`;(`).
fn glued_operator(input: &str) -> bool {
    let cmd = input_command(input);
    rx(r"\)[;&|<>!]|[;&|!]\(").is_match(&cmd)
}

/// True if the command holds `$(` inside double quotes, or a backtick outside single quotes (roughly).
fn quoted_substitution(input: &str) -> bool {
    let cmd = input_command(input);
    let (mut single, mut double) = (false, false);
    let chars: Vec<char> = cmd.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        match c {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '`' if !single => return true,
            '$' if double && chars.get(i + 1) == Some(&'(') => return true,
            _ => {}
        }
    }
    false
}

/// A test command (`[[`, `[`, `test`) holding `!`, `(`, `&&`, `||` or `|`: Rust keeps those words in the test (as
/// bash does: `[[ -f .env && -s .env ]]`, `[ ! -f .env ]`, the glob `[!a].env`); the Python guard split the command
/// there and checked the rest as commands of their own.
fn test_bracket(input: &str) -> bool {
    let cmd = input_command(input);
    let has_test = cmd.contains("[[")
        || cmd
            .split(|c: char| c.is_whitespace() || ";&|(){}".contains(c))
            .any(|w| w == "[" || w == "test" || w.starts_with("[!"));
    has_test
        && ["!", "(", ")", "&", "|", "`"]
            .iter()
            .any(|op| cmd.contains(op))
}

/// True if a line of the hook input's command has a `<<WORD` followed by a pipe into a shell, `source` or `.`, on
/// that line or, when the line ends in `|`, as the first word of a later line.
fn heredoc_piped_to_shell(input: &str) -> bool {
    let v: Value = serde_json::from_str(input).unwrap_or(Value::Null);
    let cmd = v["tool_input"]["command"].as_str().unwrap_or("");
    let shellish = |piece: &str| {
        let first = piece
            .split(|c: char| c.is_whitespace() || "();&".contains(c))
            .find(|x| !x.is_empty())
            .unwrap_or("");
        [
            "bash", "sh", "zsh", "dash", "ksh", "source", ".", "timeout", "env",
        ]
        .contains(&unquoted_base(first))
    };
    let lines: Vec<&str> = cmd.split('\n').collect();
    lines.iter().enumerate().any(|(i, line)| {
        line.split_once("<<").is_some_and(|(_, after)| {
            after.split('|').skip(1).any(shellish)
                || (after.trim_end().ends_with('|')
                    && lines[i + 1..].iter().any(|l| l.split('|').any(shellish)))
        })
    })
}

/// True if a `<<WORD` in the hook input's command sits inside quotes or a comment on its line (roughly: an odd
/// number of ' or " before it, or a `#` word before it).
fn quoted_heredoc(input: &str) -> bool {
    let v: Value = serde_json::from_str(input).unwrap_or(Value::Null);
    let cmd = v["tool_input"]["command"].as_str().unwrap_or("");
    let mut seen = String::new();
    cmd.split('\n').any(|line| {
        let hit = line.match_indices("<<").any(|(i, _)| {
            let next = line[i + 2..].trim_start_matches(['-', ' ', '\'', '"']);
            if !next.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
                return false;
            }
            let before = format!("{seen}{}", &line[..i]);
            before.matches('\'').count() % 2 == 1
                || before.matches('"').count() % 2 == 1
                || line[..i].split_whitespace().any(|w| w.starts_with('#'))
        });
        seen.push_str(line);
        seen.push('\n');
        hit
    })
}

/// A word's command name as the shell sees it: leading quotes and backslashes dropped (`\\eval`, `"bash"`), then
/// the folder (`/bin/bash`).
fn unquoted_base(w: &str) -> &str {
    let w = w.trim_start_matches(['\'', '"', '\\']);
    w.rsplit('/').next().unwrap_or(w)
}

/// True if an echo or printf segment is piped straight into a shell, `source` or `.`.
fn piped_into_shell(cmd: &str) -> bool {
    // `>|` is a redirection, not a pipe.
    let cmd = cmd.replace(">|", ">");
    let pieces: Vec<&str> = cmd.split('|').collect();
    pieces.windows(2).any(|w| {
        let printer = w[0]
            .split(|c: char| c.is_whitespace() || ";&()".contains(c))
            .any(|x| ["echo", "printf"].contains(&unquoted_base(x)));
        let first = w[1]
            .split(|c: char| c.is_whitespace() || "();&".contains(c))
            .find(|x| !x.is_empty() && !x.contains('='))
            .unwrap_or("");
        // A backslash inside a word only quotes the next letter (`z\\sh` is zsh).
        let first = unquoted_base(first).replace('\\', "");
        let first = first.as_str();
        printer
            && [
                "bash", "sh", "zsh", "dash", "ksh", "source", ".", "env", "timeout",
            ]
            .contains(&first)
    })
}

fn rule(stdout: &str) -> String {
    let v: Value = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
    let r = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    let r = r.strip_prefix("guard-bash: ").unwrap_or(r);
    r.split([' ', '(']).take(3).collect::<Vec<_>>().join(" ")
}

#[test]
fn rust_matches_python_and_dash() {
    let home = env_or("HOME", "/");
    let ref_bash = env_or(
        "CLAUDE_GUARD_REF_BASH",
        &format!("{home}/.claude/hooks/guard-bash.py"),
    );
    let ref_pip = env_or(
        "CLAUDE_GUARD_REF_PIP",
        &format!("{home}/.claude/hooks/block-pip.sh"),
    );
    if !std::path::Path::new(&ref_bash).exists() || !std::path::Path::new(&ref_pip).exists() {
        eprintln!("SKIPPED: reference hooks not found ({ref_bash}, {ref_pip})");
        return;
    }
    let n: usize = env_or("CLAUDE_GUARD_DIFF_CASES", "4000").parse().unwrap();
    let seed: u64 = env_or("CLAUDE_GUARD_DIFF_SEED", "20261124")
        .parse()
        .unwrap();
    let workers: usize = env_or("CLAUDE_GUARD_DIFF_WORKERS", "2").parse().unwrap();
    let dir = fixture_dir();
    let tmp = std::env::var("TMPDIR")
        .unwrap_or_else(|_| "/tmp".into())
        .trim_end_matches('/')
        .to_string();

    // Inputs: fixture cases (no cwd), generated commands with assorted cwd values, raw JSON edge inputs.
    let mut inputs: Vec<String> = Vec::new();
    for line in include_str!("fixtures/guard_bash_cases.tsv").lines() {
        if let Some((_, cmd)) = line.split_once('\t').filter(|_| !line.starts_with('#')) {
            let cmd = cmd.replace("{TMPDIR}", &tmp).replace('⏎', "\n");
            inputs.push(hook_input(&cmd, &Value::Null));
            inputs.push(hook_input(&cmd, &json!(dir)));
        }
    }
    let cwds = [
        Value::Null,
        json!(""),
        json!(dir),
        json!(format!("{dir}/")),
        json!("/nonexistent"),
        json!("/tmp"),
        json!(0),
        json!(5),
        json!(["x"]),
        json!(false),
    ];
    let mut rng = Rng(seed | 1);
    for _ in 0..n {
        let cmd = generate(&mut rng, &dir);
        let cwd = if rng.chance(45) {
            json!(dir)
        } else {
            cwds[rng.below(cwds.len())].clone()
        };
        inputs.push(hook_input(&cmd, &cwd));
    }
    for raw in [
        "",
        "not json",
        "{}",
        "[]",
        "null",
        "5",
        "\"x\"",
        "{\"tool_input\": null}",
        "{\"tool_input\": \"x\"}",
        "{\"tool_input\": []}",
        "{\"tool_input\": {}}",
        "{\"tool_input\": {\"command\": null}}",
        "{\"tool_input\": {\"command\": 0}}",
        "{\"tool_input\": {\"command\": \"\"}}",
        "{\"tool_input\": {\"command\": [\"sudo\"]}}",
        "{\"tool_input\": {\"command\": 5}}",
        "{\"tool_input\": {\"command\": true}}",
        "{\"tool_input\": {\"command\": 1.5}}",
        "{\"tool_input\": {\"command\": {\"a\": 1}}}",
        "{\"tool_input\": {\"command\": []}}",
        "{\"tool_input\": {\"command\": \"sudo ls\"}, \"cwd\": {}}",
        "{\"tool_input\": {\"command\": \"cat *.env\"}, \"cwd\": {\"a\": 1}}",
        "{\"tool_input\": {\"command\": \"cat .env\"}} trailing",
        "{\"tool_input\": {\"command\": \"sudo ls\"}, \"x\": NaN}",
        "{\"tool_input\": {\"command\": \"sudo \\ud800\"}}",
        "{\"tool_input\": {\"command\": \"cat .env\\n\"}}",
        "{\"tool_input\": {\"command\": \"cat \\\".env\\n\\\"\"}}",
        "{\"tool_input\": {\"command\": \"sudo ls\"}, \"tool_input\": {\"command\": \"ls\"}}",
        "\u{feff}{\"tool_input\": {\"command\": \"sudo x\"}}",
    ] {
        inputs.push(raw.to_string());
    }
    // More pieces than one check reads: the work budget blocks it (the Python guard never followed them).
    {
        let wide = format!(
            "echo {}",
            (0..12_000)
                .map(|i| format!("$(ls {i})"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        inputs.push(hook_input(&wide, &Value::Null));
    }

    // Reference: guard-bash.py in-process (driver), block-pip.sh per input.
    let driver = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference_driver.py");
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", driver, "bash", &ref_bash])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        let feed: String = inputs
            .iter()
            .map(|i| json!({"input": i}).to_string() + "\n")
            .collect();
        std::thread::spawn(move || {
            let _ = stdin.write_all(feed.as_bytes());
        });
    }
    let py_out = child.wait_with_output().unwrap();
    let py: Vec<Value> = String::from_utf8_lossy(&py_out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        py.len(),
        inputs.len(),
        "driver answered {} of {}",
        py.len(),
        inputs.len()
    );

    let pip: Vec<Out> = parallel(&inputs, workers, |i| run_with(&["/bin/dash", &ref_pip], i));
    let crash_log = format!(
        "{}/claude-guard-diff-bash-crash-{}.log",
        tmp,
        std::process::id()
    );
    let rust: Vec<Out> = parallel(&inputs, workers, |i| {
        run_with(&[BIN, "bash", "--crash-log", &crash_log], i)
    });

    // Spot check: the in-process driver gives what a real `python3 -I guard-bash.py` run prints.
    let spot: Vec<usize> = (0..inputs.len())
        .step_by((inputs.len() / 60).max(1))
        .collect();
    let real: Vec<Out> = parallel(&spot, workers, |&i| {
        run_with(&["/usr/bin/python3", "-I", &ref_bash], &inputs[i])
    });
    for (k, &i) in spot.iter().enumerate() {
        let d = py[i]["stdout"].as_str().unwrap_or("");
        // Crash texts name the crash log, which the driver points at a temp file.
        let both_crashed =
            d.contains("guard-bash crashed") && real[k].stdout.contains("guard-bash crashed");
        if py[i]["error"].is_null() && !both_crashed {
            assert_eq!(
                real[k].stdout, d,
                "driver vs real run differ on input {i}: {}",
                inputs[i]
            );
        }
    }

    let (mut same, mut known, mut bad) = (0, Vec::new(), Vec::new());
    let mut blocked = 0;
    for i in 0..inputs.len() {
        let p_err = py[i]["error"].as_str();
        let p_stdout = py[i]["stdout"].as_str().unwrap_or("").to_string();
        let reference = if !p_stdout.is_empty() {
            Out {
                stdout: p_stdout,
                code: 0,
                stderr: String::new(),
            }
        } else if pip[i].code == 2 {
            Out {
                stdout: String::new(),
                code: 2,
                stderr: format!("{PIP_MSG}\n"),
            }
        } else {
            Out {
                stdout: String::new(),
                code: 0,
                stderr: String::new(),
            }
        };
        let r = &rust[i];
        if r.code == 2 || !r.stdout.is_empty() {
            blocked += 1;
        }
        if p_err.is_none() && *r == reference {
            same += 1;
            continue;
        }
        match known_difference(p_err, &reference, r, &inputs[i]) {
            Some(why) => known.push(why),
            None => bad.push(format!(
                "input: {}\n  reference: {:?} (python error: {:?})\n  rust:      {:?}",
                inputs[i], reference, p_err, r
            )),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&crash_log);
    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for k in &known {
        *counts.entry(k).or_default() += 1;
    }
    eprintln!(
        "differential: {} inputs, {same} identical, {} known differences {:?}, {} unexpected; {blocked} blocked; {} driver spot checks",
        inputs.len(),
        known.len(),
        counts,
        bad.len(),
        spot.len()
    );
    assert!(
        bad.is_empty(),
        "{} unexpected differences (first 15):\n{}",
        bad.len(),
        bad.iter().take(60).cloned().collect::<Vec<_>>().join("\n")
    );
    // Every known difference must still excuse something in a full-size run: one that matches nothing is stale
    // (drop it) or the generator stopped producing its input (fix the generator).
    if n >= 20_000 {
        let stale: Vec<&&str> = KNOWN_KINDS
            .iter()
            .filter(|k| !counts.contains_key(**k))
            .collect();
        assert!(
            stale.is_empty(),
            "known differences that matched nothing: {stale:?}"
        );
    }
}

/// Every kind `known_difference` can return.
const KNOWN_KINDS: &[&str] = &[
    "both-crashed",
    "rust-anything-rule",
    "shell-c-string",
    "eval-string",
    "here-string",
    "process-substitution",
    "piped-script",
    "newline-separator",
    "quoted-heredoc",
    "heredoc-piped-to-shell",
    "glued-operator",
    "case-arm-end",
    "quoted-substitution",
    "pip-in-simple-command",
    "test-bracket",
    "script-on-disk",
    "interpreter-dynamic",
    "interpreter-built",
    "interpreter-command",
    "awk-command",
    "sed-exec",
    "filter-built",
    "case-in-substitution",
    "heredoc-output-run",
    "variable-expansion",
    "script-file",
    "ssh-command",
    "find-exec",
    "user-switch",
    "container-command",
    "string-runner",
    "argv-wrapper",
    "work-budget",
    "rm-redirect-target",
    "substitution-word",
];

/// A `$(...)` or backticks with more of the same simple command after it: its closing `)` or backtick (glued to
/// more of the word or not) followed by a word or `(`, not an operator or the end.
fn words_after_substitution(input: &str) -> bool {
    let cmd = input_command(input);
    (cmd.contains("$(") || cmd.contains('`'))
        && rx(r"[)`][^\s;&|]*(?:[ \t]+[^\s;&|#)]|\()").is_match(&cmd)
}

/// Differences that are intended. Anything else fails the test.
fn known_difference(
    _p_err: Option<&str>,
    reference: &Out,
    rust: &Out,
    input: &str,
) -> Option<&'static str> {
    // Both crashed and blocked; the texts name each guard's own crash log.
    if reference.stdout.contains("guard-bash crashed") && rust.stdout.contains("guard-bash crashed")
    {
        return Some("both-crashed");
    }
    // `[[ -f .env ]]`, `[ ! -f .env ]`: an existence test in Rust (allowed); the Python guard split the test and read
    // `.env` as a file a command opens.
    // Also when both block but name other files, and when the test swallows a stray `)` or a missing `]]` (a syntax
    // error bash refuses, so nothing runs).
    if reference.stdout.contains("\"deny\"")
        && (reference.stdout != rust.stdout || reference.code != rust.code)
        && test_bracket(input)
    {
        return Some("test-bracket");
    }
    // The work budget: more pieces than one check reads (deep nesting the Python guard never followed).
    if rust
        .stdout
        .contains("more nested commands, strings and scripts")
    {
        return Some("work-budget");
    }
    // A redirect's target (`rm -rf x 2>/dev/null`) isn't an rm path in Rust; the Python guard listed it, so it
    // blocked (or named it) where Rust allows (or names only the real paths).
    if reference.stdout.contains("recursive force delete")
        && reference.stdout != rust.stdout
        && input_command(input).contains('>')
    {
        return Some("rm-redirect-target");
    }
    // The rust-anything rule is Rust only (added after the port); Python allows those commands, or blocks them for
    // a later rule when Rust's check reaches the rust-anything run first (a heredoc body fed to a shell is checked
    // before the rest of the command). Same decision then; only the reason differs.
    // Also when Python only reached block-pip (exit 2) and Rust's check reached the rust-anything run first.
    if (reference.code == 0 || (reference.code == 2 && reference.stdout.is_empty()))
        && rust.code == 0
        && rule(&rust.stdout).starts_with("rust-anything ")
        && (reference.stdout.is_empty() || reference.stdout.contains("\"deny\""))
    {
        return Some("rust-anything-rule");
    }
    // Strings run as commands (`bash -c`, eval, here-strings, `source <(echo ...)`, `echo ... | bash`) are checked
    // with every rule in Rust (pip included); Python read each as one word. Rust checks them only after the rest
    // of the command passed, so the difference is always Python letting through (allow, or block-pip's exit 2)
    // what Rust blocks.
    // A crash blocks too (fail closed): a line or string checked on its own can reach a check that raises in both
    // guards (a glob with a cwd that isn't text), which the Python guard's reading never reached.
    let rust_blocks =
        (rust.code == 0 && !rust.stdout.is_empty()) || (rust.code == 2 && rust.stdout.is_empty());
    if reference.stdout.is_empty() && rust_blocks {
        // A `<<WORD` inside quotes or a comment is no heredoc in Rust's newline pass (a heredoc in a quoted `-c`
        // string stays in the string, checked on its own); the Python guard cut its "body" out of the string.
        // A `)` glued to an operator (`x=$(date); sudo ls`): Rust splits the run into operators, the Python guard
        // read it as one word.
        if glued_operator(input) {
            return Some("glued-operator");
        }
        if let Some(kind) = wrapped_kind(input) {
            return Some(kind);
        }
        // `;;` (a case arm's end) ends the command before it in Rust's newline pass; outside a case, bash refuses it
        // as a syntax error, so nothing runs. The Python guard read `;;` as a word.
        if input_command(input).contains(";;") {
            return Some("case-arm-end");
        }
        // A cat or tee heredoc piped into a shell runs its body in Rust's newline pass; the Python guard read the
        // body as data.
        if heredoc_piped_to_shell(input) {
            return Some("heredoc-piped-to-shell");
        }
        if quoted_heredoc(input) {
            return Some("quoted-heredoc");
        }
        if let Some(kind) = nested_kind(input) {
            return Some(kind);
        }
        // A command substitution in double quotes or backticks is checked in Rust; the Python guard's shlex read
        // `"$(...)"` as one word and never looked inside backticks.
        if quoted_substitution(input) {
            return Some("quoted-substitution");
        }
        // Words after an unquoted substitution (`cat $(true) .env`) stay in its simple command in Rust's newline
        // pass, which reads the substitution as one word; the Python guard ended the command at its `)`.
        if words_after_substitution(input) {
            return Some("substitution-word");
        }
        // pip run as a simple command after blanks, a keyword or an assignment (`then pip install`): block-pip's
        // pattern only matched at a line start or after ; & |.
        if rust.code == 2 && input_command(input).replace('\\', "").contains("install") {
            return Some("pip-in-simple-command");
        }
        // A newline outside quotes ends a command in Rust (second pass, after the Python reading passed); Python
        // read it as a space.
        let v: Value = serde_json::from_str(input).unwrap_or(Value::Null);
        if v["tool_input"]["command"]
            .as_str()
            .is_some_and(|c| c.contains('\n'))
        {
            return Some("newline-separator");
        }
    }
    None
}
