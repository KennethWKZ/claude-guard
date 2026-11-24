# claude-guard

Claude Code hooks in Rust: one binary, one subcommand per hook. It replaces Python and dash hooks in
`~/.claude/hooks/` one at a time, each after a differential test and a shadow week.

| Subcommand | Replaces | Hook | State |
| --- | --- | --- | --- |
| `claude-guard bash` | `guard-bash.py` + `block-pip.sh` | PreToolUse Bash | shadow since 2026-11-24 |
| `claude-guard read` | `guard-read-keys.py` | PreToolUse Read | shadow since 2026-11-24 |
| `claude-guard husky` | `husky-worktree-hooks.py` | PostToolUse Bash\|EnterWorktree, SessionStart | shadow since 2026-11-24 |
| `claude-guard prompt` | `guard-prompt.py` | UserPromptSubmit (and GraphMind's prompt hook, `--strict`) | shadow since 2026-11-24 |
| `claude-guard session-name` | `session-name-from-title.sh` | UserPromptSubmit, SessionStart | shadow since 2026-11-24 |
| `claude-guard dns-nxdomain` | `dns-nxdomain.py` (launchd agent `local.claude-guard.dns-nxdomain`) | not a hook: the DNS responder behind dns-blocklist | ported, not switched |
| `claude-guard web pre\|post` | `web-guard.sh` + `web-guard.py` | PreToolUse and PostToolUse (Bash, WebFetch, ccs-browser, ctx_index/ctx_search, WebSearch) | shadow since 2026-11-24 |

Why: a hook in Rust starts in about 7 ms and uses about 4 MB; `guard-bash.py` took 60 to 90 ms and 14 MB on every
Bash call (measured 2026-11-24 at load 13).

## What `claude-guard bash` does

Same rules, same messages, byte-for-byte the same output as the hooks it replaces:

1. `rm` with recursive and force flags on an absolute path (`~` and `$HOME` count) outside `$TMPDIR` and `/tmp`.
2. Commands that name a secrets env file (`.env`, `.env.local`, `prod.env`, `.envrc`, ...) directly, through a glob
   or through brace expansion; recursive `grep`; `rg --hidden`/`--no-ignore` without `-g '!.env*'`. Templates
   (`.env.example`, ...) stay readable, and jq/yq filters such as `'.env.FOO'` are not files.
3. `git push --force` / `-f`.
4. `sudo`.
5. `pip install` (exit 2 with "Do not use pip. Use uv instead...", after the rules above).

A quoting error in the command allows it, so a typo never locks the shell; any other failure blocks it (fail
closed) and is logged to `~/.local/state/claude-guard/bash-crash.log` (start of the command, mode 600;
`--crash-log <file>` moves it, which the tests do).

A non-string `command` (a number, bool or object) is allowed with one warning, as the Python guard does since
2026-11-24: it can't hide a shell command. Input nested too deep to check, or too deep to read as JSON (994 levels,
where Python's `json.load` stops), blocks in both.

Hook JSON is read the way Python's `json.load` reads it (`src/hookio.rs`): unpaired surrogate escapes (`\ud800`),
`NaN`, `Infinity` and numbers past f64's range (`1e400`) are accepted, and arrays and objects nest up to 993 levels
(serde_json alone stops at 128). A rejected input is allowed, so rejecting what Python read would let a command
through.

Porting notes: Python's `shlex` (posix, `punctuation_chars`), `glob`, `fnmatch` (including the `re.error` on bad
bracket ranges such as `[i-0]`) and `os.path.realpath` are ported in `src/bash/shlex.rs` and `src/bash/pyfs.rs`,
because the verdicts depend on their quirks. The `regex` crate has no lookaround or backreferences, so the heredoc
pattern is matched by hand; it runs in linear time, so no input can make the guard slow.

## What `claude-guard read` does

guard-read-keys.py's rules and messages, word for word: it refuses key and certificate-store files by name (the
requested path and the path a symlink resolves to, case-insensitively: `.pem`, `.key`, `.p12`, `id_rsa`,
`id_ed25519-work`, Vagrant's and Lima's machine keys, ...), tools' credential files in the real home folder (`.npmrc`,
`.docker/config.json`, `.config/gh/hosts.yml`, ...; the home folder comes from the user database, not `$HOME`, which a
repo's settings can override), and any regular file whose first 4 KiB has a line starting a private key (PEM or
OpenSSH, PGP, PuTTY). Exit 2 blocks with the message on stderr. Bad input allows; any other failure blocks.

Porting notes: `os.path.expanduser` (including `~name` through the user database), `relpath` and non-strict
`realpath` are ported in `src/pyfs.rs`; the three user-database calls are declared by hand in `src/pwd.rs` (macOS
`struct passwd` layout) rather than pulling in the `libc` crate and its build script.

## What `claude-guard husky` does

husky-worktree-hooks.py's behaviour: after a Bash command that mentions `worktree add`, after EnterWorktree, and at
session start, it finds the repo's worktrees from `<common git dir>/worktrees/*/gitdir` and copies the main
checkout's `.husky/_` and its graphmind hook files (`post-commit`, ... with a `# graphmind:` line) into each
worktree that has a `.husky/` folder but lacks them. It never runs git or anything from the repo, never overwrites
a file, and always exits 0; errors go to `~/.local/state/claude-guard/husky.log`. Copies match Python's
`copytree(symlinks=True)` and `copy2`: links stay links, data, mode and times are copied, extended attributes are not
(Rust's `fs::copy` would also copy them on macOS, so it isn't used). Python's text reads turned `\r\n` into `\n`;
so does this.

## What `claude-guard prompt` does

guard-prompt.py's checks, in its order, with byte-for-byte its output:

1. Secrets: ten built-in rules (AWS keys, private keys, GitHub, Atlassian, Bitbucket, Slack, Stripe, Google keys,
   JWTs) and `password = <literal>` style assignments, then gitleaks' default rules when the prompt holds a long run
   of mixed letters and digits. gitleaks runs in `/` with a clean environment, `/dev/null` as its ignore file and a
   1 s timeout, so a repo's `.gitleaks.toml`, `.gitleaksignore` or `GITLEAKS_CONFIG` can't allowlist anything.
2. Malaysian IC numbers (YYMMDD-PB-###G: dashes all or none, a real month and day, a place-of-birth code JPN issues).
3. Names from `~/.config/claude-guard/blocked-terms.txt`: case-insensitive whole words. A name warns, the prompt goes
   through and `~/.local/state/claude-guard/allow-name.log` gets one line (time, session id, folder, whether the
   prompt started with `[allow-name]`; never the name). `--strict` (GraphMind's prompt hook) blocks a name instead and
   logs nothing.

A secret or an IC number blocks with the rule name only, never the matched text. Any internal error lets the prompt
through with one warning (fail open), as the Python hook does. `--terms <file>` and `--log <file>` are for tests.

Porting notes: the `regex` crate has no lookaround or backreferences, so the `\b`, `(?<!...)`, `(?!...)` edges and
the IC number's `\4` are checked in code, with Python's Unicode meaning of `\w` (letters, numbers, `_`; not
combining marks), `\s` (adds U+001C to U+001F) and `\d` (any decimal digit: `int()` reads Arabic-Indic digits, so
`٩٠٠١١٥-10-5821` is an IC number, while a place code in other digits never matches Python's ASCII list). gitleaks
reports several findings in a different order from run to run, and both hooks name the first, so the rule name in a
gitleaks block can differ between two runs on the same prompt; the verdict doesn't.

## What `claude-guard web` does

web-guard.py's checks, with byte-for-byte its output and web.log lines, and web-guard.sh's fast path in front (a Bash
call whose input names no fetch tool and no URL is let through without parsing):

- `pre`: the URLs a call is about to open (every string in a ccs-browser call; the `url` of ctx_index and WebFetch;
  in Bash, the URLs of commands that fetch: curl, wget, http/https, xh, aria2c, lynx, links, agent-browser, also by
  path or through a `"${AB[@]}"` array). It denies callback and canary hosts, cloud metadata addresses, and URLs
  that carry a secret, a blocked name (also as a slug) or a Malaysian IC number (the `prompt` checks on the twice
  URL-decoded text; a presigned AWS URL's key id is not a secret). Tunnels, public IP literals and long encoded query
  values warn. The log keeps scheme, host and path, and `<withheld: carries data>` for a data-in-url denial.
- `post`: detect only. Invisible tag characters, bidi controls, zero-width runs, injection wording, hidden HTML text,
  a planted AWS key and callback links in what came back; Claude is told to treat it as data.

Policy: built-in lists plus `~/.config/claude-guard/url-policy.json` (`--policy`). `--log`, `--terms` and `--guard`
as in web-guard.py; the data checks are built in, so `--guard <file>` only switches them off when that file doesn't
exist (Python skipped them when it couldn't load guard-prompt.py). Any internal error, a broken policy file
included, lets the call through with one warning.

Porting notes: `urllib.parse.urlsplit` (3.9.6: tab and newline removal, scheme rules, IPv6 bracket check, the NFKC
check on non-ASCII netlocs, as a table of the 19 characters whose NFKC form holds `/?#@:`), the `hostname` property
and `unquote` (UTF-8, `errors="replace"`, ASCII runs only) are ported in `src/web.rs`. Python's dict order matters
here (which URL comes first, how the text of a response is joined), so serde_json keeps insertion order.

## What `claude-guard session-name` does

session-name-from-title.sh's behaviour, byte for byte: a session that still has its default `<folder>-<hex>` name
gets one made from Claude's latest ai-title in the transcript (lowercase, words joined by hyphens, no bare numbers
or filler words, at most 4 words and 29 characters, starting with a letter). A session already named (hook input
`session_title`, or a custom-title record in the transcript) is left alone. A name another live session holds, by
the registry `${CLAUDE_CONFIG_DIR:-$HOME/.claude}/sessions/*.json`, gets this session's own suffix, then 4
characters of its id; otherwise nothing is printed. It never blocks and always exits 0.

Porting notes: the script's jq calls go through `src/jqlite.rs` (jq 1.7.1's stream parsing: values up to the first
parse error, an unpaired surrogate is an error, NaN reads as null, number literals printed as decNumber prints them
such as `1E+2`; `-r` pretty output; `-c` escaping). The tr pipeline follows the UTF-8 locale Claude Code runs in
(İ and the Kelvin sign lowercase to i and k). The live check is dash's `kill -0`: its `number()` (strtoimax:
spaces and a sign allowed, 0 to INT_MAX) and `-number(rest)` for a leading `-`. The registry folder comes from
CLAUDE_CONFIG_DIR as in the script (Claude Code's own setting, not a test override).

## What `claude-guard dns-nxdomain` does

The responder dns-blocklist's `/etc/resolver` files point the web guard's canary and callback domains at: it
answers every UDP query on 127.0.0.1:10053 with NXDOMAIN at once (without an answer, macOS retries a dead port for
about 30 seconds), and logs each name to `~/.local/state/claude-guard/web.log` at most once a minute
(`{"mode": "dns", "name": ...}`). Same replies byte for byte and same log lines as dns-nxdomain.py; one difference
on purpose: a failed send is skipped instead of crashing the daemon (launchd restarted the Python one).

There is no shadow mode: the resolver sends each query to one port, so a second responder never sees real traffic.
The differential test runs both daemons for real on free ports and compares every reply and log line.

## Python regex semantics (`src/pyre.rs`)

Python's str patterns and the `regex` crate disagree on `\w` and `\b` (Python: letters, numbers, `_`; Rust adds
combining marks, ZWJ, `‿` and Alphabetic symbols like `Ⓐ`, and leaves out `²`), on `\s` (Python adds U+001C to
U+001F), and on IGNORECASE (Python matches `İ` and `ı` for `i`). `PyText` is a copy of the text with each such
character replaced by a stand-in Rust classes the way Python classes the original, with a byte map back to it; the
ported patterns run on that copy and report matches in the original. Found by the differential tests: `apİ_key=…`,
`Quİllfeather` and `ıgnore previous instructions` matched in Python only.

## Failure modes and logs

| Subcommand | Unreadable input | Internal error |
| --- | --- | --- |
| `bash` | allow | block (fail closed), logged |
| `read` | allow | block (fail closed) |
| `husky` | nothing copied, logged | nothing more copied, logged; always exit 0 |
| `prompt` | allow with a warning (fail open) | allow with a warning (fail open) |
| `web` | allow with a warning (fail open) | allow with a warning (fail open) |
| `session-name` | nothing printed | nothing printed |
| `--shadow` | never blocks | never blocks |

Recursion is capped, so a deeply nested input is an internal error (blocked by `bash` and `read`), never a stack overflow: an
aborted hook is a non-blocking error in Claude Code, which would let the call through. Logs are written one record
per `write` (parallel hooks never interleave) and rotate to `<log>.1` at 1 MB (crash and husky logs) or 50 MB
(shadow log).

## Shadow mode

`claude-guard <hook> --shadow` runs next to the old hook and never blocks or copies. It hands the work to a detached
copy of itself and exits at once (Claude Code waits for every hook; the comparison runs Python, which inline made
each call 100 to 200 ms slower). The copy appends one line to `~/.local/state/claude-guard/shadow.log` with the rule
ids (or copy counts), whether they agree and the timings. A line never holds a command, a path or file contents;
`session_id` and `tool_use_id` find the call in the transcript.

- `bash`, `read`: the copy decides with the Rust code and runs the old hook(s) on the same input.
- `prompt`: both sides decide without writing the allow-name log (the live Python hook writes it): Rust in a dry
  run, the old hook with `--log /dev/null`. Two gitleaks blocks agree even when the rule names differ (finding order).
- `web`: `claude-guard web --shadow pre|post`; the reference is web-guard.sh (fast path included) with
  `--log /dev/null`, and Rust decides without writing web.log. Lines are logged as hook `web-pre` or `web-post`.
- `session-name` only prints, so both run as they are; the log says whether each gave a name, never the name.
- `husky` copies files, so the old hook can't run twice. The shadow hook works out what it would copy (dry run)
  before it detaches, which is before the Python hook (about 40 ms of start-up) copies anything; the detached copy
  waits for the Python hook and checks that exactly those items appeared. A worktree the Rust code misses entirely
  isn't seen this way; the differential test covers that.

Options (arguments, never environment variables): `--reference <old hook> --pip-reference <block-pip.sh> --terms <file>
--policy <file> --log <file>` (`--pip-reference` for bash, `--terms` for prompt and web, `--policy` for web).

```sh
# agreement so far, and any disagreements
jq -s 'group_by(.hook) | map({hook: .[0].hook, calls: length, same: map(select(.same)) | length, different: map(select(.same | not))})' ~/.local/state/claude-guard/shadow.log
```

## Build, test, install

```sh
nice -n "$(test-workers --nice)" cargo test --release -j "$(test-workers)" -- --test-threads="$(test-workers)"
# differential tests against the old hooks (generated inputs; size and seed are settable)
for t in differential_bash differential_read differential_husky differential_prompt differential_web differential_session_name differential_dns; do
  CLAUDE_GUARD_DIFF_WORKERS="$(test-workers)" nice -n "$(test-workers --nice)" cargo test --release --test $t -- --nocapture
done
cargo audit
scripts/install.sh
```

The differential tests need the old hooks in `~/.claude/hooks/` (or `CLAUDE_GUARD_REF_BASH`, `CLAUDE_GUARD_REF_PIP`,
`CLAUDE_GUARD_REF_READ`, `CLAUDE_GUARD_REF_HUSKY`) and skip themselves when they are missing. The prompt test's
reference is `~/.claude/hooks/guard-prompt.py` (or `CLAUDE_GUARD_REF_PROMPT`)
with a made-up terms file; it compares stdout and the allow-name log lines (time left out). The web test's reference
is the folder `~/.claude/hooks` (`CLAUDE_GUARD_REF_WEB`): the real web-guard.sh decides the fast path (run next to a stub
web-guard.py), web-guard.py runs in-process with guard-prompt.py as its `--guard`, and stdout plus web.log lines are
compared (an unpaired surrogate is logged as U+FFFD by the Rust hooks; that is the one difference). The session-name
test runs the real script with /bin/dash on generated transcripts and registries (live, dead and odd pids, through
CLAUDE_CONFIG_DIR) and compares stdout.
`tests/reference_driver.py` runs the Python bash, read and prompt guards in-process so thousands of cases take seconds (spot
checked against real `python3 -I` runs). The husky test builds each generated repo layout twice and runs Python on
one copy and Rust on the other, then compares output, error logging and every file, mode, mtime and link.

Dependencies: `serde_json` (with `unbounded_depth` and `preserve_order`, which brings in `indexmap`) and `regex`
(13 crates built, no proc macros; serde_json, serde_core and zmij run small build scripts that detect compiler
features). The user-database calls are hand-declared, not the `libc` crate. `Cargo.lock` is committed; builds use `--locked`.

## Rollback

Each shadow hook is one extra entry in `~/.claude/settings.json` (`claude-guard <hook> --shadow`); remove it to stop.
Until a switch, the old hooks stay registered and do the real work.
