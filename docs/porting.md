# Porting notes

claude-guard replaced a set of Python and shell hooks (`guard-bash.py` + `block-pip.sh`, `guard-read-keys.py`,
`husky-worktree-hooks.py`, `guard-prompt.py`, `web-guard.sh` + `web-guard.py`, `session-name-from-title.sh`, and the
`dns-nxdomain.py` daemon). Each subcommand had to give the same verdicts and, where a tool reads them, the same bytes
of output as the hook it replaced. This file records how that was checked and where the languages disagree. None of
it is needed to use claude-guard.

## How sameness was checked

- **Table tests** (`tests/table_*.rs`) hold the hand-written cases, including every case from the original hooks' own
  test suites.
- **Differential tests** (`tests/differential_*.rs`) generate thousands of inputs from a seed, run the original hook
  and the Rust subcommand on each, and fail on any difference in output, exit code, log lines or (for husky) every
  file, mode, mtime and link. The original hooks are kept in `tests/reference/` as test-only references (nothing installs them any
  more); `CLAUDE_GUARD_REF_BASH`, `CLAUDE_GUARD_REF_PIP`, `CLAUDE_GUARD_REF_READ`, `CLAUDE_GUARD_REF_HUSKY`,
  `CLAUDE_GUARD_REF_PROMPT`, `CLAUDE_GUARD_REF_WEB`, `CLAUDE_GUARD_REF_SESSION_NAME` and `CLAUDE_GUARD_REF_DNS` point
  a test at another copy. A rule change goes into the Rust code and the matching reference together, so the
  differential tests keep comparing two independent implementations. Size and workers:
  `CLAUDE_GUARD_DIFF_CASES`, `CLAUDE_GUARD_DIFF_WORKERS`. `tests/reference_driver.py` runs the Python bash, read and
  prompt guards in-process so thousands of cases take seconds (spot checked against real `python3 -I` runs).
- **Shadow mode** ran each subcommand next to the live Python hook for real traffic before any switch (below).

```sh
for t in differential_bash differential_read differential_husky differential_prompt differential_web differential_session_name differential_dns; do
  cargo test --release --test $t -- --nocapture
done
```

## Shadow mode

`claude-guard <hook> --shadow` runs next to the old hook and never blocks or copies. It hands the work to a detached
copy of itself and exits at once (Claude Code waits for every hook; running the comparison inline made each call 100
to 200 ms slower). The copy appends one line to `~/.local/state/claude-guard/shadow.log` with the rule ids (or copy
counts), whether they agree and the timings. A line never holds a command, a path or file contents; `session_id` and
`tool_use_id` find the call in the transcript.

- `bash`, `read`: the copy decides with the Rust code and runs the old hook(s) on the same input.
- `prompt`: both sides decide without writing the allow-name log: Rust in a dry run, the old hook with
  `--log /dev/null`. Two gitleaks blocks agree even when the rule names differ (gitleaks reports findings in varying
  order).
- `web`: `claude-guard web --shadow pre|post`; the reference is web-guard.sh (fast path included) with
  `--log /dev/null`, and Rust decides without writing web.log.
- `session-name` only prints, so both run as they are; the log says whether each gave a name, never the name.
- `husky` copies files, so the old hook can't run twice. The shadow hook works out what it would copy (dry run)
  before it detaches, before the Python hook copies anything; the detached copy waits for the Python hook and checks
  that exactly those items appeared.
- `dns-nxdomain` has no shadow mode (the resolver sends each query to one port); its differential test runs both
  daemons on free ports and compares every reply and log line.

Options (arguments, never environment variables): `--reference <old hook> --pip-reference <block-pip.sh> --terms <file>
--policy <file> --log <file>`.

```sh
# agreement so far, and any disagreements
jq -s 'group_by(.hook) | map({hook: .[0].hook, calls: length, same: map(select(.same)) | length, different: map(select(.same | not))})' ~/.local/state/claude-guard/shadow.log
```

## Reading hook JSON like Python (`src/hookio.rs`)

Hook JSON is read the way Python's `json.load` reads it: unpaired surrogate escapes (`\ud800`), `NaN`, `Infinity` and
numbers past f64's range (`1e400`) are accepted, and arrays and objects nest up to 993 levels (serde_json alone stops
at 128). A rejected input is allowed, so rejecting what Python read would let a command through. A non-string
`command` (a number, bool or object) is allowed with one warning: it can't hide a shell command.

## Python regex semantics (`src/pyre.rs`)

Python's str patterns and the `regex` crate disagree on `\w` and `\b` (Python: letters, numbers, `_`; Rust adds
combining marks, ZWJ, `‿` and Alphabetic symbols like `Ⓐ`, and leaves out `²`), on `\s` (Python adds U+001C to
U+001F), and on IGNORECASE (Python matches `İ` and `ı` for `i`). `PyText` is a copy of the text with each such
character replaced by a stand-in that Rust classes the way Python classes the original, with a byte map back to it;
the ported patterns run on that copy and report matches in the original. The `regex` crate has no lookaround or
backreferences, so those edges are checked in code; everything runs in linear time.

## Per subcommand

- **bash:** Python's `shlex` (posix, `punctuation_chars`), `glob`, `fnmatch` (including the `re.error` on bad bracket
  ranges such as `[i-0]`) and `os.path.realpath` are ported in `src/bash/shlex.rs` and `src/bash/pyfs.rs`, because
  the verdicts depend on their quirks. The heredoc pattern is matched by hand.
- **read:** `os.path.expanduser` (including `~name` through the user database), `relpath` and non-strict `realpath`
  are ported in `src/pyfs.rs`; the three user-database calls are declared by hand in `src/pwd.rs` (macOS
  `struct passwd` layout) rather than pulling in the `libc` crate and its build script.
- **husky:** copies match Python's `copytree(symlinks=True)` and `copy2`: links stay links, data, mode and times are
  copied, extended attributes are not (Rust's `fs::copy` would copy them on macOS, so it isn't used). Python's text
  reads turned `\r\n` into `\n`; so does this.
- **prompt:** `\d` follows Python's `int()` (any decimal digit, so `٩٠٠١١٥-10-5821` is an IC number), while a place
  code in other digits never matches Python's ASCII list. Found by the differential tests: `apİ_key=…`,
  `Quİllfeather` and `ıgnore previous instructions` matched in Python only, before `PyText`.
- **web:** `urllib.parse.urlsplit` (3.9.6: tab and newline removal, scheme rules, IPv6 bracket check, the NFKC check
  on non-ASCII netlocs, as a table of the 19 characters whose NFKC form holds `/?#@:`), the `hostname` property and
  `unquote` (UTF-8, `errors="replace"`, ASCII runs only) are ported in `src/web.rs`. Python's dict order matters
  (which URL comes first, how a response's text is joined), so serde_json keeps insertion order. An unpaired
  surrogate is logged as U+FFFD; that is the one difference.
- **session-name:** the script's jq calls go through `src/jqlite.rs` (jq 1.7.1's stream parsing: values up to the
  first parse error, an unpaired surrogate is an error, NaN reads as null, number literals printed as decNumber prints
  them such as `1E+2`; `-r` pretty output; `-c` escaping). The tr pipeline follows the UTF-8 locale Claude Code runs
  in. The live-session check is dash's `kill -0` with its `number()` parsing.
- **dns-nxdomain:** same replies byte for byte and same log lines as the Python daemon; one difference on purpose: a
  failed send is skipped instead of crashing the daemon.
