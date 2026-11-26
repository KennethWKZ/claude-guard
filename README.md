# claude-guard

Fast guard hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code): one small Rust binary, one
subcommand per hook. It blocks dangerous Bash commands, keeps key and credential files out of the Read tool, stops
secrets and personal ID numbers in prompts and URLs, and flags hidden instructions in fetched pages.

> **Not affiliated with Anthropic.** This is an independent project. It is not made, endorsed or supported by
> Anthropic. "Claude" and "Claude Code" are Anthropic's trademarks; claude-guard only runs as hooks inside Claude Code.

A hook runs on every tool call or prompt, so start-up time matters: a claude-guard hook starts in a few milliseconds
and uses about 4 MB, where the Python hooks it replaced took 60 to 160 ms each (Apple Silicon Mac).

## What it is for, and what it isn't

The guards catch mistakes and common traps: a risky command approved on autopilot, a `.env` file read into the
conversation, a secret pasted into a prompt, a fetched page that tries to send Claude to a callback URL. Everything
Claude reads goes to the model provider, so keeping secrets out matters even when nothing goes wrong.

They are not a sandbox. The rules are public, and a determined attacker can read them. Use claude-guard together with
Claude Code's sandbox and permission rules, not instead of them. See [What it doesn't cover](#what-it-doesnt-cover).

## Subcommands

| Subcommand | Hook | What it does | On an internal error |
| --- | --- | --- | --- |
| `claude-guard bash` | PreToolUse `Bash` | Blocks `rm -rf` outside temp, reading `.env` files, recursive `grep`, `rg --hidden`, `git push --force`, `sudo`, `pip install`, rust-anything's code-running subcommands | blocks (fail closed), logged |
| `claude-guard read` | PreToolUse `Read` | Refuses key and certificate files, tools' credential files, and files that start a private key | blocks (fail closed) |
| `claude-guard prompt` | UserPromptSubmit | Blocks prompts holding secrets or Malaysian IC numbers; warns on names from your list | allows with a warning (fail open) |
| `claude-guard web pre` / `post` | PreToolUse / PostToolUse on fetch tools | `pre` denies canary, callback and cloud-metadata URLs and URLs carrying data; `post` flags hidden instructions in what came back | allows with a warning (fail open) |
| `claude-guard husky` | PostToolUse `Bash\|EnterWorktree`, SessionStart | Copies husky's `.husky/_` (and GraphMind's git hooks) into new git worktrees | nothing more copied, logged; never blocks |
| `claude-guard session-name` | UserPromptSubmit, SessionStart | Names an unnamed session from Claude's own title for it | prints nothing |
| `claude-guard repo pre-bash` | PreToolUse `Bash`, in one repo | Guards a repo configures in its own `.claude/repo-guard.json`: the Logs Insights cost guard (raw `aws logs start-query`, and Python that starts queries without the repo's guard module) and, for repos where sessions share one working tree, the shared-tree guard (git outside the commit queue, history and branch moves, discards, shell and interpreter writes to locked folders, the write ledger) | allows, logs one line (blocks once the repo opts in) |
| `claude-guard repo post-read` | PostToolUse `Read\|Bash`, in one repo | Tells a session that a file it read earlier in the repo's tracked folders was changed since by someone else (another session, a script, a person), so it reads it again before relying on it; per-session records shared with the repo's Edit hook | prints nothing, logs one line |
| `claude-guard dns-nxdomain` | not a hook | A tiny DNS responder that answers "no such domain" for blocked domains (see below) | skips that reply |

Input that isn't hook JSON is let through by every guard: a hook that blocked on bad input could lock up Claude Code.

## Install

macOS on Apple Silicon only for now: the user-database calls are declared for macOS's layout.

### Release binary

```sh
VERSION=v0.1.1
gh release download "$VERSION" -R KennethWKZ/claude-guard -p 'claude-guard-aarch64-apple-darwin.tar.gz*'
shasum -a 256 -c claude-guard-aarch64-apple-darwin.tar.gz.sha256
gh attestation verify claude-guard-aarch64-apple-darwin.tar.gz -R KennethWKZ/claude-guard --source-ref "refs/tags/$VERSION"
tar -xzf claude-guard-aarch64-apple-darwin.tar.gz
mkdir -p ~/.local/bin && install -S -m 755 claude-guard ~/.local/bin/claude-guard
~/.local/bin/claude-guard --version
```

`curl` works too (`https://github.com/KennethWKZ/claude-guard/releases/download/<version>/<file>`). See
[Verify a release](#verify-a-release).

### From source

Needs Rust 1.85 or newer (`rustup`).

```sh
git clone https://github.com/KennethWKZ/claude-guard && cd claude-guard
scripts/install.sh    # cargo build --release --locked, then an atomic copy to ~/.local/bin/claude-guard
```

## Register the hooks

Add the entries to `~/.claude/settings.json` (merge them into any `hooks` you already have). Use the **full path**
to the binary (`~/.local/bin/claude-guard`), never a bare `claude-guard`: a repository's `.claude/settings.json` can
change `PATH` for hooks, and a bare name would then run whatever that repository puts first on `PATH`.

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "~/.local/bin/claude-guard bash", "timeout": 10 }] },
      { "matcher": "Read", "hooks": [{ "type": "command", "command": "~/.local/bin/claude-guard read", "timeout": 10 }] },
      { "matcher": "Bash|WebFetch|mcp__plugin_context-mode_context-mode__ctx_index",
        "hooks": [{ "type": "command", "command": "~/.local/bin/claude-guard web pre", "timeout": 5 }] }
    ],
    "PostToolUse": [
      { "matcher": "Bash|EnterWorktree", "hooks": [{ "type": "command", "command": "~/.local/bin/claude-guard husky", "timeout": 10 }] },
      { "matcher": "Bash|WebFetch|mcp__plugin_context-mode_context-mode__ctx_(index|search)",
        "hooks": [{ "type": "command", "command": "~/.local/bin/claude-guard web post", "timeout": 5 }] }
    ],
    "UserPromptSubmit": [
      { "hooks": [
        { "type": "command", "command": "~/.local/bin/claude-guard prompt", "timeout": 5 },
        { "type": "command", "command": "~/.local/bin/claude-guard session-name", "timeout": 5 }
      ] }
    ],
    "SessionStart": [
      { "hooks": [
        { "type": "command", "command": "~/.local/bin/claude-guard husky", "timeout": 10 },
        { "type": "command", "command": "~/.local/bin/claude-guard session-name", "timeout": 5 }
      ] }
    ]
  }
}
```

Pick the hooks you want; each one works on its own. The web guard also reads the ccs-browser MCP tools
(`mcp__ccs-browser__.*`) and the ccs WebSearch tool (`mcp__ccs-websearch__WebSearch`): add them to its matchers if you
use them. To check it works, ask Claude Code to run `grep -r x .`: the Bash guard refuses it.

## Configuration

| File | Used by | What it holds |
| --- | --- | --- |
| `~/.config/claude-guard/blocked-terms.txt` | `prompt`, `web pre` | Names to watch for (customers, projects): one per line, `#` starts a comment, matched in any case as whole words. Optional |
| `~/.config/claude-guard/url-policy.json` | `web pre` | Your own `allow_hosts`, `block_hosts` and `warn_hosts` lists on top of the built-in ones. Optional |
| `<repo>/.claude/repo-guard.json` | `repo pre-bash`, `repo post-read` | That repo's rules and wording (version 1): `error_log`; under `pre_bash.logs_insights` the `guard_module` name and the `raw_cli_reason`, `script_reason` (`{path}`), `inline_reason` and `block_message` (`{why}`) texts; for the shared-tree guard `repo_label`, `locked_dirs`, `output_dirs` and the `pre_bash.git` (`block_message` with `{op}` `{message}` `{advice}`, per-operation `messages` and `advice`, defaults, `saved_prune_message`), `shell_writes`, `interpreter_writes` and `write_ledger` (`dir`, `override_env`) sections. Each rule set is on when its section is there. For `repo post-read`, `post_read`: `tracked_dirs`, `untracked_dirs`, `generated`, `record_dir`, `layer_suffixes`, `entity_command` (`runner`, `command`, `schema_dir`, `folder_key`), `read_only_runner_commands` and the `messages` (`changed_elsewhere` and `during_command` with `{files}`, `stale`). Found through `CLAUDE_PROJECT_DIR`; missing or invalid, the hook allows and says so in a `systemMessage` |

Logs go to `~/.local/state/claude-guard/` (owner-only files; `husky.log` and `bash-crash.log` rotate to `<log>.1` at
1 MB):

| Log | Holds |
| --- | --- |
| `web.log` | scheme, host and path of URLs denied or warned about (never query strings or page text), and DNS responder hits |
| `allow-name.log` | one line per prompt that went through with a watched name: time, session id, folder; never the name |
| `husky.log` | errors while copying into worktrees |
| `bash-crash.log` | the start of a command that crashed the Bash guard |

## What each guard does

### `claude-guard bash`

1. `rm` with recursive and force flags on an absolute path (`~` and `$HOME` count) outside `$TMPDIR` and `/tmp`, in
   every spelling (`-fr`, `-r -f`, `--recursive --force`, `..` tricks). A redirect's target (`2>/dev/null`,
   `> out.log`) is a file the shell opens, not an rm path (Rust only; the Python guard listed it). In a string or
   script run with a `HOME=` prefix (`HOME=/tmp/h bash -c '...'`, `env HOME=/tmp/h bash x.sh`), `~` and `$HOME` mean
   that home (Rust only), except where the shell around it expands them first (unquoted, `"$HOME"`, `eval`
   arguments, the command's own words, a script it writes itself) and when the value comes from a substitution
   (`HOME=$(mktemp -d)`): those keep the real home. A value naming another variable the command doesn't set is read
   like any unknown variable. Only a `HOME=` among the leading words counts (`env HOME=x`, not one behind another
   wrapper).
2. Commands that name a secrets env file (`.env`, `.env.local`, `prod.env`, `.envrc`, ...) directly, through a glob
   or through brace expansion; recursive `grep`; `rg --hidden`/`--no-ignore` without `-g '!.env*'`. Templates
   (`.env.example`, ...) stay readable, and jq/yq filters such as `'.env.FOO'` are not files. File tests only test:
   `[ -f .env ]`, `test -f .env`, and (Rust only) `[[ -f .env && -s .env ]]`, `[ ! -f .env ]`, `test ! -e .envrc`.
3. `git push --force` / `-f` (`--force-with-lease` is allowed).
4. `sudo`.
5. `pip install` (tells Claude to use `uv` instead), also after a keyword, wrapper or assignment (`then pip install`,
   `X=1 pip install`; Rust only).
6. [rust-anything](https://crates.io/crates/rust-anything) subcommands other than `analyze`, `map`, `doctor` and
   `help` (and `--help` / `--version`). The rest build, run or edit the code being ported; deny their MCP tools
   (`mcp__rust-anything__*`) too, so the CLI isn't the way round. A subcommand added later is blocked until it's
   listed. Found by path, behind wrappers (`timeout`, `nice -n`, `env -i`, `xargs`), in `$(…)` and backticks, and
   inside `bash -c '…'`.

A newline outside quotes and heredoc bodies ends a command, as `;` does (`cd x⏎sudo ls` is caught; the Python guard
read a newline as a space), and backslash-newline continues the line. The rules hold inside loops, `if` blocks and
`{ … }`, in heredocs fed to a shell, `source`, `.` or `eval`, and inside
strings run as commands, nested, the pip rule included: `bash -c '…'` (also `sh`, `zsh`, `dash`, `ksh`; `-lc`, `-ec`,
options before `-c`; after `env`, `timeout` or `xargs` options), `eval …` (its arguments joined, as eval does),
here-strings fed to a shell, `source` or `.` (`bash <<< '…'`), `source <(echo '…')` or `printf`, and `echo` or
`printf` output piped into a shell or `source /dev/stdin` (`echo '…' | bash`, each line on its own). The Python guard
read such a string as one word; the strings are checked after the rest of the command passed, so a command it
blocked keeps its reason. A heredoc is read only where bash reads one: outside quotes and comments, or inside
`$(…)` and backticks. So a heredoc written inside a quoted `bash -c '…'` string is checked as part of that string
(its body when a shell reads it, and the lines after its end marker), and a `<<WORD` inside quotes or a comment no
longer hides the lines after it. A heredoc whose command's output is piped into a shell that runs its input (`cat <<EOF | bash`,
`| sh -s`, `| source /dev/stdin`, through filters such as `sed <<EOF | bash` or `cat <<EOF | sed … | bash`, and
`cat <<EOF |` with the shell on the first command line after the body) has its body checked as commands: as written
(so a filter that drops a line still fails closed) and as the filters would turn it. sed `s///` (basic and `-E`
regexes, `&`, `\1`, `g`) and `i`/`a`/`c` text, awk `print` lists of literals and fields, and `perl -pe 's///'` are
followed, so `sed 's/^/sudo /' <<EOF | bash` is caught; the same holds for `echo … | sed … | bash` and
`cat FILE | sed … | bash`. A filter built some other way (`tr`, `rev`, variables, a sed script file) isn't followed. Heredocs fed through a
wrapper (`timeout 9 bash <<EOF`, `ssh host <<EOF`) or whose output is run (`eval "$(cat <<EOF …)"`, `$(cat <<EOF …)` as
a command, `bash <(cat <<EOF …)`) count as fed to a shell, and a `case` pattern's `)` doesn't end a `$(…)`. Command
substitutions are checked inside double quotes and backticks too (`echo "$(cat .env)"`, ``x=`sudo ls` ``; Rust only:
the Python guard read `"$(…)"` as one word and never looked inside backticks). An unquoted substitution is one word of
the command around it, so the arguments after it are checked as well (`cat $(true) .env`, `rm -rf $(true) /srv/x`;
Rust only: the Python guard ended the command at the `)` and let them through).

The rules also hold for what a wrapper runs (Rust only):

- argv wrappers with their options: `timeout -s KILL 9`, `nice -n 5`, `env -i X=1`, `xargs -I{}`, `caffeinate -i`,
  `stdbuf -oL`, `setsid`, `ionice -c3`, `arch -arm64`, `chroot DIR`, `taskset`, `chrt`, `unbuffer`, `sandbox-exec`,
  `doas`, `pkexec`;
- `ssh [options] HOST CMD…` (the remote command, joined as ssh sends it), and `ssh HOST` reading a heredoc, a
  here-string or a pipe;
- containers: `docker|podman|nerdctl exec|run` (with `--entrypoint`), `docker compose exec|run`, `docker-compose`,
  `kubectl|oc exec … -- CMD`, and `-i` with a heredoc, here-string or pipe into a shell in the container;
- user switches: `su -c '…'`, `runuser -c '…'`, `runuser -u USER -- CMD`, `sg GROUP -c '…'`;
- `find … -exec|-execdir|-ok|-okdir CMD {} +|;`, with `{}` read as each start path (`find /srv/old -exec rm -rf {} +`);
- string runners: `watch '…'`, `script -c '…'` and macOS `script FILE CMD`, `flock FILE -c '…'`, `env -S '…'`;
- commands an interpreter's code runs, from `-e`/`-c`/`-r` code, code on stdin (`python3 - <<EOF`, `echo … |
  python3`) and script files (`python3 x.py`, `node x.js`, `./x` with such a shebang; project and temp folders only,
  never `node_modules`, `vendor`, `.venv` or `site-packages`, and a file over 256 KiB is skipped): perl `system`,
  `exec`, backticks, `qx`, pipe `open`; python `os.system`, `os.popen`, `subprocess.*` (also imported or aliased),
  `os.exec*`, `os.spawn*`; node/bun/deno `child_process` `exec*`/`spawn*`/`execFile*`, `Bun.spawn`, `` $`…` `` (Bun,
  zx), `Deno.Command`, `Deno.run`; ruby `system`, `exec`, `spawn`, backticks, `%x()`, `IO.popen`, `Open3.*`; php
  `exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`, backticks; lua `os.execute`, `io.popen`;
  osascript `do shell script`. One string is a command line, a list an argv. Arguments are evaluated: literals,
  variables the code assigns (every value a name gets), concatenation, interpolation, `" ".join([…])`,
  `[…].join(" ")`, perl `join`, python `%` and `.format()`; an unknown name reads as the word `x`. Built code run
  through `exec`/`eval`/`compile` (python), `eval`/`new Function`/`vm.*` (node), `eval`/`instance_eval` (ruby),
  string `eval` (perl), `eval` (php) or `load` (lua) is read again, up to 4 levels. Environment lookups (`os.environ`, `os.getenv`,
  `process.env`, `ENV`, `$ENV{…}`, `getenv`, `$_ENV`) take the value the command itself gives the variable
  (`CMD=… python3 …`, `export CMD=…`); one it doesn't set stays unknown, since the hook can't see the real
  environment. File reads (`open(p).read()`, `Path(p).read_text()`, `fs.readFileSync`, `File.read`,
  `file_get_contents`, `io.open(p):read`) take the file's text: written earlier in the command, or on disk under the
  script rules. Indirect calls count: python `getattr(os, "system")`, aliases (`f = os.system`, `import … as`), node
  `cp["execSync"]`, `const run = cp.execSync`, `{execSync: run}`, ruby `send(:system, …)`, `method(:system).call`,
  php `call_user_func(_array)("system", …)` and `$f = "system"; $f(…)`;
- commands sed and awk run themselves: sed `e CMD`, a bare `e` and the `s///e` flag; awk `system("…")`,
  `"CMD" | getline` and `print … | "CMD"` (with a shell as CMD, what it prints too). With input the guard knows (a
  heredoc or `echo …` feeding them) each line is worked through; otherwise fields read as empty
  (`awk '{system("rm -rf /srv/" $1)}'` reads as `rm -rf /srv/`);
- variables set in the same command: `c='sudo ls'; bash -c "$c"`, `$c` as the command, `rm -rf "$d"` after
  `d=/srv/app` (the command is checked once more with the values put in);
- scripts written and run in the same command: `cat > run.sh <<EOF … EOF` or `echo … > run.sh`, then `bash run.sh`,
  `source run.sh` or `./run.sh`.

Script files a command runs are read from disk and checked with every rule (Rust only): `bash|sh|zsh FILE`,
`source FILE`, `. FILE`, `./FILE` or `/path/FILE` as the command (also behind wrappers), `cat FILE | bash` and
`bash < FILE`. Only files Claude could have written count: inside the session's `cwd` (unless that is the home folder
or `/`) or a temp folder, so tools and dotfiles elsewhere (`brew`, `~/.zshrc`) aren't read. Binaries (an executable
header, or a NUL byte in the first line, which bash refuses to run), files with another interpreter's shebang run as
the command (`#!/usr/bin/env node`), missing files and `bash -n FILE` aren't either; NUL bytes later in a script are
dropped before the check, as bash drops them. A script over 256 KiB is blocked rather than checked in part ("run it yourself with !"), and scripts that
source each other are each read once. The file can change between the check and the run.

In the newline pass, a run of operator characters is split the way bash splits it (Rust only): `x=$(date); sudo ls` is
two commands (the Python guard read `);` as one word, so `sudo ls` was its argument), and a case arm's `;;` ends the
command before it. Each `$(…)` and backtick is checked once, outermost first, so deep nesting costs one check per
level; a work budget (20,000 pieces: the command, its nested strings, heredoc bodies and scripts) blocks anything
bigger rather than let the hook time out, since a timed-out hook doesn't block.

A quoting error in the command allows it, so a typo never locks the shell; any other failure blocks it and is logged.
Input nested too deep to check blocks.

### `claude-guard read`

Refuses key and certificate-store files by name, both the requested path and the path a symlink resolves to, in any
case: `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`, `id_rsa`, `id_ed25519-work`, deploy keys, Vagrant's and
Lima's machine keys. Refuses tools' credential files in your real home folder (`.npmrc`, `.docker/config.json`,
`.config/gh/hosts.yml`, `.netrc`, `.git-credentials`, ...; the home folder comes from the user database, not `$HOME`,
which a repository's settings can change). Refuses any regular file whose first 4 KiB has a line starting a private
key (PEM or OpenSSH, PGP, PuTTY). Public certificates and `.pub` keys stay readable. Exit 2 blocks, with the reason on
stderr.

### `claude-guard prompt`

Checks each prompt, in this order:

1. Secrets: built-in rules (AWS keys, private keys, GitHub, Atlassian, Bitbucket, Slack, Stripe and Google keys, JWTs)
   and `password = <literal>` style assignments, then [gitleaks](https://github.com/gitleaks/gitleaks)' default rules
   when the prompt holds a long run of mixed letters and digits and gitleaks is installed in `/opt/homebrew/bin` or
   `/usr/local/bin`. gitleaks runs in `/` with a clean environment and a 1 s timeout, so a repository's gitleaks
   config can't allowlist anything.
2. Malaysian IC numbers (YYMMDD-PB-###G: dashes all or none, a real month and day, a place-of-birth code that is
   actually issued).
3. Names from `blocked-terms.txt`: a name warns and the prompt goes through, with one line in `allow-name.log`.
   `--strict` blocks a name instead and logs nothing (for tools that pass prompts on to other services).

A secret or an IC number blocks with the rule name only, never the matched text.

### `claude-guard web pre|post`

- `pre` looks at the URLs a call is about to open: every string in a ccs-browser call, the `url` of WebFetch and
  context-mode's `ctx_index`, and in Bash the URLs of commands that fetch (curl, wget, HTTPie, xh, aria2c, lynx,
  links, agent-browser, also called by path or through a `"${AB[@]}"` array). It denies callback and canary hosts
  (canarytokens, interactsh/OAST, Burp Collaborator, webhook.site and request bins, DNS loggers, blind-XSS
  catchers), cloud metadata addresses (`169.254.*`), and URLs that carry a secret, a watched name (also as a slug) or
  an IC number, checked on the twice URL-decoded text. Tunnels, public IP literals and long encoded query values only
  warn.
- `post` only reports. It flags invisible tag characters, bidi controls, zero-width runs, injection wording, hidden
  HTML text, a planted AWS key and callback links in what came back, and tells Claude to treat the content as data.

A Bash call that names no fetch tool and no URL is let through without parsing.

`claude-guard web --list-hosts` prints the built-in blocked host names and the cloud metadata names (no IP
literals), sorted, one per line, so a DNS blocklist can use the same list as the hook.

### `claude-guard husky`

After a Bash command that mentions `worktree add`, after EnterWorktree, and at session start, it finds the repository's
worktrees and copies the main checkout's `.husky/_` (git-ignored, so new worktrees don't get it, and husky then skips
the commit hooks) and GraphMind's hook files (`post-commit`, ... with a `# graphmind:` line) into each worktree that
has a `.husky/` folder but lacks them. It never runs git or anything from the repository, never overwrites a file, and
always exits 0.

### `claude-guard session-name`

A session that still has its default `<folder>-<hex>` name gets one made from Claude's latest title for the
conversation (lowercase words joined by hyphens, at most 4 words and 29 characters). A session already named is left
alone. If another live session holds the same name, this one gets a suffix.

### `claude-guard repo pre-bash`

Register it in one repo's `.claude/settings.json` (PreToolUse, matcher `Bash`), not globally: it reads that repo's
`.claude/repo-guard.json`, so the code stays generic and the repo keeps its own rules and wording. The Logs Insights
rule blocks a raw `aws ... logs ... start-query` the command runs itself (also through `bash -c`, a heredoc fed to a
shell, `$(...)` and backticks), and Python that starts a query without naming the repo's `guard_module`: a `.py` file
the command runs, found where it runs (after a `cd`, with `~` and `$VAR` expanded), or inline Python. Ported from a
Python hook and checked against it by `tests/differential_repo.rs`, which runs when `CLAUDE_GUARD_REF_REPO_BASH` and
`CLAUDE_GUARD_REF_REPO_CONFIG` point at the reference hooks and their config.

The shared-tree rules (`src/repo_tree.rs`, shell parsing in `src/shell_words.rs`) are for a repo where several
sessions share one working tree, index and branch. They block git that stages or commits outside the repo's queue,
rewrites history, moves the branch or HEAD, throws away uncommitted work, prunes unreachable objects at once (also
through `-c`, `--config-env`, `GIT_CONFIG_*` or a value saved in git config) or writes the repo's own git config;
shell writes (`>`, `tee`, `sed -i`, `cp`/`mv`, ...) onto files in `locked_dirs`; any use of the `write_ledger` folder
or its override variable in what the command runs; and python, node, perl or ruby code that writes a file in the
locked folders. Commands are followed through `cd`, `git -C`, `bash -c`, `eval`, substitutions, heredocs fed to a
shell, scripts run by path, `xargs` and `find -exec`. Checked against the Python hooks by
`tests/differential_repo_tree.rs` (same env vars). Both rule sets run on every call; the first block wins.

An internal error allows the command and logs one line per rule set to the config's `error_log` (`--crash-log F`
overrides it for tests). `repo pre-bash --shadow --reference <hook> [--reference <hook> ...]` runs next to the
Python hooks during a shadow week: it never blocks or prints, and logs rule ids and agreement only.

### `claude-guard repo post-read`

Register it in one repo's `.claude/settings.json` (PostToolUse, matcher `Read|Bash`), for a repo where several sessions
share one working tree. Per session it keeps a record of the files it read in the config's `tracked_dirs` (path, mtime,
size, SHA-256) in `record_dir`; a Read, or a Bash command that names files to a reader (cat, head, tail, sed -n, awk,
jq, yq, diff, rg or grep given files, the config's `<runner> <command> <type>/<id>`), adds them. When one changes or
goes, the next call says so once: "someone else" when the call could not have written it (a Read, or a Bash command
made only of known readers with nothing redirected into a file), "your command or another session" when a command
that can write ran meanwhile and doesn't name the file, and nothing when the call read the new content or its own
command names the file. The record format (`{"<path>": {"m": ..., "s": ..., "h": ...}}` as Python's `json.dump` writes
it, under a `flock` on `<record>.lock`) is shared with the repo's Edit hook, so both can run side by side. A notice,
never a block: an internal error prints nothing and logs one line to `error_log` (`--crash-log F` for tests). Ported
from a Python hook and checked against it by `tests/differential_repo_read.rs`, which runs when
`CLAUDE_GUARD_REF_REPO_READ` and `CLAUDE_GUARD_REF_REPO_CONFIG` point at the reference hook and its config.

`repo post-read --shadow --reference <hook> [--records DIR]` runs next to the Python hook during a shadow week. It
prints nothing and returns at once; a detached copy runs both sides, each with its own records under `DIR` (default
`<record_dir>-shadow`: `py/` and `rs/`), never the live ones. One lock around each pair feeds both the same calls in
order, so their records must stay byte-identical. The Python hook runs through a small shim that points its
`record_path` at `py/`, so the hook needs `record_path(repo, session_id)` and `main()`. Each line in the shadow log
gives the notice kind on each side (`none`, `elsewhere`, `during`, `elsewhere+during`, `crash`), `same`,
`same_reason` (identical output) and `records_same`. After a records difference, `rs/` is reset to a copy of `py/`,
so the difference is logged once. This session's own edits reach neither side's records, so both report them the
same way.

### `claude-guard dns-nxdomain`

The guards only see what Claude's tools do. A script Claude runs (Playwright, a Node script) fetches on its own. For
those, point the blocked domains at this responder with macOS `/etc/resolver/<domain>` files
(`nameserver 127.0.0.1`, `port 10053`) and run `claude-guard dns-nxdomain` as a launchd agent. It answers every query
on 127.0.0.1:10053 with NXDOMAIN at once (so programs fail fast instead of retrying) and logs each name to `web.log`
at most once a minute. The resolver files and the launchd agent are yours to set up; macOS reads `/etc/resolver` only
when the network changes.

## What it doesn't cover

- Anything a script fetches by itself: the hook sees `node script.js`, not the URLs inside. Use the DNS responder.
- Commands you run with `!` in Claude Code: hooks don't see them.
- MCP tools the web guard doesn't know, and IP-literal URLs at the DNS layer (they have no name to block).
- What Claude writes: the prompt guard checks your prompts, not the commands or files Claude produces.
- A hook that doesn't run at all (binary missing, timed out) lets the call through: Claude Code treats a failed hook
  as a non-blocking error.

## Verify a release

Each release has `claude-guard-aarch64-apple-darwin.tar.gz` and its `.sha256`, built by
`.github/workflows/release.yml` on a GitHub-hosted `macos-15` (arm64) runner from the release tag, after the tests
pass, with [build provenance](https://docs.github.com/en/actions/security-guides/using-artifact-attestations) for both
the tarball and the binary. `gh attestation verify` (needs a `gh` login) proves GitHub's runner built that file from
that tag of this repository.

The binary is ad-hoc signed (the linker's default), not Developer ID signed or notarized. `gh` and `curl` downloads
carry no quarantine flag, so macOS runs it; a browser download would be stopped by Gatekeeper.

## Development

```sh
cargo test --release --locked                              # table tests
cargo clippy --release --locked --all-targets -- -D warnings
cargo deny check && cargo audit
```

CI runs all of these on every push and pull request (`.github/workflows/ci.yml`). Dependencies are kept small:
`serde_json` and `regex`, 13 crates in all, no proc macros; `Cargo.lock` is committed and builds use `--locked`.

claude-guard started as a port of Python and shell hooks, checked against them with differential tests and a "shadow"
mode that ran both side by side. The differential tests need those original hooks, which aren't in this repository,
and skip themselves without them. [docs/porting.md](docs/porting.md) has the details, including where Python's
`json`, `re`, `shlex` and `urllib` behave differently from their Rust counterparts. Some messages still carry the
original hooks' names (`guard-bash:`, `Blocked by guard-read-keys.py:`) so tools that matched them keep working.

## Security

Found a way past a guard? Please report it privately: see [SECURITY.md](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
