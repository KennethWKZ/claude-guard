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
| `<repo>/.claude/repo-guard.json` | `repo pre-bash` | That repo's rules and wording (version 1): `error_log`; under `pre_bash.logs_insights` the `guard_module` name and the `raw_cli_reason`, `script_reason` (`{path}`), `inline_reason` and `block_message` (`{why}`) texts; for the shared-tree guard `repo_label`, `locked_dirs`, `output_dirs` and the `pre_bash.git` (`block_message` with `{op}` `{message}` `{advice}`, per-operation `messages` and `advice`, defaults, `saved_prune_message`), `shell_writes`, `interpreter_writes` and `write_ledger` (`dir`, `override_env`) sections. Each rule set is on when its section is there. Found through `CLAUDE_PROJECT_DIR`; missing or invalid, the hook allows and says so in a `systemMessage` |

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
   every spelling (`-fr`, `-r -f`, `--recursive --force`, `..` tricks).
2. Commands that name a secrets env file (`.env`, `.env.local`, `prod.env`, `.envrc`, ...) directly, through a glob
   or through brace expansion; recursive `grep`; `rg --hidden`/`--no-ignore` without `-g '!.env*'`. Templates
   (`.env.example`, ...) stay readable, and jq/yq filters such as `'.env.FOO'` are not files.
3. `git push --force` / `-f` (`--force-with-lease` is allowed).
4. `sudo`.
5. `pip install` (tells Claude to use `uv` instead).
6. [rust-anything](https://crates.io/crates/rust-anything) subcommands other than `analyze`, `map`, `doctor` and
   `help` (and `--help` / `--version`). The rest build, run or edit the code being ported; deny their MCP tools
   (`mcp__rust-anything__*`) too, so the CLI isn't the way round. A subcommand added later is blocked until it's
   listed. Found by path, behind wrappers (`timeout`, `nice -n`, `env -i`, `xargs`), in `$(…)` and backticks, and
   inside `bash -c '…'`.

The rules hold inside loops, `if` blocks and `{ … }`. A quoting error in the command allows it, so a typo never locks
the shell; any other failure blocks it and is logged. Input nested too deep to check blocks.

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
