#!/usr/bin/python3
"""Claude Code PreToolUse guard for Bash commands (team guardrail).

Blocks, before the command runs:
  1. rm with recursive+force flags on an absolute path, unless the target is inside $TMPDIR or /tmp.
  2. Commands that name a secrets env file (.env, .env.local, .env.production, prod.env, direnv's .envrc, ...)
     directly or through a glob (.env*), so Claude cannot read it into its context through cat, grep, sed, source,
     cp, base64 and so on; plus recursive grep and rg --hidden/--no-ignore, which open .env files without naming
     them.
     Templates stay readable: .env.example, .env.sample, .env.template, .env.dist, .env.defaults.
     The filter of jq/gojq/jaq/yq ('.env.FOO') is a path into the data, not a file; their file arguments
     are still checked.
  3. git push with --force or -f (use --force-with-lease, or run it yourself).
  4. sudo.

This adds to permission prompts and deny rules; it does not replace them. It only sees what is written in the
command: a path hidden in a variable or built by a script (python, node, find -exec) is not caught. Heredoc
bodies are data and are skipped, unless a shell (bash, sh, zsh) reads them. On a parse
error it allows the command, so a quoting mistake never locks the shell; a command that isn't text
is allowed with a warning; any other crash blocks the command (fail closed), including input nested
too deep to check or to read as JSON, and is logged to ~/.claude/hooks/guard-bash.crash.log.
Python 3.9 compatible (macOS /usr/bin/python3). No dependencies.
"""
import os
import stat
import sys

BYTECODE_CACHE = os.path.expanduser("~/Library/Caches/claude-guard/pycache")


def use_bytecode_cache(path):
    """Cache compiled stdlib modules in `path` (the same helper as guard-prompt.py). Under -I, macOS's
    /usr/bin/python3 writes no bytecode and has no cache folder it may write to, so every run compiled this
    hook's imports from source. Used only when the folder is a real directory owned by this user and not
    group- or world-writable: a .pyc in it runs inside this hook. Never raises."""
    try:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            os.makedirs(path, mode=0o700, exist_ok=True)
            st = os.lstat(path)
        if stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o022:
            sys.pycache_prefix = path
            sys.dont_write_bytecode = False
    except Exception:
        pass


# Before the imports below, so they load from the cache. Only when run as the hook itself.
if __name__ == "__main__":
    use_bytecode_cache(BYTECODE_CACHE)

import fnmatch, glob, json, os, re, shlex, sys

SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "!"}
PREFIXES = {"command", "builtin", "exec", "nohup", "time", "env", "xargs", "nice"}
# Shell keywords in front of a command (for ...; do CMD, if ...; then CMD, { CMD; }). Skipped so CMD is
# judged as itself: otherwise `do sudo ...` slips past the verb rules and `do jq '.env.X' f` looks like a read.
KEYWORDS = {"do", "then", "else", "elif", "if", "while", "until", "{", "}"}
ENV_FILE = re.compile(r"(^|/)(\.env(\.[^/]+)?|\.envrc|[^/]+\.env)$")
ENV_TEMPLATE = re.compile(r"\.(example|sample|template|dist|defaults)$")
# Something inside a temp dir, never the temp dir itself (macOS resolves /tmp and /var to /private/...).
TEMP_ITEM = re.compile(r"^/private/tmp/[^/]+|^/private/var/folders/[^/]+/[^/]+/T/[^/]+")
# Commands that name a .env file without reading its contents (ln makes a link, printf prints its arguments).
ENV_SAFE_VERBS = {"ls", "test", "[", "stat", "touch", "rm", "chmod", "mkdir", "echo", "printf", "ln"}
# Output redirections: the file after one is written, not read (`> .env`). Input (`<`, `<>`) still counts.
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>"}
# JSON/YAML query tools: their first plain argument is a filter program (`.env.FOO` is a path into the
# data), not a file. Their file arguments, and -f/--from-file programs, are still checked.
JQ_VERBS = {"jq", "gojq", "jaq", "yq"}
# Options that take values, so the value isn't mistaken for the filter. --slurpfile/--rawfile name a
# file as their second value; it stays checked like any other argument.
JQ_VALUE_OPTS = {"--arg": 2, "--argjson": 2, "--slurpfile": 2, "--rawfile": 2, "--indent": 1,
                 "-L": 1, "--library-path": 1}
YQ_VALUE_OPTS = {"-o": 1, "--output-format": 1, "-p": 1, "--input-format": 1, "-I": 1,
                 "--front-matter": 1, "--expression": 1}


def jq_filter_index(verb, args):
    """Index in args of the filter program of jq/gojq/jaq/yq, or None when there is none
    (-f/--from-file reads the program from a file, which must stay checked)."""
    if verb not in JQ_VERBS:
        return None
    value_opts = dict(JQ_VALUE_OPTS, **YQ_VALUE_OPTS) if verb == "yq" else JQ_VALUE_OPTS
    i = 1 if verb == "yq" and args[:1] and args[0] in ("eval", "e", "eval-all", "ea") else 0
    while i < len(args):
        a = args[i]
        if a in ("-f", "--from-file") or a.startswith("--from-file="):
            return None
        if a == "--":
            return i + 1 if i + 1 < len(args) else None
        if a in value_opts:
            i += 1 + value_opts[a]
            continue
        if a.startswith("-") and a != "-":
            i += 1
            continue
        return i
    return None


# A heredoc start: <<EOF, <<-EOF, <<'EOF', <<"EOF" (not the <<< here-string).
HEREDOC = re.compile(r"(?<!<)<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "eval", "source", "."}


def split_heredocs(command):
    """Remove heredoc bodies. A body is data for the command that reads it (cat > file, python -), so
    its text is not shell; checking it caused false alarms on code that mentions rm -rf or .env.
    Bodies read by a shell do run as commands, so they are returned to be checked on their own."""
    lines, out, run_as_shell = command.split("\n"), [], []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for m in HEREDOC.finditer(line):
            tabs, delim, body = m.group(1) == "-", m.group(3), []
            while i < len(lines):
                body_line = lines[i]
                i += 1
                if (body_line.lstrip("\t") if tabs else body_line) == delim:
                    break
                body.append(body_line)
            words = re.split(r"[;&|(]", line[:m.start()])[-1].split()
            if words and os.path.basename(words[0]) in SHELLS:
                run_as_shell.append("\n".join(body))
    return "\n".join(out), run_as_shell


def tokenize(command):
    lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()!<>")
    lex.whitespace_split = True
    return list(lex)


def segments(tokens):
    """Split into simple commands: [verb, args...], skipping prefixes like `env`, `xargs`, VAR=value."""
    out, cur = [], []
    for t in tokens + [";"]:
        if t in SEPARATORS:
            while cur and (cur[0] in PREFIXES or cur[0] in KEYWORDS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", cur[0])):
                cur.pop(0)
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(t)
    return out


def is_secret_env(token):
    path = token.split("=", 1)[1] if token.startswith("--") and "=" in token else token
    if any(c in path for c in "*?["):  # globs are judged by what they expand to (glob_hits_secret)
        return False
    return bool(ENV_FILE.search(path)) and not ENV_TEMPLATE.search(path)


ENV_PROBES = (".env", ".env.local", ".env.production", ".env.staging", ".envrc", "prod.env")


def split_top(text):
    """Split on commas that are not inside nested braces."""
    parts, depth, cur = [], 0, ""
    for c in text:
        if c == "," and depth == 0:
            parts.append(cur)
            cur = ""
            continue
        depth += (c == "{") - (c == "}")
        cur += c
    return parts + [cur]


def expand_braces(word, limit=256):
    """Brace expansion as the shell does it for comma lists, nested included (no {1..3} ranges):
    .env{,.prod} -> [.env, .env.prod]. A group without a comma ({} or {"env":"x"}) stays literal."""
    depth, start = 0, None
    for i, c in enumerate(word):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}" and depth > 0:
            depth -= 1
            if depth == 0:
                parts = split_top(word[start + 1:i])
                if len(parts) > 1:
                    out = []
                    for p in parts:
                        out += expand_braces(word[:start] + p + word[i + 1:], limit)
                        if len(out) >= limit:
                            return out[:limit]
                    return out
    return [word]


def glob_hits_secret(token, cwd):
    """True if a shell glob or brace expansion in `token` would produce a secrets env file."""
    words = expand_braces(token)
    if len(words) > 1:
        return any(is_secret_env(w) or glob_hits_secret(w, cwd) for w in words)
    if not any(c in token for c in "*?["):
        return False
    # A bracket that isn't a valid range ([i-0...] in jq or AWS --query text) makes Python 3.9's
    # glob/fnmatch raise re.error. The shell leaves such a word as it is, so it names no file.
    try:
        if cwd or os.path.isabs(token):  # expand it the way the shell would, against the real directory
            pattern = token if os.path.isabs(token) else os.path.join(cwd, token)
            return any(is_secret_env(m) for m in glob.glob(pattern)[:500])
        base = os.path.basename(token)  # no cwd: assume the usual secrets files could exist
        return any(fnmatch.fnmatchcase(p, base) and is_secret_env(p) for p in ENV_PROBES)
    except (re.error, OSError, ValueError):
        return is_secret_env(token.replace("[", "").replace("]", ""))


ENV_EXCLUDES = {"!.env*", "!*.env*", "!**/.env*", "!**/*.env*"}


def rg_excludes_env(args):
    """True if rg is told to skip every .env file: -g '!.env*', --glob=!.env*, --iglob, or **/ forms.
    '!.env' alone doesn't count: it still reads .env.local and .env.production."""
    globs = []
    for i, a in enumerate(args):
        if a in ("-g", "--glob", "--iglob") and i + 1 < len(args):
            globs.append(args[i + 1])
        elif a.startswith(("--glob=", "--iglob=")):
            globs.append(a.split("=", 1)[1])
        elif a.startswith("-g") and len(a) > 2:
            globs.append(a[2:])
    return any(g in ENV_EXCLUDES for g in globs)


def home_path(arg):
    """arg with a leading ~, $HOME or ${HOME} replaced by the home folder; other args unchanged."""
    for start in ("~", "$HOME", "${HOME}"):
        if arg == start or arg.startswith(start + "/"):
            return os.path.expanduser("~") + arg[len(start):]
    return arg


def check(command, cwd=None):
    command, shell_bodies = split_heredocs(command)
    for body in shell_bodies:
        reason = check(body, cwd)
        if reason:
            return reason
    try:
        raw = tokenize(command)
        segs = segments(raw)
    except ValueError:
        return None
    for seg in segs:
        verb, args = os.path.basename(seg[0]), seg[1:]
        if verb == "sudo":
            return "sudo is blocked: Claude never needs admin rights. Run it yourself if you must."
        if verb == "rm":
            flags = [a for a in args if a.startswith("-")]
            short = "".join(f[1:] for f in flags if not f.startswith("--"))
            if ("r" in short or "R" in short or "--recursive" in flags) and ("f" in short or "--force" in flags):
                # ~/x and $HOME/x are absolute paths too: the shell expands them before rm runs.
                paths = {a: home_path(a) for a in args}
                bad = [a for a, p in paths.items() if p.startswith("/") and not TEMP_ITEM.match(os.path.realpath(p))]
                if bad:
                    return ("recursive force delete outside temp dirs (" + ", ".join(bad) + "). "
                            "Only items inside $TMPDIR or /tmp are allowed; run it yourself after checking the path.")
        if verb == "git" and "push" in args and ("--force" in args or "-f" in args
                                                 or any(re.match(r"^-[a-zA-Z]*f", a) for a in args if not a.startswith("--"))):
            return "git push --force is blocked. Use --force-with-lease, or run it yourself."
        # Recursive searches open every file, .env included. rg and Claude's Grep tool skip hidden/gitignored files.
        if verb in ("grep", "egrep", "fgrep") and any(
                a in ("-r", "-R", "--recursive", "--dereference-recursive") or re.match(r"^-[a-zA-Z]*[rR]", a)
                for a in args if a.startswith("-") and not a.startswith("--include") and not a.startswith("--exclude")):
            return "recursive grep also reads .env files. Use rg (skips hidden and gitignored files) or the Grep tool."
        if verb == "rg" and any(a in ("--hidden", "--no-ignore", "-uu", "-uuu", "-.") or a.startswith("--no-ignore")
                                for a in args) and not rg_excludes_env(args):
            return "rg with --hidden/--no-ignore also reads .env files. Run plain rg, or exclude them with -g '!.env*'."
        if verb not in ENV_SAFE_VERBS:
            # An exclusion glob (rg -g '!.env*', --glob=!**/.env*) names .env files in order to skip them.
            written = {i + 1 for i, a in enumerate(args) if a in WRITE_REDIRECTS}
            # A jq/yq filter such as '.env.FOO' is a path into the JSON, not a file name.
            written.add(jq_filter_index(verb, args))
            secret = [a for i, a in enumerate(args) if i not in written and not a.split("=", 1)[-1].startswith("!")
                      and (is_secret_env(a) or glob_hits_secret(a, cwd))]
            # Creating a .env from a template (`cp .env.example .env`) writes it without reading it.
            # A destination that brace-expands (cp .env{,.bak}) is really a source too.
            if verb in ("cp", "install") and args and secret == [args[-1]] and len(expand_braces(args[-1])) == 1:
                secret = []
            if secret:
                return ("reading a secrets file (" + ", ".join(secret) + ") would put its values in Claude's context. "
                        "Templates like .env.example are fine; read the real file yourself.")
    return None


CRASH_LOG = os.path.expanduser("~/.claude/hooks/guard-bash.crash.log")


def log_crash(command, error):
    """Append the traceback and the start of the command (it may hold secrets: cut, mode 600)."""
    import time, traceback
    try:
        fd = os.open(CRASH_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(f"--- {time.strftime('%F %T')} python {sys.version.split()[0]}\n"
                    f"{command[:500]!r}\n{traceback.format_exc()}\n")
    except OSError:
        pass


def crashed(command, e):
    """Log a crash and return the reason that blocks the command (call inside the except block)."""
    log_crash(command, e)
    return (f"guard-bash crashed ({type(e).__name__}: {e}); command blocked. "
            f"Details in {CRASH_LOG}. Report it so the guard can be fixed.")


def main():
    try:
        payload = json.load(sys.stdin)
        command = payload.get("tool_input", {}).get("command", "")
    except (ValueError, AttributeError):
        return
    except RecursionError as e:  # JSON nested too deep to read blocks too (it used to exit 1, which let it run)
        payload, command, reason = {}, "", crashed("", e)
    else:
        # A command that isn't text (Claude Code always sends text) can't hide a shell command: allow it with a
        # warning instead of crashing. Too-deep input still blocks below: anyone can pad a command that way.
        if command and not isinstance(command, str):
            print(json.dumps({"systemMessage": "guard-bash: couldn't check this command (input not text); allowed."}))
            return
        try:
            reason = check(command, payload.get("cwd")) if command else None
        except Exception as e:  # fail closed: a bug in the guard must not let the command through
            reason = crashed(command, e)
    if reason:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "guard-bash: " + reason,
        }}))


if __name__ == "__main__":
    main()
