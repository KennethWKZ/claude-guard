"""Claude Code UserPromptSubmit guard: block prompts that carry secrets, blocked names or Malaysian IC numbers.

Runs as `/usr/bin/python3 -I <this file>` (standard library only). Reads the hook JSON on stdin and checks
its `prompt` field. Three checks, in order:

1. Secrets. Built-in rules always run. gitleaks (its default rules) also runs when the prompt holds a long
   run of mixed letters and digits, the shape real tokens have, so plain prose stays fast. It runs in `/`
   (root-owned, so nobody can plant a .gitleaks.toml there) with GITLEAKS_CONFIG* cleared and /dev/null as
   its ignore file, so a repo's .gitleaks.toml or .gitleaksignore can't change its rules, and with a hard
   timeout; if it is missing, fails or times out, the built-in rules stand.
2. Malaysian IC numbers (below).
3. Blocked terms: ~/.config/claude-guard/blocked-terms.txt (`--terms <file>` overrides the path for
   tests). UTF-8, one term per line, `#` comments and blank lines ignored, case-insensitive, whole words
   (spaces in a term match any run of spaces). A missing file means no terms.
   Malaysian IC numbers: YYMMDD-PB-###G, all dashes or none, with a real month and day and a place-of-birth
   code that JPN issues, so order ids and phone numbers don't match. Twelve digits inside a run of 32 or more
   hex characters (a SHA-256, SHA-1, MD5 or git id) are part of a hash, not an IC number.

A secret or an IC number blocks the prompt ({"decision":"block"} on stdout) with the rule name only: the
matched text is never printed, logged or put in the reason. A blocked name only warns (decided
2026-11-24): the prompt goes through, the guard shows a notice and appends one line to
~/.local/state/claude-guard/allow-name.log (time, session id, folder; never the name or the prompt).
Starting the prompt with `[allow-name]` changes only the notice, and the log line records it. Any internal
error allows the prompt and shows one warning, so a broken guard never blocks work.

`--strict`: a name blocks, the marker doesn't apply and nothing is logged. For other hooks that see the
same prompt, such as GraphMind's prompt hook (via ~/.graphmind/prompt-guard), so a name that reaches
Claude still isn't sent on to a search provider.
"""
import os
import stat
import sys

BYTECODE_CACHE = os.path.expanduser("~/Library/Caches/claude-guard/pycache")


def use_bytecode_cache(path):
    """Let Python cache compiled stdlib modules in `path`. Under -I, macOS's /usr/bin/python3 writes no
    bytecode and has no cache folder it may write to, so every prompt compiled json, re and subprocess from
    source (about 20 ms, 45 ms when gitleaks runs). Used only when the folder is a real directory owned by
    this user and not group- or world-writable: a .pyc in it runs inside this hook. Never raises."""
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


# Before the imports below, so they load from the cache. Only as the hook itself: web-guard.py imports
# this file and keeps its own settings.
if __name__ == "__main__":
    use_bytecode_cache(BYTECODE_CACHE)

import json
import re

# subprocess loads only when gitleaks runs, so plain prompts don't pay for it.

GITLEAKS_PATHS = ("/opt/homebrew/bin/gitleaks", "/usr/local/bin/gitleaks")
GITLEAKS_TIMEOUT = 1.0  # seconds; under load gitleaks starts in 150-700 ms
TERMS_FILE = os.path.expanduser("~/.config/claude-guard/blocked-terms.txt")
ALLOW_NAME_MARKER = "[allow-name]"
ALLOW_NAME_LOG = os.path.expanduser("~/.local/state/claude-guard/allow-name.log")

# (rule id, what it looks like, pattern). Rule ids follow gitleaks' names where one exists.
SECRET_RULES = [
    ("aws-access-key-id", "an AWS access key", r"(?<![A-Z0-9])(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}(?![A-Z0-9])"),
    ("private-key", "a private key", r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"),
    ("github-pat", "a GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("atlassian-api-token", "an Atlassian or Bitbucket API token", r"\bATATT3[A-Za-z0-9_=-]{100,}"),
    ("bitbucket-app-password", "a Bitbucket app password", r"\bATBB[A-Za-z0-9_=.-]{28,}"),
    ("slack-token", "a Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    ("slack-webhook-url", "a Slack webhook", r"hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_-]{20,}"),
    ("stripe-secret-key", "a Stripe secret key", r"\b[sr]k_live_[A-Za-z0-9]{20,}"),
    ("gcp-api-key", "a Google API key", r"\bAIza[A-Za-z0-9_-]{35}\b"),
    ("jwt", "a JSON web token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]
SECRET_RES = [(rid, what, re.compile(p)) for rid, what, p in SECRET_RULES]

# `password = <value>` style assignments. The value must look like a literal, so code that reads a
# setting (`password = request.input("password")`, `secret: ${SECRET}`) and placeholders pass.
# The keyword must end the name (DB_PASSWORD, aws_secret_access_key), so SecretId=, secret_name= and
# password_hash= pass.
ASSIGN_RE = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9])[A-Za-z0-9_.-]*?
    (?:password|passwd|secret|secret[_-]?key|api[_-]?key|access[_-]?key|auth[_-]?token|access[_-]?token
       |client[_-]?secret|private[_-]?key)
    ["']?\s*[:=]\s*
    (?:"(?P<dq>[^"\s]{8,200})"|'(?P<sq>[^'\s]{8,200})'|(?P<bare>[A-Za-z0-9!@\#%^&*+/=_~-]{8,200}))
    """
)
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:\$|<|\{|%|\*{3}|x{3}|\.{3}|/|\./|~/)|^(?:changeme|password|secret|example|placeholder|redacted|null|none|"
    r"undefined|your[_-].*|my[_-].*|test[_-]?.*|dummy.*|sample.*|fake.*)$|\(|process\.env|env\(|getenv"
)

# Token-shaped run: 20+ characters of a token alphabet with at least one letter and one digit.
TOKENISH_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")

# JPN place-of-birth codes: states 01-16 and 21-59, foreign 60-68, 71-72, 74-79, 82-93, 98-99.
PB_CODES = {f"{n:02d}" for n in [*range(1, 17), *range(21, 60), *range(60, 69), 71, 72, *range(74, 80),
                                 *range(82, 94), 98, 99]}
IC_RE = re.compile(r"(?<![\d-])(\d{2})(\d{2})(\d{2})(-?)(\d{2})\4(\d{4})(?![\d-])")
DAYS = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
HEX = frozenset("0123456789abcdefABCDEF")
HEX_RUN_MIN = 32  # hashes (SHA-256, SHA-1, MD5, git ids) are at least this long


def block(rule, what, way_out="Remove it and send again."):
    print(json.dumps({
        "decision": "block",
        "reason": f"Blocked: looks like {what} (rule {rule}). {way_out}",
    }))
    sys.exit(0)


def is_literal_secret(value):
    if PLACEHOLDER_RE.search(value):
        return False
    return bool(re.search(r"[A-Za-z]", value) and re.search(r"[0-9!@#%^&*+/=_~-]", value))


def builtin_secret(prompt):
    for rid, what, rx in SECRET_RES:
        if rx.search(prompt):
            return rid, what
    for m in ASSIGN_RE.finditer(prompt):
        value = m.group("dq") or m.group("sq") or m.group("bare")
        if is_literal_secret(value):
            return "secret-assignment", "a password or secret value"
    return None


def needs_gitleaks(prompt):
    for m in TOKENISH_RE.finditer(prompt):
        s = m.group(0)
        if re.search(r"[A-Za-z]", s) and re.search(r"[0-9]", s):
            return True
    return False


def gitleaks_rule(prompt):
    """First gitleaks rule id that matches, or None. Never raises."""
    exe = next((p for p in GITLEAKS_PATHS if os.access(p, os.X_OK)), None)
    if exe is None:
        return None
    try:
        import subprocess
        env = {"PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~")}
        # The report goes to stdout (redacted), so no temp folder is needed.
        out = subprocess.run(
            [exe, "stdin", "--no-banner", "--log-level", "error", "--redact", "--exit-code", "0",
             "--report-format", "json", "--report-path", "-", "--gitleaks-ignore-path", os.devnull],
            input=prompt.encode("utf-8", "replace"), cwd="/", env=env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=GITLEAKS_TIMEOUT, check=False,
        ).stdout
        findings = json.loads(out.decode("utf-8", "replace"))
        for item in findings if isinstance(findings, list) else []:
            rid = item.get("RuleID") if isinstance(item, dict) else None
            if rid:
                return str(rid)
    except Exception:
        return None
    return None


def load_terms(path):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return []
    terms = []
    for line in lines:
        term = line.strip()
        if term and not term.startswith("#") and len(term) >= 2:
            terms.append(term)
    return terms


def blocked_term(prompt, terms):
    if not terms:
        return False
    parts = sorted({r"\s+".join(map(re.escape, t.split())) for t in terms}, key=len, reverse=True)
    rx = re.compile(r"(?<!\w)(?:" + "|".join(parts) + r")(?!\w)", re.IGNORECASE)
    return rx.search(prompt) is not None


def in_hex_run(s, a, b):
    """s[a:b] is all hex and sits in a hex run of HEX_RUN_MIN or more; stops looking once that long."""
    if any(ch not in HEX for ch in s[a:b]):
        return False
    lo, hi = a, b
    while lo > 0 and hi - lo < HEX_RUN_MIN and s[lo - 1] in HEX:
        lo -= 1
    while hi < len(s) and hi - lo < HEX_RUN_MIN and s[hi] in HEX:
        hi += 1
    return hi - lo >= HEX_RUN_MIN


def malaysian_ic(prompt):
    for m in IC_RE.finditer(prompt):
        _, mm, dd, _, pb, _ = m.groups()
        month, day = int(mm), int(dd)
        if (1 <= month <= 12 and 1 <= day <= DAYS[month - 1] and pb in PB_CODES
                and not in_hex_run(prompt, m.start(), m.end())):
            return True
    return False


def log_allow_name(path, data, marker):
    """One audit line per prompt let through with a blocked name. Never raises; never logs the name."""
    import time
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "session_id": str(data.get("session_id") or ""),
                "cwd": str(data.get("cwd") or ""),
                "rule": "blocked-term",
                "marker": marker,
            }) + "\n")
    except Exception:
        pass


def options():
    """Arguments, never environment variables (a repo's settings env reaches hooks and could switch
    the checks off): `--strict` for callers other than Claude Code itself, such as GraphMind's prompt
    hook through ~/.graphmind/prompt-guard, where [allow-name] doesn't apply and nothing is logged;
    `--terms <file>` and `--log <file>` for tests."""
    args, opts, strict = sys.argv[1:], {}, False
    while args:
        if args[0] == "--strict":
            strict, args = True, args[1:]
        elif len(args) >= 2 and args[0] in ("--terms", "--log"):
            opts[args[0]], args = args[1], args[2:]
        else:
            break
    return opts.get("--terms", TERMS_FILE), opts.get("--log", ALLOW_NAME_LOG), strict


def main():
    data = json.load(sys.stdin)
    prompt = data.get("prompt") if isinstance(data, dict) else None
    if not isinstance(prompt, str) or not prompt:
        return
    terms_file, log_file, strict = options()
    notice = None
    hit = builtin_secret(prompt)
    if hit:
        block(*hit)
    if needs_gitleaks(prompt):
        rid = gitleaks_rule(prompt)
        if rid:
            block(rid, "a secret")
    # IC before names, so a prompt blocked for an IC number never logs a name as let through.
    if malaysian_ic(prompt):
        block("malaysian-ic", "a Malaysian IC number")
    if blocked_term(prompt, load_terms(terms_file)):
        if strict:
            block("blocked-term", "a name on your blocked list")
        marker = prompt.startswith(ALLOW_NAME_MARKER)
        log_allow_name(log_file, data, marker)
        notice = (f"guard-prompt: {ALLOW_NAME_MARKER} let a blocked name through for this prompt (logged)." if marker
                  else "guard-prompt: this prompt has a name on your blocked list. It was sent to Claude (logged); "
                       "GraphMind skips it.")
    if notice:
        print(json.dumps({"systemMessage": notice}))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # fail open: never block work because the guard broke
        print(json.dumps({"systemMessage": f"guard-prompt.py failed ({type(e).__name__}); prompt allowed unchecked."}))
        sys.exit(0)
