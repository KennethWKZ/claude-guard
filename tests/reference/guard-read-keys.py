#!/usr/bin/python3
"""Claude Code PreToolUse guard for the Read tool: refuse key and certificate-store files.

Claude's Read tool runs outside the Bash sandbox, and Read() deny rules only cover the
paths they name. A home-wide Read(~/**/*.pem) rule would also be merged into the sandbox
and block the certifi/cacert.pem bundles Python needs for HTTPS. So this hook checks the
file name instead, anywhere: the requested path and the path a symlink resolves to,
case-insensitively. A few machine keys have generic names (Lima's and Colima's SSH key is
a file called "user"), so those are matched by the end of their path. Keys can have any
name (~/.ssh/github_work), so it also reads the first 4 KiB of an existing regular file
and blocks one with a line that starts with a private-key header (PEM or OpenSSH, PGP,
PuTTY). Nothing it reads is shown to Claude. Tools' credential files in the home folder
(~/.npmrc, ~/.docker/config.json, ~/.config/gh/hosts.yml, ...) are refused by path; they
aren't Read() deny rules because those also reach the sandbox, and sandboxed npm, gh and
graphmind need them.

Exit 0 allows the read, exit 2 blocks it and shows stderr to Claude. Unreadable hook
input allows (as guard-bash.py does); any other crash blocks.
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

import json
import os
import pwd
import re
import sys
import traceback

KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", "_deploy_key", "_private_key")
KEY_PREFIXES = ("private_key_",)
# OpenSSH defaults, plus Vagrant's per-machine key (.vagrant/machines/<name>/<provider>/private_key).
KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "private_key")
# OpenSSH key names with a suffix (id_ed25519-work, id_rsa_github); their .pub files are fine.
KEY_NAME_PATTERN = re.compile(r"^id_(rsa|dsa|ecdsa|ed25519|ecdsa_sk|ed25519_sk)[-_.]")
# Lima's and Colima's machine SSH key.
KEY_PATH_ENDINGS = ("/.lima/_config/user", "/_lima/_config/user")
# A line that starts a private key: PEM and OpenSSH, PGP, PuTTY.
KEY_HEADER = re.compile(rb"(?m)^(-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----|PuTTY-User-Key-File-)")
SNIFF_BYTES = 4096
# Credential files, relative to the home folder. Folders end with "/".
HOME_CREDENTIALS = (
    ".npmrc", ".yarnrc.yml", ".pypirc", ".netrc", ".git-credentials", ".pgpass", ".my.cnf",
    ".vault-token", ".docker/config.json", ".kube/config", ".config/gh/hosts.yml",
    ".claude/.credentials.json", ".codex/auth.json", ".local/share/opencode/auth.json",
    ".graphmind/config.json", ".config/stripe/config.toml", ".config/auth0/config.json",
    ".config/configstore/firebase-tools.json", ".terraform.d/credentials.tfrc.json",
    ".composer/auth.json", ".config/composer/auth.json", ".cargo/credentials.toml",
    ".cargo/credentials", ".gem/credentials", ".gnupg/private-keys-v1.d/",
)


def is_key_file(path):
    path = path.lower()
    name = os.path.basename(path)
    return (name.endswith(KEY_SUFFIXES) or name.startswith(KEY_PREFIXES) or name in KEY_NAMES
            or (KEY_NAME_PATTERN.match(name) is not None and not name.endswith(".pub"))
            or path.endswith(KEY_PATH_ENDINGS))


def is_home_credential(path):
    """The real home folder (user database), not $HOME, which a caller can override."""
    home = os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
    for base in {home, pwd.getpwuid(os.getuid()).pw_dir}:
        rel = os.path.relpath(path, base) if path.startswith(base + os.sep) else None
        if rel and any(rel == c or (c.endswith("/") and rel.startswith(c)) for c in HOME_CREDENTIALS):
            return True
    return False


def has_key_header(path):
    """True if the file starts a private key near its top. Missing, unreadable and special
    files (FIFOs, devices) are left to the Read tool."""
    try:
        if not os.path.isfile(path):
            return False
        with open(path, "rb") as f:
            head = f.read(SNIFF_BYTES)
    except OSError:
        return False
    return KEY_HEADER.search(head) is not None


def main():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return 0
    if not isinstance(data, dict):
        return 0
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        return 0
    path = tool_input.get("file_path")
    if not isinstance(path, str) or not path:
        return 0

    path = os.path.expanduser(path)
    if not os.path.isabs(path):
        path = os.path.join(data.get("cwd") or os.getcwd(), path)

    real = os.path.realpath(path)
    for candidate in (path, real):
        if is_key_file(candidate):
            return block(candidate, "looks like a private key or certificate store")
        if is_home_credential(candidate):
            return block(candidate, "is a credential file")
    if has_key_header(real):
        return block(path, "contains a private key")
    return 0


def block(path, why):
    print(
        "Blocked by guard-read-keys.py: %s %s. Don't read key or credential files; work from "
        "the path, and ask the user if the task needs the contents." % (os.path.basename(path), why),
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("guard-read-keys.py crashed, so the read is blocked:\n" + traceback.format_exc(), file=sys.stderr)
        sys.exit(2)
