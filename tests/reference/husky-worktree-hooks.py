"""Copy husky's .husky/_ and graphmind's git hook files into git worktrees.

In a husky repo (core.hooksPath .husky or .husky/_), husky's .husky/_ folder is
git-ignored, so a new worktree doesn't get it and its hooks (pre-commit,
commit-msg) silently don't run, or fail. Where graphmind is set up, its hooks
are also untracked files in the main checkout's .husky/ (post-commit,
post-checkout, post-merge, post-rewrite, pre-push, each holding a
"# graphmind:" line, hidden through .git/info/exclude), so the worktree's graph
never rebuilds either.

Runs as a Claude Code hook (settings.json):
  PostToolUse  Bash|EnterWorktree  after a command that mentions "worktree add"
  SessionStart                     for the repo the session starts in

For every repo it can find from the hook input, it reads the worktree list from
<common git dir>/worktrees/*/gitdir and copies into each worktree that lacks
them: the main checkout's .husky/_ (any husky repo), and the main checkout's
graphmind hook files (only repos that have them). Repos whose main checkout
has neither .husky/_ nor a graphmind hook file in .husky/ are skipped.

Safety: runs outside the sandbox, so it never runs git, project code or
anything from the repo; it only reads and copies files. It never overwrites a
file and always exits 0. Errors go to husky-worktree-hooks.log next to it.
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
import re
import shlex
import shutil
import sys
import traceback

HOOKS = ("post-commit", "post-checkout", "post-merge", "post-rewrite", "pre-push")
MARKER = "# graphmind:"
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "husky-worktree-hooks.log")


def read(path, limit=4096):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def common_git_dir(start):
    """Walk up from start to the repo's common git dir, by reading files only."""
    d = os.path.abspath(start)
    while True:
        dot = os.path.join(d, ".git")
        if os.path.isdir(dot):
            return dot
        if os.path.isfile(dot):
            m = re.match(r"gitdir:\s*(.+)", read(dot).strip())
            if not m:
                return None
            gitdir = m.group(1).strip()
            if not os.path.isabs(gitdir):
                gitdir = os.path.normpath(os.path.join(d, gitdir))
            common = read(os.path.join(gitdir, "commondir")).strip()
            if common:
                return os.path.normpath(os.path.join(gitdir, common))
            return gitdir
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def worktree_roots(common):
    roots = []
    base = os.path.join(common, "worktrees")
    try:
        names = os.listdir(base)
    except OSError:
        return roots
    for name in names:
        gitfile = read(os.path.join(base, name, "gitdir")).strip()
        if gitfile:
            root = os.path.dirname(gitfile)
            if os.path.isdir(root):
                roots.append(root)
    return roots


def sync_repo(common):
    """Copy .husky/_ and graphmind hook files into worktrees missing them."""
    main = os.path.dirname(common)
    src_husky = os.path.join(main, ".husky")
    src_underscore = os.path.join(src_husky, "_")
    has_underscore = os.path.isdir(src_underscore)
    hooks = [h for h in HOOKS if MARKER in read(os.path.join(src_husky, h))]
    if not hooks and not has_underscore:
        return []
    done = []
    for root in worktree_roots(common):
        dst_husky = os.path.join(root, ".husky")
        if os.path.realpath(root) == os.path.realpath(main) or not os.path.isdir(dst_husky):
            continue
        copied = []
        dst_underscore = os.path.join(dst_husky, "_")
        if has_underscore and not os.path.lexists(dst_underscore):
            shutil.copytree(src_underscore, dst_underscore, symlinks=True)
            copied.append(".husky/_")
        for h in hooks:
            dst = os.path.join(dst_husky, h)
            if not os.path.lexists(dst):
                shutil.copy2(os.path.join(src_husky, h), dst)
                copied.append(h)
        if copied:
            done.append("%s (%s)" % (root, ", ".join(copied)))
    return done


def candidate_dirs(data):
    cwd = data.get("cwd") or os.getcwd()
    dirs = [cwd]
    if data.get("hook_event_name") != "PostToolUse" or data.get("tool_name") != "Bash":
        return dirs
    cmd = (data.get("tool_input") or {}).get("command") or ""
    try:
        words = shlex.split(cmd, posix=True)
    except ValueError:
        words = cmd.split()
    for i, w in enumerate(words[:-1]):
        nxt = words[i + 1]
        if w in ("-C", "cd") or (w == "add" and i > 0 and words[i - 1] == "worktree"):
            p = os.path.expanduser(nxt)
            dirs.append(p if os.path.isabs(p) else os.path.join(cwd, p))
    return dirs


def main():
    data = json.load(sys.stdin)
    event = data.get("hook_event_name", "")
    if event == "PostToolUse" and data.get("tool_name") == "Bash":
        cmd = (data.get("tool_input") or {}).get("command") or ""
        if not re.search(r"\bworktree\s+add\b", cmd):
            return
    seen, done = set(), []
    for d in candidate_dirs(data):
        if not os.path.isdir(d):
            continue
        common = common_git_dir(d)
        if common and common not in seen:
            seen.add(common)
            done += sync_repo(common)
    if done:
        msg = "husky/graphmind hooks copied into worktree(s): " + "; ".join(done)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": msg}}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        try:
            with open(LOG, "a") as f:
                f.write(traceback.format_exc() + "\n")
        except OSError:
            pass
    sys.exit(0)
