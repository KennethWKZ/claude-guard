#!/bin/dash
# Not Rust: interim until `claude-guard bash` (rust-hooks plan, phase 1); dash on purpose (fast start).
# Claude Code PreToolUse hook (matcher Bash): blocks `pip install`, `pip3 install` and `python -m pip install`
# at the start of a command or after ; & |, and tells Claude to use uv. Exit 2 blocks with the message on stderr;
# anything else (no match, bad input, no jq) allows.
# Usage (settings.json): /bin/dash ~/.claude/hooks/block-pip.sh
# Was an inline command in settings.json until 2026-11-24; same match, same message.
PATH=/usr/bin:/bin
cmd=$(jq -r '.tool_input.command' 2>/dev/null) || exit 0
if printf '%s' "$cmd" | grep -qE '(^|[;&|][[:space:]]*)(python3? -m )?pip3? install'; then
  echo 'Do not use pip. Use uv instead. Example: uv add <packages>' >&2
  exit 2
fi
exit 0
