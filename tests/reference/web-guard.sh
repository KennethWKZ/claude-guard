#!/bin/dash
# Fast path for web-guard.py (Claude Code PreToolUse/PostToolUse hook). Most Bash calls fetch nothing,
# so for Bash this starts Python only when the input mentions a fetch tool or a URL; every other tool the
# hook is registered for (ccs-browser, ctx_index, ctx_search, WebSearch, WebFetch) always goes through.
# Usage (settings.json): /bin/dash ~/.claude/hooks/web-guard.sh pre|post
PATH=/usr/bin:/bin
in=$(cat) || exit 0
case "$in" in
  *'"tool_name":"Bash"'*|*'"tool_name": "Bash"'*)
    case "$in" in
      *curl*|*wget*|*agent-browser*|*://*|*xh\ *|*aria2c*|*lynx*|*'links '*|*'http '*|*'https '*) ;;
      *) exit 0 ;;
    esac ;;
esac
# The folder comes from ${0%/*}, not $(dirname): a $( ) on the right of this pipe made each call
# about 120 ms slower (measured 24 Nov 2026, under dash and bash alike).
case "$0" in */*) dir=${0%/*} ;; *) dir=. ;; esac
printf '%s' "$in" | /usr/bin/python3 -I "$dir/web-guard.py" "$@"
