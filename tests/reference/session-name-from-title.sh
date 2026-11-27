#!/bin/dash
# Claude Code UserPromptSubmit / SessionStart hook.
# Gives a session that still has its default "<folder>-<hex>" name a readable
# name taken from Claude's own ai-title, so the @ list in other sessions shows
# what each session is doing. herdr Auto Title only copies names from Claude
# to herdr tabs; nothing sets Claude's own name, which is the gap this fills.
#
# Leaves any name already set (-n, /rename, an earlier run of this hook)
# alone, and never blocks the prompt: every failure exits 0 with no output.
# Claude does not de-duplicate hook names, so a name another live session
# holds gets this session's own suffix.
#
# System tools only: a repo's settings env can replace PATH for hooks, and
# hooks run outside the sandbox.
PATH=/usr/bin:/bin
export PATH

in=$(cat) || exit 0
[ -x /usr/bin/jq ] || exit 0

field() { printf '%s' "$in" | jq -r "$1 // empty" 2>/dev/null; }
current=$(field .session_title)
[ -n "$current" ] && exit 0

event=$(field .hook_event_name)
transcript=$(field .transcript_path)
session_id=$(field .session_id)
[ -n "$event" ] && [ -f "$transcript" ] || exit 0
# A custom-title record means the session was named (-n, /rename or this hook),
# also on resume, where the hook input may carry no session_title.
grep -qF '"type":"custom-title"' "$transcript" 2>/dev/null && exit 0

title=$(grep -F '"type":"ai-title"' "$transcript" 2>/dev/null | tail -n 1 | jq -r '.aiTitle // empty' 2>/dev/null)
[ -n "$title" ] || exit 0

# "Herdr tab agent tags" -> "herdr-tab-agent-tags": lowercase, words joined by
# hyphens, no bare numbers or filler words, at most 4 words and 29 characters
# (room for a "-xx" suffix within 32), starting with a letter.
slug=$(printf '%s' "$title" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '\n' \
  | grep -Ev '^([0-9]+|a|an|the|and|or|of|in|on|for|to|with|from|via)$' | head -n 4 \
  | paste -sd- - | cut -c1-29 | sed 's/-*$//; s/^[^a-z]*//')
[ -n "$slug" ] || exit 0

# Live sessions on this Mac: ~/.claude/sessions/<pid>.json, kept by Claude Code.
registry="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/sessions"
# grep picks the candidate files first (names and session ids are plain
# [a-z0-9-], safe in a pattern), so jq runs on a handful of files, not all.
taken() { # $1 = name; true if another live session holds it
  for f in $(grep -lE "\"name\": *\"$1\"" "$registry"/*.json 2>/dev/null); do
    out=$(jq -r '.name // "", .sessionId // "", (.pid // "" | tostring)' "$f" 2>/dev/null) || continue
    { read -r n; read -r sid; read -r pid; } <<EOF
$out
EOF
    [ "$n" = "$1" ] || continue
    [ -n "$session_id" ] && [ "$sid" = "$session_id" ] && continue
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && return 0
  done
  return 1
}

name=$slug
if taken "$name"; then
  # This session's default name ends in its own suffix ("mmt-0c" -> "0c").
  own_name=""
  case "$session_id" in *[!a-z0-9-]*|"") ;; *)
    for f in $(grep -lF "\"$session_id\"" "$registry"/*.json 2>/dev/null); do
      own_name=$(jq -r --arg s "$session_id" 'select(.sessionId == $s and .nameSource == "derived") | .name // empty' "$f" 2>/dev/null)
      [ -n "$own_name" ] && break
    done ;;
  esac
  suffix=$(printf '%s' "$own_name" | sed -n 's/.*-\([a-z0-9]\{2,4\}\)$/\1/p')
  [ -n "$suffix" ] || suffix=$(printf '%s' "$session_id" | tr -cd 'a-z0-9' | cut -c1-2)
  [ -n "$suffix" ] || exit 0
  name="$slug-$suffix"
  if taken "$name"; then
    long=$(printf '%s' "$session_id" | tr -cd 'a-z0-9' | cut -c1-4)
    [ -n "$long" ] || exit 0
    name="$(printf '%s' "$slug" | cut -c1-27 | sed 's/-*$//')-$long"
    taken "$name" && exit 0
  fi
fi

jq -cn --arg e "$event" --arg t "$name" '{hookSpecificOutput:{hookEventName:$e, sessionTitle:$t}}'
