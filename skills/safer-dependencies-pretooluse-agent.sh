#!/bin/bash
# safer-dependencies-pretooluse-agent.sh — PreToolUse:Agent hook.
#
# Creates a sentinel file immediately before each Agent tool call so that the
# paired PostToolUse:Agent hook can find exactly the manifest and lockfile
# changes written during that agent's run — regardless of whether the subagent
# committed, staged, or left changes unstaged.
#
# The sentinel is keyed on PPID (the Claude Code process PID), which is stable
# for the lifetime of a session and unique across concurrent sessions. Both hooks
# in the pair use the same PPID-based path, so no coordination is needed.
#
# Fail-open: any error exits 0 silently so a broken hook never blocks dispatch.
#
# Install — add to ~/.claude/settings.json (merge with existing hooks block):
#   "PreToolUse": [
#     {"matcher": "Agent", "hooks": [
#       {"type": "command",
#        "command": "${HOME}/.claude/skills/safer-dependencies/safer-dependencies-pretooluse-agent.sh",
#        "timeout": 5}
#     ]}
#   ]
#
# Also install the paired PostToolUse:Agent hook — this hook alone does nothing.

set -uo pipefail

# Read the hook envelope. Claude Code includes a top-level "session_id" field
# that is unique per Claude Code session, so we key the sentinel on
# PPID + session_id to avoid collisions between concurrent sessions whose
# hooks happen to inherit the same parent PID. Falls back to PPID-only when
# the payload omits session_id (e.g. test harnesses), preserving the old key.
input="$(cat 2>/dev/null || true)"
session_id=""
if [ -n "$input" ]; then
  session_id="$(printf '%s' "$input" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    sid = d.get("session_id") or ""
    # Trim to 12 chars — enough entropy for collision resistance, short
    # enough to keep the path readable in a process listing.
    print(str(sid)[:12])
except Exception:
    pass
' 2>/dev/null || true)"
fi

if [ -n "$session_id" ]; then
  SENTINEL="/tmp/.safer-deps-agent-${PPID}-${session_id}.sentinel"
else
  SENTINEL="/tmp/.safer-deps-agent-${PPID}.sentinel"
fi

# Create the sentinel without ever following a pre-existing symlink. The path is
# predictable and lives in world-writable /tmp, so a co-located attacker can
# plant a symlink here; a plain `touch` would follow it and stamp the link
# target's mtime — an arbitrary-file mtime-write primitive (CWE-59). Drop any
# stale/hostile entry first (rm removes the link itself, never its target), then
# create with `set -C` (noclobber) so the open fails closed rather than
# following if a symlink reappears in the race window or sticky-bit ownership
# blocked the unlink. The paired post-hook likewise refuses a symlinked sentinel.
rm -f "$SENTINEL" 2>/dev/null || true
( set -C; : > "$SENTINEL" ) 2>/dev/null || true

exit 0
