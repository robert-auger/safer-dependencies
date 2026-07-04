#!/bin/bash
# safer-dependencies-posttooluse-agent.sh — PostToolUse:Agent hook.
#
# After a subagent run completes, finds every manifest and lockfile the
# subagent wrote (using the sentinel from the paired PreToolUse:Agent hook),
# and audits each one via the existing shim. Findings are returned as
# additionalContext so the root session sees them in its next turn.
#
# WHY THIS HOOK EXISTS
# --------------------
# PostToolUse:Write|Edit and PreToolUse:Bash hooks only fire for the root
# session. Subagent Write/Edit/Bash calls bypass all three hooks entirely —
# any package a subagent writes into a manifest is otherwise unchecked.
# This hook closes that gap reactively: it fires in the root session after
# each Agent call and audits whatever the subagent touched.
#
# SENTINEL APPROACH
# -----------------
# The paired PreToolUse:Agent hook touches
# /tmp/.safer-deps-agent-$PPID-<session_id>.sentinel (falling back to
# /tmp/.safer-deps-agent-$PPID.sentinel when no session id is available)
# immediately before dispatch. This hook finds files newer than that sentinel,
# which is precise regardless of whether the subagent committed or not, and
# naturally covers nested subagents (agent A dispatching agent B) because the
# root's PostToolUse fires only after all of A's work — including B's writes —
# is complete on disk.
#
# Fail-open: any error, missing sentinel, missing shim, or unreadable payload
# exits 0 silently so a broken hook never blocks the root session.
#
# Install — add to ~/.claude/settings.json (merge with existing hooks block):
#   "PostToolUse": [
#     {"matcher": "Agent", "hooks": [
#       {"type": "command",
#        "command": "${HOME}/.claude/skills/safer-dependencies/safer-dependencies-posttooluse-agent.sh",
#        "timeout": 120}
#     ]}
#   ]
#
# Also install the paired PreToolUse:Agent hook — without it no sentinel exists
# and this hook exits immediately on every call.

# shellcheck disable=SC2154
set -uo pipefail

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIM="${HOOK_DIR}/shim.sh"
if [ ! -f "$SHIM" ]; then
  SHIM="${HOOK_DIR}/safer-dependencies-shim.sh"
fi

# ── FAIL-OPEN DIAGNOSTIC EMITTER ─────────────────────────────────────────────
emit_fail_open() {
  local reason="${1:-unknown}" detail="${2:-}" ts log_path log_dir
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)" || return 0
  log_path="${SAFE_DEP_AUDIT_LOG:-${HOME}/.claude/safer-dependencies-audit-$(date -u +%Y-%m 2>/dev/null).log}"
  log_dir="${log_path%/*}"
  mkdir -p "$log_dir" 2>/dev/null || return 0
  local detail_field=""
  if [ -n "$detail" ]; then
    # JSON-escape: detail is a filesystem path that can legally contain " and
    # \ (and, rarely, control chars), which would otherwise corrupt the log
    # line. Pure bash — fail-open must not depend on python3, since a missing
    # python3 is itself a fail-open reason.
    detail="${detail//\\/\\\\}"
    detail="${detail//\"/\\\"}"
    detail="${detail//$'\t'/\\t}"
    detail="${detail//$'\n'/\\n}"
    detail="${detail//$'\r'/\\r}"
    detail_field=',"detail":"'"$detail"'"'
  fi
  ( umask 077
    printf '{"ts":"%s","schema":"2.0","source":{"component":"agent.posttooluse","script":"safer-dependencies-posttooluse-agent.sh","hook":"PostToolUse","tool":"Agent","mode":"fail_open"},"fail_open":{"reason":"%s"%s}}\n' \
    "$ts" "$reason" "$detail_field" >> "$log_path" 2>/dev/null || true )
  chmod 600 "$log_path" 2>/dev/null || true  # issue #210: never world-readable
}

# Fail-open if shim is absent.
if [ ! -f "$SHIM" ]; then
  emit_fail_open "shim_missing" "${HOOK_DIR}"
  exit 0
fi

# Fail-open if Python is missing — required to parse hook envelope.
if ! command -v python3 >/dev/null 2>&1; then
  emit_fail_open "python_missing"
  exit 0
fi

# Parse cwd + session_id from the hook envelope in a single Python call.
# Agent tool payloads include top-level "cwd" and "session_id" fields. The
# sentinel key matches the paired PreToolUse:Agent hook (PPID + session_id,
# falling back to PPID alone if session_id is absent).
input="$(cat 2>/dev/null || true)"
if [ -z "$input" ]; then
  exit 0
fi

parsed="$(printf '%s' "$input" | python3 -c '
import json, sys, shlex
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
print("cwd=%s" % shlex.quote(d.get("cwd", "") or ""))
print("session_id=%s" % shlex.quote(str(d.get("session_id") or "")[:12]))
' 2>/dev/null || true)"

if [ -z "$parsed" ]; then
  exit 0
fi

# shellcheck disable=SC1090
eval "$parsed"

# Locate the sentinel written by PreToolUse:Agent. Try the session-keyed
# path first (current scheme); fall back to the PPID-only path so a hook
# pair where one side is upgraded ahead of the other still functions.
# shellcheck disable=SC2154
if [ -n "$session_id" ]; then
  SENTINEL="/tmp/.safer-deps-agent-${PPID}-${session_id}.sentinel"
  if [ ! -f "$SENTINEL" ]; then
    SENTINEL="/tmp/.safer-deps-agent-${PPID}.sentinel"
  fi
else
  SENTINEL="/tmp/.safer-deps-agent-${PPID}.sentinel"
fi

# Refuse a sentinel that is a symlink. The pre-hook always creates a plain file,
# so a symlink at this predictable /tmp path is stale or hostile. `find -newer`
# would compare against the *link's own* mtime, so a future-dated symlink makes
# every scan match nothing and silently suppresses the entire audit (CWE-377).
# Drop it and fail open rather than scan against attacker-controlled state.
if [ -L "$SENTINEL" ]; then
  emit_fail_open "sentinel_not_regular_file" "symlink"
  rm -f "$SENTINEL" 2>/dev/null || true
  exit 0
fi

if [ ! -f "$SENTINEL" ]; then
  exit 0
fi

# shellcheck disable=SC2154
if [ -z "$cwd" ] || [ ! -d "$cwd" ]; then
  exit 0
fi

# ── SHARED DISPATCH ──────────────────────────────────────────────────────────
# Reuses the same forged-payload pattern as posttooluse-bash.sh so the shim
# receives identical input regardless of which hook triggered the audit.

all_signals=()

dispatch_to_shim() {
  local path="$1" tag="$2"
  local forged shim_out ctx
  forged="$(SD_FILE_PATH="$path" SD_SESSION_TAG="$tag" python3 - <<'PY'
import json, os
fp  = os.environ["SD_FILE_PATH"]
tag = os.environ.get("SD_SESSION_TAG", "posttooluse-agent")
print(json.dumps({
    "session_id": tag,
    "hook_event_name": "PostToolUse",
    "tool_name": "Write",
    "tool_input": {"file_path": fp, "content": ""},
    "tool_response": {"type": "update", "filePath": fp, "content": "",
                      "structuredPatch": [], "originalFile": None},
}))
PY
)"
  # SAFE_DEP_CALLER tells the shim to write component=agent.posttooluse to
  # the audit log (issue #141) so stats correctly bucket subagent-dispatched
  # audits as post-agent rather than intercept.
  shim_out="$(printf '%s' "$forged" \
    | SAFE_DEP_CALLER="agent.posttooluse" bash "$SHIM" 2>/dev/null \
    || true)"
  if [ -n "$shim_out" ]; then
    # The shim prepends a [safer-dependencies <ver>] header to every ctx.
    # Strip it from each per-file dispatch — we add one fresh header at the
    # combined-emission step below so the agent sees attribution exactly once.
    ctx="$(printf '%s' "$shim_out" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    ctx = d.get("hookSpecificOutput", {}).get("additionalContext", "")
    if ctx.startswith("[safer-dependencies "):
        nl = ctx.find("\n")
        ctx = ctx[nl + 1:] if nl != -1 else ""
    print(ctx)
except Exception:
    pass
' 2>/dev/null || true)"
    [ -n "$ctx" ] && all_signals+=("$ctx")
  fi
}

# ── MANIFEST SCAN ─────────────────────────────────────────────────────────────
# Finds manifests the subagent wrote. maxdepth 5 covers monorepo layouts.
# node_modules/.git/.venv/venv excluded to keep find() fast.

MANIFEST_PATTERNS=(
  'package.json'
  'requirements*.txt'
  'pyproject.toml'
  'Pipfile'
  'Cargo.toml'
  'Gemfile'
  '*.gemspec'
  'pom.xml'
  'build.gradle'
  'build.gradle.kts'
  'go.mod'
)

for pat in "${MANIFEST_PATTERNS[@]}"; do
  while IFS= read -r mf; do
    [ -n "$mf" ] && dispatch_to_shim "$mf" "posttooluse-agent-manifest"
  done < <(find "$cwd" -maxdepth 5 -type f -name "$pat" -newer "$SENTINEL" \
             -not -path "*/node_modules/*" \
             -not -path "*/.git/*" \
             -not -path "*/.venv/*" \
             -not -path "*/venv/*" \
             2>/dev/null)
done

# ── LOCKFILE SCAN ─────────────────────────────────────────────────────────────
# Catches subagent `npm install` / `bundle install` etc. that write lockfiles
# without going through Write/Edit. maxdepth 2: lockfiles live at project root
# or one level down in monorepos.

LOCK_PATTERNS=(
  'package-lock.json'
  'pnpm-lock.yaml'
  'yarn.lock'
  'Gemfile.lock'
  'poetry.lock'
  'uv.lock'
  'Pipfile.lock'
  'go.sum'
  'bun.lock'
  'Cargo.lock'
)

for pat in "${LOCK_PATTERNS[@]}"; do
  while IFS= read -r lf; do
    [ -n "$lf" ] && dispatch_to_shim "$lf" "posttooluse-agent-lockfile"
  done < <(find "$cwd" -maxdepth 2 -type f -name "$pat" -newer "$SENTINEL" \
             -not -path "*/node_modules/*" \
             2>/dev/null)
done

# Sentinel has served its purpose — clean up so it doesn't linger.
rm -f "$SENTINEL" 2>/dev/null || true

# ── EMIT COMBINED SIGNALS ────────────────────────────────────────────────────
if [ "${#all_signals[@]}" -eq 0 ]; then
  exit 0
fi

export SD_COMBINED_CTX
SD_COMBINED_CTX="$(printf '%s\n\n' "${all_signals[@]}" | sed -e '$d')"

SAFE_DEP_SCRIPTS_DIR="${SAFE_DEP_SCRIPTS_DIR:-${HOOK_DIR}/scripts}" \
python3 - <<'PY'
import json, os, sys
ctx = os.environ.get("SD_COMBINED_CTX", "")
scripts_dir = os.environ.get("SAFE_DEP_SCRIPTS_DIR", "")
if scripts_dir and scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)
try:
    from safedep.version import attribution_header
    header = attribution_header()
except Exception:
    header = "[safer-dependencies 0.5.1]"
if ctx:
    ctx = header + "\n" + ctx
print(json.dumps({
    "hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": ctx,
    }
}))
PY

exit 0
