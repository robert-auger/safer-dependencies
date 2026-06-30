#!/bin/bash
# safer-dependencies pretooluse_bash.sh — PreToolUse:Bash hook.
#
# Pre-flight audit for package-manager install commands. Reads the Claude
# Code hook JSON from stdin, extracts the bash command, asks the Python
# helper whether any pinned package@version arguments are vulnerable, and
# either:
#   - exits 0 with no output (allow the bash command to proceed), or
#   - emits hookSpecificOutput JSON with permissionDecision: "deny"
#     plus a human-readable reason (the agent sees this and can re-issue
#     with a safe pin or invoke the safer-dependencies skill).
#
# This complements (does not replace) the existing PostToolUse Write/Edit
# shim. Even when this hook allows a command, the post-write shim still
# audits the manifest after install.
#
# Failure modes default to fail-open: any error (Python missing, helper
# crash, malformed input) returns silently with exit 0, so a broken hook
# never blocks the user's bash commands. This is configurable via
# SAFE_DEP_FAIL_MODE (or policy.fail_mode in the config file): the default
# `open` is today's behaviour; `closed` denies the install when the audit
# cannot be completed (issue #290). Even in `open` mode the fail-open is
# surfaced on stderr so it is no longer silent.
#
# Install (end-user) — mirrors the existing shim install pattern:
#   mkdir -p .claude/skills/safer-dependencies
#   cp safer-dependencies-pretooluse-bash.sh .claude/skills/safer-dependencies/pretooluse-bash.sh
#   chmod +x .claude/skills/safer-dependencies/pretooluse-bash.sh
# Then in settings.json (merge with existing hooks block):
#   "PreToolUse": [
#     {"matcher": "Bash", "hooks": [
#       {"type": "command",
#        "command": "${HOME}/.claude/skills/safer-dependencies/pretooluse-bash.sh",
#        "timeout": 30}
#     ]}
#   ]

set -uo pipefail

SHIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# SAFE_DEP_TEST_HELPER lets the contract test swap in a stub Python script
# that emits a deterministic {"action":"deny"|"allow",...} payload, so the
# bash wrapper's transform to hookSpecificOutput can be validated without
# depending on the live OSV API. Production callers leave it unset.
HELPER="${SAFE_DEP_TEST_HELPER:-${SHIM_DIR}/scripts/pretooluse_bash_audit.py}"

# ── FAIL-OPEN DIAGNOSTIC EMITTER ─────────────────────────────────────────────
# Pure bash so it works even when Python or the helper script is missing —
# those are exactly the cases we want a log entry for. Schema matches
# safedep.audit_log (mode "fail_open"). Silent on any error.
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
    printf '{"ts":"%s","schema":"2.0","source":{"component":"bash.pretooluse","script":"safer-dependencies-pretooluse-bash.sh","hook":"PreToolUse","tool":"Bash","mode":"fail_open"},"fail_open":{"reason":"%s"%s}}\n' \
    "$ts" "$reason" "$detail_field" >> "$log_path" 2>/dev/null || true )
  chmod 600 "$log_path" 2>/dev/null || true  # issue #210: never world-readable
}

# ── FAIL-MODE RESOLUTION ─────────────────────────────────────────────────────
# Resolve the effective fail_mode (open|closed) for the cases handled in pure
# bash — Python or the helper may be missing, so we cannot call into safedep
# here. The env var is the only source that does not require a TOML parser, so
# bash-side resolution honours SAFE_DEP_FAIL_MODE and otherwise defaults to
# `open` (today's behaviour). When Python IS available the helper consults the
# full env > config-file > default precedence; this bash path is the floor for
# the python-missing / helper-missing cases only.
resolve_fail_mode_env() {
  local m
  m="$(printf '%s' "${SAFE_DEP_FAIL_MODE:-}" | tr '[:upper:]' '[:lower:]')"
  m="${m// /}"
  if [ "$m" = "closed" ] || [ "$m" = "open" ]; then
    printf '%s' "$m"
  else
    printf 'open'
  fi
}

# Emit the PreToolUse deny envelope used when fail_mode=closed and the audit
# could not be completed. The reason is fixed and actionable (issue #290).
emit_fail_closed_deny() {
  local reason="${1:-the audit could not be completed}"
  local header="${SAFE_DEP_ATTRIBUTION_HEADER:-[safer-dependencies]}"
  local msg="${header} safer-dependencies could not complete its audit and fail_mode=closed: ${reason}. Re-run when the audit can complete or set SAFE_DEP_FAIL_MODE=open to allow."
  # Hand-built JSON (python may be unavailable). JSON-escape the message.
  msg="${msg//\\/\\\\}"
  msg="${msg//\"/\\\"}"
  msg="${msg//$'\t'/\\t}"
  msg="${msg//$'\n'/\\n}"
  msg="${msg//$'\r'/\\r}"
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$msg"
}

# Unified fail handler: log the fail-open diagnostic, surface it on stderr
# (so it is visible even in open mode — issue #290), then either deny
# (fail_mode=closed) or exit 0 (fail_mode=open).
handle_audit_incomplete() {
  local reason="${1:-unknown}" detail="${2:-}"
  emit_fail_open "$reason" "$detail"
  # Low-noise stderr surface so a fail-open is never wholly silent.
  printf 'safer-dependencies: audit incomplete (%s) — fail-open; install allowed without a pre-flight check\n' \
    "$reason" >&2
  if [ "$(resolve_fail_mode_env)" = "closed" ]; then
    emit_fail_closed_deny "$reason"
    exit 0
  fi
  exit 0
}

# Fail if the helper isn't installed (broken install, partial copy).
if [ ! -f "$HELPER" ]; then
  handle_audit_incomplete "helper_missing" "${HELPER}"
fi

# Fail if Python is missing entirely (every downstream call needs it).
if ! command -v python3 >/dev/null 2>&1; then
  handle_audit_incomplete "python_missing"
fi

# Read the hook input. The harness pipes a JSON object on stdin describing
# the pending tool call; we want tool_input.command and the top-level cwd.
input="$(cat 2>/dev/null || true)"
if [ -z "$input" ]; then
  exit 0
fi

# Extract command and cwd via Python (jq isn't guaranteed to be installed).
# The leading version probe (issue #211) is folded into this existing call —
# the auditor needs Python >= 3.9; an older interpreter would crash it with a
# swallowed SyntaxError. The probe snippet itself parses on any Python 3.x.
# Both values are printed as shell-safe name=value pairs so a single Python
# invocation covers both fields, keeping the latency impact to one startup.
parsed="$(printf '%s' "$input" | python3 -c '
import sys
if sys.version_info < (3, 9):
    print("command=__SD_PYTHON_TOO_OLD__%d.%d" % (sys.version_info[0], sys.version_info[1]))
    print("cwd=")
    sys.exit(0)
import json, shlex
try:
    d = json.load(sys.stdin)
    command = d.get("tool_input", {}).get("command", "")
    cwd = d.get("cwd", "") or ""
    print("command=" + shlex.quote(command))
    print("cwd=" + shlex.quote(cwd))
except Exception:
    print("command=")
    print("cwd=")
' 2>/dev/null || true)"

# SC2154: command and cwd are assigned via eval below.
eval "$parsed" 2>/dev/null || true
command="${command:-}"
cwd="${cwd:-}"

case "$command" in
  __SD_PYTHON_TOO_OLD__*)
    handle_audit_incomplete "python_too_old" "found ${command#__SD_PYTHON_TOO_OLD__}, need >= 3.9"
    ;;
esac

if [ -z "$command" ]; then
  exit 0
fi

# Pure-bash early filter: bash commands hit this hook on every call, so
# we want to short-circuit non-PM commands before paying Python startup
# cost (~250ms). Only invoke the auditor when the command at least
# *mentions* a package-manager binary as a whole word. False positives
# (e.g. `echo "npm ..."`) are handled correctly downstream by shlex
# tokenization in the auditor; this filter only needs to be cheap and
# never have false negatives for real PM invocations.
if ! printf '%s' "$command" | grep -qE '(^|[^A-Za-z0-9_])(npm|npx|pnpm|yarn|bunx|bun|pip|pip3|pipx|pipenv|uv|uvx|poetry|bundle|gem|go|cargo|deno|composer|mpip)([^A-Za-z0-9_]|$)'; then
  exit 0
fi

# Run the auditor. Pass the command as argv[1] and cwd as argv[2] so the
# helper can log the working directory for per-project attribution.
#
# Resolve the full fail_mode (env > config-file > default) now that python3
# is confirmed present, so the config-file path is honoured for the
# helper-crash case below. Falls back to the bash env-only resolution if the
# helper import itself is broken.
fail_mode="$(
  SAFE_DEP_SCRIPTS_DIR="${SAFE_DEP_SCRIPTS_DIR:-${SHIM_DIR}/scripts}" python3 -c '
import os, sys
scripts_dir = os.environ.get("SAFE_DEP_SCRIPTS_DIR", "")
if scripts_dir and scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)
try:
    from safedep.config import fail_mode
    print(fail_mode())
except Exception:
    print("")
' 2>/dev/null || true)"
fail_mode="${fail_mode:-$(resolve_fail_mode_env)}"

result="$(python3 "$HELPER" "$command" "$cwd" 2>/dev/null || true)"
if [ -z "$result" ]; then
  # The helper produced no output: it crashed, the OSV layer raised, or input
  # was malformed past the point bash can see. This is the canonical silent
  # fail-open the issue calls out — surface it, and deny under fail_mode=closed.
  emit_fail_open "helper_no_output"
  printf 'safer-dependencies: audit incomplete (helper_no_output) — fail-open; install allowed without a pre-flight check\n' >&2
  if [ "$fail_mode" = "closed" ]; then
    header="$(
      SAFE_DEP_SCRIPTS_DIR="${SAFE_DEP_SCRIPTS_DIR:-${SHIM_DIR}/scripts}" python3 -c '
import os, sys
scripts_dir = os.environ.get("SAFE_DEP_SCRIPTS_DIR", "")
if scripts_dir and scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)
try:
    from safedep.version import attribution_header
    print(attribution_header())
except Exception:
    print("[safer-dependencies]")
' 2>/dev/null || true)"
    SAFE_DEP_ATTRIBUTION_HEADER="${header:-[safer-dependencies]}" emit_fail_closed_deny "helper_no_output"
  fi
  exit 0
fi

action="$(printf '%s' "$result" | python3 -c '
import json, sys
try: print(json.load(sys.stdin).get("action", ""))
except Exception: pass
' 2>/dev/null || true)"

case "$action" in
  deny)
    # Build the hookSpecificOutput envelope. Prepend the [safer-dependencies
    # <ver>] attribution header to permissionDecisionReason so the user sees
    # this deny originated from this skill (and which version).
    #
    # SAFE_DEP_SCRIPTS_DIR is set on the python3 side of the pipe (RHS), not
    # the printf side (LHS) — env-var prefixes apply only to the immediately
    # following command, and putting it on printf would leave python3 unable
    # to find the safedep package, silently falling into the hardcoded
    # fallback branch.
    printf '%s' "$result" \
      | SAFE_DEP_SCRIPTS_DIR="${SAFE_DEP_SCRIPTS_DIR:-${SHIM_DIR}/scripts}" python3 -c '
import json, os, sys
scripts_dir = os.environ.get("SAFE_DEP_SCRIPTS_DIR", "")
if scripts_dir and scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)
try:
    from safedep.version import attribution_header
    header = attribution_header()
except Exception:
    header = "[safer-dependencies 0.5.0]"
r = json.load(sys.stdin)
reason = r.get("reason", "blocked by safer-dependencies")
out = {
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": f"{header} {reason}",
    }
}
print(json.dumps(out))
'
    exit 0
    ;;
  ask)
    # Confirm-tier findings (typosquat suspicion, staleness advisory —
    # issues #203/#204): surface as permissionDecision "ask" so the user
    # explicitly confirms instead of a hard block. Same envelope/attribution
    # as the deny branch.
    printf '%s' "$result" \
      | SAFE_DEP_SCRIPTS_DIR="${SAFE_DEP_SCRIPTS_DIR:-${SHIM_DIR}/scripts}" python3 -c '
import json, os, sys
scripts_dir = os.environ.get("SAFE_DEP_SCRIPTS_DIR", "")
if scripts_dir and scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)
try:
    from safedep.version import attribution_header
    header = attribution_header()
except Exception:
    header = "[safer-dependencies 0.5.0]"
r = json.load(sys.stdin)
reason = r.get("reason", "confirmation requested by safer-dependencies")
out = {
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": f"{header} {reason}",
    }
}
print(json.dumps(out))
'
    exit 0
    ;;
  *)
    # allow / skip / unknown — no output, bash proceeds normally.
    exit 0
    ;;
esac
