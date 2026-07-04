#!/bin/bash
# safer-dependencies-shim.sh — Claude Code PostToolUse hook for dependency auditing.
#
# Reads Claude Code hook JSON from stdin, audits dependency manifests written
# by Claude, auto-corrects unsafe versions in place, and signals the parent
# agent via hookSpecificOutput JSON on stdout.
#
# Shape C (post-write corrective): always exits 0, never blocks writes.
# Signals: UPDATED: (version replaced), BLOCKED: (no safe version or abandoned),
#          STALE: (no CVEs, no updates in 2+ years — advisory, not removed),
#          WARNING: (lock file CVE or audit error).
#
# Requires: bash, Python 3.7+, network access to OSV API + package registries.
# Platform: macOS, Linux, Windows (Git for Windows / Git Bash + Python 3 in PATH).
#
# Install (end-user):
#   mkdir -p .claude/skills/safer-dependencies
#   cp safer-dependencies-shim.sh .claude/skills/safer-dependencies/shim.sh
#   chmod +x .claude/skills/safer-dependencies/shim.sh
#   # Then point the PostToolUse hook at ${CLAUDE_PROJECT_DIR}/.claude/skills/safer-dependencies/shim.sh

set -euo pipefail

# Resolve the shim's own directory so we can locate the shared Python library
# (scripts/safedep/) and the audit module (scripts/shim_audit.py). This is
# exported so the audit module can add the right path to sys.path for its
# `from safedep.* import ...` imports.
SHIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Allow an external override so tests can inject a fake scripts directory
# (e.g. one without safedep/) to exercise the install-error path.
export SAFE_DEP_SCRIPTS_DIR="${SAFE_DEP_SCRIPTS_DIR:-${SHIM_DIR}/scripts}"

# Fallback version used by the bash-only install-error branch below (which
# fires precisely when the safedep package — including safedep/version.py —
# cannot be imported). Keep in sync with SAFER_DEP_VERSION_FALLBACK in
# scripts/safedep/version.py. The normal path resolves the version from the
# SKILL frontmatter via Python; this constant only matters when that path
# is unreachable.
SAFER_DEP_VERSION_FALLBACK="0.5.1"

# Preflight: the Python audit logic below imports `from safedep.http import ...`
# at module scope. If scripts/safedep/ is missing — which happens when the
# installer's `cp -r` produced a nested scripts/scripts/ layout (fixed upstream
# but historical installs remain broken) — the ModuleNotFoundError fires
# before any exception handler loads, the shim exits non-zero, and the
# failure is invisible because hook errors don't surface to the user in
# normal operation. Catch that case here:
#   - Emit a loud red warning so the user sees the broken install immediately
#   - Record a JSONL entry in the audit log so broken-install runs leave a trace
#   - Emit the official hookSpecificOutput signal so the agent gets a
#     system-reminder and can relay the problem to the user
#   - Exit 0 — Shape C contract, we never block writes
if [ ! -f "${SAFE_DEP_SCRIPTS_DIR}/safedep/__init__.py" ] || [ ! -f "${SAFE_DEP_SCRIPTS_DIR}/shim_audit.py" ]; then
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  log_path="${SAFE_DEP_AUDIT_LOG:-$HOME/.claude/safer-dependencies-audit-$(date +%Y-%m).log}"
  mkdir -p "$(dirname "$log_path")" 2>/dev/null || true

  # JSON-escape interpolated values (pure bash — this branch fires precisely
  # when the Python package is broken, so it must not depend on it). Paths
  # and session ids can legally contain " and \, which would otherwise make
  # BOTH the audit-log line and the hookSpecificOutput payload unparseable —
  # dropping the install-error signal exactly when it matters.
  _json_esc() {
    local v="$1"
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    v="${v//$'\t'/\\t}"
    v="${v//$'\n'/\\n}"
    v="${v//$'\r'/\\r}"
    printf '%s' "$v"
  }
  esc_scripts_dir="$(_json_esc "$SAFE_DEP_SCRIPTS_DIR")"
  esc_shim_dir="$(_json_esc "$SHIM_DIR")"

  # Canonical schema v2.2 entry. Built inline (not via safedep.audit_log)
  # because this branch fires precisely when the safedep package is missing —
  # we cannot import from it. session_id included iff CLAUDE_SESSION_ID is set.
  # model included iff SAFE_DEP_MODEL is set or readable from settings files.
  # tool is null here because hook stdin has not been parsed yet at the preflight stage.
  session_field=""
  if [ -n "${CLAUDE_SESSION_ID:-}" ]; then
    session_field=",\"session_id\":\"$(_json_esc "$CLAUDE_SESSION_ID")\""
  fi
  model_field=$(python3 -c "
import json, os, sys
model = os.environ.get('SAFE_DEP_MODEL', '')
if not model:
    for p in ['.claude/settings.json', os.path.expanduser('~/.claude/settings.json')]:
        try:
            model = json.load(open(p)).get('model', '') or ''
            if model:
                break
        except Exception:
            pass
if model:
    print(',\"model\":' + json.dumps(str(model)), end='')
" 2>/dev/null || true)
  ( umask 077
  printf '{"ts":"%s","schema":"2.2","source":{"component":"shim.install_error","script":"skills/safer-dependencies-shim.sh","hook":"PostToolUse","tool":null,"mode":"install_error"%s%s},"install_error":"safedep package missing","shim_dir":"%s","scripts_dir":"%s"}\n' \
    "$ts" "$session_field" "$model_field" "$esc_shim_dir" "$esc_scripts_dir" >> "$log_path" 2>/dev/null || true )
  chmod 600 "$log_path" 2>/dev/null || true  # issue #210: never world-readable

  # Red ANSI to stderr — visible when the terminal renders hook stderr.
  printf '\033[1;31m🔒 [safer-dependencies] INSTALL ERROR — scripts/safedep/ missing at %s\033[0m\n' "$SAFE_DEP_SCRIPTS_DIR" >&2
  printf '\033[1;31m   The shim cannot audit dependencies until the install is repaired.\033[0m\n' >&2
  printf '\033[1;31m   Fix: rm -rf %s && reinstall from https://github.com/robert-auger/safer-dependencies\033[0m\n' "$SAFE_DEP_SCRIPTS_DIR" >&2
  printf '\033[1;31m   Continuing without audit — the file you just wrote was NOT checked for vulnerabilities.\033[0m\n' >&2

  # Plain text in the JSON signal. JSON forbids raw control characters
  # (a raw ESC here would make the output unparseable and the signal would
  # never reach the agent). additionalContext is rendered as system-reminder
  # text, not terminal output, so ANSI would not render as red anyway.
  # Red rendering lives on stderr above; this channel just delivers facts.
  # The \n sequence here is the two-character JSON escape (backslash + n)
  # that the JSON parser turns into a real newline at decode time — keeping
  # the on-the-wire bytes valid JSON. A literal newline byte would make the
  # additionalContext string field unparseable.
  msg="[safer-dependencies ${SAFER_DEP_VERSION_FALLBACK}]\n🔒 INSTALL ERROR — scripts/safedep/ missing at ${esc_scripts_dir}. The shim cannot audit dependencies until the install is repaired. The file just written was NOT checked. Fix: reinstall from https://github.com/robert-auger/safer-dependencies"
  printf '{"hookSpecificOutput":{"additionalContext":"%s"}}\n' "$msg"
  exit 0
fi

# Issue #214: the audit Python now lives in a standalone module
# (skills/scripts/shim_audit.py) instead of an embedded Python heredoc. A real
# file does not consume this script's stdin the way a heredoc would, so the
# hook JSON on stdin stays connected to python3 — no temp file / mktemp / trap
# machinery is needed any more. The module's existence is guaranteed by the
# install-error preflight above (which now also checks for shim_audit.py).
AUDIT_SCRIPT="${SAFE_DEP_SCRIPTS_DIR}/shim_audit.py"

# Issue #211: run via the version-preflight launcher when available. On a
# too-old python3 the audit script fails to COMPILE (SyntaxError, swallowed
# stderr, zero diagnostics) — the launcher stays syntax-compatible with any
# Python 3.x, emits a clear PREFLIGHT-ERROR signal + fail-open audit entry,
# and exits 0. Fallback to direct execution preserves behavior for installs
# that copied scripts/ without the launcher.
PREFLIGHT_LAUNCHER="${SAFE_DEP_SCRIPTS_DIR}/shim_python_preflight.py"
if [ -f "$PREFLIGHT_LAUNCHER" ]; then
  python3 "$PREFLIGHT_LAUNCHER" "$AUDIT_SCRIPT"
else
  python3 "$AUDIT_SCRIPT"
fi
