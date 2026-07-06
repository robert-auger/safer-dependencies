#!/bin/bash
# safer-dependencies posttooluse_bash.sh — PostToolUse:Bash hook.
#
# Closes two install-time audit gaps:
#
# SCAN A — lockfile scan (issue #13, original):
#   When Claude runs `npm install`, `bundle install`, `poetry install`, `uv sync`,
#   etc., the package manager writes/updates a lockfile *without* going through
#   Claude's Write tool — so the PostToolUse:Write shim never sees the lockfile
#   and never audits its contents (transitive deps included). Scan A fires after
#   recognized install verbs and audits freshly-modified lockfiles.
#
# SCAN B — manifest scan (issue #23, new):
#   When Claude edits manifest files (package.json, pyproject.toml, Cargo.toml,
#   etc.) via a Bash command rather than the Write/Edit tools — e.g. a Python
#   batch-edit script or a sed one-liner — neither the Write shim nor scan A
#   sees the change. Scan B fires after any Bash command that isn't on the
#   read-only denylist, and audits freshly-modified manifest files.
#
# Both scans share a single JSON parse and mtime sentinel, and dispatch each
# changed file to the existing shim using a forged PostToolUse:Write payload.
# No new parsers or signal types are needed.
#
# Fail-open: any error, missing shim, or unreadable payload exits 0 silently
# so a broken hook never blocks the user.
#
# Install (end-user):
#   mkdir -p .claude/skills/safer-dependencies
#   cp safer-dependencies-posttooluse-bash.sh \
#      .claude/skills/safer-dependencies/posttooluse-bash.sh
#   chmod +x .claude/skills/safer-dependencies/posttooluse-bash.sh
# Then in settings.json (merge with existing hooks block):
#   "PostToolUse": [
#     {"matcher": "Bash", "hooks": [
#       {"type": "command",
#        "command": "${HOME}/.claude/skills/safer-dependencies/posttooluse-bash.sh",
#        "timeout": 60}
#     ]}
#   ]

# File-scope SC2154: $command, $cwd, $exit_code are assigned via `eval "$parsed"`
# (see line ~131); shellcheck cannot statically follow eval, so it warns at
# every subsequent reference. The python helper above guarantees these three
# names are always assigned before eval (or eval is skipped via the `[ -z "$parsed" ]`
# early-out). Documented invariant — disable applies file-wide.
# shellcheck disable=SC2154
set -uo pipefail

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIM="${HOOK_DIR}/safer-dependencies-shim.sh"
# Legacy fallback only: very old installs shipped the monolithic shim as
# ``shim.sh``. Prefer the canonical name so a stale ``shim.sh`` left behind by
# an in-place update can't shadow the current shim and run outdated audit code.
if [ ! -f "$SHIM" ]; then
  SHIM="${HOOK_DIR}/shim.sh"
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
    printf '{"ts":"%s","schema":"2.0","source":{"component":"bash.posttooluse","script":"safer-dependencies-posttooluse-bash.sh","hook":"PostToolUse","tool":"Bash","mode":"fail_open"},"fail_open":{"reason":"%s"%s}}\n' \
    "$ts" "$reason" "$detail_field" >> "$log_path" 2>/dev/null || true )
  chmod 600 "$log_path" 2>/dev/null || true  # issue #210: never world-readable
}

# Configurable mtime window (seconds). Both scans use the same window so a
# single sentinel covers all file-type checks. Override via env.
LOCKFILE_MTIME_WINDOW_SEC="${SAFE_DEP_POSTINSTALL_MTIME_WINDOW:-60}"

# Backdate <file>'s mtime by LOCKFILE_MTIME_WINDOW_SEC so the `find -newer`
# scans treat only files modified inside the window as "fresh". touch's
# date syntax is not portable, so try each dialect in turn:
#   1. GNU `touch -d @epoch`        — Linux / coreutils
#   2. BSD `touch -t [[CC]YY]MMDDhhmm.SS` — macOS / *BSD (epoch via `date -v`)
#   3. perl `utime`                 — last resort for environments whose
#                                     touch handles neither form
# Returns non-zero only if all three fail.
_backdate_sentinel() {
  local f="$1" epoch bsd_ts
  epoch="$(( $(date +%s) - LOCKFILE_MTIME_WINDOW_SEC ))"
  touch -d "@${epoch}" "$f" 2>/dev/null && return 0
  bsd_ts="$(date -v-"${LOCKFILE_MTIME_WINDOW_SEC}"S +%Y%m%d%H%M.%S 2>/dev/null)"
  [ -n "$bsd_ts" ] && touch -t "$bsd_ts" "$f" 2>/dev/null && return 0
  perl -e 'utime time()-'"$LOCKFILE_MTIME_WINDOW_SEC"', time()-'"$LOCKFILE_MTIME_WINDOW_SEC"', $ARGV[0]' \
    "$f" 2>/dev/null && return 0
  return 1
}

# When sourced (e.g. by the test suite to unit-test the helpers above) rather
# than executed, stop here — everything below is the hook body, which reads
# stdin and would block.
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
  return 0 2>/dev/null
fi

# Fail-open if the shim isn't present next to us.
if [ ! -f "$SHIM" ]; then
  emit_fail_open "shim_missing" "${HOOK_DIR}"
  exit 0
fi

# Fail-open if Python is missing — both scans require it.
if ! command -v python3 >/dev/null 2>&1; then
  emit_fail_open "python_missing"
  exit 0
fi

input="$(cat 2>/dev/null || true)"
if [ -z "$input" ]; then
  exit 0
fi

# ── SCAN GATES ──────────────────────────────────────────────────────────────
# Determine which scans to run before paying Python startup cost.
# Both gates operate on the raw JSON payload (fast bash greps).

# SCAN A gate — requires a package-manager name AND an install verb.
_run_lockfile_scan=0
if printf '%s' "$input" | grep -qE '(^|[^A-Za-z0-9_/.-])(npm|pnpm|yarn|bun|bundle|poetry|uv|pipenv|cargo|go|composer)([^A-Za-z0-9_.-]|$)' \
   && printf '%s' "$input" | grep -qE '(install|add|update|upgrade|require|ci|sync|lock|mod[[:space:]]+tidy|get)'; then
  _run_lockfile_scan=1
fi

# Transitive-scan opt-out (issue #245 phase 1) via the CANONICAL config (#248).
# When the `transitive` check tier resolves to "off" — `config set
# checks.transitive off` (written to ~/.config/safer-dependencies/config.toml),
# or the SAFE_DEP_* env precedence the oracle honours — skip Scan A (the
# lockfile/transitive audit) ONLY. Manifest Scan B and resolved-env Scan C
# are unaffected. Mirrors the established hook pattern (see
# pretooluse_bash_audit.py): a tiny `python3 -c "from safedep import config"`
# probe. Fail-OPEN on every failure (python missing, import error, KeyError,
# any exception): the scan PROCEEDS, so a broken config never silently widens
# the opt-out. Skips silently when off — matching the shim's ecosystem-disable
# convention for intentional user opt-outs (fail-open log entries are reserved
# for broken prerequisites, not configuration choices).
if [ "$_run_lockfile_scan" -eq 1 ]; then
  _sd_scripts_dir="${SAFE_DEP_SCRIPTS_DIR:-${HOOK_DIR}/scripts}"
  _sd_transitive_tier="$(
    SAFE_DEP_SCRIPTS_DIR="$_sd_scripts_dir" python3 -c '
import os, sys
sd = os.environ.get("SAFE_DEP_SCRIPTS_DIR", "")
if sd and sd not in sys.path:
    sys.path.insert(0, sd)
try:
    from safedep import config
    sys.stdout.write(config.check_tier("transitive"))
except Exception:
    pass
' 2>/dev/null || true)"
  if [ "$_sd_transitive_tier" = "off" ]; then
    _run_lockfile_scan=0
  fi
fi

# SCAN B gate — skip only for commands that are provably read-only.
# The denylist is intentionally short and conservative: we'd rather pay one
# fast `find` that returns empty than miss a CVE because the denylist was
# too aggressive. Commands that write to files (python3, sed, jq, node, awk,
# shell scripts, mv, cp, tee) are not listed.
#
# The first-token match alone is NOT sufficient: `echo '{...}' > package.json`,
# `cat > Pipfile <<EOF`, and `cat x && sed -i ... package.json` all start with
# a read-only token yet write files. So the fast path additionally requires
# that the payload carries NO redirect / pipe / chain / substitution marker
# anywhere. Over-matching (e.g. a `>` inside captured stdout) merely costs one
# cheap find(1) that returns empty; under-matching would skip a manifest audit
# — this gate is a perf optimization and must always err toward scanning.
_run_manifest_scan=1
if ! printf '%s' "$input" | grep -qE '[><|;`]|&&|\$\('; then
  if printf '%s' "$input" | grep -qE \
     '"command"[[:space:]]*:[[:space:]]*"[[:space:]]*(ls|ll|cat|head|tail|wc|grep|egrep|fgrep|echo|printf|pwd|which|type|env|date|stat|file)[[:space:]\\"]'; then
    _run_manifest_scan=0
  elif printf '%s' "$input" | grep -qE \
     '"command"[[:space:]]*:[[:space:]]*"[[:space:]]*git[[:space:]]+(status|log|diff|show|blame|branch|tag|describe|rev-parse|ls-files|remote[[:space:]]+(get|show|list)|fetch)[[:space:]\\"]'; then
    _run_manifest_scan=0
  fi
fi

# If neither scan is needed, exit now — no Python startup cost.
if [ "$_run_lockfile_scan" -eq 0 ] && [ "$_run_manifest_scan" -eq 0 ]; then
  exit 0
fi

# ── JSON PARSE (shared between both scans) ──────────────────────────────────
# One Python call extracts everything at once (shell-quoted assignments) so we
# avoid multiple interpreter starts.
# Issue #211: the leading version probe is folded into this existing call —
# the shim's audit logic needs Python >= 3.9; an older interpreter would fail
# with a swallowed SyntaxError. The probe snippet parses on any Python 3.x.
parsed="$(printf '%s' "$input" | python3 -c '
import sys
if sys.version_info < (3, 9):
    print("sd_python_too_old=%d.%d" % (sys.version_info[0], sys.version_info[1]))
    print("command=" + chr(39) + chr(39))
    print("cwd=" + chr(39) + chr(39))
    print("exit_code=0")
    sys.exit(0)
import json, shlex
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
ti = d.get("tool_input")  or {}
tr = d.get("tool_response") or {}
command = ti.get("command", "") or ""
cwd     = d.get("cwd", "")     or ""
for key in ("exit_code", "exitCode", "returncode", "returnCode"):
    if key in tr:
        exit_code = tr.get(key)
        break
else:
    exit_code = 0
try:
    exit_code = int(exit_code)
except Exception:
    exit_code = 0
# Emit shell-quoted assignments. Safe to eval because shlex.quote() wraps
# each value in single quotes and escapes embedded quotes.
print("command=%s" % shlex.quote(command))
print("cwd=%s"     % shlex.quote(cwd))
print("exit_code=%s" % shlex.quote(str(exit_code)))
' 2>/dev/null || true)"

if [ -z "$parsed" ]; then
  exit 0
fi

# SC1090: dynamic source not followable.
# SC2154 (file-scope, see top): command, cwd, exit_code are assigned here.
# shellcheck disable=SC1090
sd_python_too_old=""
eval "$parsed"

if [ -n "$sd_python_too_old" ]; then
  emit_fail_open "python_too_old" "found ${sd_python_too_old}, need >= 3.9"
  exit 0
fi

if [ -z "$cwd" ] || [ ! -d "$cwd" ]; then
  exit 0
fi

# ── SHARED MTIME SENTINEL ───────────────────────────────────────────────────
# Create once; both scans compare against it via `find -newer`. Backdating is
# delegated to _backdate_sentinel (defined above), which handles the GNU / BSD
# / perl touch dialects portably. Fail-open if none of them work.
sentinel="$(mktemp -t sd-cutoff.XXXXXX)"
trap 'rm -f "$sentinel"' EXIT
_backdate_sentinel "$sentinel" || exit 0

# ── SHARED SIGNAL ACCUMULATOR ───────────────────────────────────────────────
all_signals=()

# dispatch_to_shim <file_path> <session_tag>
# Forges a PostToolUse:Write payload for <file_path> and pipes it to the shim.
# Appends any additionalContext to all_signals.
dispatch_to_shim() {
  local path="$1" tag="$2"
  local forged shim_out ctx
  forged="$(SD_FILE_PATH="$path" SD_SESSION_TAG="$tag" python3 - <<'PY'
import json, os
fp  = os.environ["SD_FILE_PATH"]
tag = os.environ.get("SD_SESSION_TAG", "posttooluse-bash")
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
  # Propagate the bash command that triggered this audit so the shim can
  # detect when an attempted remediation (`bundle update <pkg>` etc.)
  # failed to move a vulnerable package past its CVE and emit an
  # escalation alongside the WARNING.
  # SAFE_DEP_CALLER tells the shim to write component=bash.posttooluse to
  # the audit log (issue #141) so stats correctly bucket this dispatch as
  # post-install rather than intercept.
  shim_out="$(printf '%s' "$forged" \
    | SAFE_DEP_TRIGGERING_COMMAND="$command" \
      SAFE_DEP_CALLER="bash.posttooluse" \
      bash "$SHIM" 2>/dev/null \
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

# ── SCAN A: lockfile scan ────────────────────────────────────────────────────
# Only runs after successful install commands.
#
# Uses -maxdepth 5 to cover monorepo layouts where sub-packages keep their
# own lockfile (e.g. apps/ruby/blameless/Gemfile.lock — depth 3 from cwd).
# Matches scan B's depth. Same path exclusions as scan B so we don't audit
# vendored lockfiles inside node_modules / .venv / .git (issue #83).
if [ "$_run_lockfile_scan" -eq 1 ] && [ "$exit_code" = "0" ]; then
  # Re-check against the parsed command string (not raw JSON) to avoid false
  # positives from stdout/stderr that happen to contain install-verb strings.
  if printf '%s' "$command" | grep -qE '(^|[^A-Za-z0-9_/.-])(npm|pnpm|yarn|bun|bundle|poetry|uv|pipenv|cargo|go|composer)([^A-Za-z0-9_.-]|$)' \
     && printf '%s' "$command" | grep -qE '(install|add|update|upgrade|require|ci|sync|lock|mod[[:space:]]+tidy|get)'; then

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
      'composer.lock'
    )

    for pat in "${LOCK_PATTERNS[@]}"; do
      while IFS= read -r lf; do
        [ -n "$lf" ] && dispatch_to_shim "$lf" "posttooluse-bash-lockfile"
      done < <(find "$cwd" -maxdepth 5 -type f -name "$pat" -newer "$sentinel" \
                 -not -path "*/node_modules/*" \
                 -not -path "*/.git/*" \
                 -not -path "*/.venv/*" \
                 -not -path "*/venv/*" \
                 2>/dev/null)
    done
  fi
fi

# ── SCAN C: resolved-environment audit (issue #228) ──────────────────────────
# Plain pip writes no lockfile, so a `pip install` / `pip install -r
# requirements.txt` resolves a transitive tree scan A never sees. After any
# successful pip-shaped install, hand the command to
# postinstall_resolved_audit.py: it re-invokes the same pip binary with the
# read-only `list --format=json`, OSV-checks the full resolved environment
# (direct + transitive), prints signal lines on stdout, and writes its own
# audit-log entry. Fail-open: any error → empty output, scan skipped.
# The gate regex is intentionally over-inclusive (`uv` also matches `uv add`);
# the helper does the precise pip/uv-pip parsing and exits silently otherwise.
if [ "$exit_code" = "0" ] \
   && printf '%s' "$command" | grep -qE '(^|[^A-Za-z0-9_.-])(pip[0-9.]*|python[0-9.]*|uv)([^A-Za-z0-9_.-]|$)' \
   && printf '%s' "$command" | grep -qE '(^|[^A-Za-z0-9_.-])install([^A-Za-z0-9_.-]|$)'; then
  RESOLVED_HELPER="${SAFE_DEP_RESOLVED_AUDIT_HELPER:-${HOOK_DIR}/scripts/postinstall_resolved_audit.py}"
  if [ -f "$RESOLVED_HELPER" ] && command -v python3 >/dev/null 2>&1; then
    resolved_out="$(python3 "$RESOLVED_HELPER" "$command" "$cwd" 2>/dev/null)" || resolved_out=""
    if [ -n "$resolved_out" ]; then
      all_signals+=("$resolved_out")
    fi
  fi
fi

# ── SCAN B: manifest scan ────────────────────────────────────────────────────
# Runs for any Bash command not on the read-only denylist. Lockfiles are
# intentionally excluded — they are already covered by scan A.
#
# Uses -maxdepth 5 (matching scan A) to cover monorepo layouts where
# manifests live several directories deep (e.g. packages/foo/sub/package.json).
# node_modules and .git are excluded to prevent runaway find times.
#
# Note: scan B does NOT gate on exit_code == 0 (unlike scan A). Reasoning: a
# command that exits non-zero may still have written part of a manifest before
# crashing, and that partial write is exactly what we want to audit. The mtime
# check is the actual gate — if no manifest was modified, the find returns
# empty and the scan exits silently. The shim is fail-open on malformed files.
if [ "$_run_manifest_scan" -eq 1 ]; then

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
    'libs.versions.toml'
    'go.mod'
    'composer.json'
  )

  for pat in "${MANIFEST_PATTERNS[@]}"; do
    while IFS= read -r mf; do
      [ -n "$mf" ] && dispatch_to_shim "$mf" "posttooluse-bash-manifest"
    done < <(find "$cwd" -maxdepth 5 -type f -name "$pat" -newer "$sentinel" \
               -not -path "*/node_modules/*" \
               -not -path "*/.git/*" \
               -not -path "*/.venv/*" \
               -not -path "*/venv/*" \
               2>/dev/null)
    # Note: dist/ and build/ are NOT excluded — npm packages ship legitimate
    # dist/package.json manifests (e.g. dist/commonjs/package.json) that must
    # be audited. Excluding those would silently drop real findings.
  done
fi

# ── EMIT combined signals ────────────────────────────────────────────────────
if [ "${#all_signals[@]}" -eq 0 ]; then
  exit 0
fi

# Join per-file signals with a blank line between for visual separation.
# Pass via env var to avoid quoting issues with embedded quotes or $ in signals.
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
    header = "[safer-dependencies 0.5.2]"
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
