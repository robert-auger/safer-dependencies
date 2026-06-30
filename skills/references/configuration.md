# Configuration and Setup Options

## Recommended settings.json (optional)

To enable intercept mode and auto-approve shell commands (no permission prompts),
add this block to `.claude/settings.json`. Requires the shim installed at
`.claude/skills/safer-dependencies/shim.sh` — see README for install steps.

```json
{
  "permissions": {
    "allow": [
      "Bash(npm view *)",
      "Bash(curl -s --max-time 10 *)",
      "Bash(npm audit *)",
      "Bash(pip-audit *)",
      "Bash(bundle audit *)",
      "Bash(gem fetch *)",
      "Bash(dependency-check *)"
    ]
  },
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write",
        "hooks": [{
          "type": "command",
          "command": "${CLAUDE_PROJECT_DIR}/.claude/skills/safer-dependencies/shim.sh",
          "timeout": 60
        }]
      },
      {
        "matcher": "Edit",
        "hooks": [{
          "type": "command",
          "command": "${CLAUDE_PROJECT_DIR}/.claude/skills/safer-dependencies/shim.sh",
          "timeout": 60
        }]
      }
    ]
  }
}
```

The `permissions.allow` block is optional. Without it you will be prompted to
approve each registry query individually.

## `SAFE_DEP_DRY_RUN` environment variable (report without correcting)

Setting `SAFE_DEP_DRY_RUN=1` (or `true` / `yes` / `on` — case-insensitive) puts the shim into report-only mode:

- Every check runs exactly as usual (OSV, staleness, abandoned, typosquat, first-publish age).
- Every signal (`UPDATED:`, `BLOCKED:`, `MAJOR-UPDATE-CONFIRM:`, `TYPOSQUAT-CONFIRM:`, `UNKNOWN:`, `SIGNATURE:`, `WARNING:`) is emitted on the same hookSpecificOutput channel.
- **The manifest on disk is never mutated.** The developer's declared versions stay exactly as written — useful for CI gates that want to report findings without auto-correcting inside a protected branch.

Audit-log entries for dry-run invocations carry `"mode": "dry_run"` so post-hoc analysis can filter for what *would* have been corrected versus what was.

**Use in CI pipelines that must fail the build on vulnerability findings but must not auto-commit version bumps.** Pair with `SAFE_DEP_AUDIT_LOG=/path/to/run.log` to capture a run-scoped audit trail without touching `~/.claude/`.

```bash
# Example: fail the build if any UPDATED or BLOCKED signal fires, without
# touching the manifest
export SAFE_DEP_DRY_RUN=1
export SAFE_DEP_AUDIT_LOG=/tmp/sd-run.log
claude --permission-mode bypassPermissions -p "audit dependencies"
jq -e 'select(.findings | length > 0)' "$SAFE_DEP_AUDIT_LOG" && exit 1 || exit 0
```

There is no env var that auto-approves `MAJOR-UPDATE-CONFIRM` or `BLOCKED` signals. Those signals are surfaced to the developer as text questions in every execution context, including `bypassPermissions` and CI runs. For CI gates that should fail the build when one fires, use the `jq` pattern above against `SAFE_DEP_AUDIT_LOG`.

## `SAFE_DEP_MAX_WORKERS` environment variable (per-package fan-out concurrency)

Each manifest audit runs its per-package metadata phase — typosquat /
existence / abandoned / staleness / advisory-age / signature — through
a bounded `ThreadPoolExecutor`. Two defaults ship:

| Code path | Default workers |
|---|---:|
| Manifest audits (`audit_npm`, `audit_pypi`, ...) | **3** |
| Lockfile audits (`audit_package_lock`, `audit_gemfile_lock`, ...) | 8 |

Manifest audits fire on every `Write` / `Edit` of a tracked manifest, so
their default is deliberately conservative — three concurrent connections
is comfortable for free public registries (PyPI, npm, RubyGems,
proxy.golang.org, Maven Central) and large enough to give a measured ~2×
speedup over strictly-serial per-package work on a 50-package manifest.

`SAFE_DEP_MAX_WORKERS=<n>` overrides both defaults in the same run,
clamped to `[1, 32]`. Use cases:

- `SAFE_DEP_MAX_WORKERS=1` — fully serialize for reproducible CI runs
  when you want deterministic wall-clock per package or are debugging a
  thread-interaction issue.
- `SAFE_DEP_MAX_WORKERS=8` or higher — private registries or internal
  mirrors where the rate-limit budget is under your control and audit
  latency matters (e.g. large monorepos with lots of first-run audits).
- Unset — the ecosystem default (3 for manifests, 8 for lockfiles)
  applies.

Malformed values (non-numeric, empty) fall back to the code path's
default silently. Integer values outside `[1, 32]` are clamped, not
rejected — the shim never refuses to run because of a misconfigured
knob.

## Config file (`~/.config/safer-dependencies/config.toml`)

Security *policy* — which checks run, at what strength, and the cooloff
release cooldown — lives in one global config file:
`~/.config/safer-dependencies/config.toml` (respects `XDG_CONFIG_HOME`).
Operational/plumbing knobs (audit-log path, concurrency, cache location,
mtime windows) remain environment-only; see the reference table below.

**Precedence, per key: environment variable → config file → built-in
default.** An env var always beats the file. A missing or unreadable file is
equivalent to all defaults; a malformed value is ignored with a one-line
`WARNING:` naming the key (surfaced by `config show` and appended to the
shim's signal output when an audit emits), and the default is used; unknown keys are
tolerated (forward compatibility). Config parsing never crashes or blocks a
hook — it fails open to defaults.

### Schema (defaults shown)

```toml
schema = 1

[cooloff]
mode = "warn"        # off | warn | block
days = 7             # integer ≥ 0

[checks]             # each: off | warn | block — defaults = today's severities
cve               = "block"
abandoned         = "block"
typosquat         = "warn"
existence         = "warn"
stale             = "warn"
hashes            = "warn"
signatures        = "warn"
first_publish_age = "warn"
transitive        = "warn"

[staleness]
years = 2                  # absorbs SAFE_DEP_STALE_YEARS
popularity_guard = true    # absorbs SAFE_DEP_STALE_POPULARITY_GUARD

[ecosystems]               # existing section, unchanged semantics
# npm = true, pypi = true, rubygems = true, maven = true, go = true, crates = true
```

### Tier semantics (`off` / `warn` / `block`)

| Tier | Pre-Install (PreToolUse) | Intercept / Post-Install / Post-Agent (post-write) | Normal mode |
|---|---|---|---|
| `off` | Check skipped entirely | Check skipped entirely | Check skipped entirely |
| `warn` | Real permission prompt (`permissionDecision: "ask"`) | The check's advisory/confirm signal: `*-CONFIRM` for typosquat/cooloff and tier demotions (e.g. `TYPOSQUAT-CONFIRM`, `COOLOFF-CONFIRM: <pkg>@<ver> was published N days ago (window: Xd) …`, `CVE-CONFIRM`); `STALE:`/`NOTE:`/`WARNING:` advisories keep their standard form | Skill instructs Claude to ask the user |
| `block` | `permissionDecision: "deny"` | Auto-correct: version-shaped findings (CVE, cooloff) rewrite the pin to the newest version that clears the policy; package-shaped findings (abandoned-style) take the existing `BLOCKED:` removal path | Finding treated as blocking |

**Block capped at confirm on post-hoc surfaces:** findings that surface
after the fact and cannot be prevented or rewritten — hash-pin advisories,
transitive CVEs found in an already-written lockfile (Post-Install Scan A /
Scan C) — accept `block` but cap it at warn-strength signaling. This is
documented behavior, not a silent downgrade.

**Cooloff CVE-fix exception (Intercept / Normal mode):** the cooloff gate
runs only on CVE-clean pins, so a CVE-driven rewrite bypasses the gate even
when the fix release is younger than the window — holding back a security
patch is self-defeating. The rewrite arrives through the normal CVE path,
so the regular `UPDATED:` signal documents it. Pre-Install `block` has no
manifest context and denies a too-fresh pin regardless; the fix then lands
via Intercept's rewrite path.

**Cooloff in Normal-mode selection:** `mode != off` keeps the resolve
scripts' existing behavior (pick the newest version ≥ `cooloff.days` old);
`mode = "off"` removes the age filter from selection.

**Cooloff ecosystem coverage:** the cooloff gate covers **npm, PyPI,
RubyGems, and crates.io** only. Maven and Go are intentionally not gated:
`registry.release_date()` has no Maven branch, so the Pre-Install cooloff
fails open for Maven pins (and Maven is absent from `_PM_STRATEGIES`
anyway), and the Intercept shim skips Go cooloff (proxy.golang.org fetches
on demand, so a release date is not reliably resolvable up front). This
asymmetry is deliberate — Maven/Go cooloff is not implemented.

### CLI

```
/safer-dependencies config                       # effective config; per key: value + source (default|config|env)
/safer-dependencies config set <key> <value>     # dotted keys: checks.stale, cooloff.days
/safer-dependencies config unset <key>           # revert key to default
/safer-dependencies config reset [--yes]         # revert managed keys to defaults (prompts; --yes skips)
/safer-dependencies config path                  # print file location
```

`set` validates key names and values; invalid input produces an error
listing the allowed values and exits 2. `reset` asks for confirmation
before clearing; `--yes` skips the prompt, and non-interactive runs
(no TTY input) cancel by default. Unmanaged sections (e.g. `[ecosystems]`)
are preserved — only the managed policy sections (`cooloff`, `checks`,
`staleness`) are reverted. The same verbs are available
directly: `python3 skills/scripts/safer_dependencies_manager.py config …`.

## Environment-variable reference

Consolidated list of every `SAFE_DEP_*` environment variable the shim, hooks, and `safedep` package honor. The three documented in detail above (`SAFE_DEP_DRY_RUN`, `SAFE_DEP_MAX_WORKERS`, `SAFE_DEP_AUDIT_LOG`) are included for completeness. The **Config key** column maps each variable to its `config.toml` key where one exists (the env var wins when both are set); knobs marked *env-only* are deliberately not in the config file.

| Variable | Default | Config key | What it controls |
|---|---|---|---|
| `SAFE_DEP_AUDIT_LOG` | `~/.claude/safer-dependencies-audit-YYYY-MM.log` | env-only | Overrides the full audit-log path (the monthly date suffix is not appended to an override). |
| `SAFE_DEP_DRY_RUN` | off | env-only | Report-only mode: every check runs and every signal is emitted, but the manifest is never rewritten. Entries carry `"mode": "dry_run"`. |
| `SAFE_DEP_MAX_WORKERS` | 3 (manifest audits) / 8 (lockfile audits) | env-only | Per-package fan-out concurrency; clamped to `[1, 32]`. |
| `SAFE_DEP_LOG_MAX_BYTES` | 10 MiB | env-only | Size-rotation cap for the audit log; files exceeding it are renamed with a `.<n>` suffix. `0` disables size rotation. |
| `SAFE_DEP_MODEL` | unset (read from Claude settings files when available) | env-only | Explicit model name recorded in the audit-log `source` block for per-model stats. |
| `SAFE_DEP_COOLOFF_MODE` | `warn` | `cooloff.mode` | Cooloff (release-age) gate mode: `off` / `warn` / `block`. See "Config file" above for per-surface semantics and the CVE-fix exception. |
| `SAFE_DEP_COOLOFF_DAYS` | 7 | `cooloff.days` | Cooloff window in days — how old a release must be before it clears the gate. |
| `SAFE_DEP_STALE_YEARS` | 2 (730 days) | `staleness.years` | Staleness threshold in years for the advisory `STALE:` check. Non-numeric or non-positive values fall back to the default. |
| `SAFE_DEP_STALE_POPULARITY_GUARD` | on | `staleness.popularity_guard` | `0`/`off`/`false`/`no` disables the popularity/latest-version guard on `STALE:` (suppression-to-`NOTE:` of mature packages where the pin IS the latest stable release, adoption clears the popularity bar, and staleness is within 2× the threshold), restoring pure elapsed-time behavior for deterministic testing. |
| `SAFE_DEP_REQUIRE_HASHES` | warn | `checks.hashes` (`enforce` aliases `block`) | `off` silences the advisory `NOTE:` emitted when a pinned `requirements*.txt` declares no `--hash=` integrity pins. |
| `SAFE_DEP_CACHE_DISABLE` | off | env-only | `1` bypasses the persistent registry-lookup cache entirely (every query hits the live registry). |
| `SAFE_DEP_CACHE_DIR` | `~/.cache/safe-dep` (respects `XDG_CACHE_HOME`) | env-only | Relocates the persistent lookup cache (e.g. per-project or per-tenant scoping). |
| `SAFE_DEP_REDACT_PATHS` | off | env-only | `1` replaces the `file` field in audit-log entries with a deterministic hash token (log-data minimization). |
| `SAFE_DEP_POSTINSTALL_MTIME_WINDOW` | 60 (seconds) | env-only | Post-Install Mode Scan A freshness window — how recently a lockfile must have been modified to be audited after an install command. |
| `SAFE_DEP_DISABLE` | unset | `[ecosystems]` | Comma-separated ecosystems to disable (e.g. `SAFE_DEP_DISABLE=pypi,go`). Takes precedence over `safer-dependencies.toml` and `config.toml`. |
| `SAFE_DEP_SCRIPTS_DIR` | `<hook directory>/scripts` | env-only | Where the hooks locate the bundled `scripts/` directory (and the `safedep` package inside it). |
| `SAFE_DEP_SKILL_MD` | auto-discovered next to `scripts/` | env-only | Explicit path to the SKILL.md / frontmatter file used for version lookup. |
| `SAFE_DEP_DELAY_WARN_THRESHOLD` | 20 (packages) | env-only | Package count above which the shim emits a long-audit heads-up (estimated network-lookup time). Non-integer values fall back to the default. |

## How to Use This Skill

### Option A — Manual audit (no hooks)

Claude invokes the skill automatically when you ask it to add a package. No setup required.

```
User: Add aiohttp to requirements.txt
```

Claude runs the checks and writes the clean version. Use this for occasional dependency work where you don't want hooks running on every file write.

### Option B — Intercept mode, interactive (recommended)

The hook fires automatically after every manifest write. Same-major CVE fixes are silent auto-corrections. You are prompted for `MAJOR-UPDATE-CONFIRM` and `BLOCKED` decisions.

**Setup:**

1. Copy `skills/safer-dependencies-shim.sh` from this repo to `.claude/skills/safer-dependencies/shim.sh` in your project and make it executable:
   ```bash
   mkdir -p .claude/skills/safer-dependencies
   cp /path/to/safer-dependencies/skills/safer-dependencies-shim.sh \
      .claude/skills/safer-dependencies/shim.sh
   chmod +x .claude/skills/safer-dependencies/shim.sh
   ```

2. Add to `.claude/settings.json`:
   ```json
   {
     "permissions": {
       "allow": [
         "Bash(npm view *)",
         "Bash(curl -s --max-time 10 *)",
         "Bash(pip-audit *)",
         "Bash(bundle audit *)"
       ]
     },
     "hooks": {
       "PostToolUse": [
         {
           "matcher": "Write",
           "hooks": [{"type": "command",
                      "command": "${CLAUDE_PROJECT_DIR}/.claude/skills/safer-dependencies/shim.sh",
                      "timeout": 60}]
         },
         {
           "matcher": "Edit",
           "hooks": [{"type": "command",
                      "command": "${CLAUDE_PROJECT_DIR}/.claude/skills/safer-dependencies/shim.sh",
                      "timeout": 60}]
         }
       ]
     }
   }
   ```

3. Start Claude normally — no extra flags.

**What you'll see:** Silent auto-corrections for same-major fixes. Text prompts for major-version decisions and blocked packages. VERIFY instructions after each corrected manifest.

### Option C — Intercept mode, autonomous (bypassPermissions)

Same setup as Option B. No additional configuration.

When running with `--permission-mode bypassPermissions`, tool calls are unblocked but **`MAJOR-UPDATE-CONFIRM` and `BLOCKED` decisions still surface as text questions** — the orchestrator pauses and asks you before continuing. `bypassPermissions` only bypasses tool-call approval prompts; text conversation is always live.

### Option D — CI report-only (no auto-correction)

When the CI pipeline must surface vulnerability findings but must not write to the manifest (e.g. on a protected branch where only reviewed PRs can land changes), set `SAFE_DEP_DRY_RUN=1`. Every check runs and every signal is emitted, but no manifest rewrite happens. Pair with the `jq` pattern above to fail the build when any finding fires.

```bash
SAFE_DEP_DRY_RUN=1 SAFE_DEP_AUDIT_LOG=/tmp/sd-run.log \
  claude --permission-mode bypassPermissions -p "audit dependencies"
```

### A note on fully unattended CI

There is no built-in "auto-approve every major bump" mode. `MAJOR-UPDATE-CONFIRM` and `BLOCKED` always surface as text questions to whoever is driving the session — by design, because both involve a real change to the project's dependency posture. For unattended CI, the recommended shape is dry-run + a `jq` gate: run the checks, capture the findings, and fail the build if any fires. A human then reviews and lands the change in a separate PR.
