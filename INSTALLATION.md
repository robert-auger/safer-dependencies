# Installation

Complete installation guide for `safer-dependencies`. For a high-level overview of what the tool does, see [README.md](README.md). For security/privacy scope, see [SECURITY.md](SECURITY.md), [PRIVACY.md](PRIVACY.md), and [CAPABILITIES.md](CAPABILITIES.md).

## Contents

- [Option A: Interactive Installation (Recommended)](#option-a-interactive-installation-recommended)
- [Option B: All projects (global install)](#option-b-all-projects-global-install)
- [Option C: Single project only](#option-c-single-project-only)
- [Windows setup](#windows-setup)
- [Post-Agent hooks (recommended)](#post-agent-hooks-recommended)
- [Permissions allowlist](#permissions-allowlist)
- [Verify installation](#verify-installation)
- [Updating to the latest version](#updating-to-the-latest-version)
- [Pinning to a release tag](#pinning-to-a-release-tag)
- [In-session self-updater (`/safer-dependencies update`)](#in-session-self-updater-safer-dependencies-update)
- [Uninstall](#uninstall)

> **Platform note:** The shim requires bash and Python 3.9+. Works on macOS,
> Linux, and Windows. The cross-process cache lock dispatches between
> `fcntl.flock` (POSIX) and `msvcrt.locking` (Windows), so concurrent Claude
> Code sessions on the same machine are safe on every supported platform.
> Windows users need Git for Windows (provides bash) and Python 3 on `PATH`.
> WSL is not required.

A complete install has three parts: the skill file, the five hook scripts
(`shim.sh`, `pretooluse-bash.sh`, `posttooluse-bash.sh`, plus the Post-Agent
hook pair `pretooluse-agent.sh` + `posttooluse-agent.sh`), and the hook
configuration. **All five hooks are recommended** for reliable automatic
checks. The skill file alone is not enough — <b>without hooks, invocation
depends on Claude deciding to reach for the skill, which it may not always
do</b>.

The Post-Agent hook pair (Mode 5) closes a real coverage gap: manifests written
by subagents bypass the other four modes. Skills, slash commands like
`/ultrareview`, and agent-orchestrated workflows often dispatch subagents
under the hood, so the Post-Agent hooks fire more often than the name
suggests. See [Post-Agent hooks](#post-agent-hooks-recommended) for the
`settings.json` snippet.

## Option A: Interactive Installation (Recommended)

Run the bootstrap one-liner — clones the repo, hands off to the interactive installer, then cleans up the clone if you want:

```bash
git clone https://github.com/robert-auger/safer-dependencies /tmp/safer-dependencies
python3 /tmp/safer-dependencies/skills/scripts/safer_dependencies_manager.py interactive_install
```

The installer will:
1. **Ask installation scope** - choose Global (recommended, covers every Claude Code session) or Project (`.claude/` in this repo only, shared with the team via git)
2. **Detect existing setup** - scans for already-installed components
3. **Explain each hook** - describes what each hook does and its performance impact:
   - **Intercept Mode** (~2-5s per manifest edit): Auto-corrects vulnerable versions after writes
   - **Pre-Install Mode** (~1-2s per install): Blocks vulnerable packages before fetch  
   - **Post-Install Mode** (~1-3s per lockfile): Audits lockfiles after successful installs
   - **Post-Agent Mode** (~10ms per subagent + 0–3s if a subagent wrote a manifest): Re-audits manifests/lockfiles after subagent calls return — subagents bypass the other hooks, so this is the reactive safety net
4. **Configure automatically** - generates `settings.json` and permissions for selected hooks
5. **Validate setup** - runs health checks to ensure everything works

> **Transitive coverage boundary:** Intercept and Pre-Install only audit **top-level, declared** packages (the manifest as written / the literal `pkg@version` on the command line). The resolved **transitive** dependency tree — where most real-world CVEs live — is audited only by **Post-Install** and **Post-Agent**. If you install Intercept without Post-Install, you have zero transitive-CVE coverage; `python3 safer_dependencies_manager.py validate_installation` (or "check safer-dependencies setup") warns about this configuration.

This gives you full control while guiding you to the most effective configuration. Manual installation options are available below for advanced users.

Once installed, security *policy* is configurable via `/safer-dependencies config`: the cooloff window and mode (release-age gate, default warn at 7 days) and a per-check `off` / `warn` / `block` tier for every check type, stored in `~/.config/safer-dependencies/config.toml`. See `skills/references/configuration.md` for the schema, tier semantics, and env-var precedence.

### Re-runs, updates, stats, validation — via natural language

Once the first install is on disk, the skill's description triggers fire on natural-language phrases. From any Claude Code session you can say:

| Goal | Phrase |
|---|---|
| Re-run the installer (change hook selection, refresh files) | `install safer-dependencies` |
| Update to a newer version | `update safer-dependencies` — fetches the latest from GitHub and re-runs the installer automatically |
| See usage stats | `show safer-dependencies stats` |
| Confirm everything is wired correctly | `check safer-dependencies setup` |

The CLI invocations (`python3 …/safer_dependencies_manager.py <command>`) remain available and do the same work — useful for CI, scripts, or if you don't want to interrupt your current chat to run a management task.

> **Note on the bootstrap step:** the natural-language phrases above only work *after* the skill file is on disk (Claude matches against the skill's `description:` field, which Claude Code only sees once `~/.claude/skills/safer-dependencies/SKILL.md` exists). The `git clone` + `python3 … interactive_install` one-liner is the canonical first install. Future plugin-marketplace distribution will close that bootstrap gap — for now, the bootstrap is one command, then conversational from there.

### What each management command produces

**`show safer-dependencies stats`** — usage analytics from the audit log:
- **Activity**: Total audits run, breakdown by hook type (intercept/pre-install/post-install)
- **Security Impact**: CVEs blocked, packages updated, major version warnings issued
- **By Model**: Per-model findings count and total audits — compare which Claude versions produce the most vulnerable dependencies
- **Eco Findings**: Per-ecosystem findings with top 3 most-blocked packages
- **Performance**: Average audit durations, network failure rates, fail-open events
- **Ecosystem Health**: Most flagged packages, ecosystem distribution, trends

Stats are generated from existing audit logs with no performance impact.

**`check my safer-dependencies setup`** — health checks on:
- Skill file location and permissions
- Hook script installation and execution permissions
- Claude Code configuration in `settings.json`
- Permission allowlist for required bash commands
- End-to-end test of permission denial flow

**`configure safer-dependencies hooks`** — interactive management:
- Add or remove specific hooks (intercept, pre-install, post-install)
- Update permission settings
- Repair broken installations
- Migrate between global and project-level configurations

## Option B: All projects (global install)

**Step 1 — Copy files:**

```bash
git clone https://github.com/robert-auger/safer-dependencies.git /tmp/safer-dependencies
mkdir -p ~/.claude/skills/safer-dependencies
cp /tmp/safer-dependencies/skills/safer-dependencies.md ~/.claude/skills/safer-dependencies/SKILL.md
cp /tmp/safer-dependencies/skills/safer-dependencies-shim.sh ~/.claude/skills/safer-dependencies/shim.sh
cp /tmp/safer-dependencies/skills/safer-dependencies-pretooluse-bash.sh ~/.claude/skills/safer-dependencies/pretooluse-bash.sh
cp /tmp/safer-dependencies/skills/safer-dependencies-posttooluse-bash.sh ~/.claude/skills/safer-dependencies/posttooluse-bash.sh
# Idempotent: remove any existing scripts/ first so re-install does not nest
# a new scripts/scripts/ subdirectory inside the old one.
rm -rf ~/.claude/skills/safer-dependencies/scripts
cp -r /tmp/safer-dependencies/skills/scripts ~/.claude/skills/safer-dependencies/scripts
# The skill links 8 supplementary docs under references/ — copy them too.
rm -rf ~/.claude/skills/safer-dependencies/references
cp -r /tmp/safer-dependencies/skills/references ~/.claude/skills/safer-dependencies/references
chmod +x ~/.claude/skills/safer-dependencies/shim.sh
chmod +x ~/.claude/skills/safer-dependencies/pretooluse-bash.sh
chmod +x ~/.claude/skills/safer-dependencies/posttooluse-bash.sh
```

> Keep the `/tmp/safer-dependencies` clone for now — the recommended
> [Post-Agent hooks](#post-agent-hooks-recommended) copy two more scripts from
> it. Delete it once everything is installed: `rm -rf /tmp/safer-dependencies`

**Step 2 — Configure hooks** in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write",
        "hooks": [{
          "type": "command",
          "command": "${HOME}/.claude/skills/safer-dependencies/shim.sh",
          "timeout": 60
        }]
      },
      {
        "matcher": "Edit",
        "hooks": [{
          "type": "command",
          "command": "${HOME}/.claude/skills/safer-dependencies/shim.sh",
          "timeout": 60
        }]
      },
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "${HOME}/.claude/skills/safer-dependencies/posttooluse-bash.sh",
          "timeout": 60
        }]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "${HOME}/.claude/skills/safer-dependencies/pretooluse-bash.sh",
          "timeout": 30
        }]
      }
    ]
  }
}
```

**Step 3 — Add the [permissions allowlist](#permissions-allowlist)** to the
same `~/.claude/settings.json`, so the skill's check commands run without a
permission prompt on every audit.

## Option C: Single project only

From your project root:

**Step 1 — Copy files:**

```bash
git clone https://github.com/robert-auger/safer-dependencies.git /tmp/safer-dependencies
mkdir -p .claude/skills/safer-dependencies
cp /tmp/safer-dependencies/skills/safer-dependencies.md .claude/skills/safer-dependencies/SKILL.md
cp /tmp/safer-dependencies/skills/safer-dependencies-shim.sh .claude/skills/safer-dependencies/shim.sh
cp /tmp/safer-dependencies/skills/safer-dependencies-pretooluse-bash.sh .claude/skills/safer-dependencies/pretooluse-bash.sh
cp /tmp/safer-dependencies/skills/safer-dependencies-posttooluse-bash.sh .claude/skills/safer-dependencies/posttooluse-bash.sh
# Idempotent: remove any existing scripts/ first so re-install does not nest
# a new scripts/scripts/ subdirectory inside the old one.
rm -rf .claude/skills/safer-dependencies/scripts
cp -r /tmp/safer-dependencies/skills/scripts .claude/skills/safer-dependencies/scripts
# The skill links 8 supplementary docs under references/ — copy them too.
rm -rf .claude/skills/safer-dependencies/references
cp -r /tmp/safer-dependencies/skills/references .claude/skills/safer-dependencies/references
chmod +x .claude/skills/safer-dependencies/shim.sh
chmod +x .claude/skills/safer-dependencies/pretooluse-bash.sh
chmod +x .claude/skills/safer-dependencies/posttooluse-bash.sh
```

> Keep the `/tmp/safer-dependencies` clone for now — the recommended
> [Post-Agent hooks](#post-agent-hooks-recommended) copy two more scripts from
> it. Delete it once everything is installed: `rm -rf /tmp/safer-dependencies`

**Step 2 — Configure hooks** in `.claude/settings.json` at your project root:

```json
{
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
      },
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "${CLAUDE_PROJECT_DIR}/.claude/skills/safer-dependencies/posttooluse-bash.sh",
          "timeout": 60
        }]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "${CLAUDE_PROJECT_DIR}/.claude/skills/safer-dependencies/pretooluse-bash.sh",
          "timeout": 30
        }]
      }
    ]
  }
}
```

`${CLAUDE_PROJECT_DIR}` is set by Claude Code automatically; no path editing needed.

**Step 3 — Add the [permissions allowlist](#permissions-allowlist)** to the
same `.claude/settings.json`, so the skill's check commands run without a
permission prompt on every audit.

**Step 4 — Commit** `.claude/` to your repo so the whole team gets it:

```bash
git add .claude/ && git commit -m "setup: add safer-dependencies security skill"
```

## Windows setup

The shim runs natively on Windows — no WSL required. Claude Code uses Git Bash
(`SHELL=/bin/bash.exe`) as its execution shell, which is provided by
[Git for Windows](https://git-scm.com/download/win).

**Prerequisites:**

1. **Git for Windows** — installs `bash`, `mktemp`, and standard Unix tools.
   Most Windows developers already have this.

2. **Python 3.9+** — install from [python.org](https://www.python.org/downloads/windows/)
   or the Microsoft Store. During install, check **"Add Python to PATH"**.
   Verify with `bash -c "python3 --version"` in a terminal.

Follow Option B or C above using Git Bash. The hook path works as-is — Claude Code
injects `${CLAUDE_PROJECT_DIR}` and Git Bash resolves it correctly.

**Verify** by asking Claude to add a known-vulnerable package (e.g. `"lodash": "4.17.10"`
in `package.json`). You should see an `UPDATED:` signal in the response.

## Post-Agent hooks (recommended)

Install these alongside the other hooks. Modes 2–4 only fire for root-session
tool calls; subagent writes bypass them. The Post-Agent hook pair is the
reactive safety net that audits whatever the subagent wrote on disk after each
Agent call returns. Because many skills and slash commands dispatch subagents
internally, this matters even if you never explicitly spawn one.

The hooks have **zero overhead when no subagent runs** — they only fire on
`PreToolUse:Agent` and `PostToolUse:Agent` events. When subagents do run, the
post-hook walks the project tree once with `find -maxdepth 5` (excluding
`node_modules`, `.git`, `.venv`, `venv`), so cost scales with project size,
typically under 1 second.

**Step 1 — Copy the two extra hook scripts** alongside the rest of the install.
Use the install root that matches your setup (`~/.claude` for Option B,
`.claude` for Option C):

```bash
# global (Option B) — substitute ~/.claude with .claude for project install
cp /tmp/safer-dependencies/skills/safer-dependencies-pretooluse-agent.sh \
   ~/.claude/skills/safer-dependencies/safer-dependencies-pretooluse-agent.sh
cp /tmp/safer-dependencies/skills/safer-dependencies-posttooluse-agent.sh \
   ~/.claude/skills/safer-dependencies/safer-dependencies-posttooluse-agent.sh
chmod +x ~/.claude/skills/safer-dependencies/safer-dependencies-pretooluse-agent.sh \
         ~/.claude/skills/safer-dependencies/safer-dependencies-posttooluse-agent.sh
```

> The Agent hooks keep their full filenames (unlike `shim.sh` etc.). Both must
> be installed together — the post-hook silently no-ops without the sentinel
> from the pre-hook.

**Step 2 — Add the matching hook entries** to your existing `settings.json`
(merge with the `hooks` block from Option B or C):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Agent",
        "hooks": [{
          "type": "command",
          "command": "${HOME}/.claude/skills/safer-dependencies/safer-dependencies-pretooluse-agent.sh",
          "timeout": 5
        }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Agent",
        "hooks": [{
          "type": "command",
          "command": "${HOME}/.claude/skills/safer-dependencies/safer-dependencies-posttooluse-agent.sh",
          "timeout": 120
        }]
      }
    ]
  }
}
```

For project-level install, swap `${HOME}/.claude` for `${CLAUDE_PROJECT_DIR}/.claude`.

## Permissions allowlist

**Why this matters:** the skill's checks shell out to registry and audit
commands (`curl`, `npm view`, `pip-audit`, the `resolve_*.py` scripts, …).
Without an allowlist, Claude Code stops and asks you to approve **every one
of those commands, on every audit** — which makes the automatic hooks feel
broken and trains you to click through prompts. The allowlist pre-approves
exactly these read-only check commands and nothing else.

The interactive installer (Option A) writes the six core command entries
(`npm view`, `curl`, `npm audit`, `pip-audit`, `bundle audit`, `gem fetch`)
for you; the block below is the complete set, including the resolver-script
entries Normal Mode uses. **Manual installs (Options B and C) must add it by
hand** — add the block below to
`~/.claude/settings.json` (global install) or `.claude/settings.json`
(project install), merging with any existing `permissions.allow` entries:

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
      "Bash(dependency-check *)",
      "Bash(python3 */safer-dependencies/scripts/resolve_npm.py)",
      "Bash(python3 */safer-dependencies/scripts/resolve_pypi.py)",
      "Bash(python3 */safer-dependencies/scripts/resolve_rubygems.py)",
      "Bash(python3 */safer-dependencies/scripts/resolve_maven.py)",
      "Bash(python3 */safer-dependencies/scripts/first_publish_pypi.py)",
      "Bash(python3 */safer-dependencies/scripts/first_publish_rubygems.py)",
      "Bash(python3 */safer-dependencies/scripts/first_publish_maven.py)",
      "Bash(python3 */safer-dependencies/scripts/github_repo_age.py)",
      "Bash(python3 */safer-dependencies/scripts/pypi_hashes.py)",
      "Bash(python3 */safer-dependencies/scripts/check_typosquat.py *)",
      "Bash(python3 */safer-dependencies/scripts/audit_log_append.py)"
    ]
  }
}
```

The Python entries are pinned to exact script filenames on purpose — a
broad `Bash(python3 *)` rule would auto-approve arbitrary Python and defeat
the point of the permission system.

## Verify installation

Run these checks from a fresh terminal after install:

```bash
# 1. Layout — scripts/safedep/ must be a direct child of scripts/
ls ~/.claude/skills/safer-dependencies/scripts/safedep/__init__.py

# 2. Executability — all hook scripts present and +x
ls -l ~/.claude/skills/safer-dependencies/{shim,pretooluse-bash,posttooluse-bash}.sh

# 2b. Supplementary references the skill links to are present
ls ~/.claude/skills/safer-dependencies/references/

# 3. Python is reachable from a shell the hook will use
python3 --version

# 4. Smoke-test the shim with an empty payload (should exit cleanly with no
#    output; non-zero exit means a broken install)
echo '{"tool_input":{"file_path":"/tmp/nope.json"}}' \
  | bash ~/.claude/skills/safer-dependencies/shim.sh
echo "shim exit: $?"
```

Then start a Claude Code session and write a manifest entry with a
known-vulnerable version (e.g. `"lodash": "4.17.10"` in `package.json`). You
should see an `UPDATED:` signal in the response.

## Updating to the latest version

The install procedure is **idempotent** — re-running the relevant commands from
[Option B](#option-b-all-projects-global-install) or
[Option C](#option-c-single-project-only) replaces every script and the
`scripts/` directory atomically. Hook configuration in `settings.json` does
not change between versions, so Step 2 of the install can be skipped.

```bash
# Refresh the source clone (handles both first-update and subsequent runs).
# Pinning the branch defends against a stale checkout that drifted off main.
git -C /tmp/safer-dependencies fetch origin main 2>/dev/null \
  && git -C /tmp/safer-dependencies checkout main 2>/dev/null \
  && git -C /tmp/safer-dependencies reset --hard origin/main 2>/dev/null \
  || git clone https://github.com/robert-auger/safer-dependencies.git /tmp/safer-dependencies

# Then re-run **Step 1** of your install option (Option B or C). The same copy
# commands work for updates — `rm -rf …/scripts` followed by `cp -r …/scripts`
# replaces the directory atomically and avoids a nested scripts/scripts/ layout.

# Re-run the Post-Agent hooks' Step 1 as well so the agent scripts refresh.

rm -rf /tmp/safer-dependencies
```

After updating, re-run the `Verify installation` checks above.

**Checking what version you're running:** the install procedure copies files
into your skills directory but doesn't track the source tag. To check,
inspect the source clone you used:

```bash
git -C /tmp/safer-dependencies describe --tags --always 2>/dev/null
```

(Empty output or "fatal: not a git repository" means the source clone was
deleted after install — re-run the update procedure to refresh.)

## Pinning to a release tag

The default update procedure tracks `origin/main` so you always get the
latest code. If you'd rather pin to a known-good tagged release —
recommended for team / shared / production environments — replace
`origin/main` with the tag in the refresh step:

```bash
git -C /tmp/safer-dependencies fetch --tags origin 2>/dev/null \
  && git -C /tmp/safer-dependencies checkout v0.5.1 2>/dev/null \
  || git clone --branch v0.5.1 --depth 1 https://github.com/robert-auger/safer-dependencies.git /tmp/safer-dependencies
```

Then re-run Step 1 of your install option as usual. The current latest
release is listed at <https://github.com/robert-auger/safer-dependencies/releases>.
See [Versioning policy](CHANGELOG.md#versioning-policy) in the changelog for what each version bump means.

## In-session self-updater (`/safer-dependencies update`)

Once safer-dependencies is installed you can update it from inside a Claude Code session without returning to a terminal:

| Command | Effect |
|---|---|
| `/safer-dependencies update` | Resolve the latest ref, preview the pending change, and (in interactive sessions) prompt for confirmation before applying |
| `/safer-dependencies update --check` | Dry-run: report what would change without writing any files |
| `/safer-dependencies update --rollback` | Restore the bundle and `settings.json` from the automatic pre-update backup |

Natural-language equivalent: say `"update safer-dependencies"` to Claude.

**How it works:** the updater resolves the latest tag (or `main` as fallback) over HTTPS, clones the verified ref into a per-run `mkdtemp(0700)` directory (readable only by the current user), then copies the updated files into place using the **already-installed** manager. The freshly-cloned manager is never executed — only the trusted copy on disk drives the apply step. Your `settings.json` hook configuration is backed up before any file is written and auto-restored if the post-update health check fails.

Every update operation (check, apply, rollback) is written to the audit log. For the trust model and tag-signing posture, see [SECURITY.md](SECURITY.md#self-update-trust-model).

## Uninstall

```bash
# Global Uninstall
rm -rf ~/.claude/skills/safer-dependencies

# Project Uninstall
rm -rf .claude/skills/safer-dependencies
```

Then remove the hook entries from your `settings.json` — **this step matters**:
otherwise Claude Code will keep trying to invoke the deleted scripts on every
tool call and log errors. Remove every entry whose `command` references the
`safer-dependencies` directory:

- `PostToolUse` matchers: `Write`, `Edit`, `Bash`
- `PreToolUse` matchers: `Bash`
- `PreToolUse` matcher `Agent` and `PostToolUse` matcher `Agent` (the Post-Agent hooks)

Optionally also remove the [permissions allowlist](#permissions-allowlist)
entries — they're harmless on their own but no longer needed.
