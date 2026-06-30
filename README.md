# Safer Dependencies for Claude Code

Automatically checks dependencies that Claude adds through its `Write`, `Edit`, and `Bash` tools, and auto-corrects vulnerable versions in place. Runs provenance, version age, vulnerability, and hash-integrity checks across npm, PyPI, RubyGems, Maven, Go, Rust, and PHP (Composer). Coverage is scoped to writes that go through Claude's tools (Intercept Mode corrects a vulnerable pin *after* the file lands, within the same tool cycle — not before); see [CAPABILITIES.md](CAPABILITIES.md) for exactly what is and isn't covered. 

> **Security & privacy:** see [SECURITY.md](SECURITY.md) (vulnerability disclosure), [PRIVACY.md](PRIVACY.md) (data egress, no telemetry), and [CAPABILITIES.md](CAPABILITIES.md) (what the tool defends against and what it doesn't).

> **License (source-available — NOT OSI "open source"):** Free to use and modify for your own purposes, **including for-profit/company internal use and building products you sell**. A separate paid license is required **only** to monetize the software *itself* — selling it, shipping it inside a product or service that is sold, or offering its functionality to third parties for a fee (including hosted/SaaS/API). Redistribution and derivatives must keep the license and credit this project. See **[LICENSE](LICENSE)** (Section 4 for the commercial restriction); commercial-license requests via [github.com/robert-auger](https://github.com/robert-auger).

## Contents

- [What it does](#what-it-does)
- [How it works](#how-it-works)
  - [Normal Mode (Manual)](#normal-mode-manual)
  - [Intercept Mode (Automatic)](#intercept-mode-automatic)
  - [Pre-Install Mode (Bash Hook)](#pre-install-mode-bash-hook)
  - [Post-Install Mode (Bash Hook)](#post-install-mode-bash-hook)
  - [Post-Agent Mode (Agent Hook Pair)](#post-agent-mode-agent-hook-pair)
- [What triggers it](#what-triggers-it)
- [What's in this repo](#whats-in-this-repo)
- [Supported ecosystems](#supported-ecosystems)
- [Install](#install)
- [Versioning](#versioning)
- [Configuration](#configuration)
  - [Auto-approve Check Commands (Optional)](#auto-approve-check-commands-optional)
- [Warning levels](#warning-levels)
- [Audit log](#audit-log)
- [Requirements](#requirements)
- [Keeping safer-dependencies up to date](#keeping-safer-dependencies-up-to-date)
- [Uninstall](#uninstall)
- [FAQ](#faq)

## What it does

When AI coding assistants like Claude add packages to your project, they often pick whatever version sounds right — without checking whether it has known security vulnerabilities, whether the package is still actively maintained, or whether the name is a typo away from a malicious lookalike. safer-dependencies fixes that by sitting between Claude and your manifest files and running security checks automatically, before any unsafe version lands in your code.

When Claude is about to add a package to your project, this skill intercepts and runs 5 checks:

1. **Provenance** -- official registry, typosquat detection (npm/PyPI/RubyGems/Maven/crates.io), package age
2. **Version age** -- picks the newest stable version published 7+ days ago (cooldown window)
3. **Vulnerability scan** -- OSV API, with ecosystem-native tools (npm audit, pip-audit, bundle audit) when available
4. **Hash-pin integrity** -- for PyPI `requirements.txt` lines with `--hash=sha256:...` pins, the declared hash is validated against PyPI's published hashes; mismatch emits a WARNING
5. **Abandoned & stale packages** -- known-abandoned packages (e.g. `paperclip`, `request`, `pycrypto`, `github.com/dgrijalva/jwt-go`) are hard-blocked immediately with a suggested replacement; packages with no stable release in 2+ years get an advisory `STALE:` warning. Hard-blocked packages are removed from the manifest and Claude will ask how to proceed; stale-only packages are left in place.

If issues are found, Claude emits warnings and may step back to a safer version. All checks are logged to `~/.claude/safer-dependencies-audit-YYYY-MM.log` (one file per calendar month).

## How it works

The skill operates in five modes (summarized below; the deepest design rationale lives in `skills/safer-dependencies.md`):

### Normal Mode (Manual)

When Claude is about to write an `import`, add a package to a manifest, or update a lock file, the skill runs inline in your session:

1. Queries the package registry for stable versions
2. Auto-selects the newest version published 7+ days ago (deterministic -- no LLM judgment)
3. Checks for known vulnerabilities via ecosystem tools and the OSV API
4. Verifies package signatures where available
5. Emits warnings if issues are found, pins the exact version
6. Logs the result to the audit trail

The version selection is handled by standalone Python scripts bundled with the skill, not by the LLM interpreting rules. The command outputs `SELECTED: <version>` and Claude uses that version exactly.

### Intercept Mode (Automatic)

Configure `.claude/settings.json` with a `PostToolUse` hook to enable automatic, transparent package verification:

1. Claude writes a manifest file (e.g. `package.json`) with the originally-requested version — the file lands on disk
2. The `PostToolUse` hook fires immediately after the write completes and invokes `safer-dependencies-shim.sh`
3. The shim reads the file, parses declared packages, and runs all security checks (typosquat, abandoned, CVE, staleness, hash-pin)
4. If corrections are needed, the shim **rewrites the manifest in place** with safe versions (or removes entries that have no safe version)
5. The shim emits signals (`UPDATED:`, `BLOCKED:`, `WARNING:`, `STALE:`, `MAJOR-UPDATE-CONFIRM:`, `REFACTOR-REQUIRED:`, `REGRESSION:`, `TYPOSQUAT-CONFIRM:`, `VERIFY:`, `CLEAN:`) via `hookSpecificOutput.additionalContext` on stdout. `REGRESSION:` precedes a `MAJOR-UPDATE-CONFIRM:` when the audit log shows the same (file, package) was previously corrected to the same safe target — that is, a subagent or stale plan has re-introduced a known-vulnerable version, and the orchestrator should restore the previously-approved version rather than re-deciding the major bump.
6. Claude receives those signals as a system-reminder and performs follow-up work (find affected imports, run tests, refactor for breaking changes)

**Design note — Shape C (post-write corrective):** the hook does NOT block writes. Each vulnerable version lands on disk first and is then auto-corrected within the same tool-use cycle. This is a deliberate choice over a `PreToolUse` blocking design — see [FAQ.md](FAQ.md#why-posttooluse-post-write-corrective-instead-of-pretooluse-pre-write-blocking-for-the-manifest-path) for the tradeoffs.

**Example signal:**
```
UPDATED: aiohttp 3.8.5 → 3.9.0 (HIGH: 33 CVEs fixed)
```

The parent agent uses these signals to identify affected code and refactor as needed.

### Pre-Install Mode (Bash Hook)

Configure `.claude/settings.json` with a `PreToolUse:Bash` hook to enable
pre-flight auditing of package-manager install commands. This complements
(does not replace) Intercept Mode — together they form a layered defense.

1. Claude attempts a Bash tool call (e.g. `npm install lodash@4.17.20`)
2. The `PreToolUse` hook fires before the call runs and invokes
   `safer-dependencies-pretooluse-bash.sh`
3. A pure-bash early filter short-circuits non-PM commands in ~115 ms
   (no Python invocation), so `git status` / `ls` / `npm test` pay
   negligible cost on the hot path
4. For recognized package-manager installs (`npm`/`pnpm`/`yarn`
   `install`/`i`/`add`), the helper tokenizes via `shlex`, extracts each
   `pkg@version` argument, and POSTs to OSV
5. Any vulnerable concrete pin → the hook returns
   `permissionDecision: "deny"` with a per-finding GHSA-id + CVSS +
   summary, plus a hint to invoke the safer-dependencies skill
6. The install never runs — no network fetch, no postinstall scripts

**Why this exists in addition to Intercept Mode:** the post-write shim
is blind to Bash. `npm install lodash@4.17.20` runs to completion (and
postinstall scripts execute) before any audit fires; `npm install -g
typosquat-pkg` writes no project manifest at all. Pre-Install Mode
closes those gaps structurally.

Pre-Install Mode only sees what the user **typed** (`pkg@version` args on
the command line). It can't see the transitive tree the resolver will
actually install. **Post-Install Mode** (below) audits the lockfile once
the install completes — the two modes are complementary, not redundant.

**Scope:** the package-manager CLIs covered here span five ecosystems
(npm/pnpm/yarn/bun/npx/deno, pip/pip3/pipx/pipenv/uv/uvx/poetry, gem/bundle,
go, cargo), plus Maven via Intercept Mode (Maven dependencies are typically
declared in `pom.xml`/`build.gradle`, not added via a CLI verb).

> **Known gap:** the Maven CLI does support direct downloads via
> `mvn dependency:get -Dartifact=group:art:version` and `mvn dependency:copy`.
> This hook does not yet recognize those invocations. If you use them
> regularly, the existing post-write shim still catches whatever lands in
> your manifest, but the pre-fetch protection only applies to the
> ecosystems listed above. Tracked as a follow-up.

Per-ecosystem syntax recognized:

| PM | Verbs | Concrete-pin syntax |
|---|---|---|
| `npm`, `pnpm`, `yarn`, `bun` | `install`, `i`, `add` (plus `yarn`/`pnpm dlx`, `bun x`, `yarn create`) | `pkg@1.2.3`, `@scope/pkg@1.2.3` |
| `npx` | (verbless — package is first positional) | `pkg@1.2.3` |
| `deno` | `add`, `install` | `npm:pkg@1.2.3` (npm-prefixed specs) |
| `pip`, `pip3`, `pipx`, `pipenv`, `uv`, `uvx`, `poetry` | `install` (pip/pip3/pipx/pipenv) / `add` (uv/poetry) / verbless (uvx) | `pkg==1.2.3` (extras `pkg[extra]==X` also handled) |
| `gem`, `bundle` | `install` (gem) / `add` | `-v 1.2.3`, `--version 1.2.3`, `--version=1.2.3` (separate flag) |
| `go` | `get`, `install` | `pkg@v1.2.3` (must include `v` prefix per Go modules) |
| `cargo` | `add`, `install` | `crate@1.2.3` |

Range pins (npm `^4.17`, pip `>=`, poetry `^`/`~`, Go `@latest`) and
unspecified versions pass through to Intercept Mode after install — the
post-write shim audits whatever the resolver picks. Auto-rewrite to a
safe version is queued as a follow-up.

**Failure mode:** fail-open. Any error (Python missing, network blip,
malformed input) exits 0 with no output, allowing bash to proceed.
Intercept Mode still runs after install, so a failed pre-flight degrades
gracefully to existing protection.

**Example deny:**
```
safer-dependencies pre-flight audit blocked this install.
Vulnerable pinned version(s) detected:
  - lodash@4.17.20 → GHSA-35jh-r3h4-6jhm (CVSS:7.4): Command Injection in lodash
Re-run with a patched version, or invoke the safer-dependencies skill
for a recommended pin.
```

### Post-Install Mode (Bash Hook)

Configure `.claude/settings.json` with a `PostToolUse:Bash` hook to enable
post-flight auditing after Bash commands. It runs **three independent scans**
against the command's `cwd`, each closing a gap the other hooks can't address:

- **Scan A — lockfiles.** After a successful install verb (`npm install`,
  `bundle install`, `poetry install`, `uv sync`, `go mod tidy`, etc.), audits
  freshly-modified lockfiles (`package-lock.json`, `Gemfile.lock`,
  `poetry.lock`, `uv.lock`, `go.sum`, `yarn.lock`, `pnpm-lock.yaml`,
  `Pipfile.lock`). This closes the **transitive-CVE gap** Pre-Install can't
  see: the user typed `pkg@version`, but the resolver may have pulled in
  dozens of transitives no one named.
- **Scan B — manifests.** After any Bash command *not* on a read-only
  denylist (`ls`, `cat`, `git status`, …), audits freshly-modified manifests.
  This is the **only** fallback for manifest edits made via `sed -i`, `jq`, or
  a script — those bypass the `Write`/`Edit` tool that Intercept Mode hooks on.
- **Scan C — resolved environment.** Plain `pip install` /
  `pip install -r requirements.txt` writes no lockfile, so Scan A never sees
  the resolved tree. After a pip-shaped install, Scan C re-invokes the same
  pip with a read-only `list --format=json` and OSV-checks the full resolved
  environment (direct + transitive).

How a scan runs:

1. Claude runs a Bash tool call
2. The `PostToolUse` hook fires *after* the command completes and invokes
   `safer-dependencies-posttooluse-bash.sh`
3. A pure-bash early filter short-circuits commands that match no scan gate in
   ~115 ms (same fast-path convention as Pre-Install), so `ls` / `git` / `cat`
   pay negligible cost
4. Each scan walks `cwd` with `find -maxdepth 5` (covers monorepo layouts;
   excludes `node_modules`, `.git`, `.venv`, `venv`) for files modified within
   the last 60 s — override via `SAFE_DEP_POSTINSTALL_MTIME_WINDOW`
5. For each freshly-modified file (Scan A/B), the hook forges a synthetic
   `PostToolUse:Write` payload and pipes it to the existing shim — the shim's
   lockfile and manifest auditors run unchanged, no duplicated logic
6. Per-file signals are concatenated and emitted as one `hookSpecificOutput`
   JSON to the parent agent

**What it catches that Pre-Install doesn't:** transitive vulnerabilities.
A clean-looking `bundle install` can pull `rack@2.2.23` (CVE-2025-27610)
as a transitive of `sinatra` — the user never typed `rack`, so
Pre-Install can't see it, but Post-Install reads the resolved
`Gemfile.lock` and reports the CVE.

**Scope:** Scan A does not rewrite resolved versions — the auto-correct
contract only applies to manifests Claude wrote directly. For transitive CVEs,
the fix is typically "update the direct dep that owns the transitive," which
needs human judgment. Scan B *does* auto-correct, because it audits manifests
through the same shim path as Intercept Mode. Scan A skips when the
`transitive` check tier is set to `off` (`config set checks.transitive off`).

**Failure mode:** fail-open, same as other hooks. Any error (missing
shim, malformed payload, Python unavailable) exits 0 silently.

**Example WARNING:**
```
WARNING: lodash@4.17.10 in lock file has GHSA-29mw-wpgm-hmr9, GHSA-35jh-r3h4-6jhm
```

### Post-Agent Mode (Agent Hook Pair)

The four modes above only fire for **root-session** tool calls. When the root
session dispatches a subagent (via the `Agent` tool — many skills and slash
commands do this internally), the subagent's Write/Edit/Bash calls bypass all
of them. Post-Agent Mode is the reactive safety net for that gap.

1. A `PreToolUse:Agent` hook (`safer-dependencies-pretooluse-agent.sh`) runs
   immediately before each Agent dispatch and touches a sentinel file at
   `/tmp/.safer-deps-agent-<PPID>-<session_id>.sentinel` (falling back to a
   PPID-only name when no session id is available)
2. The subagent runs and may write manifests or lockfiles
3. A `PostToolUse:Agent` hook (`safer-dependencies-posttooluse-agent.sh`) runs
   after the Agent call returns, `find`s every manifest and lockfile newer than
   the sentinel, and audits each via the same shim path
4. Findings surface as `additionalContext` to the root session's next turn; the
   sentinel is removed

Nested subagents are covered automatically — the root's `PostToolUse:Agent`
fires only after all of the outer agent's work (including anything *it*
dispatched) is on disk. The one gap is a global install that writes no
manifest or lockfile (`npm install -g …`): there is nothing to scan. Like the
other hooks, it fails open — any error (missing sentinel, missing shim,
unreadable payload) exits 0 silently. Full design rationale lives in
`skills/safer-dependencies.md`.

## What triggers it

The skill fires automatically when Claude:

**Manifest / install operations**
- Adds or updates a package in `package.json`, `requirements.txt`, `Gemfile`, `pom.xml`, `build.gradle`, `Cargo.toml`, `go.mod`, or any other supported manifest
- Writes an `import`, `require`, or `use` for a package not already declared in the manifest
- Generates or updates a lock file (checks only new/changed entries)
- Runs a package-manager install via Bash (`npm install`, `bundle install`, `poetry install`, `uv sync`, `go mod tidy`, etc.) — Pre-Install audits the command args, Post-Install audits the resulting lockfile
- Writes a `Dockerfile` or CI workflow (`.github/workflows/*.yml`, etc.) that embeds pinned package-manager install steps

**Selection & recommendation questions**
- Library/framework comparisons: "should I use axios or node-fetch?", "moment vs dayjs?", "which is better X or Y?"
- Recommendation requests: "what's a good HTTP client for Python?", "recommend a logging library for Go", "what package handles CSV in Node?"
- Version selection: "what version of Django should I use?", "latest stable Flask?"

**Intent-to-use expressions (pre-add)**
- "I want to use FastAPI for this", "I'm thinking of adding Celery", "we're looking at Prisma as the ORM", "let's use Tailwind"

**Package health and trust questions**
- "Is moment.js still maintained?", "is this gem still active?", "is X abandoned?", "is X EOL?", "can I trust this package?", "when was faker last updated?"

**Scaffolding commands**
- `npx create-react-app`, `npm create vite@latest`, `django-admin startproject`, `rails new`, `cargo new` + `cargo add`, "bootstrap a new FastAPI project"

**Implicit package adds (feature requests that imply a new dependency)**
- "Add Redis caching to the app", "connect to Postgres", "add JWT auth", "write code to send emails" — fires when no package for that capability is already in the manifest

**Migration and porting**
- "Migrate from requests to httpx", "move from CRA to Vite", "port from moment to date-fns" — audits the incoming package

It does **not** fire for:

- Standard library imports (`os`, `fs`, `java.util.*`, etc.)
- Already-declared dependencies that aren't being changed
- Academic discussion of how a package works internally ("explain React's reconciler", "how does webpack's module resolution work?") — comparison and selection questions do still fire
- Installing OS-level apps, runtimes, or IDE extensions (Python itself, Docker, Homebrew, VS Code extensions)

## What's in this repo

This is a **skill + hook bundle**, not a single skill file. A complete install deploys these pieces:

| File | Role |
|---|---|
| `skills/safer-dependencies.md` | The **skill** (`SKILL.md` once installed). Describes audit procedures and includes management mode for installation/stats. |
| `skills/safer-dependencies-shim.sh` | `PostToolUse:Write`/`Edit` hook — audits manifest + lockfile writes and auto-corrects vulnerable versions in place (Intercept Mode). |
| `skills/safer-dependencies-pretooluse-bash.sh` | `PreToolUse:Bash` hook — pre-flight OSV audit of package-manager install commands; denies vulnerable concrete pins before the install runs (Pre-Install Mode). |
| `skills/safer-dependencies-posttooluse-bash.sh` | `PostToolUse:Bash` hook — post-flight audit after Bash commands; catches transitive CVEs in freshly-written lockfiles, manifests edited via `sed`/`jq`/scripts, and the resolved environment of plain `pip install` (Post-Install Mode). |
| `skills/safer-dependencies-pretooluse-agent.sh` + `skills/safer-dependencies-posttooluse-agent.sh` | `PreToolUse:Agent` + `PostToolUse:Agent` hook pair — closes the subagent coverage gap. Modes 2–4 only fire for root-session tool calls, so any manifest a subagent writes bypasses them. Post-Agent audits whatever the subagent wrote after each Agent tool-call returns (Post-Agent Mode). |
| `skills/scripts/` | Shared Python library (`safedep/`) and standalone resolver scripts used by all hooks. |
| `skills/scripts/safer_dependencies_manager.py` | Management module for interactive installation, usage stats, and setup validation. |

The skill file alone is not enough — without hooks, automatic invocation depends on Claude deciding to reach for the skill. Install all five pieces for full coverage; many skills and slash commands dispatch subagents internally, so the Post-Agent pair matters even if you never explicitly spawn one. (See [FAQ.md](FAQ.md#why-a-skill-alone-is-not-sufficient) for why a skill on its own can't guarantee coverage.)

## Supported ecosystems

| Ecosystem | Manifest | Lock file |
|-----------|----------|-----------|
| npm | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| PyPI | `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py`, `setup.cfg` | `Pipfile.lock`, `poetry.lock`, `uv.lock` |
| RubyGems | `Gemfile`, `*.gemspec` | `Gemfile.lock` |
| Maven | `pom.xml`, `build.gradle`, `libs.versions.toml` | -- |
| Go | `go.mod` | `go.sum` |
| Rust | `Cargo.toml` | `Cargo.lock` |

## Install

**Bootstrap (first install)** — runs the interactive installer that prompts for scope (global vs project) and which hooks to enable, writes `settings.json`, and validates the setup:

```bash
git clone https://github.com/robert-auger/safer-dependencies /tmp/safer-dependencies
python3 /tmp/safer-dependencies/skills/scripts/safer_dependencies_manager.py interactive_install
```

**After install** — re-runs, updates, stats, and health checks all work via natural language to Claude (no need to remember the CLI):

| What you want | Say to Claude |
|---|---|
| Refresh / change which hooks are enabled | `install safer-dependencies` |
| Update to a newer version | re-run the bootstrap command; the installer is idempotent and preserves your `settings.json` customisations |
| See usage stats | `show safer-dependencies stats` |
| Confirm the setup is healthy | `check safer-dependencies setup` |

For manual file-by-file install (advanced users, air-gapped, or setups without `git clone` access), see [INSTALLATION.md](INSTALLATION.md) — covers global (Option B), project-level (Option C), Windows specifics, Post-Agent hooks, verification, and release pinning.

> **Platform note:** macOS, Linux, and Windows are supported. Windows needs Git for Windows (provides bash) and Python 3 on `PATH` — no WSL required.

## Versioning

Releases follow [SemVer](https://semver.org/) starting at `v0.1.0`.

| Bump | Triggers |
|---|---|
| **Major** (`v1 → v2`) | Breaking changes to hook contracts (e.g. removing a hook script or matcher), to the `settings.json` schema users are expected to ship, or to the audit-log JSON schema (field removed, renamed, or type-changed) |
| **Minor** (`v0.1 → v0.2`) | New ecosystems, new operating modes, new signal types, new `source.component` values, new optional `source` fields, new opt-in env vars |
| **Patch** (`v0.1.0 → v0.1.1`) | Bug fixes, doc fixes, internal refactors, performance work, dependency-only changes |

Pre-1.0 (current): minor versions may still introduce small breaking
changes if a clear correctness bug requires it. Each release's notes
call out any user-visible change. The full release history lives on the
[Releases page](https://github.com/robert-auger/safer-dependencies/releases).

**How to know what version you're running:** the install procedure
copies files into your skills directory but doesn't track the source
tag. To check, inspect the source clone you used:

```bash
git -C /tmp/safer-dependencies describe --tags --always 2>/dev/null
```

(Empty output or "fatal: not a git repository" means the source clone
was deleted after install — re-run the update procedure to refresh.)


## Configuration

### Auto-approve Check Commands (Optional)

By default Claude will prompt you to approve each `curl`, `npm view`, etc. To auto-approve the commands this skill uses, add these to your `.claude/settings.json`:

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

Place this file at `~/.claude/settings.json` (global) or `.claude/settings.json` (project-level).

## Warning levels

| Level | Meaning | Example |
|-------|---------|---------|
| CRITICAL | Stop and ask user | Typosquat detected, tampered signature |
| HIGH | Warn and proceed | Known CVE, package < 30 days old |
| MEDIUM | Warn and proceed | Version < 7 days old, missing signature |
| LOW | Warn and proceed | Unsigned Ruby gem (expected) |

## Audit log

Every check is logged to `~/.claude/safer-dependencies-audit-YYYY-MM.log` (one file per calendar month, where `YYYY-MM` is the UTC year-month) as a single JSON line. Override the full path with the `SAFE_DEP_AUDIT_LOG` environment variable (when set, the date suffix is not appended). Files are also size-rotated when they exceed `SAFE_DEP_LOG_MAX_BYTES` (default 10 MiB; set to `0` to disable). Set `SAFE_DEP_MODEL` to override the model value written to `source.model` in each entry — useful for A/B comparisons between model versions.

All five modes append to the same file. Each entry carries a **`source` block** (schema 2.2) identifying which component wrote it:

| `source.component` | Written by | Trigger |
|---|---|---|
| `shim.posttooluse` | `shim.sh` | Manifest or lockfile write (Intercept Mode, Post-Install dispatch) |
| `shim.install_error` | `shim.sh` | Shim preflight install failure |
| `bash.pretooluse` | `pretooluse-bash.sh` | Bash install command (Pre-Install Mode) |
| `bash.posttooluse` | `posttooluse-bash.sh` | Post-Install Bash hook itself, when it fail-opens before reaching the shim |
| `agent.pretooluse` | `pretooluse-agent.sh` | Reserved for Pre-Agent fail-open events (the hook itself is currently silent on success) |
| `agent.posttooluse` | `posttooluse-agent.sh` | Post-Agent hook fail-open events (e.g. shim missing, python_missing) |
| `manual.skill` | Claude running Normal Mode | Manual audit invoked inline |

`source.model` records the Claude Code model active in the session (e.g. `"claude-sonnet-4-6"`). Present in schema 2.1+; entries written by older installs omit the field. The stats command degrades gracefully to `"unknown"` when it is absent.

Filter by `source.component` with `jq`:

```bash
jq -r '.source.component' audit.log | sort | uniq -c | sort -rn
jq -c 'select(.source.component == "bash.pretooluse")' audit.log

# Surface every silent fail-open across all hooks:
jq -c 'select(.source.mode == "fail_open") | {component: .source.component, reason: .fail_open.reason, ts}' audit.log
```

For easier analysis, ask Claude for usage statistics instead of parsing logs manually:
```
"Show safer-dependencies stats for the last month"
```
This provides human-readable summaries of activity, security impact, and performance metrics extracted from these audit logs.

**Entry shapes (schema 2.2).** Three distinct shapes share the same `ts` / `schema` / `source` header:

| Shape | When it's written | Distinguishing fields |
|---|---|---|
| **Audit entry** | Manifest / lockfile / bash-install audit | `file`, `ecosystem`, `checked`, `findings`, `abandoned`, `stale`, `typosquat`, `unknown`, `signatures`, `notes`, `clean` |
| **Install-error entry** | Shim preflight install-error (component `shim.install_error`) | `install_error`, `shim_dir`, `scripts_dir` |
| **Fail-open entry** | Any hook entry-point exits early because of `helper_missing` / `shim_missing` / `python_missing`. `source.mode` is `"fail_open"` | `fail_open: { reason, detail? }` |

Audit entries: Intercept Mode runs the full pipeline (provenance, version age, OSV, abandoned/stale, typosquat, signatures), so all arrays can populate. Pre-Install Mode runs OSV only today, so `abandoned` / `stale` / `typosquat` / `signatures` are always empty. Post-Install dispatch (lockfile audit) writes under `shim.posttooluse` with `findings` populated by `WARNING:` strings from the lockfile auditors. The `notes` array carries informational `NOTE:` signals (e.g. manifest-skipped-because-unpinned).

Schema 2.2 added — additively — four fields to **lockfile** audit entries: `lockfile`, `manifest_ref`, `relation_summary` (a direct/transitive/unknown classification of each flagged package against the sibling manifest), and a `policy` block recording the `transitive` tier in force. The bump is backward-compatible: readers of 2.1 entries tolerate the new fields, and the `source.model` field remains present from 2.1 onward.

```json
{
  "ts": "2026-04-19T12:34:56Z",
  "schema": "2.2",
  "source": {
    "component": "shim.posttooluse",
    "script": "shim.sh",
    "hook": "PostToolUse:Write",
    "tool": "Write",
    "mode": "intercept",
    "model": "claude-sonnet-4-6"
  },
  "file": "/path/to/project/package.json",
  "ecosystem": "npm",
  "checked": ["express@4.18.2", "lodash@4.17.21"],
  "findings": ["UPDATED: express 4.18.2 → 4.22.1 (HIGH: 1 CVE fixed)"],
  "abandoned": [],
  "stale": [],
  "typosquat": [],
  "unknown": [],
  "signatures": [],
  "notes": [],
  "clean": ["lodash@4.17.21"]
}
```

Pre-Install Mode example (Bash hook, vulnerable pin denied):

```json
{
  "ts": "2026-04-23T06:56:21Z",
  "schema": "2.2",
  "source": {
    "component": "bash.pretooluse",
    "script": "pretooluse-bash.sh",
    "hook": "PreToolUse:Bash",
    "tool": "Bash",
    "mode": "intercept",
    "model": "claude-sonnet-4-6"
  },
  "file": "bash:npm install lodash@4.17.20 ms@2.1.3",
  "ecosystem": "npm",
  "checked": ["lodash@4.17.20", "ms@2.1.3"],
  "findings": [
    "BLOCKED: lodash@4.17.20 GHSA-35jh-r3h4-6jhm (CVSS:3.1/...): Command Injection in lodash"
  ],
  "abandoned": [],
  "stale": [],
  "typosquat": [],
  "unknown": [],
  "signatures": [],
  "notes": [],
  "clean": ["ms@2.1.3"]
}
```

Fail-open Mode example (Post-Install Bash hook called with no shim adjacent — broken install):

```json
{
  "ts": "2026-05-03T07:14:11Z",
  "schema": "2.2",
  "source": {
    "component": "bash.posttooluse",
    "script": "safer-dependencies-posttooluse-bash.sh",
    "hook": "PostToolUse",
    "tool": "Bash",
    "mode": "fail_open",
    "model": "claude-sonnet-4-6"
  },
  "fail_open": {
    "reason": "shim_missing",
    "detail": "/home/alice/.claude/skills/safer-dependencies"
  }
}
```

A fail-open entry says: "this hook fired but exited early without auditing because something prerequisite was missing." Use the jq filter above (`select(.source.mode == "fail_open")`) to surface every silent loss-of-protection event in your log.

When the shim runs in dry-run mode (`SAFE_DEP_DRY_RUN=1`), entries also include `"mode": "dry_run"` so post-hoc analysis can filter audit-only invocations.

## Requirements

- Python 3.9+ (the hooks probe for this and fail-open on older interpreters)
- `curl` (for registry API calls and OSV vulnerability checks)
- Ecosystem tools (optional, skill falls back to OSV API if missing):
  - `npm` for npm packages
  - `pip-audit` for Python packages
  - `bundle` for Ruby packages
  - `dependency-check` for Java packages

## Keeping safer-dependencies up to date

`/safer-dependencies update` is a hardened self-updater that fetches the latest code from GitHub over HTTPS, isolates the clone in a per-run `mkdtemp(0700)` directory, and applies the update by **copying files into place** via the already-installed manager (the freshly-cloned manager is never executed). Settings and hook configuration in `settings.json` are backed up automatically and rolled back on a failed health check.

| Command | Effect |
|---|---|
| `update` | Preview pending change (interactive sessions prompt for confirmation), then apply |
| `update --check` | Dry-run: resolve the latest ref and report what would change, no files written |
| `update --rollback` | Restore the previous bundle from the automatic pre-update backup |

Natural-language equivalent: say `"update safer-dependencies"` to Claude -- it routes to the same logic.

Every update operation is recorded in the audit log. For the full trust model (HTTPS chain, GitHub trust ceiling, tag-signing posture), see [SECURITY.md](SECURITY.md#self-update-trust-model).


## Uninstall

```bash
# Global Uninstall
rm -rf ~/.claude/skills/safer-dependencies

# Project Uninstall
rm -rf .claude/skills/safer-dependencies
```

Then remove the hook entries from your `settings.json` — otherwise Claude Code
will try to invoke the deleted scripts and log errors. Remove every entry
whose `command` references the `safer-dependencies` directory:

- `PostToolUse` matchers: `Write`, `Edit`, `Bash`
- `PreToolUse` matchers: `Bash`
- `PreToolUse` matcher `Agent` and `PostToolUse` matcher `Agent` (the Post-Agent hooks)

## FAQ

Design-decision rationale (why `PostToolUse` instead of `PreToolUse`, why signatures aren't verified, why scripts and shim are duplicated, skill-loading gotchas, etc.) is documented in [`FAQ.md`](./FAQ.md).
