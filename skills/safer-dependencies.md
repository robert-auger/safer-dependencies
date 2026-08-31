---
name: safer-dependencies
version: 0.6.1
source: https://github.com/robert-auger/safer-dependencies
description: Security audit for npm / PyPI / RubyGems / Maven / Go / Rust / PHP (Composer) package dependencies. Checks CVEs, typosquats, version age, abandonment/EOL, and hash-pin integrity; auto-corrects to a safe version. Also provides installation, configuration, stats, and validation management for safer-dependencies itself. TRIGGER BEFORE writing or editing a dependency manifest or lockfile (package.json, package-lock.json, requirements*.txt, pyproject.toml, Pipfile(.lock), poetry.lock, uv.lock, Gemfile(.lock), *.gemspec, pom.xml, build.gradle, libs.versions.toml, go.mod, go.sum, yarn.lock, pnpm-lock.yaml, Cargo.toml, Cargo.lock, composer.json, composer.lock); or on package-manager commands (`npm/yarn/pnpm/bun install|add`, `pip/pipenv install`, `uv add|sync`, `poetry add|install`, `bundle add|install|update`, `gem install`, `go get`, `cargo add|install`, `composer require|install`); or on phrases like "add/upgrade <pkg>", "pin <pkg> to <older>", "downgrade/rollback <pkg>", "replace <A> with <B>", or audit phrases ("is <pkg>@<ver> safe?", "audit my manifest"); or on library/framework SELECTION questions ("what library should I use for X?", "recommend a package for X", "which is better X or Y?", "X vs Y", "X or Y for this?" when X/Y are packages, "what's the best X library?", "what package handles X?", "compare X and Y"); or on VERSION SELECTION ("what version of X?", "which X version is stable?", "latest stable X", "what version of X should I use for a new project?"); or on INTENT-TO-USE expressions ("I want to use X", "I'm thinking of adding X", "planning to use X", "we're looking at X", "I'm going to bring in X", "let's use X" — where X is a library/framework, not an OS app); or on PACKAGE HEALTH and TRUST questions ("is X maintained?", "is X abandoned?", "is X EOL?", "can I trust X?", "when was X last updated?", "is X still actively developed?", "is this gem/package/library still maintained?", "is this gem/package still active?"); or on SCAFFOLDING commands that embed a dependency tree (npx create-*, npm create vite@latest, django-admin startproject, rails new, cargo new + cargo add, cookiecutter templates, "bootstrap a new X project", "set up a new X server from scratch"); or on IMPLICIT PACKAGE ADDS where a feature request implies installing a new library not already in the manifest ("add Redis caching", "connect to Postgres", "add JWT auth", "send emails from the app", "add a job queue") — fire if no package for that capability appears in the manifest; or on MIGRATION/PORTING ("migrate from X to Y", "move from X to Y", "port from X to Y") — fire on the incoming package; or on Dockerfile / CI workflow files (*.yml, Dockerfile) that embed pip/npm/cargo/go install commands with pinned package versions; or on MANAGEMENT requests ("install safer-dependencies", "configure safer-dependencies", "setup safer-dependencies", "safer-dependencies stats", "check safer-dependencies", "validate safer-dependencies", "update safer-dependencies", "upgrade safer-dependencies", "update my safer-dependencies", "refresh safer-dependencies"). SKIP on read-only manifest questions (no write/add planned), academic package discussion with no install intent ("how does webpack's module resolution work?", "explain React's reconciler" — NOT comparison/selection questions), formatting-only edits, non-dep fields (name/scripts/keywords), or when "install X" means an OS app/runtime/IDE extension (Python, Docker, Homebrew, VS Code extension) not a library. Elixir/Dart/Clojure are NOT audited yet — flag the gap rather than silently no-opping.
---

# Safe Dependency Checks — Alpha 1.0

## This is a rigid skill

Every layer runs on every package. Every manifest write produces an audit-log entry (Step 8). There is no "light touch" mode and no per-package judgment about whether a layer is worth running at volume. The `superpowers:using-superpowers` taxonomy classifies skills as rigid or flexible — this one is **rigid**: follow the procedure exactly, do not adapt it away.

If you find yourself thinking any of the following, stop — you are rationalizing, not reasoning:

| Thought | Reality |
|---------|---------|
| "25 packages is too many to audit each one individually" | Supply-chain attacks specifically hide in large dependency sets. Use the documented procedure on every package. Volume is not a reason to reduce checks; it is a reason to insist on them. |
| "These are all well-known packages, OSV alone is enough" | Familiar packages ship CVEs regularly (e.g. axios, vite, lodash). Familiarity is not evidence of safety — the layers exist because name-recognition is a bad heuristic. |
| "I'll skip the audit log just this once — the checks still ran" | The audit log is the only durable proof the skill ran. Unlogged runs are indistinguishable from skipped runs on review. Step 8 is not cleanup; it is the completion gate. |
| "The script path substitution is annoying, I'll eyeball a version" | Once you bypass Step 1's registry script, Layers 1c/1f (age, staleness) lose their hook and silently drop. Resolve `$SKILL_DIR` once at the top and use it consistently — do not hand-pick versions from memory. |
| "There's no intercept shim installed, so a lighter touch is fine" | Normal mode and intercept mode run the **same checks**. Absence of the shim means *more* discipline is required in the parent session, not less. |
| "The user is moving fast, I'll show them results and log later" | "Later" inside a single turn means "never." Log before reporting completion. |

Do not tell the user a dependency has been added, a manifest has been written, or a build is green until the audit log contains an entry for this run. Evidence before assertion.

## Example triggers

The frontmatter `description` above carries the canonical trigger list (loaded
on every session). For a longer-form catalog with concrete user phrasings
across **adds, upgrades, downgrades, replacements, manifest writes, audits,
selection/recommendation, intent-to-use, package-health, scaffolding,
implicit feature-driven adds, and migrations** — plus the corresponding "do
NOT fire" cases — read `references/triggers.md`.

**Two operational rules are load-bearing and stay inline:**

- **If intercept mode is configured for this project** (PostToolUse hook + shim — see the project's `.claude/settings.json`), do NOT run Normal-mode Steps 1–8 inline before the write. Write the declared version; the shim will audit and auto-correct on disk, then emit signals back. Running both duplicates every check, doubles OSV traffic, and wastes the 60 s hook budget. Normal mode is for *manual* audits ("audit my package.json" / "is X safe?"), not for pre-emptively shadowing every manifest write.

- **If the target ecosystem is not yet audited** — PHP (`composer.json`), Elixir (`mix.exs`), Dart (`pubspec.yaml`), Clojure (`deps.edn` / `project.clj`), Haskell (`cabal.project`), Crystal (`shards.yml`), and similar — the skill fires conceptually but the shim has no auditor for those manifests. Surface this gap explicitly ("safer-dependencies has no auditor for PHP yet; consider `composer audit` manually") rather than silently no-opping.

## Overview

The safer-dependencies skill provides comprehensive security auditing for package dependencies across multiple ecosystems (npm, Python, Ruby, Java, Go). It runs four layers of checks — provenance/typosquat, version age, vulnerability scanning, and hash-pin integrity (when declared) — before packages are added to manifests or lock files. It also hard-blocks packages that are abandoned or unmaintained, regardless of whether they have known CVEs.

**A note on signature verification:** Traditional package signatures (PGP/GPG on gems, npm legacy signatures, Maven `.asc` files) are intentionally NOT checked in the hook. Adoption is near-zero outside Maven Central, PGP trust roots are effectively broken at registry scale, and install tools (`go mod verify`, `cargo`, `npm ci` with lockfile) handle last-mile integrity better than a pre-write check could. The modern supply-chain integrity answer is hash pinning (supported for PyPI `requirements.txt` with `--hash=` lines, validated automatically) and provenance attestations (npm/Sigstore, PyPI PEP 740 — planned as a future enhancement).

Updates and installation: https://github.com/robert-auger/safer-dependencies

The skill operates in five modes:

1. **Normal mode** — Manual audit invoked directly by Claude when adding dependencies
2. **Intercept mode** — Automatic transparent interception triggered by manifest write hooks (`PostToolUse:Write|Edit`); signals updates back to the parent agent for code refactoring
3. **Pre-Install mode** — Automatic pre-flight audit triggered by Bash invocations of package-manager install commands (`PreToolUse:Bash`); blocks vulnerable concrete pins before fetch and writes the same audit log entries as Intercept mode
4. **Post-Install mode** — Automatic audit triggered after any Bash command (`PostToolUse:Bash`); runs two scans: (A) audits freshly-modified **lockfiles** after install commands, catching transitive CVEs that Pre-Install can't see (Pre-Install only sees the user-typed `pkg@version`, not the resolved tree); (B) audits freshly-modified **manifests** after non-read-only Bash commands, the only fallback for `sed -i` / `jq` / script edits that bypass Intercept's Write/Edit hook
5. **Post-Agent mode** — Automatic reactive audit triggered after each Agent tool call returns (`PostToolUse:Agent`); finds every manifest and lockfile the subagent wrote (using a PPID-keyed sentinel created by the paired `PreToolUse:Agent` hook) and audits them via the shim. Closes the subagent hook gap: modes 2–4 only fire for root-session tool calls; subagent writes otherwise bypass all hooks.

The five modes perform overlapping security checks but differ in trigger surface, blocking semantics, and check depth: Normal/Intercept run the full pipeline (provenance, version age, OSV, abandoned/stale, typosquat, hash-pin); Pre-Install runs OSV only against concrete `pkg@version` pins extracted from the Bash command and denies the call before the install reaches the network; Post-Install runs the shim's full audit pipeline against freshly-modified lockfiles (Scan A — after installs) and manifests (Scan B — after any non-read-only Bash command, catching `sed`/`jq`/script edits that bypass Intercept); Post-Agent runs the same lockfile + manifest scan as Post-Install but scoped to changes made during a specific subagent run.

**Transitive coverage boundary:** Intercept and Pre-Install only ever see **top-level, declared** packages — Intercept audits the manifest as written, Pre-Install audits the literal `pkg@version` typed on the command line. The resolved **transitive** dependency tree (where the majority of real-world CVEs live) is audited ONLY by Post-Install and Post-Agent. A setup with Intercept alone looks protected but has zero transitive-CVE coverage; `/safer-dependencies validate` warns about this configuration.

## Execution Contexts

In interactive sessions the skill surfaces `MAJOR-UPDATE-CONFIRM` and `BLOCKED` as text questions and waits for the developer's reply before proceeding. `STALE` is advisory — surfaced but non-blocking. In autonomous sessions (`bypassPermissions` active with no human turn between tool calls, batch instructions, or any context where text questions cannot reach a human) the orchestrator cannot wait for a reply and falls back to the deterministic autonomous-session rule defined under [On `MAJOR-UPDATE-CONFIRM:` Signal](#on-major-update-confirm-signal): default to minimum-tier YES (bump the version to fix the CVE, mark the migration as pending in the commit message) unless an earlier explicit deferral on record overrides it. There is no env var that auto-approves these signals; the rule is procedural. Full matrix in `references/execution-contexts.md`.

## Operating Modes

### Normal Mode (Manual Audit)

**There is no `safer-dependencies` CLI binary or slash command.** Normal mode is an inline procedure executed in the parent session: Claude follows Steps 1–8 below (registry query → version-resolution script → Layer 1–4 checks → write the corrected version) using its Bash and Read tools directly. The standalone Python scripts in `skills/scripts/` are pipe-helpers invoked from those Bash steps, not a unified CLI.

**When to use Normal mode** (vs. Intercept mode, which runs the shim under the PostToolUse hook):
- Manually auditing a new package before adding it to a manifest
- Checking for vulnerabilities in existing dependencies
- Verifying security posture before a major version update
- Generating a version recommendation without modifying any file on disk

**Output to surface to the developer:**
- Summary lines prefixed with `[safer-dependency-skill]`
- Clean packages: `✓ <pkg>@<version> — clean`
- Warnings: `⚠️ <SEVERITY>` with issue, detail, and action taken
- Errors: `❌` with troubleshooting hints
- Recommendations: `📦 RECOMMENDED — <pkg> <old> → <new>`

**Example workflow:**
```
User: I want to add aiohttp to requirements.txt
Claude: [follows Steps 1–8 inline]
[safer-dependency-skill] HIGH — aiohttp@3.8.5 (PyPI)
   Issue: [layer 3] 33 unmitigated CVEs in this version
   Detail: CVE-2023-32315 (HIGH), CVE-2023-30943 (MEDIUM), ...
   Action: Stepping back to 3.9.0 (clean)
[safer-dependency-skill] ✓ aiohttp@3.9.0 — clean

[Claude adds aiohttp==3.9.0 to requirements.txt]
```

**Common failure mode to avoid:** do NOT attempt to invoke a `safer-dependencies` shell command, slash command, or `--recommendation-only` / `--ecosystem` / `--lock-file-diff` flag. None of these exist. Execute the procedure inline.

### Intercept Mode (Automatic Transparent Interception)

Intercept mode fires automatically whenever Claude writes or edits a dependency
manifest. It is implemented by `safer-dependencies-shim.sh` — an executable shell
script that Claude Code's PostToolUse hook invokes after every Write/Edit.

**How it works:**
1. Claude writes a manifest file (e.g. `package.json` with `lodash@4.17.10`)
2. Claude Code fires the PostToolUse hook, piping hook JSON to the shim via stdin
3. Shim reads `tool_input.file_path`; if the basename is not a known manifest, exits silently
4. Shim reads the file from disk, parses declared packages, and checks each against OSV
5. For any package with CVEs: shim resolves the newest CVE-free version ≥ 7 days old
6. Shim rewrites the file on disk with the safe version in place
7. Shim emits an `UPDATED:` signal via `hookSpecificOutput.additionalContext` JSON on stdout
8. Claude Code delivers that JSON to the parent agent as a `system-reminder`
9. Parent agent sees the `UPDATED:` signal and performs refactoring, breaking-change review, and tests

**Design notes:**
- Shape C (post-write corrective): the file lands on disk with the user's version first,
  then is auto-corrected. No PreToolUse blocking — corrective UX is less surprising.
- Always exits 0: a non-zero hook exit surfaces as a hook error, not actionable context.
  Errors (network failures, parse failures) surface as `WARNING:` signals instead.
- Manifest filtering happens inside the shim (not via `if:` regex in settings.json),
  so the hook fires on all writes but exits in < 100 ms for non-manifest files.

**Configuration in `.claude/settings.json`:**
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
      }
    ]
  }
}
```

`${CLAUDE_PROJECT_DIR}` is set by Claude Code in the hook environment and resolves
to the project root — so this template works at any install location without editing.

**Example intercept flow:**
```
[Claude writes package.json with "lodash": "4.17.10"]
[PostToolUse:Write hook fires → shim receives hook JSON on stdin]
[Shim parses package.json, finds lodash@4.17.10, queries OSV → CVE-2019-10744]
[Shim resolves safe version: 4.17.21 (CVE-free, 1900+ days old)]
[Shim rewrites package.json: "lodash": "4.17.21"]
[Shim emits: {"hookSpecificOutput":{"additionalContext":"UPDATED: lodash 4.17.10 → 4.17.21 (HIGH: CVE-2019-10744)"}}]
[Claude Code delivers additionalContext as system-reminder to parent agent]
[Parent agent sees UPDATED signal, checks for lodash usage, runs tests]
```

### Pre-Install Mode (PreToolUse Bash Audit)

Pre-Install mode fires automatically before Claude executes a Bash tool call.
It is implemented by `safer-dependencies-pretooluse-bash.sh` — invoked by
Claude Code's `PreToolUse` hook with matcher `Bash` — and is the only mode
that can prevent a vulnerable package from being fetched in the first place.

**Why this exists in addition to Intercept mode:** Intercept mode runs
*after* a manifest write. Bash invocations of package-manager install verbs
bypass that surface entirely:

- `npm install lodash@4.17.20` runs to completion (vulnerable package fetched,
  postinstall scripts executed) before the resulting `package.json` write
  triggers the shim. By that point malicious postinstall code has already run.
- `npm install -g typosquat-pkg` writes no project manifest. Intercept mode
  never fires at all.

Pre-Install mode closes that gap structurally — the install is denied before
fetch.

**How it works:**
1. Claude attempts a Bash tool call (e.g. `npm install lodash@4.17.20`)
2. Claude Code fires the `PreToolUse:Bash` hook, piping hook JSON to the
   pretooluse-bash script via stdin
3. A pure-bash early filter short-circuits non-PM commands in ~115 ms (no
   Python invocation), so `git status` / `ls` / `npm test` pay negligible
   cost on the hot path
4. For recognized package-manager installs (npm/pnpm/yarn/bun install|i|add,
   yarn/pnpm dlx, bun x, yarn create, npx, deno add|install,
   pip/pip3/pipx/pipenv install, uv add, uvx, poetry add, gem install,
   bundle add, go get, go install, cargo add|install), the helper tokenizes
   via `shlex`, extracts each `pkg@version` argument with per-ecosystem
   syntax handling, and POSTs to OSV in parallel via `safedep.http.parallel_map`
5. Any vulnerable concrete pin → the hook returns `permissionDecision: "deny"`
   with a per-finding GHSA-id + CVSS + summary, plus a hint to invoke this
   skill for a recommended pin. The Bash call never runs.
6. Audit log entry is appended to `~/.claude/safer-dependencies-audit-YYYY-MM.log`
   (same monthly-rotated file as Intercept mode), with `file` recorded as `bash:<command>`
   (truncated to 120 chars) since there is no manifest path

**Per-ecosystem syntax recognized:**
- npm/pnpm/yarn/bun/npx/deno: `pkg@1.2.3`, `@scope/pkg@1.2.3`
- pip/pip3/pipx/pipenv/uv/uvx/poetry: `pkg==1.2.3` (extras `pkg[extra]==X` normalize to `pkg`)
- gem/bundle: version is in a separate flag (`-v VER`, `--version VER`,
  `--version=VER`)
- go: `pkg@v1.2.3` (must include `v` prefix per Go module versioning)
- cargo: `crate@1.2.3` (`cargo add`, `cargo install`)

Range pins (npm `^4.17`, pip `>=`, poetry `^`/`~`, Go `@latest`) and
unspecified versions pass through to Intercept mode after install — the
post-write shim audits whatever the resolver picks.

**Maven** is not addressed in Pre-Install mode. Maven dependencies are
typically declared in `pom.xml`/`build.gradle` (covered by Intercept mode);
the CLI download verbs `mvn dependency:get` and `mvn dependency:copy` are
the only known gap.

**Failure mode:** fail-open. Any error (Python missing, network blip,
malformed input) exits 0 with no output. Intercept mode still runs after
install, so a failed pre-flight degrades gracefully to existing
protection — never worse than Intercept mode alone.

**Example deny:**
```
[Claude attempts: npm install lodash@4.17.20]
[PreToolUse:Bash hook fires → pretooluse-bash.sh receives hook JSON on stdin]
[Hook tokenizes, extracts (lodash, 4.17.20), queries OSV in parallel]
[Hook emits: {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"safer-dependencies pre-flight audit blocked this install.\nVulnerable pinned version(s) detected:\n  - lodash@4.17.20 GHSA-35jh-r3h4-6jhm (CVSS:7.4): Command Injection in lodash\nRe-run with a patched version, or invoke the safer-dependencies skill for a recommended pin."}}]
[Bash tool call is denied; npm install never runs]
[Audit log appends entry: {"file":"bash:npm install lodash@4.17.20","ecosystem":"npm","checked":["lodash@4.17.20"],"findings":["BLOCKED: lodash@4.17.20 GHSA-..."],"clean":[]}]
[Claude reads the deny reason and decides whether to retry with a different pin]
```

**Audit-log entry-shape difference from Intercept mode:** Pre-Install
entries always have empty `abandoned`, `stale`, `typosquat`, and
`signatures` arrays because pre-flight runs only OSV (no provenance,
no abandoned/stale check, no typosquat). Filter by `file` field prefix
(`bash:` vs absolute path) to distinguish the two modes' entries.

### Post-Install Mode (PostToolUse Bash Audit)

Post-Install mode fires automatically *after* any Bash command and runs two
independent scans against the command's `cwd`:

- **Scan A — lockfile scan.** After recognized package-manager install verbs
  (`npm|pnpm|yarn|bundle|poetry|uv|go` × `install|add|ci|sync|lock|mod tidy|get|…`)
  that exited 0, finds freshly-modified lockfiles (`package-lock.json`,
  `pnpm-lock.yaml`, `yarn.lock`, `Gemfile.lock`, `poetry.lock`, `uv.lock`,
  `Pipfile.lock`, `go.sum`) and audits them via the shim. Closes the
  transitive-CVE gap Pre-Install can't see — Pre-Install only knows the
  user-typed `pkg@version`, not the resolved dependency tree.
- **Scan B — manifest scan.** After any Bash command not on a read-only
  denylist (`ls`, `cat`, `git status`, etc.), finds freshly-modified manifest
  files (`package.json`, `pyproject.toml`, `Cargo.toml`, `Gemfile`, `pom.xml`,
  `build.gradle`, `go.mod`, etc.) and audits them via the shim. Closes the
  Bash-edit gap: when Claude edits a manifest via `sed -i`, a Python script,
  `jq`, or any other Bash invocation, the PostToolUse:Write hook (Intercept)
  never fires. Scan B is the only path that catches those writes.

Both scans use a 60-second mtime sentinel (override with
`SAFE_DEP_POSTINSTALL_MTIME_WINDOW`) and `maxdepth 5` to cover monorepos.
Path exclusions (`node_modules`, `.git`, `.venv`, `venv`) prevent vendored
files from being re-audited.

Implemented by `safer-dependencies-posttooluse-bash.sh`. Each freshly-found
file is dispatched to the existing shim via a forged PostToolUse:Write
payload — same audit pipeline (CVE/STALE/TYPOSQUAT) as Intercept mode, no
duplicated logic. Per-file signals are concatenated and emitted as one
`hookSpecificOutput`.

Installation mirrors the other hooks — see the script header for the
`settings.json` snippet. Safe to install alongside Pre-Install; the two
modes complement each other. With Scan B in place this hook is the only
fallback for Bash-driven manifest edits, so the interactive installer
defaults it to ON.

Coverage gaps (design, not bugs):

- Installs that run outside Claude's `Bash` tool (manual shell, IDE
  integrations, CI) aren't seen by this hook. Closing that requires a
  session-start filesystem sweep, which is outside the current hook surface.
- Package managers that stream lockfile updates mid-run (none of the
  mainstream ones do). Failed installs (exit code != 0) skip Scan A
  because partial lockfiles would produce misleading signals; Scan B still
  runs since a crashed `sed -i` can leave a partial manifest worth auditing.

### Post-Agent Mode (PostToolUse:Agent Audit)

Post-Agent mode closes the subagent hook gap. Modes 2–4 only fire for
root-session tool calls — a subagent's Write/Edit/Bash calls bypass all
three hooks entirely. Post-Agent audits whatever the subagent wrote after
the Agent call returns, surfacing any findings to the root session's next turn.

**How it works — sentinel-file approach:**

A `PreToolUse:Agent` hook (`safer-dependencies-pretooluse-agent.sh`) runs
immediately before each Agent dispatch and touches:

```
/tmp/.safer-deps-agent-<PPID>-<session_id>.sentinel
```

(falling back to `/tmp/.safer-deps-agent-<PPID>.sentinel` when no session id
is available in the hook payload).

The `PostToolUse:Agent` hook (`safer-dependencies-posttooluse-agent.sh`)
runs after the Agent call returns. It:

1. Locates the sentinel (keyed on PPID plus a 12-char session-id suffix —
   stable for the session, unique across concurrent Claude Code instances)
2. `find`s every manifest and lockfile in `cwd` newer than the sentinel
   (maxdepth 5 for manifests, maxdepth 2 for lockfiles) — works whether
   the subagent committed or not, and naturally covers nested agents (agent A
   dispatching agent B) because the root's PostToolUse fires only after all
   of A's work is on disk
3. For each file found, forges a PostToolUse:Write payload and pipes it to
   the existing shim — same signal types, same audit logic, no duplication
4. Emits combined signals as `additionalContext` so the root session sees
   them in its next turn
5. Removes the sentinel

**Relationship to the HARD GATE (pre-dispatch):**

Post-Agent mode is a **reactive safety net**, not a replacement for the
pre-dispatch Normal-mode check. The HARD GATE (`Pre-dispatch requirement for
orchestrators` section above) prevents the subagent from starting with a
vulnerable manifest; Post-Agent catches new additions the subagent made.
Both are needed for full coverage.

**Installation:**

Add both hooks to `~/.claude/settings.json` (merge with existing hooks block):

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

**Coverage:**

| Subagent action | Covered by Post-Agent? |
|-----------------|----------------------|
| Writes `package.json` | ✅ manifest scan |
| Writes `requirements.txt` | ✅ manifest scan |
| Writes `Gemfile` | ✅ manifest scan |
| Runs `npm install` (lockfile updated) | ✅ lockfile scan |
| Runs `bundle install` (lockfile updated) | ✅ lockfile scan |
| Nested subagent writes manifest | ✅ covered when outer agent returns |
| Global `npm install -g` (no manifest/lockfile written) | ❌ no file written to scan |

**Fail-open:** any error (missing sentinel, missing shim, unreadable payload,
find returning empty) exits 0 silently — a broken hook never blocks the root session.

## Signal Format

Intercept mode communicates package updates to the parent agent through UPDATED signals. These signals allow Claude to identify affected code and perform necessary refactoring when security updates change API surfaces.

**Signal syntax:**
```
UPDATED: <package_name> <old_version> → <new_version> (<reason>)
```

**Fields:**
- `package_name` — Name of the package as it appears in the manifest
- `old_version` — Version that was requested (may be vulnerable or deprecated)
- `new_version` — Safe version selected by security checks
- `reason` — Brief explanation of why the update was necessary

**Reason codes:**
- `CVE-XXXX: N CVEs fixed` — Vulnerable version; N CVEs were found and fixed in new version
- `CRITICAL: N CVEs fixed` — Multiple critical vulnerabilities addressed
- `HIGH: N CVEs fixed` — High-severity vulnerabilities fixed
- `version age security` — Old version below 7-day cooldown threshold, newer stable available
- `typosquat resolved` — Package name was corrected from typosquat
- `registry verified` — Source was verified after integrity concern

**Signal examples:**
```
UPDATED: aiohttp 3.8.5 → 3.9.0 (HIGH: 33 CVEs fixed)
UPDATED: cryptography 41.0.0 → 46.0.6 (CRITICAL: 10 CVEs fixed)
UPDATED: marshmallow 3.20.0 → 3.26.2 (version age security)
UPDATED: requests 2.28.0 → 2.31.0 (HIGH: CVE-2023-32315 fixed)
UPDATED: django 3.2.0 → 3.2.20 (HIGH: 5 CVEs fixed)
UPDATED: lodash 4.17.15 → 4.17.21 (CRITICAL: 6 CVEs fixed)
```

**Fresh-version exception (OSV-verified):** `UPDATED:` may be emitted even when the new version is less than 7 days old, *if and only if* OSV's advisory for a CVE present in the current pinned version lists that new version as the `fixed` version. The 7-day community-vetting gate is deliberately bypassed in this case because the evidence source (OSV's structured `fixed` field) is the same authoritative source the shim already trusts for CVE detection — no new trust boundary is introduced. Release-notes claims, changelog keywords, and advisory summaries mentioning a CVE are **not** accepted, because those strings are forgeable by a compromised publisher account. When the only candidate fix is fresh and OSV has not yet ingested the fix-range advisory, the shim emits `BLOCKED:` (entry removed) as today — preferring a false negative over applying potentially-forged content. See `FAQ.md` for the full rationale.

**`MAJOR-UPDATE-CONFIRM: <pkg> <old> has <cve-ids> — safe version requires major bump to <new>`**
Emitted when the safe version crosses a major version boundary upward (e.g. fastify 4.x → 5.x). No clean same-major version exists. **The shim does NOT rewrite the manifest** — it presents the developer with a choice. For known packages the signal includes a `MIGRATION NOTES:` block with specific breaking changes and a link to the official guide. The signal ends with an `ACTION REQUIRED` block asking the parent agent to confirm with the developer.

When the developer says **YES**: the parent agent updates the manifest to the suggested version. The shim will re-fire on the next write and confirm the new version is clean.

When the developer says **NO**: the parent agent writes the package and version to the session-scoped skip file at `~/.claude/sd-skipped-{SESSION_ID}.json` (a JSON dict of `{pkg: version}`). The shim reads this file and suppresses re-prompts for declined packages for the remainder of the session. A new session starts clean and will prompt again if the vulnerable version is still present.

When migration notes are present, the parent agent MUST include them in the prompt of every implementer subagent that touches files importing the updated package. When no migration notes are present, the parent agent should check the package changelog before dispatching implementers.

**`BLOCKED: <pkg> <version> has <cve-ids> — entry removed`**
Emitted when every known version of a package has CVEs and no safe version can be found. The shim removes the entry from the manifest on disk.

**`BLOCKED: <pkg> — abandoned: <reason>`**
Emitted when a package is in the known-abandoned list (e.g. `paperclip`, `request`, `github.com/dgrijalva/jwt-go`). The entry is removed from the manifest on disk. The reason field includes a suggested replacement where one exists.

**`STALE: <pkg> — last release <date>, no updates in 2+ years`**
Emitted when the newest stable version of a package has not been published in over two years. The entry is **not** removed from the manifest — this is an advisory signal only. The parent agent should surface this to the developer and ask whether to find an alternative, but may continue working if the developer accepts the risk.

For `BLOCKED:` signals (CVE with no safe version, or abandoned): the parent agent must ask the developer how to proceed (find an alternative, pin a known-acceptable version with an explicit risk acknowledgement, or remove the feature that requires the package). Do not write any code that imports the blocked package until the developer has decided.

For `STALE:` signals: surface the finding to the developer and ask if they want to replace the dependency. Unlike `BLOCKED:`, the manifest is not modified — the developer makes the call. Implementation may continue if the developer accepts the risk.

**`SIGNATURE: <pkg>@<version> — unsigned (<SEVERITY>: <reason>)`**
Emitted at Layer 4 when the shim can confirm that the artifact is **not** signed. Signed artifacts pass silently (they're the expected baseline).

- **Maven (MEDIUM):** Maven Central returned 404 for the detached GPG `.asc` file at `repo1.maven.org/maven2/<groupPath>/<artifactId>/<version>/<artifactId>-<version>.jar.asc`. Uncommon — most published Maven Central artifacts are GPG-signed and Maven Central validates at upload.
- **RubyGems (LOW):** the `.gem` archive for this version contains no `.sig` entries. Informational — most gems are unsigned; the signal surfaces for completeness but does not gate the dependency.

Lookup failures (network error, 5xx, timeout) fail open and emit nothing — the parent agent should treat absence-of-SIGNATURE-signal as "check was inconclusive or the package is signed", not as proof of signing. Implemented by `safedep.signatures.maven_has_signature()` and `safedep.signatures.rubygems_has_signature()`, both shared with the manual-mode skill so findings are identical on the same input.

(npm provenance attestations are tracked separately and will land in a follow-on PR. PyPI uses `--hash=sha256:` pinning at Layer 4 — see the PyPI section below.)

**`UNKNOWN: <pkg>@<version> — not found in <ecosystem> registry (possible typo or fabricated name)`**
Emitted when the canonical registry returns HTTP 404 for this package. Closes a silent-bypass vector: a fabricated or mistyped package name (e.g. ``node-notifier-alt`` in npm, ``reqeusts`` in PyPI) would otherwise pass every check, since OSV has no CVEs for nonexistent packages, the version listers return empty, and the staleness check has no data. The shim does NOT modify the manifest — the parent agent pauses and asks the developer whether the name is intentional (a private / internal package) or a mistake to correct. Ecosystems: npm, PyPI, RubyGems, Maven, Go. Implemented by `safedep.existence.package_exists()`; the check fails open on network errors so transient registry outages do not produce false UNKNOWN findings.

**`TYPOSQUAT-CONFIRM: <pkg>@<version> may be a typosquat of '<ref>' (edit distance N) — verify intentional before proceeding`**
Emitted when the package name is within 1–2 edits of a well-known package in the same ecosystem (e.g. `rubycop` vs `rubocop`, `reqeusts` vs `requests`). The shim does NOT remove the package — the parent agent pauses and confirms with the developer before proceeding. Ecosystems covered: npm, PyPI, RubyGems, Maven, crates.io. For deeper investigation, the standalone `check_typosquat.py` script remains available for manual invocation against any package name (it accepts `--ecosystem crates` for Rust).

A **popularity guard** runs before the signal is emitted: if the candidate package itself has meaningful adoption in its ecosystem (weekly downloads at or above the per-ecosystem threshold in `safedep.popularity.POPULARITY_THRESHOLD`), the finding is suppressed. This prevents false positives on legitimate packages whose names happen to share edit distance with well-known packages — e.g. `pyarrow` (~20M weekly PyPI downloads) no longer gets flagged as a typosquat of `arrow`. A real typosquat attack would not accumulate that kind of adoption before being flagged and removed.

The guard fails open: if the download lookup fails (network error, 404, or an ecosystem with no canonical download source such as Maven or Go), the raw typosquat finding is emitted unchanged.

For offline invocation or deterministic unit testing, the CLI accepts `--no-popularity-guard` to bypass the suppression: `python3 <skill-directory>/scripts/check_typosquat.py <pkg> --ecosystem <eco> --no-popularity-guard`.

**`VERIFY: run \`<install-command>\` then run \`<test-command>\` / review imports`**
Appended once per manifest write whenever any corrections were made (UPDATED or BLOCKED removals). `STALE:` signals do not produce a `VERIFY:` entry because stale packages are not removed from the manifest. The VERIFY signal is adaptive based on project context:

- **Tier 1 (tests detected):** `VERIFY: run \`<install>\` then run \`<test>\`` — when test directories (`test/`, `tests/`, `__tests__/`, `spec/`) or test scripts (package.json `test`, pyproject.toml pytest config) are found near the manifest.
- **Tier 2 (no tests + major update):** `VERIFY: run \`<install>\` then audit all files importing <pkg> for breaking patterns` — includes migration notes as a checklist.
- **Tier 3 (no tests + same-major):** `VERIFY: run \`<install>\` then review all files importing <pkg> to confirm API compatibility` — general import review.

The install command is package-manager-aware: `yarn.lock` → `yarn install`, `pnpm-lock.yaml` → `pnpm install`, `poetry.lock` → `poetry install`, `uv.lock` → `uv sync`, etc. The parent agent MUST run the stated install command and confirm exit code 0 before reporting the manifest as fixed.

**`CLEAN: N packages checked — no known vulnerabilities (pkg@ver, pkg@ver, ...) — security audit only, not a compatibility check`**
Emitted when a manifest is scanned and all packages are clean. This confirms the shim ran and checked every package — distinguishing "checked and clean" from "not checked." The parent agent can report this to the developer as confirmation of coverage. No action is required. The claim is scoped to *security* findings: a CLEAN package can still be incompatible with the project's runtime or other dependencies. For plain-pip `requirements*.txt` files the CLEAN line may be followed by honest-coverage `NOTE:` lines (transitive dependencies not audited without a lockfile; missing `--hash` integrity pins) — these are advisories, not findings.

**`LOOKUP-FAILED: vulnerability lookup failed for N package(s) [pkg@ver, ...]. First error: <detail>. CVE status unknown; these entries were NOT auto-corrected. Retry after rate-limit/connectivity recovers.`**
Emitted when the OSV vulnerability API could not be reached (HTTP 429 rate-limit, 5xx server error, network timeout, or malformed response) for one or more packages. **This is not the same as `CLEAN:`** — the listed packages have NOT been verified. The shim deliberately did not rewrite those entries because doing so on unverified data could mask a real CVE. Parent agent should surface this to the developer, suggest retrying (e.g. re-save the manifest) once connectivity is restored, and NOT treat the listed packages as audited.

**`NOTE: <basename> recognised as <ecosystem> manifest but no pinned dependencies found — audit skipped. Pin versions (<example>) so CVE/typosquat/staleness checks apply.`**
Informational — emitted when the shim recognises the file as a manifest for a supported ecosystem (e.g. `requirements.txt`, `Gemfile`) but the parser finds no pinned `pkg==version` / `gem 'name', '1.2.3'` entries. The audit was skipped because there are no versions to check against OSV. **This is not a finding** and does not go in the `findings` array of the audit log — it lands in a dedicated `notes` array. The parent agent should treat it as a hint: either pin versions so future writes get audited, or continue knowing the manifest is declaratively loose (e.g. a library author using `>=` / `~>` constraints on purpose). No action is strictly required. `NOTE:` signals never block writes and never cause rewrites.

**Other signals the shim emits (one-liners):**

- **`REFACTOR-REQUIRED: <pkg> <old> → <new> is a MAJOR version ...`** — emitted alongside `MAJOR-UPDATE-CONFIRM:`; the parent agent MUST complete the embedded refactor procedure before continuing.
- **`REGRESSION: ...`** — prepended to a `MAJOR-UPDATE-CONFIRM:` when the audit log shows the same `(file, package)` was previously corrected to the same safe target; restore the previously-approved version.
- **`PEER-COMPAT-NOTE: <pkg> is being major-bumped to <new> ...`** — advisory that other packages in the manifest may have peer/compatibility constraints on the bumped package.
- **`STALE-LOCKFILE: <lockfile> predates the last manifest write ...`** — the lockfile is missing or older than the corrected manifest; re-run the install so the lockfile matches.
- **`OPEN-CVE: <pkg>@<ver> was flagged on <date> ...`** — re-surfaces a previously-flagged, still-unresolved CVE from the audit log so it isn't forgotten across turns.
- **`GAP: <ecosystem> not yet audited by safer-dependencies ...`** — the manifest belongs to an unsupported ecosystem (PHP, Elixir, Dart, ...); run the named native auditor manually.
- **`UNAUDITED: could not read <file> (<error>) — audit skipped`** — the shim could not read the manifest; the file was NOT audited and must not be treated as clean.

The shim also writes a persistent audit log to `~/.claude/safer-dependencies-audit-YYYY-MM.log` (JSONL format, one file per calendar month) on every manifest invocation, whether clean or not. Each entry records the timestamp, file path, ecosystem, packages checked, findings, and clean packages.

**Parent agent responsibilities when receiving signals:**

For `UPDATED:` signals — follow the steps below after receiving the signal.

For `MAJOR-UPDATE-CONFIRM:` and `BLOCKED:` signals — the import site scan MUST be completed and the results included in implementer subagent prompts BEFORE any implementation begins. These signals indicate breaking changes or package removal. Subagents started without the affected file list will write code against the wrong assumptions. See the dedicated sections below.

For `STALE:` signals — group all STALE findings from the manifest into a single developer prompt rather than asking per-package. Use this format:

```
⚠️  Stale dependency advisory (N package(s)):
  • <pkg>@<ver> — last release <date>, no updates in X years
  • ...

Options:
  A) Accept all risks and continue (package still works; you own the tradeoff)
  B) Replace specific packages — tell me which ones
  C) Replace all stale packages — I'll find active alternatives

Which approach? (A/B/C)
```

Wait for an explicit response. Do not proceed with implementation until the developer replies. Once the developer accepts (A) or specifies replacements (B/C), record the decision and continue.

**On `UPDATED:` signals (same-major, non-breaking):**
1. **Identify affected code** — Find all files that import or use the updated package
2. **Check API compatibility** — Review release notes for breaking changes between old and new versions
3. **Refactor if needed** — Update code to use new APIs if the version bump introduces breaking changes
4. **Test thoroughly** — Run unit tests and integration tests to verify compatibility
5. **Commit with notes** — Create a commit explaining the security update and any refactoring changes

Example parent agent response:
```
Detected UPDATED signal: aiohttp 3.8.5 → 3.9.0
Scanning for imports... Found in: app.py, services/http_client.py
Checking release notes for breaking changes...
- ClientSession.get() API unchanged ✓
- Timeout handling improved (backward compatible) ✓
- New context manager protocol added (optional upgrade) ℹ️
All existing code remains compatible.
Updating requirements.txt and running tests...
Tests pass. Committing security update.
```

## Configuration

All check steps (Steps 1–8) run directly in the current session. Do not delegate to
subagents — they cannot run Bash or curl due to sandbox restrictions.

## Subagent Orchestration

**PostToolUse hooks fire only for the root session.** Subagent Write/Edit calls do NOT
trigger the PostToolUse hook — a subagent writing a manifest bypasses the dependency
security shim entirely. Any packages written into a manifest by a subagent are unchecked
unless the orchestrator takes explicit action before dispatch.

### Pre-dispatch requirement for orchestrators

Before dispatching any subagent that may write to a manifest file (`package.json`,
`requirements.txt`, `Gemfile`, `pom.xml`, `build.gradle`, etc.), run this skill's
Normal-mode Steps 1–8 in the current (root) session for that manifest. Because the
PostToolUse hook will not fire for the subagent's Write/Edit call, the pre-dispatch
Normal-mode check is the only mechanism that guarantees security coverage for subagent
manifest writes.

> **HARD GATE:** Complete Normal-mode Steps 1–8 for the target manifest BEFORE dispatching
> any implementer subagent that will write to it. Proceed only after Step 8 (audit log
> entry) is written and all signals are resolved.

### If you are the orchestrator dispatching subagents

When dispatching any subagent that may write to a manifest file (`package.json`,
`requirements.txt`, `Gemfile`, `pom.xml`, `build.gradle`, etc.), include the following
block **verbatim** in the subagent's prompt:

---
> **Dependency security signals:** If any Write or Edit tool result contains a
> `system-reminder` or additional context with one of the lines below, handle it
> immediately before continuing:
>
> `UPDATED: <pkg> <old> → <new> (<reason>)` — A security hook corrected a vulnerable
> version on disk. Find all files importing `<pkg>`, check for breaking API changes
> between `<old>` and `<new>`, refactor if needed, run tests, and include
> `security: <pkg> <old> → <new>` in your commit message.
>
> `MAJOR-UPDATE-CONFIRM: ...` — A major version bump requires developer approval. The
> manifest was NOT rewritten. **Stop all work** and surface this signal verbatim in your
> output so the orchestrator can relay it to the developer.
>
> `BLOCKED: <pkg> <version> ... — entry removed` — No safe version exists; the entry was
> removed from the manifest. **Stop all work** and surface this signal verbatim. Do not
> write any code that imports `<pkg>`.
>
> `VERIFY: run \`<install>\` then run \`<test>\`` — Run both commands and report exit
> codes and any failures in your output.
>
> `CLEAN: N packages checked — no known vulnerabilities` — No action needed.
>
> **Pre-flight Bash deny:** If a `Bash` tool call is denied with a
> `permissionDecisionReason` starting with `safer-dependencies pre-flight
> audit blocked this install.`, the install never ran. The reason lists
> each `<pkg>@<version> → <GHSA-id> (<CVSS>): <summary>`. Pick a patched
> version (or invoke this skill via Steps 1–8 to resolve a safe pin) and
> reissue the command — do not silently abandon the install.

---

### If you are a subagent and received a signal

Because Bash may not be available in the subagent sandbox, you cannot run the full
safer-dependencies checks yourself. Handle each signal as follows:

| Signal | What you can do | What to escalate |
|--------|----------------|-----------------|
| `UPDATED:` | Use Glob/Grep/Read to find import sites; use Edit/Write to refactor. If Bash is available, run the VERIFY install + test commands. | If Bash is unavailable, include the VERIFY step in your output for the orchestrator to complete. |
| `MAJOR-UPDATE-CONFIRM:` | Nothing — stop work on the affected package. | Surface the full signal verbatim in your output. The orchestrator must present it to the developer before proceeding. |
| `BLOCKED:` (CVE or abandoned) | Nothing — stop work on the affected package. | Surface the full signal verbatim in your output. The orchestrator must decide on a replacement. |
| `STALE:` (no CVEs, no updates 2+ years) | Continue only if the developer accepts the risk. | Surface the signal verbatim. The orchestrator asks the developer whether to replace. |
| `VERIFY:` | Run install + test if Bash is available. | If Bash is unavailable, include the exact VERIFY instruction in your output. |
| `TYPOSQUAT-CONFIRM:` | Pause — confirm with developer that the package name is intentional before writing any import. | Surface the signal verbatim if the developer is not available. |
| `UNKNOWN:` | Pause — the registry could not find this package. Ask the developer whether it is a private/internal package (pass-through acceptable) or a fabricated/mistyped name (abort the dependency addition). | Surface the signal verbatim if the developer is not available. |
| `SIGNATURE:` (MEDIUM Maven) | Note the absence of the GPG `.asc` — unusual for a Maven Central artifact. Ask the developer whether this is an acceptable source. | Surface the signal verbatim; not a hard block. |
| `SIGNATURE:` (LOW RubyGems) | Informational — most gems are unsigned. Proceed. | Include in the audit log; no action needed. |
| `CLEAN:` | No action. Optionally note it in your output as confirmation. | Nothing to escalate. |

**Never silently discard a signal.** If you cannot act on it yourself, surface it in your
output so the orchestrator can.

## Parent Agent Response Expectations

When the parent agent (Claude) receives `UPDATED:` signals from intercept mode, it should follow this protocol to ensure code compatibility and security:

### 1. Parse the Signal

Extract these components from each `UPDATED:` line:
- Package name
- Old version
- New version
- Reason (severity and type of update)

### 2. Identify Affected Code

Search the codebase for:
- Direct imports: `import <package>`, `require('<package>')`, `from <package> import ...`, `use <package>`
- Package usage in code that calls its APIs
- Configuration files that reference the package
- Comments or documentation that mention version-specific behavior

### 3. Check for Breaking Changes

For each file that uses the updated package:
- Review the package's release notes between old and new versions
- Check GitHub issues/discussions for breaking changes
- Review the package's migration guide (if available)
- Look for deprecated API warnings in the new version's documentation

**Breaking change indicators:**
- Function/method signature changes
- Return type changes
- Required new parameters
- Removed methods or classes
- Different exception types
- Configuration schema changes
- Behavior changes in error handling

### 4. Refactor Code If Needed

**If no breaking changes detected:**
- No code changes needed
- Dependencies are already compatible
- Proceed to testing

**If breaking changes detected:**
- Update API calls to use new signatures
- Add/remove parameters as needed
- Handle new exception types
- Update configuration if schemas changed
- Test each change incrementally

**Before refactoring, read `references/refactoring-examples.md`** for the
concrete patterns (method-signature change, removed feature). Then check
the package's official migration guide for the specific version pair —
the reference file's two scenarios are templates, not exhaustive coverage,
so for any package not shown there you must consult the package's own
release notes for the breaking-change list.

### 5. Run Tests

Execute the full test suite:
```bash
# Python
pytest
python -m unittest discover

# Node.js
npm test
yarn test

# Ruby
rspec
bundle exec rake test

# Java
mvn test
gradle test
```

**Test coverage requirements:**
- Unit tests for each affected module
- Integration tests for cross-package interactions
- End-to-end tests if package affects user-facing features
- Security tests (verify vulnerability is actually fixed)

### 6. Commit with Detailed Notes

When committing the security update and any refactoring:

**Commit message format:**
```
security: update <package> from <old> to <new>

<reason for update>

Changes:
- Updated <package> version due to <CVE/age/other>
- <Any refactoring done>: <brief description>
- <Any API compatibility notes>

Test results:
- All existing tests pass
- <Any new tests added>

Affected modules:
- <file1>: <what changed>
- <file2>: <what changed>

Co-Authored-By: safer-dependencies skill
```

**Example commit:**
```
security: update aiohttp from 3.8.5 to 3.9.0

CVE-2023-32315 and 32 other CVEs fixed in aiohttp 3.9.0.
No breaking changes to API used by our code.

Changes:
- Updated requirements.txt: aiohttp 3.8.5 → 3.9.0
- Verified ClientSession API compatibility
- All timeout handling code still works

Test results:
- tests/test_http_client.py: PASS (12 tests)
- tests/integration/test_api_calls.py: PASS (8 tests)
- Full test suite: PASS (124 tests)

Affected modules:
- services/http_client.py: No changes needed, API compatible
- app.py: No changes needed, basic usage unaffected

Co-Authored-By: safer-dependencies skill
```

### On `MAJOR-UPDATE-CONFIRM:` Signal

When the shim emits `MAJOR-UPDATE-CONFIRM:` (safe version crosses a major version boundary upward), the manifest has NOT been rewritten. The developer must approve the upgrade:

> HARD GATE: Complete steps 1-3 before dispatching ANY implementer subagent.
> Dispatching implementers before the affected file list is known guarantees reactive
> failures. The scan takes seconds. The fix loops it prevents take hours.

1. Present the full signal to the developer, including migration notes and CVE details
2. Ask the developer: proceed with the major version upgrade, or leave as-is?
3. **If YES — scan BEFORE implementing:**

   **Step 3a — Scan for all import sites (MANDATORY BEFORE ANY SUBAGENT DISPATCH)**

   Search all source files in the project for imports of the updated package:

   ```bash
   # npm example
   grep -r --include="*.js" --include="*.ts" --include="*.mjs" \
     -l "require('fastify')\|require(\"fastify\")\|from 'fastify'\|from \"fastify\"" .

   # Python example
   grep -r --include="*.py" -l "import django\|from django" .

   # Ruby example
   grep -r --include="*.rb" -l "require 'nokogiri'\|require \"nokogiri\"" .
   ```

   Record the full list of affected files. This list MUST be included in the prompt of
   every implementer subagent that will touch those files.

   **Step 3b — Check migration guide**

   If the signal includes `MIGRATION NOTES:`, use those notes directly. If no notes are present, find the package's official migration/upgrade guide manually. Record any breaking changes. These MUST also be included in every implementer subagent prompt.

   **Step 3c — Update the manifest** to the suggested version.

   **Step 3d — Dispatch implementers with full context**

   Each implementer subagent prompt must include:
   - The affected file list from Step 3a
   - The breaking changes from Step 3b
   - The new version being used

   **Step 3e — Refactor, verify, report**

   After all implementers complete: run VERIFY install/test command, run test suite, report results.

4. **If NO:**
   - Write the declined package and version to the skip file: `~/.claude/sd-skipped-{SESSION_ID}.json`
   - Communicate explicitly: the CVEs remain unresolved, and the shim will not re-prompt for this package in this session
   - A new session will prompt again if the vulnerable version is still present

   **What NO means for the code:** The package stays at the vulnerable version exactly as written. The orchestrator does NOT write any code to accommodate a new API, does NOT update any imports, and does NOT make any other code changes. The developer has explicitly acknowledged the CVE and accepted the risk for this session. Record this decision with the CVE IDs in a comment if the developer requests it.

   **Silent deferral is not a valid NO.** Taking no action and committing — without writing the skip file and without naming the CVE in the commit message — leaves the CVE unresolved with no audit trail. The shim will re-prompt on every subsequent scan, and the regression will not be visible to reviewers reading the commit history. Either choose YES (apply the upgrade) or write the skip-file artifact for NO.

#### Autonomous-session rule (when no developer turn is coming)

An **autonomous** session is one where the orchestrator is executing a multi-step task without waiting for human confirmation between tool calls — batch instructions ("build all projects and commit"), `bypassPermissions` active with no expected human turn before the next tool call, or any other context where text questions cannot reach a human. In that mode the standard "ask the developer" protocol above collapses: there is no one to answer, and the agent reading its own `additionalContext` cannot wait for a reply that isn't coming.

In autonomous sessions apply this deterministic rule INSTEAD of step 2 above:

1. **Default to implicit YES (minimum tier).** Apply step 3c — update the manifest to the safe version — immediately. This fixes the CVE in seconds. Skip steps 3a, 3b, 3d, 3e for now; they form the "full migration tier" below.

2. **Include the CVE ID in your commit message.** Use the format: `security: <pkg> <old> → <new> (<GHSA-id>) — full migration pending`. This creates the audit trail reviewers need.

3. **Note that the migration is pending.** The manifest is at the safe version, but the codebase may still import the old API. Surface this in the response so it is not silently lost: "Bumped <pkg> to fix <CVE>. Import-site refactor (steps 3a, 3b, 3d, 3e) is required before production deploy."

4. **Honor explicit deferral if it was recorded earlier in the conversation.** If the developer said "don't update <pkg>" or "skip CVEs for now" upstream of this signal, treat that as explicit NO, write the skip-file entry per step 4 of the standard flow, and add `CVE-DEFERRED: <GHSA-id>` to the commit message. Do not bump the version.

The minimum tier (manifest bump) is mandatory in autonomous mode. The full migration tier is preferred but may legitimately be a follow-up commit — what is NOT acceptable is committing a vulnerable version with no audit trail of the decision.

> **Full migration tier (steps 3a, 3b, 3d, 3e):** scan import sites, check the migration guide, dispatch implementer subagents with the affected file list, refactor and verify. In an interactive session these run in the same change as the version bump; in an autonomous session they may run after, but they MUST run before the code reaches a production deploy. The pending migration is recorded in the commit message and surfaced to the user, not silently dropped.

### On `BLOCKED:` Signal

When the shim emits `BLOCKED:` (no safe version exists, entry removed from manifest):

> HARD GATE: Scan for import sites before dispatching any implementer subagent.

**Step 1 — Scan for all import sites (MANDATORY BEFORE ANY SUBAGENT DISPATCH)**

The shim has removed the package from the manifest. Find every file that still imports it — those files will break at runtime if not updated.

```bash
# npm example — axios blocked
grep -r --include="*.js" --include="*.ts" -l \
  "require('axios')\|require(\"axios\")\|from 'axios'\|from \"axios\"" .
```

Record the full list. Include it in every implementer subagent prompt along with:
- What package was blocked and why (CVE IDs)
- What replacement approach to use (native fetch, alternative library, etc.)

**Step 2 — Decide on replacement approach**

Ask the developer (or decide based on context) how to replace the blocked package:
- Native alternative (e.g. `axios` → Node.js native `fetch`)
- Alternative library (e.g. `mjml` → raw HTML templates)
- Remove the feature entirely

**Step 3 — Dispatch implementers with full context**

Each implementer subagent prompt must include the affected file list and replacement approach.

### On `VERIFY:` Signal

When the shim emits a `VERIFY:` signal, follow its instructions exactly:

- **Tier 1 (includes test command):** Run the install command, then run the test command. Classify the result using the table below.
- **Tier 2 (includes breaking patterns):** Run the install command, then audit all files importing the package for the listed breaking patterns. Confirm no breaking patterns remain.
- **Tier 3 (includes import review):** Run the install command, then review all files importing the package to confirm API usage is compatible with the new version.

If the install command fails, surface the full error output and ask the developer how to proceed — do not silently ignore install errors.

**Tier 1 test failure classification:**

When tests exit non-zero, inspect the output to classify the failure before deciding how to proceed:

| Failure type | Examples | Classification | Action |
|---|---|---|---|
| **Compatibility failure** | `ImportError`, `ModuleNotFoundError`, `AttributeError`, `TypeError` in files that import the updated package | **Blocking** | Do not mark VERIFY complete. Report to developer: the version bump broke API compatibility. |
| **Infrastructure failure** | `Connection refused`, `ECONNREFUSED`, `OperationalError: could not connect`, `REDIS_URL not set`, `docker: command not found` | **Non-blocking** | Note that tests require infrastructure not available in this environment. Advise developer to run tests locally. Mark VERIFY complete with caveat. |
| **Unrelated pre-existing failure** | Test failures in files that do not import the updated package, failures that also appeared before this correction | **Non-blocking** | Note as pre-existing. Mark VERIFY complete for the dependency update specifically. |
| **Unclear** | Output does not clearly match any category above | Ask developer to classify before marking complete. |

**Three-step VERIFY protocol (Tier 1):**

1. Run the install command (e.g. `pip install -r requirements.txt`)
   - If non-zero exit: surface the full error and ask the developer. Stop.
2. Run the test command (e.g. `pytest`)
   - If exit 0: VERIFY complete.
   - If non-zero exit: go to step 3.
3. Scan test output for failure type:
   - `ImportError` / `ModuleNotFoundError` / `AttributeError` / `TypeError` in package import files → **blocking compatibility failure**. Report and stop.
   - `Connection refused` / `ECONNREFUSED` / missing env var / Docker not found → **infrastructure failure**. Mark complete with caveat; advise local run.
   - Output unclear → ask developer to classify.

**VERIFY completion gate — do not mark the manifest as fixed until all of the following are true:**

- [ ] Install command ran and exited 0 (or failure was surfaced to developer)
- [ ] Test command ran (Tier 1), or import sites were audited (Tier 2), or import review was completed (Tier 3)
- [ ] Any blocking compatibility failure was reported to the developer and resolved
- [ ] Infrastructure failures were noted and developer was advised to run locally
- [ ] All per-package VERIFY entries in the shim output were addressed (one gate per updated package)
- [ ] Audit log Step 8 was written for this manifest

Do not declare the manifest complete, close the task, or report success until every box above is checked.

### Exception: Manual Override

If the parent agent determines that:
- The update is too risky for the project's timeline
- Breaking changes require extensive refactoring
- The vulnerability is not exploitable in the project's context

The agent should:
1. Document the decision with CVE number and risk assessment
2. Create a task/issue to address the update later
3. Add a comment in the manifest file explaining the override
4. Do NOT commit without a documented reason

Example override comment:
```
# TODO: Update aiohttp to 3.9.0 (currently 3.8.5)
# CVE-2023-32315 present but not exploitable in our use case
# (we don't use multipart form handling)
# Update planned for Q2 after major feature release
```

### Setup, settings.json, env vars, and usage options

See `references/configuration.md` for:

- Recommended `.claude/settings.json` (PostToolUse hooks + permissions allowlist)
- `SAFE_DEP_DRY_RUN` (report-only for CI gates) and `SAFE_DEP_AUDIT_LOG` (override audit log path) env vars
- Four usage options: manual (A), intercept-interactive (B), intercept-autonomous (C), report-only CI (D)


## Supported Manifest Files

The skill auto-detects and audits these ecosystems:

| Ecosystem | Manifests | Lockfiles |
|---|---|---|
| Python | `requirements.txt`, `setup.py`, `setup.cfg`, `pyproject.toml`, `Pipfile` | `Pipfile.lock`, `poetry.lock`, `uv.lock` |
| npm / Node | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Ruby | `Gemfile`, `*.gemspec` | `Gemfile.lock` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts`, `libs.versions.toml` | — |
| Go | `go.mod` | `go.sum` |
| Rust | `Cargo.toml` | `Cargo.lock` |

All supported files are auto-intercepted by the hooks when configured in
`.claude/settings.json`. For per-language format details, pinning strategies,
range-vs-pin trade-offs, and concrete syntax examples (TOML / JSON / Ruby /
XML / Gradle), read `references/manifest-formats.md`.

## When This Skill Applies

You MUST run this skill before:
- Adding a package to any supported manifest file (see list above)
- Writing an `import`, `require`, or `use` statement for a library not already declared in the project
- Recommending a library as part of an implementation
- Generating or updating a lock file — check only newly added or changed entries, not the full file

**Run this skill once per new package**, regardless of how many conditions above match (e.g., adding both an import and a manifest entry for the same package counts as one invocation).

Do NOT run this skill for:
- Standard library / built-in imports: Python (`os`, `sys`, `json`, `re`, `datetime`, etc.), Java (`java.util.*`, `java.io.*`, etc.), Node.js built-ins (`fs`, `path`, `http`, `crypto`, `node:*`), Ruby stdlib (`require 'json'`, `require 'date'`, `require 'net/http'`, etc.)
- Already-declared dependencies that are not being changed
- Edits to existing code that do not touch dependency declarations

When new code requires an existing dependency at a **different version**, run in
recommendation-only mode (see the Existing Dependency Version Bumps section).

## Management Mode Detection

**BEFORE proceeding with normal package security audits,** check if the user is requesting management of the safer-dependencies system itself:

**Installation requests** — detect phrases like:
- "install safer-dependencies"
- "help me install safer-dependencies"
- "set up safer-dependencies"
- "configure safer-dependencies"
- "how do I install safer-dependencies"

**Stats requests** — detect phrases like:
- "show safer-dependencies stats"
- "safer-dependencies statistics"
- "what stats do you have for safer-dependencies"
- "safer-dependencies usage stats"
- "show me safer-dependencies activity"
- "get safer-dependencies metrics"

**Validation requests** — detect phrases like:
- "check safer-dependencies setup"
- "validate safer-dependencies installation"
- "is safer-dependencies working?"
- "safer-dependencies health check"
- "verify safer-dependencies setup"
- "test safer-dependencies configuration"

**Projects (by-project) requests** — detect phrases like:
- "safer-dependencies stats by project"
- "which projects use safer-dependencies"
- "show me safer-dependencies usage per project"
- the `projects` subcommand or the `--by-project` flag (see Slash-command invocation below)

**Update requests** — detect phrases like:
- "update safer-dependencies"
- "upgrade safer-dependencies"
- "refresh safer-dependencies"

**Version requests** — detect phrases like:
- "safer-dependencies version"
- "what version of safer-dependencies"
- "which safer-dependencies version is installed"
- the `version` subcommand (see Slash-command invocation below)

**Slash-command invocation.** When invoked as `/safer-dependencies [subcommand]`, the
leading argument is a management subcommand — NOT a package to audit — and routes
directly (no "safer-dependencies" keyword required):

| Subcommand | Action |
|------------|--------|
| (no subcommand) · `menu` | interactive **selectable menu** of the actions below — presented via the native `AskUserQuestion` picker (Usage stats / View · edit config / Validate installation, with the rest under "Other"); falls back to a text `menu`/`menu select` flow in headless sessions (see "Menu Mode" below) |
| `stats` | usage analytics (standard report) |
| `projects` · `stats --by-project` | per-project **ranked dashboard** (which projects triggered the skill + their stats) |
| `install` | interactive installation |
| `validate` (or `check`) | installation health check |
| `update` (or `upgrade`) | self-update from the upstream repo |
| `version` | show installed version, install location(s), and (when online) the latest upstream version on `main` with an upgrade hint |
| `config` | show/edit the global policy file (`~/.config/safer-dependencies/config.toml`) — verbs: `config` (show effective config + source), `config menu` (X-grid of the current configuration, current values marked `[x]`), `config apply` (write the changes from an edited grid on stdin), `config set <key> <value>`, `config unset <key>`, `config reset`, `config path` |

A bare `/safer-dependencies` typed by the user (with no package/manifest under audit)
renders the interactive **menu** — it no longer jumps straight to `stats`; the user
picks the action from the native `AskUserQuestion` picker (text-menu fallback in
headless sessions). Flags pass through to the manager: `stats --window 30d`,
`stats --top 20`, `stats --all`, `stats --json` (machine-readable export of the
full stats dict, including the transitive-coverage section), `projects --window 30d`.
The by-project view shows
**every** project — real repos, test scaffolds, and the collapsed self-test temp-dir
bucket — classified by kind, never excluded. When Claude **auto-invokes** this skill to
audit a package (a manifest write or an "add X" trigger), ignore this fast path and run
the normal audit procedure instead.

**Menu Mode (bare invocation).** When the user types `/safer-dependencies` with no
subcommand, present a **selectable menu** and route their choice. Do NOT print a text
list the user has to scroll, copy, and edit — that is not a usable menu.

**Interactive sessions — use the native picker.** Present the menu with the
**`AskUserQuestion`** tool (the harness's selectable picker), a single question with
header `Action` and these options, in this order:

- **Usage stats** → routes to `stats`
- **View / edit config** → routes to `config` (see below)
- **Validate installation** → routes to `validate`

The picker always appends an **Other** choice. Use it (or a typed reply) for the
less-common actions — **per-project stats** (`projects`), **install**
(`interactive_install`), **update** (`self_update`); mention these in the question so
the user knows they are reachable. `AskUserQuestion` caps a question at four options,
which is why only the three primary actions are listed and the rest live under Other.

Once an action is chosen, run it exactly as if the user had typed
`/safer-dependencies <action>`:

- `stats` → `python3 "$MANAGER_SCRIPT" stats`
- `projects` → `python3 "$MANAGER_SCRIPT" stats --by-project`
- `validate` → `python3 "$MANAGER_SCRIPT" validate_installation`
- `install` → `python3 "$MANAGER_SCRIPT" interactive_install`
- `update` → The manager **refuses to apply without an explicit `--yes`** (#271): a bare
  `python3 "$MANAGER_SCRIPT" self_update` only previews the plan (it clones/applies nothing),
  so the apply path can never fire from an unconfirmed auto-trigger phrase. In **interactive
  sessions**: first run `python3 "$MANAGER_SCRIPT" self_update --check` to preview the update
  plan, show the output (including the trust warning for the upstream source), then ask the
  developer for confirmation via `AskUserQuestion` (Yes / No / Check only). **On YES, re-run
  with `--yes` to apply** (`python3 "$MANAGER_SCRIPT" self_update --yes`). On No / Check only,
  stop. In **autonomous sessions** (`bypassPermissions`, no human turn coming), apply the
  implicit-YES rule deliberately: pass `--yes` (`python3 "$MANAGER_SCRIPT" self_update --yes`)
  unless an explicit earlier deferral is on record — the `--yes` is the intentional,
  documented autonomous-confirmation, not an accidental bare apply.
- `config` → first show the current-config grid (`python3 "$MANAGER_SCRIPT" config menu`)
  so the user sees every key's current value **and the one-line `↳` description of what
  each setting impacts** (sourced from `CONFIG_KEY_DESCRIPTIONS` in the manager). Then
  drive edits **interactively with `AskUserQuestion`** — do NOT require the user to phrase
  changes in prose. Because the
  picker caps at four questions of four options each, you cannot show all thirteen keys
  at once: ask an **area** first (Check tiers / Cooloff / Staleness), then present that
  area's keys as selectable toggle rows — one `AskUserQuestion` question per key, options
  = its allowed values (check tiers `off`/`warn`/`block`; `staleness.popularity_guard`
  `on`/`off`; numeric keys `cooloff.days`/`staleness.years` offer common presets plus
  `Other` for a custom value). Put that key's `↳` description in the **question** text (so
  the user knows what the knob does) and note its **current** value in the option
  descriptions so an unchanged pick is a no-op. Apply every changed key with
  `config set <key> <value>` (skip keys left at their current value), then re-show the
  grid to confirm. Natural-language edits ("set cooloff to block") still work as a
  shortcut but are never required.

**Headless / autonomous fallback — deterministic text path.** When `AskUserQuestion`
cannot reach a human (`bypassPermissions`, batch instructions, no human turn coming),
use the text parsers instead: `python3 "$MANAGER_SCRIPT" menu` renders the action list;
pipe the reply into `python3 "$MANAGER_SCRIPT" menu select` (prints `SELECTED: <action>`,
exit 2 on no/multiple marks); for config, `config menu` → `config apply` (stdin) writes
only changed keys (a row with two marks aborts the whole apply, exit 2; a no-mark row is
unchanged).

Menu Mode is for the *user-typed* bare slash command only; never enter it while auditing
a package.

**Management Mode Detection:**

First, check if the user's request is about managing safer-dependencies itself:

```bash
# The invocation context. For a slash command `/safer-dependencies <subcommand>` this
# is the bare subcommand (e.g. "stats", "projects", "stats --by-project"); for a
# natural-language request it is the full phrase.
USER_REQUEST="$*"
REQ_LC="$(printf '%s' "$USER_REQUEST" | tr '[:upper:]' '[:lower:]')"
set -- $REQ_LC
FIRST="${1:-}"; SECOND="${2:-}"

management_mode=""

# (0) Bare invocation — `/safer-dependencies` with no arguments at all renders the
#     interactive X-menu (see "Menu Mode" above).
if [ -z "$FIRST" ]; then management_mode="menu"; fi

# (1) Slash-command subcommand: a known verb that stands ALONE or is followed by a flag.
#     This is what makes `/safer-dependencies stats` and `/safer-dependencies projects`
#     work. The "alone or flag" guard keeps audit-style "install redis package" /
#     "validate my package.json" (verb + a package/path) OUT of management mode.
case "$FIRST" in
    menu|stats|projects|by-project|install|setup|configure|validate|check|update|upgrade|config|version)
        # config is exempt from the "alone or flag" guard: it takes positional args
        # (e.g. `config set checks.stale block`) that must reach the manager.
        if [ -z "$SECOND" ] || [ "${SECOND#-}" != "$SECOND" ] || [ "$FIRST" = "config" ]; then
            case "$FIRST" in
                menu)                    management_mode="menu" ;;
                projects|by-project)     management_mode="projects" ;;
                validate|check)          management_mode="validate" ;;
                update|upgrade)          management_mode="update" ;;
                install|setup|configure) management_mode="install" ;;
                config)                  management_mode="config" ;;
                version)                 management_mode="version" ;;
                stats)
                    case "$REQ_LC" in
                        *--by-project*) management_mode="projects" ;;
                        *)              management_mode="stats" ;;
                    esac ;;
            esac
        fi ;;
esac

# (2) Explicit --by-project flag anywhere selects the ranked dashboard.
case "$REQ_LC" in *--by-project*) [ -z "$management_mode" ] && management_mode="projects" ;; esac

# (3) Natural-language requests (must name "safer-dependencies").
if [ -z "$management_mode" ] && printf '%s' "$REQ_LC" | grep -qiE "safer.?dependencies"; then
    if   printf '%s' "$REQ_LC" | grep -qiE "(install|set up|setup|configure)";            then management_mode="install"
    elif printf '%s' "$REQ_LC" | grep -qiE "(^|[^a-z])(config|settings|cooloff|policy)($|[^a-z])";            then management_mode="config"
    elif printf '%s' "$REQ_LC" | grep -qiE "project";                                     then management_mode="projects"
    elif printf '%s' "$REQ_LC" | grep -qiE "(stats|statistics|usage|metrics|activity)";   then management_mode="stats"
    elif printf '%s' "$REQ_LC" | grep -qiE "(update|upgrade|refresh)";                    then management_mode="update"
    elif printf '%s' "$REQ_LC" | grep -qiE "version";                                     then management_mode="version"
    elif printf '%s' "$REQ_LC" | grep -qiE "(check|validate|verify|health|test|working)"; then management_mode="validate"
    fi
fi

if [ -n "$management_mode" ]; then
    echo "Detected management request ($management_mode) - delegating to SaferDependenciesManager..."

    SKILL_DIR="<skill-directory>"
    MANAGER_SCRIPT="$SKILL_DIR/scripts/safer_dependencies_manager.py"
    if [ ! -f "$MANAGER_SCRIPT" ]; then
        echo "ERROR: Manager module not found at $MANAGER_SCRIPT"
        exit 1
    fi

    # Pass through any flags typed after a stats/projects subcommand
    # (e.g. --window 30d, --top 20, --all) or args after config (e.g. set checks.stale block).
    # --by-project is supplied explicitly below.
    EXTRA=""
    case "$FIRST" in
        stats|projects|by-project|config|update|upgrade|refresh)
            EXTRA="$(printf '%s' "$USER_REQUEST" | sed -E 's/^[[:space:]]*[A-Za-z-]+[[:space:]]*//; s/--by-project//g')" ;;
    esac

    case "$management_mode" in
        # menu: INTERACTIVE sessions present the picker via AskUserQuestion (see
        # "Menu Mode" above) — do not run this branch there. The `menu` text command
        # is the HEADLESS fallback; its reply is piped into `menu select` next turn.
        menu)     python3 "$MANAGER_SCRIPT" menu ;;
        install)  python3 "$MANAGER_SCRIPT" interactive_install ;;
        stats)    python3 "$MANAGER_SCRIPT" stats $EXTRA ;;
        projects) python3 "$MANAGER_SCRIPT" stats --by-project $EXTRA ;;
        validate) python3 "$MANAGER_SCRIPT" validate_installation ;;
        # update: the manager refuses to apply without --yes (#271). A bare
        # `self_update` (or one carrying only --check) PREVIEWS the plan and stops,
        # so an unconfirmed auto-trigger phrase can never reach the apply path. The
        # orchestrator follows the "update" routing prose above: preview first, then
        # re-invoke with --yes (passed through $EXTRA) only after the developer
        # confirms (interactive) or per the implicit-YES rule (autonomous).
        update)   python3 "$MANAGER_SCRIPT" self_update $EXTRA ;;
        version)  python3 "$MANAGER_SCRIPT" version ;;
        config)   python3 "$MANAGER_SCRIPT" config $EXTRA ;;
    esac

    echo "Management request completed - skipping normal audit mode"
    exit 0
else
    # Not a management request - proceed with normal audit flow
    echo "Normal audit mode - proceeding with package security checks"
    # Continue to normal skill logic...
fi
```

**Management mode is transparent to users** — they don't need to know about the delegation; just handle their request naturally.

**Do NOT trigger management mode for normal package security requests** like "audit my dependencies", "check if lodash has CVEs", or "install redis package" (different from "install safer-dependencies").

### Transitive dependency metrics

Lockfile audits (Post-Install Scan A and the Intercept lockfile path) cover the
**resolved transitive tree** — the coverage manifest-level audits cannot see.
Phase 1 measures and warns only:

- The `transitive` tier uses the existing canonical config: set it with
  `/safer-dependencies config set checks.transitive off|warn|block` (the same
  `config` CLI added for every other check tier). `off` skips the Post-Install
  lockfile Scan A; `warn` (default) keeps it on. There is **no** separate
  transitive-config subcommand or JSON config file.
- Every lockfile audit-log entry (schema 2.2) now records a `relation_summary`
  classifying each checked package as direct (declared in the sibling manifest),
  transitive (pulled in by the resolver), or unknown (manifest missing /
  unparseable — fail open), plus a `policy` block snapshotting
  `{transitive_tier: <off|warn|block>}` from the config above.
- `/safer-dependencies stats` gains a **Transitive coverage** section computed
  from those entries (lockfile audits, direct vs transitive volume, transitive
  findings, top-5 flagged transitive packages); `stats --json` exports the full
  stats dict including this section.

## Package Manager Command Detection

**BEFORE proceeding with normal audit flow,** check if this is a package manager command that should be delegated to the Pre-Install hook:

```bash
# Check if this is a package manager bash command
if echo "$USER_REQUEST" | grep -qE "(npm|yarn|pnpm|bun|pip|poetry|uv|bundle|gem|go|cargo).*(install|add)"; then
    echo "Package manager command detected - delegating to Pre-Install hook"
    # Delegate to pretooluse hook
    exit 0
fi
```

**Package manager commands** are handled by the Pre-Install hook system, which:
- Intercepts package manager commands before execution
- Performs real-time vulnerability checks during installation
- Blocks vulnerable packages before they're fetched
- Provides immediate feedback in the terminal

**Normal audit flow** (this skill) handles:
- Dependency file analysis and recommendations
- Version resolution for manifest files  
- Security auditing of existing dependencies
- Manual package safety queries

## Step 1: Resolve the Version

When no version is specified, resolve the safest stable version before any other checks:

1. Query the registry for all stable releases. Exclude versions with pre-release tags
   (`alpha`, `beta`, `rc`, `dev`, `preview`, `a`, `b`).
2. Find the **newest version published ≥7 days ago** — this is the initial candidate.
3. **Security exception:** If the newest release (even if published < 7 days ago) explicitly
   references a CVE fix in its release notes or changelog, use it instead. Note the exception
   in your output.
4. Run Layer 3 (vulnerability scan, Step 4) on the candidate. If it has unmitigated CVEs,
   step back to the previous version and repeat from **step 4 only** (the CVE security
   exception in step 3 applies only to the newest release, not older candidates).
5. If no clean version exists, use the least-vulnerable available version and emit a CRITICAL warning.
6. **Always pin the version explicitly.** Never use range specifiers.
   - Python: `requests==2.31.0` not `requests>=2.31.0`
   - npm: `"axios": "1.6.8"` not `"axios": "^1.6.8"`
   - Ruby: `gem 'rails', '7.1.3'` not `gem 'rails', '~> 7.1'`
   - Java: `<version>3.12.0</version>` (exact, no ranges)

**Script path resolution:**

The version resolution scripts are located in the `scripts/` subdirectory relative to this skill file. Replace `<skill-directory>` below with the actual directory containing this skill file. For example:
- Global install: `~/.claude/skills/safer-dependencies/scripts/resolve_npm.py`
- Project install: `.claude/skills/safer-dependencies/scripts/resolve_npm.py`

**Registry query commands per ecosystem:**

npm — resolve version, auto-select newest stable ≥ cooloff window (default 7 days):
```bash
npm view <pkg> time --json | python3 <skill-directory>/scripts/resolve_npm.py
```
Outputs top 10 stable versions, then a `SELECTED: <version>` line. Use that version — do not override this selection with your own judgment. The only exception: if the newest release (even inside the cooloff window) explicitly fixes a CVE, you may use it instead and note the exception.

Python — resolve version, auto-select newest stable ≥ cooloff window (default 7 days):
```bash
curl -s --max-time 10 https://pypi.org/pypi/<pkg>/json | python3 <skill-directory>/scripts/resolve_pypi.py
```
Outputs stable versions sorted by semver descending with age, then a `SELECTED: <version>` line. Uses `packaging.version.Version` if available, falls back to numeric tuple sort.

Ruby — resolve version, auto-select newest stable ≥ cooloff window (default 7 days):
```bash
curl -s --max-time 10 https://rubygems.org/api/v1/versions/<gem>.json | \
  python3 <skill-directory>/scripts/resolve_rubygems.py
```
RubyGems API returns versions in reverse chronological order. Outputs stable versions with age, then a `SELECTED: <version>` line.

Java — resolve version from Maven Central, auto-select newest stable ≥ cooloff window (default 7 days):
```bash
curl -s --max-time 10 "https://search.maven.org/solrsearch/select?q=g:<groupId>+a:<artifactId>&core=gav&rows=50&wt=json&sort=timestamp+desc" | \
  python3 <skill-directory>/scripts/resolve_maven.py
```
Maven Central sorted by timestamp descending. Allows platform classifiers (`-jre`, `-android`, `-jakarta`, `-native`) which are stable releases, not pre-release tags. Outputs top 10 stable versions with age, then a `SELECTED: <version>` line.

### Self-check: Version resolution

The command outputs a `SELECTED: <version>` line. **Use that version exactly.** Do not override it.

Verify before proceeding:

1. **Output has a SELECTED line:** If you see `ERROR:` or a Python traceback instead — the command failed. Do not guess a version; re-run or report the error.

2. **No WARNING line:** If you see a `WARNING: no version >=…d old` line, note this in your output. The command still selects the best available, but the cooldown window (default 7 days) was not met.

3. **No pre-release leaked:** Scan the listed versions. None should contain `alpha`, `beta`, `rc`, `dev`, `preview`, `canary`, `next`, `nightly`, `experimental`, `snapshot`, or a hyphen followed by a letter. If any do, the filter has a bug — do not use that version.

4. **Version exists on registry:** The SELECTED version must appear in the command's output. Never use a version from memory or training data.

**Example of correct output:**
```
4.22.1 2025-12-01 (125d)
5.2.1 2025-12-01 (125d)
5.2.0 2025-12-01 (125d)
SELECTED: 4.22.1
```

**Example with age warning:**
```
17.0.6 2026-04-05 (0d)
17.0.5 2026-03-20 (16d)
SELECTED: 17.0.5
```
The command automatically skipped 17.0.6 (0d < 7d) and selected 17.0.5 (16d ≥ 7d).

## Step 2: Layer 1 — Provenance Checks

Sub-checks run in order. **1a and 1b are the only blocking checks** — if either fails, do not proceed. All other sub-checks emit warnings and continue.

### 1a. Official registry confirmation

Verify the package is hosted on the canonical registry for its ecosystem:
- npm → npmjs.com
- Python → pypi.org
- Ruby → rubygems.org
- Java → Maven Central (search.maven.org)

If the package resolves to a mirror, unofficial fork, or private registry not expected for the
project: emit CRITICAL warning and **stop — do not proceed** with an unrecognized source.

### 1b. Typosquat check

Run the typosquat script. It uses Optimal String Alignment (Damerau-Levenshtein variant)
against a hardcoded reference list of well-known packages per ecosystem.

```bash
python3 <skill-directory>/scripts/check_typosquat.py "<pkg>" --ecosystem <ecosystem>
```

Where `<ecosystem>` is one of: `npm`, `pypi`, `rubygems`, `maven`.
Note: these are the script's internal tokens (all lowercase). They differ in casing from the
OSV API ecosystem strings (`PyPI`, `RubyGems`) used later in Step 4.

**Self-check:** The script outputs exactly one of:

- `CLEAN` — no near-match found; proceed to 1c.
- One or more `TYPOSQUAT: <input> is N edit(s) from <reference>` lines — stop and ask the user.

If the script errors (non-zero exit, missing file, Python traceback): emit MEDIUM warning
"Typosquat check could not run — manual review recommended" and proceed. Do not block on a
script failure.

**If TYPOSQUAT lines appear:** emit the alert and blocked output below, then present the
three options to the user. Do not write anything to the manifest until the user responds.

```
\033[1;31mALERT TYPOSQUAT\033[0m
[safer-dependency-skill] 🛑 BLOCKED — <pkg> (<ecosystem>)
   Issue: [layer 1b] Possible typosquat detected
   Detail: "<pkg>" is N edit(s) from "<reference>" (well-known package)

   What would you like to do?
     A. I meant "<reference>" — run checks on the correct name and add it to the manifest
     B. "<pkg>" is intentional — proceed with this name as-is
     C. Don't add anything — abort, no manifest change
```

**After user responds:**

- **Option A — correct the name:** restart all checks from Step 1 using `<reference>`. If
  checks pass, write `<reference>==<resolved-version>` to the manifest. The originally
  requested name `<pkg>` is never written anywhere.
- **Option B — intentional:** resume from Layer 1c using the original name `<pkg>`. Record
  the confirmation in the audit log entry's `signals` list (e.g.
  `"NOTE: user confirmed override of typosquat warning for <pkg>"`) — the log
  appender accepts only its schema fields, so a custom top-level field would be dropped.
- **Option C — abort:** do not write anything to the manifest. Inform the user that no
  package was added and they can investigate `<pkg>` before retrying.

### 1c. Package first-publish age

Query the package's first-ever publish date:

npm:
```bash
npm view <pkg> time.created
```

Python (earliest release upload time — ISO strings sort correctly, no version parsing needed):
```bash
curl -s --max-time 10 https://pypi.org/pypi/<pkg>/json | python3 <skill-directory>/scripts/first_publish_pypi.py
```

Ruby (earliest version created_at):
```bash
curl -s --max-time 10 https://rubygems.org/api/v1/versions/<gem>.json | \
  python3 <skill-directory>/scripts/first_publish_rubygems.py
```

Java (earliest version from Maven Central):
```bash
curl -s --max-time 10 "https://search.maven.org/solrsearch/select?q=g:<groupId>+a:<artifactId>&core=gav&rows=200&wt=json" | \
  python3 <skill-directory>/scripts/first_publish_maven.py
```

Emit HIGH warning if first-publish date < 30 days ago. Then continue.

### 1d. GitHub repository age (best-effort)

If registry metadata includes a GitHub repository URL, check its creation date:
```bash
curl -s --max-time 10 https://api.github.com/repos/<owner>/<repo> | python3 <skill-directory>/scripts/github_repo_age.py
```

Emit HIGH warning if repo created < 30 days ago.

Skip this sub-check if: no GitHub URL in registry metadata, or the API call fails. Do not block.

### 1e. Download count signal

Use judgment to flag anomalously low adoption:
- A package 2+ years old with < 500 total downloads is suspicious
- A package 3 days old with 50,000 downloads may have artificial inflation — treat as corroborating
  signal alongside 1c, not a standalone warning
- Emit LOW warning if download count alone is the only concern

### 1f. Latest-release staleness (2+ years)

Distinct from 1c (first-publish age, which flags *newly-created* packages) — this check flags packages whose newest stable release is more than two years old. The maintainer has likely walked away; a zero-day landing tomorrow will not get a fix.

Call `safedep.staleness.is_stale(newest_release_ts)` from the shared library. Both the shim and this skill use the same threshold (730 days), so threshold decisions are identical on the same input — except that the shim additionally applies the popularity/latest-version guard described below (manual mode does not query popularity, so a package the shim downgrades to a mature `NOTE:` may still surface as `STALE:` in a manual audit; treat the shim's classification as authoritative when both ran).

```python
import sys; sys.path.insert(0, '<skill-directory>/scripts')
from safedep.staleness import is_stale
# newest_release_ts is the timezone-aware datetime of the newest stable version.
# Reuse the timestamp already fetched during Step 1 version resolution.
stale, last_date = is_stale(newest_release_ts)
```

If `stale` is True, emit a STALE advisory:

```
[safer-dependency-skill] ⚠️ STALE — <pkg> (<ecosystem>)
   Issue: [layer 1f] Latest release <last_date>, no updates in 2+ years
   Detail: Package may be unmaintained. New CVEs will not be patched if discovered.
   Advisory — inform the developer and ask whether to find an alternative. Implementation may continue if the developer accepts the risk.
```

If `stale` is False: pass silently and continue to 1g.

The staleness threshold can be overridden for specific audits by passing `threshold_days=N` to `is_stale()`. The shim honors the `SAFE_DEP_STALE_YEARS` environment variable (a number of years, converted at 365 days/yr); missing, non-numeric, or non-positive values fall back to the 730-day default. The manual-mode skill should honor the same override for consistency.

**Popularity/latest-version guard (mature ≠ stale):** elapsed time alone cannot distinguish a finished, widely-used package (Flask-SQLAlchemy: latest release ~2.7 years old, top-tier adoption) from a dead one. When a package crosses the staleness threshold, the shim downgrades `STALE:` to an informational `NOTE: … mature, not flagged STALE` only when ALL THREE corroborate: the pinned version IS the newest stable release (the user is not behind), the package clears the per-ecosystem popularity bar (`safedep.popularity`, the same data the typosquat layer uses), AND the staleness is within 2× the threshold. The 2× cap preserves true positives — genuinely abandoned packages keep large legacy download numbers (`nose`: last release 2015, still clears the download bar a decade later) but accumulate staleness far beyond the cap. Curated-abandoned packages are unaffected (that check runs first and BLOCKs regardless). The guard is fail-closed: a popularity-lookup failure keeps the `STALE:` signal — suppression needs corroboration, and absence of data is not corroboration. Disable with `SAFE_DEP_STALE_POPULARITY_GUARD=0` for deterministic, pure elapsed-time behavior.

**Cooloff (release-age gate):** the inverse of staleness — a release *too new* to be community-vetted. Configurable via `cooloff.mode` (`off` / `warn` / `block`, default `warn`) and `cooloff.days` (default 7) in `~/.config/safer-dependencies/config.toml`, or the `SAFE_DEP_COOLOFF_MODE` / `SAFE_DEP_COOLOFF_DAYS` env overrides. Enforced in three places: at version selection (Step 1's resolve scripts pick the newest stable version ≥ the window unless `mode = off`), in Intercept (shim), and in Pre-Install. Under `warn`, a fresh pin emits `COOLOFF-CONFIRM: <pkg>@<ver> was published N days ago (window: Xd) …` on post-write surfaces — stop and ask the developer before proceeding; at Pre-Install the warn-mode signal uses the `COOLOFF:` prefix (the permission ask itself carries the confirm semantics). Under `block`, Intercept rewrites the pin to the newest clean same-major release clearing the window (signal: `COOLOFF:`) and Pre-Install denies the install. **CVE-fix exception (Intercept / Normal mode):** the cooloff gate runs only on CVE-clean pins, so a CVE-driven rewrite bypasses the gate even when the fix release is younger than the window — holding back a security patch is self-defeating; the rewrite arrives through the normal CVE path, so the regular `UPDATED:` signal documents it. Pre-Install `block` has no manifest context and denies a too-fresh pin regardless; the fix then lands via Intercept's rewrite path. See `references/configuration.md` for the full tier table.

### 1g. Abandoned-package lookup

Layer 1 also consults a curated map of packages known to be abandoned, deprecated, or actively-harmful even before CVE data or staleness thresholds would catch them. The map lives at `safedep.abandoned.KNOWN_ABANDONED` (see `safedep/abandoned.py` for the current list) covering npm, PyPI, RubyGems, and Go. Both the shim and this skill consult the same map, so both surfaces produce the same `BLOCKED: ... abandoned: ...` finding for the same input.

```python
import sys; sys.path.insert(0, '<skill-directory>/scripts')
from safedep.abandoned import lookup as check_abandoned
note = check_abandoned(pkg_name, ecosystem)  # ecosystem is lowercase: "npm", "pypi", "rubygems", "go"
```

If `note` is non-None, emit a BLOCKED finding:

```
[safer-dependency-skill] 🛑 BLOCKED — <pkg> (<ecosystem>)
   Issue: [layer 1g] Package is on the known-abandoned list
   Detail: <note from the map — includes replacement guidance>
   Waiting for user confirmation before proceeding — switch to the named replacement or accept the risk explicitly.
```

`note` always includes a named replacement (per the map's contribution policy) — surface it verbatim so the developer knows what to use instead. Example: `"github.com/dgrijalva/jwt-go" → "Abandoned, CVE-2020-26160 — use github.com/golang-jwt/jwt/v5"`.

**Ordering:** run 1g *before* Layer 3 (vulnerability scan). A known-abandoned package is blocked regardless of whether its current version has a CVE — the maintainer walking away is itself a supply-chain issue.

## Step 3: Layer 2 — Version Age

Reuse the publish timestamp already fetched in Step 1 — do not query the registry again.

- If version was published **≥7 days ago**: pass silently.
- If version was published **< 7 days ago**:
  - Check the release notes or changelog for an explicit CVE reference.
  - **CVE found** → security exception applies; proceed and note the exception in output. No warning.
  - **No CVE found** → this case is normally already handled by version resolution stepping back
    in Step 1. This warning only fires when the user has **explicitly pinned** a version that
    is < 7 days old.

Emit a MEDIUM warning using the unified format in Step 6, with:
- Issue: `[layer 2] Version published <N> days ago — below the 7-day cooldown threshold`
- Detail: `Published: <date>. No CVE fix found in release notes to justify exception.`
- Action: `Proceeding with user-specified version. Consider <previous-stable-version> as safer alternative.`

## Step 4: Layer 3 — Vulnerability Scan

Run the ecosystem-native tool first. If the command is not found or fails, fall back to the OSV API.
Warn for ANY CVE found, at all severity levels — label each with its actual severity.

### npm

Primary — requires an existing `package-lock.json` or `npm-shrinkwrap.json`:
```bash
npm audit --json
```
Parse JSON output. Flag any advisory with `severity` of `critical`, `high`, `moderate`, or `low`.

If no lockfile exists yet (new project, first dependency), skip `npm audit` and use the OSV fallback directly.

OSV fallback:
```bash
curl -s --max-time 10 -X POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"package": {"name": "<pkg>", "ecosystem": "npm"}, "version": "<version>"}'
```

### Python

Primary — audit single package before it's added to requirements:
```bash
echo "<pkg>==<version>" > /tmp/_audit_check.txt && pip-audit -r /tmp/_audit_check.txt --format json && rm -f /tmp/_audit_check.txt
```
If requirements.txt already exists, also run:
```bash
pip-audit -r requirements.txt --format json
```

OSV fallback:
```bash
curl -s --max-time 10 -X POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"package": {"name": "<pkg>", "ecosystem": "PyPI"}, "version": "<version>"}'
```

### Ruby

Run OSV to check the specific version before it is added to the lockfile:
```bash
curl -s --max-time 10 -X POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"package": {"name": "<gem>", "ecosystem": "RubyGems"}, "version": "<version>"}'
```

If a Gemfile.lock already exists, additionally run `bundle audit` to scan the full lockfile:
```bash
bundle audit check --update
```

### Java (Maven / Gradle)

Primary — run OWASP Dependency-Check if available:
```bash
dependency-check --project <name> --scan <pom.xml or build.gradle> --format JSON --out ./dc-report
```

OSV fallback:
```bash
curl -s --max-time 10 -X POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"package": {"name": "<groupId>:<artifactId>", "ecosystem": "Maven"}, "version": "<version>"}'
```

### Interpreting results

For each CVE found, emit a warning using the severity from the advisory. Include the CVE ID in
the Detail field. If version resolution in Step 1 already stepped back to a clean version, still
emit the warning for the originally-resolved version to explain why the version changed.

If a tool is unavailable and the OSV API also fails (no network, etc.): emit MEDIUM warning
"Vulnerability scan could not be completed — manual review recommended" and proceed.

### Self-check: Vulnerability scan

1. **OSV response format:** A clean package returns `{}` (empty JSON object). A vulnerable package returns `{"vulns": [...]}` with one or more entries. If you get an HTML page, connection error, or empty string — the scan failed, not "clean". Emit the MEDIUM "scan could not be completed" warning.

2. **Do not confuse "scan failed" with "no vulnerabilities".** Only `{}` or `{"vulns":[]}` means clean. Anything else (timeout, 4xx/5xx, malformed JSON) means the scan was inconclusive.

3. **pip-audit requires `-r` flag:** The command uses a temp requirements file, not a `--package` flag. If `pip-audit` reports an unrecognized argument, the command syntax is wrong.

## Step 5: Layer 4 — Hash-pin Integrity

### Python (PyPI)

When `requirements.txt` declares hash pins, the shim validates them automatically. Each line of the form:

```
<pkg>==<version> \
    --hash=sha256:<abc...>
```

is checked by fetching `https://pypi.org/pypi/<pkg>/<version>/json` and comparing the declared `sha256` against PyPI's published digests for every distribution file of that version. Behaviors:

- **Match** → silent (no signal — integrity confirmed)
- **No declared hash** → skipped (hash pinning is opt-in)
- **Mismatch** → `WARNING: <pkg>@<version> declared hash does not match any PyPI-published sha256 digest — entry may have been tampered with in the manifest`
- **PyPI fetch failure** → no signal (network degradation is handled by the network-failure signal path)

To generate hash pins for a new dependency (manual invocation), the `pypi_hashes.py` helper remains available:

```bash
curl -s --max-time 10 https://pypi.org/pypi/<pkg>/<version>/json | \
  python3 <skill-directory>/scripts/pypi_hashes.py
```

Append the output lines to `requirements.txt`.

### npm / Ruby / Maven

Not checked by the automatic hook. Rationale:

- **npm classic signatures** and **Ruby gem signing**: adoption is well under 1%; emitting WARNINGs for every unsigned package produces noise that trains users to ignore the signal.
- **Maven `.asc` files**: Maven Central validates GPG at publish time, but client-side PGP verify requires the signer's public key in a local keyring, which is almost never configured. Presence/absence of the `.asc` file is a weak signal by itself.
- **Install-time integrity** is already handled correctly by `npm ci` (lockfile hashes), `bundle install` (Gemfile.lock checksums), and `mvn` (Maven Central upload validation). The skill's value is decision-time safety, not re-implementing install-time checks.

**Future enhancement:** npm provenance attestation detection — when `dist.attestations` is present on `registry.npmjs.org/<pkg>/<version>`, the package was built via Sigstore in a verified CI workflow. A WARNING when a previously-signed package ships an unsigned update catches maintainer-account compromise. Tracked in the issue tracker.

## Step 6: Emit Output

All output from this skill MUST be prefixed with `[safer-dependency-skill]` for clear
attribution so the developer can identify what made the change or what errored.

### Summary mode

For **direct dependencies** (single package being added): emit one line per package
regardless of outcome. The developer should always see that the skill ran.

For **transitive dependencies** (lock file diff with multiple new entries): collapse
clean results into one summary line, emit individual lines only for issues.

### Output formats

**Clean check (direct dep):**
```
[safer-dependency-skill] ✓ <pkg>@<version> (<ecosystem>) — clean
```

**Clean check (transitive deps, collapsed):**
```
[safer-dependency-skill] ✓ <N> transitive dependencies clean (<ecosystem>)
```
If some transitive deps have issues, still emit the summary line for the clean ones
AND individual warning lines for the problematic ones.

**Sub-item formatting rule:** Top-level lines (header, summary) get the `[safer-dependency-skill]` prefix. Detail lines that elaborate on the header are emitted as bulleted sub-items (`  - `) with NO prefix.

**Warning:**
```
[safer-dependency-skill] ⚠️  <SEVERITY> — <pkg>@<version> (<ecosystem>)
  - Issue: <one-line description>
  - Detail: <CVE ID, publish date, missing signature, etc.>
  - Action: <what was done — e.g. "Stepped back to 2.30.0 (clean)" or "Proceeding with warned version">
```

For multiple issues on the same package, group under one header with the highest severity:
```
[safer-dependency-skill] ⚠️  HIGH — <pkg>@<version> (<ecosystem>)
  - Issue 1: <description>
  - Detail: <finding>
  - Issue 2: <description>
  - Detail: <finding>
  - Action: <action taken>
```

**Error (command failure):**
```
[safer-dependency-skill] ❌ <brief failure description> — <pkg> (<ecosystem>)
  - Reason: <why it failed>
  - Fallback: <what was tried / what was skipped>
  - Troubleshoot: <actionable hint if known>
```

**Recommendation (existing dep version bump):**
```
[safer-dependency-skill] 📦 RECOMMENDED — <pkg> <current> → <new> (<patch|minor|MAJOR> bump)
  - Reason: <why the new version is needed>
  - Vuln check: <Clean | CVE-XXXX (SEVERITY)>
  - Age: <N days ✓ | ⚠️ below 7-day threshold>
  - To update: <exact install command>
```
For MAJOR bumps, add a sub-item: `  - ⚠️  Major version bump: review release notes before accepting.`

**Blocking stop (CRITICAL):**
```
[safer-dependency-skill] 🛑 BLOCKED — <pkg> (<ecosystem>)
  - Issue: <what triggered the stop — typosquat, unrecognized registry, tampered signature>
  - Detail: <specifics>
  - Waiting for user confirmation before proceeding.
```

### Severity level definitions

- **CRITICAL** — active exploit CVE, suspected typosquat (pending user confirmation), tampered signature, unrecognized registry source
- **HIGH** — unmitigated CVE (any CVSS severity), package first published < 30 days ago
- **MEDIUM** — version < 7 days old with no CVE exception, signature missing where commonly expected (npm, newer PyPI packages), Maven unsigned
- **LOW** — unsigned Ruby gem (expected), low download count as sole signal

The severity shown in the warning header is the highest among all issues for that package. If there are both HIGH and LOW findings, the header reads `HIGH`.

### Layer attribution in warnings

When a warning is emitted, include the layer that fired it in the Issue line when it
aids troubleshooting. Examples:
- `Issue: [layer 1c] Package first published 12 days ago`
- `Issue: [layer 3] Unmitigated CVE in resolved version`
- `Issue: [layer 4] Declared hash does not match PyPI-published sha256 digest`

This lets the developer quickly identify which check triggered and skip or reconfigure it if needed.

## Step 7: Write the Code

Proceed with writing the code using the resolved (and checked) version. Do not block on warnings.
The warning is already emitted — the user has been informed and can decide next steps.
Use the pinned version in any manifest additions.

**Before writing to a manifest, consult `references/manifest-formats.md`** for the
exact pinning syntax of the target ecosystem (`requirements.txt`, `package.json`,
`Gemfile`, `pom.xml`, `build.gradle`, `Cargo.toml`, `go.mod`). The body's
"Supported Manifest Files" section lists what's recognised; the reference file
has the per-language syntax you write into the file. Always pin exact, never
range — that contract is non-negotiable regardless of ecosystem.

**Exception:** If a CRITICAL stop was triggered (unrecognized registry in 1a, or suspected typosquat
in 1b), do NOT write the code. Those checks stop execution before reaching this step.

## Step 8: Write Audit Log Entry

After completing all checks and writing the code, append one canonical JSONL entry to the audit log so Normal-mode runs end up in the same file, with the same schema, as intercept-mode runs from the shim.

Pipe a JSON object describing this run into the `audit_log_append.py` helper. The helper writes to `~/.claude/safer-dependencies-audit-YYYY-MM.log` (monthly-rotated, where `YYYY-MM` is the current year-month) by default; override the full path with `SAFE_DEP_AUDIT_LOG`. The helper creates the parent directory if needed and is silent on every error path — audit logging must never break the user-visible flow.

```bash
echo '{
  "file_path": "<absolute path to manifest just written>",
  "ecosystem": "<npm|pypi|rubygems|maven|go>",
  "checked": ["<pkg@version>", "..."],
  "signals": ["<one signal line per finding, e.g. UPDATED: lodash 4.17.10 → 4.17.21 (HIGH: 6 CVEs fixed)>"]
}' | python3 <skill-directory>/scripts/audit_log_append.py
```

Field semantics:
- `file_path` — absolute path of the manifest the run audited (or the package descriptor path for an existing-dep recommendation)
- `ecosystem` — lower-case identifier
- `checked` — every `pkg@version` that went through Layer 1–4
- `signals` — every emitted line. Use the same signal shapes the shim emits (`UPDATED:`, `BLOCKED:`, `STALE:`, `MAJOR-UPDATE-CONFIRM:`, `TYPOSQUAT-CONFIRM:`, `UNKNOWN:`, `SIGNATURE:`, `WARNING:`). The library partitions them into the canonical buckets (`findings`, `abandoned`, `stale`, `typosquat`, `unknown`, `signatures`, `clean`) before writing.
- For dry-run / report-only flows, add `"dry_run": true` — the entry will get `"mode": "dry_run"` for filtering.

Do not print anything to the user about the log write. The helper is silent by design.

---

## Troubleshooting

See `references/troubleshooting.md` for symptoms, causes, and fixes covering:
hooks not triggering, signals not appearing, version updates not happening,
registry connection issues, signature verification failures, atomic-update
failures, cross-ecosystem contamination, and the activity + audit log formats.

---

## Existing Dependency Version Bumps

When new code requires an existing dependency at a higher version than currently declared,
present a recommendation and wait for user confirmation. Do NOT modify any manifest automatically.

1. Identify the minimum version required for the new code to work (check API docs or changelog
   for when the needed feature/method was introduced).
2. Find the smallest increment satisfying the requirement:
   - Try patch first (`x.y.Z` → `x.y.Z+n`)
   - Then minor (`x.Y.z` → `x.Y+n.0`)
   - Then major (`X.y.z` → `X+n.0.0`) — only if patch/minor cannot satisfy
3. Run all four check layers on the recommended version before surfacing it.
4. For **major version bumps**: include an explicit breaking-change warning and link to the
   migration guide or release notes if known.
5. Present using the recommendation format from Step 6 and wait for the user to respond:

```
[safer-dependency-skill] 📦 RECOMMENDED — <pkg> <current> → <new> (<patch|minor|MAJOR> bump) (<ecosystem>)
  - Reason: <why the new code needs this version — be specific about which API/feature>
  - Vuln check: <Clean | CVE-XXXX-XXXXX (<severity>)>
  - Age: <N days ✓ | ⚠️ N days — below 7-day threshold>
  - To update: <exact install command with pinned version>
```
For MAJOR bumps, append a sub-item: `  - ⚠️  Major version bump: <package> X.x contains breaking changes. Review release notes before accepting.`

Do not write the new code until the user has responded to the recommendation.

Run Step 8 (audit log) after presenting the recommendation, including a `signals` entry `"NOTE: recommended only — not applied"` so the entry is distinguishable from an applied update (the log appender accepts only its schema fields, so a custom `outcome` field would be dropped). Do not wait for user response before logging.

## Lock File Diff Handling

When generating or updating a lock file, identify only the **newly added or changed entries**
in the diff. Do not re-check entries already present before this operation.

For each new transitive dependency in the diff, run a **reduced check set**:

| Check | Run? |
|---|---|
| Layer 1a — Official registry | Yes |
| Layer 1c — Package first-publish age (< 30 days) | Yes |
| Layer 1b, 1d, 1e — Typosquat, GitHub age, downloads | No (too noisy for transitive) |
| Layer 2 — Version age (< 7 days) | No |
| Layer 3 — Vulnerability scan | CRITICAL and HIGH severity only |
| Layer 4 — Hash-pin integrity | No (only validated on primary manifest) |

**Identifying the diff:**

If the lock file is already tracked by git, use `git diff` to find new entries. If the lock file
is new (untracked or not yet committed), treat **all** entries as new — every dependency in the
file needs checking.

To detect which case applies:
```bash
git ls-files --error-unmatch <lockfile> 2>/dev/null && echo "TRACKED" || echo "NEW"
```

**If tracked** — diff only:

npm / yarn (`package-lock.json` or `yarn.lock`):
```bash
git diff package-lock.json | grep '^+' | grep '"resolved"' | sed 's/.*"resolved": "\([^"]*\)".*/\1/'
```

Python (`Pipfile.lock`):
```bash
git diff Pipfile.lock | grep '^+' | grep '"version"'
```

Ruby (`Gemfile.lock`):
```bash
git diff Gemfile.lock | grep '^+[A-Za-z]' | grep -v '^+++' | awk '{print $1, $2}'
```

Java (`maven-wrapper.properties` or generated lockfile):
Parse any added `<dependency>` blocks in the diff output.

**If new/untracked** — parse all entries from the file directly (no `git diff`):

npm: `cat package-lock.json | python3 -c "import json,sys; [print(k,v.get('version','')) for k,v in json.load(sys.stdin).get('packages',{}).items() if k]"`

Python: `cat Pipfile.lock | python3 -c "import json,sys; d=json.load(sys.stdin); [print(k,v.get('version','')) for k,v in {**d.get('default',{}),**d.get('develop',{})}.items()]"`

Ruby: `grep -E '^\s+\S+ \(' Gemfile.lock | awk '{print $1, $2}' | tr -d '()'`

**Warning format for transitive dependencies:**

Use the unified warning format from Step 6 with `[transitive]` appended after the severity:

```
[safer-dependency-skill] ⚠️  HIGH [transitive] — <pkg>@<version> (<ecosystem>)
  - Issue: <one-line description>
  - Detail: <specific finding>
  - Action: Proceeding — transitive dependency added by <direct-parent-package>
```

If no transitive issues found, emit the collapsed clean-summary line from Step 6:

```
[safer-dependency-skill] ✓ <N> transitive dependencies clean (<ecosystem>)
```

---

## Worked Examples

See `references/examples.md` for six end-to-end walkthroughs: Python package
with CVE, npm scoped-package update, Ruby gem version update, Java dependency
update, typosquat detection, and transitive-dependency warning handling.

## Workflows and Performance

See `references/performance.md` for:

- Integration with Claude Code workflows (intercept mode, manual audit, recommendation-only)
- Execution-time breakdown, caching strategy, network timeouts
- Performance tuning tips for large projects and parallel workflows

