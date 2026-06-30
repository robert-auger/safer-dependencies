# Frequently Asked Questions

Design-decision rationale for the safer-dependencies skill. Each entry documents a choice that has come up more than once in discussion — if you find yourself asking "why this way?", you're probably looking for an entry below.

## Contents

- [Why a skill alone is not sufficient](#why-a-skill-alone-is-not-sufficient)
  - [Isn't the skill enough on its own?](#isnt-the-skill-enough-on-its-own)
  - [What does a skill miss that hooks catch?](#what-does-a-skill-miss-that-hooks-catch)
  - [Why is automatic skill-triggering unreliable?](#why-is-automatic-skill-triggering-unreliable)
  - [Why keep the skill at all if hooks are deterministic?](#why-keep-the-skill-at-all-if-hooks-are-deterministic)
- [Architecture](#architecture)
- [Security check decisions](#security-check-decisions)
- [Scope and coverage decisions](#scope-and-coverage-decisions)
- [Sandbox and subagent limitations](#sandbox-and-subagent-limitations)
- [Skill-loading gotchas](#skill-loading-gotchas)

---

## Why a skill alone is not sufficient

A skill defines **what** to check. It does not guarantee the check **runs**. The gap between "a correct audit procedure exists in a file" and "the procedure actually executed on every dependency change" is the entire reason this project ships hooks at all. A skill is invoked by the *model's judgment*; a hook is fired by the *harness* on a tool-call event. Only the second is deterministic — and dependency security is a domain where a check that runs 95% of the time is a check that misses the one supply-chain attack that mattered.

### Isn't the skill enough on its own?

No. A skill is **model-mediated**: it runs only when Claude decides its frontmatter description matches the current task and calls the `Skill` tool. That decision is probabilistic, and it degrades in exactly the situations where you most need the check:

- **The procedure isn't even loaded until it's invoked.** At session start only the skill's *name and one-line description* enter context. The `SKILL.md` body — the actual layer-by-layer procedure, the HARD GATEs, the signal protocol — does **not** load until the skill is explicitly invoked (see [Skill-loading gotchas](#skill-loading-gotchas)). Before invocation, Claude does not hold the procedure it is supposed to follow.
- **Triggering depends on surface phrasing.** "Add express" matches the description cleanly. Hand-editing a `package.json`, a bulk refactor that happens to touch a manifest, or an *implicit* add ("add Redis caching") may never surface to the model as a dependency event worth invoking the skill for.
- **Attention drifts in long sessions.** The skill file itself ships a table of the rationalizations a model uses to talk itself out of running — "these are all well-known packages, OSV alone is enough", "25 packages is too many to audit each one individually", "the user is moving fast, I'll log later". That table exists in `skills/safer-dependencies.md` precisely because skipping is a real, observed failure mode, not a hypothetical one.
- **Nothing enforces it.** No build breaks if the skill is skipped. The audit log (Step 8) is the only durable proof the skill ran — and a skill that was never invoked writes no log, so a *skipped* run is indistinguishable from a *clean* run on later review.

A hook removes the judgment call. `PostToolUse:Write|Edit` fires in the harness after **every** manifest write — whether or not Claude thought about dependencies, whether or not the skill body was loaded, whether or not the model "felt" a package was well-known. That guarantee is the one property a skill structurally cannot provide.

### What does a skill miss that hooks catch?

Even a *perfectly* invoked skill only audits what Claude consciously routes through it: top-level packages in manifest writes it deliberately performs. Real dependency changes arrive through surfaces the model rarely reasons about as "a manifest write" — and each hook mode exists to close one of them:

| Bypass surface | Why the skill alone misses it | Hook that closes it |
|----------------|-------------------------------|---------------------|
| **Bash installs** (`npm install x@1.2.3`, `pip install ...`) | The package is fetched and its postinstall / `setup.py` scripts **execute before any manifest reasoning happens**. By the time a post-write audit could look, malicious install-time code has already run. | Pre-Install (`PreToolUse:Bash`) — denies the install *before* fetch |
| **Transitive dependencies** | The skill audits *declared, top-level* packages. The resolved tree — where the majority of real-world CVEs live — only appears in the lockfile, which a manifest-focused skill never reads. | Post-Install Scan A (`PostToolUse:Bash`) — audits freshly-written lockfiles |
| **`sed` / `jq` / script edits** | These don't go through the `Write`/`Edit` tool the skill (and the Intercept hook) reason about, so the edited manifest is never seen. | Post-Install Scan B (`PostToolUse:Bash`) — audits manifests modified by any Bash command |
| **Subagent writes** | Subagents frequently don't invoke the skill, **cannot run Bash to audit themselves** (sandboxed — anthropics/claude-code#25526), and root-session hooks do **not** fire for subagent tool calls. | Post-Agent (`PreToolUse:Agent` + `PostToolUse:Agent`) — audits what the subagent wrote after the Agent call returns |

The pattern is consistent: each hook exists because a common, legitimate way of adding a dependency bypasses both the skill *and* every other hook. The five modes are not redundancy — they are five **non-overlapping** bypass surfaces, and a skill covers none of them on its own.

### Why is automatic skill-triggering unreliable?

Three independent reasons, each grounded in how this skill is actually built:

1. **It's a classification decision, not a guarantee.** The frontmatter description is a long heuristic ("trigger before writing a manifest… or on phrases like…"). The model can reasonably read a given task as *not* matching. False negatives are inherent to any description-matched trigger — there is no code path that forces invocation.
2. **The procedure that would insist on running is gated behind the very invocation it's trying to cause.** The body that tells Claude "this is a rigid skill, run every layer on every package" does not load until the skill is invoked. The instruction can't push the model toward a decision the model has to make *before* reading it.
3. **There is no backstop.** If the model guesses wrong, nothing else runs. A hook, by contrast, fires on the tool event regardless of the model's classification — so a wrong guess costs nothing.

This is why the project treats Normal (skill) mode as the **manual / on-demand** path and the hooks as the **always-on** protection. It is also why `/safer-dependencies validate` warns when Intercept/Pre-Install are configured without Post-Install: you'd have a deterministic *top-level* check but zero *transitive* coverage.

### Why keep the skill at all if hooks are deterministic?

Because hooks and the skill do genuinely different jobs, and neither replaces the other:

- **Hooks detect and auto-correct on disk.** They rewrite a vulnerable pin, remove an abandoned package, validate a hash, and emit a signal. What they *cannot* do is read your source, refactor an import, run your tests, or decide whether a breaking major-version bump is acceptable for your project.
- **The skill is the procedure Claude follows to act on what a hook found** — locate import sites, review breaking changes, run the `VERIFY:` install/test gate, and handle `MAJOR-UPDATE-CONFIRM:` / `BLOCKED:` / `STALE:` decisions. It is also the only path for genuinely manual questions ("is django 5.0 safe?", "what's the safest current flask?") where no file is being written and there is nothing for a hook to fire on.

So the division of labor is: **the hook guarantees the check happens; the skill defines what to do about it.** Drop the skill and you get signals nobody knows how to act on. Drop the hooks and you get a procedure that runs only when the model remembers to. You need both.

One consequence worth internalizing: a signal landing in `additionalContext` does **not** auto-load the skill body (see [Skill-loading gotchas](#skill-loading-gotchas)). In a session where only hooks fire, Claude responds to the *self-describing signal text*, not the full protocol — which is why the shim's `MAJOR-UPDATE-CONFIRM:`, `BLOCKED:`, and `VERIFY:` signals are written to carry their own `ACTION REQUIRED:` instructions inline rather than assuming the procedure is in context.

---

## Architecture

### Why `PostToolUse` (post-write corrective) instead of `PreToolUse` (pre-write blocking) for the manifest path?

The Write/Edit hook fires after Claude's Write/Edit completes. The shim reads the just-written file from disk, rewrites vulnerable versions in place, and emits signals. This is called "Shape C — post-write corrective" in `skills/safer-dependencies.md`.

> **Note:** the project _does_ use a `PreToolUse:Bash` hook for the
> separate Pre-Install Mode (`safer-dependencies-pretooluse-bash.sh`).
> Bash installs (`npm install lodash@4.17.20`, `pip install urllib3==1.24.1`)
> are blocked before fetch. The reasoning below is specifically about why
> `PreToolUse:Write|Edit` was rejected for the *manifest* path — different
> tradeoffs apply to Bash because the install hasn't happened yet and
> there is no alternate corrective path, while a manifest write has
> already produced the canonical source of truth that the post-write
> shim can edit.

Four reasons `PreToolUse:Write|Edit` was rejected:

1. **Non-blocking, crash-resilient.** `PostToolUse` hooks always exit 0. If Python crashes, network is down, or the shim times out, the write still lands. With `PreToolUse` exit-code-2 blocking: a shim crash = the developer can't write the file at all, a 30-second OSV timeout = Claude is frozen for 30s per manifest edit.

2. **Latency budget.** `PostToolUse` runs asynchronously relative to the user's perception. A `PreToolUse` blocking design would stop the write for the full audit duration (2–5s × N packages) — a 20-package manifest could block 40–100s.

3. **Simpler shim architecture.** Post-write: `read file → modify in place → emit signal`. Pre-write content-rewriting would require intercepting the proposed content, transforming it, and returning modified content as stdout JSON — a bigger rewrite, using a newer and less-tested Claude Code hook shape.

4. **Corrective UX > blocking UX.** Claude sees `UPDATED: rack 2.0.1 → 2.2.23` and knows exactly what the new state is. A blocking flow would force Claude to re-decide, re-issue a Write, wait for re-audit — more round trips, slower convergence.

**The tradeoff:** a brief window (~1–5s) where a vulnerable version sits on disk before correction. If the shim crashes mid-audit the uncorrected version persists. Flagged for future reconsideration.

**Common misconception:** `before:Write` is **not** a real Claude Code matcher syntax. Claude Code uses `PreToolUse`/`PostToolUse` with a separate `matcher` field specifying the tool name. If you see `before:Write` in older docs or examples, it's from a design phase that was never implemented.

---

## Security check decisions

### Why aren't package signatures cryptographically verified (PGP, npm classic, gem `.sig`, Maven `.asc`)?

We check **presence** of signature files (via `safedep.signatures`) but deliberately do not do full cryptographic verification. Honest assessment, supported by real adoption data:

- **npm classic signatures:** under 1% of packages are signed. A hard warning on "unsigned" fires for 99% of normal packages — pure noise.
- **Ruby gem signing:** same story, under 1% adoption. The shim checks for `.sig` presence in the gem archive and emits a `LOW` advisory when missing — rare enough to be informational.
- **Maven Central PGP:** 100% of published artifacts have `.asc` files, so the shim emits a `MEDIUM` advisory when one is missing (because the absence is unusual). Client-side PGP verify would require the signer's public key in a local keyring, which is almost never configured — we'd get a `verify-failed` outcome on >95% of otherwise-fine packages.
- **Legacy PyPI GPG:** PyPI removed GPG support in 2023.

Full cryptographic verification would be slow (keyring fetches, signature downloads), noisy, and would verify authenticity (came from whom) rather than safety (is this code malicious) — a stolen npm token + signed publish = signed malware. Signatures are an install-time integrity concern, not a decision-time safety concern.

**What we do instead for Layer 4:**
- PyPI hash-pin validation when `requirements.txt` uses `--hash=sha256:...`.
- Signature-presence checks for Maven `.asc` and RubyGems `.sig` via `safedep.signatures` — presence only, not a crypto verify. The Maven check is a cheap HEAD request against the `.asc` URL; the RubyGems check downloads the full `.gem` archive and inspects its tar members for signature files.
- npm provenance attestation detection is planned for a future release.

### Why is typosquat detection a `TYPOSQUAT-CONFIRM:` prompt instead of a `BLOCKED:` removal?

False-positive rate. Typosquat detection uses edit distance against a reference list of ~40 well-known packages per ecosystem, guarded by download-count popularity so only suspicious packages reach the signal. A distance of 1–2 edits catches real typosquats (`lodahs` vs `lodash`) but also produces false positives:

- Legitimate forks with small name variations
- Parody / joke packages that are deliberately named close to famous ones
- Packages that share a common prefix with a famous one but are independent (`express-fileupload` vs `express`)
- Typosquat reference list is limited — an unusual package name similar to one NOT on the reference list won't be flagged

`BLOCKED:` would remove the package from the manifest on disk, forcing the developer to deal with a false positive every time. `TYPOSQUAT-CONFIRM:` preserves the manifest, tells the developer "verify intentional before proceeding," and lets them keep the package if it's legitimate. (At one point the signal was emitted as `WARNING:` — the rename was purely so the parent agent could disambiguate developer-confirmation prompts from pure-informational warnings.)

### Why do abandoned/no-safe-CVE packages get `BLOCKED` (removed from manifest) instead of flagged with a comment?

The `BLOCKED` path is reserved for situations where **there is no safe option** and continuing to use the package is a known-bad outcome:

- **Abandoned** (`paperclip`, `request`, `dgrijalva/jwt-go`): the package has been declared end-of-life by its maintainer. No upstream fixes will come. Keeping it in the manifest means knowingly shipping unmaintained code.
- **No-safe-CVE-version** (all versions have known exploits): there is no clean version to downgrade or upgrade to.

**Staleness is not in this list.** A package with no release in 2+ years may or may not be abandoned, so the shim treats it as advisory: it emits a `STALE:` signal and leaves the manifest entry in place. Only explicit abandonment (the curated `KNOWN_ABANDONED` list) or a no-safe-version situation triggers removal.

For these cases, leaving the entry in the manifest with a comment would be passive — the developer might not notice, Claude might not re-examine. Removing the entry forces a decision: find an alternative, explicitly pin with a risk acknowledgement, or remove the feature that needs the package. The shim's removal is a pro-active nudge, not a punishment.

### Why does the 7-day cooldown have an exception for OSV-verified security fixes but not for release-notes claims?

The 7-day cooldown exists to give new versions time to be vetted by the community before they're trusted. A version published yesterday hasn't had time for security researchers, Dependabot, or OSV to catch any issues that shipped with it.

But there's one case where a < 7 day version is demonstrably safer than the current pin: when OSV's own advisory for the vulnerability currently in the manifest explicitly lists the new version as the fix. In that case the evidence source is the *same authoritative source* the shim already trusts to identify the CVE. Extending that trust to OSV's fix-version field adds no new trust boundary.

Release-notes evidence ("this version fixes CVE-X" in a changelog or GitHub Release body) is deliberately **not** accepted, even though it would catch a small additional window of legitimate fresh fixes that OSV hasn't yet ingested. Two reasons:

1. **Forgery.** Release-notes text is authored by whoever published the version. A compromised publisher account — a recurring attack vector on npm and PyPI — can include a believable CVE-fix string in release notes for a malicious version. An attacker pulling this off gets the shim to auto-install malware against users whose only protection is the 7-day cooldown.

2. **Unengaged-developer threat model.** The skill is designed for developers who rely on the shim to keep them safe without having to reason about library provenance per-package. A prompt asking them to confirm a fresh-fix candidate would be security theater in that audience — it would be clicked through without examination. The safer default is to auto-apply only what OSV's machine-readable data can vouch for, and leave the rest BLOCKED until either OSV ingests the advisory or a more engaged user manually intervenes.

The cost of excluding release-notes evidence is the OSV-ingestion lag: typically hours, sometimes up to a day. During that window, a legitimate fresh fix is BLOCKED rather than auto-applied. The vulnerable version is still removed from the manifest, so the user doesn't stay running the CVE — they just don't yet have the fix. Net protection is not worse than the pre-exception behavior.

Implemented in `pick_safe_version` via `_candidate_is_osv_stated_fix` (see `skills/safer-dependencies-shim.sh`). Signal shape is unchanged — `UPDATED:` is reused because the trust level is identical to the existing UPDATED path.

---

## Scope and coverage decisions

### Why doesn't Go get the first-publish age check?

Technical limitation, not a design choice.

The Go module proxy (`proxy.golang.org`) has no bulk listing endpoint that includes publication dates. For npm / PyPI / RubyGems / Maven, a single registry response enumerates every version with timestamps — we compute `min(all dates)` to get the package's first-ever publish. For Go, finding the earliest version would require fetching `@v/<version>.info` for every version individually — 50–200 HTTP requests per package — blowing the 60-second hook budget.

Until there's a better Go source for first-publish data, the Go path no-ops on this check. CVE, staleness, abandoned, and manifest-rewriting checks all work normally for Go.

### Why does the GitHub repo age check only fire when first-publish has already flagged the package?

GitHub API rate limits.

Unauthenticated GitHub API requests are capped at 60 per hour per IP. A manifest with 20 new packages could burn the full budget on a single hook invocation, rendering subsequent checks in the same session useless. Making the GitHub check conditional — it only runs when first-publish has already flagged a package as young (< 30 days) — limits GitHub API usage to the few packages that are actually suspicious.

The threshold (30 days for the repo) is deliberately the same as for first-publish. A package first published 10 days ago that claims a GitHub repo 5 years old is less worrying than one whose repo is also 10 days old — the latter is a stronger signal of fresh supply-chain setup.

### Why these specific thresholds — 7 days, 30 days, 730 days?

Each threshold is calibrated for a specific concern:

| Threshold | Check | Rationale |
|---|---|---|
| **7 days** | Cooldown (Layer 2) | Community vetting window. A version published < 7 days ago hasn't had time for security researchers, dependabot, or OSV to catch issues. Too aggressive would exclude every newest-version; too lax would ship brand-new CVE-laden releases. |
| **30 days** | First-publish age (advisory) | "New package" threshold. Packages less than 30 days old as a whole project (not just as a new version) are too fresh to have build up reputation — common supply-chain attack vector is a typosquat published recently. |
| **30 days** | GitHub repo age (advisory, conditional) | Same as first-publish. A brand-new repo backing a brand-new package is a stronger signal than either alone. |
| **730 days (2y)** | Staleness → advisory `STALE:` signal | "Likely unmaintained." Two years with no releases doesn't prove abandonment, but it means the absence of any security updates during that window. Advisory only — the manifest entry is left in place. |

These are defaults. If a project needs different thresholds, the relevant constants in `skills/safer-dependencies-shim.sh` are `AGE_GATE_DAYS`, `FIRST_PUBLISH_THRESHOLD_DAYS`, and `GITHUB_REPO_THRESHOLD_DAYS` — plain integers near the top of the embedded Python. The staleness window is different: `STALENESS_THRESHOLD_DAYS` is imported from `safedep.staleness` and can be overridden at runtime via the `SAFE_DEP_STALE_YEARS` environment variable (a number of years).

---

## Sandbox and subagent limitations

### Do the hooks run inside subagents?

No. PostToolUse and PreToolUse hooks fire only for the **root session** — the top-level Claude Code process where the hooks are registered in `~/.claude/settings.json`. When the root session dispatches a subagent via the Agent tool, the subagent runs in a separate execution context. Any Write, Edit, or Bash calls the subagent makes do not trigger the hooks.

This means **all three original hooks have a subagent blind spot**:

| Hook | What it covers | What it misses |
|------|---------------|----------------|
| `PostToolUse:Write\|Edit` (shim) | Root session manifest writes | Subagent manifest writes |
| `PreToolUse:Bash` | Root session `npm install pkg@ver` | Subagent Bash install calls |
| `PostToolUse:Bash` | Root session post-install lockfile audit | Subagent post-install state |

**PostToolUse:Agent closes this gap** — see the next entry.

### How does PostToolUse:Agent close the subagent hook gap?

The `PreToolUse:Agent` + `PostToolUse:Agent` hook pair (`safer-dependencies-pretooluse-agent.sh` and `safer-dependencies-posttooluse-agent.sh`) audits whatever the subagent wrote, after the Agent call returns in the root session.

**Sentinel approach:** `PreToolUse:Agent` touches `/tmp/.safer-deps-agent-<PPID>-<session_id>.sentinel` (falling back to `/tmp/.safer-deps-agent-<PPID>.sentinel` when no session id is available) immediately before dispatch. `PostToolUse:Agent` finds manifests and lockfiles newer than that sentinel, audits each via the existing shim, and emits findings as `additionalContext` to the root session's next turn.

**What's covered:**

| Subagent action | Covered? |
|-----------------|----------|
| Writes any manifest (`package.json`, `Gemfile`, `requirements.txt`, ...) | ✅ |
| Runs `npm install` / `bundle install` / `poetry install` (lockfile written) | ✅ |
| Nested subagent writes (agent A dispatches agent B) | ✅ — root PostToolUse fires after all of A's work, including B's writes, is on disk |
| Global `npm install -g` (no manifest/lockfile written) | ❌ — nothing to scan |

**Installation:** see the `Post-Agent Mode` section in `skills/safer-dependencies.md` for the `settings.json` snippet.

**Reactive, not preventive:** PostToolUse:Agent fires after the subagent has already finished. The pre-dispatch HARD GATE (`Pre-dispatch requirement for orchestrators` section in the skill doc) remains the preventive control. Use both for full coverage.

### What should I do when using subagents?

**Preventive (always required):** Run Normal-mode Steps 1–8 in the root session for any manifest the subagent will write or modify, *before* dispatching. See the "Pre-dispatch requirement for orchestrators" HARD GATE in `skills/safer-dependencies.md`. This ensures the starting manifest is clean before the subagent touches it.

**Reactive safety net:** Install the PostToolUse:Agent hook pair. After each Agent call returns, the hook scans for manifests and lockfiles changed during that agent's run and surfaces findings to the root session's next turn.

### Can sandboxed subagents run the audit themselves?

Not directly. Subagents in sandbox mode cannot run Bash commands, so they cannot invoke the shim. The PostToolUse:Agent hook runs in the **root session**, so it is unaffected by sandbox restrictions — findings surface correctly regardless.

Non-sandboxed subagents (full Bash access) can also invoke the shim directly:

```bash
echo '{"tool_input":{"file_path":"package.json"}}' | bash ~/.claude/skills/safer-dependencies/shim.sh
```

### Does bypassPermissions bypass security checks?

No. `bypassPermissions: true` mutes tool-call permission prompts for the root session only — it does not disable the hooks, and signal text (MAJOR-UPDATE-CONFIRM, BLOCKED, STALE, VERIFY) still lands in the agent's `additionalContext`.

What does change is how `MAJOR-UPDATE-CONFIRM` is processed. In an interactive session the orchestrator pauses and asks the developer. In an autonomous session (`bypassPermissions` with no expected human turn — batch instructions, CI-assisted work) no human is coming to answer, so the orchestrator falls back to a deterministic rule: default to implicit YES at the minimum tier (bump the manifest pin, include the CVE id in the commit message, mark the full migration as pending), unless an explicit earlier deferral on record overrides as NO (skip-file entry + `CVE-DEFERRED:` commit-message tag). Silent inaction is not a valid NO. Full rule in `skills/safer-dependencies.md` under "Autonomous-session rule" and the table in `references/execution-contexts.md`.

### Why are my audit log queries returning no results?

The log is monthly-rotated. On a **fresh install** querying `~/.claude/safer-dependencies-audit.log` (no date suffix) returns empty because that file does not exist — use the current month's file instead:

```bash
# Current month
jq '.' ~/.claude/safer-dependencies-audit-$(date +%Y-%m).log

# List all months on disk
ls ~/.claude/safer-dependencies-audit-*.log

# Search across all months
cat ~/.claude/safer-dependencies-audit-*.log | jq 'select(.findings | length > 0)'
```

#### Upgrade case: the legacy file may exist for installs from before 2026-04-30

A 2026-04-30 change introduced monthly rotation. Before that the shim wrote every audit entry to the single non-suffixed file `~/.claude/safer-dependencies-audit.log`. **If you upgraded the installed shim across that boundary, you have months of entries stranded in the legacy file while month-suffixed queries miss them.**

Check whether you have a legacy file with content:

```bash
ls -l ~/.claude/safer-dependencies-audit.log 2>/dev/null && \
  wc -l ~/.claude/safer-dependencies-audit.log
```

If it exists and is non-empty, run the one-time migration helper to fold its entries into the new month-suffixed files (existing month-file content is preserved; the legacy file is renamed to `…audit.log.migrated`, never deleted, so you keep evidence):

```bash
# Inspect what would happen first
python3 ~/.claude/skills/safer-dependencies/scripts/migrate_legacy_audit_log.py --dry-run

# Apply the migration
python3 ~/.claude/skills/safer-dependencies/scripts/migrate_legacy_audit_log.py
```

The script is idempotent — running it a second time finds no legacy file and exits 0 silently. Source: [`skills/scripts/migrate_legacy_audit_log.py`](skills/scripts/migrate_legacy_audit_log.py).

---

## Skill-loading gotchas

### Does the skill's response protocol automatically load when the hook fires?

**No.** This was verified empirically in live-session testing (no checked-in test exercises it — the full loading-behavior report lives in session transcripts, not in the test suite). The hook system and the skill system are independent in Claude Code:

1. **At session start:** only skill names + frontmatter descriptions load into the available-skills catalog. The SKILL.md body does not load.
2. **When the hook fires:** the shim emits signals as `system-reminder` context. This does NOT trigger the associated skill to load.
3. **When Claude invokes the Skill tool** (auto-trigger from the description, or programmatic invocation): the SKILL.md body loads as a tool result. Sibling supplementary files do NOT auto-load.
4. **When Claude Reads the SKILL.md file:** it enters context via the normal Read tool result.

**Practical implication:** in a fresh session where the hook fires but the skill is never explicitly invoked, Claude responds to signals based on:
- The signal text itself (mostly self-describing for `UPDATED:` / `CLEAN:`)
- The skill's one-line description in the available-skills catalog
- Training knowledge

But it will **not** have the protocol content from SKILL.md — including the HARD GATE subagent-scan requirements, the 3-tier VERIFY failure classification, or the Subagent Orchestration passthrough block.

### Mitigations if you rely on the protocol

- **Invoke the skill once at session start** — any explicit Skill-tool invocation (e.g. ask Claude to audit a known-good package like "check that lodash@4.17.21 is safe") loads the SKILL.md body into context and it stays cached for the remainder of the session.
- **For CI / autonomous sessions** — include an explicit skill invocation in the opening prompt so the protocol is loaded before any manifest writes trigger signals.
- **Keep signal text self-describing** — the shim's `MAJOR-UPDATE-CONFIRM:` and `BLOCKED:` signals already include `ACTION REQUIRED:` lines with short protocol hints. That guidance is embedded in the signal itself, not dependent on SKILL.md being loaded.
