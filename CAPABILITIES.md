# Capabilities

This document is the explicit enumeration of `safer-dependencies`' capabilities: what it defends against, what it does NOT defend against, the assumptions it relies on, and how the defenses compose at install time. Companion documents: [PRIVACY.md](PRIVACY.md) (data egress) and [SECURITY.md](SECURITY.md) (vulnerability disclosure).

## What the tool defends against

The tool intercepts dependency additions made by Claude Code and runs four classes of checks before unsafe code reaches your tree.

### 1. Known CVEs (OSV-listed)
- **What:** Looks up every concrete `package@version` against the [OSV](https://osv.dev) database (and ecosystem-native scanners when available — `npm audit`, `pip-audit`, `bundle audit`).
- **Confidence:** High for ecosystems OSV covers comprehensively (npm, PyPI, RubyGems, Maven, Go, crates, Packagist/PHP). PHP/Composer (`composer.json`/`composer.lock`) is CVE/staleness/existence-audited and auto-corrected like the others; note typosquat detection does *not* yet cover Packagist.
- **Limit:** Cannot detect a vulnerability that has not yet been reported to OSV (zero-days, embargoed CVEs).

### 2. Typosquats
- **What:** Detects package names within edit-distance 1–2 of well-known packages (e.g., `reqeusts` ↔ `requests`, `rubycop` ↔ `rubocop`). Emits a `TYPOSQUAT-CONFIRM:` warning; the manifest is **not modified** (you decide).
- **Confidence:** Medium. Optimized for false-negative aversion (we'd rather warn on a real package than miss an attack), so expect occasional false positives.
- **Limit:** Will not detect homograph attacks (Unicode lookalikes) or registry-impersonation attacks (e.g. a package that *is* the well-known name but has been hijacked).

### 3. Abandoned / unmaintained packages
- **What:** Two layers — (a) a hard-coded list of widely-known-abandoned packages (`paperclip`, `request`, `pycrypto`, `github.com/dgrijalva/jwt-go`, etc.) blocked instantly with a suggested replacement; (b) a 2-year staleness heuristic (`safedep/staleness.py`) that emits an advisory `STALE:` signal for any package whose newest stable release is older than 730 days (the manifest entry is left in place).
- **Confidence:** High for the curated list, medium for the heuristic (some legitimately stable packages will be flagged — see "Known false positives" below).
- **Limit:** Cannot tell you a package was *just* abandoned by its maintainer last week.

### 4. Premature versions (cooldown window)
- **What:** Refuses to pin any version published less than 7 days ago, and prefers the newest stable version published ≥7 days ago. Pre-release identifiers (`-alpha`, `-rc`, `1.0.0a1`) are excluded entirely. Exception: a fresher version is allowed through the cooldown if and only if OSV reports it as a fix for a confirmed CVE in the otherwise-preferred version.
- **Confidence:** High. This is a structural defense against typosquat-on-publish and supply-chain attacks where the bad actor has < 7 days of public exposure.
- **Limit:** A patient attacker who waits 8 days will pass this check.

### 5. Hash-pin integrity (PyPI requirements.txt)
- **What:** When a `requirements.txt` line declares `--hash=sha256:...`, the declared hash is compared against PyPI's published hashes for the named version. Mismatches emit a `WARNING:`.
- **Confidence:** High.
- **Limit:** Only covers PyPI hash-pinned lines. Does not cover `package-lock.json`, `poetry.lock`, etc. (the package manager itself enforces those).

### 6. Package existence verification
- **What:** Every concrete `package@version` is checked against the canonical registry (`registry.npmjs.org`, `pypi.org`, `rubygems.org`, Maven Central, `proxy.golang.org`). A package that isn't found in its registry emits an `UNKNOWN:` signal so the orchestrator knows Claude may have hallucinated a name or referenced an internal/private package not on the public registry.
- **Confidence:** High for public-registry packages.
- **Limit:** Cannot distinguish a hallucinated name from a private/internal package the user legitimately depends on — the user has to confirm. Network-dependent: returns inconclusive when registries are unreachable.

### 7. Signature verification (where available)
- **What:** For ecosystems where signatures are conventional (Maven Central `.asc` files, RubyGems `.sig` archives), the tool checks for the presence of a signature. Unsigned artifacts emit a `SIGNATURE:` signal at MEDIUM (Maven, where signing is standard) or LOW (RubyGems, where it's expected to be absent).
- **Confidence:** Medium — presence-only check, not a cryptographic verification of the signature itself.
- **Limit:** Doesn't cryptographically verify the signature; doesn't cover npm, PyPI, Go, or Rust (where signature conventions differ or aren't mainstream).

### 8. Regression detection (audit log cross-reference)
- **What:** When the shim is about to emit `MAJOR-UPDATE-CONFIRM:` for a package, it cross-references the audit log via `safedep.audit_log.find_prior_correction(file, package)`. If the same `(file, package)` was previously corrected to the same safe target, a `REGRESSION:` line is prepended so the orchestrator recognises the re-introduction (typical cause: a subagent wrote the manifest from a snapshot predating the correction) and restores the previously-approved version rather than re-deciding the major bump.
- **Confidence:** High when the audit log is intact and accessible.
- **Limit:** Requires a populated audit log — fresh installs or rotated-out months don't carry prior history. Doesn't detect regressions inside the same calendar month if the prior correction was rotated out.

## What the tool does NOT defend against

These threats are **out of scope** by design or by current implementation. Adopters should layer additional controls if these matter:

- **Compromised package registries.** If npm, PyPI, RubyGems, Maven, Go proxy, or OSV serve us malicious data, we trust it. (We do verify HTTPS certificates, so MITM is not in this category.)
- **Compromised OSV.** If OSV reports a vulnerable version as safe, we report it as safe.
- **Postinstall scripts.** Once a package is approved and installed, its install-time scripts run with full user privileges. This tool does not sandbox installs.
- **Runtime malicious behavior.** Static metadata (publish date, registry presence, OSV match) cannot detect what a package does at runtime.
- **Maintainer takeover.** A legitimate package whose maintainer account was compromised, where the new owner publishes a malicious version, is detected only after OSV ingests an advisory.
- **Homograph attacks.** Unicode lookalikes (e.g. Cyrillic `а` for Latin `a`) are not currently in the typosquat distance check.
- **Compromised dependencies of dependencies (transitive) outside the lockfile audit window.** We audit lockfiles when the install hook runs, but we don't continuously re-audit existing lockfiles in a watcher loop.
- **The Claude Code agent itself.** If Claude is compromised or jailbroken into emitting malicious tool calls that bypass hooks (e.g. by writing to a non-manifest path that later gets renamed), we cannot help.
- **The user's own pre-existing manifest.** When the hook fires for the first time, packages already in the manifest are not retroactively audited unless they are touched by a write/edit.
- **Ecosystems outside the audited set (Elixir, Dart, Swift, C++ Conan/vcpkg, Haskell, Crystal, Clojure, R).** Writes to `mix.exs`, `pubspec.yaml`, `Package.swift`, `conanfile.txt`, `vcpkg.json`, `cabal.project`, `shards.yml`, `deps.edn`, and `renv.lock` are *detected and flagged* with a `GAP:` signal pointing at the native auditor (`mix hex.audit`, `dart pub outdated --mode=security`, etc.) — but the tool does not run those native auditors itself. (PHP/Composer is **in** the audited set — see the ecosystem coverage section above.)
- **Air-gapped or fully-offline environments.** The tool degrades to "inconclusive" with no network — see [PRIVACY.md](PRIVACY.md#air-gapped--offline-use).
- **Denial-of-service from malformed manifests.** Per [SECURITY.md](SECURITY.md), the tool is expected to fail open (exit 0, no rewrite) on malformed input; an attacker who can write your manifest can cause an audit to silently no-op, but that attacker already has manifest write access and could just edit dependencies directly. See **[Fail mode: availability vs. safety](#fail-mode-availability-vs-safety)** below for the `closed` opt-in that turns non-adversarial audit failures (OSV unreachable, Python missing, hook crash) into a Pre-Install deny instead of a silent allow.

## Fail mode: availability vs. safety

By default every hook **fails open**: if an audit cannot be completed — OSV is rate-limited or unreachable, `python3`/the helper is missing, the hook times out, or input is malformed — the operation is allowed and a diagnostic is recorded (and also surfaced on stderr so it is never wholly silent). This favors **availability**: a broken or stressed hook never blocks your work. The cost is **safety**: a legitimately vulnerable package can slip through exactly when something is broken.

`SAFE_DEP_FAIL_MODE` (or `policy.fail_mode` in the config file) lets you choose the tradeoff:

| value | behavior when an audit cannot complete |
|-------|----------------------------------------|
| `open` (**default**) | Allow the operation; record the fail-open in the audit log and on stderr. Byte-for-byte the historical behavior. |
| `closed` | **Pre-Install (`PreToolUse:Bash`) denies** the install with an actionable message; re-run when the audit can complete, or temporarily set `SAFE_DEP_FAIL_MODE=open`. |

Resolution precedence mirrors the other policy knobs: **environment variable > project/global config file > built-in default**.

```bash
# One-off, e.g. in CI where a missed CVE is worse than a blocked job:
SAFE_DEP_FAIL_MODE=closed npm install lodash@4.17.20
```

```toml
# ~/.config/safer-dependencies/config.toml — make it the default for this user
[policy]
fail_mode = "closed"
```

**Scope of `closed` today:** it is wired into the Pre-Install Bash hook (the layer that can already issue a `deny`). The Intercept manifest-write path still fails open in `closed` mode (a visible `AUDIT-INCOMPLETE:` signal there is planned follow-up work). Even in `open` mode, all hooks now surface a fail-open on stderr, not only in the audit log.

When choosing `closed`, weigh the availability cost: a flaky network or an OSV outage will start denying installs, and the only escape is to fix the audit path or flip back to `open`.

## Assumptions

The tool's correctness depends on these assumptions. If any are violated, the defenses above degrade.

1. **OSV and registry data are accurate.** Stale or wrong upstream data → wrong decisions.
2. **System CA bundle is uncompromised.** TLS verification uses the OS-trusted root store.
3. **Python 3.9+ and Bash are present.** Hooks fail-open if not (no audit runs) — unless `SAFE_DEP_FAIL_MODE=closed`, which makes the Pre-Install hook deny instead. See [Fail mode: availability vs. safety](#fail-mode-availability-vs-safety).
4. **Hook timeout (default 60s) is sufficient.** A slow network can starve audits; the tool degrades to inconclusive but does not block the user's session.
5. **`~/.cache/safe-dep/` and `~/.claude/` are user-writable and not shared across users.** Multi-tenant deployments should redirect via `$SAFE_DEP_CACHE_DIR` and `$SAFE_DEP_AUDIT_LOG`.
6. **The 7-day cooldown and 2-year staleness threshold are calibrated to community vetting reality.** The staleness window is configurable via the `SAFE_DEP_STALE_YEARS` environment variable; the cooldown period is not configurable today (tracked as future work). `STALE:` findings are downgraded to an informational mature `NOTE:` when the pinned version is the current latest release, adoption clears the per-ecosystem popularity bar, and staleness is within 2× the threshold (`SAFE_DEP_STALE_POPULARITY_GUARD=0` disables this guard).
7. **Claude Code passes the hook payload faithfully.** The shim parses `tool_input.file_path` from the hook JSON; a hook payload that lies about the file path can cause incorrect audits. This is a Claude-Code-trust assumption.

## Known false positives

- Long-lived stable packages (e.g. `six`, `python-dateutil` at certain points) may exceed the 2-year staleness threshold despite being intentionally feature-complete. The staleness heuristic is conservative — adopters who hit a false positive should open an issue or override via the per-ecosystem disable knob.
- Typosquat detection is intentionally noisy in favor of false negatives. A package legitimately named close to a popular package will warn until a curated "known-safe-neighbor" list grows.

## How the defenses compose at install time

Five hook surfaces cover the ways a dependency can enter a project under Claude Code:

1. **Normal Mode (inline, manual)** — when invoked via the skill description ("add express", "is django@5.0 safe?"), the skill runs the full audit pipeline inline in the parent session and reports findings before any manifest edit.
2. **Intercept Mode — `PostToolUse:Write` / `Edit`** (`safer-dependencies-shim.sh`) — fires when Claude writes a manifest (`package.json`, `requirements.txt`, etc.) or a lockfile, audits the new pins, and **rewrites the manifest in place** to a safe version when one exists.
3. **Pre-Install Mode — `PreToolUse:Bash`** (`safer-dependencies-pretooluse-bash.sh`) — intercepts `pip install foo==1.2`, `npm i bar@2.0`, `gem install …`, and similar before they run. If the concrete pin is OSV-vulnerable, the install is **denied** (`permissionDecision: "deny"`) before the resolver fetches anything.
4. **Post-Install Mode — `PostToolUse:Bash`** (`safer-dependencies-posttooluse-bash.sh`) — fires after Bash commands and runs three scans: (A) after install verbs (`npm install`, `bundle install`, `poetry install`, `uv sync`, `go mod tidy`, etc.) it audits any lockfile freshly written by the resolver — catching transitive CVEs Pre-Install couldn't see (the user typed `pkg@version`, but the resolver pulled in dozens of transitives nobody named); (B) after any non-read-only command it audits freshly-modified manifests, the only fallback for edits made via `sed -i`/`jq`/scripts that bypass the Write/Edit hook; (C) after plain `pip install` (which writes no lockfile) it OSV-checks the full resolved environment.
5. **Post-Agent Mode — `PreToolUse:Agent` + `PostToolUse:Agent`** (`safer-dependencies-pretooluse-agent.sh` + `safer-dependencies-posttooluse-agent.sh`) — closes the subagent coverage gap. Modes 2–4 only fire for root-session tool calls, so any manifest a subagent writes bypasses them. The pre-hook drops a sentinel; the post-hook finds manifests/lockfiles modified during the subagent's run and dispatches them through the shim. Matters even if you never explicitly spawn subagents — many skills and slash commands dispatch them internally.

Together, these cover direct manifest edits, script/`sed`-driven manifest edits, command-line installs, transitive deps, and subagent-orchestrated writes — the common ways a vulnerable package enters a project **through Claude's `Write`, `Edit`, `Bash`, and `Agent` tools**.

**What is _not_ covered:** every hook is triggered by a Claude Code tool call, so any write that bypasses those tools entirely fires no hook and is not audited. This includes manifests written by an MCP-server tool, saves from an IDE/editor or a human typing in a separate terminal, and manifests materialized on disk by `git checkout` / `git merge` / `git stash pop`. The Post-Agent net is also reactive and mtime/sentinel-based: a subagent that writes a manifest as its final action, or whose write races the sentinel window, can slip. These are inherent to a tool built on Claude Code hooks — the coverage above is strong for the in-tool paths, not a guarantee against every channel.
