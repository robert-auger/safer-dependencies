# Security Policy

## Reporting a vulnerability

If you believe you've found a security issue in `safer-dependencies` (the skill, the hooks, the Python scripts, or anything in this repo), please **do not** open a public GitHub issue.

Instead, use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/robert-auger/safer-dependencies/security)
2. Click **Report a vulnerability**
3. Fill in the form — include reproduction steps and, if relevant, the ecosystem (npm / PyPI / RubyGems / Maven / Go / crates) and package name

You'll get an acknowledgement and the discussion stays private until a fix is ready.

### Encrypted disclosure

If GitHub's private vulnerability reporting is not acceptable for your environment (e.g. you must use PGP), open a public issue requesting a contact channel.

## Scope

In scope:
- The skill instructions in `skills/safer-dependencies.md`
- The five hook scripts in `skills/safer-dependencies-{shim,pretooluse-bash,posttooluse-bash,pretooluse-agent,posttooluse-agent}.sh`
- The Python scripts under `skills/scripts/` (including `safedep/`)
- CI configuration in `.github/workflows/`
- Documentation that describes security behavior (e.g. `PRIVACY.md`, `CAPABILITIES.md`)

Out of scope:
- Vulnerabilities in upstream packages the tool queries — report those to the package maintainer or OSV
- Issues in Claude Code itself — report to Anthropic via [their security disclosure process](https://www.anthropic.com/responsible-disclosure-policy)
- Denial-of-service from submitting malformed manifests — the tool is expected to fail open (exit 0, no rewrite) on bad input
- The defensive *limits* enumerated in [CAPABILITIES.md](CAPABILITIES.md) (e.g. "does not detect Unicode homograph attacks") — those are explicit non-goals, not bugs

## Supported versions

The **latest release and the current `main` branch** are supported. Older releases do not receive backported security fixes.

| Version | Supported |
|---------|-----------|
| `v0.5.2` (latest) | ✅ |
| `main` (HEAD) | ✅ |
| Older releases | ❌ |

## Response expectations

This is a solo-maintained project. The maintainer aims to:

- **Acknowledge** a private vulnerability report within **3 business days**.
- **Triage** (confirm or refute) within **7 business days** of acknowledgement.
- **Patch and disclose** critical issues (RCE, credential exfiltration, silent audit bypass) on a best-effort basis prioritized over feature work.
- **Coordinate** with reporters on disclosure timing — default 90 days from triage to public disclosure unless a fix lands sooner.

These are targets, not contractual SLAs. If you have not received an acknowledgement within 7 calendar days, escalate by opening a public issue **without security-sensitive details** asking the maintainer to check their inbox.

## What we treat as critical

- Remote code execution via the hook (e.g. command injection from a malformed manifest the hook touches)
- Credential exfiltration (e.g. `GITHUB_TOKEN` leaked to a non-`api.github.com` host)
- Silent audit bypass (the hook reports "clean" while a known-vulnerable package is in the manifest)
- TLS verification disabled or downgraded
- Telemetry added without an explicit `PRIVACY.md` update — see [PRIVACY.md](PRIVACY.md), the "no telemetry" claim is load-bearing

## What we treat as non-critical

- Performance regressions (unless they cause the hook to time out and silently no-op)
- False positives in typosquat or staleness detection
- Documentation errors that don't misrepresent security behavior

## Self-update trust model

`/safer-dependencies update` (and its `--check` / `--rollback` variants) fetches upstream code from GitHub over HTTPS, then applies the update by copying files into place via the **already-installed** manager. The freshly-cloned manager is never executed — only the trusted copy already on disk drives the apply step. This limits the blast radius of a compromised upstream commit to reading/writing the safer-dependencies install directory; no arbitrary code from the clone executes.

**Trust ceiling:** when you run `/safer-dependencies update`, you trust:
1. GitHub's HTTPS transport (TLS certificate chain)
2. The publishing account (`robert-auger/safer-dependencies`) not having been compromised

**Clone isolation:** the temporary clone is created in a `mkdtemp(0700)` directory — readable and writable only by the current user — and is removed when the update completes or fails.

**Tag signing is intentionally out of scope.** A bare `git verify-tag` without a pinned allowed-signer fingerprint authenticates nothing — it succeeds for any signed tag regardless of who signed it, and fails for keyless clones that downloaded a shallow archive. If tag verification is added in the future, it must pin a specific allowed-signer fingerprint and be mandatory (not advisory) when the target tag is signed. Until then, this tool makes no signing claims.

**Apply requires explicit confirmation (`--yes`).** The manager itself — not just the skill prose — refuses to clone or apply an update unless the caller passes `--yes` (alias `--non-interactive`). A bare `python3 safer_dependencies_manager.py self_update` (or `/safer-dependencies update` without a confirmed YES) resolves and previews the plan, prints the upstream trust warning, then **stops without cloning or copying anything** — it is a dry-run, not a fetch+apply. This makes the updater safe by default: a direct CLI invocation or an unconfirmed auto-trigger phrase can never silently fetch and apply upstream code. The apply path fires only when `--yes` is supplied, which happens (a) in interactive sessions after the developer confirms the previewed plan via `AskUserQuestion`, or (b) in autonomous (`bypassPermissions`) sessions per the deliberate implicit-YES rule. Use `update --check` for an equivalent dry-run preview, and `update --rollback` to restore the previous version from the automatic backup.

**Audit logging:** both an applied update and a manual `--rollback` are recorded in the audit log at `~/.claude/safer-dependencies-audit-YYYY-MM.log` as an entry with `"event": "self_update"` (queryable via `jq 'select(.event=="self_update")'`), capturing the version transition, the resolved ref/sha, the fallback flag, the per-scope outcome (global / project), and the overall status. An apply entry records the upstream ref/sha with a `status` of `success` or `error`; a `--rollback` entry sets `ref` to `backup:<stamp>`, marks every restored scope `rolled_back`, and carries `status: rolled_back`. Only `--check` (dry-run) writes no entry — it returns before auditing.

## Coordinated disclosure

If your finding affects upstream packages (a real CVE in `requests`, `lodash`, etc.), please report to the package maintainer **first**, then file with OSV. Reporting it here only helps if the issue is in *our* detection logic — e.g. "the tool fails to flag this CVE."
