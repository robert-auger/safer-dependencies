# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/).

## Versioning policy

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

## [Unreleased]

## [0.6.1] - 2026-08-31

### Changed
- README restructured: the "How it works" mode walkthrough (all five mode
  subsections) now follows "Warning levels", with the Contents list reordered
  to match; a new "Changing the cooldown period" section under Install
  documents `config set cooloff.days` / `cooloff.mode`, the
  `SAFE_DEP_COOLOFF_*` environment overrides, and the cooloff caveats
  (off-mode selection, CVE-fix bypass, Maven/Go not gated). (#98)

## [0.6.0] - 2026-08-16

### Added
- **New `remediate` command (and `validate --fix`)** — removes the over-broad
  rule from the global and current-project `settings.json` on demand, run by the
  already-installed tool. This is the dependable one-step remediation and the
  only path that reaches the cross-scope case (rule in one scope, tool invoked
  from another). It only ever touches a `settings.json` that exists, parses, and
  actually contains the rule — it never scaffolds a scope, never rewrites a
  malformed file, and never touches `permissions.deny`; it backs up to
  `settings.json.bak` and writes atomically. `validate`'s guidance was corrected
  (a plain update cannot remove the rule on the upgrade that delivers the fix).

### Fixed
- **The issue #3 permission migration now self-heals via the marker in
  `settings.json`, not the installed version.** Earlier releases gated removal of
  the over-broad `Bash(curl -s --max-time 10 *)` rule on the installed version,
  so upgrading `0.5.1 → 0.5.2` with the plain updater left the rule in place: the
  update is performed by the pre-update code (which never runs the new removal
  logic), and once on a post-0.5.1 version the version gate could never fire
  again. The migration now triggers on the **presence of that exact rule**, so
  any install still carrying it is cleaned up on the next install/update that
  runs the fixed code. (Consequently, a newer install that still carries the
  marker is now remediated too, where before it was left untouched.)
- **pnpm v6–v8 lockfiles: peer-dependency'd packages are now vulnerability-scanned.**
  The lockfile parser dropped every package that declares peer dependencies
  (`react-dom` and much of the React / Babel / ESLint ecosystem) from pnpm
  v6/v7/v8 lockfiles, so a vulnerable pinned version of such a package was never
  sent to the OSV/CVE audit. The parser now handles the `(peer@ver)` context
  suffix that pnpm puts on `packages:` keys. A detection false negative on
  everyday `pnpm install` output — no attacker or crafted input involved.
- **A command substitution no longer disables the pre-install audit.** A
  `$(…)` / backtick anywhere in a package-manager command (e.g.
  `pip install requests==2.6.0 --target "$(pwd)/vendor"`) caused the whole
  command to be skipped, so concretely-pinned versions were never checked before
  install. The auditor now audits the concrete pins and defers only the
  individual operands whose identity is itself a substitution
  (e.g. `pip install $(cat reqs.txt)`), surfacing a note for those. Another
  honest-path detection false negative.
- **A "project"-scope install run from the home directory no longer corrupts
  the global `settings.json`.** With `cwd == $HOME`, the "project" `.claude/`
  directory *is* the global `~/.claude/`, so a project-scope install or update
  wrote `${CLAUDE_PROJECT_DIR}`-relative hook paths into the global settings
  file — and those paths fail to resolve in every other project, silently
  breaking the hooks everywhere else. The installer now detects the collision
  and coerces the install to the global scope (with a printed notice and a
  machine-readable `coerced_scope` result flag), and scope enumeration
  (validation, remediation, config detection) treats the single directory as
  one scope instead of two. Already-corrupted installs self-heal on their next
  install or update run, which strips the broken entries and rewrites them
  against `${HOME}`.
- **The docs no longer claim `curl`, `npm view`, and `pip-audit` are
  pre-approved.** README's Configuration section and GETTING-STARTED still
  described the pre-0.5.2 permissions allowlist; they now describe the Safer
  profile that 0.5.2 actually ships (the exact-form `npm audit` /
  `bundle audit` rules; `curl` is never pre-approved, and `npm view` /
  `pip-audit` are opt-in via the Convenience profile). The README intro also
  no longer overstates the Intercept hook as blocking before the write — it
  corrects the manifest on disk right after the write lands (Shape C), and
  the intro now says exactly that.

### Changed
- **README and GETTING-STARTED reworked for first-time users.** Clearer intro,
  a real "Getting started" section with a working TOC link, an everyday-use
  note in GETTING-STARTED §4 describing the automatic flag-and-upgrade
  behavior, and a platform note in README and INSTALLATION (hands-on testing
  to date on macOS and Windows; Linux exercised by the automated CI matrix).

## [0.5.2] - 2026-07-06

### Security
- Hardened the `settings.json` permission allowlist safer-dependencies asks
  Claude Code to pre-approve — reported by [@karlkfi](https://github.com/karlkfi)
  (thank you). Removed the previously suggested overly-broad `Bash(curl -s --max-time 10 *)` rule (its
  trailing `*` pre-approved curl to any host — an unattended exfiltration path),
  along with the `npm view`, `pip-audit`, `gem fetch`, and `dependency-check`
  wildcards, and pinned `npm audit` / `bundle audit` to their exact read-only
  forms.
- The installer now writes a minimal **Safer** default; `INSTALLATION.md`
  documents an opt-in **Convenience** profile (`npm view` / `pip-audit` /
  `gem fetch`) with the security trade-offs spelled out.
- **Existing installs are remediated.** On install or update, the
  previously-recommended broad rules are removed from your `settings.json` —
  matched exactly, and only when the old broad `curl` rule is present and the
  installed version is at or below the last vulnerable release (clean and newer
  installs are left untouched). A fresh install or interactive re-install shows a
  one-time opt-in prompt (**[R]** remove / **[K]** keep) listing exactly what it
  will change; `update` auto-remediates and prints a notice of what it removed.
  The edit is written atomically, and the prior `settings.json` is copied to
  `settings.json.bak` first, so any change is fully recoverable.

### Fixed
- `checks.signatures = "block"` and `checks.first_publish_age = "block"` now
  actually escalate to `BLOCKED:` (manifest entry removed), matching the
  documented tier-semantics table in `skills/references/configuration.md`.
  Previously `block` silently behaved identically to `warn` for these two
  checks — every other check (`cve`, `abandoned`, `typosquat`, `existence`,
  `stale`) already escalated correctly.

## [0.5.1] - 2026-07-03

Documentation release: the docs were simplified and reorganized so that each
topic lives in exactly one place.

### Added
- **GETTING-STARTED.md** — a short zero-to-installed guide (prerequisites,
  interactive install, verification, everyday use), linked as the first item
  in the README and shipped in both the public repo and the self-update bundle.

### Changed
- **Documentation simplified and reorganized.** INSTALLATION.md is now the
  single source of truth for install mechanics: the Bash permissions allowlist
  became a first-class section with rationale (and an explicit step in the
  manual install options, which previously omitted it), and the uninstall and
  update instructions moved there from the README. The README shrank to an
  overview with pointers, with Configuration nested under Install. The
  versioning policy moved from the README into this changelog.
- `release.yml` workflow actions bumped to current versions (Dependabot).

### Fixed
- INSTALLATION.md manual install options no longer instruct deleting the
  source clone before the Post-Agent hooks section copies its two scripts
  from it — following the guide top-to-bottom previously failed at that step.
- Docs now state precisely that the interactive installer writes the six core
  permission-allowlist entries; the full block in INSTALLATION.md remains the
  complete manual set.
- README "Supported ecosystems" table gained the missing PHP (Composer) row.

## [0.5.0] - 2026-06-30

Initial public release under
[github.com/robert-auger/safer-dependencies](https://github.com/robert-auger/safer-dependencies).

### Added
- Hardened self-updater: `safer-dependencies update` copies new skill/hook files without executing them, logs the operation to the audit trail, and supports `--check` (dry-run diff) and `--rollback` (restore previous version). Trust model and signing posture documented in [SECURITY.md](SECURITY.md).
