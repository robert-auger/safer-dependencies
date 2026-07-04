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
