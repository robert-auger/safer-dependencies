# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.0] - 2026-06-30

Initial public release under
[github.com/robert-auger/safer-dependencies](https://github.com/robert-auger/safer-dependencies).

### Added
- Hardened self-updater: `safer-dependencies update` copies new skill/hook files without executing them, logs the operation to the audit trail, and supports `--check` (dry-run diff) and `--rollback` (restore previous version). Trust model and signing posture documented in [SECURITY.md](SECURITY.md).
