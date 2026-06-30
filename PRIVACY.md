# Privacy & Data-Egress Statement

This document describes exactly what data leaves your machine when `safer-dependencies` runs, and what does not. It is a companion to [SECURITY.md](SECURITY.md) (vulnerability disclosure) and [CAPABILITIES.md](CAPABILITIES.md) (defensive scope).

## TL;DR

- **No telemetry.** This tool does not phone home. There is no analytics endpoint, no usage tracking, no install ping.
- **What is sent:** package names + version strings to public package registries and the OSV vulnerability database. That's it.
- **What is never sent:** the contents of your manifest or lockfile, your source code, file paths, environment variables, credentials, or any identifier of you, your machine, or your project.
- **All traffic is HTTPS** with system-trusted certificate verification (no `verify=False`).
- **Logs stay local.** A JSONL audit log is appended to `~/.claude/safer-dependencies-audit-YYYY-MM.log` (one file per calendar month) — override the full path with `$SAFE_DEP_AUDIT_LOG`. It is never transmitted. Installs from before 2026-04-30 may have a non-suffixed legacy file at `~/.claude/safer-dependencies-audit.log`; see the FAQ section "Why are my audit log queries returning no results?" for the one-time migration helper that folds it into the rotated layout.

## Network endpoints contacted

The tool issues outbound HTTPS requests to the following endpoints. Each row lists the host, the purpose, and what is sent in the URL or request body.

| Host | Purpose | Data sent |
|---|---|---|
| `api.osv.dev` | Vulnerability lookup (OSV) | Package name, version, ecosystem (POST JSON, single + batch) |
| `registry.npmjs.org` | npm package metadata | Package name in URL path |
| `api.npmjs.org` | npm download statistics (popularity heuristic) | Package name in URL path |
| `pypi.org` | PyPI package metadata | Package name (and version, for hash lookups) in URL path |
| `pypistats.org` | PyPI download statistics (popularity heuristic) | Package name in URL path |
| `rubygems.org` | RubyGems metadata + gem download (signature verification) | Package name + version in URL path |
| `search.maven.org` | Maven Central search API | Package coordinates as Solr query string |
| `repo1.maven.org` | Maven artifact + GPG signature fetch | Package coordinates in URL path |
| `proxy.golang.org` | Go module proxy (version list + info) | Module path + version in URL path |
| `crates.io` | Rust crate version/metadata lookups | Crate name in URL path |
| `api.github.com` | GitHub repo metadata + ruby-advisory-db lookup | `owner/repo` and path in URL |
| `raw.githubusercontent.com` | rubysec/ruby-advisory-db YAML files | Package path in URL |

If any of these calls fail, the tool **degrades to "inconclusive"** for that check, records a `WARNING` in the audit log, and does **not** mark the package safe. See [CAPABILITIES.md](CAPABILITIES.md) for fail-mode behavior.

## What is NOT sent

The tool does **not** transmit any of the following, anywhere:

- Manifest or lockfile **contents** (only extracted package@version pairs are queried)
- Project file paths, repository URLs, or directory structure (the audit log records absolute paths *locally*; nothing is uploaded)
- Source code
- Environment variables (with the single exception below)
- Operating-system identifiers, hostnames, MAC addresses, machine IDs
- Email addresses, usernames, or any contributor identity
- Telemetry beacons, install pings, error reports, crash dumps

### Environment-variable exception

`GITHUB_TOKEN` (or `GH_TOKEN`) is read from the environment **if and only if** present, and used solely as a `Bearer` token in the `Authorization` header to `api.github.com` requests. This raises GitHub's anonymous rate limit (60/hour) to the authenticated limit (5000/hour). The token is never logged, printed, or sent to any host other than `api.github.com`. Source: `skills/scripts/safedep/github.py`.

If you do not set `GITHUB_TOKEN`, the tool functions normally with the lower rate limit.

## Local data the tool writes

| Path | Purpose | Configurable |
|---|---|---|
| `~/.claude/safer-dependencies-audit-YYYY-MM.log` | JSONL audit log — one entry per hook invocation; records ecosystem, packages checked, findings, file path. Monthly-rotated (UTC year-month suffix) and size-rotated when files exceed `SAFE_DEP_LOG_MAX_BYTES` (default 10 MiB). | `$SAFE_DEP_AUDIT_LOG` overrides the full path (date suffix is not appended); `$SAFE_DEP_LOG_MAX_BYTES` tunes the size cap (set to `0` to disable size rotation). |
| `~/.cache/safe-dep/lookups.json` | Persistent cache of registry lookups (24h OSV TTL, 6h version TTL, 7d negative TTL) | `$SAFE_DEP_CACHE_DIR`, `$XDG_CACHE_HOME` |
| `~/.cache/safe-dep/.lookups.lock` | POSIX advisory lock for cache writes | (same dir as cache) |

The audit log records absolute project paths so that you (the user) can correlate audit entries to manifests. **It does not record manifest content.** If your environment requires log-data minimization (e.g. multi-tenant CI), set `$SAFE_DEP_AUDIT_LOG` to a per-tenant location, or set `$SAFE_DEP_REDACT_PATHS=1` to replace the `file` field with a deterministic hash token.

Audit log files are created with `0600` permissions (owner read/write only), and existing log files are tightened to `0600` on the next write — a dependency inventory should never be readable by other local users via a permissive umask.

Two further opt-in redaction policies (both degrade stats and regression detection for the affected entries, by design):

- `$SAFE_DEP_REDACT_CVES=1` — vulnerability identifiers (`CVE-…`, `GHSA-…`, `PYSEC-…`, `RUSTSEC-…`, `GO-…`, `OSV-…`) in log entries are replaced with `<redacted-cve>`.
- `$SAFE_DEP_REDACT_PACKAGES=<regex>[,<regex>…]` — package names fully matching any pattern (e.g. `internal-.*,@corp/.*`) are replaced with a deterministic hash token across all entry fields, keeping private package names out of the log.

The audit log is rotated by month (UTC year-month suffix) and additionally by size — when a file exceeds `SAFE_DEP_LOG_MAX_BYTES` (default 10 MiB), it is renamed with a `.<n>` suffix and a fresh file is opened. Set `SAFE_DEP_LOG_MAX_BYTES=0` to disable size rotation.

## No telemetry — verification

The audit confirmed the absence of telemetry by:

1. Searching all Python and shell source for analytics SDKs, telemetry endpoints, beacon URLs, and HTTP POSTs to non-registry hosts. **None found.**
2. Confirming every outbound HTTPS call resolves to a host in the table above.
3. Confirming the audit log is append-only to a local file with no network sink.

You can verify yourself by running:

```bash
grep -rE 'https?://' skills/ | grep -vE 'osv\.dev|npmjs\.org|pypi\.org|pypistats|rubygems|maven|golang|github|crates'
```

The output should be empty (any matches will be in comments or example URLs in documentation).

## Air-gapped / offline use

The tool is **not designed for fully air-gapped operation** today. With no network access:

- All registry and OSV lookups fail with `HTTPLookupError`.
- Each failure is recorded in the audit log as a `WARNING:` (the package is **not** marked safe).
- The hook returns success (does not block writes) so your session continues, but the audit value approaches zero.

Air-gapped operation against an internal mirror (e.g. Artifactory) is **not yet supported** but is a reasonable feature request — open an issue with your mirror's URL pattern.
