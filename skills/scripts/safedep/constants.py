# SPDX-License-Identifier: LicenseRef-safer-dependencies-1.0
# See the LICENSE file at the repository root for the full terms.
"""Centralized magic constants used across the safer-dependencies tool.

Closes audit finding F-20: previously these values were duplicated across
resolve_npm.py, resolve_pypi.py, resolve_rubygems.py, resolve_maven.py, and
the shim's embedded Python. Drift between copies was a real risk.

REVIEW THIS: the resolve_*.py scripts still hard-code the 7-day age gate
inline. Wiring them through this module is intentionally deferred so the
diff for finding F-20 stays focused on infrastructure (this file + an
audit-log change). A follow-up PR can land the resolve_*.py edits without
behavioral risk once this module is in place.
"""

from __future__ import annotations

import os

# ───────────────────────────── Time gates ─────────────────────────────

#: Days a package version must be public before this tool will pin to it.
#: An OSV-verified security fix is allowed through fresher (see shim.sh
#: handling of GHSA-fresh-fix). Currently still hard-coded in resolve_*.py
#: as `7`; pulling those references through this constant is the next
#: ratchet step.
VERSION_AGE_GATE_DAYS: int = 7

#: A package whose newest stable release is older than this is considered
#: STALE and blocked. Source of truth used to be staleness.py:24.
STALENESS_THRESHOLD_DAYS: int = 730  # ≈ 2 years

# ───────────────────────────── Cache TTLs ─────────────────────────────

#: How long an OSV vulnerability lookup is reused.
CACHE_TTL_OSV_SECONDS: int = 24 * 60 * 60  # 24 h

#: How long a registry version-list / metadata lookup is reused.
CACHE_TTL_VERSION_SECONDS: int = 6 * 60 * 60  # 6 h

#: How long a "package not found" / 404 result is reused.
CACHE_TTL_NEGATIVE_SECONDS: int = 7 * 24 * 60 * 60  # 7 d

# ───────────────────────────── Concurrency ─────────────────────────────

#: Default per-manifest worker count. Lockfile audits use a higher default
#: (8) because they're more I/O-heavy. Both are clamped to [1, 32].
DEFAULT_MANIFEST_WORKERS: int = 3
DEFAULT_LOCKFILE_WORKERS: int = 8
WORKER_CLAMP_MIN: int = 1
WORKER_CLAMP_MAX: int = 32

# ───────────────────────────── HTTP timeouts ─────────────────────────────

#: Per-request HTTP timeout (seconds). Shim sites use a tighter 5s to fit
#: inside the 60s hook budget; safedep.http defaults to 10s for non-hook
#: callers.
HTTP_TIMEOUT_DEFAULT_S: int = 10
HTTP_TIMEOUT_SHIM_S: int = 5

# ───────────────────────────── Hook budget ─────────────────────────────

#: Hook timeout (seconds) the project recommends in settings.json. This
#: is informational — the actual timeout is set by the user's settings.json
#: and enforced by Claude Code, not by us.
HOOK_BUDGET_RECOMMENDED_S: int = 60

# ───────────────────────────── Audit log ─────────────────────────────

#: Soft cap on audit-log size. When a write would push the log past this,
#: it gets rotated to <log>.1, then <log>.2, etc., dropping anything past
#: AUDIT_LOG_MAX_ROTATIONS.
#:
#: Override via SAFE_DEP_LOG_MAX_BYTES (set to 0 to disable rotation).
AUDIT_LOG_MAX_BYTES_DEFAULT: int = 10 * 1024 * 1024  # 10 MiB

#: Number of rotated archives kept on disk. <log>, <log>.1, …, <log>.N.
AUDIT_LOG_MAX_ROTATIONS: int = 3


def audit_log_max_bytes() -> int:
    """Effective max-bytes value, honoring SAFE_DEP_LOG_MAX_BYTES."""
    raw = os.environ.get("SAFE_DEP_LOG_MAX_BYTES")
    if raw is None:
        return AUDIT_LOG_MAX_BYTES_DEFAULT
    try:
        v = int(raw)
    except ValueError:
        return AUDIT_LOG_MAX_BYTES_DEFAULT
    return max(0, v)


def redact_paths_enabled() -> bool:
    """Whether SAFE_DEP_REDACT_PATHS is on."""
    return os.environ.get("SAFE_DEP_REDACT_PATHS", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def redact_cves_enabled() -> bool:
    """Whether SAFE_DEP_REDACT_CVES is on (issue #210).

    Replaces vulnerability identifiers (CVE/GHSA/PYSEC/RUSTSEC/…) in audit-log
    entries with ``<redacted-cve>``. Opt-in: redacting ids degrades stats and
    regression detection for the affected entries.
    """
    return os.environ.get("SAFE_DEP_REDACT_CVES", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def redact_package_patterns() -> "list[str]":
    """Comma-separated regex list from SAFE_DEP_REDACT_PACKAGES (issue #210).

    Package names fully matching any pattern are replaced with a stable hash
    token in audit-log entries (e.g. ``internal-.*,@corp/.*`` keeps private
    package names out of the log). Empty/unset → no package redaction.
    """
    raw = os.environ.get("SAFE_DEP_REDACT_PACKAGES", "").strip()
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]
