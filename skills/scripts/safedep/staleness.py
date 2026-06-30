"""Shared staleness check — a package is "stale" when its newest stable
release is older than STALENESS_THRESHOLD_DAYS (default 730 days = 2 years).

Staleness is an informational axis distinct from the first-publish-age
check in safedep.registry: first-publish-age catches packages that are
too new to trust, staleness catches packages that stopped getting
updates long ago (maintainer walked away, upstream is dead).

The version-fetch step remains the caller's responsibility — each
ecosystem has its own registry layout, and the shim already has the
per-ecosystem version-fetch helpers. This module owns the threshold
and the comparison only.

Both the shim (intercept mode) and the manual-mode skill consult this
module so the threshold is a single source of truth.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Tuple

# Re-export from the centralized constants module (audit finding F-20).
# The named constant stays exported here so existing imports keep working.
from safedep.constants import STALENESS_THRESHOLD_DAYS


def stale_threshold_days() -> int:
    """Staleness threshold in days, routed through the safedep.config oracle
    (issue #232): the SAFE_DEP_STALE_YEARS env override takes precedence over
    the policy file's ``staleness.years`` (the oracle implements that
    precedence), converted at 365 days/yr; hard fallback to
    STALENESS_THRESHOLD_DAYS if the oracle is unavailable.

    Same semantics as the shim's ``_stale_threshold_days`` (issue #190);
    shared here so the Pre-Install hook (issue #204) cannot drift from it.
    The import is lazy to keep this module free of import-time cycles.
    """
    try:
        from safedep.config import stale_years
        return int(stale_years() * 365)
    except Exception:
        return STALENESS_THRESHOLD_DAYS


def is_stale(
    newest_release_ts: datetime,
    now: Optional[datetime] = None,
    threshold_days: int = STALENESS_THRESHOLD_DAYS,
) -> Tuple[bool, Optional[str]]:
    """Classify a package as stale or not based on its newest release timestamp.

    Args:
        newest_release_ts: timezone-aware datetime of the newest stable release
            (the caller is responsible for filtering pre-releases before passing
            in the timestamp).
        now: override "current time" for deterministic testing. Defaults to
            datetime.now(tz=timezone.utc).
        threshold_days: override the staleness threshold. Defaults to
            STALENESS_THRESHOLD_DAYS (730).

    Returns:
        (True, 'YYYY-MM-DD') when the newest release is older than threshold_days.
        (False, None) when it is not.

    Raises:
        TypeError: if newest_release_ts is naive (no tzinfo). The shim and the
            skill both work exclusively with UTC-aware datetimes — a naive
            timestamp would produce wrong deltas across DST boundaries and is
            almost always a bug at the call site.
    """
    if newest_release_ts.tzinfo is None:
        raise TypeError("newest_release_ts must be timezone-aware (UTC)")
    if now is None:
        now = datetime.now(tz=timezone.utc)
    age_days = (now - newest_release_ts).days
    if age_days > threshold_days:
        return True, newest_release_ts.strftime("%Y-%m-%d")
    return False, None
