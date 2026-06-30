"""Per-ecosystem package popularity lookups.

Used by the typosquat check to suppress false positives on popular legitimate
packages whose names happen to share edit distance with a well-known package
(e.g. ``pyarrow`` vs ``arrow`` — both real, both popular).

Rationale:
  A real typosquat attack depends on the attacker's package remaining
  below the radar. Once a package accumulates meaningful adoption, the
  probability it is a typosquat drops steeply. If the candidate package
  the user is about to install has large download numbers itself, the
  shared-prefix match against a well-known package is almost certainly
  a coincidence (think ``pyarrow`` / ``arrow``, ``react-dom`` / ``react``).

This module does the lookup only. The suppression decision lives in
``safedep.typosquat`` alongside the existing edit-distance code.

Per-ecosystem endpoints and metrics (documented so callers know what they
are comparing):
  npm:       https://api.npmjs.org/downloads/point/last-week/<pkg>        (weekly)
  pypi:      https://pypistats.org/api/packages/<pkg>/recent              (last week)
  rubygems:  https://rubygems.org/api/v1/gems/<pkg>.json                  (cumulative)
  maven:     no canonical source — returns None
  go:        no canonical source — returns None

Network failure, 404, or malformed response all return None (fail-open).
The caller treats None as "no suppression signal available" and emits
the typosquat finding unchanged.
"""

from __future__ import annotations

from typing import Optional

from safedep import cache
from safedep.http import _http_get, quote_pkg


# Suppression thresholds per ecosystem. A candidate at or above the threshold
# is considered "popular enough on its own" that the typosquat match is
# almost certainly a coincidence.
#
# Tuned against known false positives:
#   - pyarrow (PyPI) has ~20M weekly downloads — threshold 10k suppresses it
#   - react-dom (npm) has ~30M weekly — threshold 10k suppresses it
#   - the fabricated ``reqests`` typo would have ~0 — stays flagged
#   - rubygems uses cumulative downloads because the v1 API does not
#     expose a weekly number; threshold 1M corresponds to "well-established"
POPULARITY_THRESHOLD = {
    "npm":      10_000,    # weekly
    "pypi":     10_000,    # last-week
    "rubygems": 1_000_000, # cumulative
}


def downloads(pkg: str, ecosystem: str) -> Optional[int]:
    """Return the ecosystem-appropriate download number for ``pkg``, or None.

    None means the number could not be determined (network failure, 404,
    malformed response, or no canonical source for this ecosystem). Callers
    should treat None as "no suppression signal" — fail-open.

    The successful count is cached on disk (``cache.get_or_compute``, keyed by
    ecosystem+package) so consecutive hook runs reuse it instead of re-hitting
    the registry. This is what keeps the popularity guard DETERMINISTIC: the
    guard is fail-closed, so without caching a transient registry outage on a
    later audit would flip a "mature" package back to STALE. ``get_or_compute``
    never caches ``None``, so a failed lookup is always retried — failures are
    never frozen in. ``SAFE_DEP_CACHE_DISABLE=1`` restores the uncached path.
    """
    if ecosystem == "npm":
        fetch = _npm_downloads
    elif ecosystem == "pypi":
        fetch = _pypi_downloads
    elif ecosystem == "rubygems":
        fetch = _rubygems_downloads
    else:
        # Go and Maven have no canonical download-count endpoint.
        return None
    return cache.get_or_compute(cache.popularity_key(ecosystem, pkg), lambda: fetch(pkg), cache.TTL_POPULARITY)


def is_popular(pkg: str, ecosystem: str) -> bool:
    """Convenience wrapper: True if ``pkg`` is known-popular in its ecosystem.

    Returns False when the ecosystem has no threshold configured or the
    download lookup fails — callers should not suppress typosquat findings
    on a fail-open path.
    """
    threshold = POPULARITY_THRESHOLD.get(ecosystem)
    if threshold is None:
        return False
    count = downloads(pkg, ecosystem)
    if count is None:
        return False
    return count >= threshold


def _npm_downloads(pkg: str) -> Optional[int]:
    data = _http_get(f"https://api.npmjs.org/downloads/point/last-week/{quote_pkg(pkg)}")
    if not isinstance(data, dict):
        return None
    value = data.get("downloads")
    return value if isinstance(value, int) else None


def _pypi_downloads(pkg: str) -> Optional[int]:
    data = _http_get(f"https://pypistats.org/api/packages/{quote_pkg(pkg)}/recent")
    if not isinstance(data, dict):
        return None
    value = (data.get("data") or {}).get("last_week")
    return value if isinstance(value, int) else None


def _rubygems_downloads(pkg: str) -> Optional[int]:
    data = _http_get(f"https://rubygems.org/api/v1/gems/{quote_pkg(pkg)}.json")
    if not isinstance(data, dict):
        return None
    value = data.get("downloads")
    return value if isinstance(value, int) else None
