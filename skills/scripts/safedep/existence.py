"""Does this package exist in its canonical registry?

Used by both the shim and the manual-mode skill to close a silent-bypass
vector: a fabricated or mistyped package name (e.g. ``node-notifier-alt``
or ``reqeusts``) that is not registered anywhere would otherwise pass
every check — OSV has no vulns for nonexistent packages, the version
listers return empty, the staleness check has no data. Net effect: a
made-up dependency slips through unnoticed.

This module provides a single per-ecosystem lookup that answers:
  - True  — the registry returned 200 (package exists)
  - False — the registry returned 404 (package is not registered)
  - None  — the lookup could not be completed (network failure,
             timeout, non-2xx non-404 status). Callers treat None as
             "do not suppress and do not flag" — fail-open.

Only True → False requires an ``UNKNOWN:`` signal in the caller. None
means the existence question is unanswered for this invocation; later
checks may still surface CVE / staleness / abandoned findings from
cached or partial data.

The status-code approach (via ``_http_get_status``) is necessary because
the regular ``_http_get`` helper collapses both 404 and network failures
into ``None`` — losing the distinction we need here.
"""

from __future__ import annotations

from typing import Optional

from safedep.http import _http_get_status, quote_pkg
from safedep.goproxy import encode_module_path as _goproxy_encode


def package_exists(
    pkg: str,
    ecosystem: str,
    *,
    group_id: str = "",
    artifact_id: str = "",
) -> Optional[bool]:
    """Return True / False / None per the module docstring."""
    if ecosystem == "npm":
        return _status_to_verdict(
            _http_get_status(f"https://registry.npmjs.org/{quote_pkg(pkg)}")
        )
    if ecosystem == "pypi":
        return _status_to_verdict(
            _http_get_status(f"https://pypi.org/pypi/{quote_pkg(pkg)}/json")
        )
    if ecosystem == "rubygems":
        return _status_to_verdict(
            _http_get_status(f"https://rubygems.org/api/v1/gems/{quote_pkg(pkg)}.json")
        )
    if ecosystem == "crates":
        # crates.io: 404 on unknown crate, 200 with crate metadata otherwise.
        # Same endpoint family the shim's crates_versions helper uses.
        return _status_to_verdict(
            _http_get_status(f"https://crates.io/api/v1/crates/{quote_pkg(pkg)}")
        )
    if ecosystem == "maven":
        if not group_id or not artifact_id:
            return None
        url = (
            f"https://search.maven.org/solrsearch/select?"
            f"q=g:{group_id}+a:{artifact_id}&core=gav&rows=1&wt=json"
        )
        # Maven Central always returns 200 even for missing artifacts;
        # numFound in the response body is the real signal. Use the JSON
        # helper here instead of status.
        from safedep.http import _http_get  # local import, used only by maven path
        data = _http_get(url)
        if not isinstance(data, dict):
            return None
        response = data.get("response")
        if not isinstance(response, dict):
            return None
        num_found = response.get("numFound")
        if isinstance(num_found, int):
            return num_found > 0
        return None
    if ecosystem == "go":
        # proxy.golang.org: 404 on unknown module, 200 with plain-text
        # version list on known module. Some modules have no tagged
        # versions, in which case @v/list returns 200 with empty body —
        # we treat that as "exists" (the module proxy confirmed it).
        # The proxy protocol case-encodes uppercase letters as `!` + lower;
        # without this every mixed-case module path (e.g. Masterminds/squirrel,
        # IBM/sarama, BurntSushi/toml) returns 404 and is mis-flagged
        # as a fabricated name.
        status = _http_get_status(
            f"https://proxy.golang.org/{_goproxy_encode(pkg)}/@v/list"
        )
        return _status_to_verdict(status)
    if ecosystem == "packagist":
        # Packagist metadata API: 404 on unknown vendor/package, 200 with the
        # version-metadata document otherwise. Names are always vendor/package;
        # a bare token (no slash) is a platform/virtual package and not
        # resolvable here — fail-open.
        if "/" not in pkg:
            return None
        return _status_to_verdict(
            _http_get_status(
                f"https://repo.packagist.org/p2/{quote_pkg(pkg, keep_slash=True)}.json"
            )
        )
    return None


def _status_to_verdict(status: int) -> Optional[bool]:
    """Collapse an HTTP status code into True / False / None verdict.

    200–299 → True   (registry confirmed)
    404     → False  (registry explicitly rejected)
    anything else (0, 5xx, 410, 429, ...) → None (inconclusive)
    """
    if 200 <= status < 300:
        return True
    if status == 404:
        return False
    return None
