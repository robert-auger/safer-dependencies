"""Shared OSV (Open Source Vulnerabilities) single-query client.

The OSV ``/v1/query`` POST and its response-shape handling used to be
copy-pasted in three places: ``check_osv`` / ``check_osv_full`` inside
``safer-dependencies-shim.sh`` and ``_osv_query`` inside
``pretooluse_bash_audit.py``. They differed only in error policy and return
shape, so they are consolidated here behind a single :func:`query_vulns`.

Two error policies, selected per call site (NOT a global default):

  * ``strict=True`` — used by the post-write shim, which rewrites manifests.
    An unreachable / rate-limited / malformed OSV response raises
    :class:`OSVLookupError` so the caller can record the failure and refuse to
    treat the package as verified. This is the #109 correctness contract:
    an empty result must mean "OSV authoritatively returned no vulnerabilities",
    never "OSV was unreachable".

  * ``strict=False`` — used by the Pre-Install Bash hook, which only gates an
    install that the post-write shim will re-audit anyway. Network blips fail
    open (return ``[]``) so a transient OSV outage never blocks an install.

The caller passes the OSV ecosystem string directly (``"npm"``, ``"PyPI"``,
``"RubyGems"``, ``"Maven"``, ``"Go"``, ``"crates.io"``, ``"Packagist"``).
Internal-tag → OSV-string mapping stays with the caller (the shim's
``OSV_ECOSYSTEM`` table), since only the shim uses internal tags.
"""

from __future__ import annotations

from typing import List

from safedep.http import (
    HTTPLookupError,
    _http_post_json,
    _http_post_json_strict,
)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


class OSVLookupError(Exception):
    """Raised when a strict OSV vulnerability lookup cannot be completed.

    The correctness failure described in #109: a rate-limited / network-failed
    OSV query used to be indistinguishable from a clean ("no vulns") response,
    which caused the audit to mark rate-limited packages as safe. Call sites
    that catch this exception must record the failure and NOT treat the
    package as verified.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def query_vulns(
    package_name: str,
    version: str,
    osv_ecosystem: str,
    *,
    strict: bool,
    timeout: int = 10,
) -> List[dict]:
    """Query OSV for a single ``package@version`` and return its vuln objects.

    ``osv_ecosystem`` is the OSV-schema ecosystem string (e.g. ``"PyPI"``),
    not the shim's internal lowercase tag. Returns the full ``vulns`` list of
    advisory dicts (possibly empty); callers that only need CVE ids extract
    ``v["id"]`` themselves.

    With ``strict=True`` an HTTP error / timeout / rate-limit / non-dict
    response raises :class:`OSVLookupError`. With ``strict=False`` every such
    failure collapses to ``[]`` (fail-open).
    """
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": osv_ecosystem},
    }
    if not strict:
        try:
            result = _http_post_json(OSV_QUERY_URL, payload, timeout=timeout)
        except Exception:  # noqa: BLE001 — fail-open: any blip → no finding
            return []
        if not isinstance(result, dict):
            return []
        return result.get("vulns") or []

    try:
        result = _http_post_json_strict(OSV_QUERY_URL, payload, timeout=timeout)
    except HTTPLookupError as e:
        raise OSVLookupError(
            f"OSV {osv_ecosystem}:{package_name}@{version}: {e}"
        ) from e
    if not isinstance(result, dict):
        raise OSVLookupError(
            f"OSV {osv_ecosystem}:{package_name}@{version}: "
            f"unexpected response type {type(result).__name__}"
        )
    return list(result.get("vulns", []) or [])
