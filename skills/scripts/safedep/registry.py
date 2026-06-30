"""Registry query helpers shared by the shim and standalone scripts.

Pure-traversal helpers (``_pypi_earliest_upload_time_str``,
``_rubygems_earliest_created_at_str``, ``_maven_docs_earliest_timestamp_ms``)
operate on already-parsed registry JSON and return the raw string/int values
so the standalone first_publish_* CLI scripts can keep their byte-exact
output contract (tests compare exact timestamp strings).

``earliest_publish_datetime`` is the typed wrapper the shim uses — it returns
a ``datetime`` regardless of ecosystem, calling into the same per-ecosystem
traversals so the two callers cannot drift.

``first_publish_date`` is the fetcher-plus-parser used by the shim's hook
flow; it does the HTTP round-trip and delegates parsing to
``earliest_publish_datetime``.
"""
from datetime import datetime, timezone

from safedep.http import _http_get, _parse_dt, quote_pkg


# In-process memo of parsed registry documents. The pooled HTTP layer
# reuses CONNECTIONS, not bodies — without this, a staleness check followed
# by a cooloff check re-downloads the identical (sometimes multi-MB)
# registry doc. Hook processes are per-invocation: no TTL needed.
# None results are memoized too: a 404/network-fail repeat is the same
# answer within one hook run (fail-open stands).
_DOC_MEMO: dict = {}


def _get_doc(ecosystem: str, pkg: str, url: str):
    key = (ecosystem, pkg)
    if key not in _DOC_MEMO:
        _DOC_MEMO[key] = _http_get(url)
    return _DOC_MEMO[key]


def _clear_doc_memo_for_tests() -> None:
    _DOC_MEMO.clear()


# ---------------------------------------------------------------------------
# Pure traversal helpers — used by the standalone CLI scripts AND internally
# by earliest_publish_datetime.
# ---------------------------------------------------------------------------

def _pypi_earliest_upload_time_str(data) -> "str | None":
    """Return the earliest PyPI upload_time string across all releases, or None.

    Prefers ``upload_time_iso_8601`` (more precise) when both are present, which
    matches the shim's existing behaviour.
    """
    if not isinstance(data, dict):
        return None
    dates = []
    for files in (data.get("releases") or {}).values():
        if not isinstance(files, list):
            continue
        for f in files:
            if isinstance(f, dict):
                ts = f.get("upload_time_iso_8601") or f.get("upload_time")
                if ts:
                    dates.append(ts)
    return min(dates) if dates else None


def _rubygems_earliest_created_at_str(data) -> "str | None":
    """Return earliest RubyGems ``created_at`` string, or None for non-list input."""
    if not isinstance(data, list):
        return None
    dates = [v["created_at"] for v in data if isinstance(v, dict) and "created_at" in v]
    return min(dates) if dates else None


def _maven_docs_earliest_timestamp_ms(docs) -> "int | None":
    """Return earliest Maven timestamp (ms since epoch) across docs, or None."""
    if not isinstance(docs, list):
        return None
    stamps = [d["timestamp"] for d in docs if isinstance(d, dict) and "timestamp" in d]
    return min(stamps) if stamps else None


# ---------------------------------------------------------------------------
# Typed datetime wrapper — used by the shim.
# ---------------------------------------------------------------------------

def earliest_publish_datetime(data, ecosystem: str) -> "datetime | None":
    """Return the earliest recorded publish datetime from parsed registry data.

    Supports npm, pypi, rubygems, maven. Returns None for unknown ecosystems
    or when no valid timestamp is extractable.
    """
    if ecosystem == "npm":
        if not isinstance(data, dict):
            return None
        ts = (data.get("time") or {}).get("created")
        if ts:
            try:
                return _parse_dt(ts)
            except Exception:
                pass
        times = []
        for v, t in (data.get("time") or {}).items():
            if v in ("created", "modified"):
                continue
            try:
                times.append(_parse_dt(t))
            except Exception:
                pass
        return min(times) if times else None
    if ecosystem == "pypi":
        s = _pypi_earliest_upload_time_str(data)
        if not s:
            return None
        try:
            return _parse_dt(s)
        except Exception:
            return None
    if ecosystem == "rubygems":
        s = _rubygems_earliest_created_at_str(data)
        if not s:
            return None
        try:
            return _parse_dt(s)
        except Exception:
            return None
    if ecosystem == "maven":
        if not isinstance(data, dict):
            return None
        docs = (data.get("response") or {}).get("docs", [])
        ms = _maven_docs_earliest_timestamp_ms(docs)
        if ms is None:
            return None
        try:
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Fetcher + parser — used by the shim's hook flow.
# ---------------------------------------------------------------------------

def first_publish_date(pkg: str, ecosystem: str,
                       group_id: str = "", artifact_id: str = "") -> "datetime | None":
    """Return the earliest recorded publish datetime for a package, or None."""
    if ecosystem == "npm":
        encoded = quote_pkg(pkg)
        data = _http_get(f"https://registry.npmjs.org/{encoded}")
    elif ecosystem == "pypi":
        data = _http_get(f"https://pypi.org/pypi/{quote_pkg(pkg)}/json")
    elif ecosystem == "rubygems":
        data = _http_get(f"https://rubygems.org/api/v1/versions/{quote_pkg(pkg)}.json")
    elif ecosystem == "maven":
        data = _http_get(
            "https://search.maven.org/solrsearch/select"
            f"?q=g:{group_id}+AND+a:{artifact_id}&core=gav&rows=200&wt=json"
        )
    else:
        return None
    if data is None:
        return None
    return earliest_publish_datetime(data, ecosystem)


def first_publish_age_days(pkg: str, ecosystem: str,
                           group_id: str = "", artifact_id: str = "") -> "int | None":
    """Return age in days since the package was first published, or None on error."""
    dt = first_publish_date(pkg, ecosystem, group_id=group_id, artifact_id=artifact_id)
    if dt is None:
        return None
    return (datetime.now(timezone.utc) - dt).days


# ---------------------------------------------------------------------------
# Latest stable release — used by the Pre-Install hook's staleness check
# (issue #204). The shim keeps its own full version-list fetchers (it needs
# them for version *selection*); this helper answers the narrower question
# "what is the newest stable release and when was it published?".
# ---------------------------------------------------------------------------

def latest_stable_release(pkg: str, ecosystem: str) -> "tuple[str, datetime] | None":
    """Return ``(version, publish_datetime)`` of the newest stable release.

    Supports npm / pypi / rubygems / crates (the ecosystems the Pre-Install
    hook extracts concrete pins for, minus Go — Go staleness needs a second
    per-version round-trip and stays a shim-only check for now).
    Fail-open: returns None on any network/parse failure or unknown ecosystem.
    """
    from safedep.prerelease import is_prerelease

    try:
        if ecosystem == "npm":
            encoded = quote_pkg(pkg)
            data = _get_doc("npm", pkg, f"https://registry.npmjs.org/{encoded}")
            times = (data or {}).get("time")
            if not isinstance(times, dict):
                return None
            best: "tuple[str, datetime] | None" = None
            for ver, ts in times.items():
                if ver in ("created", "modified") or not isinstance(ts, str):
                    continue
                if is_prerelease(ver, "npm"):
                    continue
                try:
                    dt = _parse_dt(ts)
                except Exception:
                    continue
                if best is None or dt > best[1]:
                    best = (ver, dt)
            return best
        if ecosystem == "pypi":
            data = _get_doc("pypi", pkg, f"https://pypi.org/pypi/{quote_pkg(pkg)}/json")
            releases = (data or {}).get("releases")
            if not isinstance(releases, dict):
                return None
            best = None
            for ver, files in releases.items():
                if is_prerelease(ver, "pypi") or not isinstance(files, list) or not files:
                    continue
                stamps = []
                for f in files:
                    # Skip yanked uploads (review finding): a recently-yanked
                    # release must not mask staleness or count as "latest".
                    if (f or {}).get("yanked"):
                        continue
                    ts = (f or {}).get("upload_time_iso_8601") or (f or {}).get("upload_time")
                    if isinstance(ts, str):
                        try:
                            stamps.append(_parse_dt(ts))
                        except Exception:
                            pass
                if not stamps:
                    continue
                dt = min(stamps)
                if best is None or dt > best[1]:
                    best = (ver, dt)
            return best
        if ecosystem == "rubygems":
            data = _get_doc(
                "rubygems", pkg, f"https://rubygems.org/api/v1/versions/{quote_pkg(pkg)}.json")
            if not isinstance(data, list):
                return None
            best = None
            for row in data:
                if not isinstance(row, dict) or row.get("prerelease"):
                    continue
                ver, ts = row.get("number"), row.get("created_at")
                if not isinstance(ver, str) or not isinstance(ts, str):
                    continue
                if is_prerelease(ver, "rubygems"):
                    continue
                try:
                    dt = _parse_dt(ts)
                except Exception:
                    continue
                if best is None or dt > best[1]:
                    best = (ver, dt)
            return best
        if ecosystem == "crates":
            data = _get_doc("crates", pkg, f"https://crates.io/api/v1/crates/{quote_pkg(pkg)}")
            versions = (data or {}).get("versions")
            if not isinstance(versions, list):
                return None
            best = None
            for row in versions:
                if not isinstance(row, dict) or row.get("yanked"):
                    continue
                ver, ts = row.get("num"), row.get("created_at")
                if not isinstance(ver, str) or not isinstance(ts, str):
                    continue
                if is_prerelease(ver, "crates"):
                    continue
                try:
                    dt = _parse_dt(ts)
                except Exception:
                    continue
                if best is None or dt > best[1]:
                    best = (ver, dt)
            return best
    except Exception:
        return None
    return None


def release_date(pkg: str, version: str, ecosystem: str) -> "datetime | None":
    """Publish datetime of one specific version, or None (fail-open).

    Used by the Pre-Install cooloff check (issue #232). Shares the in-process
    registry-doc memo (``_DOC_MEMO``) with latest_stable_release — same
    (ecosystem, pkg) document, so a cooloff check after a staleness check
    costs zero extra round-trips within one hook process. (Go is the
    exception: its per-version .info URL is memoized per (pkg, version).)

    Cooloff coverage is npm/pypi/rubygems/crates: there is intentionally NO
    Maven branch here, so Pre-Install cooloff fails open (returns None) for
    Maven pins — Maven is absent from `_PM_STRATEGIES` anyway, and the
    Intercept shim separately skips Go cooloff. See references/configuration.md
    ("Cooloff ecosystem coverage"). Maven/Go cooloff is not implemented.
    """
    want = version.lstrip("vV")
    try:
        if ecosystem == "npm":
            encoded = quote_pkg(pkg)
            times = (_get_doc("npm", pkg,
                              f"https://registry.npmjs.org/{encoded}") or {}).get("time")
            if isinstance(times, dict):
                for ver, ts in times.items():
                    if ver.lstrip("vV") == want and isinstance(ts, str):
                        return _parse_dt(ts)
            return None
        if ecosystem == "pypi":
            releases = (_get_doc("pypi", pkg,
                                 f"https://pypi.org/pypi/{quote_pkg(pkg)}/json") or {}).get("releases")
            if isinstance(releases, dict):
                for ver, files in releases.items():
                    if ver.lstrip("vV") != want or not isinstance(files, list):
                        continue
                    stamps = []
                    for f in files:
                        if (f or {}).get("yanked"):
                            continue
                        ts = (f or {}).get("upload_time_iso_8601") or (f or {}).get("upload_time")
                        if isinstance(ts, str):
                            try:
                                stamps.append(_parse_dt(ts))
                            except Exception:
                                pass
                    return min(stamps) if stamps else None
            return None
        if ecosystem == "rubygems":
            rows = _get_doc(
                "rubygems", pkg, f"https://rubygems.org/api/v1/versions/{quote_pkg(pkg)}.json")
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, dict) and str(row.get("number", "")).lstrip("vV") == want:
                        ts = row.get("created_at")
                        return _parse_dt(ts) if isinstance(ts, str) else None
            return None
        if ecosystem == "crates":
            versions = (_get_doc("crates", pkg,
                                 f"https://crates.io/api/v1/crates/{quote_pkg(pkg)}") or {}).get("versions")
            if isinstance(versions, list):
                for row in versions:
                    if isinstance(row, dict) and str(row.get("num", "")).lstrip("vV") == want:
                        ts = row.get("created_at")
                        return _parse_dt(ts) if isinstance(ts, str) else None
            return None
        if ecosystem == "go":
            from safedep.goproxy import encode_module_path
            # Per-VERSION document, not a package-level doc — key the memo by
            # pkg@version so distinct versions don't collide.
            info = _get_doc(
                "go", pkg + "@" + want,
                f"https://proxy.golang.org/{encode_module_path(pkg)}/@v/v{want}.info")
            ts = (info or {}).get("Time")
            return _parse_dt(ts) if isinstance(ts, str) else None
    except Exception:
        return None
    return None
