import json
import os
import re
import sys
from datetime import datetime, timezone

# TOML parser. Python 3.11+ ships ``tomllib`` in the stdlib; older versions
# need the ``tomli`` polyfill (tomli is the upstream library tomllib was
# adopted from — same API, same author, zero runtime deps). Without this
# shim, pyproject.toml / libs.versions.toml / poetry.lock / uv.lock audits
# silently fail with "shim audit error: No module named 'tomllib'" on
# Python 3.8–3.10. When neither library is available we set _tomllib to
# None; call sites surface that as a visible WARNING rather than a silent
# empty audit.
try:
    import tomllib as _tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as _tomllib  # type: ignore[no-redef]
    except ImportError:
        _tomllib = None  # type: ignore[assignment]

# Locate the shared library (scripts/safedep) using the path exported by the
# bash wrapper. Fall back to a best-effort search if the env var is missing
# (e.g. when the Python file is reused outside the shim wrapper).
_scripts_dir = os.environ.get("SAFE_DEP_SCRIPTS_DIR")
if _scripts_dir and os.path.isdir(os.path.join(_scripts_dir, "safedep")):
    if _scripts_dir not in sys.path:
        sys.path.insert(0, _scripts_dir)
from safedep.http import (
    _http_get,
    _http_get_text,
    _http_post_json,
    _parse_dt,
    parallel_map,
)
from safedep.version import attribution_header


# ─────────────────────────── manifest-audit concurrency ───────────────────────────
# Manifest audits (audit_npm, audit_pypi, ...) fan out per-package metadata
# fetches via parallel_map. The default of 3 is intentionally conservative so
# that public registries (PyPI, npm, RubyGems, proxy.golang.org, Maven Central)
# are never hit with more than 3 concurrent connections from a single audit.
# Power users on private mirrors can raise this via SAFE_DEP_MAX_WORKERS (the
# same env var the lockfile path uses); when that env var is unset, the lockfile
# path uses 8 (its existing default) and the manifest path uses 3 (this default).
_MANIFEST_DEFAULT_MAX_WORKERS = 3


def _manifest_max_workers() -> int:
    """Concurrency for per-package fan-out in manifest audits.

    Honors SAFE_DEP_MAX_WORKERS if explicitly set (clamped to [1, 32] by
    safedep.http._resolve_max_workers); otherwise returns 3. Kept lower than
    the lockfile path's default-of-8 because manifest audits typically run
    interactively (per Write/Edit) where unbounded fan-out would be a
    rate-limit risk against free public registries.
    """
    raw = os.environ.get("SAFE_DEP_MAX_WORKERS")
    if raw and raw.strip().lstrip("-").isdigit():
        return max(1, min(int(raw), 32))
    return _MANIFEST_DEFAULT_MAX_WORKERS


from safedep.osv import OSVLookupError, query_vulns as _osv_query_vulns
from safedep import cache as _cache
# first_publish_date is re-exported here (not referenced in this module) so the
# advisory-age test suite can monkeypatch/exercise it via ``shim.first_publish_date``.
from safedep.registry import first_publish_date, first_publish_age_days  # noqa: F401
from safedep.github import (
    # _extract_github_repo is re-exported for the advisory-age tests
    # (``shim._extract_github_repo``); it is not referenced in this module.
    extract_repo_from_registry as _extract_github_repo,  # noqa: F401
    github_repo_for_package as _github_repo_for_package,
    github_repo_age_days,
)
from safedep.typosquat import best_match_guarded as check_typosquat
from safedep.prerelease import is_prerelease as _is_prerelease
from safedep.pypi_hashes import iter_pypi_artifact_hashes as _iter_pypi_artifact_hashes
from safedep.abandoned import lookup as check_abandoned
from safedep.constants import VERSION_AGE_GATE_DAYS
from safedep.staleness import STALENESS_THRESHOLD_DAYS, is_stale as _is_stale
from safedep.existence import package_exists as _package_exists
from safedep.goproxy import encode_module_path as _goproxy_encode
from safedep.audit_log import build_source as _build_audit_source
from safedep.signatures import (
    maven_has_signature as _maven_has_signature,
    rubygems_has_signature as _rubygems_has_signature,
)
from safedep.lockfiles import parse_yarn_lock, parse_pnpm_lock
from safedep.audit_log import write_entry as _audit_log_write_entry
from safedep.audit_log import find_prior_correction as _find_prior_correction
from safedep.config import is_disabled as _ecosystem_is_disabled

# Policy tiers (issue #232). Hard fail-open: any config error → defaults.
try:
    from safedep.config import check_tier as _policy_check_tier
    from safedep.config import cooloff_days as _policy_cooloff_days
    from safedep.config import cooloff_mode as _policy_cooloff_mode
    from safedep.config import load_warnings as _policy_load_warnings
except Exception:  # noqa: BLE001
    _policy_check_tier = None
    _policy_cooloff_days = None
    _policy_cooloff_mode = None
    _policy_load_warnings = None


def _tier(name: str, default: str) -> str:
    if _policy_check_tier is None:
        return default
    try:
        return _policy_check_tier(name)
    except Exception:  # noqa: BLE001
        return default


# 'off' tiers neuter the check functions once at import time — zero
# per-call-site edits, and warn/block branching is centralized in
# _apply_policy_to_result below.
if _tier("typosquat", "warn") == "off":
    check_typosquat = lambda *a, **k: None  # noqa: E731
if _tier("abandoned", "block") == "off":
    check_abandoned = lambda *a, **k: None  # noqa: E731

# ─────────────────────────── constants ───────────────────────────

MANIFEST_ECOSYSTEM = {
    # Node.js
    "package.json":        "npm",
    # Python — pip, Pipenv, Poetry, uv, Hatch, PEP 621
    "requirements.txt":    "pypi",
    "Pipfile":             "pypi",
    "pyproject.toml":      "pypi",
    "setup.py":            "pypi",
    "setup.cfg":           "pypi",
    # Ruby — Bundler, gem development
    "Gemfile":             "rubygems",
    # Java — Maven, Gradle (including Version Catalog)
    "pom.xml":             "maven",
    "build.gradle":        "maven",
    "build.gradle.kts":    "maven",
    "libs.versions.toml":  "maven",
    # Go
    "go.mod":              "go",
    # Rust — Cargo
    "Cargo.toml":          "crates",
    # PHP — Composer
    "composer.json":       "packagist",
}
LOCK_FILES = {
    # Node.js
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    # Python
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    # Ruby
    "Gemfile.lock",
    # Java — Gradle dependency locking (single-file format, settings.gradle
    # opt-in via `dependencyLocking { lockAllConfigurations() }`).
    "gradle.lockfile",
    # Go
    "go.sum",
    # Rust — Cargo
    "Cargo.lock",
    # PHP — Composer
    "composer.lock",
}
# Reverse map for the ecosystem-disable check (PR #6 / safer-dependencies.toml).
# Lockfiles don't carry ecosystem info in MANIFEST_ECOSYSTEM, so we map them
# explicitly. Order tracks LOCK_FILES above. Path-qualified files
# (vendor/modules.txt) are handled separately in main().
LOCK_FILE_ECOSYSTEM = {
    "package-lock.json":    "npm",
    "npm-shrinkwrap.json":  "npm",
    "yarn.lock":            "npm",
    "pnpm-lock.yaml":       "npm",
    "bun.lock":             "npm",
    "Pipfile.lock":         "pypi",
    "poetry.lock":          "pypi",
    "uv.lock":              "pypi",
    "pdm.lock":             "pypi",
    "Gemfile.lock":         "rubygems",
    "gradle.lockfile":      "maven",
    "go.sum":               "go",
    "Cargo.lock":           "crates",
    "composer.lock":        "packagist",
}
# Recognised-but-unaudited manifest formats. The skill description promises
# to flag the coverage gap rather than silently no-op (issue #155); this
# table is the source of truth for which filenames qualify as "we see it,
# we know what it is, we don't audit it yet". Each entry maps the basename
# to (ecosystem label, native audit tool suggestion). Tools with no
# community-standard auditor get a manual-review hint.
UNSUPPORTED_MANIFESTS = {
    "mix.exs":        ("Elixir",         "mix hex.audit"),
    "pubspec.yaml":   ("Dart",           "dart pub outdated --mode=security"),
    "Package.swift":  ("Swift",          "no standard audit tool yet — review manually"),
    "conanfile.txt":  ("C++ (Conan)",    "no standard audit tool yet — review manually"),
    "vcpkg.json":     ("C++ (vcpkg)",    "no standard audit tool yet — review manually"),
    "cabal.project":  ("Haskell",        "cabal-audit (community)"),
    "shards.yml":     ("Crystal",        "no standard audit tool yet — review manually"),
    "deps.edn":       ("Clojure",        "clj -M:nvd (or similar)"),
    "renv.lock":      ("R",              "no standard audit tool yet — review manually"),
}
AGE_GATE_DAYS = VERSION_AGE_GATE_DAYS
OSV_ECOSYSTEM = {
    "npm":       "npm",
    "pypi":      "PyPI",
    "rubygems":  "RubyGems",
    "maven":     "Maven",
    "go":        "Go",
    "crates":    "crates.io",
    "packagist": "Packagist",
}

# ─────────────────────────── RubyGems meta-gem detection ───────────────────────────
# Meta-gems (rails, rspec, etc.) ship as thin wrappers whose runtime deps are
# pinned to the same version as the meta-gem itself. Advisories are filed under
# the component gem names (actionpack, rspec-core, ...), so querying the meta-gem
# alone misses them. We detect the pattern structurally by asking rubygems.org
# for the gem's runtime dependency list — no static gem list to maintain.
_RUBYGEMS_COMPONENTS_CACHE = {}  # (pkg, version) -> [component_name, ...]


def _rubygems_components(package_name: str, version: str) -> list:
    """
    Return the list of runtime dependencies of `package_name@version` that are
    pinned to exactly that version (=) or to the same minor line (~>) — i.e.
    the component gems that make up a meta-gem release.

    Examples:
      rails 6.0.0       → actionpack, activesupport, ... (12 components, all `= 6.0.0`)
      rspec 3.12.0      → rspec-core, rspec-mocks, rspec-expectations (all `~> 3.12.0`)
      sinatra 3.0.0     → [] or [rack-protection] (deps mostly version ranges)
      nokogiri 1.10.3   → [] (regular gem)

    Empty list means "not a meta-gem (at this version)" — the caller should then
    proceed with a normal single-name lookup.
    """
    version = version.strip()
    key = (package_name, version)
    if key in _RUBYGEMS_COMPONENTS_CACHE:
        return _RUBYGEMS_COMPONENTS_CACHE[key]

    url = f"https://rubygems.org/api/v2/rubygems/{package_name}/versions/{version}.json"
    data = _http_get(url, timeout=5)
    if not isinstance(data, dict):
        _RUBYGEMS_COMPONENTS_CACHE[key] = []
        return []

    components = []
    for dep in data.get("dependencies", {}).get("runtime", []):
        req = (dep.get("requirements") or "").strip()
        name = dep.get("name") or ""
        if not name:
            continue
        # Requirement strings look like "= 6.0.0", "~> 3.12.0", ">= 1.3.0", or
        # compound "~> 2.2, >= 2.2.4". A component pin is a SINGLE requirement
        # (no comma) of form `=` or `~>` matching the parent version.
        if "," in req:
            continue
        m = re.match(r"^(=|~>)\s*(.+)$", req)
        if not m:
            continue
        dep_ver = m.group(2).strip()
        if dep_ver == version:
            components.append(name)

    _RUBYGEMS_COMPONENTS_CACHE[key] = components
    return components

# HTTP helpers (_http_get, _http_get_text, _http_post_json) and the pre-release
# filter (_is_prerelease) are imported from safedep.* above — shared with the
# standalone CLI scripts.


# ─────────────────────────── OSV vulnerability check ───────────────────────────

def check_osv(package_name: str, version: str, ecosystem: str) -> list:
    """Return list of vulnerability IDs for this package@version, or [] if clean.

    Raises :class:`OSVLookupError` when the OSV query cannot be completed
    (HTTP error, timeout, rate limit, malformed response). This is the #109
    correctness fix: empty-list must mean "OSV authoritatively returned no
    vulnerabilities", never "OSV was unreachable".
    """
    osv_eco = OSV_ECOSYSTEM.get(ecosystem)
    if not osv_eco:
        return []
    vulns = _osv_query_vulns(package_name, version, osv_eco, strict=True)
    return [v.get("id", "") for v in vulns if v.get("id")]


def check_osv_full(package_name: str, version: str, ecosystem: str) -> list:
    """Return full OSV advisory objects for package@version, or [].

    Sibling of :func:`check_osv`, which only returns CVE IDs. This one
    preserves the full ``affected[].ranges[].events[]`` structure so
    callers can reason about fix version ranges. Used by
    :func:`pick_safe_version` to implement the fresh-fix exception
    (candidates < AGE_GATE_DAYS are allowed iff OSV explicitly states
    they fix a CVE present in the current pinned version).

    Raises :class:`OSVLookupError` on HTTP/shape failure, same contract
    as :func:`check_osv`. Not cached: called only for vulnerable current
    pins from a single ``pick_safe_version`` invocation, which is
    already a slow path.
    """
    osv_eco = OSV_ECOSYSTEM.get(ecosystem)
    if not osv_eco:
        return []
    return _osv_query_vulns(package_name, version, osv_eco, strict=True)


# OSV /v1/querybatch cap per request (https://google.github.io/osv.dev/post-v1-querybatch/).
_OSV_BATCH_MAX = 1000


def check_osv_batch(queries: list) -> dict:
    """Batch OSV lookup. Cuts per-manifest OSV calls from O(n) to O(ceil(n/1000)) (#108).

    ``queries`` is a list of ``(ecosystem_internal, package_name, version)`` tuples
    (``ecosystem_internal`` is the shim's internal tag — ``"npm"``, ``"pypi"``,
    etc. — NOT the OSV ecosystem string). Returns a dict keyed by the same tuple
    mapping to a list of CVE/GHSA IDs. Missing fields / unknown ecosystems are
    silently skipped, and on any HTTP / shape failure the function returns
    whatever it has so callers can fall back to per-package :func:`check_osv`.

    Uses the lenient :func:`_http_post_json` deliberately: a batch miss here is
    a best-effort cache prewarm, not an authoritative verdict. Callers that
    need strict semantics still go through :func:`check_osv_cached` where an
    unreachable OSV raises ``OSVLookupError`` (see #109).
    """
    if not queries:
        return {}
    body_queries: list = []
    key_order: list = []
    for key in queries:
        if not (isinstance(key, tuple) and len(key) == 3):
            continue
        eco_internal, name, version = key
        osv_eco = OSV_ECOSYSTEM.get(eco_internal)
        if not osv_eco or not name or not version:
            continue
        body_queries.append({
            "version": version,
            "package": {"name": name, "ecosystem": osv_eco},
        })
        key_order.append(key)

    result_map: dict = {}
    for start in range(0, len(body_queries), _OSV_BATCH_MAX):
        chunk = body_queries[start:start + _OSV_BATCH_MAX]
        chunk_keys = key_order[start:start + _OSV_BATCH_MAX]
        resp = _http_post_json(
            "https://api.osv.dev/v1/querybatch",
            {"queries": chunk},
        )
        if not isinstance(resp, dict):
            continue
        results = resp.get("results")
        if not isinstance(results, list) or len(results) != len(chunk_keys):
            continue
        for key, entry in zip(chunk_keys, results):
            if not isinstance(entry, dict):
                continue
            vulns = entry.get("vulns") or []
            ids = [v.get("id", "") for v in vulns if isinstance(v, dict) and v.get("id")]
            result_map[key] = ids
    return result_map


# Module-level cache keyed by (ecosystem, name, version). Values are CVE ID lists.
# Keeps the 60s hook budget intact when the same component is probed multiple times
# (e.g. during pick_safe_version's candidate scan).
_OSV_CACHE = {}


# ─────────────── large-audit delay warning ───────────────
# Counts the total packages this shim invocation has handed to
# ``prewarm_osv_cache`` (manifest auditors and lockfile auditors alike).
# When the total first crosses ``_LARGE_AUDIT_THRESHOLD`` we emit a yellow
# stderr line in real time so the human sees the delay coming, and ``main()``
# prepends a retrospective NOTE: signal so the agent can echo the same
# expectation to the user on its next turn.
_AUDIT_TOTAL_PACKAGES = 0
_LARGE_AUDIT_STDERR_NOTIFIED = False


def _parse_threshold_env(default: int) -> int:
    """Robust int parse for the threshold env var.

    Any non-integer value (empty string, "disabled", "20.5", whitespace-only)
    falls back to the default rather than crashing the shim at module-load
    time. A misconfigured env var must not break every hook invocation.
    """
    raw = os.environ.get("SAFE_DEP_DELAY_WARN_THRESHOLD", "").strip()
    if not raw:
        return default
    sign = "-" if raw.startswith("-") else ""
    if not raw.lstrip("-").isdigit():
        return default
    try:
        return int(sign + raw.lstrip("-"))
    except ValueError:
        return default


_LARGE_AUDIT_THRESHOLD = _parse_threshold_env(default=20)


def _estimate_audit_seconds(n: int) -> int:
    """Rough wall-clock estimate for an audit of ``n`` packages.

    Assumes the bottleneck is network round-trips against public registries,
    parallelised across ``SAFE_DEP_MAX_WORKERS`` workers (default 3). 2s per
    package is a deliberately conservative per-call average that covers OSV
    + registry metadata + advisory-age lookups. Minimum of 5s so a 21-pkg
    audit doesn't promise "expect ~14s" only for the user to wait longer.
    """
    workers_raw = os.environ.get("SAFE_DEP_MAX_WORKERS", "3").strip()
    workers = int(workers_raw) if workers_raw.lstrip("-").isdigit() else 3
    workers = max(1, workers)
    return max(5, (n // workers) * 2)


def _maybe_notify_large_audit(total: int) -> None:
    """One-shot stderr warning the first time we cross the threshold.

    Stderr is the only channel that reaches the user before the hook
    completes — ``additionalContext`` is buffered and only delivered when
    the audit finishes. Yellow ANSI matches the install-error red branch
    above; the JSON envelope below is unaffected.
    """
    global _LARGE_AUDIT_STDERR_NOTIFIED
    if _LARGE_AUDIT_STDERR_NOTIFIED or total <= _LARGE_AUDIT_THRESHOLD:
        return
    _LARGE_AUDIT_STDERR_NOTIFIED = True
    est = _estimate_audit_seconds(total)
    sys.stderr.write(
        f"\033[1;33m[safer-dependencies] auditing {total} dependencies — "
        f"expect ~{est}s of network lookups\033[0m\n"
    )
    sys.stderr.flush()


def prewarm_osv_cache(pkg_versions: list, ecosystem: str) -> None:
    """Pre-populate ``_OSV_CACHE`` for a manifest's declared packages (#108).

    ``pkg_versions`` is a list of ``(name, version)`` tuples. One batched OSV
    query replaces N serial ``check_osv`` calls. Entries already cached
    (in-memory or on disk) are skipped; on batch failure the cache is simply
    not populated and subsequent per-package calls go through the normal path.
    """
    if _tier("cve", "block") == "off":
        return
    if not pkg_versions:
        return
    # Track total across every audit_* call in this shim invocation so the
    # user sees one delay warning even when a write spans multiple manifests
    # or a lockfile + manifest pair.
    global _AUDIT_TOTAL_PACKAGES
    _AUDIT_TOTAL_PACKAGES += len(pkg_versions)
    _maybe_notify_large_audit(_AUDIT_TOTAL_PACKAGES)
    queries: list = []
    for name, version in pkg_versions:
        if not name or not version:
            continue
        key = (ecosystem, name, version)
        if key in _OSV_CACHE:
            continue
        disk_key = _cache.osv_key(ecosystem, name, version)
        cached = _cache.get(disk_key)
        if cached is not None:
            _OSV_CACHE[key] = cached
            continue
        queries.append(key)
    if not queries:
        return
    batch_results = check_osv_batch(queries)
    for key, cves in batch_results.items():
        _OSV_CACHE[key] = cves
        _cache.put(_cache.osv_key(*key), cves, _cache.TTL_OSV)


def check_osv_cached(package_name: str, version: str, ecosystem: str) -> list:
    """check_osv with two-tier memoization: in-process dict + on-disk cache.

    The in-process dict is the hot path during a single audit (e.g.
    pick_safe_version's candidate scan probes the same package repeatedly).
    The on-disk cache (safedep.cache) carries results across hook
    invocations so a 15-manifest workspace doesn't re-resolve the same
    common deps from scratch each time. Disk lookup itself is sub-ms;
    network OSV is 100ms-30s under throttling.
    """
    key = (ecosystem, package_name, version)
    if key in _OSV_CACHE:
        return _OSV_CACHE[key]
    disk_key = _cache.osv_key(ecosystem, package_name, version)
    cached = _cache.get(disk_key)
    if cached is not None:
        _OSV_CACHE[key] = cached
        return cached
    # On OSVLookupError we let the exception propagate WITHOUT caching —
    # a rate-limited / network-failed lookup is not authoritative, so
    # persisting it as "clean" would re-introduce the #109 bug.
    cves = check_osv(package_name, version, ecosystem)
    _OSV_CACHE[key] = cves
    # Confirmed results (clean or vulnerable) are safe to cache to disk now
    # that #109 distinguishes authoritative empty-list from lookup failure.
    _cache.put(disk_key, cves, _cache.TTL_OSV)
    return cves


def check_osv_rubygems_expanded(package_name: str, version: str) -> list:
    """
    Query OSV for a RubyGems package AND every component gem discovered by
    `_rubygems_components` (data-driven, library-agnostic — works for rails,
    rspec, or any meta-gem). Returns the union of CVE IDs, deduplicated and
    stable-ordered (the gem itself first, then its components in API order).
    """
    seen = set()
    result = []
    for cid in check_osv_cached(package_name, version, "rubygems"):
        if cid not in seen:
            seen.add(cid)
            result.append(cid)
    for component in _rubygems_components(package_name, version):
        for cid in check_osv_cached(component, version, "rubygems"):
            if cid not in seen:
                seen.add(cid)
                result.append(cid)
    return result


# Module-level caches for ruby-advisory-db.
# _RADB_LISTING[pkg] -> list of advisory filenames (or None = 404 / no entry)
# _RADB_YAML[(pkg, filename)] -> parsed advisory dict (or None on failure)
_RADB_LISTING = {}
_RADB_YAML = {}
_RADB_DISABLED = False  # Toggled true after repeated failures to avoid blowing the budget.


def _radb_listing(pkg: str) -> list:
    """Return list of advisory filenames for pkg in ruby-advisory-db, or []."""
    global _RADB_DISABLED
    if _RADB_DISABLED:
        return []
    if pkg in _RADB_LISTING:
        return _RADB_LISTING[pkg] or []
    url = f"https://api.github.com/repos/rubysec/ruby-advisory-db/contents/gems/{pkg}"
    data = _http_get(url, timeout=5)
    if data is None:
        # Network error — disable fallback for the rest of this run so we don't
        # compound hook latency by retrying for every gem.
        _RADB_DISABLED = True
        _RADB_LISTING[pkg] = []
        return []
    if not isinstance(data, list):
        # 404 for this gem — cache the negative result, keep fallback enabled.
        _RADB_LISTING[pkg] = []
        return []
    names = [entry.get("name", "") for entry in data if entry.get("name", "").endswith(".yml")]
    _RADB_LISTING[pkg] = names
    return names


def _radb_yaml(pkg: str, filename: str) -> dict:
    """Fetch and parse one advisory YAML. Returns dict or {} on failure."""
    key = (pkg, filename)
    if key in _RADB_YAML:
        return _RADB_YAML[key] or {}
    url = f"https://raw.githubusercontent.com/rubysec/ruby-advisory-db/master/gems/{pkg}/{filename}"
    text = _http_get_text(url, timeout=5)
    if not text:
        _RADB_YAML[key] = None
        return {}
    # Minimal YAML parser: this advisory format is flat key:value plus a couple
    # of list fields. We avoid pulling in PyYAML (not in stdlib) to keep the
    # single-file shim self-contained.
    parsed = _parse_radb_yaml(text)
    _RADB_YAML[key] = parsed
    return parsed


def _parse_radb_yaml(text: str) -> dict:
    """Tiny YAML subset parser for ruby-advisory-db advisory files.

    Handles: scalar `key: value`, block-scalar `key: |`, and list fields
    (`patched_versions:` / `unaffected_versions:`) with `- "..."` entries.
    Returns dict with at minimum: cve, ghsa, patched_versions (list),
    unaffected_versions (list), url.
    """
    result = {"patched_versions": [], "unaffected_versions": []}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        # Top-level key detection (no leading whitespace)
        m = re.match(r"^([a-zA-Z_]+):\s*(.*)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key in ("patched_versions", "unaffected_versions"):
                # Consume subsequent "  - \"...\"" lines
                items = []
                j = i + 1
                while j < len(lines):
                    item_m = re.match(r"""^\s+-\s+['"]?([^'"]+?)['"]?\s*$""", lines[j])
                    if not item_m:
                        break
                    items.append(item_m.group(1).strip())
                    j += 1
                result[key] = items
                i = j
                continue
            if val.startswith("|"):
                # Block scalar — skip its content; we don't need it.
                j = i + 1
                while j < len(lines) and (lines[j].startswith(" ") or lines[j] == ""):
                    j += 1
                i = j
                continue
            # Strip surrounding quotes if any
            val = val.strip('"').strip("'")
            if val:
                result[key] = val
        i += 1
    return result


def _version_satisfies_constraint(version: str, constraint: str) -> bool:
    """
    Check whether `version` satisfies a single Ruby-style version constraint
    like ">= 3.0.0.beta1", "~> 5.2.4.1", "< 6.1.0", "= 1.2.3".
    Falls back to False on parse failure (safer to flag than silently pass).
    """
    m = re.match(r"^\s*(>=|<=|>|<|~>|=)\s*(.+)$", constraint.strip())
    if not m:
        return False
    op, target = m.group(1), m.group(2).strip()

    def _key(v: str) -> tuple:
        # Split on dots. Numeric prefix becomes the sortable tuple; as soon as
        # a non-numeric segment appears (e.g. "beta1", "rc2"), the version is
        # flagged as pre-release. Ruby semantics: pre-release sorts BEFORE the
        # stable version at the same numeric prefix (1.0.0.rc1 < 1.0.0).
        parts = v.strip().split(".")
        nums = []
        pre = []
        for seg in parts:
            if seg.isdigit():
                if not pre:
                    nums.append(int(seg))
                else:
                    pre.append(seg)
            else:
                pre.append(seg)
        # Stable flag: 1 if no pre-release tail, else 0 (so stable > pre).
        return tuple(nums), (1 if not pre else 0), tuple(pre)

    vk, vflag, vpre = _key(version)
    tk, tflag, tpre = _key(target)

    if op == "~>":
        # ~> A[.B[.C[.D...]]] means: >= target AND first (N-1) numeric segments
        # of version equal target's (where N = number of numeric segments in
        # target). Single-segment ~> X is unbounded upward.
        if not tk:
            return False
        if (vk, vflag, vpre) < (tk, tflag, tpre):
            return False
        if len(tk) <= 1:
            return True
        prefix_len = len(tk) - 1
        return vk[:prefix_len] == tk[:prefix_len]

    lhs = (vk, vflag, vpre)
    rhs = (tk, tflag, tpre)
    if op == ">=": return lhs >= rhs
    if op == "<=": return lhs <= rhs
    if op == ">":  return lhs >  rhs
    if op == "<":  return lhs <  rhs
    if op == "=":  return lhs == rhs
    return False


def _is_version_affected(version: str, advisory: dict) -> bool:
    """
    ruby-advisory-db semantics: a version is AFFECTED unless it satisfies at
    least one `patched_versions` OR `unaffected_versions` constraint.
    """
    for group in ("patched_versions", "unaffected_versions"):
        for constraint in advisory.get(group, []):
            if _version_satisfies_constraint(version, constraint):
                return False
    # If the advisory had no patched/unaffected constraints at all, treat as
    # affected (conservative — matches bundler-audit's default behaviour).
    return True


def check_ruby_advisory_db(package_name: str, version: str) -> list:
    """
    Query ruby-advisory-db for advisories affecting package_name@version.
    Returns list of CVE/GHSA identifiers, deduplicated, empty on error.
    """
    ids = []
    for filename in _radb_listing(package_name):
        advisory = _radb_yaml(package_name, filename)
        if not advisory:
            continue
        if _is_version_affected(version, advisory):
            ident = advisory.get("cve") or advisory.get("ghsa") or filename.replace(".yml", "")
            if ident and not ident.startswith(("CVE-", "GHSA-")):
                # Some files store just the number (e.g. "2015-9235"); prefix it.
                if re.match(r"^\d{4}-\d+$", ident):
                    ident = f"CVE-{ident}"
            if ident and ident not in ids:
                ids.append(ident)
    return ids


def check_rubygems_vulns(package_name: str, version: str) -> list:
    """
    Unified RubyGems vulnerability check:
      1. Expanded OSV query (meta-gem components included).
      2. ruby-advisory-db fallback for advisories missing from OSV.
    Returns deduplicated list of identifiers (CVE-*/GHSA-*).
    """
    seen = set()
    result = []
    for cid in check_osv_rubygems_expanded(package_name, version):
        if cid not in seen:
            seen.add(cid)
            result.append(cid)
    for cid in check_ruby_advisory_db(package_name, version):
        if cid not in seen:
            seen.add(cid)
            result.append(cid)
    # Also consult ruby-advisory-db for each discovered meta-gem component,
    # so a meta-gem with advisories in ruby-advisory-db-only (not OSV) still
    # gets caught. Uses the same data-driven component discovery.
    for component in _rubygems_components(package_name, version):
        for cid in check_ruby_advisory_db(component, version):
            if cid not in seen:
                seen.add(cid)
                result.append(cid)
    return result


# ─────────────────────────── registry resolvers ───────────────────────────

# _parse_dt is imported from safedep.http above — shared with the standalone
# CLI scripts.


def _cached_versions(eco: str, package: str):
    """Read versions list from on-disk cache. Returns [(v, dt), ...] or None on miss."""
    cached = _cache.get(_cache.versions_key(eco, package))
    if cached is None:
        return None
    try:
        return [(v, _parse_dt(ts)) for v, ts in cached]
    except Exception:
        return None


def _put_cached_versions(eco: str, package: str, versions: list) -> None:
    """Persist [(v, datetime), ...] as JSON-safe [[v, iso_string], ...].

    Empty lists are intentionally not cached. An empty result could mean
    "no stable versions" OR "the HTTP layer silently swallowed a 429"
    (see #109). Persisting the latter would durably hide upgrades.
    """
    if not versions:
        return
    try:
        serialized = [[v, dt.isoformat()] for v, dt in versions]
    except Exception:
        return
    _cache.put(_cache.versions_key(eco, package), serialized, _cache.TTL_VERSIONS)


def npm_versions(package: str) -> list:
    """Return [(version, published_datetime), ...] newest-first, stable only."""
    cached = _cached_versions("npm", package)
    if cached is not None:
        return cached
    # Encode scoped packages: @scope/name → %40scope%2Fname
    encoded = package.replace("@", "%40").replace("/", "%2F")
    data = _http_get(f"https://registry.npmjs.org/{encoded}")
    if not data:
        return []
    versions = []
    for v, ts in data.get("time", {}).items():
        if v in ("created", "modified"):
            continue
        if _is_prerelease(v, "npm"):
            continue
        try:
            versions.append((v, _parse_dt(ts)))
        except Exception:
            pass
    versions.sort(key=lambda x: x[1], reverse=True)
    versions = versions[:20]
    _put_cached_versions("npm", package, versions)
    return versions


def pypi_versions(package: str) -> list:
    """Return [(version, first_uploaded_datetime), ...] newest-first, stable only."""
    cached = _cached_versions("pypi", package)
    if cached is not None:
        return cached
    data = _http_get(f"https://pypi.org/pypi/{package}/json")
    if not data:
        return []
    versions = []
    for v, files in data.get("releases", {}).items():
        if _is_prerelease(v, "pypi"):
            continue
        upload_times = []
        for f in files:
            ts = f.get("upload_time_iso_8601") or f.get("upload_time", "")
            if ts:
                try:
                    upload_times.append(_parse_dt(ts))
                except Exception:
                    pass
        if upload_times:
            versions.append((v, min(upload_times)))
    versions.sort(key=lambda x: x[1], reverse=True)
    versions = versions[:20]
    _put_cached_versions("pypi", package, versions)
    return versions


def pypi_requires_python(package: str) -> dict:
    """Return {version: requires_python_spec} from PyPI release-file metadata.

    The spec is each release's ``Requires-Python`` (e.g. ``">=3.10"``); empty
    string when a release declares none. Used to skip safe-version candidates
    the project's Python floor cannot install (issue #195).
    """
    data = _http_get(f"https://pypi.org/pypi/{package}/json")
    if not data:
        return {}
    out = {}
    for v, files in data.get("releases", {}).items():
        spec = ""
        for f in files:
            spec = f.get("requires_python") or ""
            if spec:
                break
        out[v] = spec
    return out


def rubygems_versions(package: str) -> list:
    """Return [(version, published_datetime), ...] newest-first, stable only."""
    cached = _cached_versions("rubygems", package)
    if cached is not None:
        return cached
    data = _http_get(f"https://rubygems.org/api/v1/versions/{package}.json")
    if not isinstance(data, list):
        return []
    versions = []
    for entry in data:
        v = entry.get("number", "")
        if not v or _is_prerelease(v, "rubygems"):
            continue
        ts = entry.get("created_at", "")
        try:
            versions.append((v, _parse_dt(ts)))
        except Exception:
            pass
    versions.sort(key=lambda x: x[1], reverse=True)
    versions = versions[:20]
    _put_cached_versions("rubygems", package, versions)
    return versions


def maven_versions(group_id: str, artifact_id: str) -> list:
    """Return [(version, published_datetime), ...] newest-first, stable only."""
    maven_pkg = f"{group_id}:{artifact_id}"
    cached = _cached_versions("maven", maven_pkg)
    if cached is not None:
        return cached
    url = (
        "https://search.maven.org/solrsearch/select"
        f"?q=g:{group_id}+AND+a:{artifact_id}&core=gav&rows=20&wt=json"
    )
    data = _http_get(url)
    if not data:
        return []
    versions = []
    for doc in data.get("response", {}).get("docs", []):
        v = doc.get("v", "")
        if not v or _is_prerelease(v, "maven"):
            continue
        ts_ms = doc.get("timestamp")
        if ts_ms:
            try:
                dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
                versions.append((v, dt))
            except Exception:
                pass
    versions.sort(key=lambda x: x[1], reverse=True)
    versions = versions[:20]
    _put_cached_versions("maven", maven_pkg, versions)
    return versions


def _semver_key(version: str) -> tuple:
    """Parse vX.Y.Z (or X.Y.Z) → (X, Y, Z) tuple for numeric sorting."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", version)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return (0, 0, 0)


def _major(version: str) -> int:
    """Return the major version integer, or 0 if unparseable."""
    m = re.match(r"^v?(\d+)", version.strip())
    return int(m.group(1)) if m else 0


MIGRATION_HINTS = {
    "fastify:4:5": [
        "Async handlers MUST return the reply object: return reply.send(...)",
        "reply.send() no longer accepts callbacks — use async/await",
        "reply.sendFile() removed — use @fastify/static",
        "Full guide: https://github.com/fastify/fastify/blob/main/docs/Guides/Migration-Guide-V5.md",
    ],
    "express:4:5": [
        "express.bodyParser() removed — use express.json() / express.urlencoded()",
        "res.json() no longer accepts status as first arg — use res.status(N).json(...)",
        "Full guide: https://expressjs.com/en/guide/migrating-5.html",
    ],
    "mongoose:7:8": [
        "Model.findByIdAndUpdate() no longer returns the old doc by default — pass { returnDocument: 'after' }",
        "Strict mode is now on by default for queries",
        "Full guide: https://mongoosejs.com/docs/migrating_to_8.html",
    ],
    "next:13:14": [
        "Pages Router unchanged — App Router is stable and preferred",
        "next/font now requires explicit subsets",
        "Full guide: https://nextjs.org/docs/app/building-your-application/upgrading/version-14",
    ],
    "next:14:15": [
        "Async request APIs (cookies, headers, params) are now required to be awaited",
        "Full guide: https://nextjs.org/docs/app/building-your-application/upgrading/version-15",
    ],
    "knex:2:3": [
        "knex() constructor no longer accepts a callback — use .initialize()",
        "Full guide: https://github.com/knex/knex/blob/master/CHANGELOG.md",
    ],
    "sequelize:6:7": [
        "DataTypes.STRING no longer coerces numbers — validate input explicitly",
        "Full guide: https://sequelize.org/docs/v7/other-topics/upgrade/",
    ],
    "typeorm:0:1": [
        "createConnection() removed — use DataSource instead",
        "Full guide: https://typeorm.io/changelog",
    ],
    "jest:28:29": [
        "jest-circus is now the default runner — remove explicit testRunner config",
        "Full guide: https://jestjs.io/blog/2022/08/25/jest-29",
    ],
    "webpack:4:5": [
        "Node.js polyfills no longer injected automatically — add fallback config explicitly",
        "Full guide: https://webpack.js.org/migrate/5/",
    ],
}


def _migration_notes(pkg: str, from_ver: str, to_ver: str) -> str:
    """Return formatted migration notes if hints exist for this major bump, else empty string."""
    from_major = _major(from_ver)
    to_major = _major(to_ver)
    key = f"{pkg.lower()}:{from_major}:{to_major}"
    hints = MIGRATION_HINTS.get(key)
    if not hints:
        return ""
    lines = "\n".join(f"  - {h}" for h in hints)
    return f"\nMIGRATION NOTES:\n{lines}"


# ─────────────────────────── abandoned / staleness checks ───────────────────────────
# STALENESS_THRESHOLD_DAYS and the is_stale helper are imported from
# safedep.staleness above — shared with the manual-mode skill so the
# 2-year threshold lives in a single source of truth.


# check_abandoned is imported from safedep.abandoned above — shared with the
# standalone scripts and with the manual-mode skill so both surfaces consult the
# same curated list.


def emit_signature_maven(group_id: str, artifact_id: str, version: str, signals: list) -> None:
    """Append a MEDIUM SIGNATURE: signal when Maven Central has no .asc for this artifact.

    Signed artifacts pass silently — ``.asc`` presence is the expected baseline
    for published Maven Central releases. A missing signature (404) is
    noteworthy enough to surface to the developer; lookup failure is fail-open.
    """
    if _tier("signatures", "warn") == "off":
        return
    signed = _maven_has_signature(group_id, artifact_id, version)
    if signed is False:
        signals.append(
            f"SIGNATURE: {group_id}:{artifact_id}@{version} \u2014 unsigned on "
            f"Maven Central (MEDIUM: GPG .asc file missing — uncommon for published artifacts)"
        )


def emit_signature_rubygems(pkg: str, version: str, signals: list) -> None:
    """Append a LOW SIGNATURE: signal when the .gem archive lacks .sig entries.

    Most RubyGems packages are unsigned — this check is informational rather
    than actionable (the developer cannot reasonably require signed gems
    without forking half the ecosystem). LOW severity keeps it out of the
    action-required flow while still appearing in the audit log.
    """
    if _tier("signatures", "warn") == "off":
        return
    signed = _rubygems_has_signature(pkg, version)
    if signed is False:
        signals.append(
            f"SIGNATURE: {pkg}@{version} \u2014 unsigned RubyGem "
            f"(LOW: most gems are unsigned; informational only)"
        )


def check_existence(
    pkg_display: str,
    pkg_registry_name: str,
    version: str,
    ecosystem: str,
    signals: list,
    *,
    group_id: str = "",
    artifact_id: str = "",
) -> bool:
    """Emit UNKNOWN: signal if the package is not found in its canonical registry.

    Closes the fabricated-name bypass where a package that doesn't exist in
    any registry silently passes every check (OSV has no vulns for it, the
    version lister returns empty, staleness has no data).

    Returns True when the package is confirmed-nonexistent and the caller
    should skip subsequent checks for this entry; False otherwise (registry
    confirmed it exists, or the lookup was inconclusive).

    Fail-open: a network error / timeout / malformed response returns
    False (continue with the rest of the audit). Only an explicit 404
    from the registry emits UNKNOWN.
    """
    if _tier("existence", "warn") == "off":
        return False
    exists = _package_exists(
        pkg_registry_name, ecosystem,
        group_id=group_id, artifact_id=artifact_id,
    )
    if exists is False:
        signals.append(
            f"UNKNOWN: {pkg_display}@{version} \u2014 not found in {ecosystem} registry "
            f"(possible typo or fabricated name)"
        )
        return True
    return False


def _stale_threshold_days() -> int:
    """Staleness threshold in days, routed through the safedep.config oracle
    (issue #232): SAFE_DEP_STALE_YEARS env takes precedence over the policy
    file's `staleness.years`, both converted at 365 days/yr. Hard fallback to
    STALENESS_THRESHOLD_DAYS if the oracle is unavailable (issue #190)."""
    try:
        from safedep.config import stale_years
        return int(stale_years() * 365)
    except Exception:
        return STALENESS_THRESHOLD_DAYS


def _stale_popularity_guard_enabled() -> bool:
    """The issue #231 guard is ON by default; routed through the safedep.config
    oracle (issue #232): SAFE_DEP_STALE_POPULARITY_GUARD env (0/false/no/off
    disables — the deterministic-testing escape hatch) takes precedence over
    the policy file's `staleness.popularity_guard`. Hard fallback to the
    env-only check if the oracle is unavailable."""
    try:
        from safedep.config import stale_popularity_guard
        return stale_popularity_guard()
    except Exception:
        return os.environ.get("SAFE_DEP_STALE_POPULARITY_GUARD", "").strip().lower() not in {
            "0", "false", "no", "off",
        }


def _stale_guard_applies(pkg: str, ecosystem: str,
                         pinned_version: str, newest_version: str,
                         age_days: int, threshold_days: int) -> bool:
    """Issue #231: elapsed time alone cannot distinguish "mature and stable"
    from "abandoned and risky". Suppression requires ALL of:
      - the pinned version IS the newest stable release (user isn't behind),
      - adoption above the per-ecosystem popularity threshold, and
      - the release is at most 2x the staleness threshold old. "The project
        simply hasn't needed a release" is plausible at 2-4 years; a 10-year
        silence is abandonment regardless of install inertia (e.g. nose still
        clears the download bar a decade after its last release).
    Popularity lookup is fail-closed for the guard (lookup failure → guard
    does not apply → STALE still fires): suppression needs corroboration,
    and absence of data is not corroboration.

    Caveat: the rubygems popularity metric is CUMULATIVE downloads (the v1
    API exposes nothing weekly), i.e. partly install inertia — the 2x age
    cap is the only real backstop there. npm/pypi use weekly figures.
    maven/go/crates have no popularity source, so the guard never fires for
    them (is_popular returns False) and STALE behavior is unchanged.
    """
    if not pinned_version or not newest_version:
        return False
    if not _stale_popularity_guard_enabled():
        return False
    if age_days > 2 * threshold_days:
        return False
    if pinned_version.lstrip("vV") != newest_version.lstrip("vV"):
        return False
    try:
        from safedep.popularity import is_popular
        return bool(is_popular(pkg, ecosystem))
    except Exception:
        return False


_VERSIONS_MEMO: dict = {}


def _versions_for(pkg: str, ecosystem: str, group_id: str = "", artifact_id: str = ""):
    """One in-process fetch of the stable-version list per (eco, pkg) per
    hook run — check_staleness and check_cooloff share it (review M1).
    Failures return [] and are memoized (same answer within one run)."""
    key = (ecosystem, pkg, group_id, artifact_id)
    if key in _VERSIONS_MEMO:
        return _VERSIONS_MEMO[key]
    try:
        if ecosystem == "npm":
            versions = npm_versions(pkg)
        elif ecosystem == "pypi":
            versions = pypi_versions(pkg)
        elif ecosystem == "rubygems":
            versions = rubygems_versions(pkg)
        elif ecosystem == "crates":
            versions = crates_versions(pkg)
        elif ecosystem == "maven":
            versions = maven_versions(group_id, artifact_id)
        else:
            versions = []
    except Exception:  # noqa: BLE001
        versions = []
    _VERSIONS_MEMO[key] = versions
    return versions


def check_staleness(pkg: str, ecosystem: str, group_id: str = "", artifact_id: str = "",
                    pinned_version: str = ""):
    """
    Return (is_stale, last_date_str, status):
      (True,  'YYYY-MM-DD', "stale")  — newest stable release is older than the
                                        staleness threshold (default 730 days;
                                        override via SAFE_DEP_STALE_YEARS)
      (False, 'YYYY-MM-DD', "mature") — old by the threshold, but the pinned
                                        version IS the current latest and the
                                        package clears the popularity bar
                                        (issue #231 guard; see _stale_guard_applies)
      (False, None,         "fresh")  — not stale (or lookup failed)
    Fetches only the top-1 version for Go to limit HTTP calls.
    """
    if _tier("stale", "warn") == "off":
        return False, None, "fresh"
    now = datetime.now(tz=timezone.utc)
    try:
        if ecosystem in ("npm", "pypi", "rubygems", "crates", "maven"):
            versions = _versions_for(pkg, ecosystem, group_id, artifact_id)
        elif ecosystem == "go":
            # Fetch top-1 candidate only to limit HTTP calls.
            # proxy.golang.org case-encodes uppercase letters per the module
            # proxy spec — without _goproxy_encode, mixed-case modules 404.
            _enc = _goproxy_encode(pkg)
            raw = _http_get_text(f"https://proxy.golang.org/{_enc}/@v/list")
            if not raw.strip():
                return False, None, "fresh"
            all_versions = [v.strip() for v in raw.splitlines() if v.strip()]
            stable = [v for v in all_versions if not _is_prerelease(v, "go")]
            stable.sort(key=_semver_key, reverse=True)
            versions = []
            for v in stable[:1]:
                info = _http_get(f"https://proxy.golang.org/{_enc}/@v/{v}.info", timeout=5)
                if info and info.get("Time"):
                    try:
                        dt = _parse_dt(info["Time"])
                        versions = [(v, dt)]
                    except Exception:
                        pass
        else:
            return False, None, "fresh"
    except Exception:
        return False, None, "fresh"

    if not versions:
        return False, None, "fresh"

    newest_ver, newest_dt = versions[0]
    threshold = _stale_threshold_days()
    stale, last_date = _is_stale(newest_dt, now=now, threshold_days=threshold)
    if not stale:
        return False, None, "fresh"
    age_days = (now - newest_dt).days
    # "Latest" must hold under BOTH orderings (review finding): versions[0]
    # is newest-by-publish-DATE; a recently-published old-branch backport can
    # make it differ from the highest semver. Requiring the pin to equal both
    # keeps the mature NOTE from affirming "current latest" to a user who is
    # actually behind the highest release.
    try:
        semver_newest = max(versions, key=lambda t: _semver_key(t[0]))[0]
    except Exception:  # noqa: BLE001
        semver_newest = newest_ver
    if (_stale_guard_applies(pkg, ecosystem, pinned_version, newest_ver,
                             age_days, threshold)
            and pinned_version.lstrip("vV") == semver_newest.lstrip("vV")):
        return False, last_date, "mature"
    return True, last_date, "stale"


def check_cooloff(pkg: str, version: str, ecosystem: str,
                  group_id: str = "", artifact_id: str = ""):
    """Release-age gate (issue #232).

    Returns (action, signal, rewrite_target):
      (None, None, None)              — off / aged / unknown date (fail-open)
      ("confirm", "COOLOFF-CONFIRM: …", None)   — warn mode, or block mode
                                        with no aged candidate to rewrite to
      ("rewrite", "COOLOFF: …", "<ver>")        — block mode; rewrite pin to
                                        the newest version clearing the window
    Reuses the same per-ecosystem version lists as check_staleness (one
    shared fetch via the pooled HTTP cache). Never gates CVE-driven
    rewrites — call sites run it only when the pin is CVE-clean, which is
    exactly the spec's security-fix exception.
    """
    if _policy_cooloff_mode is None:
        return None, None, None
    try:
        mode = _policy_cooloff_mode()
    except Exception:  # noqa: BLE001
        return None, None, None
    if mode == "off":
        return None, None, None
    try:
        days = _policy_cooloff_days() if _policy_cooloff_days else 7
    except Exception:  # noqa: BLE001
        days = 7
    now = datetime.now(tz=timezone.utc)
    if ecosystem not in ("npm", "pypi", "rubygems", "crates", "maven"):
        return None, None, None  # go: covered by Pre-Install only
    versions = _versions_for(pkg, ecosystem, group_id, artifact_id)
    if not versions:
        return None, None, None  # lookup failure — fail open, parity with old except
    pin_dt = None
    want = version.lstrip("vV")
    for ver, dt in versions:
        if ver.lstrip("vV") == want:
            pin_dt = dt
            break
    if pin_dt is None:
        return None, None, None  # unknown date — fail open
    age = (now - pin_dt).days
    if age >= days:
        return None, None, None
    ago = f"{age} day{'' if age == 1 else 's'} ago"
    if mode == "warn":
        return ("confirm",
                f"COOLOFF-CONFIRM: {pkg}@{version} was published {ago} "
                f"(window: {days}d) — too new to be community-vetted. Ask the "
                f"developer whether to proceed or pin an older release.",
                None)
    # block: newest same-major version clearing the window that is ALSO
    # OSV-clean — a security tool must never rewrite to a vulnerable or
    # cross-major target (review findings C1/I1). No qualifying candidate →
    # downgrade to confirm.
    aged = [(v, dt) for v, dt in versions if (now - dt).days >= days]
    target = None
    for v, _dt in aged:
        if _major(v) != _major(version):
            continue
        try:
            # _vuln_check returns the CVE list — truthy means vulnerable.
            if _vuln_check(pkg, v, ecosystem, group_id, artifact_id):
                continue
        except Exception:  # noqa: BLE001 — lookup failure: do not trust the candidate
            continue
        target = v
        break
    if target is not None:
        return ("rewrite",
                f"COOLOFF: {pkg}@{version} was published {ago} "
                f"(window: {days}d) — rewritten to {target}, the newest "
                f"clean release clearing the window.",
                target)
    return ("confirm",
            f"COOLOFF-CONFIRM: {pkg}@{version} was published {ago} "
            f"(window: {days}d) and no clean same-major release clears the "
            f"window — ask the developer before proceeding.",
            None)


# ─────────────────────────── first-publish age + GitHub repo age ───────────────────────────
# Advisory-only signals. A fresh package (< 30 days since first-ever publish) or a
# freshly-created GitHub repo is an elevated supply-chain risk even when the
# current version passes CVE / staleness / abandoned checks. Both emit WARNING.
#
# first_publish_date / first_publish_age_days are imported from safedep.registry
# above — shared with skills/scripts/first_publish_{pypi,rubygems,maven}.py.

FIRST_PUBLISH_THRESHOLD_DAYS = 30
GITHUB_REPO_THRESHOLD_DAYS = 30


def advisory_age_checks(pkg_display: str, version: str, pkg_registry_name: str,
                        ecosystem: str, signals: list,
                        group_id: str = "", artifact_id: str = "") -> None:
    """Run first-publish + GitHub-repo age checks; append WARNING signals as needed.

    pkg_display: name shown in signals (e.g. 'group:artifact' for maven)
    pkg_registry_name: name used in registry API calls (e.g. osv_name for pypi)
    """
    if _tier("first_publish_age", "warn") == "off":
        return
    fp_days = first_publish_age_days(
        pkg_registry_name, ecosystem,
        group_id=group_id, artifact_id=artifact_id,
    )
    if fp_days is None or fp_days >= FIRST_PUBLISH_THRESHOLD_DAYS:
        return
    signals.append(
        f"WARNING: {pkg_display}@{version} \u2014 package first published "
        f"{fp_days} days ago (below 30-day community vetting threshold)"
    )
    # Only check GitHub repo age when first-publish has already flagged —
    # limits GitHub API usage to suspicious packages (60/hr unauthenticated limit).
    if ecosystem not in ("npm", "pypi", "rubygems"):
        return
    repo_path = _github_repo_for_package(pkg_registry_name, ecosystem)
    if not repo_path:
        return
    repo_days = github_repo_age_days(repo_path)
    if repo_days is None or repo_days >= GITHUB_REPO_THRESHOLD_DAYS:
        return
    signals.append(
        f"WARNING: {pkg_display}@{version} \u2014 GitHub repository {repo_path} "
        f"is {repo_days} days old (newly-created project, elevated supply-chain risk)"
    )


# ─────────────────────────── session skip list ───────────────────────────

SESSION_ID = os.environ.get("CLAUDE_SESSION_ID", "default")
SKIP_FILE = os.path.expanduser(f"~/.claude/sd-skipped-{SESSION_ID}.json")


def _read_skip_list() -> dict:
    """Return {pkg: version} of developer-declined MAJOR-UPDATEs. Empty dict on any error."""
    try:
        with open(SKIP_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


# ─────────────────────────── adaptive VERIFY helpers ───────────────────────────

def _detect_install_cmd(manifest_path: str, ecosystem: str) -> str:
    """Return the correct install command based on lock files and ecosystem."""
    root = os.path.dirname(manifest_path)
    if ecosystem == "npm":
        if os.path.exists(os.path.join(root, "yarn.lock")):
            return "yarn install"
        if os.path.exists(os.path.join(root, "pnpm-lock.yaml")):
            return "pnpm install"
        return "npm install"
    if ecosystem == "pypi":
        if os.path.exists(os.path.join(root, "poetry.lock")):
            return "poetry install"
        if os.path.exists(os.path.join(root, "uv.lock")):
            return "uv sync"
        if os.path.basename(manifest_path) == "Pipfile":
            return "pipenv install"
        return "pip install -r requirements.txt"
    if ecosystem == "rubygems":
        return "bundle install"
    if ecosystem == "maven":
        if os.path.basename(manifest_path).startswith("build.gradle"):
            return "gradle dependencies"
        return "mvn dependency:resolve"
    if ecosystem == "go":
        return "go mod tidy"
    if ecosystem == "crates":
        # `cargo build` is the canonical "after Cargo.toml changed, fetch +
        # compile" verb. `cargo fetch` only downloads (no compile), and
        # `cargo check` skips codegen — both leave the build state
        # ambiguous. `cargo build` exits non-zero on any incompatibility,
        # which is what we want the agent to surface and act on after a
        # CVE-driven bump.
        return "cargo build"
    if ecosystem == "packagist":
        return "composer update"
    return "install dependencies"


def _detect_tests(manifest_path: str) -> bool:
    """Return True if a test suite is detected near the manifest."""
    root = os.path.dirname(manifest_path)
    for d in ("test", "tests", "__tests__", "spec"):
        if os.path.isdir(os.path.join(root, d)):
            return True
    try:
        with open(os.path.join(root, "package.json"), "r", encoding="utf-8") as fh:
            pkg = json.loads(fh.read())
        scripts = pkg.get("scripts", {})
        if any(k in scripts for k in ("test", "jest", "mocha", "vitest")):
            return True
    except Exception:
        pass
    try:
        with open(os.path.join(root, "pyproject.toml"), "r", encoding="utf-8") as fh:
            toml_content = fh.read()
        if any(t in toml_content for t in ("pytest", "unittest", "[tool.pytest")):
            return True
    except Exception:
        pass
    return False


def _detect_test_cmd(manifest_path: str, ecosystem: str) -> str:
    """Return the likely test command for the ecosystem."""
    if ecosystem == "npm":
        return "npm test"
    if ecosystem == "pypi":
        return "pytest"
    if ecosystem == "rubygems":
        return "bundle exec rspec"
    if ecosystem == "maven":
        if os.path.basename(manifest_path).startswith("build.gradle"):
            return "gradle test"
        return "mvn test"
    if ecosystem == "go":
        return "go test ./..."
    if ecosystem == "crates":
        return "cargo test"
    if ecosystem == "packagist":
        return "composer test"
    return "run tests"


def _parse_semver_triple(v):
    """Parse 'X[.Y[.Z]]' (with optional leading 'v') into a (X, Y, Z) int tuple.
    Returns None if no numeric major could be extracted."""
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", (v or "").strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def _simple_semver_satisfies(target, range_str):
    """Conservative npm-style semver-range satisfaction.

    Returns True / False / None (None == can't determine; caller treats
    None as "don't flag" to avoid false positives on exotic ranges).

    Handles the peer-constraint patterns that actually appear in npm
    metadata: ``''``, ``*``, ``X``, ``X.Y``, ``X.Y.Z`` (exact), ``X.x``,
    ``X.Y.x``, ``^X.Y.Z`` (with the 0.x.y corner case), ``~X.Y.Z``,
    ``>=X.Y.Z`` / ``>X.Y.Z`` / ``<X.Y.Z`` / ``<=X.Y.Z``, and ``A || B``
    alternation. Space-separated ANDs (``>=1 <2``) are handled too.

    Anything else returns None — better silent than wrong.
    """
    if range_str is None:
        return None
    rs = range_str.strip()
    if rs == "" or rs == "*" or rs.lower() == "x":
        return True
    if "||" in rs:
        any_ok = False
        any_none = False
        for alt in rs.split("||"):
            r = _simple_semver_satisfies(target, alt.strip())
            if r is True:
                any_ok = True
                break
            if r is None:
                any_none = True
        if any_ok:
            return True
        return None if any_none else False
    # Space-separated AND, e.g. ">=1.0.0 <2.0.0"
    toks = rs.split()
    if len(toks) > 1 and all(re.match(r"^([<>]=?|=|\^|~)?\d", t) for t in toks):
        results = [_simple_semver_satisfies(target, t) for t in toks]
        if any(r is False for r in results):
            return False
        if any(r is None for r in results):
            return None
        return True
    t = _parse_semver_triple(target)
    if t is None:
        return None
    # ^X.Y.Z  (npm caret: lock to leading non-zero major; for 0.x.y lock to leading non-zero minor)
    m = re.match(r"^\^(\d+)(?:\.(\d+))?(?:\.(\d+))?$", rs)
    if m:
        rx, ry, rz = int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)
        if rx > 0:
            return (t >= (rx, ry, rz)) and (t < (rx + 1, 0, 0))
        if ry > 0:
            return (t >= (0, ry, rz)) and (t < (0, ry + 1, 0))
        return (t >= (0, 0, rz)) and (t < (0, 0, rz + 1))
    # ~X.Y.Z
    m = re.match(r"^~(\d+)(?:\.(\d+))?(?:\.(\d+))?$", rs)
    if m:
        rx, ry, rz = int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)
        return (t >= (rx, ry, rz)) and (t < (rx, ry + 1, 0))
    # Comparators
    m = re.match(r"^(>=|<=|>|<|=)?(\d+)(?:\.(\d+))?(?:\.(\d+))?$", rs)
    if m:
        op = m.group(1) or "="
        rx = int(m.group(2))
        ry = int(m.group(3) or 0)
        rz = int(m.group(4) or 0)
        rv = (rx, ry, rz)
        if op == ">=":
            return t >= rv
        if op == ">":
            return t > rv
        if op == "<=":
            return t <= rv
        if op == "<":
            return t < rv
        # Exact: only require components that were supplied.
        if m.group(4):
            return t == rv
        if m.group(3):
            return t[0] == rx and t[1] == ry
        return t[0] == rx
    # X.x / X.* / X.Y.x / X.Y.*
    m = re.match(r"^(\d+)\.(?:x|\*)(?:\.(?:\d+|x|\*))?$", rs)
    if m:
        return t[0] == int(m.group(1))
    m = re.match(r"^(\d+)\.(\d+)\.(?:x|\*)$", rs)
    if m:
        return t[0] == int(m.group(1)) and t[1] == int(m.group(2))
    return None


def _fetch_npm_peer_deps(pkg, version):
    """Fetch the peerDependencies dict for npm pkg@version.

    Returns a dict (possibly empty) on success, or ``None`` on any fetch
    failure / 404 / parse failure. Negative results are cached with a
    sentinel string so we don't re-hammer the registry for the same
    missing version within the TTL window.
    """
    if not pkg or not version:
        return None
    key = _cache.versions_key("npm-peerdeps", f"{pkg}@{version}")
    cached = _cache.get(key)
    if cached is not None:
        return None if cached == "_NONE_" else cached
    encoded = pkg.replace("@", "%40").replace("/", "%2F")
    data = _http_get(
        f"https://registry.npmjs.org/{encoded}/{version}", timeout=5
    )
    if not data or not isinstance(data, dict):
        _cache.put(key, "_NONE_", _cache.TTL_VERSIONS)
        return None
    peer_deps = data.get("peerDependencies") or {}
    if not isinstance(peer_deps, dict):
        peer_deps = {}
    _cache.put(key, peer_deps, _cache.TTL_VERSIONS)
    return peer_deps


def _check_npm_peer_conflicts(major_pkg, new_ver, manifest_packages):
    """Scan ``manifest_packages`` for declared peer constraints on
    ``major_pkg`` that ``new_ver`` would violate. Returns a list of
    ``PEER-COMPAT:`` signal strings (one per conflicting consumer).

    Each entry in ``manifest_packages`` is a tuple where index 0 is the
    package name and index 1 is its (cleaned) version. Tuples can have a
    third ``dep_key`` element from ``parse_package_json``; it is ignored.

    Empty list means either "no conflicts" or "registry unreachable for
    every consumer"; callers fall back to the generic note in the latter
    case so the agent still has *something* actionable.
    """
    conflicts = []
    for entry in manifest_packages or []:
        if not isinstance(entry, (tuple, list)) or len(entry) < 2:
            continue
        other_pkg, other_ver = entry[0], entry[1]
        if not other_pkg or other_pkg == major_pkg:
            continue
        peer_deps = _fetch_npm_peer_deps(other_pkg, other_ver)
        if not peer_deps:
            continue
        peer_range = peer_deps.get(major_pkg)
        if not peer_range:
            continue
        satisfies = _simple_semver_satisfies(new_ver, peer_range)
        if satisfies is False:
            conflicts.append(
                f"PEER-COMPAT: {other_pkg}@{other_ver} declares peer "
                f"`{major_pkg}: {peer_range}`; proposed upgrade to "
                f"{major_pkg}@{new_ver} does not satisfy that range. "
                f"Upgrade {other_pkg} to a version that lists "
                f"{major_pkg}@{new_ver} as an accepted peer."
            )
    return conflicts


def _build_peer_compat_note(pkg, new_ver, ecosystem, manifest_path,
                            manifest_packages=None):
    """Build PEER-COMPAT signal(s) for an npm major bump.

    With ``manifest_packages`` provided (audit_npm passes the parsed list):
      1. Fetch each other package's ``peerDependencies`` from
         registry.npmjs.org.
      2. For any peer constraint on ``pkg`` violated by ``new_ver``,
         emit a *specific* PEER-COMPAT signal naming the conflicting
         consumer and quoting its peer range. This is the registry-aware
         path that catches cases like @vitejs/plugin-react@4.x declaring
         vite peer ``^4 || ^5`` when vite is being bumped to 8.
      3. If specific conflicts are found, return them joined by newlines.
      4. If no conflicts are found AND we successfully fetched metadata
         for at least one other package, return "" — the registry
         actively told us there is no conflict, so a generic note would
         be noise.
      5. If we could not fetch metadata for ANY other package (offline /
         all timeouts), fall back to the generic safety-net note so the
         agent at least knows to watch the install output.

    Non-npm ecosystems return "" — peerDependencies is npm-specific.
    """
    if ecosystem != "npm":
        return ""
    install_cmd = _detect_install_cmd(manifest_path, ecosystem)
    generic_note = (
        f"PEER-COMPAT-NOTE: {pkg} is being major-bumped to {new_ver}. Other "
        f"packages in this manifest may declare peerDependencies that "
        f"exclude this major. After `{install_cmd}`, inspect the install "
        f"output for `npm WARN ERESOLVE` or `unmet peer dependency` lines "
        f"naming {pkg}; if any appear, upgrade the warning package(s) to a "
        f"version that lists {pkg}@{new_ver} as an accepted peer."
    )
    if not manifest_packages:
        return generic_note
    # Specific path: try the registry-aware check.
    conflicts = _check_npm_peer_conflicts(pkg, new_ver, manifest_packages)
    if conflicts:
        return "\n".join(conflicts)
    # Conflicts list is empty. Distinguish "registry confirmed no conflict"
    # from "we couldn't reach the registry at all" — if at least one other
    # consumer's metadata fetch succeeded, treat empty as authoritative.
    saw_any_meta = False
    for entry in manifest_packages:
        if not isinstance(entry, (tuple, list)) or len(entry) < 2:
            continue
        if entry[0] == pkg:
            continue
        if _fetch_npm_peer_deps(entry[0], entry[1]) is not None:
            saw_any_meta = True
            break
    return "" if saw_any_meta else generic_note


def _build_blocked_replacement_refactor_signal(pkg, ecosystem, manifest_path):
    """Build a REFACTOR-CHECK signal emitted alongside CVE-BLOCKED removals.

    When the shim emits ``BLOCKED: {pkg} {version} has {cves} — entry
    removed``, the offending entry is stripped from the manifest. The
    agent is then expected to choose a replacement — typically either a
    higher major of the same package (the case Rust's jsonwebtoken 9 →
    10 and rand 0.8 → 0.10 took during real builds) or a different
    package entirely. Either replacement carries the same consumer-code
    refactor risk as a MAJOR-UPDATE-CONFIRM, but the existing
    ``_build_major_bump_refactor_signal`` is only wired to the
    MAJOR-UPDATE-CONFIRM emission sites — BLOCKED paths emit no refactor
    directive at all, so agents have been observed discovering the API
    breakage at compile / runtime instead of from a write-time nudge.

    This helper closes that gap. It is intentionally generic about the
    target version (the agent hasn't picked one yet when BLOCKED fires)
    so it warns about the *category* of risk rather than quoting a
    specific peer range or migration note: "your replacement may have a
    different API surface — review imports and the replacement's
    changelog before declaring the upgrade done."

    Tiering mirrors the existing refactor helper: when tests are
    detected we name the test command so the agent has a concrete
    completion gate.
    """
    install_cmd = _detect_install_cmd(manifest_path, ecosystem)
    head = (
        f"REFACTOR-CHECK: {pkg} was removed because no safe version "
        f"exists in its current major. Any replacement — whether a "
        f"higher major of {pkg} or a different package — is likely to "
        f"differ in API surface."
    )
    if _detect_tests(manifest_path):
        test_cmd = _detect_test_cmd(manifest_path, ecosystem)
        return (
            f"{head} After `{install_cmd}` review every file importing "
            f"{pkg} against the replacement's changelog or migration "
            f"guide; refactor API usage as needed, then run `{test_cmd}`. "
            f"Do not claim the upgrade is complete until tests pass."
        )
    return (
        f"{head} After `{install_cmd}` review every file importing "
        f"{pkg} against the replacement's changelog or migration guide; "
        f"refactor API usage as needed. Do not claim the upgrade is "
        f"complete until you have explicitly confirmed compatibility."
    )


def _build_major_bump_refactor_signal(pkg, old_ver, new_ver, manifest_path,
                                      ecosystem, migration_notes=""):
    """Build a REFACTOR-REQUIRED signal emitted alongside MAJOR-UPDATE-CONFIRM.

    Major version bumps almost always contain breaking API changes. Without
    an explicit nudge, agents have been observed to accept the bump and skip
    the consumer-code review that breaking changes require — they lean on
    "the build passed" / "tests passed" as proof of correctness, even when
    no tests exercise the affected code paths. This signal forces the agent
    to plan refactoring work *before* claiming the upgrade is complete.

    Why a separate signal (not just a sentence appended to the existing
    MAJOR-UPDATE-CONFIRM): the parent agent reads signal *lines* and decides
    which to act on. A distinct REFACTOR-REQUIRED prefix is easier to grep for,
    test against, and route to a follow-up workflow than a paragraph buried
    inside the CONFIRM block. It also keeps the CONFIRM block focused on the
    upgrade-or-not authorization question, separate from the post-upgrade
    correctness question.

    Tiering mirrors ``_build_verify_signal``:
      * If per-package migration notes are known, surface those breaking
        patterns by name so the agent knows what to grep for.
      * If the project has tests, name the test command so the agent
        runs them explicitly after refactoring.
      * Generic fallback: review all importers + consult changelog.
    """
    install_cmd = _detect_install_cmd(manifest_path, ecosystem)
    head = (
        f"REFACTOR-REQUIRED: {pkg} {old_ver} → {new_ver} is a MAJOR version "
        f"bump. Before claiming the upgrade is complete, you MUST:"
    )
    if migration_notes:
        return (
            f"{head} If you proceed, after `{install_cmd}` audit every file "
            f"importing {pkg} for these breaking patterns:{migration_notes}\n"
            f"Refactor API usage as needed. Do not claim the upgrade is "
            f"complete until no breaking patterns remain."
        )
    if _detect_tests(manifest_path):
        test_cmd = _detect_test_cmd(manifest_path, ecosystem)
        return (
            f"{head} If you proceed, after `{install_cmd}` review every file "
            f"importing {pkg} and consult the {pkg}@{new_ver} changelog / "
            f"migration guide; refactor API usage as needed, then run "
            f"`{test_cmd}`. Do not claim the upgrade is complete until tests "
            f"pass."
        )
    return (
        f"{head} If you proceed, after `{install_cmd}` review every file "
        f"importing {pkg} and consult the {pkg}@{new_ver} changelog / "
        f"migration guide; refactor API usage as needed. Do not claim the "
        f"upgrade is complete until you have explicitly confirmed "
        f"compatibility."
    )


def _build_verify_signal(packages, manifest_path, ecosystem, migration_notes=""):
    """Build adaptive VERIFY/REFACTOR-REQUIRED signal(s) covering every auto-corrected package.

    ``packages`` is a non-empty list of ``(pkg_display, old_ver, new_ver)`` tuples. When
    multiple packages are corrected in a single hook invocation we emit ONE
    combined signal that names every package. For major version bumps, generates
    REFACTOR-REQUIRED with imperative language; otherwise generates VERIFY.

    Tiering is unchanged:
      * Tier 1 (tests detected): one signal, run install + tests. Package list
        is appended so the agent knows which imports to audit if tests fail.
      * Tier 2 (no tests + migration notes): callers pass ``migration_notes``
        for a single representative package whose notes need to surface.
      * Tier 3 (no tests + no migration notes): one signal, review imports for
        each listed package after install.
    """
    if not packages:
        return ""
    install_cmd = _detect_install_cmd(manifest_path, ecosystem)
    has_tests = _detect_tests(manifest_path)

    # Check if any package has a major version bump
    major_bumps = []
    regular_updates = []

    for item in packages:
        if len(item) == 3:  # New format: (pkg_display, old_ver, new_ver)
            pkg_display, old_ver, new_ver = item
            if old_ver != "latest" and new_ver != "latest" and _major(new_ver) > _major(old_ver):
                major_bumps.append((pkg_display, old_ver, new_ver))
            else:
                regular_updates.append((pkg_display, new_ver))
        else:  # Legacy format: (pkg_display, new_ver)
            pkg_display, new_ver = item
            regular_updates.append((pkg_display, new_ver))

    # If we have major bumps, generate REFACTOR-REQUIRED signal
    if major_bumps:
        pkg_display, old_ver, new_ver = major_bumps[0]  # Representative package
        return (
            f"REFACTOR-REQUIRED: {pkg_display} {old_ver} → {new_ver} is a MAJOR version bump. Before claiming the upgrade is complete, you MUST:\n"
            f"  1. Find every file that imports {pkg_display} (`grep -r \"from {pkg_display}\" .` or equivalent)\n"
            f"  2. Consult the {pkg_display} migration guide for breaking API changes\n"
            f"  3. Update each import site to match the new API\n"
            f"  4. Run the test suite and confirm it passes\n"
            f"Skipping these steps will leave the codebase in a broken state."
        )

    # Otherwise generate regular VERIFY signal for non-major updates
    pkg_list = ", ".join(f"{p}@{v}" for p, v in regular_updates)
    pkg_names = ", ".join(p for p, _ in regular_updates)

    if has_tests:
        test_cmd = _detect_test_cmd(manifest_path, ecosystem)
        suffix = f" Updated: {pkg_list}." if len(packages) > 1 else ""
        return (
            f"VERIFY: run `{install_cmd}` then run `{test_cmd}`\n"
            f"Confirm both exit 0 before marking this correction complete.{suffix}"
        )
    elif migration_notes:
        # Per-package breaking-pattern audit for a single representative.
        pkg_display = packages[0][0]
        return (
            f"VERIFY: run `{install_cmd}` then audit all files importing {pkg_display} "
            f"for these breaking patterns:{migration_notes}\n"
            f"Confirm install exits 0 and no breaking patterns remain."
        )
    else:
        return (
            f"VERIFY: run `{install_cmd}` then review all files importing {pkg_names} "
            f"to confirm API usage is compatible with the new version(s).\n"
            f"Confirm install exits 0 before marking this correction complete."
        )


def _stale_lockfile_signal(
    file_path: str,
    ecosystem: str,
    install_cmd: str,
    pre_rewrite_mtime=None,  # float or None
) -> str:
    """Return a STALE-LOCKFILE signal if the lock file is absent or predates the manifest.

    ``pre_rewrite_mtime`` is the manifest mtime captured BEFORE the shim rewrote it.
    Using the pre-rewrite mtime is essential: ``_finalize_audit`` writes the manifest
    itself, so the post-rewrite mtime is always 'now' and would falsely flag any lock
    file written before the current invocation — including lock files that are
    genuinely up-to-date from a prior ``npm install``.

    With ``pre_rewrite_mtime`` we answer the correct question: "was the lock file
    updated after the agent last changed the manifest (before the shim ran)?"

    Falls back to the current mtime when ``pre_rewrite_mtime`` is None (e.g. when
    called from contexts outside ``_finalize_audit``).

    Returns an empty string when no stale condition is detected (lock file is
    fresh, or the ecosystem has no canonical lock file).
    """
    _lock_candidates: dict = {
        "npm":      ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "pypi":     ["Pipfile.lock", "poetry.lock", "uv.lock"],
        "rubygems": ["Gemfile.lock"],
        "go":       ["go.sum"],
        "crates":   ["Cargo.lock"],
        "maven":    ["gradle.lockfile"],
    }
    # Each lock file is (re)generated by its own toolchain — the advice must
    # name a command that actually produces that file. The generic per-
    # ecosystem install_cmd is wrong across toolchains within one ecosystem
    # (verified live: a requirements.txt project was told to run
    # `pip install -r requirements.txt` "to generate Pipfile.lock", which
    # pip cannot do — that file is pipenv's).
    _lock_regen_cmds: dict = {
        "package-lock.json": "npm install",
        "yarn.lock":         "yarn install",
        "pnpm-lock.yaml":    "pnpm install",
        "Pipfile.lock":      "pipenv install",
        "poetry.lock":       "poetry lock",
        "uv.lock":           "uv lock",
        "pdm.lock":          "pdm lock",
        "Gemfile.lock":      "bundle install",
        "go.sum":            "go mod tidy",
        "Cargo.lock":        "cargo build",
        "gradle.lockfile":   "gradle dependencies --write-locks",
    }
    candidates = _lock_candidates.get(ecosystem, [])
    # pypi is multi-toolchain: which lock file is canonical depends on the
    # manifest. Plain requirements.txt / setup.py / setup.cfg projects have
    # NO canonical lock file at all — for those, only warn about an existing
    # stale lock, never claim a missing one should be generated.
    manifest_basename = os.path.basename(file_path)
    absent_is_reportable = True
    if ecosystem == "pypi":
        if manifest_basename == "Pipfile":
            candidates = ["Pipfile.lock"]
        elif manifest_basename == "pyproject.toml":
            candidates = ["poetry.lock", "uv.lock", "pdm.lock"]
        else:
            candidates = ["Pipfile.lock", "poetry.lock", "uv.lock"]
            absent_is_reportable = False
    if not candidates:
        return ""
    if pre_rewrite_mtime is None:
        try:
            pre_rewrite_mtime = os.path.getmtime(file_path)
        except OSError:
            return ""
    root = os.path.dirname(os.path.abspath(file_path))
    for lock_name in candidates:
        lock_path = os.path.join(root, lock_name)
        if os.path.exists(lock_path):
            try:
                lock_mtime = os.path.getmtime(lock_path)
            except OSError:
                continue
            if lock_mtime < pre_rewrite_mtime:
                regen_cmd = _lock_regen_cmds.get(lock_name, install_cmd)
                return (
                    f"STALE-LOCKFILE: {lock_name} predates the last manifest write and still "
                    f"reflects the old dependency versions. Run `{regen_cmd}` now to "
                    f"regenerate {lock_name} before committing — without this step the "
                    f"installed dependencies will not match {manifest_basename}."
                )
            # A matching lock file exists and is at least as recent as the pre-rewrite
            # manifest — install ran after the manifest was last changed. No signal needed.
            return ""
    # No lock file found for any candidate — install has never been run, or was
    # run from a different working directory. Only reportable when the manifest
    # type has a canonical lock file (see absent_is_reportable above).
    if not absent_is_reportable:
        return ""
    first = candidates[0]
    regen_cmd = _lock_regen_cmds.get(first, install_cmd)
    return (
        f"STALE-LOCKFILE: {first} not found after manifest rewrite. "
        f"Run `{regen_cmd}` now to generate {first} and pin the updated "
        f"dependency versions — without a lock file the installed versions are "
        f"non-deterministic."
    )


def go_versions(module: str) -> list:
    """Return [(version, published_datetime), ...] newest-first, stable only."""
    cached = _cached_versions("go", module)
    if cached is not None:
        return cached
    # proxy.golang.org case-encodes uppercase letters per the module proxy
    # spec — without _goproxy_encode, mixed-case modules 404.
    enc = _goproxy_encode(module)
    raw = _http_get_text(f"https://proxy.golang.org/{enc}/@v/list")
    if not raw.strip():
        return []
    all_versions = [v.strip() for v in raw.splitlines() if v.strip()]
    stable = [v for v in all_versions if not _is_prerelease(v, "go")]
    # Sort by semver descending; top candidates are most likely to be recent + clean
    stable.sort(key=_semver_key, reverse=True)
    candidates = stable[:8]
    results = []
    for v in candidates:
        # Use a shorter per-request timeout to stay within the hook's 60s budget
        info = _http_get(f"https://proxy.golang.org/{enc}/@v/{v}.info", timeout=5)
        if info and info.get("Time"):
            try:
                dt = _parse_dt(info["Time"])
                results.append((v, dt))
            except Exception:
                pass
    results.sort(key=lambda x: x[1], reverse=True)
    results = results[:10]
    _put_cached_versions("go", module, results)
    return results


# Crate names are restricted by crates.io to ASCII alphanumerics plus ``-``/``_``.
# Validate before interpolating into the URL path so a malformed or hostile
# manifest name can't traverse paths or inject a different endpoint.
_CRATE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def crates_versions(name: str) -> list:
    """Return [(version, published_datetime), ...] newest-first, stable, non-yanked."""
    if not _CRATE_NAME_RE.match(name or ""):
        return []
    cached = _cached_versions("crates", name)
    if cached is not None:
        return cached
    # crates.io rejects requests without a User-Agent (403); _http_get sets one.
    data = _http_get(f"https://crates.io/api/v1/crates/{name}/versions")
    if not isinstance(data, dict):
        return []
    versions = []
    for entry in data.get("versions", []):
        v = entry.get("num", "")
        if not v or entry.get("yanked") or _is_prerelease(v, "crates"):
            continue
        ts = entry.get("created_at", "")
        try:
            versions.append((v, _parse_dt(ts)))
        except Exception:
            pass
    versions.sort(key=lambda x: x[1], reverse=True)
    versions = versions[:20]
    _put_cached_versions("crates", name, versions)
    return versions


# ─────────────────────────── safe version picker ───────────────────────────

def _vuln_check(osv_name: str, version: str, ecosystem: str,
                group_id: str = "", artifact_id: str = "") -> list:
    """Ecosystem-aware vulnerability check. Use this instead of check_osv inside
    pick_safe_version and any other place that vets candidate versions, so that
    rubygems meta-gem expansion + ruby-advisory-db fallback stay in effect.

    Routes through :func:`check_osv_cached` so ``prewarm_osv_cache`` (#108)
    actually benefits non-rubygems ecosystems — previously the npm / pypi /
    maven / go path called ``check_osv`` directly and bypassed the module cache.
    """
    if ecosystem == "rubygems":
        return check_rubygems_vulns(osv_name, version)
    return check_osv_cached(osv_name, version, ecosystem)


def _candidate_is_osv_stated_fix(
    candidate: str,
    ecosystem: str,
    osv_name: str,
    advisories: list,
) -> bool:
    """True iff any advisory states candidate is a fix for osv_name in this ecosystem.

    An advisory states a fix when it has an ``affected`` entry matching
    this package + ecosystem AND one of that entry's ranges contains a
    ``fixed`` event whose version is ≤ candidate under :func:`_semver_key`.

    Fail-closed: any parse failure, missing field, or ambiguous structure
    returns False. Caller treats False as "no verified fix signal" and
    falls through to the existing age-gate skip → BLOCKED path. We prefer
    false negatives over false positives.

    Only OSV's structured ``fixed`` event is consulted — release-notes
    text, changelog keywords, and advisory summaries are ignored. The
    7-day age gate exists to defend against supply-chain attacks via
    compromised publishers, and release-notes claims are forgeable by
    exactly those attackers. See FAQ.md for the full rationale.
    """
    if not advisories:
        return False
    osv_eco = OSV_ECOSYSTEM.get(ecosystem)
    if not osv_eco:
        return False
    candidate_key = _semver_key(candidate)
    if candidate_key == (0, 0, 0):
        return False
    osv_name_norm = osv_name.lower()
    osv_eco_norm = osv_eco.lower()
    for adv in advisories:
        if not isinstance(adv, dict):
            continue
        for aff in adv.get("affected", []) or []:
            if not isinstance(aff, dict):
                continue
            pkg = aff.get("package") or {}
            if (pkg.get("ecosystem") or "").lower() != osv_eco_norm:
                continue
            if (pkg.get("name") or "").lower() != osv_name_norm:
                continue
            for rng in aff.get("ranges", []) or []:
                if not isinstance(rng, dict):
                    continue
                for event in rng.get("events", []) or []:
                    if not isinstance(event, dict):
                        continue
                    fix = event.get("fixed")
                    if not fix:
                        continue
                    fix_key = _semver_key(fix)
                    if fix_key == (0, 0, 0):
                        continue  # unparseable fix version — fail closed
                    if candidate_key >= fix_key:
                        return True
    return False


def _pyver_tuple(v: str) -> tuple:
    """Parse a dotted version into a tuple of ints, stopping at the first
    non-numeric component. "3.10" -> (3, 10); "3.9.0" -> (3, 9, 0); "3" -> (3,)."""
    parts = []
    for p in str(v).strip().split("."):
        m = re.match(r"\d+", p)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts)


def _pyver_cmp(a: tuple, b: tuple) -> int:
    """Three-way compare two version tuples, zero-padding the shorter one."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _eval_pyver_clause(clause: str, target: tuple) -> bool:
    """True if version tuple ``target`` satisfies one PEP 440-style clause
    (e.g. ``">=3.10"``, ``"!=3.9.*"``, ``"~=3.8"``). Raises ValueError on an
    unparseable clause so the caller can fail open."""
    m = re.match(r"^\s*(===|>=|<=|==|!=|~=|>|<)\s*(.+)$", clause)
    if not m:
        raise ValueError(f"unparseable clause: {clause!r}")
    op, ver = m.group(1), m.group(2).strip()
    wildcard = ver.endswith(".*")
    vt = _pyver_tuple(ver[:-2] if wildcard else ver)
    if not vt:
        raise ValueError(f"unparseable version: {ver!r}")
    if op in ("==", "===", "!="):
        eq = target[: len(vt)] == vt if wildcard else _pyver_cmp(target, vt) == 0
        return eq if op != "!=" else not eq
    if op == "~=":
        prefix = vt[:-1] if len(vt) > 1 else vt
        return _pyver_cmp(target, vt) >= 0 and target[: len(prefix)] == prefix
    if op == ">=":
        return _pyver_cmp(target, vt) >= 0
    if op == ">":
        return _pyver_cmp(target, vt) > 0
    if op == "<=":
        return _pyver_cmp(target, vt) <= 0
    return _pyver_cmp(target, vt) < 0  # op == "<"


def _python_spec_admits(spec, floor: str) -> bool:
    """True if a package whose ``Requires-Python`` is ``spec`` is installable on
    Python ``floor`` (e.g. "3.9"). Empty/None spec admits everything. Any parse
    failure fails OPEN (admits) — never reject a candidate we cannot evaluate."""
    spec = (spec or "").strip()
    if not spec:
        return True
    try:
        target = _pyver_tuple(floor)
        if not target:
            return True
        for clause in spec.split(","):
            if clause.strip() and not _eval_pyver_clause(clause, target):
                return False
        return True
    except Exception:
        return True


def _min_python_floor(spec: str) -> str:
    """Lowest X.Y a project supports, from a requires-python / poetry-python
    spec. ">=3.9" -> "3.9"; "^3.8" -> "3.8"; ">=3.8,<3.13" -> "3.8". Upper-bound-
    only or unparseable specs yield "" (no floor -> no candidate filtering)."""
    spec = (spec or "").strip()
    if not spec:
        return ""
    for clause in spec.split(","):
        m = re.match(r"^\s*(>=|==|~=|\^|~)\s*(\d+(?:\.\d+)*)", clause)
        if m:
            # Keep full precision (e.g. ">=3.9.5" -> "3.9.5"): truncating to
            # "3.9" lowers the floor to 3.9.0 and over-rejects candidates whose
            # Requires-Python lies between 3.9.0 and the real floor (#195 review).
            return m.group(2)
    return ""


def _pyproject_python_floor(content: str) -> str:
    """Project's minimum Python from pyproject.toml: [project].requires-python
    (PEP 621 / uv) or [tool.poetry.dependencies].python (Poetry). "" if absent
    or unparseable."""
    if _tomllib is None:
        return ""
    try:
        data = _tomllib.loads(content)
    except Exception:
        return ""
    spec = data.get("project", {}).get("requires-python", "")
    if not spec:
        spec = (
            data.get("tool", {}).get("poetry", {})
            .get("dependencies", {}).get("python", "")
        )
        # Poetry also allows the table form: python = { version = ">=3.9" }.
        if isinstance(spec, dict):
            spec = spec.get("version", "")
    return _min_python_floor(spec) if isinstance(spec, str) else ""


def pick_safe_version(
    osv_name: str,
    ecosystem: str,
    current_version: str,
    group_id: str = "",
    artifact_id: str = "",
    python_floor: str = "",
) -> tuple:
    """
    Returns (safe_version, current_cves):
      - safe_version == current_version, current_cves == []  → already clean
      - safe_version != current_version, current_cves != []  → needs update
      - safe_version is None, current_cves != []             → no safe version found
    Strategy: same-major first, upgrade-only cross-major, never downgrade.

    Fresh-fix exception: a candidate published < AGE_GATE_DAYS ago is
    allowed *only* when OSV's advisory for one of ``current_cves``
    explicitly lists that candidate version in its ``fixed`` event range.
    Release-notes claims are deliberately not consulted — forgery risk.
    See FAQ.md for the full rationale.
    """
    if _tier("cve", "block") == "off":
        return None, []
    now = datetime.now(tz=timezone.utc)

    # Check current version first
    current_cves = _vuln_check(osv_name, current_version, ecosystem, group_id, artifact_id)
    if not current_cves:
        return current_version, []  # already clean

    # Fetch OSV advisories once for the fresh-fix exception. Fail-open:
    # on lookup error, advisories stays [] — fresh candidates are then
    # blocked as today, and older candidates are unaffected.
    advisories: list = []
    try:
        advisories = check_osv_full(osv_name, current_version, ecosystem)
    except OSVLookupError:
        advisories = []

    # Fetch available versions
    if ecosystem == "npm":
        candidates = npm_versions(osv_name)
    elif ecosystem == "pypi":
        candidates = pypi_versions(osv_name)
    elif ecosystem == "rubygems":
        candidates = rubygems_versions(osv_name)
    elif ecosystem == "maven":
        candidates = maven_versions(group_id, artifact_id)
    elif ecosystem == "go":
        candidates = go_versions(osv_name)
    elif ecosystem == "crates":
        candidates = crates_versions(osv_name)
    else:
        return None, current_cves

    # Issue #195: for PyPI, drop candidates the project's declared Python floor
    # cannot install — a CVE-clean version that requires a newer Python than the
    # project supports is not a usable fix. Fail-open: a release with unknown or
    # empty Requires-Python is kept.
    if ecosystem == "pypi" and python_floor:
        rp_map = pypi_requires_python(osv_name)
        candidates = [
            (v, d)
            for (v, d) in candidates
            if _python_spec_admits(rp_map.get(v, ""), python_floor)
        ]

    current_major = _major(current_version)

    def _first_clean(filtered_candidates):
        for version, pub_date in filtered_candidates:
            age_days = (now - pub_date).days
            if age_days < AGE_GATE_DAYS:
                # Fresh. Allow only when OSV explicitly states this
                # version fixes a current CVE. Release-notes claims are
                # not consulted — see FAQ.
                if not _candidate_is_osv_stated_fix(version, ecosystem, osv_name, advisories):
                    continue
                # Fall through: still verify the candidate is clean of
                # OTHER CVEs. A fix for CVE-X that introduced CVE-Y is
                # not safe.
            cves = _vuln_check(osv_name, version, ecosystem, group_id, artifact_id)
            if not cves:
                return version
        return None

    # Pass 1: same-major candidates (newest → oldest)
    same_major = [(v, d) for v, d in candidates if _major(v) == current_major]
    result = _first_clean(same_major)
    if result:
        return result, current_cves

    # Pass 2: upgrade-only cross-major, newest → oldest by publish date
    # (naturally surfaces the most recently maintained major line)
    higher_major = [(v, d) for v, d in candidates if _major(v) > current_major]
    result = _first_clean(higher_major)
    if result:
        return result, current_cves

    # Pass 3: no safe version found — never downgrade
    return None, current_cves


def _emit_lookup_failures(signals: list, failures: list) -> None:
    """Append one aggregate LOOKUP-FAILED signal summarizing per-package OSV failures.

    This is the user-visible half of the #109 fix: when OSV was rate-limited
    or unreachable for one or more packages, the audit must surface that
    fact distinctly from the CLEAN / UPDATED / BLOCKED set of signals so
    the parent agent doesn't mistake "did not verify" for "verified clean".
    """
    if not failures:
        return
    sample = ", ".join(f"{p}@{v}" for p, v, _ in failures[:5])
    suffix = "" if len(failures) <= 5 else f" (+{len(failures) - 5} more)"
    first_reason = failures[0][2]
    signals.append(
        f"LOOKUP-FAILED: vulnerability lookup failed for {len(failures)} package(s) "
        f"[{sample}{suffix}]. First error: {first_reason}. "
        "CVE status unknown; these entries were NOT auto-corrected. "
        "Retry after rate-limit/connectivity recovers."
    )
    # Idempotent: clear so the call is safe to place before every exit path
    # (audit functions may have multiple `_finalize_audit` / `return` branches).
    failures.clear()


# ─────────────────────────── lockfile fan-out helpers ───────────────────────────

# Both helpers take a ``job`` tuple and return ``(display_name, identifier,
# version, outcome)`` where ``outcome`` is a list of CVE IDs (empty = clean)
# or an :class:`OSVLookupError`. The main thread reduces those tuples into
# the audit's shared ``signals`` / ``lookup_failures`` lists — parallel
# workers never mutate shared state, which keeps everything lock-free.
#
# ``display_name`` is shown in the WARNING signal; ``identifier`` is what the
# LOOKUP-FAILED aggregate uses (may differ for pypi where the OSV name is a
# normalised form and the display name preserves user-visible casing).

def _lockfile_osv_check_one(job: tuple) -> tuple:
    """Thread-safe single-entry CVE lookup via :func:`check_osv_cached`.

    ``job`` is ``(display_name, osv_name, version, ecosystem)``.
    """
    display_name, osv_name, version, ecosystem = job
    try:
        cves = check_osv_cached(osv_name, version, ecosystem)
    except OSVLookupError as exc:
        return (display_name, osv_name, version, exc)
    return (display_name, osv_name, version, cves)


def _lockfile_safe_version_check_one(job: tuple) -> tuple:
    """Thread-safe single-entry CVE lookup via :func:`pick_safe_version`.

    Used for lockfile audits that want the rubygems meta-gem expansion /
    ruby-advisory-db fallback (``audit_gemfile_lock``, ``audit_poetry_lock``,
    ``audit_uv_lock``). Only the ``cves`` component of ``pick_safe_version``
    is consumed — we ignore ``safe_ver`` because lockfiles are not rewritten
    in place, only reported on.
    """
    display_name, osv_name, version, ecosystem = job
    try:
        _safe_ver, cves = pick_safe_version(osv_name, ecosystem, version)
    except OSVLookupError as exc:
        return (display_name, osv_name, version, exc)
    return (display_name, osv_name, version, cves)


# Captures the `— run <command>` remediation suggestion at the end of a
# lockfile WARNING (used only by audit_gemfile_lock / audit_poetry_lock /
# audit_uv_lock / audit_pdm_lock — the four lockfiles where the shim
# offers a specific update command).
_REMEDIATION_SUFFIX_RE = re.compile(r"\s—\s+run\s+(.+?)\s*$")

# Pulls (pkg, version, lockfile, cves) out of a lockfile WARNING. Tolerates
# both `pkg@ver` (rubygems / poetry / npm) and `pkg==ver` (pipfile) forms,
# though only the `@` forms currently carry a `— run` suffix.
_REMEDIATION_HEAD_RE = re.compile(
    r"WARNING:\s+(\S+?)[@=]+(\S+?)\s+in\s+(\S+)\s+has\s+([^—]+?)\s*—"
)


def _matches_remediation(triggering: str, suggestion: str) -> bool:
    """Whether the bash command ``triggering`` is a plausible attempt to
    run the suggestion ``— run <suggestion>`` from a WARNING.

    Match rules — conservative, false negatives are fine, false positives
    are not (a false positive would tell the user their fix failed when
    they never tried it):

    1. The suggestion's first two tokens (package manager + verb, e.g.
       ``bundle update``, ``uv lock``) must appear as consecutive tokens
       somewhere in ``triggering``.
    2. If the suggestion names a specific package (the first non-flag
       token after the verb), the triggering command must either name
       that same package as a non-flag token after the verb, or name no
       package at all (a broader update of everything still counts as
       attempting the fix for the named package).
    """
    s_tokens = suggestion.split()
    t_tokens = triggering.split()
    if len(s_tokens) < 2 or len(t_tokens) < 2:
        return False
    pm, verb = s_tokens[0], s_tokens[1]
    pm_idx = None
    for i in range(len(t_tokens) - 1):
        if t_tokens[i] == pm and t_tokens[i + 1] == verb:
            pm_idx = i
            break
    if pm_idx is None:
        return False
    suggested_pkg = next(
        (tok for tok in s_tokens[2:] if not tok.startswith("-")), None
    )
    if suggested_pkg is None:
        return True
    after_verb = t_tokens[pm_idx + 2:]
    bare_after_verb = [t for t in after_verb if not t.startswith("-")]
    if suggested_pkg in bare_after_verb:
        return True
    if not bare_after_verb:
        return True
    return False


def _remediation_failed_signal(warning_signal: str,
                               triggering_command) -> "str | None":
    """Return a MAJOR-UPDATE-CONFIRM line escalating ``warning_signal``
    when the user has just attempted the WARNING's suggested remediation
    and it did not move the package past the CVE.

    Returns None when there is nothing to escalate: no triggering command
    in scope, no ``— run X`` suffix on the WARNING, the triggering
    command is unrelated, or the WARNING shape is unrecognized.

    The escalation explicitly names the ``vuln-risk`` skill so the
    follow-up workflow is unambiguous: invoke vuln-risk, look for an
    unreleased fix or workaround, then make a documented ship/no-ship
    call with the developer.
    """
    if not triggering_command:
        return None
    suffix_match = _REMEDIATION_SUFFIX_RE.search(warning_signal)
    if not suffix_match:
        return None
    suggestion = suffix_match.group(1).strip()
    if not _matches_remediation(triggering_command, suggestion):
        return None
    head_match = _REMEDIATION_HEAD_RE.match(warning_signal)
    if not head_match:
        return None
    pkg, ver, _lockfile, cves = head_match.groups()
    return (
        f"MAJOR-UPDATE-CONFIRM: {pkg}@{ver} still has {cves.strip()} "
        f"after `{triggering_command.strip()}` — automated update did "
        f"not produce a newer version.\n"
        f"ACTION REQUIRED: Ask the developer whether to proceed with the vulnerability.\n"
        f"  If YES → 1) invoke the vuln-risk skill on the CVE, 2) assess severity, 3) check for unreleased fix or config workaround, 4) document risk assessment, 5) decide whether to ship. Do NOT mark complete after step 3.\n"
        f"  If NO  → block deployment until vulnerability is resolved"
    )


def _reduce_lockfile_results(results, signals: list, lookup_failures: list,
                             format_warning) -> None:
    """Fold the (display, osv_name, version, outcome) tuples from parallel_map
    into the audit's shared ``signals`` and ``lookup_failures`` lists.
    ``format_warning(display_name, version, cves) -> str`` builds the
    per-lockfile WARNING string with the right suffix (``in Gemfile.lock
    — run bundle update`` vs plain ``in lock file`` etc.).

    When ``$SAFE_DEP_TRIGGERING_COMMAND`` records the bash command that
    triggered this audit, each emitted WARNING is checked against that
    command via ``_remediation_failed_signal``: if the user just ran the
    WARNING's own remediation suggestion and the WARNING is still here,
    a MAJOR-UPDATE-CONFIRM escalation is appended right after the
    WARNING.
    """
    triggering = os.environ.get("SAFE_DEP_TRIGGERING_COMMAND", "")
    for display_name, osv_name, version, outcome in results:
        if isinstance(outcome, OSVLookupError):
            lookup_failures.append((osv_name, version, outcome.reason))
            continue
        if outcome:
            warning = format_warning(display_name, version, outcome)
            signals.append(warning)
            escalation = _remediation_failed_signal(warning, triggering)
            if escalation:
                signals.append(escalation)


# ─────────────────────────── manifest parsers ───────────────────────────

def parse_package_json(content: str) -> list:
    """Return [(package, version, dep_key), ...].

    Walks the four standard dep dicts plus npm's ``overrides`` (npm 8.3+)
    and Yarn's ``resolutions``. Both are mechanisms for forcing a
    specific version of a (potentially transitive) dependency. A
    vulnerable version forced via ``overrides`` is the version actually
    installed; auditing only the standard dicts would miss it.

    For ``overrides``/``resolutions``, only flat ``"name": "version"``
    entries are collected. Nested forms (``"react": {".": "18.0",
    "react-dom": "18.0"}``), reference forms (``"$dep-name"``), glob
    patterns (``"**/foo"``), and scoped paths (``"parent/child"``) are
    skipped — they don't pin a top-level package@version coordinate that
    OSV can resolve cleanly. The skipped forms are still picked up by
    package-lock.json / yarn.lock / pnpm-lock.yaml auditing post-install.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    packages = []
    for dep_key in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
        for pkg, ver in data.get(dep_key, {}).items():
            if not isinstance(ver, str):
                # Valid JSON can carry a number/null/object value here; npm
                # rejects it later, but the parser must skip the malformed
                # entry rather than crash and abort the audit of every
                # well-formed pin in the same file.
                continue
            # Strip semver range operators (^, ~, >=, etc.)
            clean = re.sub(r"^[~^>=<\s]+", "", ver.strip())
            if re.match(r"^\d+\.\d+", clean):
                packages.append((pkg, clean, dep_key))
    override_sources = [
        ("overrides", data.get("overrides", {})),
        ("resolutions", data.get("resolutions", {})),
        ("pnpm.overrides", (data.get("pnpm") or {}).get("overrides", {})),
    ]
    for ovr_key, ovr_map in override_sources:
        if not isinstance(ovr_map, dict):
            continue
        for pkg, val in ovr_map.items():
            # Skip nested-form self-reference key and any non-package-like keys.
            if pkg == "." or not re.match(r"^[a-zA-Z0-9@_]", pkg):
                continue
            # Skip Yarn glob patterns and scoped paths.
            if "/" in pkg or "*" in pkg:
                continue
            if not isinstance(val, str):
                continue
            # Skip $-references like "$lodash" (npm overrides feature).
            if val.startswith("$"):
                continue
            clean = re.sub(r"^[~^>=<\s]+", "", val.strip())
            if re.match(r"^\d+\.\d+", clean):
                packages.append((pkg, clean, ovr_key))
    return packages


def _is_composer_platform_package(name: str) -> bool:
    """True for composer virtual / platform packages that have no Packagist
    entry and cannot be queried against OSV.

    Composer's ``require`` block mixes real ``vendor/package`` deps with
    platform constraints: ``php`` (and ``php-64bit`` etc.), PHP extensions
    (``ext-mbstring``), bundled libraries (``lib-openssl``), the Composer
    runtime API (``composer-runtime-api``), and the like. Real packages are
    always ``vendor/name``; platform packages never contain a ``/`` except
    the ``ext-`` / ``lib-`` families which still aren't Packagist names.
    """
    lowered = name.lower()
    if lowered == "php" or lowered.startswith("php-"):
        return True
    if lowered.startswith(("ext-", "lib-", "composer-", "composer_")):
        return True
    # Real Packagist coordinates are always vendor/package. Anything without a
    # slash that isn't already matched above is a non-queryable platform/meta
    # token (e.g. a bare "hhvm").
    if "/" not in name:
        return True
    return False


def parse_composer_json(content: str) -> list:
    """Return [(package, version, dep_key), ...] for composer.json.

    Walks ``require`` and ``require-dev`` (composer's two dependency dicts;
    keys are ``vendor/package``, values are version constraints like
    ``^1.2.3`` / ``1.2.3`` / ``>=1.0``). Mirrors :func:`parse_package_json`:
    range operators are stripped and only entries that resolve to a concrete
    ``major.minor[...]`` pin are returned (unpinned ranges are surfaced by
    the no-pin NOTE in main(), same as the other manifests).

    Composer ``platform`` virtual packages (``php``, ``ext-*``, ``lib-*``,
    ``composer-runtime-api`` …) are skipped — they are not real
    OSV-queryable Packagist packages.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    packages = []
    for dep_key in ("require", "require-dev"):
        section = data.get(dep_key, {})
        if not isinstance(section, dict):
            continue
        for pkg, ver in section.items():
            if not isinstance(ver, str):
                # Valid JSON can carry a non-string value; composer rejects it
                # later, but the parser must skip rather than crash the audit.
                continue
            if _is_composer_platform_package(pkg):
                continue
            # Strip composer range operators (^, ~, >=, etc.) and any
            # stability suffix separator. ``1.2.3`` is the concrete form.
            clean = re.sub(r"^[~^>=<\s]+", "", ver.strip())
            if re.match(r"^\d+\.\d+", clean):
                packages.append((pkg, clean, dep_key))
    return packages


def extract_non_registry_composer_refs(content: str) -> list:
    """Return [(pkg, ref), ...] for composer.json entries whose constraint or
    repository points at a non-Packagist source (``dev-*`` VCS branches,
    inline ``dist.url`` / ``source.url`` repositories). OSV cannot resolve
    these, so the shim emits an UNKNOWN signal per ref (issue #156 parity).
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []
    refs = []
    for dep_key in ("require", "require-dev"):
        section = data.get(dep_key, {})
        if not isinstance(section, dict):
            continue
        for pkg, ver in section.items():
            if _is_composer_platform_package(pkg):
                continue
            if not isinstance(ver, str):
                continue
            v = ver.strip()
            # dev-master, dev-main#<sha>, and explicit VCS/URL constraints are
            # resolved from a repository, not Packagist version metadata.
            if (
                v.startswith("dev-")
                or "#" in v
                or v.startswith(("git+", "git://", "git@", "file:",
                                 "http://", "https://"))
            ):
                refs.append((pkg, v))
    # Inline custom repositories (``repositories`` block with explicit
    # dist/source URLs) override Packagist for the named packages.
    repos = data.get("repositories")
    repo_iter = []
    if isinstance(repos, dict):
        repo_iter = list(repos.values())
    elif isinstance(repos, list):
        repo_iter = repos
    for repo in repo_iter:
        if not isinstance(repo, dict):
            continue
        pkg_block = repo.get("package")
        if isinstance(pkg_block, dict):
            name = pkg_block.get("name", "")
            url = ((pkg_block.get("dist") or {}).get("url")
                   or (pkg_block.get("source") or {}).get("url") or "")
            if name and url:
                refs.append((name, url))
    return refs


def extract_non_registry_npm_refs(content: str) -> list:
    """Return [(pkg, ref), ...] for package.json entries whose version field
    points at a non-registry source (git URL, local path, tarball URL,
    github: shorthand). These cannot be resolved against OSV, so the shim
    emits an UNKNOWN signal for each so the user knows the audit didn't
    apply to that dep (issue #156).
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []
    refs = []
    for dep_key in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
        section = data.get(dep_key) or {}
        if not isinstance(section, dict):
            continue
        for pkg, ver in section.items():
            if not isinstance(ver, str):
                continue
            v = ver.strip()
            if (
                v.startswith(("git+", "git://", "git@", "file:",
                              "http://", "https://", "github:"))
                or v.endswith((".tgz", ".tar.gz"))
            ):
                refs.append((pkg, v))
    return refs


def extract_non_registry_pypi_refs(content: str) -> list:
    """Return non-registry install lines from a requirements.txt-style file.

    Captures bare URL/git+/file: install lines and PEP 508 direct-URL form
    (``pkg @ url``). OSV cannot resolve these refs, so each is reported as
    an UNKNOWN signal (issue #156).
    """
    refs = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if line.startswith(("http://", "https://", "git+", "file:", "ftp://")):
            refs.append(line)
            continue
        # PEP 508 direct URL: ``pkg @ https://...``
        if " @ " in line:
            name, url = line.split(" @ ", 1)
            name = name.strip()
            url = url.strip()
            if url.startswith(("http://", "https://", "git+", "file:")):
                refs.append(f"{name} @ {url}")
    return refs


def parse_requirements_txt(content: str) -> list:
    """Return [(package, version), ...] for pinned (==) entries only.

    Tolerates pip's "extras" syntax (``pkg[extra]==ver`` and
    ``pkg[a,b] == ver``). Extras select optional dependency groups but
    do not change the package's identity for vulnerability lookups, so
    the captured name is the bare package name.
    """
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(
            r"^([A-Za-z0-9_\-\.]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s#;,\[]+)",
            line,
        )
        if m:
            packages.append((m.group(1), m.group(2)))
    return packages


def parse_requirements_hashes(content: str) -> list:
    """Return [(pkg, version, [sha256_hashes])] for pinned lines that declare --hash=sha256:.

    Handles both single-line and backslash-continuation style. Packages without
    declared hashes are omitted — this parser only surfaces hash-pin declarations
    so Layer 4 can validate them.
    """
    results = []
    current_pkg = current_ver = None
    current_hashes = []

    def _flush():
        if current_pkg and current_hashes:
            results.append((current_pkg, current_ver, list(current_hashes)))

    for raw_line in content.splitlines():
        stripped = raw_line.strip().rstrip("\\").strip()
        if not stripped or stripped.startswith("#"):
            continue
        hash_matches = re.findall(r"--hash=sha256:([a-fA-F0-9]{64})", stripped)
        # Skip non-hash lines that start with '-' (pip option lines like -r, -e, -c)
        if stripped.startswith("-") and not hash_matches:
            continue
        # Same extras-tolerant shape as parse_requirements_txt above —
        # see its docstring for why the bare name is captured.
        pkg_match = re.match(
            r"^([A-Za-z0-9_\-\.]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s#;,\[]+)",
            stripped,
        )
        if pkg_match:
            _flush()
            current_pkg = pkg_match.group(1)
            current_ver = pkg_match.group(2)
            current_hashes = list(hash_matches)
        elif hash_matches and current_pkg:
            current_hashes.extend(hash_matches)
    _flush()
    return results


def check_pypi_hash_pin(pkg: str, version: str, declared: list) -> tuple:
    """Validate declared sha256 hashes against PyPI's published digests.

    Returns (ok: bool, pypi_hashes: list). ok is True if at least one declared
    hash matches PyPI's published digests for this version, or if the PyPI fetch
    failed (fail-open — network errors are handled elsewhere).
    """
    if not declared:
        return True, []
    data = _http_get(f"https://pypi.org/pypi/{pkg}/{version}/json")
    if not data:
        return True, []
    published = {sha.lower() for _, sha in _iter_pypi_artifact_hashes(data)}
    if not published:
        return True, []
    declared_lower = {h.lower() for h in declared}
    return bool(declared_lower & published), sorted(published)


def parse_pipfile(content: str) -> list:
    """Return [(package, version), ...] for pinned entries in
    [packages] / [dev-packages].

    Pipfile is a TOML document. Pipenv documents two value shapes:

      pkg = "==1.2.3"
      pkg = {version = "==1.2.3", extras = ["security"], markers = "..."}

    Before this function used tomllib, the inline-table form (the second
    shape) was silently dropped because the previous regex only matched
    a string literal immediately after ``=``. Now we parse the TOML
    structurally, accept both shapes, and fall back to the regex parser
    only if tomllib is unavailable or the document is malformed.

    Only ``==<concrete>`` pins are returned; range / wildcard / starred
    versions ("*", ">=1.0", "~=1.4.2") aren't audit-eligible (OSV
    expects concrete versions).
    """
    if _tomllib is not None:
        try:
            data = _tomllib.loads(content)
        except Exception:
            data = None
        if isinstance(data, dict):
            packages: list = []
            for section in ("packages", "dev-packages"):
                section_table = data.get(section, {})
                if not isinstance(section_table, dict):
                    continue
                for pkg, spec in section_table.items():
                    ver: str = ""
                    if isinstance(spec, str):
                        ver = spec
                    elif isinstance(spec, dict):
                        v = spec.get("version", "")
                        if isinstance(v, str):
                            ver = v
                    m = re.match(r"^==\s*(.+)$", ver.strip())
                    if m:
                        packages.append((pkg, m.group(1).strip()))
            return packages
    # Fallback: original regex-based parser. Doesn't see inline tables,
    # but that's strictly an improvement over a tomllib crash.
    packages = []
    in_section = False
    for line in content.splitlines():
        stripped = line.strip()
        if re.match(r"^\[(packages|dev-packages)\]", stripped):
            in_section = True
            continue
        if stripped.startswith("["):
            in_section = False
            continue
        if not in_section:
            continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\']?==\s*([^\s"\']+)', stripped)
        if m:
            packages.append((m.group(1), m.group(2)))
    return packages


def parse_gemfile(content: str) -> list:
    """Return [(gem_name, version), ...] for pinned entries."""
    packages = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Match: gem 'name', '1.2.3' or gem "name", "~> 1.2"
        m = re.match(r"""gem\s+['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]""", stripped)
        if m:
            ver_raw = m.group(2).strip()
            # Strip operators; keep only the version number portion
            clean = re.sub(r"^[~>=<\s]+", "", ver_raw)
            if re.match(r"^\d+\.\d+", clean):
                packages.append((m.group(1), clean))
    return packages


def _pom_properties(root, ns: str) -> dict:
    """Return {property_name: literal_value} for <properties> children."""
    props = {}
    for properties in root.iter(f"{ns}properties"):
        for child in properties:
            name = child.tag[len(ns):] if child.tag.startswith(ns) else child.tag
            value = (child.text or "").strip()
            if name and value:
                props[name] = value
    return props


def _resolve_pom_version(version: str, props: dict) -> str:
    """Resolve a single ${prop.name} reference, or return the input unchanged.
    Nested references are not chased — Maven allows them, but they're rare and
    chasing them complicates verification. The verification gate in the
    finaliser will downgrade any unresolved ref to a WARNING."""
    m = re.fullmatch(r"\$\{([^}]+)\}", version.strip())
    if not m:
        return version
    return props.get(m.group(1), "")


def parse_pom_xml(content: str) -> list:
    """Return [(group_id, artifact_id, version), ...].

    Resolves ``<version>${prop.name}</version>`` indirection against the
    project's ``<properties>`` block so deps using property references — the
    dominant pattern in real Maven projects — are visible to the audit.
    Unresolvable references (property not declared) are skipped to avoid
    false positives."""
    import xml.etree.ElementTree as ET
    packages = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return []
    ns_m = re.match(r"\{.*\}", root.tag)
    ns = ns_m.group(0) if ns_m else ""
    props = _pom_properties(root, ns)
    for dep in root.iter(f"{ns}dependency"):
        group    = (dep.findtext(f"{ns}groupId")    or "").strip()
        artifact = (dep.findtext(f"{ns}artifactId") or "").strip()
        version_raw = (dep.findtext(f"{ns}version") or "").strip()
        version = _resolve_pom_version(version_raw, props)
        if group and artifact and version and re.match(r"^\d+[\.\d]*", version):
            packages.append((group, artifact, version))
    return packages


_GRADLE_CONFIG_WORDS = (
    r"(?:implementation|api|compile|testImplementation|"
    r"androidTestImplementation|debugImplementation|releaseImplementation|"
    r"runtimeOnly|testRuntimeOnly|kapt|kaptTest|annotationProcessor|"
    r"compileOnly|testCompileOnly)"
)


def _gradle_var_defs(content: str) -> dict:
    """Map variable name → declared string value for ``val`` / ``def`` / ``var``
    declarations. Used to resolve ``$varName`` interpolation in dep coords."""
    return {
        m.group(1): m.group(2)
        for m in re.finditer(
            r'(?:val|def|var)\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
            content,
        )
    }


def parse_build_gradle(content: str) -> list:
    """Return [(group_id, artifact_id, version), ...] across all common forms.

    Covers four declaration shapes that real-world Gradle projects use:

      * Colon-coordinate string:
            implementation("group:artifact:version")
      * Named-args (Groovy):
            implementation group: 'X', name: 'Y', version: 'Z'
      * Version-block (Kotlin DSL or Groovy):
            implementation("g:a") { version { strictly("Z") } }
      * Variable interpolation:
            val v = "1.0"
            implementation("g:a:$v")
    """
    var_defs = _gradle_var_defs(content)

    def _resolve(v: str) -> str:
        if v.startswith("$"):
            name = v.lstrip("$").lstrip("{").rstrip("}")
            return var_defs.get(name, v)
        return v

    raw: list = []
    cfg = _GRADLE_CONFIG_WORDS

    # Form 1: colon-coord (group:artifact:version)
    for m in re.finditer(
        cfg + r"[\s(]*[\"']([^\"']+):([^\"']+):([^\"']+)[\"']",
        content,
    ):
        raw.append((m.group(1), m.group(2), m.group(3)))

    # Form 2: named-args (Groovy)
    for m in re.finditer(
        cfg + r"\s+group:\s*[\"']([^\"']+)[\"']\s*,\s*"
        r"name:\s*[\"']([^\"']+)[\"']\s*,\s*"
        r"version:\s*[\"']([^\"']+)[\"']",
        content,
    ):
        raw.append((m.group(1), m.group(2), m.group(3)))

    # Form 3: version-block (Kotlin DSL / Groovy)
    for m in re.finditer(
        cfg + r"[\s(]*[\"']([^\"']+):([^\"']+)[\"'][^{]*\{\s*"
        r"version\s*\{\s*(?:strictly|require|prefer)\s*\(\s*[\"']([^\"']+)[\"']\s*\)\s*\}",
        content,
        re.DOTALL,
    ):
        raw.append((m.group(1), m.group(2), m.group(3)))

    packages: list = []
    for group, artifact, version in raw:
        version = _resolve(version)
        if re.match(r"^\d+", version):
            packages.append((group, artifact, version))
    return packages


def parse_go_mod(content: str) -> list:
    """Return [(module_path, version), ...] of registry-resolvable pins.

    Walks both ``require`` and ``replace`` directives (single-line and
    block forms). ``replace`` is the override mechanism Go uses to swap
    a required module's version (or path) at build time:

        replace github.com/foo/bar => github.com/foo/bar v1.5.0
        replace github.com/foo/bar v1.0.0 => github.com/foo/bar v1.5.0
        replace github.com/foo/bar => ./local/fork
        replace (
            github.com/baz/qux => github.com/baz/qux v0.9.0
        )

    A vulnerable version forced by ``replace`` is the version actually
    fetched and built — auditing only the ``require`` line would miss
    it. We resolve replacements onto the require list before returning,
    so audit_go sees the post-replace pins. Local-path replacements
    (./relative, /absolute) drop the module from the audit list (no
    registry coordinate to query OSV against).

    ``exclude`` directives are parsed separately by
    ``_parse_go_mod_excludes`` and cross-checked by ``audit_go`` to
    detect require/exclude contradictions. ``retract`` directives are
    intentionally not parsed: they are publisher-side annotations on a
    module's own releases, and the Go toolchain already surfaces a
    warning when a consumer requires a retracted version.
    """
    requires = []  # [(module_path, version), ...]
    # [(lhs_path, lhs_ver_or_None, rhs_path, rhs_ver_or_None_for_path_replace)]
    replaces = []
    in_require_block = False
    in_replace_block = False

    def _parse_require_line(payload: str) -> None:
        parts = payload.split()
        if len(parts) >= 2 and re.match(r"^v\d+", parts[1]):
            requires.append((parts[0], parts[1]))

    def _parse_replace_line(payload: str) -> None:
        if "=>" not in payload:
            return
        lhs, rhs = payload.split("=>", 1)
        lhs_parts = lhs.split()
        rhs_parts = rhs.split()
        if not lhs_parts or not rhs_parts:
            return
        lhs_path = lhs_parts[0]
        lhs_ver = (
            lhs_parts[1]
            if len(lhs_parts) >= 2 and re.match(r"^v\d+", lhs_parts[1])
            else None
        )
        rhs_path = rhs_parts[0]
        # Local-path replacements (./, ../, /abs) cannot be audited
        # against a registry; record them so the require entry is dropped.
        if rhs_path.startswith(".") or rhs_path.startswith("/"):
            replaces.append((lhs_path, lhs_ver, rhs_path, None))
            return
        rhs_ver = (
            rhs_parts[1]
            if len(rhs_parts) >= 2 and re.match(r"^v\d+", rhs_parts[1])
            else None
        )
        if rhs_ver is None:
            return
        replaces.append((lhs_path, lhs_ver, rhs_path, rhs_ver))

    for line in content.splitlines():
        stripped = line.strip()
        if "//" in stripped:
            stripped = stripped[: stripped.index("//")].strip()
        if not stripped:
            continue
        if stripped == "require (":
            in_require_block = True
            continue
        if stripped == "replace (":
            in_replace_block = True
            continue
        if stripped == ")":
            in_require_block = False
            in_replace_block = False
            continue
        if stripped.startswith("require ") and not stripped.endswith("("):
            _parse_require_line(stripped[len("require "):].strip())
        elif stripped.startswith("replace ") and not stripped.endswith("("):
            _parse_replace_line(stripped[len("replace "):].strip())
        elif in_require_block:
            _parse_require_line(stripped)
        elif in_replace_block:
            _parse_replace_line(stripped)

    # Apply replaces. For each require, find a matching replace (by module
    # path, and by version if the replace specifies one). If matched and
    # the rhs is registry-resolvable, swap to the replacement coordinate.
    # If matched and rhs is a local path, drop the entry (not auditable).
    final = []
    for module, version in requires:
        applied = False
        for lhs_path, lhs_ver, rhs_path, rhs_ver in replaces:
            if lhs_path != module:
                continue
            if lhs_ver is not None and lhs_ver != version:
                continue
            if rhs_ver is None:
                applied = True  # path replacement → not auditable, drop
                break
            final.append((rhs_path, rhs_ver))
            applied = True
            break
        if not applied:
            final.append((module, version))
    return final


def _parse_go_mod_excludes(content: str) -> dict:
    """Return {module_path: {version, ...}} for every ``exclude`` directive.

    Supports both single-line and block forms::

        exclude github.com/foo/bar v1.5.0

        exclude (
            github.com/foo/bar v1.5.0
            github.com/baz/qux v0.9.0
        )

    Used by ``audit_go`` to cross-check the require list: a module@version
    that appears in both ``require`` and ``exclude`` is a contradiction —
    Go refuses to resolve it, and ``audit_go`` emits a WARNING.
    """
    excludes: dict = {}
    in_exclude_block = False
    for line in content.splitlines():
        stripped = line.strip()
        if "//" in stripped:
            stripped = stripped[: stripped.index("//")].strip()
        if not stripped:
            continue
        if stripped == "exclude (":
            in_exclude_block = True
            continue
        if stripped == ")":
            in_exclude_block = False
            continue
        if stripped.startswith("exclude ") and not stripped.endswith("("):
            payload = stripped[len("exclude "):].strip()
        elif in_exclude_block:
            payload = stripped
        else:
            continue
        parts = payload.split()
        if len(parts) >= 2 and re.match(r"^v\d+", parts[1]):
            mod, ver = parts[0], parts[1]
            excludes.setdefault(mod, set()).add(ver)
    return excludes


def parse_go_sum(content: str) -> list:
    """Return [(module_path, version), ...] deduped, stable versions only."""
    seen, packages = set(), []
    for line in content.splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        module_path = parts[0]
        version = parts[1].split("/")[0]  # strip /go.mod suffix
        if module_path in seen:
            continue
        if re.match(r"^v\d+", version) and not _is_prerelease(version, "go"):
            seen.add(module_path)
            packages.append((module_path, version))
    return packages


def _split_pep508(dep_str: str) -> tuple:
    """Split a PEP 508 dependency string into (name, version).

    Returns ('', '') on failure. PEP 508 allows an optional extras
    bracket between the name and the version specifier — e.g.
    ``requests[security,socks] >= 2.25.0; python_version >= "3.6"``.
    The bracket is consumed but discarded; only the bare package name
    is returned (extras don't change the package's CVE-query identity,
    and PyPI/OSV both index by bare name). Trailing PEP 508 environment
    markers (``; …``) are excluded from the version capture by the
    ``[^\\s;,]*`` class on the version group.
    """
    m = re.match(
        r'^([A-Za-z0-9_.\-]+)(?:\s*\[[^\]]*\])?\s*([><=!~^]+\s*[^\s;,]*)?',
        dep_str.strip(),
    )
    if not m:
        return "", ""
    name = m.group(1)
    ver = (m.group(2) or "").lstrip("><=!~^ ")
    return name, ver


def parse_pyproject_toml(content: str) -> list:
    """Parse deps from pyproject.toml supporting PEP 621, Poetry, and uv layouts."""
    if _tomllib is None:
        return []
    try:
        data = _tomllib.loads(content)
    except Exception:
        return []

    packages = []

    # PEP 621 standard (uv, hatch, flit, and others)
    for dep in data.get("project", {}).get("dependencies", []):
        name, ver = _split_pep508(dep)
        if name and ver:
            packages.append((name, ver))

    # PEP 621 optional dependencies
    for group_deps in data.get("project", {}).get("optional-dependencies", {}).values():
        for dep in group_deps:
            name, ver = _split_pep508(dep)
            if name and ver:
                packages.append((name, ver))

    # Poetry
    for section in ["dependencies", "dev-dependencies"]:
        poetry_deps = data.get("tool", {}).get("poetry", {}).get(section, {})
        if isinstance(poetry_deps, dict):
            for pkg, spec in poetry_deps.items():
                if pkg == "python":
                    continue
                ver = spec if isinstance(spec, str) else spec.get("version", "")
                if ver:
                    packages.append((pkg, ver.lstrip("^~>= ")))

    # Poetry dependency groups
    for group_data in data.get("tool", {}).get("poetry", {}).get("group", {}).values():
        if isinstance(group_data, dict):
            for pkg, spec in group_data.get("dependencies", {}).items():
                ver = spec if isinstance(spec, str) else spec.get("version", "")
                if ver:
                    packages.append((pkg, ver.lstrip("^~>= ")))

    # uv dev dependencies
    for dep in data.get("tool", {}).get("uv", {}).get("dev-dependencies", []):
        name, ver = _split_pep508(dep)
        if name and ver:
            packages.append((name, ver))

    # uv [tool.uv.sources] registry-form overrides: a source entry that has a
    # ``version`` field and no ``url``/``git``/``path`` key is a concrete
    # crates-style pin against a registry and should be audited. url/git/path
    # forms have no PyPI coordinate; they are silently skipped here and
    # surfaced as NOTE signals by _uv_sources_notes / audit_pyproject_toml.
    for pkg, src in data.get("tool", {}).get("uv", {}).get("sources", {}).items():
        if isinstance(src, dict) and "version" in src and not any(
            k in src for k in ("url", "git", "path")
        ):
            packages.append((pkg, src["version"]))

    return packages


def _uv_sources_notes(content: str) -> list:
    """Return NOTE signals for [tool.uv.sources] url/git/path entries.

    These package sources have no PyPI coordinate, so the shim cannot audit
    them against public CVE databases. Surfacing a NOTE makes the coverage
    gap explicit rather than silently skipping the packages.
    """
    if _tomllib is None:
        return []
    try:
        data = _tomllib.loads(content)
    except Exception:
        return []
    notes = []
    for pkg, src in data.get("tool", {}).get("uv", {}).get("sources", {}).items():
        if not isinstance(src, dict):
            continue
        src_type = next((k for k in ("url", "git", "path") if k in src), None)
        if src_type:
            notes.append(
                f"NOTE: {pkg} sourced from non-PyPI ([tool.uv.sources] {src_type}=...) "
                f"— not auditable against public CVE databases; "
                f"verify supply-chain controls on the upstream source"
            )
    return notes


def parse_setup_py(content: str) -> list:
    """Extract dep declarations from setup.py via regex (no exec).

    Walks ``install_requires`` (production runtime), ``setup_requires``
    (build-time tools — PEP 517 deprecates this in favour of
    pyproject.toml's ``[build-system].requires``, but legacy setup.py
    files still use it), ``tests_require`` (test-time deps), and the
    ``extras_require={"name": [...]}`` dict (optional dep groups). Each
    is a list of PEP 508 strings, parsed via _split_pep508.

    Dev/test/extras deps execute in developer environments with full
    repo access; supply-chain risk is structurally identical to runtime
    deps. Auditing only ``install_requires`` was a real gap for any
    setup.py declaring pytest/mypy/black/etc. there.
    """
    packages = []
    for kw in ("install_requires", "setup_requires", "tests_require"):
        # The list body is captured with quoted strings consumed atomically
        # ("..." / '...') so a ``]`` inside an extras spec ("pkg[extra]==v")
        # does not terminate the capture — a bare ``[^\]]+`` body stopped at
        # the extras bracket and silently dropped every dep from that point on.
        m = re.search(
            rf"{kw}\s*=\s*\[((?:[^\[\]\"']|\"[^\"]*\"|'[^']*')*)\]",
            content,
            re.DOTALL,
        )
        if not m:
            continue
        for dep in re.findall(r'["\']([^"\']+)["\']', m.group(1)):
            name, ver = _split_pep508(dep)
            if name and ver:
                packages.append((name, ver))
    # ``extras_require={"dev": [...], "test": [...]}``: harvest every
    # quoted string inside the dict body. Extra-name keys ("dev",
    # "test", ...) parse as a name with no version and are filtered by
    # the ``if name and ver`` gate, so the overshoot is graceful.
    extras_match = re.search(
        r"extras_require\s*=\s*\{(.*?)\}", content, re.DOTALL,
    )
    if extras_match:
        for dep in re.findall(r'["\']([^"\']+)["\']', extras_match.group(1)):
            name, ver = _split_pep508(dep)
            if name and ver:
                packages.append((name, ver))
    return packages


def parse_setup_cfg(content: str) -> list:
    """Extract dep declarations from setup.cfg.

    Reads ``[options]`` for ``install_requires``, ``setup_requires``,
    and ``tests_require``, plus the ``[options.extras_require]`` section
    where each key names an extra and the value is a multi-line list of
    PEP 508 strings. Dev/test/extras deps audit identically to runtime
    deps (see parse_setup_py for the rationale).
    """
    import configparser
    cfg = configparser.ConfigParser()
    try:
        cfg.read_string(content)
    except Exception:
        return []
    packages = []

    def _emit_lines(raw: str) -> None:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            name, ver = _split_pep508(line)
            if name and ver:
                packages.append((name, ver))

    for kw in ("install_requires", "setup_requires", "tests_require"):
        _emit_lines(cfg.get("options", kw, fallback=""))
    if cfg.has_section("options.extras_require"):
        for extra_name in cfg.options("options.extras_require"):
            _emit_lines(cfg.get("options.extras_require", extra_name, fallback=""))
    return packages


def parse_gemspec(content: str) -> list:
    """Extract dependency declarations from a .gemspec.

    Covers:
      - All three Ruby dependency-decl forms: ``add_dependency``,
        ``add_runtime_dependency``, ``add_development_dependency``.
        (The bare ``add_dependency`` and ``_runtime`` variants ship as
        runtime; ``_development`` is the test/dev path. All three
        execute in developer environments and audit identically.)
      - Multi-constraint version specs: ``add_dependency 'rails',
        '>= 5.0', '< 6.0'``. Each constraint produces a separate
        ``(name, version, True)`` 3-tuple where the third element is
        ``is_multi_constraint`` — set to True when a **single call**
        carries multiple version arguments. audit_gemspec builds
        ``multi_constraint`` from this flag rather than re-deriving it
        from the flat list, which would falsely flag two separate
        single-constraint lines for the same gem.

    Operator prefixes (``~>``, ``>=``, ``<``, ``=``, ``>``, ``<=``,
    ``!=``) are stripped via a regex prefix-strip — OSV is queried
    against the bare version. (A plain ``lstrip`` here would treat the
    operators as a character set and silently mangle ``>= X`` into
    ``= X`` — see #44.)

    Returns a list of ``(name, version, is_multi_constraint)`` 3-tuples.
    """
    packages = []
    for m in re.finditer(
        r'add(?:_runtime|_development)?_dependency\s+["\']([^"\']+)["\']'
        r'((?:\s*,\s*["\'][^"\']+["\'])*)',
        content,
    ):
        name = m.group(1)
        cleaned_vers = []
        for raw in re.findall(r'["\']([^"\']+)["\']', m.group(2)):
            cleaned = re.sub(r'^[~><=! ]+', '', raw).strip()
            if cleaned:
                cleaned_vers.append(cleaned)
        # is_multi_constraint is True only when this single call has
        # multiple version arguments — NOT when the same gem name
        # appears on separate lines (each of which is single-constraint).
        is_multi = len(cleaned_vers) > 1
        for ver in cleaned_vers:
            packages.append((name, ver, is_multi))
    return packages


def parse_libs_versions_toml(content: str) -> list:
    """Parse Gradle Version Catalog — extracts [versions] entries referenced by [libraries]."""
    if _tomllib is None:
        return []
    try:
        data = _tomllib.loads(content)
    except Exception:
        return []

    versions = data.get("versions", {})
    packages = []

    for lib_key, lib_val in data.get("libraries", {}).items():
        if not isinstance(lib_val, dict):
            continue
        module = _libs_module_coord(lib_val)
        if not module or ":" not in module:
            continue
        ver = _resolve_libs_version(lib_val.get("version"), versions)
        if module and ver:
            packages.append((module, ver))

    return packages


def _libs_module_coord(lib_val: dict) -> str:
    """Resolve a Gradle catalog library entry to its ``group:artifact`` coord.

    Supports the two documented forms: ``module = "group:artifact"`` and the
    split ``{ group = "...", name = "..." }`` form (used in Gradle's own docs).
    """
    module = lib_val.get("module", "")
    if isinstance(module, str) and ":" in module:
        return module
    group = lib_val.get("group")
    name = lib_val.get("name")
    if isinstance(group, str) and isinstance(name, str) and group and name:
        return f"{group}:{name}"
    return ""


def _resolve_libs_version(ver_ref, versions: dict) -> str:
    """Resolve a Gradle catalog library version to a concrete string.

    Handles ``version = "1.2.3"`` (inline), ``version.ref = "alias"`` (catalog
    reference), and rich-version notation
    ``version = { strictly/require/prefer = "..." }``. For rich versions the
    binding constraint is preferred: ``strictly`` > ``require`` > ``prefer``.
    """
    if isinstance(ver_ref, str):
        return ver_ref
    if isinstance(ver_ref, dict):
        ref = ver_ref.get("ref")
        if isinstance(ref, str) and ref:
            return versions.get(ref, "")
        for key in ("strictly", "require", "prefer"):
            val = ver_ref.get(key)
            if isinstance(val, str) and val:
                return val
    return ""


# ─────────────────────────── manifest rewriters ───────────────────────────

def _detect_json_indent(content: str):
    """Return the indent argument to pass to json.dumps that best matches the
    input's existing indentation. Returns ``"\\t"`` for tab-indented files, an
    int for space-indented files (2/4/etc.), or 2 if the file is compact
    (single-line) — indent style is undefined for compact JSON, and 2 keeps
    the rewrite readable."""
    for line in content.splitlines():
        if line.startswith("\t"):
            return "\t"
        m = re.match(r"^( +)\S", line)
        if m:
            return len(m.group(1))
    return 2


def rewrite_package_json(content: str, updates: dict) -> str:
    """updates: {pkg: (old_ver, new_ver)}. Preserves range operators and the
    file's existing indent style (tabs, 2-space, 4-space).

    Walks the four standard dep dicts plus ``overrides``, ``resolutions``,
    and ``pnpm.overrides`` (flat-string entries only) to mirror
    parse_package_json. Nested overrides (``{".": "x.y", "child": "z.w"}``)
    are intentionally left untouched — the parser doesn't pin those, so
    audit_npm never asks for a rewrite of one.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return content
    for dep_key in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
        for pkg, (old_ver, new_ver) in updates.items():
            if pkg in data.get(dep_key, {}):
                orig = data[dep_key][pkg]
                if not isinstance(orig, str):
                    continue
                prefix_m = re.match(r"^([~^>=<\s]+)", orig)
                prefix = prefix_m.group(1) if prefix_m else ""
                # Anchor on the audited OLD version. The updates dict is keyed
                # by package name, but the same package can appear in several
                # dep dicts at DIFFERENT versions — and only the occurrence
                # the auditor saw as same-major-updatable is safe to rewrite.
                # Without this check, a second occurrence needing a major bump
                # (MAJOR-UPDATE-CONFIRM, "If NO → leave version as-is") was
                # silently major-bumped on disk. Range operators are stripped
                # from both sides (the auditor passes the bare version; some
                # callers pass the original ranged spec).
                if orig[len(prefix):] != re.sub(r"^[~^>=<\s]+", "", old_ver):
                    continue
                data[dep_key][pkg] = prefix + new_ver
    override_targets = [
        data.get("overrides"),
        data.get("resolutions"),
        (data.get("pnpm") or {}).get("overrides"),
    ]
    for ovr in override_targets:
        if not isinstance(ovr, dict):
            continue
        for pkg, (old_ver, new_ver) in updates.items():
            if pkg not in ovr:
                continue
            orig = ovr[pkg]
            if not isinstance(orig, str) or orig.startswith("$"):
                continue  # nested / reference form — leave untouched
            prefix_m = re.match(r"^([~^>=<\s]+)", orig)
            prefix = prefix_m.group(1) if prefix_m else ""
            if orig[len(prefix):] != re.sub(r"^[~^>=<\s]+", "", old_ver):
                continue  # pinned at a different version — not the audited entry
            ovr[pkg] = prefix + new_ver
    indent = _detect_json_indent(content)
    return json.dumps(data, indent=indent) + "\n"


def rewrite_composer_json(content: str, updates: dict) -> str:
    """updates: {pkg: (old_ver, new_ver)}. Preserves range operators and the
    file's existing indent style. Mirrors :func:`rewrite_package_json` for
    composer's ``require`` / ``require-dev`` dicts (vendor/package → constraint).

    Anchors on the audited OLD version so a package pinned at a different
    version in the other dep dict isn't silently rewritten.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return content
    for dep_key in ("require", "require-dev"):
        section = data.get(dep_key)
        if not isinstance(section, dict):
            continue
        for pkg, (old_ver, new_ver) in updates.items():
            if pkg not in section:
                continue
            orig = section[pkg]
            if not isinstance(orig, str):
                continue
            prefix_m = re.match(r"^([~^>=<\s]+)", orig)
            prefix = prefix_m.group(1) if prefix_m else ""
            if orig[len(prefix):] != re.sub(r"^[~^>=<\s]+", "", old_ver):
                continue
            section[pkg] = prefix + new_ver
    indent = _detect_json_indent(content)
    return json.dumps(data, indent=indent) + "\n"


def _normalize_pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _hash_pinned_pkgs(content: str) -> set:
    """Return the set of PEP 503-normalized package names that declare --hash="""
    return {
        _normalize_pep503(p)
        for p, _v, hashes in parse_requirements_hashes(content)
        if hashes
    }


def rewrite_requirements_txt(content: str, updates: dict) -> str:
    """updates: {pkg: (old_ver, new_ver)}. Case-insensitive package name match.

    Hash-pinned packages (those with --hash=sha256: continuation lines) are
    intentionally skipped — bumping the version while leaving the hashes
    unchanged would produce a file that fails ``pip install --require-hashes``.
    Callers (audit_pypi) emit a HASH-PINNED-UPDATE warning instead so the user
    can refresh hashes via pip-compile / uv lock.
    """
    hashed = _hash_pinned_pkgs(content)
    lines = []
    for line in content.splitlines():
        m = re.match(
            r"^([A-Za-z0-9_\-\.]+)(?:\s*\[[^\]]*\])?\s*==\s*([^\s#;,\[]+)",
            line.strip(),
        )
        if m:
            pkg_lower = m.group(1).lower()
            for upd_pkg, (old_ver, new_ver) in updates.items():
                if upd_pkg.lower() != pkg_lower:
                    continue
                if m.group(2) != old_ver:
                    # Same package pinned at a DIFFERENT version (e.g. a
                    # second line behind an environment marker). That pin was
                    # not the audited entry — rewriting it could be a silent
                    # major bump.
                    break
                if _normalize_pep503(upd_pkg) in hashed:
                    break  # leave hash-pinned blocks untouched
                # count=1: replace only the version pin (the first == on the
                # line). An unbounded sub also clobbered ``==X`` occurrences
                # in trailing comments and environment markers
                # (`; python_version=="3.8"`), corrupting them.
                line = re.sub(r"==\s*[^\s#;,\[]+", f"=={new_ver}", line, count=1)
                break
        lines.append(line)
    result = "\n".join(lines)
    if content.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def rewrite_pipfile(content: str, updates: dict) -> str:
    """updates: {pkg: (old_ver, new_ver)}. Handles both Pipfile pin forms.

    Both patterns anchor at line start (``(?m)^``): without the anchor,
    ``requests = "==X"`` matched INSIDE ``grequests = "==X"`` and the
    suffix-named sibling was silently rewritten — to a version that may
    not even exist for that package, breaking the next ``pipenv install``
    with no signal naming the clobbered package.

    Was a closure inside audit_pypi; promoted to module level so the test
    suite exercises the real implementation instead of a copy.
    """
    for p, (old, new) in updates.items():
        # String form: ``pkg = "==1.2.3"``
        content = re.sub(
            r"(?m)(^[ \t]*" + re.escape(p) + r"""\s*=\s*['"]?)==""" + re.escape(old),
            r"\g<1>==" + new, content,
        )
        # Inline-table form: ``pkg = {version = "==1.2.3", ...}``.
        # Anchored on line start + package name + the literal
        # ``version = "==<old>"`` inside the same entry so neither a
        # suffix-named sibling nor a second package with the same version
        # gets clobbered.
        content = re.sub(
            r"(?m)(^[ \t]*" + re.escape(p) + r"\s*=\s*\{[^}]*?version\s*=\s*['\"])"
            + r"==" + re.escape(old) + r"(['\"])",
            r"\g<1>==" + new + r"\g<2>",
            content,
        )
    return content


def rewrite_gemfile(content: str, updates: dict) -> str:
    """updates: {gem: (old_ver, new_ver)}.

    Handles both single-line ``gem 'foo', '~> 1.0'`` and the multi-line
    declaration form Bundler accepts:

        gem 'foo',
            '~> 1.0'
    """
    for pkg, (_old, new_ver) in updates.items():
        pat = re.compile(
            r"""(gem\s+['"]""" + re.escape(pkg) + r"""['"]\s*,\s*\n?\s*['"])"""
            r"""([^'"]+)"""
            r"""(['"])""",
        )
        content = pat.sub(
            lambda mm, new_ver=new_ver: mm.group(1)
            + re.sub(r"\d[\d\.]*", new_ver, mm.group(2), count=1)
            + mm.group(3),
            content,
            count=1,
        )
    return content


def rewrite_pom_xml(content: str, updates: dict) -> str:
    """
    updates: {(group_id, artifact_id): (old_ver, new_ver)}.

    For each update, locates the dependency block by groupId + artifactId and
    inspects its ``<version>``: if the literal is a ``${prop.name}`` reference,
    the rewrite targets the matching ``<properties>`` entry instead (anchored
    on the property name) so the indirection stays intact and only the right
    property is updated. Otherwise the dep's ``<version>`` element itself is
    rewritten.
    """
    for (group, artifact), (old_ver, new_ver) in updates.items():
        # Find this dep's raw <version> literal so we can tell whether it's a
        # property reference. A targeted regex (rather than re-parsing XML) is
        # enough here because pom.xml dependency blocks have a stable shape and
        # we need to preserve exact whitespace/comments anyway.
        find_dep = re.compile(
            r"<dependency>(?:(?!</dependency>).)*?"
            r"<groupId>\s*" + re.escape(group) + r"\s*</groupId>(?:(?!</dependency>).)*?"
            r"<artifactId>\s*" + re.escape(artifact) + r"\s*</artifactId>(?:(?!</dependency>).)*?"
            r"<version>\s*([^<\s]+)\s*</version>(?:(?!</dependency>).)*?</dependency>",
            re.DOTALL,
        )
        m_dep = find_dep.search(content)
        if not m_dep:
            continue
        version_literal = m_dep.group(1)
        prop_match = re.fullmatch(r"\$\{([^}]+)\}", version_literal)
        if prop_match:
            # Update the property entry. Anchor on the property name so two
            # properties sharing the same value cannot collide.
            prop_name = prop_match.group(1)
            prop_pat = re.compile(
                r"(<" + re.escape(prop_name) + r">\s*)"
                + re.escape(old_ver)
                + r"(\s*</" + re.escape(prop_name) + r">)"
            )
            content = prop_pat.sub(
                lambda mm, new_ver=new_ver: mm.group(1) + new_ver + mm.group(2),
                content,
                count=1,
            )
        else:
            # Direct version: replace inside the matched dependency block.
            pat_direct = re.compile(
                r"(<dependency>(?:(?!</dependency>).)*?"
                r"<groupId>\s*" + re.escape(group) + r"\s*</groupId>(?:(?!</dependency>).)*?"
                r"<artifactId>\s*" + re.escape(artifact) + r"\s*</artifactId>(?:(?!</dependency>).)*?"
                r"<version>\s*)" + re.escape(old_ver)
                + r"(\s*</version>(?:(?!</dependency>).)*?</dependency>)",
                re.DOTALL,
            )
            content = pat_direct.sub(r"\g<1>" + new_ver + r"\g<2>", content)
    return content


def rewrite_build_gradle(content: str, updates: dict) -> str:
    """updates: {(group_id, artifact_id): (old_ver, new_ver)}.

    Tries each declaration form in turn until one matches:
      1. Colon-coord literal
      2. Named-args (Groovy)
      3. Version-block (Kotlin/Groovy ``version { strictly(...) }``)
      4. Variable interpolation — resolves ``"g:a:$varName"`` and rewrites the
         ``val`` / ``def`` / ``var`` declaration of ``varName``.
    """
    cfg = _GRADLE_CONFIG_WORDS
    for (group, artifact), (old_ver, new_ver) in updates.items():
        # Form 1: literal colon-coord substitution.
        old_coord = f"{group}:{artifact}:{old_ver}"
        if old_coord in content:
            content = content.replace(old_coord, f"{group}:{artifact}:{new_ver}")
            continue

        # Form 2: named-args.
        pat_named = re.compile(
            r"(" + cfg + r"\s+group:\s*[\"']" + re.escape(group) + r"[\"']\s*,\s*"
            r"name:\s*[\"']" + re.escape(artifact) + r"[\"']\s*,\s*"
            r"version:\s*[\"'])" + re.escape(old_ver) + r"([\"'])"
        )
        new_content, n = pat_named.subn(
            lambda m, new_ver=new_ver: m.group(1) + new_ver + m.group(2), content, count=1,
        )
        if n:
            content = new_content
            continue

        # Form 3: version-block.
        pat_block = re.compile(
            r"(" + cfg + r"[\s(]*[\"']" + re.escape(group) + r":" + re.escape(artifact)
            + r"[\"'][^{]*\{\s*version\s*\{\s*(?:strictly|require|prefer)\s*\(\s*[\"'])"
            + re.escape(old_ver) + r"([\"']\s*\))",
            re.DOTALL,
        )
        new_content, n = pat_block.subn(
            lambda m, new_ver=new_ver: m.group(1) + new_ver + m.group(2), content, count=1,
        )
        if n:
            content = new_content
            continue

        # Form 4: variable interpolation. Locate the var referenced in the
        # coord string, then update that var's declaration.
        ref = re.search(
            cfg + r"[\s(]*[\"']" + re.escape(group) + r":" + re.escape(artifact)
            + r":\$\{?(\w+)\}?[\"']",
            content,
        )
        if ref:
            var_name = ref.group(1)
            pat_var = re.compile(
                r"((?:val|def|var)\s+" + re.escape(var_name) + r"\s*=\s*[\"'])"
                + re.escape(old_ver) + r"([\"'])"
            )
            new_content, n = pat_var.subn(
                lambda m, new_ver=new_ver: m.group(1) + new_ver + m.group(2), content, count=1,
            )
            if n:
                content = new_content
                continue
    return content


def rewrite_go_mod(content: str, updates: dict) -> str:
    """updates: {module_path: (old_ver, new_ver)}. Replaces version in require lines."""
    lines = []
    for line in content.splitlines():
        for module, (old_ver, new_ver) in updates.items():
            # Match lines containing the module path followed by the exact old version
            if re.search(r"\b" + re.escape(module) + r"\s+" + re.escape(old_ver) + r"\b", line):
                line = re.sub(
                    r"(\b" + re.escape(module) + r"\s+)" + re.escape(old_ver) + r"\b",
                    r"\g<1>" + new_ver,
                    line,
                    count=1,
                )
                break
        lines.append(line)
    result = "\n".join(lines)
    if content.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


# Operator/whitespace chars that may legally precede a version literal in
# Python/TOML/Ruby dep specs. Captured as a group so the rewriter preserves
# whatever the user had (e.g., poetry's ``^1.0.0``, npm-style ``~1.0.0``,
# pip's ``>=1.0.0``).
_VER_OP_CLASS = r"[~^>=<! ]*"
# PEP 508 / pip operator (anchored as a literal-string prefix to the version).
_PEP508_OP = r"(?:==|>=|<=|~=|!=|===|>|<|\^|~)"


def rewrite_pyproject_toml(content: str, updates: dict) -> str:
    """updates: {pkg: (old_ver, new_ver)}. Anchors on the package name across
    Poetry string form, Poetry/uv inline-table form, and PEP 621 array form."""
    for pkg, (old, new) in updates.items():
        name = re.escape(pkg)
        old_re = re.escape(old)
        # Poetry/uv string form: ``flask = "^1.0.0"`` or ``flask = '1.0.0'``.
        pat_string = re.compile(
            r'(^[ \t]*' + name + r'\s*=\s*["\'])(' + _VER_OP_CLASS + r')'
            + old_re + r'(["\'])',
            re.MULTILINE,
        )
        content, n = pat_string.subn(
            lambda m, new=new: m.group(1) + m.group(2) + new + m.group(3),
            content,
        )
        if n:
            continue
        # Inline-table form: ``flask = { version = "1.0.0", extras = [...] }``.
        # Bound the search to a single ``{...}`` block on one line.
        pat_inline = re.compile(
            r'(^[ \t]*' + name + r'\s*=\s*\{[^}\n]*version\s*=\s*["\'])('
            + _VER_OP_CLASS + r')' + old_re + r'(["\'][^}\n]*\})',
            re.MULTILINE,
        )
        content, n = pat_inline.subn(
            lambda m, new=new: m.group(1) + m.group(2) + new + m.group(3),
            content,
        )
        if n:
            continue
        # PEP 621 array form: ``"flask==1.0.0"`` inside a ``dependencies = [...]``.
        pat_pep621 = re.compile(
            r'(["\'])' + name + r'\s*(' + _PEP508_OP + r')\s*' + old_re + r'(["\'])'
        )
        content, _ = pat_pep621.subn(
            lambda m, pkg=pkg, new=new: m.group(1) + pkg + m.group(2) + new + m.group(3),
            content,
            count=1,
        )
    return content


def rewrite_setup_py(content: str, updates: dict) -> str:
    """updates: {pkg: (old_ver, new_ver)}. Anchors on string-literal entries
    inside ``install_requires=[...]`` (and friends). Preserves an optional
    extras spec (``"pkg[extra]==old"``) — parse_setup_py delivers extras
    deps, so the rewriter must handle the same form or the update would be
    downgraded to a manual-action WARNING."""
    for pkg, (old, new) in updates.items():
        pat = re.compile(
            r'(["\'])' + re.escape(pkg) + r'(\s*\[[^\]]*\])?\s*(' + _PEP508_OP + r')\s*'
            + re.escape(old) + r'(["\'])'
        )
        content, _ = pat.subn(
            lambda m, pkg=pkg, new=new: m.group(1) + pkg + (m.group(2) or "") + m.group(3) + new + m.group(4),
            content,
            count=1,
        )
    return content


def rewrite_setup_cfg(content: str, updates: dict) -> str:
    """updates: {pkg: (old_ver, new_ver)}. Each dependency lives on its own
    indented line under ``install_requires =`` (INI multi-value form)."""
    for pkg, (old, new) in updates.items():
        pat = re.compile(
            r'(^[ \t]*' + re.escape(pkg) + r'\s*)(' + _PEP508_OP + r'\s*)'
            + re.escape(old) + r'([ \t]*(?:[#;].*)?$)',
            re.MULTILINE,
        )
        content, _ = pat.subn(
            lambda m, new=new: m.group(1) + m.group(2) + new + m.group(3),
            content,
            count=1,
        )
    return content


def rewrite_gemspec(content: str, updates: dict) -> str:
    """updates: {pkg: (old_ver, new_ver)}. Anchors on the gem name in
    ``add_dependency`` / ``add_runtime_dependency`` declarations."""
    for pkg, (old, new) in updates.items():
        pat = re.compile(
            r'(add(?:_runtime|_development)?_dependency\s+["\']' + re.escape(pkg)
            + r'["\']\s*,\s*["\'])([~><=! ]*)' + re.escape(old) + r'(["\'])'
        )
        content, _ = pat.subn(
            lambda m, new=new: m.group(1) + m.group(2) + new + m.group(3),
            content,
            count=1,
        )
    return content


def rewrite_libs_versions_toml(content: str, updates: dict) -> str:
    """updates: {"group:artifact": (old_ver, new_ver)} for Gradle Version
    Catalogs. Re-parses the TOML to follow ``version.ref`` indirection so the
    rewrite anchors on the correct ``[versions]`` key (or, for inline form,
    the correct ``[libraries]`` entry) instead of the first matching version
    literal anywhere in the file."""
    if _tomllib is None:
        return content
    try:
        data = _tomllib.loads(content)
    except Exception:
        return content
    libraries = data.get("libraries", {}) or {}
    for module, (old, new) in updates.items():
        for lib_key, lib_val in libraries.items():
            if not isinstance(lib_val, dict):
                continue
            if _libs_module_coord(lib_val) != module:
                continue
            ver_field = lib_val.get("version")
            if isinstance(ver_field, str):
                # Inline form: ``foo = { module = "...", version = "X" }`` (also
                # covers the split ``{ group, name, version = "X" }`` form).
                pat = re.compile(
                    r'(^[ \t]*' + re.escape(lib_key)
                    + r'\s*=\s*\{[^}\n]*version\s*=\s*["\'])'
                    + re.escape(old) + r'(["\'][^}\n]*\})',
                    re.MULTILINE,
                )
                content = pat.sub(
                    lambda m, new=new: m.group(1) + new + m.group(2),
                    content,
                    count=1,
                )
            elif isinstance(ver_field, dict):
                ref_key = ver_field.get("ref")
                if isinstance(ref_key, str) and ref_key:
                    # ``version.ref = "X"`` indirects into ``[versions]``;
                    # rewrite the entry under [versions] anchored on its key.
                    pat = re.compile(
                        r'(^[ \t]*' + re.escape(ref_key)
                        + r'\s*=\s*["\'])' + re.escape(old) + r'(["\'])',
                        re.MULTILINE,
                    )
                else:
                    # Rich version: ``version = { strictly/require/prefer = "X" }``
                    # (single-line inline table). Rewrite the constraint literal
                    # in place, anchored on this library's key.
                    pat = re.compile(
                        r'(^[ \t]*' + re.escape(lib_key)
                        + r'\s*=\s*\{.*?(?:strictly|require|prefer)\s*=\s*["\'])'
                        + re.escape(old) + r'(["\'])',
                        re.MULTILINE,
                    )
                content = pat.sub(
                    lambda m, new=new: m.group(1) + new + m.group(2),
                    content,
                    count=1,
                )
            break
    return content


# ─────────────────────────── manifest entry removers ───────────────────────────

def remove_from_package_json(content: str, pkg_names: list) -> str:
    """Remove named packages from all dependency dicts. Returns updated JSON.

    Mirrors parse_package_json by also clearing entries from
    ``overrides``, ``resolutions``, and ``pnpm.overrides``. Nested-form
    override values aren't surfaced by the parser, so this only removes
    flat ``name: version`` entries (a nested-form key happens to ``pop``
    cleanly too if a same-name entry exists alongside it; that matches
    Cargo's ``cargo update -p`` semantics).
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return content
    for dep_key in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies", "overrides", "resolutions"):
        for pkg in pkg_names:
            data.get(dep_key, {}).pop(pkg, None)
    pnpm_ovr = (data.get("pnpm") or {}).get("overrides")
    if isinstance(pnpm_ovr, dict):
        for pkg in pkg_names:
            pnpm_ovr.pop(pkg, None)
    return json.dumps(data, indent=2) + "\n"


def remove_from_composer_json(content: str, pkg_names: list) -> str:
    """Remove named packages from composer's ``require`` / ``require-dev``
    dicts. Returns updated JSON. Mirrors :func:`remove_from_package_json`."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return content
    for dep_key in ("require", "require-dev"):
        section = data.get(dep_key)
        if not isinstance(section, dict):
            continue
        for pkg in pkg_names:
            section.pop(pkg, None)
    return json.dumps(data, indent=4) + "\n"


def remove_from_requirements_txt(content: str, pkg_names: list) -> str:
    """Remove pinned lines whose package name is in pkg_names (case-insensitive).

    Hash-pinned blocks span multiple lines via trailing-backslash continuation;
    when removing the leading ``pkg==X`` line, drop every following continuation
    line (``--hash=...``) too. Without this, the orphaned ``--hash=`` lines would
    attach themselves to whatever requirement followed and break the file.
    """
    lower_names = {_normalize_pep503(p) for p in pkg_names}
    src = content.splitlines(keepends=False)
    out = []
    i = 0
    while i < len(src):
        line = src[i]
        m = re.match(r"^([A-Za-z0-9_\-\.]+)", line.strip())
        if m and _normalize_pep503(m.group(1)) in lower_names:
            # Skip this line and any backslash-continuation that follows.
            while i < len(src) and src[i].rstrip().endswith("\\"):
                i += 1
            i += 1  # skip the final (non-continuation) line of the block
            continue
        out.append(line)
        i += 1
    result = "\n".join(out)
    if content.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def remove_from_gemfile(content: str, pkg_names: list) -> str:
    """Remove gem lines whose name is in pkg_names."""
    lower_names = {p.lower() for p in pkg_names}
    lines = []
    for line in content.splitlines():
        m = re.match(r"""gem\s+['"]([^'"]+)['"]""", line.strip())
        if m and m.group(1).lower() in lower_names:
            continue
        lines.append(line)
    result = "\n".join(lines)
    if content.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def remove_from_pom_xml(content: str, pkg_names: list) -> str:
    """Remove <dependency> blocks matching 'groupId:artifactId' entries in pkg_names."""
    for pkg in pkg_names:
        parts = pkg.split(":", 1)
        if len(parts) != 2:
            continue
        group, artifact = parts
        pattern = re.compile(
            r"\s*<dependency>(?:(?!</dependency>).)*?"
            r"<groupId>\s*" + re.escape(group) + r"\s*</groupId>"
            r"(?:(?!</dependency>).)*?"
            r"<artifactId>\s*" + re.escape(artifact) + r"\s*</artifactId>"
            r"(?:(?!</dependency>).)*?</dependency>",
            re.DOTALL,
        )
        content = pattern.sub("", content)
    return content


def remove_from_build_gradle(content: str, pkg_names: list) -> str:
    """Remove dependency directive lines matching 'groupId:artifactId' entries."""
    lines = []
    for line in content.splitlines():
        keep = True
        stripped = line.strip()
        if re.match(r"(implementation|api|compile|testImplementation|runtimeOnly)", stripped):
            for pkg in pkg_names:
                parts = pkg.split(":", 1)
                if len(parts) == 2 and f"{parts[0]}:{parts[1]}:" in line:
                    keep = False
                    break
        if keep:
            lines.append(line)
    result = "\n".join(lines)
    if content.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def remove_from_go_mod(content: str, pkg_names: list) -> str:
    """Remove require lines matching module paths in pkg_names."""
    lines = []
    for line in content.splitlines():
        stripped = line.strip()
        keep = True
        for module in pkg_names:
            if re.match(
                r"^(?:require\s+)?" + re.escape(module) + r"\s+v\d+",
                stripped,
            ):
                keep = False
                break
        if keep:
            lines.append(line)
    result = "\n".join(lines)
    if content.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def remove_from_pyproject_toml(content: str, pkg_names: list) -> str:
    """Remove dependency lines matching pkg_names from pyproject.toml."""
    lines = []
    for line in content.splitlines():
        keep = True
        for pkg in pkg_names:
            if re.search(r'["\']' + re.escape(pkg) + r'[><=!~^]', line, re.IGNORECASE):
                keep = False
                break
            if re.search(r'^\s*' + re.escape(pkg) + r'\s*=', line, re.IGNORECASE):
                keep = False
                break
        if keep:
            lines.append(line)
    return "\n".join(lines) + ("\n" if content.endswith("\n") else "")


def remove_from_setup_py(content: str, pkg_names: list) -> str:
    """Remove items from install_requires list matching pkg_names.

    The pattern anchors the package name at the opening quote with no
    leading wildcard.  After the name, only version-specifier characters
    (``><=!~``), the extras bracket (``[``), an environment-marker
    semicolon (``;``), a direct-reference ``@``, or whitespace are
    allowed — a ``-`` that begins a hyphenated suffix (e.g. ``flask-login``)
    is not in that set, preventing substring clobbering.

    Two passes (double-quote then single-quote) keep the open/close quote
    types consistent so inner quotes of the other type (common in
    environment markers like ``sys_platform=='win32'``) are not treated
    as terminators.
    """
    for pkg in pkg_names:
        for q in ('"', "'"):
            pattern = (
                re.escape(q)
                + re.escape(pkg)
                + r'(?:[><=!~\[;@ \t][^'
                + re.escape(q)
                + r']*)?'
                + re.escape(q)
                + r',?\s*'
            )
            content = re.sub(pattern, '', content, flags=re.IGNORECASE)
    return content


def remove_from_setup_cfg(content: str, pkg_names: list) -> str:
    """Remove lines from install_requires section matching pkg_names."""
    lines = []
    for line in content.splitlines():
        keep = True
        for pkg in pkg_names:
            if re.match(r'\s*' + re.escape(pkg) + r'\s*[><=!~]', line.strip(), re.IGNORECASE):
                keep = False
                break
        if keep:
            lines.append(line)
    return "\n".join(lines) + ("\n" if content.endswith("\n") else "")


def remove_from_gemspec(content: str, pkg_names: list) -> str:
    """Remove ``add_*_dependency`` lines matching pkg_names from a .gemspec.

    Mirrors parse_gemspec / rewrite_gemspec by accepting all three Ruby
    forms: ``add_dependency``, ``add_runtime_dependency``,
    ``add_development_dependency``.
    """
    lines = []
    for line in content.splitlines():
        keep = True
        for pkg in pkg_names:
            if re.search(
                r'add(?:_runtime|_development)?_dependency\s+["\']'
                + re.escape(pkg) + r'["\']',
                line,
            ):
                keep = False
                break
        if keep:
            lines.append(line)
    return "\n".join(lines) + ("\n" if content.endswith("\n") else "")


def remove_from_libs_versions_toml(content: str, pkg_names: list) -> str:
    """Remove library entries matching pkg_names from a libs.versions.toml."""
    # Remove lines containing the module coordinate. Handles both the
    # ``module = "group:artifact"`` form (coord appears verbatim) and the split
    # ``{ group = "...", name = "..." }`` form (coord is split across two keys,
    # so match when BOTH halves appear on the line).
    lines = []
    for line in content.splitlines():
        keep = True
        for pkg in pkg_names:
            if pkg in line:
                keep = False
                break
            if ":" in pkg:
                grp, art = pkg.split(":", 1)
                if grp and art and grp in line and art in line:
                    keep = False
                    break
        if keep:
            lines.append(line)
    return "\n".join(lines) + ("\n" if content.endswith("\n") else "")


# ─────────────────────────── audit finaliser ───────────────────────────

def _pkg_display(key) -> str:
    """Render an updates-dict key as a human-readable package identifier."""
    return f"{key[0]}:{key[1]}" if isinstance(key, tuple) else str(key)


def _finalize_audit(
    file_path: str,
    content: str,
    updates: dict,
    blocked_pkgs: list,
    signals: list,
    rewriter_fn,
    remover_fn,
    ecosystem: str,
) -> None:
    """
    Write version updates, remove BLOCKED entries, and append adaptive VERIFY: signal.

    After the rewrite/remove step, verifies that each declared change actually
    landed in the resulting content. Updates whose new version did not appear,
    and removals whose package is still present, have their UPDATED:/BLOCKED:
    signal downgraded to WARNING: and are excluded from the VERIFY: summary.
    Without this gate, a buggy rewriter (silent no-op against a manifest form
    it does not handle) makes the parent agent trust a fix that never landed.

    Mutates signals in place. Always exits cleanly — errors become WARNING: lines.
    """
    # Capture the manifest mtime BEFORE any rewrite so _stale_lockfile_signal can
    # compare against it. After _write_file the mtime is 'now', which would make
    # every lock file appear stale regardless of whether npm/cargo/etc. already ran.
    _pre_rewrite_mtime = None  # float or None
    try:
        _pre_rewrite_mtime = os.path.getmtime(file_path)
    except OSError:
        pass
    wrote = False
    failed_updates: set = set()
    failed_blocks: set = set()
    final_content = content
    try:
        if updates:
            new_content = rewriter_fn(content, updates)
            for key, (_old, new_ver) in updates.items():
                # If the new version literal isn't in the post-rewrite content,
                # the rewriter could not apply this update. (False negatives are
                # possible if an unrelated occurrence of the version literal
                # already existed; format-anchored verification per ecosystem
                # is left for follow-up.)
                if not new_ver or new_ver not in new_content:
                    failed_updates.add(key)
            _write_file(file_path, new_content)
            final_content = new_content
            wrote = True
        if blocked_pkgs:
            try:
                with open(file_path, "r", encoding="utf-8") as fh:
                    disk_content = fh.read()
            except Exception:
                disk_content = final_content
            new_content = remover_fn(disk_content, blocked_pkgs)
            # If the remover did not change content at all, every blocked entry
            # failed. Per-entry verification would need format-aware "was this
            # package removed?" helpers; the all-or-nothing check here at least
            # catches the common silent no-op.
            if new_content == disk_content:
                for pkg in blocked_pkgs:
                    failed_blocks.add(pkg)
            _write_file(file_path, new_content)
            final_content = new_content
            wrote = True
    except Exception as exc:
        signals.append(f"WARNING: failed to rewrite {file_path}: {exc}")
        return

    base_name = os.path.basename(file_path)

    # Downgrade UPDATED:/COOLOFF: signals for updates that did not land.
    # COOLOFF rewrites flow through the same `updates` dict, so a failed one
    # would otherwise leave a lying "rewritten to" signal (review M2).
    if failed_updates:
        for i, sig in enumerate(signals):
            if not (sig.startswith("UPDATED: ") or sig.startswith("COOLOFF: ")):
                continue
            for key in failed_updates:
                disp = _pkg_display(key)
                if (sig.startswith(f"UPDATED: {disp} ")
                        or sig.startswith(f"COOLOFF: {disp}@")):
                    old_ver, new_ver = updates[key]
                    signals[i] = (
                        f"WARNING: rewrite skipped for {disp} — could not locate "
                        f"{old_ver} in {base_name} (rewriter may not handle this "
                        f"manifest form); manual update to {new_ver} required"
                    )
                    break

    # Downgrade BLOCKED: signals when nothing was actually removed.
    if failed_blocks:
        for i, sig in enumerate(signals):
            if not sig.startswith("BLOCKED: "):
                continue
            for pkg in failed_blocks:
                # BLOCKED: <pkg> <version> ...  OR  BLOCKED: <pkg> — abandoned ...
                if (sig.startswith(f"BLOCKED: {pkg} ")
                        or sig.startswith(f"BLOCKED: {pkg}—")
                        or sig.startswith(f"BLOCKED: {pkg} —")):
                    signals[i] = (
                        f"WARNING: removal skipped for {pkg} — could not locate "
                        f"entry in {base_name}; manual removal required"
                    )
                    break

    if wrote:
        verify_packages: list = []
        if updates:
            for key, (_old, new_ver) in updates.items():
                if key in failed_updates:
                    continue
                verify_packages.append((_pkg_display(key), _old, new_ver))
        if blocked_pkgs and not failed_blocks:
            for name in blocked_pkgs:
                verify_packages.append((name, "latest"))
        if verify_packages:
            install_cmd = _detect_install_cmd(file_path, ecosystem)
            stale_sig = _stale_lockfile_signal(
                file_path, ecosystem, install_cmd, _pre_rewrite_mtime
            )
            if stale_sig:
                signals.append(stale_sig)
            signals.append(_build_verify_signal(verify_packages, file_path, ecosystem))


# ─────────────────────────── signal emitter ───────────────────────────

# Dry-run mode: when SAFE_DEP_DRY_RUN is set to a truthy value, the shim runs
# every check and emits every signal exactly as usual but does not mutate the
# manifest on disk. Useful for CI gates that want to report on vulnerabilities
# without auto-correcting. Audit-log entries for a dry-run invocation get a
# "mode": "dry_run" field so post-hoc analysis can filter.
DRY_RUN = os.environ.get("SAFE_DEP_DRY_RUN", "").lower() in ("1", "true", "yes", "on")


# Stable identifier for this script in source.script — relative to repo root
# so log consumers can trace a line back to this file regardless of install
# location. See safedep.audit_log for the provenance schema.
_SOURCE_SCRIPT = "skills/safer-dependencies-shim.sh"


# Allowlist of source.component values the post-install bash and agent
# hooks may set via SAFE_DEP_CALLER when they forge a PostToolUse:Write
# payload and dispatch into this shim. Any other value (including empty
# or unknown strings) falls back to the default — defends against forged
# components in the audit log if the env var ever leaks from elsewhere.
_CALLER_OVERRIDE_ALLOWED = ("bash.posttooluse", "agent.posttooluse")


def _audit_source(tool_name):
    """Build the source block for a PostToolUse invocation of this shim.

    When the shim is dispatched by the post-install bash or agent hook,
    SAFE_DEP_CALLER carries the originator's component tag so the audit
    log records who triggered the audit, not just that the shim ran.
    Without this, post-install dispatches were indistinguishable from
    direct Write/Edit invocations in stats (issue #141).
    """
    caller = os.environ.get("SAFE_DEP_CALLER", "")
    component = caller if caller in _CALLER_OVERRIDE_ALLOWED else "shim.posttooluse"
    return _build_audit_source(
        component=component,
        script=_SOURCE_SCRIPT,
        hook="PostToolUse",
        tool=tool_name or None,
        mode="dry_run" if DRY_RUN else "intercept",
    )


def _write_audit_log(file_path: str, ecosystem: str, checked: list, signals: list,
                     *, tool_name: str = "", lockfile: bool = False,
                     manifest_ref: str = "", relation_summary: dict = None) -> None:
    """Append one canonical JSONL entry. Thin wrapper over the shared library
    so both surfaces (shim and Normal-mode CLI helper) write the same schema
    to the same file. ``tool_name`` is the Claude Code tool that triggered
    this invocation (``Write`` or ``Edit``); passed through to source.tool
    so post-hoc analysis can distinguish Write from Edit traffic.

    ``lockfile`` / ``manifest_ref`` / ``relation_summary`` (issue #245):
    lockfile audits additionally record the direct/transitive relation block
    computed by ``_classify_lockfile_relations``. Defaults keep every
    manifest-audit call site producing the unchanged non-lockfile shape."""
    _audit_log_write_entry(
        file_path, ecosystem, checked, signals,
        source=_audit_source(tool_name),
        dry_run=DRY_RUN,
        lockfile=lockfile,
        manifest_ref=manifest_ref,
        relation_summary=relation_summary,
    )


# ── REGRESSION DETECTION (issue #133) ────────────────────────────────────────
# A MAJOR-UPDATE-CONFIRM finding can be a re-introduction rather than a fresh
# CVE — a subagent (or a stale plan) wrote the manifest from a snapshot that
# predates an earlier correction. Cross-reference the audit log: if the same
# (file, package) was previously corrected to the same safe version via an
# UPDATED: signal, emit a REGRESSION: line ahead of the MAJOR-UPDATE-CONFIRM
# so the orchestrator recognises the re-introduction and restores the
# previously-approved version. Pairs with the autonomous-session rule from
# SKILL.md (issue #132): in autonomous mode the orchestrator applies
# minimum-tier YES on receipt of MAJOR-UPDATE-CONFIRM, so an extra REGRESSION
# preamble lets it correctly frame the change in its commit message.

# The em-dash is U+2014 — present in the live shim signals. Patterns matched:
#   "MAJOR-UPDATE-CONFIRM: pytest 8.3.5 has GHSA-... — safe version requires major bump to 9.0.3"
# followed (after a newline) by the "ACTION REQUIRED:" block in the same signal.
# The safe-version capture is greedy on \S+ then trimmed of trailing punctuation
# because versions contain dots ("9.0.3") and a naive lookahead-on-dot truncates
# them mid-string.
_MAJOR_CONFIRM_RE = re.compile(
    r"^MAJOR-UPDATE-CONFIRM:\s+(?P<pkg>\S+)\s+(?P<ver>\S+)\s+has\s+.+?"
    r"safe version requires major bump to\s+(?P<safe>\S+)",
    re.DOTALL,
)


def _strip_version_trailing_punct(ver: str) -> str:
    """Drop trailing punctuation/whitespace from a version captured greedily."""
    return ver.rstrip(",.;:\n\r\t )]}")


def _annotate_regressions(file_path: str, signals: list) -> list:
    """Prepend a REGRESSION: line for any MAJOR-UPDATE-CONFIRM that re-introduces
    a previously-corrected package.

    Pure function in the sense that it does not modify ``signals`` in place —
    returns a new list with REGRESSION lines inserted just before each
    matching MAJOR-UPDATE-CONFIRM. Silent on any audit-log read failure.
    """
    if not file_path or not signals:
        return signals
    out: list = []
    for sig in signals:
        if not isinstance(sig, str):
            out.append(sig)
            continue
        m = _MAJOR_CONFIRM_RE.match(sig)
        if not m:
            out.append(sig)
            continue
        pkg = m.group("pkg")
        current_ver = _strip_version_trailing_punct(m.group("ver"))
        proposed_safe = _strip_version_trailing_punct(m.group("safe"))
        try:
            prior = _find_prior_correction(file_path, pkg)
        except Exception:
            prior = None
        if prior is None:
            out.append(sig)
            continue
        # We only call this a regression when the prior corrected_to version
        # matches the proposed safe target. Different safe target = the
        # advisory changed (e.g. new CVE on a higher major); not a clean
        # re-introduction of a known-approved fix.
        if prior.get("new_version") != proposed_safe:
            out.append(sig)
            continue
        ts = prior.get("ts") or "earlier in this session"
        regression_line = (
            f"REGRESSION: {pkg} was previously corrected to {proposed_safe} "
            f"at {ts} (audit log component={prior.get('component') or 'unknown'}). "
            f"This MAJOR-UPDATE-CONFIRM is a re-introduction of "
            f"{pkg} {current_ver} — not a new CVE. The safe target "
            f"{proposed_safe} has already been approved in this project; "
            f"restoring it does NOT introduce a new major-version decision. "
            f"Apply the minimum-tier YES (bump {pkg} back to {proposed_safe}) "
            f"and note in the commit message that this is a regression fix."
        )
        out.append(regression_line)
        out.append(sig)
    return out


def emit_signals(lines: list) -> None:
    """Write hookSpecificOutput JSON to stdout for the parent agent.

    A single attribution header — ``[safer-dependencies <version>]`` — is
    prepended to ``additionalContext`` so the user can tell that any
    question or directive in the signal block originated from this skill
    (and which version of it). Downstream aggregators (the posttooluse
    bash/agent hooks) strip this header back off before re-wrapping so the
    parent agent never sees it duplicated.
    """
    if not lines:
        return
    ctx = "\n".join([attribution_header()] + list(lines))
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": ctx,
        }
    }))


def _severity(cves: list) -> str:
    return "CRITICAL" if len(cves) >= 2 else "HIGH"


# ─────────────────────────── ecosystem auditors ───────────────────────────

def _write_file(path: str, content: str) -> None:
    """Write content to path unless dry-run mode is active.

    In dry-run mode the manifest on disk is never mutated — the shim still
    runs every check and emits every signal, so the parent agent can see
    exactly what *would* have changed without the change actually landing.
    """
    if DRY_RUN:
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _apply_policy_to_result(out: dict, pkg: str, version: str) -> None:
    """Map non-default tiers onto a per-package audit result (issue #232).

    Default tiers leave `out` untouched (zero behavior change). Mutates in
    place: warn-escalations rewrite signal prefixes; block-escalations set
    out["blocked"] (driving the existing removal path); cve=warn downgrades
    a pending rewrite to a CONFIRM signal.
    """
    try:
        sigs = out.get("signals") or []
        # stale → block: STALE: becomes BLOCKED (removal path)
        if _tier("stale", "warn") == "block":
            for i, s in enumerate(sigs):
                if s.startswith(f"STALE: {pkg}"):
                    sigs[i] = (f"BLOCKED: {pkg} — stale (policy checks.stale=block): "
                               + s[len("STALE: "):])
                    out["blocked"] = pkg
        # typosquat → block
        if _tier("typosquat", "warn") == "block":
            for i, s in enumerate(sigs):
                if s.startswith(f"TYPOSQUAT-CONFIRM: {pkg}@"):
                    sigs[i] = (f"BLOCKED: {pkg} — typosquat suspicion "
                               f"(policy checks.typosquat=block): " + s.split("— ", 1)[-1])
                    out["blocked"] = pkg
        # existence → block (UNKNOWN: pkg@ver …)
        if _tier("existence", "warn") == "block":
            for i, s in enumerate(sigs):
                if s.startswith(f"UNKNOWN: {pkg}@"):
                    sigs[i] = (f"BLOCKED: {pkg} — not found in registry "
                               f"(policy checks.existence=block): " + s.split("— ", 1)[-1])
                    out["blocked"] = pkg
        # abandoned → warn: BLOCKED becomes ABANDONED-CONFIRM (no removal)
        if _tier("abandoned", "block") == "warn":
            for i, s in enumerate(sigs):
                if s.startswith(f"BLOCKED: {pkg} — abandoned:"):
                    sigs[i] = ("ABANDONED-CONFIRM: " + s[len("BLOCKED: "):]
                               + " — policy checks.abandoned=warn: ask the developer")
                    if out.get("blocked") == pkg:
                        out["blocked"] = None
        # cve → warn: a pending CVE-driven rewrite becomes a CONFIRM, no file
        # mutation. Keyed on the UPDATED: signal (not bare out["update"]) so a
        # cooloff-driven rewrite under cooloff.mode=block is NOT cancelled by
        # the cve tier — the two policies are independent (review finding).
        if _tier("cve", "block") == "warn" and out.get("update"):
            _updated_idx = next(
                (i for i, s in enumerate(sigs) if s.startswith("UPDATED:")), None)
            if _updated_idx is not None:
                _u_pkg, _old, _new = out["update"]
                if isinstance(_u_pkg, tuple):  # maven (group, artifact)
                    _u_pkg = ":".join(_u_pkg)
                out["update"] = None
                sigs[_updated_idx] = (
                    f"CVE-CONFIRM: {_u_pkg} {_old} has known CVEs; "
                    f"fix available at {_new} — policy checks.cve=warn: "
                    f"ask the developer before updating.")
    except Exception:  # noqa: BLE001 — policy mapping must never break audits
        pass


def _audit_one_package(
    pkg,
    version,
    *,
    ecosystem,
    file_path,
    skip_list,
    osv_name=None,
    osv_version=None,
    do_typosquat=True,
    python_floor="",
    signature_fn=None,
    do_migration_notes=True,
    peer_manifest_packages=None,
    multi_constraint=frozenset(),
    update_key=None,
):
    """Shared single-package audit pipeline used by the per-ecosystem manifest
    auditors (#291).

    Runs the canonical pipeline — typosquat → existence → abandoned →
    pick_safe_version → staleness → advisory-age → cooloff → signature → CVE
    decision — and returns the same ``out`` dict shape every auditor's inner
    ``_audit_one`` produced before the de-duplication::

        {"checked", "signals", "blocked", "update", "lookup_failure"}

    Per-ecosystem specifics are passed as keyword arguments so the body stays
    byte-for-byte identical to the 10 copies it replaces:

    - ``osv_name``: the registry/OSV name (PyPI normalises ``[-_.]+`` → ``-``);
      defaults to ``pkg``.
    - ``osv_version``: the version used for OSV/registry queries (Go strips
      ``+incompatible``); defaults to ``version``. Display/message/update use
      the original ``version``.
    - ``do_typosquat``: Go and crates auditors omit the typosquat probe.
    - ``python_floor``: threaded into ``pick_safe_version`` for PyPI (PEP 621
      ``requires-python`` floor, #195); empty for every other ecosystem (the
      ``pick_safe_version`` default).
    - ``signature_fn``: callable ``(pkg, version, signals)`` that appends a
      SIGNATURE signal (RubyGems / gemspec). ``None`` for ecosystems without a
      signature layer here.
    - ``do_migration_notes``: crates does not attach migration notes.
    - ``peer_manifest_packages``: npm threads the parsed manifest packages into
      the peer-compat note; others pass ``None``.
    - ``multi_constraint``: gemspec range-pins that must not be auto-rewritten
      (WARNING instead of UPDATED/BLOCKED). Empty for everyone else, so the
      guard is inert.
    - ``update_key``: the key stored in ``out["update"]`` / used for the
      ``checked`` and skip-list lookups when it differs from ``pkg`` (none of
      the 10 simple-name ecosystems need this; reserved for clarity).

    Maven and the Gradle version-catalog (``libs.versions.toml``) auditors are
    intentionally NOT routed through this helper: they carry group:artifact
    coordinates, thread ``group_id``/``artifact_id`` into every registry call,
    and store a ``(group, artifact)`` tuple as the update key — a genuine
    structural divergence that would tangle this body. They keep their own
    ``_audit_one``.
    """
    if osv_name is None:
        osv_name = pkg
    if osv_version is None:
        osv_version = version
    if update_key is None:
        update_key = pkg
    out = {
        "checked": "",
        "signals": [],
        "blocked": None,
        "update": None,
        "lookup_failure": None,
    }
    out["checked"] = f"{pkg}@{version}"
    # Check 0: typosquat (advisory — warn only, does not modify manifest)
    if do_typosquat:
        ts = check_typosquat(osv_name, ecosystem)
        if ts:
            _d, _ref = ts
            out["signals"].append(
                f"TYPOSQUAT-CONFIRM: {pkg}@{version} may be a typosquat of '{_ref}' "
                f"(edit distance {_d}) — verify intentional before proceeding"
            )
    # Check 0.5: existence (skip further checks if the registry 404s — fabricated name)
    if check_existence(pkg, osv_name, version, ecosystem, out["signals"]):
        _apply_policy_to_result(out, pkg, version)
        return out
    # Check 1: known abandoned
    abandon_reason = check_abandoned(pkg, ecosystem)
    if osv_name != pkg:
        abandon_reason = abandon_reason or check_abandoned(osv_name, ecosystem)
    if abandon_reason:
        out["blocked"] = update_key
        out["signals"].append(f"BLOCKED: {pkg} — abandoned: {abandon_reason}")
        _apply_policy_to_result(out, pkg, version)
        return out
    try:
        # PyPI threads a requires-python floor (#195); every other ecosystem
        # calls pick_safe_version with exactly the three positional args its
        # original auditor used — keep that call shape so test mocks that pin
        # the 3-arg signature (crates/rubygems) stay valid.
        if python_floor:
            safe_ver, cves = pick_safe_version(
                osv_name, ecosystem, osv_version, python_floor=python_floor
            )
        else:
            safe_ver, cves = pick_safe_version(osv_name, ecosystem, osv_version)
    except OSVLookupError as _osv_e:
        out["lookup_failure"] = (osv_name, osv_version, _osv_e.reason)
        _apply_policy_to_result(out, pkg, version)
        return out
    # Check 3: staleness (only if CVE-clean)
    if not cves:
        is_stale, last_date, st_status = check_staleness(
            osv_name, ecosystem, pinned_version=osv_version
        )
        if is_stale:
            out["signals"].append(f"STALE: {pkg} — last release {last_date}, no updates in 2+ years")
            _apply_policy_to_result(out, pkg, version)
            return out
        if st_status == "mature":
            out["signals"].append(f"NOTE: {pkg} — latest stable release ({last_date}) crossed the staleness threshold but is the current latest and widely adopted — mature, not flagged STALE")
        advisory_age_checks(osv_name, version, osv_name, ecosystem, out["signals"])
        co_action, co_signal, co_target = check_cooloff(osv_name, osv_version, ecosystem)
        if co_action == "confirm":
            out["signals"].append(co_signal)
        elif co_action == "rewrite":
            out["signals"].append(co_signal)
            out["update"] = (update_key, version, co_target)
    # Check 4: Layer 4 signatures — informational LOW if unsigned
    if signature_fn is not None:
        signature_fn(pkg, version, out["signals"])
    if not cves:
        _apply_policy_to_result(out, pkg, version)
        return out
    if safe_ver and safe_ver != osv_version:
        sev = _severity(cves)
        # Multi-constraint pin (gemspec range): rewrite is unsafe (which bound
        # to change?). Surface a WARNING instead of UPDATED/BLOCKED.
        if pkg in multi_constraint:
            out["signals"].append(
                f"WARNING: {pkg}@{version} has {', '.join(cves[:2])} — "
                f"multi-constraint pin (range with multiple bounds); safe "
                f"version is {safe_ver}, but auto-rewrite skipped (would alter "
                f"the constraint range). Edit the .gemspec manually."
            )
            _apply_policy_to_result(out, pkg, version)
            return out
        if _major(safe_ver) > _major(osv_version):
            if pkg in skip_list and skip_list[pkg] == version:
                _apply_policy_to_result(out, pkg, version)
                return out
            notes = _migration_notes(pkg, version, safe_ver) if do_migration_notes else ""
            out["signals"].append(
                f"MAJOR-UPDATE-CONFIRM: {pkg} {version} has {', '.join(cves[:2])} — "
                f"safe version requires major bump to {safe_ver}{notes}\n"
                f"ACTION REQUIRED: Ask the developer whether to proceed with the upgrade.\n"
                f"  If YES → 1) scan every file importing {pkg}, 2) check migration guide for breaking changes, 3) update {os.path.basename(file_path)}, 4) refactor callers, 5) run tests. Do NOT mark complete after step 3.\n"
                f"  If NO  → leave version as-is, acknowledge CVEs remain unresolved"
            )
            out["signals"].append(_build_major_bump_refactor_signal(
                pkg, version, safe_ver, file_path, ecosystem, notes))
            _peer_note = _build_peer_compat_note(
                pkg, safe_ver, ecosystem, file_path,
                manifest_packages=peer_manifest_packages,
            )
            if _peer_note:
                out["signals"].append(_peer_note)
        else:
            out["update"] = (update_key, version, safe_ver)
            out["signals"].append(
                f"UPDATED: {pkg} {version} → {safe_ver} ({sev}: {', '.join(cves[:2])})"
            )
    else:
        # No safe version. Multi-constraint pins still get a WARNING rather than
        # entry-removal — removing one bound of a range pin would silently
        # re-shape the constraint.
        if pkg in multi_constraint:
            out["signals"].append(
                f"WARNING: {pkg}@{version} has {', '.join(cves[:2])} — "
                f"multi-constraint pin; no safe version available. "
                f"Edit the .gemspec manually to address."
            )
            _apply_policy_to_result(out, pkg, version)
            return out
        out["blocked"] = update_key
        out["signals"].append(
            f"BLOCKED: {pkg} {version} has {', '.join(cves[:2])} — entry removed"
        )
        out["signals"].append(
            _build_blocked_replacement_refactor_signal(pkg, ecosystem, file_path))
    _apply_policy_to_result(out, pkg, version)
    return out


def audit_npm(file_path: str, content: str) -> tuple:
    """Returns (signals, checked) where checked is list of 'pkg@version'."""
    packages = parse_package_json(content)
    nonregistry_refs = extract_non_registry_npm_refs(content)
    updates, blocked_pkgs, signals = {}, [], []
    # Issue #156: emit an UNKNOWN signal for each dep whose version field is a
    # non-registry source (git+/file:/http URL, github: shorthand). The audit
    # log entry's findings array will surface these alongside CVE findings, so
    # operators can distinguish "audited and clean" from "couldn't audit".
    for _pkg, _ref in nonregistry_refs:
        signals.append(
            f"UNKNOWN: {_pkg} uses a non-registry source ({_ref}); "
            f"safer-dependencies cannot resolve this against OSV — confirm "
            f"origin trust manually"
        )
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # One batched OSV query warms _OSV_CACHE for every declared package (#108)
    # so the per-package _vuln_check current-version probes hit cache.
    prewarm_osv_cache([(p, v) for p, v, _ in packages], "npm")
    def _audit_one(pkg_version_tuple):
        pkg, version, _src = pkg_version_tuple
        return _audit_one_package(
            pkg, version,
            ecosystem="npm", file_path=file_path, skip_list=skip_list,
            peer_manifest_packages=packages,
        )

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    _emit_lookup_failures(signals, lookup_failures)
    _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                    rewrite_package_json, remove_from_package_json, "npm")
    _emit_lookup_failures(signals, lookup_failures)
    return signals, checked


def audit_packagist(file_path: str, content: str) -> tuple:
    """Audit a composer.json. Returns (signals, checked).

    Mirrors :func:`audit_npm` for PHP / Composer: walks ``require`` /
    ``require-dev`` via :func:`parse_composer_json`, OSV-checks each concrete
    pin against the ``Packagist`` ecosystem, and emits the same signal shapes
    (UPDATED / BLOCKED / UNKNOWN / TYPOSQUAT-CONFIRM / STALE). Vulnerable pins
    with no resolvable safe version are BLOCKED (entry removed) — the shim
    does not maintain a Packagist version-list resolver, so it never proposes
    a version-bump rewrite for composer (audit parity, not auto-correction).
    """
    packages = parse_composer_json(content)
    nonregistry_refs = extract_non_registry_composer_refs(content)
    updates, blocked_pkgs, signals = {}, [], []
    # Issue #156 parity: emit an UNKNOWN signal for each dep whose constraint /
    # repository is a non-Packagist source (dev-* VCS branch, inline dist/source
    # URL) that OSV cannot resolve.
    for _pkg, _ref in nonregistry_refs:
        signals.append(
            f"UNKNOWN: {_pkg} uses a non-registry source ({_ref}); "
            f"safer-dependencies cannot resolve this against OSV — confirm "
            f"origin trust manually"
        )
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # One batched OSV query warms _OSV_CACHE for every declared package (#108).
    prewarm_osv_cache([(p, v) for p, v, _ in packages], "packagist")

    def _audit_one(pkg_version_tuple):
        pkg, version, _src = pkg_version_tuple
        return _audit_one_package(
            pkg, version,
            ecosystem="packagist", file_path=file_path, skip_list=skip_list,
        )

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    _emit_lookup_failures(signals, lookup_failures)
    _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                    rewrite_composer_json, remove_from_composer_json, "packagist")
    _emit_lookup_failures(signals, lookup_failures)
    return signals, checked


def audit_pypi(file_path: str, content: str, basename: str) -> tuple:
    """Returns (signals, checked) where checked is list of 'pkg@version'."""
    # requirements.txt / Pipfile carry no PEP 621 floor to thread yet (issue #195).
    project_floor = ""
    if basename == "Pipfile":
        packages = parse_pipfile(content)
        hash_pins = {}
        nonregistry_refs: list = []
    else:
        packages = parse_requirements_txt(content)
        hash_pins = {p: hashes for p, _v, hashes in parse_requirements_hashes(content)}
        nonregistry_refs = extract_non_registry_pypi_refs(content)
    updates, blocked_pkgs, signals = {}, [], []
    # Issue #156: emit an UNKNOWN signal for each bare URL / git+ / file: line
    # in requirements.txt. These are direct-URL installs that OSV can't resolve
    # against a registry entry; without this the user has no signal that the
    # audit didn't apply to them.
    for _ref in nonregistry_refs:
        signals.append(
            f"UNKNOWN: requirements.txt declares a non-registry source ({_ref}); "
            f"safer-dependencies cannot resolve this against OSV — confirm "
            f"origin trust manually"
        )
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # One batched OSV query warms _OSV_CACHE for every declared package (#108).
    prewarm_osv_cache(
        [(re.sub(r"[-_.]+", "-", p).lower(), v) for p, v in packages],
        "pypi",
    )
    # Layer 4: hash-pin validation (PyPI only, requirements.txt only, opt-in via --hash=)
    for pkg, version in packages:
        declared = hash_pins.get(pkg, [])
        if not declared:
            continue
        ok, _published = check_pypi_hash_pin(pkg, version, declared)
        if not ok:
            signals.append(
                f"WARNING: {pkg}@{version} declared hash does not match any "
                f"PyPI-published sha256 digest \u2014 entry may have been tampered with in the manifest"
            )
    def _audit_one(pkg_version_tuple):
        pkg, version = pkg_version_tuple
        osv_name = re.sub(r"[-_.]+", "-", pkg).lower()
        return _audit_one_package(
            pkg, version,
            ecosystem="pypi", file_path=file_path, skip_list=skip_list,
            osv_name=osv_name, python_floor=project_floor,
        )

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    if basename == "Pipfile":
        _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                        rewrite_pipfile, remove_from_requirements_txt, "pypi")
    else:
        # Hash-pinned packages cannot be safely auto-bumped: their --hash=sha256
        # continuation lines describe the OLD release, and pip --require-hashes
        # will reject the file if the version changes without a corresponding
        # hash refresh. Pull those packages out of `updates` and replace their
        # UPDATED: signal with a hash-specific WARNING telling the user to use
        # pip-compile / uv lock to refresh hashes.
        hashed_normalized = {_normalize_pep503(p) for p in hash_pins}
        for pkg in list(updates.keys()):
            if _normalize_pep503(pkg) not in hashed_normalized:
                continue
            old_ver, new_ver = updates.pop(pkg)
            for i, sig in enumerate(signals):
                if sig.startswith(f"UPDATED: {pkg} {old_ver} "):
                    signals[i] = (
                        f"WARNING: HASH-PINNED-UPDATE: {pkg} {old_ver} → "
                        f"{new_ver} available with CVE fix, but {basename} uses "
                        f"--hash= pinning. Refresh hashes via `pip-compile` or "
                        f"`uv lock` before bumping the version; manual version "
                        f"bump alone will break --require-hashes installs."
                    )
                    break
        _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                        rewrite_requirements_txt, remove_from_requirements_txt, "pypi")
    _emit_lookup_failures(signals, lookup_failures)
    return signals, checked


def audit_rubygems(file_path: str, content: str) -> tuple:
    """Returns (signals, checked) where checked is list of 'pkg@version'."""
    packages = parse_gemfile(content)
    updates, blocked_pkgs, signals = {}, [], []
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # Batched OSV warm-up (#108). check_osv_rubygems_expanded still fans out
    # per-component, but the primary-gem current-version probes hit cache.
    prewarm_osv_cache(list(packages), "rubygems")
    def _audit_one(pkg_version_tuple):
        pkg, version = pkg_version_tuple
        return _audit_one_package(
            pkg, version,
            ecosystem="rubygems", file_path=file_path, skip_list=skip_list,
            signature_fn=emit_signature_rubygems,
        )

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    _emit_lookup_failures(signals, lookup_failures)
    _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                    rewrite_gemfile, remove_from_gemfile, "rubygems")
    _emit_lookup_failures(signals, lookup_failures)
    return signals, checked


def audit_maven(file_path: str, content: str, basename: str) -> tuple:
    """Returns (signals, checked) where checked is list of 'pkg@version'."""
    if basename.endswith(".xml"):
        packages = parse_pom_xml(content)
    else:
        packages = parse_build_gradle(content)
    updates, blocked_pkgs, signals = {}, [], []
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # Batched OSV warm-up (#108).
    prewarm_osv_cache([(f"{g}:{a}", v) for g, a, v in packages], "maven")
    def _audit_one(pkg_version_tuple):
        group, artifact, version = pkg_version_tuple
        out = {
            "checked": "",
            "signals": [],
            "blocked": None,
            "update": None,
            "lookup_failure": None,
        }
        osv_name = f"{group}:{artifact}"
        out["checked"] = f"{osv_name}@{version}"
        # Check 0: typosquat (advisory — warn only, does not modify manifest)
        ts = check_typosquat(osv_name, "maven")
        if ts:
            _d, _ref = ts
            out["signals"].append(
                f"TYPOSQUAT-CONFIRM: {osv_name}@{version} may be a typosquat of '{_ref}' "
                f"(edit distance {_d}) \u2014 verify intentional before proceeding"
            )
        # Check 0.5: existence (skip further checks if the registry 404s — fabricated name)
        if check_existence(osv_name, osv_name, version, "maven", out["signals"],
                           group_id=group, artifact_id=artifact):
            _apply_policy_to_result(out, osv_name, version)
            return out
        # Check 1: known abandoned (maven doesn't have entries in KNOWN_ABANDONED yet, but check anyway)
        abandon_reason = check_abandoned(osv_name, "maven")
        if abandon_reason:
            out["blocked"] = osv_name
            out["signals"].append(f"BLOCKED: {osv_name} \u2014 abandoned: {abandon_reason}")
            _apply_policy_to_result(out, osv_name, version)
            return out
        try:
            safe_ver, cves = pick_safe_version(
                osv_name, "maven", version, group_id=group, artifact_id=artifact
            )
        except OSVLookupError as _osv_e:
            out["lookup_failure"] = (osv_name, version, _osv_e.reason)
            _apply_policy_to_result(out, osv_name, version)
            return out
        # Check 3: staleness (only if CVE-clean)
        if not cves:
            is_stale, last_date, _st_status = check_staleness(osv_name, "maven", group_id=group, artifact_id=artifact, pinned_version=version)
            if is_stale:
                out["signals"].append(f"STALE: {osv_name} \u2014 last release {last_date}, no updates in 2+ years")
                _apply_policy_to_result(out, osv_name, version)
                return out
            if _st_status == "mature":
                out["signals"].append(f"NOTE: {osv_name} — latest stable release ({last_date}) crossed the staleness threshold but is the current latest and widely adopted — mature, not flagged STALE")
            advisory_age_checks(osv_name, version, osv_name, "maven", out["signals"], group_id=group, artifact_id=artifact)
            co_action, co_signal, co_target = check_cooloff(osv_name, version, "maven", group_id=group, artifact_id=artifact)
            if co_action == "confirm":
                out["signals"].append(co_signal)
            elif co_action == "rewrite":
                out["signals"].append(co_signal)
                out["update"] = ((group, artifact), version, co_target)
        # Check 4: Layer 4 signatures — MEDIUM if Maven Central has no .asc
        emit_signature_maven(group, artifact, version, out["signals"])
        if not cves:
            _apply_policy_to_result(out, osv_name, version)
            return out
        if safe_ver and safe_ver != version:
            sev = _severity(cves)
            if _major(safe_ver) > _major(version):
                if osv_name in skip_list and skip_list[osv_name] == version:
                    _apply_policy_to_result(out, osv_name, version)
                    return out
                notes = _migration_notes(osv_name, version, safe_ver)
                out["signals"].append(
                    f"MAJOR-UPDATE-CONFIRM: {osv_name} {version} has {', '.join(cves[:2])} \u2014 "
                    f"safe version requires major bump to {safe_ver}{notes}\n"
                    f"ACTION REQUIRED: Ask the developer whether to proceed with the upgrade.\n"
                    f"  If YES \u2192 1) scan every file importing {osv_name}, 2) check migration guide for breaking changes, 3) update {os.path.basename(file_path)}, 4) refactor callers, 5) run tests. Do NOT mark complete after step 3.\n"
                    f"  If NO  \u2192 leave version as-is, acknowledge CVEs remain unresolved"
                )
                out["signals"].append(_build_major_bump_refactor_signal(
                    osv_name, version, safe_ver, file_path, "maven", notes))
                _peer_note = _build_peer_compat_note(osv_name, safe_ver, "maven", file_path)
                if _peer_note:
                    out["signals"].append(_peer_note)
            else:
                out["update"] = ((group, artifact), version, safe_ver)
                out["signals"].append(
                    f"UPDATED: {osv_name} {version} \u2192 {safe_ver} ({sev}: {', '.join(cves[:2])})"
                )
        else:
            out["blocked"] = osv_name
            out["signals"].append(
                f"BLOCKED: {osv_name} {version} has {', '.join(cves[:2])} \u2014 entry removed"
            )
            out["signals"].append(
                _build_blocked_replacement_refactor_signal(osv_name, "maven", file_path))
        _apply_policy_to_result(out, osv_name, version)
        return out

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    if basename.endswith(".xml"):
        _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                        rewrite_pom_xml, remove_from_pom_xml, "maven")
    else:
        _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                        rewrite_build_gradle, remove_from_build_gradle, "maven")
    _emit_lookup_failures(signals, lookup_failures)
    return signals, checked


def audit_go(file_path: str, content: str) -> tuple:
    """Returns (signals, checked) where checked is list of 'module@version'."""
    packages = parse_go_mod(content)
    updates, blocked_pkgs, signals = {}, [], []
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # Cross-check: warn when a require and an exclude pin the same module@version.
    # This is a structural contradiction — Go refuses to resolve it.
    excludes = _parse_go_mod_excludes(content)
    for _mod, _ver in packages:
        if _mod in excludes and _ver in excludes[_mod]:
            signals.append(
                f"WARNING: {_mod} {_ver} is both required and excluded in go.mod "
                f"— Go will refuse to resolve this; remove the exclude or update the require pin"
            )
    # Batched OSV warm-up (#108). Use the osv_version form (strip +incompatible).
    prewarm_osv_cache(
        [(m, v.replace("+incompatible", "")) for m, v in packages],
        "go",
    )
    def _audit_one(pkg_version_tuple):
        module_path, version = pkg_version_tuple
        osv_version = version.replace("+incompatible", "")
        return _audit_one_package(
            module_path, version,
            ecosystem="go", file_path=file_path, skip_list=skip_list,
            osv_version=osv_version, do_typosquat=False,
        )

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    _emit_lookup_failures(signals, lookup_failures)
    _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                    rewrite_go_mod, remove_from_go_mod, "go")
    _emit_lookup_failures(signals, lookup_failures)
    return signals, checked


def audit_pyproject_toml(file_path: str, content: str) -> tuple:
    """Returns (signals, checked) for pyproject.toml (PEP 621, Poetry, uv)."""
    packages = parse_pyproject_toml(content)
    project_floor = _pyproject_python_floor(content)  # issue #195
    updates, blocked_pkgs, signals = {}, [], []
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # Batched OSV warm-up (#108).
    prewarm_osv_cache(
        [(re.sub(r"[-_.]+", "-", p).lower(), v) for p, v in packages],
        "pypi",
    )
    def _audit_one(pkg_version_tuple):
        pkg, version = pkg_version_tuple
        osv_name = re.sub(r"[-_.]+", "-", pkg).lower()
        return _audit_one_package(
            pkg, version,
            ecosystem="pypi", file_path=file_path, skip_list=skip_list,
            osv_name=osv_name, python_floor=project_floor,
        )

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    _emit_lookup_failures(signals, lookup_failures)
    _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                    rewrite_pyproject_toml, remove_from_pyproject_toml, "pypi")
    _emit_lookup_failures(signals, lookup_failures)
    # Append NOTE signals for [tool.uv.sources] non-registry entries AFTER the
    # CVE audit so they don't suppress the CLEAN signal when all auditable deps
    # are clean. The developer still sees coverage-gap notes in the output.
    signals.extend(_uv_sources_notes(content))
    return signals, checked


def audit_setup_py(file_path: str, content: str) -> tuple:
    """Returns (signals, checked) for setup.py."""
    packages = parse_setup_py(content)
    project_floor = ""  # setup.py python_requires not threaded yet (issue #195)
    updates, blocked_pkgs, signals = {}, [], []
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # Batched OSV warm-up (#108).
    prewarm_osv_cache(
        [(re.sub(r"[-_.]+", "-", p).lower(), v) for p, v in packages],
        "pypi",
    )
    def _audit_one(pkg_version_tuple):
        pkg, version = pkg_version_tuple
        osv_name = re.sub(r"[-_.]+", "-", pkg).lower()
        return _audit_one_package(
            pkg, version,
            ecosystem="pypi", file_path=file_path, skip_list=skip_list,
            osv_name=osv_name, python_floor=project_floor,
        )

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    _emit_lookup_failures(signals, lookup_failures)
    _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                    rewrite_setup_py, remove_from_setup_py, "pypi")
    _emit_lookup_failures(signals, lookup_failures)
    return signals, checked


def audit_setup_cfg(file_path: str, content: str) -> tuple:
    """Returns (signals, checked) for setup.cfg."""
    packages = parse_setup_cfg(content)
    project_floor = ""  # setup.cfg python_requires not threaded yet (issue #195)
    updates, blocked_pkgs, signals = {}, [], []
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # Batched OSV warm-up (#108).
    prewarm_osv_cache(
        [(re.sub(r"[-_.]+", "-", p).lower(), v) for p, v in packages],
        "pypi",
    )
    def _audit_one(pkg_version_tuple):
        pkg, version = pkg_version_tuple
        osv_name = re.sub(r"[-_.]+", "-", pkg).lower()
        return _audit_one_package(
            pkg, version,
            ecosystem="pypi", file_path=file_path, skip_list=skip_list,
            osv_name=osv_name, python_floor=project_floor,
        )

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    _emit_lookup_failures(signals, lookup_failures)
    _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                    rewrite_setup_cfg, remove_from_setup_cfg, "pypi")
    _emit_lookup_failures(signals, lookup_failures)
    return signals, checked


def audit_gemspec(file_path: str, content: str) -> tuple:
    """Returns (signals, checked) for .gemspec files.

    Multi-constraint pins (``add_dependency 'rails', '>= 5.0', '< 6.0'``)
    surface every constraint to OSV, but the auto-rewrite path is
    suppressed for those packages — reshaping a bound pair is a
    judgment call, not a mechanical replacement. Single-constraint
    pins continue to UPDATED:/MAJOR-UPDATE-CONFIRM:/BLOCKED: as before.
    """
    packages = parse_gemspec(content)
    updates, blocked_pkgs, signals = {}, [], []
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # Build multi_constraint from the per-call flag emitted by parse_gemspec.
    # A gem is multi-constraint only when a SINGLE add_*_dependency call had
    # multiple version args — NOT simply because the same name appears on
    # two separate single-constraint lines (which are two independent pins
    # and MUST each be audited/rewritten independently).
    multi_constraint = {n for n, v, is_multi in packages if is_multi}
    # Batched OSV warm-up (#108). prewarm_osv_cache expects (name, version) pairs.
    prewarm_osv_cache([(n, v) for n, v, _ in packages], "rubygems")
    def _audit_one(pkg_version_tuple):
        pkg, version, _is_multi = pkg_version_tuple
        return _audit_one_package(
            pkg, version,
            ecosystem="rubygems", file_path=file_path, skip_list=skip_list,
            signature_fn=emit_signature_rubygems,
            multi_constraint=multi_constraint,
        )

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    _emit_lookup_failures(signals, lookup_failures)
    _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                    rewrite_gemspec, remove_from_gemspec, "rubygems")
    _emit_lookup_failures(signals, lookup_failures)
    return signals, checked


def audit_libs_versions_toml(file_path: str, content: str) -> tuple:
    """Returns (signals, checked) for Gradle Version Catalog (libs.versions.toml)."""
    packages = parse_libs_versions_toml(content)
    updates, blocked_pkgs, signals = {}, [], []
    lookup_failures: list = []
    checked = []
    skip_list = _read_skip_list()
    # Batched OSV warm-up (#108). parse_libs_versions_toml yields "group:artifact".
    prewarm_osv_cache(list(packages), "maven")
    def _audit_one(pkg_version_tuple):
        module, version = pkg_version_tuple
        out = {
            "checked": "",
            "signals": [],
            "blocked": None,
            "update": None,
            "lookup_failure": None,
        }
        out["checked"] = f"{module}@{version}"
        # Check 0: typosquat (advisory — warn only, does not modify manifest)
        ts = check_typosquat(module, "maven")
        if ts:
            _d, _ref = ts
            out["signals"].append(
                f"TYPOSQUAT-CONFIRM: {module}@{version} may be a typosquat of '{_ref}' "
                f"(edit distance {_d}) \u2014 verify intentional before proceeding"
            )
        # Check 0.5: existence (skip further checks if Maven Central 404s — fabricated name)
        _grp_early = module.split(":")[0] if ":" in module else ""
        _art_early = module.split(":")[1] if ":" in module else module
        if check_existence(module, module, version, "maven", out["signals"],
                           group_id=_grp_early, artifact_id=_art_early):
            _apply_policy_to_result(out, module, version)
            return out
        # Check 1: known abandoned
        abandon_reason = check_abandoned(module, "maven")
        if abandon_reason:
            out["blocked"] = module
            out["signals"].append(f"BLOCKED: {module} \u2014 abandoned: {abandon_reason}")
            _apply_policy_to_result(out, module, version)
            return out
        _grp = module.split(":")[0] if ":" in module else ""
        _art = module.split(":")[1] if ":" in module else module
        try:
            safe_ver, cves = pick_safe_version(
                module, "maven", version,
                group_id=_grp,
                artifact_id=_art
            )
        except OSVLookupError as _osv_e:
            out["lookup_failure"] = (module, version, _osv_e.reason)
            _apply_policy_to_result(out, module, version)
            return out
        # Check 3: staleness (only if CVE-clean)
        if not cves:
            is_stale, last_date, _st_status = check_staleness(module, "maven", group_id=_grp, artifact_id=_art, pinned_version=version)
            if is_stale:
                out["signals"].append(f"STALE: {module} \u2014 last release {last_date}, no updates in 2+ years")
                _apply_policy_to_result(out, module, version)
                return out
            if _st_status == "mature":
                out["signals"].append(f"NOTE: {module} — latest stable release ({last_date}) crossed the staleness threshold but is the current latest and widely adopted — mature, not flagged STALE")
            advisory_age_checks(module, version, module, "maven", out["signals"], group_id=_grp, artifact_id=_art)
            co_action, co_signal, co_target = check_cooloff(module, version, "maven", group_id=_grp, artifact_id=_art)
            if co_action == "confirm":
                out["signals"].append(co_signal)
            elif co_action == "rewrite":
                out["signals"].append(co_signal)
                out["update"] = (module, version, co_target)
        # Check 4: Layer 4 signatures — MEDIUM if Maven Central has no .asc
        emit_signature_maven(_grp, _art, version, out["signals"])
        if not cves:
            _apply_policy_to_result(out, module, version)
            return out
        if safe_ver and safe_ver != version:
            sev = _severity(cves)
            if _major(safe_ver) > _major(version):
                if module in skip_list and skip_list[module] == version:
                    _apply_policy_to_result(out, module, version)
                    return out
                notes = _migration_notes(module, version, safe_ver)
                out["signals"].append(
                    f"MAJOR-UPDATE-CONFIRM: {module} {version} has {', '.join(cves[:2])} \u2014 "
                    f"safe version requires major bump to {safe_ver}{notes}\n"
                    f"ACTION REQUIRED: Ask the developer whether to proceed with the upgrade.\n"
                    f"  If YES \u2192 1) scan every file importing {module}, 2) check migration guide for breaking changes, 3) update {os.path.basename(file_path)}, 4) refactor callers, 5) run tests. Do NOT mark complete after step 3.\n"
                    f"  If NO  \u2192 leave version as-is, acknowledge CVEs remain unresolved"
                )
                out["signals"].append(_build_major_bump_refactor_signal(
                    module, version, safe_ver, file_path, "maven", notes))
                _peer_note = _build_peer_compat_note(module, safe_ver, "maven", file_path)
                if _peer_note:
                    out["signals"].append(_peer_note)
            else:
                out["update"] = (module, version, safe_ver)
                out["signals"].append(
                    f"UPDATED: {module} {version} \u2192 {safe_ver} ({sev}: {', '.join(cves[:2])})"
                )
        else:
            out["blocked"] = module
            out["signals"].append(
                f"BLOCKED: {module} {version} has {', '.join(cves[:2])} \u2014 entry removed"
            )
            out["signals"].append(
                _build_blocked_replacement_refactor_signal(module, "maven", file_path))
        _apply_policy_to_result(out, module, version)
        return out

    results = parallel_map(_audit_one, packages, max_workers=_manifest_max_workers())
    for r in results:
        checked.append(r["checked"])
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    _emit_lookup_failures(signals, lookup_failures)
    _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                    rewrite_libs_versions_toml, remove_from_libs_versions_toml, "maven")
    _emit_lookup_failures(signals, lookup_failures)
    return signals, checked


# ─────────────────────────── lock file auditors ───────────────────────────

def audit_package_lock(content: str) -> tuple:
    """Audit a package-lock.json. Returns ``(signals, checked)``.

    ``checked`` lists every ``pkg@version`` actually OSV-checked so clean
    lockfile audits produce a CLEAN summary + audit-log entry (issue #244)
    instead of being indistinguishable from "never ran".
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return [], []
    signals = []
    lookup_failures: list = []
    # Collect (pkg, version) first, then one batched OSV warm-up (#108) —
    # lockfiles commonly list hundreds of transitive deps.
    to_check: list = []
    packages = data.get("packages", {})
    seen: set = set()
    # lockfileVersion 2+: packages object. npm hoists one copy of a package to
    # the top of node_modules and nests others (e.g.
    # node_modules/email-templates/node_modules/nodemailer), so the same name
    # commonly resolves to several versions. Deduplicate by (name, version) —
    # NOT by name alone — so every distinct resolved version is OSV-checked.
    # Name-only dedup is order-dependent and drops a vulnerable nested copy
    # whenever a clean copy of the same name is iterated first. This matches
    # audit_yarn_lock / audit_pnpm_lock / audit_cargo_lock.
    for path, info in packages.items():
        if not path:
            continue
        pkg = re.sub(r"^.*node_modules/", "", path)
        version = info.get("version", "")
        if not version or _is_prerelease(version, "npm") or (pkg, version) in seen:
            continue
        seen.add((pkg, version))
        to_check.append((pkg, version))
    # lockfileVersion 1 fallback
    if not packages:
        for pkg, info in data.get("dependencies", {}).items():
            version = info.get("version", "")
            if version:
                to_check.append((pkg, version))
    prewarm_osv_cache(to_check, "npm")
    jobs = [(p, p, v, "npm") for p, v in to_check]
    results = parallel_map(_lockfile_osv_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: f"WARNING: {pkg}@{ver} in lock file has {', '.join(cves[:2])}",
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{p}@{v}" for p, v in to_check]


def audit_composer_lock(content: str) -> tuple:
    """Audit a composer.lock. Returns ``(signals, checked)`` — issue #244.

    composer.lock carries fully-resolved dependencies in two arrays,
    ``packages`` (runtime) and ``packages-dev`` (dev), each an object with a
    ``name`` (vendor/package) and an exact ``version`` (e.g. ``1.2.3`` or
    ``v1.2.3``). Mirrors :func:`audit_package_lock`: collect the resolved set,
    one batched OSV warm-up (#108), then a parallel CVE check per entry.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return [], []
    signals = []
    lookup_failures: list = []
    to_check: list = []  # (name, version)
    seen: set = set()
    for section in ("packages", "packages-dev"):
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        for info in entries:
            if not isinstance(info, dict):
                continue
            name = info.get("name", "")
            # composer.lock pins carry a leading ``v`` on some packages;
            # OSV's Packagist coordinates are version-literal, so strip it.
            version = str(info.get("version", "")).lstrip("vV")
            if not name or not version or name in seen:
                continue
            if _is_prerelease(version, "packagist"):
                continue
            seen.add(name)
            to_check.append((name, version))
    prewarm_osv_cache(to_check, "packagist")  # #108
    jobs = [(p, p, v, "packagist") for p, v in to_check]
    results = parallel_map(_lockfile_osv_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: f"WARNING: {pkg}@{ver} in lock file has {', '.join(cves[:2])}",
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{p}@{v}" for p, v in to_check]


def audit_pipfile_lock(content: str) -> tuple:
    """Audit a Pipfile.lock. Returns ``(signals, checked)`` — see issue #244."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return [], []
    signals = []
    lookup_failures: list = []
    to_check: list = []  # (display_pkg, osv_name, version)
    for section in ("default", "develop"):
        for pkg, info in data.get(section, {}).items():
            version = info.get("version", "").lstrip("=")
            if not version:
                continue
            osv_name = re.sub(r"[-_.]+", "-", pkg).lower()
            to_check.append((pkg, osv_name, version))
    prewarm_osv_cache([(osv, v) for _, osv, v in to_check], "pypi")  # #108
    jobs = [(display, osv, v, "pypi") for display, osv, v in to_check]
    results = parallel_map(_lockfile_osv_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: f"WARNING: {pkg}=={ver} in lock file has {', '.join(cves[:2])}",
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{pkg}@{v}" for pkg, _, v in to_check]


def audit_go_sum(content: str) -> tuple:
    """Return WARNING signals for CVE-bearing packages in go.sum.
    go.sum contains every transitive dependency with cryptographic hashes.
    We check each unique module but do not rewrite go.sum (it is machine-generated).
    """
    packages = parse_go_sum(content)
    signals = []
    lookup_failures: list = []
    prewarm_osv_cache(list(packages), "go")  # #108
    jobs = [(mp, mp, v, "go") for mp, v in packages]
    results = parallel_map(_lockfile_osv_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda mp, ver, cves: f"WARNING: {mp}@{ver} in go.sum has {', '.join(cves[:2])}",
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{mp}@{v}" for mp, v in packages]


def audit_gemfile_lock(content: str) -> tuple:
    """Check GEM section of Gemfile.lock for vulnerable versions."""
    signals = []
    lookup_failures: list = []
    entries: list = []
    in_specs = False
    for line in content.splitlines():
        if line.strip() == "GEM":
            in_specs = False
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
            continue
        if in_specs:
            m = re.match(r'\s{4}(\S+)\s+\(([^)]+)\)', line)
            if m:
                entries.append((m.group(1), m.group(2)))
    prewarm_osv_cache(entries, "rubygems")  # #108
    jobs = [(p, p, v, "rubygems") for p, v in entries]
    results = parallel_map(_lockfile_safe_version_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: (
            f"WARNING: {pkg}@{ver} in Gemfile.lock has "
            f"{', '.join(cves[:2])} — run bundle update {pkg}"
        ),
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{p}@{v}" for p, v in entries]


def audit_poetry_lock(content: str) -> tuple:
    """Check [[package]] entries in poetry.lock. Returns ``(signals, checked)``."""
    if _tomllib is None:
        return [
            "WARNING: cannot audit poetry.lock — Python TOML parser not available. "
            "On Python 3.8–3.10 install the polyfill: `pip install tomli`. "
            "(Python 3.11+ includes tomllib in the standard library.)"
        ], []
    try:
        data = _tomllib.loads(content)
    except Exception:
        return [], []
    signals = []
    lookup_failures: list = []
    entries: list = []
    for pkg_entry in data.get("package", []):
        pkg = pkg_entry.get("name", "")
        ver = pkg_entry.get("version", "")
        if not pkg or not ver:
            continue
        osv_name = re.sub(r"[-_.]+", "-", pkg).lower()
        entries.append((pkg, osv_name, ver))
    prewarm_osv_cache([(osv, v) for _, osv, v in entries], "pypi")  # #108
    jobs = [(display, osv, v, "pypi") for display, osv, v in entries]
    results = parallel_map(_lockfile_safe_version_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: (
            f"WARNING: {pkg}@{ver} in poetry.lock has "
            f"{', '.join(cves[:2])} — run poetry update {pkg}"
        ),
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{pkg}@{v}" for pkg, _, v in entries]


def audit_uv_lock(content: str) -> tuple:
    """Check [[package]] entries in uv.lock. Returns ``(signals, checked)``."""
    if _tomllib is None:
        return [
            "WARNING: cannot audit uv.lock — Python TOML parser not available. "
            "On Python 3.8–3.10 install the polyfill: `pip install tomli`. "
            "(Python 3.11+ includes tomllib in the standard library.)"
        ], []
    try:
        data = _tomllib.loads(content)
    except Exception:
        return [], []
    signals = []
    lookup_failures: list = []
    entries: list = []
    for pkg_entry in data.get("package", []):
        pkg = pkg_entry.get("name", "")
        ver = pkg_entry.get("version", "")
        if not pkg or not ver:
            continue
        osv_name = re.sub(r"[-_.]+", "-", pkg).lower()
        entries.append((pkg, osv_name, ver))
    prewarm_osv_cache([(osv, v) for _, osv, v in entries], "pypi")  # #108
    jobs = [(display, osv, v, "pypi") for display, osv, v in entries]
    results = parallel_map(_lockfile_safe_version_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: (
            f"WARNING: {pkg}@{ver} in uv.lock has "
            f"{', '.join(cves[:2])} — run uv lock --upgrade-package {pkg}"
        ),
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{pkg}@{v}" for pkg, _, v in entries]


def audit_pdm_lock(content: str) -> tuple:
    """Check [[package]] entries in pdm.lock for vulnerable versions.

    PDM's lockfile is TOML with the same ``[[package]]`` shape uv uses, so the
    extraction logic mirrors ``audit_uv_lock`` — only the remediation hint
    differs (PDM users run ``pdm update --update-eager <pkg>``).
    """
    if _tomllib is None:
        return [
            "WARNING: cannot audit pdm.lock — Python TOML parser not available. "
            "On Python 3.8–3.10 install the polyfill: `pip install tomli`. "
            "(Python 3.11+ includes tomllib in the standard library.)"
        ], []
    try:
        data = _tomllib.loads(content)
    except Exception:
        return [], []
    signals = []
    lookup_failures: list = []
    entries: list = []
    for pkg_entry in data.get("package", []):
        pkg = pkg_entry.get("name", "")
        ver = pkg_entry.get("version", "")
        if not pkg or not ver:
            continue
        osv_name = re.sub(r"[-_.]+", "-", pkg).lower()
        entries.append((pkg, osv_name, ver))
    prewarm_osv_cache([(osv, v) for _, osv, v in entries], "pypi")
    jobs = [(display, osv, v, "pypi") for display, osv, v in entries]
    results = parallel_map(_lockfile_safe_version_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: (
            f"WARNING: {pkg}@{ver} in pdm.lock has "
            f"{', '.join(cves[:2])} — run pdm update --update-eager {pkg}"
        ),
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{pkg}@{v}" for pkg, _, v in entries]


def audit_yarn_lock(content: str) -> tuple:
    """Return WARNING signals for CVE-bearing packages resolved in yarn.lock.

    Uses safedep.lockfiles.parse_yarn_lock for the text-format parsing. No
    typosquat / staleness / abandoned checks (transitive deps follow the
    reduced check-set per the parity plan's Part D).
    """
    signals: list = []
    lookup_failures: list = []
    try:
        entries = parse_yarn_lock(content)
    except Exception:
        return signals, []
    seen = set()
    to_check: list = []
    for pkg, version in entries:
        if not version or _is_prerelease(version, "npm") or (pkg, version) in seen:
            continue
        seen.add((pkg, version))
        to_check.append((pkg, version))
    prewarm_osv_cache(to_check, "npm")  # #108
    jobs = [(p, p, v, "npm") for p, v in to_check]
    results = parallel_map(_lockfile_osv_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: f"WARNING: {pkg}@{ver} in lock file has {', '.join(cves[:2])}",
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{p}@{v}" for p, v in to_check]


def audit_pnpm_lock(content: str) -> tuple:
    """Audit pnpm-lock.yaml. Returns ``(signals, checked)`` — see issue #244."""
    signals: list = []
    lookup_failures: list = []
    try:
        entries = parse_pnpm_lock(content)
    except Exception:
        return signals, []
    seen = set()
    to_check: list = []
    for pkg, version in entries:
        if not version or _is_prerelease(version, "npm") or (pkg, version) in seen:
            continue
        seen.add((pkg, version))
        to_check.append((pkg, version))
    prewarm_osv_cache(to_check, "npm")  # #108
    jobs = [(p, p, v, "npm") for p, v in to_check]
    results = parallel_map(_lockfile_osv_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: f"WARNING: {pkg}@{ver} in lock file has {', '.join(cves[:2])}",
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{p}@{v}" for p, v in to_check]


def _strip_jsonc(text: str) -> str:
    """Strip ``//`` line comments and ``/* */`` block comments from JSONC.

    Unlike a regex-based approach this scanner tracks whether the current
    position is inside a JSON string literal and never removes ``//``
    sequences that appear there.  This matters because bun.lock stores
    SHA-512 integrity hashes as base64 strings, and base64 uses ``/`` as a
    valid character — two consecutive slashes (``//``) appear in roughly 2%
    of 88-character SHA-512 values, corrupting the JSON when stripped.

    Newlines inside comments are preserved so that line numbers remain
    stable (aids debugging if ``json.loads`` subsequently fails).
    """
    out: list = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            out.append(ch)
            i += 1
            while i < n:
                c = text[i]
                out.append(c)
                i += 1
                if c == '\\':
                    if i < n:
                        out.append(text[i])
                        i += 1
                elif c == '"':
                    break
        elif ch == '/' and i + 1 < n:
            if text[i + 1] == '/':
                i += 2
                while i < n and text[i] != '\n':
                    i += 1
            elif text[i + 1] == '*':
                i += 2
                while i < n - 1 and not (text[i] == '*' and text[i + 1] == '/'):
                    if text[i] == '\n':
                        out.append('\n')
                    i += 1
                i += 2
            else:
                out.append(ch)
                i += 1
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def audit_bun_lock(content: str) -> tuple:
    """Return WARNING signals for CVE-bearing packages in bun.lock (Bun ≥1.2 text format).

    bun.lock is JSONC: JSON with // line comments and trailing commas. The
    ``packages`` object maps each package name to an array whose first element
    is ``"<name>@<version>"``.
    """
    stripped = _strip_jsonc(content)
    stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return [], []
    signals: list = []
    lookup_failures: list = []
    seen: set = set()
    to_check: list = []
    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        return [], []
    for entry in packages.values():
        if not isinstance(entry, list) or not entry:
            continue
        head = entry[0]
        if not isinstance(head, str) or "@" not in head:
            continue
        at = head.rfind("@")
        if at <= 0:
            continue
        pkg, version = head[:at], head[at + 1:]
        if not version or _is_prerelease(version, "npm") or (pkg, version) in seen:
            continue
        seen.add((pkg, version))
        to_check.append((pkg, version))
    prewarm_osv_cache(to_check, "npm")
    jobs = [(p, p, v, "npm") for p, v in to_check]
    results = parallel_map(_lockfile_osv_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: f"WARNING: {pkg}@{ver} in bun.lock has {', '.join(cves[:2])}",
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{p}@{v}" for p, v in to_check]


def parse_gradle_lockfile(content: str) -> list:
    """Extract ``(group, artifact, version)`` triples from a gradle.lockfile."""
    triples: list = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("empty="):
            continue
        coord, _, _configs = line.partition("=")
        coord = coord.strip()
        parts = coord.split(":")
        if len(parts) != 3:
            continue
        group, artifact, version = (p.strip() for p in parts)
        if not (group and artifact and version):
            continue
        triples.append((group, artifact, version))
    return triples


def audit_gradle_lockfile(content: str) -> tuple:
    """Check resolved coordinates in gradle.lockfile. Returns ``(signals, checked)``."""
    triples = parse_gradle_lockfile(content)
    signals: list = []
    lookup_failures: list = []
    seen: set = set()
    to_check: list = []
    for group, artifact, version in triples:
        coord = f"{group}:{artifact}"
        if (coord, version) in seen:
            continue
        seen.add((coord, version))
        to_check.append((coord, version))
    prewarm_osv_cache(to_check, "maven")
    jobs = [(coord, coord, ver, "maven") for coord, ver in to_check]
    results = parallel_map(_lockfile_osv_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda coord, ver, cves: (
            f"WARNING: {coord}@{ver} in gradle.lockfile has "
            f"{', '.join(cves[:2])} — run "
            f"`gradle dependencies --write-locks` after upgrading"
        ),
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{coord}@{v}" for coord, v in to_check]


def parse_go_vendor_modules(content: str) -> list:
    """Extract ``(module_path, version)`` tuples from a vendor/modules.txt."""
    pairs: list = []
    for raw in content.splitlines():
        if not raw.startswith("# ") or raw.startswith("## "):
            continue
        rest = raw[2:].strip()
        parts = rest.split()
        if len(parts) < 2:
            continue
        module_path, version = parts[0], parts[1]
        if not version.startswith("v"):
            continue
        if "=>" in rest:
            tail = rest.split("=>", 1)[1].strip().split()
            if len(tail) >= 2 and tail[1].startswith("v"):
                module_path, version = tail[0], tail[1]
            else:
                continue
        pairs.append((module_path, version))
    return pairs


def parse_cargo_toml(content: str) -> list:
    """Extract ``(name, version)`` pairs from a Cargo.toml manifest.

    Walks every dependency section Cargo recognises:
      [dependencies], [dev-dependencies], [build-dependencies],
      [target.'…'.dependencies] / [target.'…'.dev-dependencies] /
      [target.'…'.build-dependencies] under the ``target`` table,
      [workspace.dependencies] in workspace-root manifests (where
      version pins live for member crates that reference them via
      ``dep = { workspace = true }``), and [patch.<registry>] overrides
      that use a registry-form version pin (path/git patch forms are
      silently skipped — they have no crates.io coordinate to query).

    Each dep value is either a version string (`serde = "1.0.0"`) or an
    inline table (`tokio = { version = "1.20", features = [...] }`). Path /
    git / workspace deps are skipped because they don't resolve to a
    crates.io coordinate. (A member-crate entry of the form
    ``dep = { workspace = true }`` is correctly skipped here; the actual
    pin is read from ``[workspace.dependencies]`` in the root manifest.)
    """
    if _tomllib is None:
        return []
    try:
        data = _tomllib.loads(content)
    except Exception:
        return []
    pairs: list = []

    def _emit(section: dict) -> None:
        if not isinstance(section, dict):
            return
        for name, spec in section.items():
            if isinstance(spec, str):
                pairs.append((name, spec))
            elif isinstance(spec, dict):
                # Skip non-registry sources.
                if any(k in spec for k in ("path", "git", "workspace")):
                    continue
                ver = spec.get("version", "")
                if isinstance(ver, str) and ver:
                    pairs.append((name, ver))

    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        _emit(data.get(key, {}))
    targets = data.get("target", {})
    if isinstance(targets, dict):
        for tgt in targets.values():
            if not isinstance(tgt, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                _emit(tgt.get(key, {}))
    # Workspace-root [workspace.dependencies]. Cargo only recognises this
    # single section under [workspace] for shared deps — there is no
    # [workspace.dev-dependencies] or [workspace.build-dependencies].
    workspace = data.get("workspace", {})
    if isinstance(workspace, dict):
        _emit(workspace.get("dependencies", {}))
    # [patch.<registry>] overrides (e.g. [patch.crates-io]). Registry-form
    # overrides (those with a "version" field and no "path"/"git") pin a
    # concrete crates.io coordinate and are audited like normal deps.
    # Path/git patches have no registry coordinate; the existing _emit skip
    # logic handles them silently (same as all other path/git deps).
    for registry_patches in data.get("patch", {}).values():
        if isinstance(registry_patches, dict):
            _emit(registry_patches)
    return pairs


def rewrite_cargo_toml(content: str, updates: dict) -> str:
    """``updates: {pkg: (old_ver, new_ver)}``. Rewrite Cargo.toml deps in place.

    Handles the three Cargo.toml dependency-declaration forms:

      A) String:        ``serde = "1.0.0"``
      B) Inline-table:  ``tokio = { version = "1.0.0", features = [...] }``
      C) Table-section: ``[dependencies.serde]``  /
                        ``version = "1.0.0"``

    All three preserve the existing version-operator prefix (``^`` /
    ``~`` / ``=``) on the literal — Cargo treats ``serde = "1.0.0"`` as
    ``serde = "^1.0.0"`` by default, but if the user explicitly typed
    ``=1.0.0`` for an exact pin, that operator must survive the rewrite.

    Anchors on the package name + the literal old version, so a sibling
    crate that happens to be pinned at the same version isn't clobbered.
    The table-section pattern (C) walks the same dep-section prefixes
    parse_cargo_toml accepts (dependencies / dev-dependencies /
    build-dependencies, plus target.* and workspace.* prefixes).
    """
    for pkg, (old, new) in updates.items():
        # Pattern A: ``pkg = "[<op>]<old>"``
        pat_a = re.compile(
            r"(^[ \t]*" + re.escape(pkg) + r"\s*=\s*\")"
            r"(\^|~|=)?" + re.escape(old) + r"(\")",
            re.MULTILINE,
        )
        content = pat_a.sub(
            lambda m, new=new: m.group(1) + (m.group(2) or "") + new + m.group(3),
            content,
        )
        # Pattern B: ``pkg = { ... version = "[<op>]<old>" ... }`` — single-line
        # inline tables only (TOML inline tables can't span lines).
        pat_b = re.compile(
            r"(^[ \t]*" + re.escape(pkg) + r"\s*=\s*\{[^}]*?\bversion\s*=\s*\")"
            r"(\^|~|=)?" + re.escape(old) + r"(\")",
            re.MULTILINE,
        )
        content = pat_b.sub(
            lambda m, new=new: m.group(1) + (m.group(2) or "") + new + m.group(3),
            content,
        )
        # Pattern C: ``[<prefix.>(dependencies|dev-dependencies|build-dependencies).pkg]``
        # followed by ``version = "[<op>]<old>"`` somewhere in the section.
        # The ``[\s\S]*?\bversion\s*=`` lazy match terminates on the first
        # ``version = "..."`` after the section header — which is the version
        # field for THIS pkg, since each table-section names exactly one dep.
        pat_c = re.compile(
            r"(^\[(?:[A-Za-z0-9_.\-]+\.)*"
            r"(?:dependencies|dev-dependencies|build-dependencies)\."
            + re.escape(pkg) + r"\][\s\S]*?\bversion\s*=\s*\")"
            r"(\^|~|=)?" + re.escape(old) + r"(\")",
            re.MULTILINE,
        )
        content = pat_c.sub(
            lambda m, new=new: m.group(1) + (m.group(2) or "") + new + m.group(3),
            content,
        )
    return content


def remove_from_cargo_toml(content: str, pkg_names: list) -> str:
    """Remove dep entries for ``pkg_names`` from a Cargo.toml.

    Handles all three forms parse_cargo_toml surfaces:

      A/B) Single-line:  ``pkg = "..."``  /  ``pkg = { ... }``
      C)   Multi-line:   ``[dependencies.pkg]`` and every following
                          line up to the next ``[section]`` or EOF.

    Any other ``pkg = ...`` appearance (e.g. inside a feature array
    elsewhere) won't trigger removal because we anchor on line start.
    """
    if not pkg_names:
        return content
    pkg_set = set(pkg_names)
    lines = content.splitlines(keepends=False)
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Form A/B: single-line dep at top level of a section.
        # Guard: skip lines that are workspace-inherited entries such as
        #   serde = { workspace = true }
        # These share the same ``pkg =`` prefix but must NOT be removed —
        # the actual version pin lives in [workspace.dependencies] of the
        # workspace root, which parse_cargo_toml already skips for inherited
        # entries.  Stripping the member-crate reference would break the build.
        skip = False
        if not re.search(r"workspace\s*=\s*true", line):
            for pkg in pkg_set:
                if re.match(r"^[ \t]*" + re.escape(pkg) + r"\s*=", line):
                    skip = True
                    break
        if skip:
            i += 1
            continue
        # Form C: section header `[…dependencies.pkg]`. Skip the header
        # plus every subsequent body line until the next section.
        m = re.match(
            r"^\[(?:[A-Za-z0-9_.\-]+\.)*"
            r"(?:dependencies|dev-dependencies|build-dependencies)\."
            r"([A-Za-z0-9_\-]+)\]",
            line,
        )
        if m and m.group(1) in pkg_set:
            i += 1
            while i < len(lines) and not re.match(r"^\[", lines[i]):
                i += 1
            continue
        out.append(line)
        i += 1
    result = "\n".join(out)
    if content.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def audit_cargo_toml(file_path: str, content: str) -> tuple:
    """Returns ``(signals, checked)`` for Cargo.toml.

    Cargo's version specs (``"1.0.0"``) are caret-equivalent ranges, but
    OSV queries against the literal pin still surface CVEs reliably — we
    treat each declared version as the audit-eligible version, mirroring
    how ``audit_pypi`` handles loose pins.

    Manifest is rewritten in place via rewrite_cargo_toml /
    remove_from_cargo_toml; signal shape matches the other manifest
    audits (UPDATED:, MAJOR-UPDATE-CONFIRM:, BLOCKED:).
    """
    if _tomllib is None:
        return [
            "WARNING: cannot audit Cargo.toml — Python TOML parser not available. "
            "On Python 3.8–3.10 install the polyfill: `pip install tomli`. "
            "(Python 3.11+ includes tomllib in the standard library.)"
        ], []
    pairs = parse_cargo_toml(content)
    updates: dict = {}
    blocked_pkgs: list = []
    signals: list = []
    lookup_failures: list = []
    checked: list = []
    skip_list = _read_skip_list()
    seen: set = set()
    deduped: list = []
    for name, version in pairs:
        # Strip leading caret/tilde/= so the OSV query carries a bare version.
        bare = version.lstrip("^~=").strip()
        if not bare or (name, bare) in seen:
            continue
        seen.add((name, bare))
        # Typosquat (advisory only): warn before any registry call so the
        # signal surfaces even when the typo'd name 404s on crates.io.
        ts = check_typosquat(name, "crates")
        if ts:
            _d, _ref = ts
            signals.append(
                f"TYPOSQUAT-CONFIRM: {name}@{bare} may be a typosquat of '{_ref}' "
                f"(edit distance {_d}) — verify intentional before proceeding"
            )
            # This signal lives in the OUTER list, so _apply_policy_to_result
            # never sees it — escalate checks.typosquat=block here (review I2).
            if _tier("typosquat", "warn") == "block":
                signals[-1] = ("BLOCKED: " + name + " — typosquat suspicion "
                               "(policy checks.typosquat=block): "
                               + signals[-1].split("— ", 1)[-1])
                blocked_pkgs.append(name)
        deduped.append((name, bare))
        checked.append(f"{name}@{bare}")
    prewarm_osv_cache(deduped, "crates")

    def _audit_one(pv):
        pkg, version = pv
        return _audit_one_package(
            pkg, version,
            ecosystem="crates", file_path=file_path, skip_list=skip_list,
            do_typosquat=False, do_migration_notes=False,
        )

    results = parallel_map(_audit_one, deduped, max_workers=_manifest_max_workers())
    for r in results:
        signals.extend(r["signals"])
        if r["blocked"] is not None:
            blocked_pkgs.append(r["blocked"])
        if r["update"] is not None:
            _u_pkg, _u_old, _u_new = r["update"]
            updates[_u_pkg] = (_u_old, _u_new)
        if r["lookup_failure"] is not None:
            lookup_failures.append(r["lookup_failure"])
    _emit_lookup_failures(signals, lookup_failures)
    _finalize_audit(file_path, content, updates, blocked_pkgs, signals,
                    rewrite_cargo_toml, remove_from_cargo_toml, "crates")
    return signals, checked


def audit_cargo_lock(content: str) -> tuple:
    """Check [[package]] entries in Cargo.lock for vulnerable versions.

    Cargo.lock lists every transitive dependency. We only audit packages
    whose ``source`` is the crates.io registry — path/git/workspace deps
    don't have a registry coordinate to query OSV against. Cargo.lock is
    machine-regenerated by ``cargo update`` / ``cargo build``, so we emit
    WARNING signals only and never rewrite.
    """
    if _tomllib is None:
        return [
            "WARNING: cannot audit Cargo.lock — Python TOML parser not available. "
            "On Python 3.8–3.10 install the polyfill: `pip install tomli`."
        ], []
    try:
        data = _tomllib.loads(content)
    except Exception:
        return [], []
    signals: list = []
    lookup_failures: list = []
    seen: set = set()
    to_check: list = []
    for pkg_entry in data.get("package", []):
        name = pkg_entry.get("name", "")
        ver = pkg_entry.get("version", "")
        source = pkg_entry.get("source", "") or ""
        if not name or not ver:
            continue
        # Only audit registry deps. Cargo's source string for crates.io looks
        # like "registry+https://github.com/rust-lang/crates.io-index". Path
        # and git deps either omit "source" entirely or use "git+…" / etc.
        if "crates.io-index" not in source:
            continue
        if (name, ver) in seen:
            continue
        seen.add((name, ver))
        to_check.append((name, ver))
    prewarm_osv_cache(to_check, "crates")
    jobs = [(p, p, v, "crates") for p, v in to_check]
    results = parallel_map(_lockfile_osv_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda pkg, ver, cves: (
            f"WARNING: {pkg}@{ver} in Cargo.lock has "
            f"{', '.join(cves[:2])} — run `cargo update -p {pkg}` to refresh"
        ),
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{p}@{v}" for p, v in to_check]


def audit_go_vendor_modules(content: str) -> tuple:
    """Check vendored modules in vendor/modules.txt. Returns ``(signals, checked)``."""
    pairs = parse_go_vendor_modules(content)
    signals: list = []
    lookup_failures: list = []
    seen: set = set()
    to_check: list = []
    for module_path, version in pairs:
        if (module_path, version) in seen:
            continue
        seen.add((module_path, version))
        to_check.append((module_path, version))
    prewarm_osv_cache(to_check, "go")
    jobs = [(mp, mp, v, "go") for mp, v in to_check]
    results = parallel_map(_lockfile_osv_check_one, jobs)
    _reduce_lockfile_results(
        results, signals, lookup_failures,
        lambda mp, ver, cves: (
            f"WARNING: {mp}@{ver} in vendor/modules.txt has "
            f"{', '.join(cves[:2])} — bump go.mod and re-run `go mod vendor`"
        ),
    )
    _emit_lookup_failures(signals, lookup_failures)
    return signals, [f"{mp}@{v}" for mp, v in to_check]


# ─────────────────────── lockfile relation tagging (issue #245) ───────────────────────
# Phase 1: measure + warn only. For every lockfile audit, classify each
# checked package as `direct` (its name is DECLARED in the sibling manifest)
# or `transitive` (pulled in by the resolver). The classification feeds the
# audit log's schema-2.2 relation_summary so stats can report transitive
# coverage; nothing is blocked here (enforcement is gated by the canonical
# `transitive` check tier from #248's config, consulted at write time).
#
# Cheap best-effort by design: manifest parsing here extracts declared NAMES
# only (no version constraints, no network). On ANY failure — missing
# manifest, unparseable content, unmapped lockfile (vendor/modules.txt) —
# every package classifies as "unknown". Fail open, never crash.

# Sibling manifest candidates per lockfile basename, tried in order.
LOCKFILE_MANIFEST_CANDIDATES = {
    "package-lock.json":   ("package.json",),
    "npm-shrinkwrap.json": ("package.json",),
    "yarn.lock":           ("package.json",),
    "pnpm-lock.yaml":      ("package.json",),
    "bun.lock":            ("package.json",),
    "Pipfile.lock":        ("Pipfile",),
    "poetry.lock":         ("pyproject.toml", "Pipfile"),
    "uv.lock":             ("pyproject.toml", "Pipfile"),
    "pdm.lock":            ("pyproject.toml", "Pipfile"),
    "Gemfile.lock":        ("Gemfile",),
    "gradle.lockfile":     ("build.gradle", "build.gradle.kts"),
    "go.sum":              ("go.mod",),
    "Cargo.lock":          ("Cargo.toml",),
}

# PEP 508 requirement strings start with the project name; everything after
# the first extras-bracket / operator / space is constraint noise.
_PEP508_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_GEMFILE_GEM_RE = re.compile(r"""^\s*gem\s+(['"])([^'"]+)\1""", re.MULTILINE)
# Gradle dependency coordinates: "group:artifact[:version...]" inside quotes.
_GRADLE_COORD_RE = re.compile(r"""["']([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+)(?::[^"']*)?["']""")
_GO_REQUIRE_LINE_RE = re.compile(r"^require\s+(\S+)\s+v\S+")
_GO_BLOCK_DEP_RE = re.compile(r"^(\S+)\s+v\S+")


def _relation_norm_name(name: str, ecosystem: str) -> str:
    """Canonicalise a package name for declared-vs-checked comparison.

    PyPI names are case-insensitive with `-`/`_`/`.` equivalence (PEP 503);
    other ecosystems just fold case (npm registry names are lowercase
    already; the fold is harmless elsewhere and avoids false transitives)."""
    n = name.strip().lower()
    if ecosystem == "pypi":
        n = re.sub(r"[-_.]+", "-", n)
    return n


def _relation_pkg_name(token: str) -> str:
    """Package name from a checked/`WARNING:` ``pkg@ver`` token.

    Handles scoped npm names (``@scope/pkg@1.0.0``), Pipfile-style
    ``pkg==1.2.3`` warning tokens, Go module paths, and Maven/Gradle
    ``group:artifact@version`` coordinates."""
    if "==" in token:
        return token.split("==", 1)[0]
    if token.startswith("@"):
        return "@" + token[1:].split("@", 1)[0]
    return token.split("@", 1)[0]


def _manifest_declared_names(manifest_path: str, manifest_basename: str,
                             ecosystem: str) -> set:
    """Best-effort set of normalised DECLARED package names, or raise.

    Name extraction only — deliberately minimal so it stays cheap inside a
    hook. Any exception propagates to the caller, which fails open to
    relation "unknown"."""
    with open(manifest_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    names: set = set()
    if manifest_basename == "package.json":
        data = json.loads(content)
        for section in ("dependencies", "devDependencies",
                        "optionalDependencies", "peerDependencies"):
            block = data.get(section)
            if isinstance(block, dict):
                names.update(block.keys())
    elif manifest_basename == "Gemfile":
        names.update(m.group(2) for m in _GEMFILE_GEM_RE.finditer(content))
    elif manifest_basename == "pyproject.toml":
        if _tomllib is None:
            raise RuntimeError("no TOML parser")
        data = _tomllib.loads(content)
        project = data.get("project") or {}
        for req in project.get("dependencies") or []:
            m = _PEP508_NAME_RE.match(str(req))
            if m:
                names.add(m.group(1))
        for group in (project.get("optional-dependencies") or {}).values():
            for req in group or []:
                m = _PEP508_NAME_RE.match(str(req))
                if m:
                    names.add(m.group(1))
        poetry = (data.get("tool") or {}).get("poetry") or {}
        names.update(poetry.get("dependencies") or {})
        for group in (poetry.get("group") or {}).values():
            if isinstance(group, dict):
                names.update(group.get("dependencies") or {})
        names.discard("python")  # interpreter constraint, not a package
    elif manifest_basename == "Pipfile":
        if _tomllib is None:
            raise RuntimeError("no TOML parser")
        data = _tomllib.loads(content)
        names.update(data.get("packages") or {})
        names.update(data.get("dev-packages") or {})
    elif manifest_basename == "go.mod":
        in_block = False
        for line in content.splitlines():
            stripped = line.split("//", 1)[0].strip()
            if stripped.startswith("require ("):
                in_block = True
                continue
            if in_block:
                if stripped == ")":
                    in_block = False
                    continue
                m = _GO_BLOCK_DEP_RE.match(stripped)
                if m:
                    names.add(m.group(1))
            else:
                m = _GO_REQUIRE_LINE_RE.match(stripped)
                if m:
                    names.add(m.group(1))
    elif manifest_basename == "Cargo.toml":
        if _tomllib is None:
            raise RuntimeError("no TOML parser")
        data = _tomllib.loads(content)
        dep_tables = [data.get("dependencies"), data.get("dev-dependencies"),
                      data.get("build-dependencies"),
                      (data.get("workspace") or {}).get("dependencies")]
        for target in (data.get("target") or {}).values():
            if isinstance(target, dict):
                for section in ("dependencies", "dev-dependencies",
                                "build-dependencies"):
                    dep_tables.append(target.get(section))
        for table in dep_tables:
            if not isinstance(table, dict):
                continue
            for key, spec in table.items():
                # `alias = { package = "real-name", ... }` — the lockfile
                # records the real crate name, not the alias.
                if isinstance(spec, dict) and isinstance(spec.get("package"), str):
                    names.add(spec["package"])
                else:
                    names.add(key)
    elif manifest_basename in ("build.gradle", "build.gradle.kts"):
        names.update(m.group(1) for m in _GRADLE_COORD_RE.finditer(content))
    return {_relation_norm_name(n, ecosystem) for n in names if n}


def _classify_lockfile_relations(file_path: str, basename: str,
                                 checked: list, signals: list) -> tuple:
    """Return ``(manifest_ref, relation_summary)`` for a lockfile audit.

    ``manifest_ref`` is the absolute path of the sibling manifest used for
    classification ("" when none was found / parsed). ``relation_summary``
    matches the schema-2.2 block. Fail-open: any parse failure classifies
    everything as "unknown" rather than guessing."""
    ecosystem = LOCK_FILE_ECOSYSTEM.get(basename, "")
    manifest_ref = ""
    declared = None
    try:
        lock_dir = os.path.dirname(os.path.abspath(file_path))
        for candidate in LOCKFILE_MANIFEST_CANDIDATES.get(basename, ()):
            candidate_path = os.path.join(lock_dir, candidate)
            if os.path.isfile(candidate_path):
                manifest_ref = candidate_path
                declared = _manifest_declared_names(candidate_path, candidate,
                                                    ecosystem)
                break
    except Exception:  # noqa: BLE001 — fail open, never crash the hook
        manifest_ref = ""
        declared = None

    summary = {"direct_checked": 0, "transitive_checked": 0,
               "unknown_checked": 0, "transitive_flagged": 0,
               "transitive_flagged_pkgs": []}

    def _relation(token: str) -> str:
        if declared is None:
            return "unknown"
        name = _relation_norm_name(_relation_pkg_name(token), ecosystem)
        return "direct" if name in declared else "transitive"

    for token in checked:
        summary[f"{_relation(token)}_checked"] += 1

    # A package name resolving to MORE THAN ONE version in the tree has at least
    # one nested (transitive) copy — npm hoists one version and nests the rest.
    # A flagged copy of such a name is therefore a transitive occurrence even
    # when the name is ALSO a direct dependency (the hoisted direct copy is
    # typically the clean one, e.g. a patched nodemailer@9 hoisted over a
    # vulnerable nodemailer@7 nested under email-templates). Single-version
    # declared packages stay "direct" (a genuinely direct vulnerable dep).
    versions_per_name: dict = {}
    for token in checked:
        nm = _relation_norm_name(_relation_pkg_name(token), ecosystem)
        versions_per_name.setdefault(nm, set()).add(token)
    multi_version_names = {nm for nm, toks in versions_per_name.items() if len(toks) > 1}

    # transitive_flagged: only CVE warnings name a finding — they carry the
    # offending pkg@ver (or pkg==ver) as the second whitespace token followed by
    # " has <advisories>". Operational WARNINGs (rewrite failures, missing TOML
    # parser, audit timeouts) lack that separator and are skipped, mirroring the
    # audit log's finding discriminator (safedep.audit_log._is_cve_warning).
    for sig in signals:
        if (not isinstance(sig, str) or not sig.startswith("WARNING:")
                or " has " not in sig):
            continue
        parts = sig.split()
        if len(parts) < 2 or not ("@" in parts[1] or "==" in parts[1]):
            continue
        token = parts[1]
        nm = _relation_norm_name(_relation_pkg_name(token), ecosystem)
        is_transitive = (_relation(token) == "transitive"
                         or (declared is not None and nm in multi_version_names))
        if is_transitive:
            summary["transitive_flagged"] += 1
            if token not in summary["transitive_flagged_pkgs"]:
                summary["transitive_flagged_pkgs"].append(token)
    return manifest_ref, summary


# ─────────────────────────── timeout handling (issue #213) ───────────────────────────
# Claude Code enforces the hook timeout externally (SIGTERM, then SIGKILL).
# Without handlers, a large audit dies mid-flight: truncated/absent audit-log
# entry, no signal, and the user cannot tell "hook never ran" from "hook was
# killed". Strategy: handle SIGTERM, and self-impose a soft deadline slightly
# under the recommended 60s budget (SAFE_DEP_SOFT_DEADLINE_SECS, default 55,
# 0 disables) so we get to write a truncation marker and a WARNING before the
# external kill lands.

class _AuditTimeout(BaseException):
    # BaseException, NOT Exception: the audit pipeline (deliberately) wraps
    # every per-file and per-package step in broad `except Exception` blocks.
    # A timeout must sail past all of them and reach the __main__ handler —
    # the same reason KeyboardInterrupt subclasses BaseException.
    pass


# Set by main() once the hook payload is parsed, so a timeout entry can name
# the file that was being audited.
_CURRENT_AUDIT_FILE = ""
_CURRENT_AUDIT_TOOL = ""


def _soft_deadline_secs() -> int:
    raw = os.environ.get("SAFE_DEP_SOFT_DEADLINE_SECS", "").strip()
    if raw:
        try:
            return max(0, int(float(raw)))
        except ValueError:
            pass
    return 55


def _install_timeout_handlers() -> None:
    """Best-effort; signal handling only works in the main thread and on
    POSIX — any failure leaves the previous (kill-without-warning) behavior."""
    try:
        import signal as _signal

        def _on_timeout(signum, frame):  # noqa: ARG001
            raise _AuditTimeout(signum)

        _signal.signal(_signal.SIGTERM, _on_timeout)
        deadline = _soft_deadline_secs()
        if deadline > 0 and hasattr(_signal, "alarm"):
            _signal.signal(_signal.SIGALRM, _on_timeout)
            _signal.alarm(deadline)
    except Exception:  # noqa: BLE001
        pass


def _handle_audit_timeout(exit_fn=os._exit) -> None:
    """Emit a WARNING signal + a truncation-marked audit entry, then exit 0.

    Uses os._exit (not sys.exit): the audit fans work out over non-daemon
    ThreadPoolExecutor threads, and a normal interpreter shutdown would block
    joining them — exactly the hang the external SIGKILL then reaps, losing
    our output. Everything here is best-effort and must not raise.
    """
    deadline = _soft_deadline_secs()
    target = _CURRENT_AUDIT_FILE or "<unknown>"
    msg = (f"WARNING: dependency audit timed out (~{deadline}s hook budget) while "
           f"auditing {target} — results are INCOMPLETE and the manifest was NOT "
           f"fully audited. Re-save the file to retry, raise the hook timeout in "
           f".claude/settings.json, or split very large manifests.")
    try:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": msg,
            }
        }))
        sys.stdout.flush()
    except Exception:  # noqa: BLE001
        pass
    try:
        from safedep.audit_log import _write_json_line, build_entry
        entry = build_entry(
            file_path=target,
            ecosystem="",
            checked=[],
            signals=[msg],
            source=_audit_source(tool_name=_CURRENT_AUDIT_TOOL or None),
        )
        entry["timeout"] = True
        # WARNING: is in none of build_entry's buckets — persist the message
        # in notes so the log entry carries the human-readable cause, not
        # just the bare timeout flag.
        entry["notes"] = list(entry.get("notes") or []) + [msg]
        _write_json_line(entry)
    except Exception:  # noqa: BLE001
        pass
    exit_fn(0)


# ─────────────────────────── main ───────────────────────────

def _coverage_advisories(file_path: str, basename: str, ecosystem: str,
                         content: str, checked: list) -> list:
    """Honest-coverage NOTEs for pip requirements files (issues #228/#229).

    Scoped to ``requirements*.txt`` / ``*.in`` — the plain-pip layout where
    both gaps actually exist. Pipfile/pyproject/poetry flows carry their own
    lockfiles, which Post-Install Scan A audits for the transitive tree.

    1. Transitive-coverage NOTE (#228 minimum): with no adjacent pip lockfile,
       only the declared top-level pins were audited — say so instead of
       letting CLEAN read as full-tree clearance.
    2. Missing-hash NOTE (#229): pinned versions without ``--hash=`` lines
       mean artifact bytes are unverified at install time. Silence with
       ``SAFE_DEP_REQUIRE_HASHES=off``. Not emitted for ``.in`` files —
       hashes belong in the compiled output, not pip-tools inputs.
    """
    notes: list = []
    if ecosystem != "pypi" or not checked:
        return notes
    if not (basename.startswith("requirements")
            and (basename.endswith(".txt") or basename.endswith(".in"))):
        return notes
    manifest_dir = os.path.dirname(os.path.abspath(file_path))
    pip_locks = ("poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock")
    if not any(os.path.isfile(os.path.join(manifest_dir, lk)) for lk in pip_locks):
        notes.append(
            f"NOTE: transitive dependencies not audited — {basename} pins "
            f"top-level packages only and no lockfile was found. The audit "
            f"covers the {len(checked)} declared packages, not the resolved "
            f"install tree."
        )
    if (basename.endswith(".txt")
            and "--hash" not in content
            and _tier("hashes", "warn") != "off"):
        notes.append(
            f"NOTE: {basename} pins versions without --hash integrity pins — "
            f"artifact bytes are unverified at install time. Generate them "
            f"with: pip-compile --generate-hashes "
            f"(set SAFE_DEP_REQUIRE_HASHES=off to silence)."
        )
    return notes


def main() -> None:
    # 1. Read hook JSON from stdin
    try:
        raw = sys.stdin.buffer.read()
        if not raw.strip():
            return
        hook_json = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return

    # 2. Extract file path from hook payload
    tool_input = hook_json.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return
    file_path = tool_input.get("file_path", "")
    if not file_path or not isinstance(file_path, str):
        # A non-string file_path (number, list, object) is malformed input —
        # without this guard, os.path.basename raised OUTSIDE the audit
        # try-block: traceback on stderr + exit 1, breaking the Shape C
        # "hook always exits 0" contract.
        return
    # Tool name (Write / Edit / MultiEdit / ...). Threaded into source.tool
    # so the audit log distinguishes Write-triggered runs from Edit-triggered.
    _hook_tool = hook_json.get("tool_name", "") or ""

    # Issue #213: record what is being audited so a timeout entry can name it.
    global _CURRENT_AUDIT_FILE, _CURRENT_AUDIT_TOOL
    _CURRENT_AUDIT_FILE = file_path
    _CURRENT_AUDIT_TOOL = _hook_tool

    basename = os.path.basename(file_path)

    # 3. Dispatch: manifest or lock file?
    ecosystem = MANIFEST_ECOSYSTEM.get(basename)
    is_lock   = basename in LOCK_FILES
    # .gemspec files have project-specific names (e.g. mygem.gemspec)
    if not ecosystem and not is_lock and basename.endswith(".gemspec"):
        ecosystem = "rubygems"
    # Split-requirements files: requirements-dev.txt, requirements_test.txt,
    # plus pip-tools input files (requirements.in, requirements-dev.in, …).
    # Common pip convention; pip itself recognises any path passed via -r.
    if not ecosystem and not is_lock and basename.startswith("requirements") and (
        basename.endswith(".txt") or basename.endswith(".in")
    ):
        ecosystem = "pypi"
    # Go vendoring: vendor/modules.txt is path-qualified, not basename-qualified —
    # `modules.txt` is too generic to add to LOCK_FILES wholesale.
    is_go_vendor = (
        basename == "modules.txt"
        and os.path.basename(os.path.dirname(os.path.abspath(file_path))) == "vendor"
    )
    if is_go_vendor:
        is_lock = True
    # Issue #232: checks.transitive=off — skip lockfile audits entirely.
    if is_lock and _tier("transitive", "warn") == "off":
        return
    if not ecosystem and not is_lock:
        # Recognised-but-unaudited manifest format (issue #155): emit a GAP
        # signal + audit log entry so the user knows the audit didn't apply,
        # instead of silently no-opping. The skill description already
        # promises this — the hook now enforces it.
        if basename in UNSUPPORTED_MANIFESTS:
            eco_label, tool_hint = UNSUPPORTED_MANIFESTS[basename]
            signals = [
                f"GAP: {eco_label} not yet audited by safer-dependencies; "
                f"consider {tool_hint} manually"
            ]
            try:
                _write_audit_log(file_path, "unsupported", [], signals,
                                 tool_name=_hook_tool)
            except Exception:  # noqa: BLE001 — logging must not break the hook
                pass
            emit_signals(signals)
        return  # not a manifest — silent exit (or GAP-only exit above)

    # Honour project / user configuration: silently skip ecosystems disabled
    # via safer-dependencies.toml or SAFE_DEP_DISABLE. Resolve the ecosystem
    # from the manifest table, the lockfile→ecosystem map, or the path-aware
    # vendor/modules.txt branch (Go).
    _eco_for_disable = ecosystem or LOCK_FILE_ECOSYSTEM.get(basename, "")
    if is_go_vendor:
        _eco_for_disable = "go"
    if _eco_for_disable and _ecosystem_is_disabled(_eco_for_disable):
        return  # silently skip — user opted out

    # 4. Read the file that was just written
    if not os.path.isfile(file_path):
        # Deliberately silent: a missing manifest is a routine, expected state
        # (non-materialised write, rolled-back edit, deleted/renamed manifest).
        # Emitting here would be noisy on every rm/mv of a manifest and is
        # indistinguishable to the user from a false alarm. The genuinely
        # anomalous case — file present but unreadable — is handled below.
        # Asserted by the ghost-file case in tests/shim/test_shim.sh.
        return
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError as _read_err:
        # File exists but cannot be read — permission error or I/O failure.
        # Same rationale: emit rather than silently return.
        emit_signals([
            f"UNAUDITED: could not read {basename} ({_read_err}) — audit skipped. "
            f"Check file permissions and re-save to trigger a fresh audit."
        ])
        return

    # 5. Audit
    signals, checked = [], []
    try:
        if is_lock:
            # Lockfile auditors return (signals, checked) — issue #244: clean
            # lockfile audits must populate `checked` so they produce a CLEAN
            # summary + audit-log entry instead of exiting invisibly.
            if basename == "package-lock.json" or basename == "npm-shrinkwrap.json":
                signals, checked = audit_package_lock(content)
            elif basename == "bun.lock":
                signals, checked = audit_bun_lock(content)
            elif basename == "Pipfile.lock":
                signals, checked = audit_pipfile_lock(content)
            elif basename == "poetry.lock":
                signals, checked = audit_poetry_lock(content)
            elif basename == "uv.lock":
                signals, checked = audit_uv_lock(content)
            elif basename == "pdm.lock":
                signals, checked = audit_pdm_lock(content)
            elif basename == "Gemfile.lock":
                signals, checked = audit_gemfile_lock(content)
            elif basename == "go.sum":
                signals, checked = audit_go_sum(content)
            elif is_go_vendor:
                signals, checked = audit_go_vendor_modules(content)
            elif basename == "yarn.lock":
                signals, checked = audit_yarn_lock(content)
            elif basename == "pnpm-lock.yaml":
                signals, checked = audit_pnpm_lock(content)
            elif basename == "gradle.lockfile":
                signals, checked = audit_gradle_lockfile(content)
            elif basename == "Cargo.lock":
                signals, checked = audit_cargo_lock(content)
            elif basename == "composer.lock":
                signals, checked = audit_composer_lock(content)
        elif ecosystem == "npm":
            signals, checked = audit_npm(file_path, content)
        elif ecosystem == "pypi":
            if basename == "pyproject.toml":
                signals, checked = audit_pyproject_toml(file_path, content)
            elif basename == "setup.py":
                signals, checked = audit_setup_py(file_path, content)
            elif basename == "setup.cfg":
                signals, checked = audit_setup_cfg(file_path, content)
            else:
                signals, checked = audit_pypi(file_path, content, basename)
        elif ecosystem == "rubygems":
            if basename.endswith(".gemspec"):
                signals, checked = audit_gemspec(file_path, content)
            else:
                signals, checked = audit_rubygems(file_path, content)
        elif ecosystem == "maven":
            if basename == "libs.versions.toml":
                signals, checked = audit_libs_versions_toml(file_path, content)
            else:
                signals, checked = audit_maven(file_path, content, basename)
        elif ecosystem == "go":
            signals, checked = audit_go(file_path, content)
        elif ecosystem == "crates":
            signals, checked = audit_cargo_toml(file_path, content)
        elif ecosystem == "packagist":
            signals, checked = audit_packagist(file_path, content)
    except Exception as exc:  # noqa: BLE001
        signals = [f"WARNING: shim audit error for {basename}: {exc}"]

    # 6a. Manifest recognised but nothing to audit — tell the user why.
    #     Without this, silent exit makes the hook indistinguishable from
    #     "never ran" on unpinned pip/rubygems manifests, hiding the audit gap.
    if not signals and not checked and not is_lock and ecosystem:
        _pin_example = {
            "pypi":     "`pkg==1.2.3` in requirements.txt",
            "rubygems": "`gem 'name', '1.2.3'` in Gemfile",
            "npm":      '`"pkg": "1.2.3"` in package.json',
            "maven":    "<version>1.2.3</version>",
            "go":       "require example.com/pkg v1.2.3",
            "crates":   '`serde = "1.0.0"` in Cargo.toml',
            "packagist": '`"vendor/pkg": "1.2.3"` in composer.json',
        }.get(ecosystem, "an explicit version")
        signals = [f"NOTE: {basename} recognised as {ecosystem} manifest but no pinned "
                   f"dependencies found — audit skipped. Pin versions ({_pin_example}) "
                   f"so CVE/typosquat/staleness checks apply."]

    # 6a-bis. Regression annotation — issue #133. For every MAJOR-UPDATE-CONFIRM
    #     in `signals`, cross-reference the audit log for a prior UPDATED entry
    #     targeting the same (file, package, safe_version). If found, prepend a
    #     REGRESSION: line so the orchestrator recognises the re-introduction
    #     and restores the previously-approved version rather than treating it
    #     as a fresh major-bump decision.
    try:
        signals = _annotate_regressions(file_path, signals)
    except Exception:  # noqa: BLE001 — defensive; regression check must not break the audit
        pass

    # 6b. Write persistent audit log (clean, vulnerable, or skipped-with-NOTE).
    #     Logging the NOTE case lets post-hoc analysis distinguish "hook never
    #     ran" from "hook ran but found nothing to audit".
    if checked or signals:
        # Lockfiles have no MANIFEST_ECOSYSTEM entry — resolve via the
        # lockfile→ecosystem map so entries log "npm"/"pypi"/… instead of
        # the opaque "lock" bucket (keeps per-ecosystem stats accurate).
        _log_eco = ecosystem or LOCK_FILE_ECOSYSTEM.get(basename, "")
        if is_go_vendor and not _log_eco:
            _log_eco = "go"
        # Issue #245 phase 1: lockfile entries carry the direct/transitive
        # relation block (classified against the sibling manifest's declared
        # names). Fail-open: classification errors degrade to "unknown".
        _lock_manifest_ref, _lock_relations = "", None
        if is_lock:
            try:
                _lock_manifest_ref, _lock_relations = _classify_lockfile_relations(
                    file_path, basename, checked, signals)
            except Exception:  # noqa: BLE001 — tagging must not break the audit
                _lock_manifest_ref, _lock_relations = "", None
        _write_audit_log(file_path, _log_eco or "lock", checked, signals,
                         tool_name=_hook_tool, lockfile=is_lock,
                         manifest_ref=_lock_manifest_ref,
                         relation_summary=_lock_relations)

    # 7. If no issues found, emit CLEAN summary. The wording scopes the claim
    #    to security findings — a CLEAN package can still be runtime-
    #    incompatible with the project (issue #230).
    #    Issue #231 review: mature NOTEs are advisories — when they are the
    #    ONLY signals, they must inform the CLEAN summary rather than
    #    suppress it (same placement doctrine as the #228/#229 coverage
    #    advisories in 7b).
    _mature_notes = [s for s in signals
                     if s.startswith("NOTE:") and "mature, not flagged STALE" in s]
    if checked and _mature_notes and len(_mature_notes) == len(signals):
        signals = []
    if not signals and checked:
        pkg_list = ", ".join(checked[:8])
        overflow = f" +{len(checked) - 8} more" if len(checked) > 8 else ""
        # Issue #244: scope the lockfile CLEAN claim explicitly — this is the
        # resolved tree (transitive dependencies included), the coverage that
        # manifest-level audits cannot see.
        _scope = (f" in {basename} (resolved lockfile tree, transitive dependencies included)"
                  if is_lock else "")
        signals = [f"CLEAN: {len(checked)} packages checked{_scope} — no known vulnerabilities ({pkg_list}{overflow}) — security audit only, not a compatibility check"]
        signals.extend(_mature_notes)

    # 7b. Honest-coverage advisories (issues #228/#229) — appended after the
    #     CLEAN determination so they inform the summary rather than suppress
    #     it (same placement rationale as the large-audit NOTE below).
    try:
        signals.extend(_coverage_advisories(
            file_path, basename, ecosystem or "", content, checked))
    except Exception:  # noqa: BLE001 — advisories must not break the audit
        pass

    # 8. Retrospective delay NOTE — paired with the real-time stderr warning
    #    emitted by ``_maybe_notify_large_audit``. The agent uses this to set
    #    expectations with the user when the next audit of similar size lands.
    if _AUDIT_TOTAL_PACKAGES > _LARGE_AUDIT_THRESHOLD and signals:
        est = _estimate_audit_seconds(_AUDIT_TOTAL_PACKAGES)
        signals.insert(0,
            f"NOTE: large audit — {_AUDIT_TOTAL_PACKAGES} dependencies checked "
            f"(~{est}s of network lookups). Set SAFE_DEP_DELAY_WARN_THRESHOLD "
            f"to tune this threshold.")

    # 6c. Persistent open-CVE registry — write new MAJOR-UPDATE-CONFIRM entries
    #     and re-surface unresolved ones from prior runs.
    #
    #     MAJOR-UPDATE-CONFIRM signals require developer action (major-version
    #     bump + refactor) that the shim cannot perform automatically.  Without
    #     persistence, once the hook fires and the agent acknowledges but defers
    #     the work, the finding is lost — no subsequent hook invocation will
    #     re-surface it unless the same manifest is written again.  The registry
    #     closes this gap: HIGH+ major-bump requirements are written on first
    #     detection and re-surfaced on every subsequent audit of the same
    #     manifest until the package is patched or removed.
    #
    #     Fail-open: any registry I/O error is swallowed; the registry is a
    #     best-effort enhancement, not a hard gate.
    try:
        _update_open_cve_registry(file_path, signals)
        open_cve_signals = _surface_open_cves(file_path, content, signals)
        if open_cve_signals:
            signals = open_cve_signals + signals
    except Exception:  # noqa: BLE001 — registry must not break the audit
        pass

    # Surface config-file problems once per audit (issue #232): values that
    # failed validation resolved to defaults — the user should know.
    try:
        if _policy_load_warnings is not None:
            _cfg_warnings = _policy_load_warnings()
            if _cfg_warnings and signals:
                signals.extend(_cfg_warnings)
    except Exception:  # noqa: BLE001
        pass

    emit_signals(signals)


# ─────────────────────────── open-CVE registry ───────────────────────────────
#
# A JSONL file at ~/.claude/safer-dependencies-open-cves.jsonl that tracks
# MAJOR-UPDATE-CONFIRM findings that require developer action.  Each line is a
# JSON object with the fields below.  The registry is append-only; resolved
# entries are filtered out at read time by checking whether the current audit
# still surfaces the same finding.
#
# Schema per entry:
#   manifest  — absolute path to the manifest file
#   pkg       — package name (as it appears in the signal)
#   ecosystem — "npm", "crates", "pypi", etc.
#   cves      — list of CVE/GHSA IDs (up to 2)
#   safe_ver  — safe version that requires the major bump
#   cur_ver   — current (vulnerable) version
#   ts        — ISO-8601 UTC timestamp of first detection


# SAFE_DEP_OPEN_CVE_REGISTRY overrides the registry path (mirrors
# SAFE_DEP_AUDIT_LOG) so test suites and sandboxes never write
# MAJOR-UPDATE-CONFIRM tracking entries into the developer's real
# ~/.claude registry.
_OPEN_CVE_REGISTRY_PATH = os.environ.get("SAFE_DEP_OPEN_CVE_REGISTRY") or os.path.join(
    os.environ.get("HOME", os.path.expanduser("~")),
    ".claude",
    "safer-dependencies-open-cves.jsonl",
)

# Pattern to extract fields from a MAJOR-UPDATE-CONFIRM signal line.
# Matches: "MAJOR-UPDATE-CONFIRM: {pkg} {cur_ver} has {cves} — safe version requires major bump to {safe_ver}"
_MAJOR_UPDATE_RE = re.compile(
    r"^MAJOR-UPDATE-CONFIRM:\s+"
    r"(?P<pkg>\S+)\s+"
    r"(?P<cur_ver>\S+)\s+"
    r"has\s+(?P<cves>[^——]+?)"
    r"\s*[——].*?major bump to\s+(?P<safe_ver>\S+)",
    re.DOTALL,
)


def _parse_major_update_signal(signal: str):
    """Extract (pkg, cur_ver, cves_list, safe_ver) from a MAJOR-UPDATE-CONFIRM line.

    Returns None if the signal does not match the expected format.
    """
    m = _MAJOR_UPDATE_RE.match(signal)
    if not m:
        return None
    cves_raw = m.group("cves").strip()
    # CVE IDs are comma-separated (e.g. "GHSA-abc, GHSA-xyz" or "CVE-2024-123")
    cves = [c.strip() for c in cves_raw.split(",") if c.strip()]
    return m.group("pkg"), m.group("cur_ver"), cves, m.group("safe_ver")


def _read_open_cve_registry():
    """Return all entries from the open-CVE registry as a list of dicts."""
    try:
        with open(_OPEN_CVE_REGISTRY_PATH, "r", encoding="utf-8") as fh:
            return [json.loads(ln) for ln in fh if ln.strip()]
    except FileNotFoundError:
        return []
    except Exception:
        return []


def _append_open_cve_entry(entry: dict) -> None:
    """Append a single entry to the registry (creates the file if absent)."""
    try:
        os.makedirs(os.path.dirname(_OPEN_CVE_REGISTRY_PATH), exist_ok=True)
        with open(_OPEN_CVE_REGISTRY_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _update_open_cve_registry(file_path: str, signals: list) -> None:
    """Write new MAJOR-UPDATE-CONFIRM entries from ``signals`` to the registry.

    Skips entries that are already in the registry for the same (manifest, pkg)
    pair to avoid duplicate accumulation across repeated hook invocations.
    """
    existing = _read_open_cve_registry()
    existing_keys = {(e["manifest"], e["pkg"]) for e in existing}
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = os.path.abspath(file_path)
    # Also infer ecosystem from the manifest basename so callers don't have to
    # pass it in (the signals don't carry it, and file_path is available here).
    _eco = MANIFEST_ECOSYSTEM.get(os.path.basename(file_path), "unknown")
    for sig in signals:
        parsed = _parse_major_update_signal(sig)
        if not parsed:
            continue
        pkg, cur_ver, cves, safe_ver = parsed
        if (manifest, pkg) in existing_keys:
            continue  # already tracked
        _append_open_cve_entry({
            "manifest": manifest,
            "pkg": pkg,
            "ecosystem": _eco,
            "cves": cves,
            "safe_ver": safe_ver,
            "cur_ver": cur_ver,
            "ts": ts,
        })
        existing_keys.add((manifest, pkg))


# Per-ecosystem manifest parsers, keyed by basename. Each returns a list whose
# tuples carry (name, version, ...). The version captured here is the same spec
# string the MAJOR-UPDATE-CONFIRM signal embeds (both come from these parsers),
# so registry cur_ver and a fresh parse are directly string-comparable.
_MANIFEST_VERSION_PARSERS = {
    "package.json":       parse_package_json,
    "requirements.txt":   parse_requirements_txt,
    "Pipfile":            parse_pipfile,
    "pyproject.toml":     parse_pyproject_toml,
    "setup.py":           parse_setup_py,
    "setup.cfg":          parse_setup_cfg,
    "Gemfile":            parse_gemfile,
    "pom.xml":            parse_pom_xml,
    "build.gradle":       parse_build_gradle,
    "build.gradle.kts":   parse_build_gradle,
    "libs.versions.toml": parse_libs_versions_toml,
    "go.mod":             parse_go_mod,
    "Cargo.toml":         parse_cargo_toml,
}


def _current_manifest_versions(file_path: str, content: str) -> dict:
    """Return {package: version} currently declared in the manifest.

    Returns None when there is no parser for this manifest type. Note that the
    per-ecosystem parsers swallow errors and return [] on malformed input, so
    an empty dict is ambiguous (genuinely empty vs. failed parse); callers must
    treat a falsy result as "no evidence" rather than "package absent".
    """
    parser = _MANIFEST_VERSION_PARSERS.get(os.path.basename(file_path))
    if parser is None:
        return None
    try:
        out: dict = {}
        for tup in parser(content):
            if isinstance(tup, (list, tuple)) and len(tup) >= 2:
                out[tup[0]] = tup[1]
        if not out and os.path.basename(file_path) == "package.json":
            # parse_package_json swallows JSONDecodeError into [] — but for
            # the open-CVE surface logic, "valid JSON with no pinned deps"
            # (genuinely empty) and "invalid JSON" (transient glitch) need
            # opposite handling. Re-check validity so the caller can tell
            # them apart: invalid → None (parse failure).
            try:
                json.loads(content)
            except (json.JSONDecodeError, ValueError):
                return None
        return out
    except Exception:
        return None


def _prune_open_cve_registry(resolved_keys: set) -> None:
    """Rewrite the registry, dropping entries whose (manifest, pkg) resolved.

    Fail-open: any I/O error leaves the registry untouched.
    """
    if not resolved_keys:
        return
    try:
        entries = _read_open_cve_registry()
        kept = [e for e in entries
                if (e.get("manifest"), e.get("pkg")) not in resolved_keys]
        if len(kept) == len(entries):
            return
        tmp = _OPEN_CVE_REGISTRY_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for e in kept:
                fh.write(json.dumps(e) + "\n")
        os.replace(tmp, _OPEN_CVE_REGISTRY_PATH)
    except Exception:
        pass


def _surface_open_cves(file_path: str, content: str, current_signals: list) -> list:
    """Return OPEN-CVE: re-surface signals for still-unresolved prior entries.

    An entry re-surfaces only when the package is still declared in the
    manifest at the same vulnerable version that was recorded. Resolution is
    detected directly from the manifest, matching the documented contract
    ("persist until the package is upgraded or removed"):

      * package removed from the manifest  → resolved → pruned, not surfaced
      * version changed (upgraded/patched)  → resolved → pruned, not surfaced
      * still pinned at the vulnerable spec → unresolved → surfaced

    A still-unresolved entry is suppressed (but kept) when the current audit
    already emitted a MAJOR-UPDATE-CONFIRM for it — the agent is being told in
    this same turn, so OPEN-CVE would be a duplicate. The re-surface therefore
    earns its keep precisely when the manifest is re-audited but the live audit
    did NOT re-flag the package (e.g. a network-degraded run), which is exactly
    the gap a stateless signal leaves open.

    Returns a (possibly empty) list of OPEN-CVE: signal strings to prepend
    before the current audit's signals.
    """
    manifest = os.path.abspath(file_path)
    entries = _read_open_cve_registry()
    if not entries:
        return []
    current_versions = _current_manifest_versions(file_path, content)
    # Collect (pkg, cur_ver) pairs already covered by current signals so we
    # don't double-report them in the same turn.
    current_majors = set()
    for sig in current_signals:
        parsed = _parse_major_update_signal(sig)
        if parsed:
            _pkg, _cur, _, _ = parsed
            current_majors.add((_pkg, _cur))

    surface: list = []
    resolved_keys: set = set()
    for entry in entries:
        if entry.get("manifest") != manifest:
            continue
        pkg = entry.get("pkg", "")
        cur_ver = entry.get("cur_ver", "")
        # Prune only on POSITIVE evidence of resolution: a non-empty parse that
        # either omits the package (removed) or pins a different version
        # (upgraded/patched). An empty or unparseable manifest yields no such
        # evidence (parsers swallow errors and return []), so we must NOT prune
        # there — a transient parse glitch must never silently drop a finding.
        if current_versions:
            declared = current_versions.get(pkg)
            if declared is None or declared != cur_ver:
                resolved_keys.add((manifest, pkg))
                continue
            # declared == cur_ver: still pinned at the vulnerable spec —
            # fall through to surface.
        elif current_versions is not None:
            # Parsed-but-empty manifest: no positive evidence the vulnerable
            # pin is STILL declared (the package was very likely removed).
            # Keep the entry (conservatism: a parser limitation must not drop
            # a finding) but do NOT surface: an OPEN-CVE "has not been
            # applied — address this" directive for a removed package is a
            # false instruction that recurs on every future write.
            continue
        # current_versions is None: genuine parse failure / no parser —
        # fail-safe to the historical behavior and re-surface, so a
        # transient glitch never silently drops a live finding.
        if (pkg, cur_ver) in current_majors:
            continue  # still vulnerable, but already surfaced in this turn
        cves_str = ", ".join(entry.get("cves", []))
        safe_ver = entry.get("safe_ver", "")
        first_seen = entry.get("ts", "")[:10]  # date portion only
        surface.append(
            f"OPEN-CVE: {pkg}@{cur_ver} was flagged on {first_seen} for "
            f"{cves_str} — a major bump to {safe_ver} is required but has "
            f"not been applied. Address this before closing out the "
            f"dependency update task."
        )
    _prune_open_cve_registry(resolved_keys)
    return surface


if __name__ == "__main__":
    _install_timeout_handlers()
    try:
        main()
        # Cancel the soft-deadline alarm the moment main() returns: a large
        # audit finishing just under the deadline must not have the pending
        # SIGALRM land during teardown (stdout flush, worker-thread join) —
        # outside this try it would be an uncaught BaseException: traceback
        # + non-zero exit, breaking the Shape C contract.
        try:
            import signal as _sig
            _sig.alarm(0)
        except Exception:  # noqa: BLE001
            pass
    except _AuditTimeout:
        _handle_audit_timeout()
