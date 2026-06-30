"""GitHub metadata helpers shared by the shim and the github_repo_age.py CLI.

``created_at_from_repo_data`` is a pure helper used by the standalone CLI
script: given a parsed GitHub ``/repos/{owner}/{repo}`` response, return the
``created_at`` ISO string or None. The shim's ``github_repo_age_days`` uses
the same helper internally after the HTTP fetch, so the two callers cannot
drift on how the ``created_at`` field is read.

``extract_repo_from_registry`` / ``github_repo_for_package`` / ``github_repo_age_days``
are the shim's higher-level entry points — the standalone CLI doesn't need
these today, but they live here so all GitHub concerns are in one module.
"""
import os
import re
from datetime import datetime, timezone

from safedep.http import _http_get, _parse_dt


def _github_auth_headers() -> "dict | None":
    """Return GitHub API request headers if a token is available, else None.

    Reads ``GITHUB_TOKEN`` first (standard CI / Actions convention), falls
    back to ``GH_TOKEN`` (gh CLI convention). Returning None means the
    caller makes an unauthenticated request — which hits GitHub's 60/hr
    per-IP rate limit. With a token, the limit is 5000/hr per token.

    Using a token is strictly additive: if neither env var is set, this
    function returns None and ``_http_get`` behaves identically to the
    unauthenticated path. There is no code path where setting a token
    breaks a previously-working case.

    No scope is required for public repo metadata reads; any token
    (even a fine-grained PAT with zero repo permissions) will work.
    """
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        return None
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def created_at_from_repo_data(data) -> "str | None":
    """Return ``created_at`` from a GitHub repo API response dict, or None.

    Raises AttributeError when ``data`` is a non-mapping (e.g. a JSON array) —
    mirrors the standalone ``github_repo_age.py``'s historical behaviour,
    which is documented by its test suite (JSON array input → ``ERROR``).
    """
    return (data or {}).get("created_at")


def extract_repo_from_registry(registry_data, ecosystem: str) -> "str | None":
    """Extract an 'owner/name' GitHub path from npm/pypi/rubygems registry metadata."""
    candidates = []
    if ecosystem == "npm":
        repo = (registry_data or {}).get("repository")
        if isinstance(repo, dict):
            candidates.append(repo.get("url", ""))
        elif isinstance(repo, str):
            candidates.append(repo)
        candidates.append((registry_data or {}).get("homepage", ""))
    elif ecosystem == "pypi":
        info = (registry_data or {}).get("info") or {}
        urls = info.get("project_urls") or {}
        candidates.extend(urls.values())
        candidates.append(info.get("home_page", ""))
    elif ecosystem == "rubygems":
        candidates.append((registry_data or {}).get("source_code_uri", ""))
        candidates.append((registry_data or {}).get("homepage_uri", ""))
    # maven rarely exposes a GitHub URL via the Solr endpoint — skip
    for c in candidates:
        if not isinstance(c, str) or "github.com" not in c:
            continue
        m = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s#?.]+)", c)
        if m:
            return f"{m.group(1)}/{m.group(2)}"
    return None


def github_repo_age_days(repo_path: str) -> "int | None":
    """Query GitHub API for a repo's created_at, return age in days or None.

    Uses ``GITHUB_TOKEN`` / ``GH_TOKEN`` for authentication when set, which
    raises the rate limit from 60/hr to 5000/hr per token. Unauthenticated
    requests continue to work — the call degrades gracefully to None on
    rate-limit (treated the same as any other GitHub API failure).
    """
    if not repo_path or "/" not in repo_path:
        return None
    data = _http_get(
        f"https://api.github.com/repos/{repo_path}",
        timeout=5,
        headers=_github_auth_headers(),
    )
    if not data:
        return None
    ts = created_at_from_repo_data(data)
    if not ts:
        return None
    try:
        return (datetime.now(timezone.utc) - _parse_dt(ts)).days
    except Exception:
        return None


def github_repo_for_package(pkg: str, ecosystem: str) -> "str | None":
    """Fetch registry metadata once and extract the owner/name GitHub path."""
    if ecosystem == "npm":
        encoded = pkg.replace("@", "%40").replace("/", "%2F")
        data = _http_get(f"https://registry.npmjs.org/{encoded}")
    elif ecosystem == "pypi":
        data = _http_get(f"https://pypi.org/pypi/{pkg}/json")
    elif ecosystem == "rubygems":
        data = _http_get(f"https://rubygems.org/api/v1/gems/{pkg}.json")
    else:
        return None
    return extract_repo_from_registry(data, ecosystem)
