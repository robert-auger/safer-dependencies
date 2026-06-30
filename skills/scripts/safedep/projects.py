"""Derive a 'project' identity from an audit-log ``file`` path, and aggregate
per-project statistics.

The audit log records only a ``file`` path (e.g. ``/Users/x/code/app/package.json``)
or, for Pre-Install Bash denials, a ``bash:<command>`` pseudo-path. There is no
explicit project field, and historical paths frequently no longer exist on disk,
so attribution must be done purely from the path string — no ``git``/filesystem
lookups.

Grouping rules (validated against ~10k real audit-log entries):

  * Non-attributable: anything that is not an absolute path (``bash:…`` pseudo-paths,
    empty/relative names) returns ``None`` — counted separately, never invented as a project.
    Pre-Install Bash entries that include a ``cwd`` field are attributed via that field
    instead of being counted as non-attributable.
  * Repo: ``<home>/<workspace>/<repo>/…`` collapses to ``<repo>`` (so a repo's
    ``tests/``, ``fixtures/``, and ``.claude/worktrees/agent-*/`` copies all roll up
    to the one repo rather than fragmenting into dozens of leaf dirs).
  * Self-test bucket: the test-suite's ephemeral macOS temp dirs
    (``/var/folders/…``, ``/private/var/folders/…``, ``…/pytest-of-…``) collapse into
    ONE tagged bucket. They have random suffixes, so showing them individually is noise,
    not information — but the bucket and its full stats are shown and counted (never hidden).
  * Scaffold: sub-apps under ``/tmp`` / ``/private/tmp`` (monorepos, generated test
    projects) stay split — each app is its own mini-project (``monorepo/order-service``).
  * Other: any other absolute layout falls back to its leading path segments.
  * Windows paths (``C:\\…`` or ``C:/…``) are normalized to POSIX form (``/c/…``)
    before matching, so Windows users get the same attribution as Unix users.

``kind`` is one of: ``repo`` | ``scaffold`` | ``self-test`` | ``other`` — used to
classify/group, never to exclude.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

# Single tagged bucket for the test suite's ephemeral temp dirs.
SELF_TEST_LABEL = "·self-tests (temp dirs)"

# Home-relative directories that hold checked-out repos. A manifest under any of
# these collapses to its top-level repo name.
WORKSPACE_DIRS = frozenset({"code", "projects", "dev", "src", "repos", "work", "git"})


def _to_posix(path: str) -> str:
    """Normalize a Windows or mixed-separator path to POSIX form.

    ``C:\\Users\\x\\code\\app`` → ``/c/Users/x/code/app``
    ``C:/Users/x/code/app``     → ``/c/Users/x/code/app``
    ``/home/x/app``             → ``/home/x/app`` (unchanged)

    Only the drive letter is lowercased; the rest of the path is left
    as-is so directory names with unusual casing still match _HOME_RE.
    """
    path = path.replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/", path)
    if m:
        path = "/" + m.group(1).lower() + "/" + path[3:]
    return path


# Normalize _HOME so Windows paths (C:\Users\x) become /c/Users/x and the
# module-level regexes compiled from it work on both platforms.
_HOME = _to_posix(os.path.expanduser("~"))

_WORKTREE_RE = re.compile(r"^(.*?)/\.claude/worktrees/agent-[^/]+/")
_SELF_TEST_RE = re.compile(r"(?:^|/)(?:private/)?var/folders/")
_HOME_RE = re.compile(re.escape(_HOME) + r"/([^/]+)/([^/]+)")
_TMP_APP_RE = re.compile(r"^/(?:private/)?tmp/([^/]+)/(?:[^/]+/)?([^/]+)/[^/]+$")
_TMP_ONE_RE = re.compile(r"^/(?:private/)?tmp/([^/]+)/[^/]+$")
_TMP_ROOT_RE = re.compile(r"^/(?:private/)?tmp/([^/]+)")


def collapse_worktree(path: str) -> str:
    """Strip a ``.claude/worktrees/agent-XXX/...`` suffix back to the repo root."""
    m = _WORKTREE_RE.search(path + "/")
    return m.group(1) if m else path


def project_key(path: Optional[str]) -> Optional[Tuple[str, str]]:
    """Return ``(kind, label)`` for a log ``file`` path, or ``None`` if the entry
    cannot be attributed to a project (e.g. a ``bash:<command>`` Pre-Install denial).

    Windows paths (``C:\\…`` / ``C:/…``) are normalized to POSIX form before matching
    so they receive the same attribution as Unix paths.
    """
    if not isinstance(path, str):
        return None
    path = _to_posix(path)
    if not path.startswith("/"):
        return None

    path = collapse_worktree(path)

    if _SELF_TEST_RE.search(path) or "/pytest-of-" in path:
        return ("self-test", SELF_TEST_LABEL)

    m = _HOME_RE.match(path)
    if m and m.group(1) in WORKSPACE_DIRS:
        return ("repo", m.group(2))

    m = _TMP_APP_RE.match(path)
    if m:
        return ("scaffold", f"{m.group(1)}/{m.group(2)}")
    m = _TMP_ONE_RE.match(path)
    if m:
        return ("scaffold", m.group(1))
    m = _TMP_ROOT_RE.match(path)
    if m:
        return ("scaffold", m.group(1))

    parts = [p for p in path.split("/") if p]
    return ("other", "/".join(parts[:2]) if parts else path)


def _has_cve(text: str) -> bool:
    """True only when the finding cites a real advisory IDENTIFIER (``CVE-…`` or
    ``GHSA-…``), not merely the bare words 'CVE'/'GHSA' in prose (e.g. 'no CVE found')."""
    up = text.upper()
    return "CVE-" in up or "GHSA-" in up


_ROLLUP_KEYS = ("audits", "findings", "cves", "updated",
                "abandoned", "typosquat", "stale", "pkgs_checked")


def _rollup(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    r = {k: sum(x[k] for x in rows) for k in _ROLLUP_KEYS}
    r["count"] = len(rows)
    return r


def aggregate_projects(logs: List[Dict[str, Any]], top_n: int = 12) -> Dict[str, Any]:
    """Aggregate audit-log entries into per-project statistics.

    Returns a dict with:
      * ``projects_top``    — top ``top_n`` projects (audits desc), each with rich stats
      * ``more_rollup``     — combined stats for the projects beyond ``top_n``
      * ``grand_totals``    — totals across ALL attributable projects
      * ``distinct_projects`` / ``non_attributable`` — coverage accounting
      * ``top_n``           — echo of the requested cap
    """
    agg: Dict[str, Dict[str, Any]] = {}
    non_attributable = 0

    for entry in logs:
        key = project_key(entry.get("file"))
        if key is None:
            # Pre-Install Bash entries use ``bash:<command>`` as their file
            # path. Fall back to the ``cwd`` field (logged since schema 2.1)
            # so these entries are attributed to the project they ran in.
            key = project_key(entry.get("cwd"))
        if key is None:
            non_attributable += 1
            continue
        kind, label = key
        a = agg.get(label)
        if a is None:
            a = {
                "label": label, "kind": kind, "audits": 0, "findings": 0,
                "cves": 0, "updated": 0, "abandoned": 0, "typosquat": 0,
                "stale": 0, "pkgs_checked": 0, "ecosystems": {},
                "days": set(), "last": None,
            }
            agg[label] = a

        a["audits"] += 1
        a["pkgs_checked"] += len(entry.get("checked") or [])

        findings = entry.get("signals") or entry.get("findings") or []
        if findings:
            a["findings"] += 1
        for f in findings:
            s = str(f)
            if _has_cve(s):
                a["cves"] += 1
            if "UPDATED:" in s.upper():
                a["updated"] += 1

        a["abandoned"] += len(entry.get("abandoned") or [])
        a["typosquat"] += len(entry.get("typosquat") or [])
        a["stale"] += len(entry.get("stale") or [])

        eco = entry.get("ecosystem")
        if eco:
            a["ecosystems"][eco] = a["ecosystems"].get(eco, 0) + 1

        ts = entry.get("ts")
        if ts:
            a["days"].add(ts[:10])
            if a["last"] is None or ts > a["last"]:
                a["last"] = ts

    projects: List[Dict[str, Any]] = []
    for a in agg.values():
        # Annotate the true type (ecosystem name -> count). Without it `ecos` is
        # Any, and `dict(sorted(ecos.items(), key=lambda kv: -kv[1]))` lets mypy
        # resolve dict() to the typeshed `Iterable[list[bytes]]` overload, wrongly
        # inferring `kv[1]` as bytes (mypy 1.14.1).
        ecos: Dict[str, int] = a["ecosystems"]
        top_eco = max(ecos.items(), key=lambda kv: kv[1])[0] if ecos else None
        projects.append({
            "label": a["label"], "kind": a["kind"], "audits": a["audits"],
            "findings": a["findings"], "cves": a["cves"], "updated": a["updated"],
            "abandoned": a["abandoned"], "typosquat": a["typosquat"], "stale": a["stale"],
            "pkgs_checked": a["pkgs_checked"],
            "ecosystems": dict(sorted(ecos.items(), key=lambda kv: -kv[1])),
            "top_ecosystem": top_eco,
            "days_active": len(a["days"]),
            "last_active": (a["last"] or "")[:10] or None,
        })

    # audits desc, then label asc for deterministic ordering
    projects.sort(key=lambda p: (-p["audits"], p["label"]))

    top = projects[:top_n]
    rest = projects[top_n:]
    grand = _rollup(projects)
    grand["projects"] = len(projects)

    return {
        "projects_top": top,
        "more_rollup": _rollup(rest),
        "grand_totals": grand,
        "distinct_projects": len(projects),
        "non_attributable": non_attributable,
        "top_n": top_n,
    }
