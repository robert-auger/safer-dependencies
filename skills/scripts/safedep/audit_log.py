"""Canonical audit-log writer shared by the shim and Normal-mode callers.

Every entry carries a ``source`` block that identifies which component,
script, hook, and tool produced it — so post-hoc analysis (``jq``, the
troubleshooting playbook, CI dashboards) can distinguish a PostToolUse
manifest rewrite from a PreToolUse ``npm install`` audit from a manual
Normal-mode audit without inspecting the entry's other fields.

Schema v2.0 (one JSONL line per check run):

    {
      "ts": "2026-04-19T12:34:56Z",   # ISO 8601 UTC, second precision
      "schema": "2.0",
      "source": {
        "component": "shim.posttooluse" | "shim.install_error"
                   | "bash.pretooluse" | "bash.posttooluse"
                   | "agent.pretooluse" | "agent.posttooluse"
                   | "manual.skill",
        "script":    "skills/safer-dependencies-shim.sh"  # or equivalent relpath
                   | "skills/scripts/pretooluse_bash_audit.py"
                   | "skills/scripts/audit_log_append.py",
        "hook":      "PostToolUse" | "PreToolUse" | null,   # null for manual
        "tool":      "Write" | "Edit" | "Bash" | null,      # null for manual
        "mode":      "intercept" | "manual" | "install_error",
        "session_id": "<claude session id>"   # optional, present when
                                               # $CLAUDE_SESSION_ID is set
      },

      # Regular audit entries (shim.posttooluse, bash.pretooluse, manual.skill):
      "file":      "/abs/path/to/manifest",
      "ecosystem": "npm" | "pypi" | "rubygems" | "maven" | "go",
      "checked":   ["pkg@1.2.3", ...],
      "findings":  [<every signal that names a finding>],
      "abandoned": [<BLOCKED: ... — abandoned: ...>],
      "stale":     [<STALE: ...>],
      "typosquat": [<TYPOSQUAT-CONFIRM: ...>],
      "unknown":   [<UNKNOWN: ...>],
      "signatures":[<SIGNATURE: ...>],
      "notes":     [<NOTE: ...>],
      "clean":     [<pkg@ver from checked that produced no finding>],
      "mode":      "dry_run"   # present when dry_run=True

      # Install-error entries (shim.install_error):
      "install_error": "<error message>",
      "shim_dir":      "<resolved shim directory>",
      "scripts_dir":   "<expected scripts dir that was missing>"

      # Fail-open diagnostic entries (any bash hook with mode == "fail_open"):
      "fail_open": {
        "reason": "python_missing" | "helper_missing" | "shim_missing" | "<other>",
        "detail": "<optional human-readable context>"
      }

      # Lockfile entries only (schema 2.2, issue #245 — additive; readers of
      # older entries and non-lockfile entries are unaffected):
      "lockfile": true,
      "manifest_ref": "/abs/path/to/sibling/manifest" | "",
      # policy block is sourced from the CANONICAL config (#248): the single
      # effective tier for the `transitive` check (off | warn | block).
      "policy": {"transitive_tier": "off" | "warn" | "block"},
      "relation_summary": {
        "direct_checked": N,        # checked pkgs declared in the manifest
        "transitive_checked": N,    # checked pkgs NOT declared (pulled in)
        "unknown_checked": N,       # manifest missing/unparseable — fail open
        "transitive_flagged": N,    # WARNING signals on transitive pkgs
        "transitive_flagged_pkgs": ["pkg@ver", ...]  # ≤ the flagged set;
                                    # powers the stats "top flagged" list
      }
    }

Query cookbook (jq):

    # Which component fired the most times?
    jq -r '.source.component' audit.log | sort | uniq -c | sort -rn

    # Every manual-audit finding:
    jq -c 'select(.source.component == "manual.skill") | .findings[]?' audit.log

    # Any install-errors in the last 24h?
    jq -c 'select(.source.component == "shim.install_error")' audit.log

Path: ``$SAFE_DEP_AUDIT_LOG`` if set (exact path, no date suffix), else
``~/.claude/safer-dependencies-audit-YYYY-MM.log`` for the current UTC month.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional


SCHEMA_VERSION = "2.2"

# Known component tags. Kept as a constant (not an enum) so callers outside
# the package can validate against this tuple without importing enum machinery.
COMPONENT_TAGS = (
    "shim.posttooluse",
    "shim.install_error",
    "bash.pretooluse",
    "bash.posttooluse",
    "agent.pretooluse",
    "agent.posttooluse",
    "manual.skill",
)

# Paths searched in order by read_configured_model(). Module-level so tests
# can monkeypatch without touching os.path logic.
_SETTINGS_SEARCH_PATHS = [
    os.path.join(".claude", "settings.json"),
    os.path.join(os.path.expanduser("~"), ".claude", "settings.json"),
]


def read_configured_model() -> Optional[str]:
    """Return the Claude Code model configured for this session, or None.

    Resolution order:
    1. $SAFE_DEP_MODEL env var (explicit override)
    2. .claude/settings.json  (project-level)
    3. ~/.claude/settings.json (global)

    Silent on every failure — audit logging must never break the caller.
    """
    env_model = os.environ.get("SAFE_DEP_MODEL")
    if env_model:
        return env_model
    for path in _SETTINGS_SEARCH_PATHS:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            model = data.get("model")
            if model:
                return str(model)
        except Exception:
            pass
    return None


_FINDING_PREFIXES = (
    "UPDATED:",
    "MAJOR-UPDATE:",
    "MAJOR-UPDATE-CONFIRM:",
    "BLOCKED:",
    "STALE:",
    "TYPOSQUAT-CONFIRM:",
    "UNKNOWN:",
    "SIGNATURE:",
    # GAP: emitted for manifests of recognised-but-unaudited ecosystems
    # (composer.json, mix.exs, pubspec.yaml, …) so the audit log surfaces
    # the skipped coverage instead of silently no-opping (issue #155).
    "GAP:",
    # Resolved-environment findings from the Post-Install Scan C
    # (postinstall_resolved_audit.py, issue #228). Format keeps pkg@version
    # as the second whitespace token so _pkg_name(f.split()[1]) holds.
    "TRANSITIVE-CVE:",
    "RESOLVED-CVE:",
    # Cooloff (release-age) gate findings — issue #232. Token 2 is pkg@ver.
    "COOLOFF-CONFIRM:",
    "COOLOFF:",
    # Policy-tier demotions (issue #232): abandoned→warn, cve→warn.
    "ABANDONED-CONFIRM:",
    "CVE-CONFIRM:",
)


def _is_cve_warning(signal: str) -> bool:
    """True for a lockfile/manifest CVE warning that names a finding.

    The shim emits CVE hits on resolved lockfile entries as
    ``WARNING: <pkg@ver> ... has <advisory, ...>`` (e.g.
    ``WARNING: nodemailer@7.0.13 in lock file has GHSA-…``). These name a real
    finding — the offending ``pkg@ver`` / ``pkg==ver`` is the second whitespace
    token — so they belong in ``findings`` (and must drop out of ``clean``),
    not be silently treated as clean. Operational WARNINGs (rewrite failures,
    missing-TOML-parser, audit timeouts, hash mismatch) never contain the
    ``" has "`` advisory-list separator, so they remain non-findings.
    """
    if not signal.startswith("WARNING:") or " has " not in signal:
        return False
    parts = signal.split()
    return len(parts) >= 2 and ("@" in parts[1] or "==" in parts[1])


def _pkg_name(token: str) -> str:
    """Package name from a ``pkg`` or ``pkg@version`` token.

    Scoped npm names start with ``@`` (``@scope/pkg`` / ``@scope/pkg@1.0.0``),
    so a naive ``split("@")[0]`` maps EVERY scoped name to ``""`` — one scoped
    finding then knocked every other scoped package out of the clean list.
    """
    if token.startswith("@"):
        return "@" + token[1:].split("@", 1)[0]
    return token.split("@", 1)[0]


def default_log_path(dt: Optional[datetime] = None) -> str:
    """Return the canonical audit log path for the current calendar month.

    ``$SAFE_DEP_AUDIT_LOG`` overrides (exact path, no date suffix injected).
    Otherwise returns ``~/.claude/safer-dependencies-audit-YYYY-MM.log`` for
    the UTC month of ``dt`` (defaults to now).  The ``dt`` parameter exists
    for deterministic testing — callers should not set it in production.
    """
    override = os.environ.get("SAFE_DEP_AUDIT_LOG")
    if override:
        return override
    if dt is None:
        dt = datetime.now(timezone.utc)
    ym = dt.strftime("%Y-%m")
    return os.path.join(os.path.expanduser("~"), ".claude", f"safer-dependencies-audit-{ym}.log")


def build_source(
    *,
    component: str,
    script: str,
    hook: Optional[str] = None,
    tool: Optional[str] = None,
    mode: str,
    session_id: Optional[str] = None,
    model: Optional[str] = None,
) -> dict[str, Any]:
    """Construct the ``source`` block.

    Raises ``ValueError`` if ``component`` is not a known tag — the call
    sites are enumerable (4) and catching typos here is cheap insurance.
    ``hook`` and ``tool`` may be None for manual invocations; ``mode`` is
    free-form (``intercept`` / ``manual`` / ``install_error``) but callers
    should pick one of those three to keep analysis consistent.

    If ``session_id`` is omitted, ``$CLAUDE_SESSION_ID`` is consulted.
    Omitted entirely from the output when neither is set.
    """
    if component not in COMPONENT_TAGS:
        raise ValueError(
            f"unknown source.component {component!r}; "
            f"expected one of {COMPONENT_TAGS}"
        )
    src: dict[str, Any] = {
        "component": component,
        "script": script,
        "hook": hook,
        "tool": tool,
        "mode": mode,
    }
    if session_id is None:
        session_id = os.environ.get("CLAUDE_SESSION_ID") or None
    if session_id:
        src["session_id"] = session_id
    if model is None:
        model = read_configured_model()
    if model:
        src["model"] = model
    return src


def _transitive_policy_block() -> dict[str, Any]:
    """Effective transitive policy for lockfile entries (issue #245).

    Sourced from the CANONICAL config system (#248): a snapshot of the
    single ``transitive`` check tier in force when the audit ran, so
    post-hoc analysis knows which policy applied. Fail-open to the
    documented default ("warn") — audit logging must never break the
    caller, and #248 owns the policy keys (this block does NOT invent
    transitive_policy / threshold knobs).
    """
    try:
        from safedep.config import check_tier
        return {"transitive_tier": check_tier("transitive")}
    except Exception:
        return {"transitive_tier": "warn"}


def build_entry(
    file_path: str,
    ecosystem: str,
    checked: list,
    signals: list,
    *,
    source: dict,
    dry_run: bool = False,
    cwd: Optional[str] = None,
    now: Optional[datetime] = None,
    lockfile: bool = False,
    manifest_ref: str = "",
    relation_summary: Optional[dict] = None,
) -> dict[str, Any]:
    """Construct one canonical audit-log entry for a manifest / bash audit.

    Pure function — no I/O. ``now`` is injectable for deterministic tests;
    when omitted, the current UTC time is used. ``source`` should come from
    :func:`build_source`.

    ``cwd`` is the working directory at the time of the hook call. It is
    stored in the entry when provided so that Pre-Install Bash entries (whose
    ``file`` is a ``bash:<command>`` pseudo-path) can be attributed to a
    project by the per-project dashboard.

    ``lockfile`` / ``manifest_ref`` / ``relation_summary`` (schema 2.2,
    issue #245): when ``lockfile`` is True the entry additionally carries
    the direct/transitive relation block plus a ``policy`` block sourced
    from #248's config (``check_tier("transitive")``) — see the module
    docstring. All three default to "off" so every pre-existing call site
    keeps producing the unchanged non-lockfile shape.
    """
    findings = [s for s in signals
                if s.startswith(_FINDING_PREFIXES) or _is_cve_warning(s)]
    finding_pkgs = {_pkg_name(f.split()[1]) for f in findings}
    clean = [p for p in checked if _pkg_name(p) not in finding_pkgs]
    abandoned = [s for s in signals if "— abandoned:" in s]
    stale = [s for s in signals if s.startswith("STALE:")]
    typosquat = [s for s in signals if s.startswith("TYPOSQUAT-CONFIRM:")]
    unknown = [s for s in signals if s.startswith("UNKNOWN:")]
    signatures = [s for s in signals if s.startswith("SIGNATURE:")]
    notes = [s for s in signals if s.startswith("NOTE:")]

    ts_dt = now if now is not None else datetime.now(timezone.utc)
    entry: dict[str, Any] = {
        "ts": ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema": SCHEMA_VERSION,
        "source": source,
        "file": file_path,
        "ecosystem": ecosystem,
        "checked": checked,
        "findings": findings,
        "abandoned": abandoned,
        "stale": stale,
        "typosquat": typosquat,
        "unknown": unknown,
        "signatures": signatures,
        "notes": notes,
        "clean": clean,
    }
    if cwd:
        entry["cwd"] = cwd
    if lockfile:
        entry["lockfile"] = True
        entry["manifest_ref"] = manifest_ref or ""
        entry["policy"] = _transitive_policy_block()
        if isinstance(relation_summary, dict):
            entry["relation_summary"] = relation_summary
        else:
            # Caller flagged a lockfile but supplied no classification —
            # fail open: everything checked is of unknown relation.
            entry["relation_summary"] = {
                "direct_checked": 0,
                "transitive_checked": 0,
                "unknown_checked": len(checked),
                "transitive_flagged": 0,
                "transitive_flagged_pkgs": [],
            }
    if dry_run:
        entry["mode"] = "dry_run"
    return entry


def build_install_error_entry(
    *,
    install_error: str,
    shim_dir: str,
    scripts_dir: str,
    source: dict,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Construct an install-error entry (shim preflight failure).

    Shape differs from :func:`build_entry` (no ecosystem / checked /
    signals), but carries the same ``ts`` / ``schema`` / ``source`` header
    so analysis tooling can treat the log as one coherent stream.
    """
    ts_dt = now if now is not None else datetime.now(timezone.utc)
    return {
        "ts": ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema": SCHEMA_VERSION,
        "source": source,
        "install_error": install_error,
        "shim_dir": shim_dir,
        "scripts_dir": scripts_dir,
    }


def _maybe_rotate(path: str, incoming_bytes: int) -> None:
    """Rotate the audit log if appending would exceed the size cap.

    Rotation scheme: ``<log>.1`` → ``<log>.2`` → ... up to
    ``AUDIT_LOG_MAX_ROTATIONS``; oldest is dropped. The current log moves
    to ``<log>.1`` and a new empty log is created on the next append.

    Honors ``SAFE_DEP_LOG_MAX_BYTES`` (set to 0 to disable rotation).
    Silent on any error — audit-log housekeeping must never interfere
    with the caller's flow.
    """
    try:
        from safedep.constants import audit_log_max_bytes, AUDIT_LOG_MAX_ROTATIONS
        cap = audit_log_max_bytes()
        if cap == 0:
            return
        try:
            current_size = os.path.getsize(path)
        except OSError:
            return
        if current_size + incoming_bytes <= cap:
            return
        # Time to rotate. Drop the oldest, shift the rest down.
        for i in range(AUDIT_LOG_MAX_ROTATIONS, 0, -1):
            src = path if i == 1 else f"{path}.{i - 1}"
            dst = f"{path}.{i}"
            if os.path.exists(src):
                try:
                    if os.path.exists(dst):
                        os.remove(dst)
                    os.rename(src, dst)
                    # Issue #210: a legacy (pre-0600) log keeps its old mode
                    # through the rename — tighten the archive too.
                    os.chmod(dst, 0o600)
                except OSError:
                    pass
    except Exception:
        pass


def _redact_path(path: str) -> str:
    """Replace an absolute path with a stable-but-non-identifying token.

    Used when ``SAFE_DEP_REDACT_PATHS`` is on. The same path always maps
    to the same token within a session so post-hoc analysis can still
    correlate entries; the token is short and reveals neither directory
    structure nor repo names.
    """
    import hashlib
    digest = hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()[:12]
    return f"<redacted:{digest}>"


# Vulnerability-identifier shapes for SAFE_DEP_REDACT_CVES (issue #210).
_VULN_ID_RE = None  # compiled lazily


def _vuln_id_re():
    global _VULN_ID_RE
    if _VULN_ID_RE is None:
        import re
        _VULN_ID_RE = re.compile(
            r"\b(?:CVE-\d{4}-\d{4,}"
            r"|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}"
            r"|PYSEC-\d{4}-\d+"
            r"|RUSTSEC-\d{4}-\d+"
            r"|GO-\d{4}-\d+"
            r"|OSV-[0-9A-Za-z-]+)\b"
        )
    return _VULN_ID_RE


# Entry fields that hold human-readable signal strings or pkg@version tokens —
# the only places vulnerability ids and package names appear.
_REDACTABLE_LIST_FIELDS = (
    "checked", "findings", "abandoned", "stale", "typosquat",
    "unknown", "signatures", "notes", "clean",
)


def _redact_cve_ids(entry: dict) -> dict:
    """Replace vulnerability identifiers with ``<redacted-cve>`` (issue #210)."""
    out = {**entry}
    rx = _vuln_id_re()
    for field in _REDACTABLE_LIST_FIELDS:
        vals = out.get(field)
        if isinstance(vals, list):
            out[field] = [rx.sub("<redacted-cve>", v) if isinstance(v, str) else v
                          for v in vals]
    return out


def _redact_packages(entry: dict, patterns: list) -> dict:
    """Replace package names matching any policy regex with a stable hash
    token across every signal/pkg field (issue #210).

    Names are collected from ``checked``/``clean`` tokens and from the second
    whitespace token of signal lines (the canonical ``PREFIX: pkg@ver …``
    shape). Fail-open: an invalid regex is skipped.
    """
    import re
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error:
            continue
    if not compiled:
        return entry

    candidates: set = set()
    for field in ("checked", "clean"):
        for tok in entry.get(field) or []:
            if isinstance(tok, str) and tok:
                candidates.add(_pkg_name(tok))
    for field in _REDACTABLE_LIST_FIELDS:
        for sig in entry.get(field) or []:
            if isinstance(sig, str):
                parts = sig.split()
                if len(parts) >= 2 and parts[0].endswith(":"):
                    candidates.add(_pkg_name(parts[1]))

    to_redact = {name for name in candidates
                 if name and any(rx.fullmatch(name) for rx in compiled)}
    if not to_redact:
        return entry

    out = {**entry}
    for name in to_redact:
        token = _redact_path(name)  # same stable short-hash token shape
        name_rx = re.compile(r"(?<![A-Za-z0-9_.@/-])" + re.escape(name)
                             + r"(?![A-Za-z0-9_.-])")
        for field in _REDACTABLE_LIST_FIELDS:
            vals = out.get(field)
            if isinstance(vals, list):
                out[field] = [name_rx.sub(token, v) if isinstance(v, str) else v
                              for v in vals]
    return out


def _write_json_line(
    entry: dict,
    log_path: Optional[str] = None,
    dt: Optional[datetime] = None,
) -> None:
    """Append a pre-built entry dict as one JSONL line. Silent on any error.

    Audit log failure must never affect hook output or the caller's flow.
    Honors ``SAFE_DEP_REDACT_PATHS`` (replaces ``file`` field with a hash
    token) and rotates per ``SAFE_DEP_LOG_MAX_BYTES``.
    ``dt`` pins the month used by ``default_log_path`` when ``log_path`` is
    not provided — pass the entry's own timestamp so the file month matches.
    """
    try:
        from safedep.constants import (
            redact_cves_enabled,
            redact_package_patterns,
            redact_paths_enabled,
        )
        path = log_path if log_path is not None else default_log_path(dt=dt)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # Optional path redaction — only applied to user-project paths,
        # never to internal fields like script/shim_dir which could be
        # useful for diagnosing install errors.
        if redact_paths_enabled() and isinstance(entry.get("file"), str):
            entry = {**entry, "file": _redact_path(entry["file"])}
        # Optional field redaction (issue #210). Opt-in: both degrade stats /
        # regression detection for the affected entries, by design.
        if redact_cves_enabled():
            entry = _redact_cve_ids(entry)
        _pkg_patterns = redact_package_patterns()
        if _pkg_patterns:
            entry = _redact_packages(entry, _pkg_patterns)
        line = json.dumps(entry) + "\n"
        _maybe_rotate(path, len(line.encode("utf-8")))
        # 0600 from birth (issue #210): the log maps a machine's dependency
        # history; never leave it readable to other local users via a
        # permissive umask. O_CREAT mode applies only on creation; the
        # follow-up chmod tightens pre-existing logs (no-op when already 0600).
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line)
        finally:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except Exception:
        pass


def write_entry(
    file_path: str,
    ecosystem: str,
    checked: list,
    signals: list,
    *,
    source: dict,
    dry_run: bool = False,
    cwd: Optional[str] = None,
    log_path: Optional[str] = None,
    now: Optional[datetime] = None,
    lockfile: bool = False,
    manifest_ref: str = "",
    relation_summary: Optional[dict] = None,
) -> None:
    """Append one canonical audit entry. Silent on any error."""
    try:
        entry = build_entry(
            file_path=file_path,
            ecosystem=ecosystem,
            checked=checked,
            signals=signals,
            source=source,
            dry_run=dry_run,
            cwd=cwd,
            now=now,
            lockfile=lockfile,
            manifest_ref=manifest_ref,
            relation_summary=relation_summary,
        )
    except Exception:
        return
    _write_json_line(entry, log_path=log_path, dt=now)


def build_fail_open_entry(
    *,
    reason: str,
    detail: Optional[str] = None,
    source: dict,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Construct a fail-open diagnostic entry.

    A fail-open entry says: "this hook fired but exited early without auditing
    because something prerequisite was missing." It exists so users can tell
    the difference between "audit ran and found nothing" and "audit never ran
    because the install is broken."  Pure function — no I/O.
    """
    ts_dt = now if now is not None else datetime.now(timezone.utc)
    fail_open: dict[str, Any] = {"reason": reason}
    if detail:
        fail_open["detail"] = detail
    return {
        "ts": ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema": SCHEMA_VERSION,
        "source": source,
        "fail_open": fail_open,
    }


def write_fail_open_entry(
    *,
    reason: str,
    detail: Optional[str] = None,
    source: dict,
    log_path: Optional[str] = None,
    now: Optional[datetime] = None,
) -> None:
    """Append one fail-open diagnostic entry. Silent on any error."""
    try:
        entry = build_fail_open_entry(
            reason=reason,
            detail=detail,
            source=source,
            now=now,
        )
    except Exception:
        return
    _write_json_line(entry, log_path=log_path, dt=now)


def write_install_error_entry(
    *,
    install_error: str,
    shim_dir: str,
    scripts_dir: str,
    source: dict,
    log_path: Optional[str] = None,
    now: Optional[datetime] = None,
) -> None:
    """Append one install-error entry. Silent on any error."""
    try:
        entry = build_install_error_entry(
            install_error=install_error,
            shim_dir=shim_dir,
            scripts_dir=scripts_dir,
            source=source,
            now=now,
        )
    except Exception:
        return
    _write_json_line(entry, log_path=log_path, dt=now)


def write_update_entry(
    from_version,
    to_version,
    ref,
    sha,
    fallback,
    scopes,
    status,
    log_path: Optional[str] = None,
    dt: Optional[datetime] = None,
) -> None:
    """Record a self-update operation. Silent on any error.

    Shape differs from :func:`build_entry` (no ecosystem / checked / signals):
    it captures the version transition, the verified ref/sha the clone was
    pinned to, whether the resolver fell back to ``main``, the per-scope
    outcomes, and the overall status — so post-hoc analysis can audit which
    upstream code each scope was upgraded to and whether any scope rolled back.
    """
    try:
        entry = {
            "ts": (dt or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event": "self_update",
            "from": from_version,
            "to": to_version,
            "ref": ref,
            "sha": sha,
            "fallback": fallback,
            "scopes": scopes,
            "status": status,
        }
    except Exception:
        return
    _write_json_line(entry, log_path=log_path, dt=dt)


# ── Regression detection (issue #133) ────────────────────────────────────────
#
# When the shim is about to emit MAJOR-UPDATE-CONFIRM for a package, it can
# cross-reference the audit log to determine whether the same (file, package)
# was already corrected to the same safe version in a prior entry. If so, the
# current finding is not a fresh CVE — it is a re-introduction (typically by
# a subagent that wrote the manifest from a snapshot predating the correction).
#
# The shim uses this to emit a REGRESSION: signal alongside the standard
# MAJOR-UPDATE-CONFIRM so the orchestrator can recognise the re-introduction
# and restore the previously-approved version without treating it as a brand
# new major-bump decision.

# UPDATED: <pkg> <old> → <new> (...)
# The arrow is the unicode rightwards arrow → in shim output; we also
# accept the ASCII "->" form for manual.skill entries written from contexts
# that escaped the unicode glyph.
import re as _re
_UPDATED_RE = _re.compile(
    r"^UPDATED:\s+(?P<pkg>\S+)\s+(?P<old>\S+)\s+(?:→|->)\s+(?P<new>\S+)"
)


def find_prior_correction(
    file_path: str,
    package: str,
    *,
    log_path: Optional[str] = None,
    lookback_lines: int = 5000,
    now: Optional[datetime] = None,
) -> Optional[dict]:
    """Find the most recent ``UPDATED: <package> ...`` entry for ``file_path``.

    Scans up to ``lookback_lines`` recent lines of the audit log (default 5000
    — enough to cover several days of normal activity without being slow).
    Returns ``None`` if no prior correction exists, or a dict with keys:

        {
          "old_version": "<the vulnerable version that was corrected from>",
          "new_version": "<the safe version it was corrected to>",
          "ts":          "<ISO timestamp of the prior correction>",
          "component":   "<source.component of the prior entry>",
        }

    Silent on any I/O or parse error — returns ``None``. Audit-log reads must
    never break the caller's flow.
    """
    if not file_path or not package:
        return None
    path = log_path if log_path is not None else default_log_path(dt=now)
    try:
        if not os.path.exists(path):
            return None
        # Tail the file: read all lines but only keep the last `lookback_lines`.
        # The audit log rotates at ~SAFE_DEP_LOG_MAX_BYTES, so the tail is
        # bounded in practice; we still cap to avoid pathological reads.
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    if lookback_lines and lookback_lines > 0:
        lines = lines[-lookback_lines:]

    # Walk from newest → oldest so the first match wins.
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(entry, dict):
            continue
        if entry.get("file") != file_path:
            continue
        findings = entry.get("findings") or []
        if not isinstance(findings, list):
            continue
        for sig in findings:
            if not isinstance(sig, str):
                continue
            m = _UPDATED_RE.match(sig)
            if not m:
                continue
            if m.group("pkg") != package:
                continue
            source = entry.get("source") or {}
            return {
                "old_version": m.group("old"),
                "new_version": m.group("new"),
                "ts": entry.get("ts", ""),
                "component": source.get("component", "") if isinstance(source, dict) else "",
            }
    return None
