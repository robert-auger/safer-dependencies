"""
PostToolUse:Bash resolved-environment audit ("Scan C", issue #228).

After a successful plain-pip install (``pip install …``, ``pip install -r
requirements.txt``, ``python -m pip install …``, ``uv pip install …``) there is
no lockfile for Scan A to audit, so the transitive dependency tree the
resolver just installed was never CVE-checked. This script closes that gap:

  1. argv[1] = the bash command, argv[2] = the cwd the command ran in.
  2. Extract the pip invocation prefix (``pip3`` / ``python -m pip`` /
     ``uv pip``) from the command — never execute the user's command itself.
  3. Run ``<prefix> list --format=json`` (read-only) in the same cwd to
     enumerate the *resolved* environment: direct + transitive packages.
  4. Batch-query OSV (``/v1/querybatch``) for every installed pin.
  5. Emit plain-text signals on stdout (one per line) for the bash hook to
     append to additionalContext, and write one canonical audit-log entry.

Output contract (stable with safer-dependencies-posttooluse-bash.sh):
  - stdout: zero or more signal lines (``TRANSITIVE-CVE:`` / ``RESOLVED-CVE:``
    / ``CLEAN-RESOLVED:``). Empty stdout means "nothing to report".
  - exit code is always 0 (fail-open): any error → silent empty output.

Packages already declared in a top-level ``requirements*.txt`` are labelled
``RESOLVED-CVE:`` (the Intercept shim should have flagged them at write time);
undeclared ones are labelled ``TRANSITIVE-CVE:`` — these are exactly the
findings no other mode can see.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from safedep.http import _http_post_json  # noqa: E402

try:
    from safedep.audit_log import (  # noqa: E402
        build_source as _build_source,
        write_entry as _audit_log_write_entry,
    )
except Exception:  # pragma: no cover — defensive
    _build_source = None
    _audit_log_write_entry = None

try:
    from safedep.config import is_disabled as _ecosystem_is_disabled  # noqa: E402
except Exception:  # pragma: no cover — defensive (fail open)
    def _ecosystem_is_disabled(_eco: str) -> bool:  # type: ignore[no-redef]
        return False

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_BATCH_MAX = 500
# Hard cap on environment size; beyond this we audit the first N and say so.
_MAX_PACKAGES = 2000
# pip list must answer fast — it is local metadata, not a network call.
_PIP_LIST_TIMEOUT = 20
# Whole-scan soft deadline (seconds). Scan C runs BETWEEN Scan A and the
# hook's combined-emission step; without a deadline a slow OSV could blow
# the 60s hook timeout and destroy Scan A's already-collected signals
# (review finding). Override via SAFE_DEP_RESOLVED_AUDIT_DEADLINE; 0 disables.
_DEFAULT_DEADLINE = 25


def _install_deadline() -> None:
    """Best-effort SIGALRM deadline; on expiry exit 0 silently (fail-open).
    No-op where alarm is unavailable (Windows)."""
    raw = os.environ.get("SAFE_DEP_RESOLVED_AUDIT_DEADLINE", "").strip()
    try:
        deadline = int(float(raw)) if raw else _DEFAULT_DEADLINE
    except ValueError:
        deadline = _DEFAULT_DEADLINE
    if deadline <= 0:
        return
    try:
        import signal

        def _expire(signum, frame):  # noqa: ARG001
            os._exit(0)

        if hasattr(signal, "SIGALRM"):
            signal.signal(signal.SIGALRM, _expire)
            signal.alarm(deadline)
    except Exception:  # noqa: BLE001
        pass


_SHELL_OPS = {"&&", "||", ";", "|", "&"}
_PIP_RE = re.compile(r"^pip[0-9]*(\.[0-9]+)?$")
_PYTHON_RE = re.compile(r"^python[0-9]*(\.[0-9]+)?$")
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Same pinned-requirement shape the shim's parse_requirements_txt accepts,
# plus bare (unpinned) names — we only need the *name* for the
# declared-vs-transitive split.
_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9_\-\.]+)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~;#]|$)")


def _norm(name: str) -> str:
    """PEP 503 normalization."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def split_clauses(command: str) -> list[list[str]]:
    """Tokenize a shell command and split on &&, ||, ;, |, & operators."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []
    clauses: list[list[str]] = []
    cur: list[str] = []
    for tok in tokens:
        if tok in _SHELL_OPS:
            if cur:
                clauses.append(cur)
            cur = []
        else:
            cur.append(tok)
    if cur:
        clauses.append(cur)
    return clauses


def extract_pip_prefix(command: str) -> "tuple[list[str], str] | None":
    """Return ``(argv_prefix, cd_subdir)`` of the first pip-install clause.

    ``cd_subdir`` is the accumulated relative directory from leading ``cd``
    clauses ("" when none) — the install's effective working directory
    relative to the hook payload's cwd. Returns None when no pip-install
    clause is recognised.

    Recognised shapes (after stripping leading VAR=value assignments):
      pip install …           → ["pip"]
      pip3.12 install …       → ["pip3.12"]
      python -m pip install … → ["python", "-m", "pip"]
      uv pip install …        → ["uv", "pip"]

    The returned prefix is what we re-invoke with ``list --format=json``;
    it is the same executable the user's install just ran, never the
    arbitrary remainder of the command.
    """
    subdir = ""
    for clause in split_clauses(command):
        toks = [t for t in clause if not _ENV_ASSIGN_RE.match(t)]
        if not toks:
            continue
        # Track `cd <dir>` clauses so declared_names/_audit_file_label and a
        # relative pip path resolve against the directory the install
        # actually ran in (review finding). Unresolvable cd targets (vars,
        # tilde, multiple args) abort the scan rather than mislabel.
        if toks[0] == "cd":
            if len(toks) == 2 and not toks[1].startswith(("-", "~")) \
                    and "$" not in toks[1]:
                subdir = os.path.join(subdir, toks[1]) if subdir else toks[1]
                continue
            return None
        head = os.path.basename(toks[0])
        prefix: list[str] | None = None
        rest: list[str] = []
        if _PIP_RE.match(head):
            prefix, rest = toks[:1], toks[1:]
        elif _PYTHON_RE.match(head) and toks[1:3] == ["-m", "pip"]:
            prefix, rest = toks[:3], toks[3:]
        elif head == "uv" and toks[1:2] == ["pip"]:
            prefix, rest = toks[:2], toks[2:]
        if prefix is None:
            continue
        # `install` must be the SUBCOMMAND (first non-flag token), not any
        # argument: `pip show install` / `pip download x -d install` must
        # not trigger a scan (review finding).
        subcommand = next((t for t in rest if not t.startswith("-")), "")
        if subcommand != "install":
            continue
        if "--dry-run" in rest:
            continue
        # --target/--prefix/--root install somewhere `<pip> list` cannot
        # see; skip rather than report a misleading environment.
        if any(t == flag or t.startswith(flag + "=")
               for t in rest
               for flag in ("--target", "--prefix", "--root")):
            continue
        return prefix, subdir
    return None


def list_installed(prefix: list[str], cwd: str) -> list[tuple[str, str]]:
    """Run ``<prefix> list --format=json`` and return [(name, version), …]."""
    cmd = list(prefix) + ["list", "--format=json"]
    if os.path.basename(prefix[0]) != "uv":
        cmd.append("--disable-pip-version-check")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_PIP_LIST_TIMEOUT, cwd=cwd or None,
        )
    except Exception:
        return []
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        rows = json.loads(proc.stdout)
    except ValueError:
        return []
    out: list[tuple[str, str]] = []
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                name, version = row.get("name"), row.get("version")
                if isinstance(name, str) and isinstance(version, str) and name and version:
                    out.append((name, version))
    return out


def _pyproject_declared_names(cwd: str) -> set[str]:
    """Best-effort [project] dependency names from pyproject.toml."""
    names: set[str] = set()
    path = os.path.join(cwd, "pyproject.toml")
    if not os.path.isfile(path):
        return names
    try:
        try:
            import tomllib as _toml  # Python 3.11+
        except ImportError:
            import tomli as _toml  # type: ignore[no-redef]
        with open(path, "rb") as fh:
            data = _toml.load(fh)
        project = data.get("project") or {}
        specs = list(project.get("dependencies") or [])
        for group in (project.get("optional-dependencies") or {}).values():
            if isinstance(group, list):
                specs.extend(group)
        for spec in specs:
            if not isinstance(spec, str):
                continue
            m = _REQ_NAME_RE.match(spec.strip())
            if m:
                names.add(_norm(m.group(1)))
    except Exception:  # noqa: BLE001 — fail-open
        return names
    return names


def declared_names(cwd: str) -> set[str]:
    """Normalized package names declared at the top level of the project:
    requirements*.txt pins plus pyproject.toml [project].dependencies /
    optional-dependencies (review finding: pyproject-based projects would
    otherwise see every direct dep mislabeled transitive)."""
    names: set[str] = set()
    names.update(_pyproject_declared_names(cwd))
    try:
        entries = os.listdir(cwd)
    except OSError:
        return names
    for fname in entries:
        if not (fname.startswith("requirements") and fname.endswith(".txt")):
            continue
        try:
            with open(os.path.join(cwd, fname), encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith(("#", "-")):
                        continue
                    m = _REQ_NAME_RE.match(line)
                    if m:
                        names.add(_norm(m.group(1)))
        except OSError:
            continue
    return names


def osv_querybatch(pins: list[tuple[str, str]]) -> list[list[str]]:
    """Query OSV for each (name, version) pin; return vuln-id lists per pin.

    Fail-open: a failed chunk yields empty lists for its pins.
    """
    results: list[list[str]] = []
    for start in range(0, len(pins), _OSV_BATCH_MAX):
        chunk = pins[start:start + _OSV_BATCH_MAX]
        payload = {
            "queries": [
                {"version": v, "package": {"name": _norm(n), "ecosystem": "PyPI"}}
                for n, v in chunk
            ]
        }
        resp = _http_post_json(OSV_QUERYBATCH_URL, payload, timeout=20)
        rows = resp.get("results") if isinstance(resp, dict) else None
        if not isinstance(rows, list) or len(rows) != len(chunk):
            results.extend([[] for _ in chunk])
            continue
        for row in rows:
            vulns = row.get("vulns") if isinstance(row, dict) else None
            ids = []
            if isinstance(vulns, list):
                ids = [v.get("id") for v in vulns
                       if isinstance(v, dict) and isinstance(v.get("id"), str)]
            results.append(ids)
    return results


def _audit_file_label(cwd: str) -> str:
    """The audit-log ``file`` for this run: the requirements file when one
    exists (that is the manifest this environment realizes), else the cwd."""
    candidate = os.path.join(cwd, "requirements.txt")
    if os.path.isfile(candidate):
        return candidate
    try:
        for fname in sorted(os.listdir(cwd)):
            if fname.startswith("requirements") and fname.endswith(".txt"):
                return os.path.join(cwd, fname)
    except OSError:
        pass
    return cwd


def build_signals(
    installed: list[tuple[str, str]],
    vuln_ids: list[list[str]],
    declared: set[str],
) -> list[str]:
    signals: list[str] = []
    capped = False
    for (name, version), ids in zip(installed, vuln_ids):
        if not ids:
            continue
        shown = ", ".join(ids[:4]) + (f" +{len(ids) - 4} more" if len(ids) > 4 else "")
        if _norm(name) in declared:
            signals.append(
                f"RESOLVED-CVE: {name}@{version} — {shown} — declared package "
                f"confirmed vulnerable in the installed environment. "
                f"ACTION REQUIRED: update the pin in requirements.txt to a fixed release."
            )
        else:
            signals.append(
                f"TRANSITIVE-CVE: {name}@{version} — {shown} — pulled in "
                f"transitively (not declared in requirements*.txt). "
                f"ACTION REQUIRED: pin a fixed version of {name} in requirements.txt "
                f"or upgrade the parent package that requires it."
            )
        if len(signals) >= 20:
            capped = True
            break
    if capped:
        signals.append("NOTE: resolved-environment findings capped at 20 — "
                       "run a full audit (pip-audit) for the complete list.")
    if not signals and installed:
        signals.append(
            f"CLEAN-RESOLVED: {len(installed)} packages in the resolved pip "
            f"environment checked (direct + transitive) — no known vulnerabilities"
        )
    return signals


def _write_audit_entry(cwd: str, installed: list[tuple[str, str]], signals: list[str]) -> None:
    if _audit_log_write_entry is None or _build_source is None:
        return
    try:
        source = _build_source(
            component="bash.posttooluse",
            script="skills/scripts/postinstall_resolved_audit.py",
            hook="PostToolUse",
            tool="Bash",
            mode="intercept",
        )
        _audit_log_write_entry(
            file_path=_audit_file_label(cwd),
            ecosystem="pypi",
            checked=[f"{n}@{v}" for n, v in installed[:500]],
            signals=signals,
            source=source,
        )
    except Exception:
        pass


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        return 0
    _install_deadline()
    command, cwd = argv[1], argv[2]
    if _ecosystem_is_disabled("pypi"):
        return 0
    try:
        from safedep.config import check_tier as _check_tier
        if _check_tier("transitive") == "off":
            return 0
    except Exception:  # noqa: BLE001 — fail-open to scanning
        pass
    extracted = extract_pip_prefix(command)
    if extracted is None:
        return 0
    prefix, subdir = extracted
    if subdir:
        cwd = os.path.normpath(os.path.join(cwd, subdir))
        if not os.path.isdir(cwd):
            return 0
    installed = list_installed(prefix, cwd)
    if not installed:
        return 0
    overflow_note = ""
    if len(installed) > _MAX_PACKAGES:
        overflow_note = (f"NOTE: resolved environment has {len(installed)} packages; "
                         f"audited the first {_MAX_PACKAGES}.")
        installed = installed[:_MAX_PACKAGES]
    vuln_ids = osv_querybatch(installed)
    signals = build_signals(installed, vuln_ids, declared_names(cwd))
    if overflow_note:
        signals.append(overflow_note)
    _write_audit_entry(cwd, installed, signals)
    for line in signals:
        print(line)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception:  # noqa: BLE001 — fail-open contract
        sys.exit(0)
