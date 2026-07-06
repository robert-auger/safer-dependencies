#!/usr/bin/env python3
"""
SaferDependenciesManager - Centralized UX manager for safer-dependencies system.

This module provides the foundation for installation, stats, and validation
of the safer-dependencies skill and hook system.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any

try:
    from safedep.projects import aggregate_projects
except ImportError:
    # When this module is imported package-qualified (e.g. ``skills.scripts.
    # safer_dependencies_manager``) the sibling ``safedep`` package is not a
    # top-level import. Put this file's own directory on the path and retry, so
    # the import works however the manager is loaded (direct script, pytest, or
    # package import).
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from safedep.projects import aggregate_projects

# Single source of truth for the upstream repo — update here when transferring to a new org.
REPO_URL = "https://github.com/robert-auger/safer-dependencies"

# Raw URL for the SKILL frontmatter on `main` — the single source of truth for the
# version (mirrors safedep.version's frontmatter resolution, just upstream). Derived
# from REPO_URL so transferring orgs only requires editing REPO_URL.
_RAW_BASE = REPO_URL.replace("https://github.com/", "https://raw.githubusercontent.com/")
UPSTREAM_VERSION_URL = f"{_RAW_BASE}/main/skills/safer-dependencies.md"

# Docs section explaining the recommended (Safer) vs opt-in (Convenience)
# permission allowlist. Derived from REPO_URL so it stays correct after the
# public-repo publish scrub rewrites the org/repo slug.
PERMISSIONS_DOCS_URL = f"{REPO_URL}/blob/main/INSTALLATION.md#permissions-allowlist"

_TOP_PACKAGES_LIMIT = 3

# Maps each safer-dependencies hook script basename to its logical selection key.
# ``post_agent`` is shared by both the pre- and post-tooluse agent scripts.
_HOOK_BY_SCRIPT: Dict[str, str] = {
    "safer-dependencies-shim.sh": "intercept",
    "safer-dependencies-pretooluse-bash.sh": "pre_install",
    "safer-dependencies-posttooluse-bash.sh": "post_install",
    "safer-dependencies-pretooluse-agent.sh": "post_agent",
    "safer-dependencies-posttooluse-agent.sh": "post_agent",
}


def _fetch_upstream_version(url: "str | None" = None, timeout: float = 5.0):
    """Return the ``version:`` from the upstream SKILL frontmatter on ``main``.

    Returns the version string, or ``None`` on ANY failure (network down, HTTP
    error, malformed frontmatter). Never raises — the ``version`` subcommand
    degrades gracefully to installed-version-only when this returns ``None``.

    Isolated as a module-level function so tests can monkeypatch it without any
    real network I/O. ``SAFE_DEP_UPSTREAM_URL`` overrides the URL (used by tests
    to force a fast offline failure without real network access).
    """
    from urllib.request import urlopen

    if url is None:
        url = os.environ.get("SAFE_DEP_UPSTREAM_URL", UPSTREAM_VERSION_URL)

    try:
        with urlopen(url, timeout=timeout) as resp:  # noqa: S310 (trusted https URL)
            text = resp.read(4096).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 — any failure degrades to "unknown upstream"
        return None

    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    m = re.search(r"^version:\s*(.+?)\s*$", text[3:end], re.MULTILINE)
    if not m:
        return None
    return m.group(1).strip().strip('"').strip("'")

def _upstream_endpoints(repo_url):
    base = repo_url.rstrip("/")
    slug = base.replace("https://github.com/", "")
    return {
        "clone_url": base + ".git" if not base.endswith(".git") else base,
        "api_tags_url": f"https://api.github.com/repos/{slug}/tags",
        "api_commits_url": f"https://api.github.com/repos/{slug}/commits/main",
        "raw_base": _RAW_BASE,
    }


def _fetch_tags(repo_url=REPO_URL, timeout=5.0):
    import json
    from urllib.request import urlopen, Request
    url = _upstream_endpoints(repo_url)["api_tags_url"]
    req = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "safer-deps"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8", "replace"))
    return [(t["name"], t["commit"]["sha"]) for t in data]


def _fetch_main_sha(repo_url=REPO_URL, timeout=5.0):
    import json
    from urllib.request import urlopen, Request
    url = _upstream_endpoints(repo_url)["api_commits_url"]
    req = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "safer-deps"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", "replace"))["sha"]


def _semver_key(name):
    parts = name.lstrip("v").split(".")
    try:
        return tuple(int(p) for p in parts[:3])
    except ValueError:
        return None


def _resolve_upstream_target(timeout=5.0):
    """See Shared Interfaces. Comparison version is frontmatter in BOTH branches (#277)."""
    try:
        tags = [(n, s) for (n, s) in _fetch_tags(timeout=timeout) if _semver_key(n) is not None]
        if tags:
            name, sha = max(tags, key=lambda ns: _semver_key(ns[0]))
            # Read the frontmatter version FROM THE RESOLVED TAG ref, not main (#277):
            # the installed bytes are the tag's, so the advertised version must match.
            # Stay org-agnostic by interpolating the tag into UPSTREAM_VERSION_URL's
            # main-pinned path rather than reconstructing it.
            tag_url = UPSTREAM_VERSION_URL.replace("/main/", f"/{name}/")
            version = _fetch_upstream_version(url=tag_url, timeout=timeout)
            if version is None:
                return None
            return {"ref": name, "kind": "tag", "sha": sha, "version": version, "fallback": False}
        version = _fetch_upstream_version(timeout=timeout)
        if version is None:
            return None
        sha = _fetch_main_sha(timeout=timeout)
        return {"ref": "main", "kind": "branch", "sha": sha, "version": version, "fallback": True}
    except Exception:  # noqa: BLE001 — never raises across the network boundary
        return None


# Canonical lowercase names for ecosystems that appear under multiple spellings in the log.
_ECOSYSTEM_ALIASES: Dict[str, str] = {
    'crates.io': 'crates',
    'pypi': 'pypi',
    'rubygems': 'rubygems',
}


def _normalize_ecosystem(name: str) -> str:
    """Fold ecosystem name to a canonical lowercase string."""
    lowered = name.lower()
    return _ECOSYSTEM_ALIASES.get(lowered, lowered)


class SaferDependenciesManager:
    """Centralized manager for safer-dependencies UX operations."""

    def __init__(self):
        """Initialize the manager with path detection."""
        self.home_dir = Path.home()
        self.claude_dir = self.home_dir / ".claude"
        self.project_claude_dir = Path.cwd() / ".claude"
        self.repo_url = REPO_URL
        # Source root that _install_skill_file / _install_hooks copy FROM.
        # Defaults to this checkout's skills/ dir (unchanged behavior). self_update
        # repoints it at a verified CLONE's skills/ dir so the trusted installed
        # manager copies the clone's files WITHOUT executing the clone (copy-not-
        # execute, #270), then restores it in a finally.
        self._source_dir = Path(__file__).resolve().parent.parent

    def detect_existing_setup(self):
        """
        Detect existing safer-dependencies setup.

        Returns:
            dict: Structure containing skill_file, hooks, settings_configured, permissions_configured
        """
        return {
            'skill_file': self._check_skill_file_locations(),
            'hooks': {
                'intercept': self._check_hook_installed('safer-dependencies-shim.sh'),
                'pre_install': self._check_hook_installed('safer-dependencies-pretooluse-bash.sh'),
                'post_install': self._check_hook_installed('safer-dependencies-posttooluse-bash.sh'),
                # Post-Agent is a paired hook (PreToolUse:Agent + PostToolUse:Agent);
                # both files must be present to count as installed (#147).
                'post_agent': self._check_paired_hooks(
                    'safer-dependencies-pretooluse-agent.sh',
                    'safer-dependencies-posttooluse-agent.sh',
                ),
            },
            'settings_configured': self._check_settings_json(),
            'permissions_configured': self._check_permissions()
        }

    def interactive_install(self):
        """
        Interactive installation flow for safer-dependencies.

        Follows exact 7-step flow from specification:
        1. Baseline Setup: Copy skill file if missing
        2. Hook Discovery: Scan for existing installations
        3. Interactive Prompts: For each missing hook, present description/impact/benefit
        4. Auto-Configuration: Generate settings.json entries
        5. Permission Setup: Add bash allowlist entries
        6. Validation: Run health check
        7. Summary: Report what was installed

        Returns:
            dict: Installation result with status, summary, and installed components
        """
        try:
            existing = self.detect_existing_setup()
            self._display_installation_header(existing)
            use_global = self._prompt_for_scope()
            hook_selections = self._prompt_for_hooks()
            from_version = self._installed_skill_version(use_global)
            remove_legacy = self._confirm_legacy_removal(use_global, from_version)
            return self.apply_install(use_global, hook_selections, remove_legacy=remove_legacy)
        except PermissionError as e:
            return {'status': 'error', 'summary': f'Installation failed due to permission error: {e}', 'installed': []}
        except Exception as e:  # noqa: BLE001
            return {'status': 'error', 'summary': f'Installation failed: {e}', 'installed': []}

    def apply_install(self, use_global, hook_selections, existing_entries=None, allow_placeholder=True, remove_legacy=True):
        """Prompt-free installer core. Reused by interactive_install and self_update.

        Args:
            use_global (bool): Install into the global ~/.claude tree when True,
                project .claude/ when False.
            hook_selections (dict): Which hooks to install (intercept / pre_install / etc.).
            existing_entries (dict | None): Per-command hook config carried forward from
                _detect_installed_config (Task 5).
            allow_placeholder (bool): When False, raises RuntimeError if a source skill or
                hook file is absent rather than silently writing an inert placeholder.
                interactive_install keeps the default True (first-install safety net).
                Task 9's self_update orchestrator will pass False so a working install is
                never downgraded to a stub.
        """
        # issue #3: read the version already installed for this scope BEFORE the
        # skill file is overwritten, so the permission migration can tell a
        # potentially vulnerable (or older) install (remediate) from a newer one (leave alone).
        from_version = self._installed_skill_version(use_global)
        installed_components = []
        installed_components.extend(self._install_skill_file(use_global, allow_placeholder=allow_placeholder))
        installed_components.extend(
            self._install_hooks(hook_selections, use_global, allow_placeholder=allow_placeholder)['copied_files']
        )
        settings_result = self._configure_settings(hook_selections, use_global, existing_entries)
        if settings_result.get('_updated'):
            installed_components.append('settings.json')
        perm_result = self._configure_permissions(use_global, from_version=from_version, remove_legacy=remove_legacy)
        if perm_result.get('updated'):
            installed_components.append('permissions configuration')
        if perm_result.get('removed'):
            print(
                f"Removed {len(perm_result['removed'])} legacy over-broad permission "
                f"rule(s) from settings.json (issue #3): "
                f"{', '.join(perm_result['removed'])}"
            )
        validation = self.validate_installation()
        status = 'success' if validation['valid'] else 'warning'
        summary = (f'Successfully installed safer-dependencies with {len(installed_components)} components'
                   if validation['valid'] else f'Installation completed with {len(validation["issues"])} issues')
        return {'status': status, 'summary': summary, 'installed': installed_components, 'validation': validation}

    def self_update(self, check=False, force=False, rollback=False,
                    confirm=False, repo_url: str = REPO_URL) -> dict:
        """Orchestrate a verified, per-scope, copy-not-execute self-update (#270,#280,#281,#271).

        Flow:
          rollback → restore most-recent backup per scope and return.
          plan_update → offline / up-to-date short-circuits.
          check → print the human-readable plan (NO clone) and STOP.
          NOT confirm → SAME as check: print the plan (NO clone), tell the caller
          how to proceed, and STOP. This is the confirmation gate (#271): applying
          upstream code is NEVER done unprompted. A direct CLI
          ``self_update`` (no ``--yes``) is a dry-run, not a fetch+apply.
          else (confirm): detect installed scopes (none → genuine fresh install),
          clone the verified ref, assert its sources are present, then per scope:
          backup → point _source_dir at the clone's skills/ →
          apply_install(allow_placeholder=False) → restore _source_dir →
          health-check → keep or restore the backup. Audit the outcome; always
          rmtree the clone.

        Args:
            check (bool): dry-run only — resolve + preview, never clone/apply.
            force (bool): apply even when already up to date (still gated by confirm).
            rollback (bool): restore the most-recent backup and return.
            confirm (bool): the explicit apply gate (#271). WITHOUT it, an apply
                degrades to the ``check`` dry-run. The CLI maps ``--yes`` /
                ``--non-interactive`` to this; the interactive skill flow sets it
                only after the developer answers YES to the previewed plan, and an
                autonomous session sets it per the implicit-YES rule.

        The clone's manager is NEVER executed — the trusted installed manager copies
        the clone's verified files into the live bundle (copy-not-execute, #270).
        """
        import shutil as _shutil
        import datetime as _dt

        # Keep resolver (module REPO_URL) and clone (self.repo_url) consistent.
        self.repo_url = repo_url

        if rollback:
            return self._do_rollback()

        plan = self.plan_update(force=force)
        if not plan["reachable"]:
            return {"status": "offline",
                    "summary": "offline / lookup failed — no changes made"}
        if plan["up_to_date"] and not force:
            return {"status": "up_to_date",
                    "summary": f"already up to date ({plan['installed']})"}
        target = plan["target"]
        if check:
            return {"status": "check", "summary": self._format_plan(plan)}

        # Confirmation gate (#271): applying upstream code requires an explicit
        # opt-in. Without `confirm`, self_update behaves exactly like `--check` —
        # it resolves and previews the plan but does NOT clone or apply, then tells
        # the caller how to proceed. This makes a bare
        # `python3 safer_dependencies_manager.py self_update` safe by default: it
        # can never silently fetch+execute upstream code.
        if not confirm:
            return {
                "status": "check",
                "summary": (
                    self._format_plan(plan)
                    + "\n  CONFIRM REQUIRED: this was a dry-run. To apply, re-run with "
                      "--yes (or use the interactive /safer-dependencies update flow, "
                      "which previews the plan and asks for confirmation first)."
                ),
            }

        cfg = self._detect_installed_config()
        if not cfg["scopes"]:
            # Nothing installed yet — a self-update degenerates into a fresh install.
            return self.interactive_install()

        try:
            clone = self._clone_verified(target)
        except Exception as e:  # noqa: BLE001 — clone failure must not crash the caller
            return {"status": "error", "summary": f"update aborted: {e}"}

        original_source = self._source_dir
        try:
            # Guard the placeholder path (#275): abort BEFORE touching any live
            # install if the clone is missing required sources.
            self._assert_sources_present(clone, cfg)

            ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            outcomes = []
            for scope in cfg["scopes"]:
                backup = self._backup_scope(scope, ts)
                try:
                    # self_update only reaches this apply loop after an explicit
                    # --yes/confirm, so it auto-remediates the legacy rules with
                    # no interactive prompt (the opt-in prompt lives in
                    # interactive_install, where a human is present). apply_install
                    # still prints a notice of what it removed.
                    self._source_dir = clone / "skills"
                    self.apply_install(
                        scope["use_global"], scope["hook_selections"],
                        existing_entries=scope["existing_entries"],
                        allow_placeholder=False,
                    )
                finally:
                    self._source_dir = original_source
                installed_mgr = scope["bundle_dir"] / "scripts" / "safer_dependencies_manager.py"
                if self._health_check(installed_mgr, scope["bundle_dir"]):
                    outcomes.append((scope, "kept"))
                else:
                    self._restore_scope(backup, scope)
                    outcomes.append((scope, "rolled_back"))

            status = "success" if all(o == "kept" for _, o in outcomes) else "error"
            self._audit_update(plan, target, outcomes, status)
            scope_summary = ", ".join(
                f"{'global' if s['use_global'] else 'project'}:{o}" for s, o in outcomes
            )
            summary = (f"{plan['installed']} → {target['version']} "
                       f"({target['ref']}); {scope_summary}")
            return {"status": status, "summary": summary}
        except Exception as e:  # noqa: BLE001 — surface as error, clone still cleaned up
            return {"status": "error", "summary": f"update aborted: {e}"}
        finally:
            self._source_dir = original_source
            _shutil.rmtree(clone, ignore_errors=True)

    def _format_plan(self, plan):
        """Human-readable update plan string (for --check and confirmation).

        Shows installed → target, the ref/sha provenance, a fallback notice when
        the resolver fell back to main, and the trust warning that the update
        pulls and applies upstream code. The CHANGELOG excerpt lives in the clone,
        which --check intentionally does NOT create, so it's noted as available
        after the update runs rather than shown here.
        """
        target = plan["target"]
        if target["kind"] == "tag":
            prov = f"{target['ref']}"
        else:
            short = (target.get("sha") or "")[:7]
            prov = f"main@{short}"
        lines = [
            f"Update available: {plan['installed']} → {target['version']} ({prov})",
        ]
        if plan.get("fallback") or target.get("fallback"):
            lines.append(
                "  note: no release tag found — falling back to the main branch HEAD."
            )
        lines.append(
            "  TRUST: this pulls and applies upstream code from "
            f"{self.repo_url} and overwrites your installed bundle."
        )
        lines.append(
            "  (CHANGELOG excerpt is available from the verified clone once the "
            "update runs.)"
        )
        return "\n".join(lines)

    def _assert_sources_present(self, clone, cfg):
        """Raise RuntimeError if the clone is missing the skill file or any hook
        selected by any scope — guards apply_install's placeholder path (#275).
        """
        skills = clone / "skills"
        skill_file = skills / "safer-dependencies.md"
        if not skill_file.exists():
            raise RuntimeError(f"clone missing skill source: {skill_file}")
        hook_files = {
            "intercept":    ("safer-dependencies-shim.sh",),
            "pre_install":  ("safer-dependencies-pretooluse-bash.sh",),
            "post_install": ("safer-dependencies-posttooluse-bash.sh",),
            "post_agent":   ("safer-dependencies-pretooluse-agent.sh",
                             "safer-dependencies-posttooluse-agent.sh"),
        }
        for scope in cfg["scopes"]:
            for key, selected in scope.get("hook_selections", {}).items():
                if not selected or key not in hook_files:
                    continue
                for fname in hook_files[key]:
                    if not (skills / fname).exists():
                        raise RuntimeError(f"clone missing hook source: {skills / fname}")

    def _do_rollback(self):
        """Restore the most-recent backup for every detected scope."""
        cfg = self._detect_installed_config()
        if not cfg["scopes"]:
            return {"status": "error", "summary": "no installed scopes to roll back"}
        backups_root = self.claude_dir / "skills" / ".safer-dependencies-backups"
        if not backups_root.exists():
            return {"status": "error", "summary": "no backups available to restore"}
        stamps = sorted([p for p in backups_root.iterdir() if p.is_dir()])
        if not stamps:
            return {"status": "error", "summary": "no backups available to restore"}
        latest = stamps[-1]
        from_version = self._current_version()
        restored = []          # human labels for the summary
        restored_scopes = []   # {"global": bool} for the audit entry
        for scope in cfg["scopes"]:
            sub = latest / ("global" if scope["use_global"] else "project")
            if sub.exists():
                self._restore_scope(sub, scope)
                restored.append("global" if scope["use_global"] else "project")
                restored_scopes.append(scope["use_global"])
        if not restored:
            return {"status": "error",
                    "summary": f"no matching scope backup under {latest.name}"}
        self._audit_rollback(from_version, latest.name, restored_scopes)
        return {"status": "rolled_back",
                "summary": f"restored {', '.join(restored)} from backup {latest.name}"}

    def _current_version(self):
        """Best-effort read of the currently-installed version. None on any failure."""
        try:
            from safedep.version import resolve_version
            return resolve_version()
        except Exception:  # noqa: BLE001 — version lookup must never break rollback
            return None

    def _audit_rollback(self, from_version, backup_name, restored_scopes):
        """Record a manual --rollback to the audit log. Silent on any failure.

        Reuses the ``self_update`` event shape: ``ref``/``sha`` identify the
        restored backup rather than an upstream clone, ``fallback`` is False, and
        every restored scope is tagged ``rolled_back``. ``to`` is left None — the
        restored version is not reliably resolvable without busting the version
        cache, and the backup name already pins which snapshot was restored.
        """
        try:
            from safedep import audit_log
        except ImportError:
            return
        try:
            audit_log.write_update_entry(
                from_version=from_version, to_version=None,
                ref=f"backup:{backup_name}", sha=None, fallback=False,
                scopes=[{"global": g, "outcome": "rolled_back"} for g in restored_scopes],
                status="rolled_back",
            )
        except Exception:  # noqa: BLE001 — auditing must never break the rollback
            pass

    def _audit_update(self, plan, target, outcomes, status):
        """Record the update outcome to the audit log. Silent on any failure."""
        try:
            from safedep import audit_log
        except ImportError:
            return
        try:
            audit_log.write_update_entry(
                from_version=plan["installed"], to_version=target["version"],
                ref=target["ref"], sha=target["sha"], fallback=target["fallback"],
                scopes=[{"global": s["use_global"], "outcome": o} for s, o in outcomes],
                status=status,
            )
        except Exception:  # noqa: BLE001 — auditing must never break the update
            pass

    def _git_head_sha(self, repo_dir):
        """Return the HEAD commit SHA of the git repo at *repo_dir*."""
        r = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return r.stdout.strip()

    def _clone_verified(self, target):
        """Fresh-clone the resolved ref into a unique 0700 temp dir. Never reuse a path."""
        import tempfile, os
        clone_dir = tempfile.mkdtemp(prefix="sd-update-")   # unique per run
        os.chmod(clone_dir, 0o700)
        common = ["git", "-c", "protocol.file.allow=never"]
        try:
            if target["kind"] == "tag":
                subprocess.run(
                    common + ["clone", "--depth", "1", "--no-local",
                               "--branch", target["ref"],
                               _upstream_endpoints(self.repo_url)["clone_url"], clone_dir],
                    capture_output=True, text=True, check=True,
                )
                head = self._git_head_sha(clone_dir)
                if head != target["sha"]:
                    raise RuntimeError(
                        f"tag {target['ref']} HEAD {head} != resolved {target['sha']}"
                    )
            else:
                # main fallback: cloned HEAD is authoritative; do NOT abort on a moving-branch mismatch (#273)
                subprocess.run(
                    common + ["clone", "--depth", "1", "--no-local", "--branch", "main",
                               _upstream_endpoints(self.repo_url)["clone_url"], clone_dir],
                    capture_output=True, text=True, check=True,
                )
            return pathlib.Path(clone_dir)
        except subprocess.CalledProcessError as e:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise RuntimeError(f"clone failed: {e.stderr}") from e
        except Exception:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise

    def _detect_install_locations(self) -> List[str]:
        """Return human-readable labels for detected install locations.

        Checks the global bundle (``~/.claude/skills/safer-dependencies``) and the
        project-local bundle (``<cwd>/.claude/skills/safer-dependencies``) by
        existence. Returns an empty list when neither is present (e.g. running
        straight from a source checkout).
        """
        locations: List[str] = []
        global_dir = self.claude_dir / "skills" / "safer-dependencies"
        project_dir = self.project_claude_dir / "skills" / "safer-dependencies"
        if global_dir.exists():
            locations.append(f"global ({global_dir})")
        if project_dir.exists():
            locations.append(f"project ({project_dir})")
        return locations

    def _detect_installed_config(self) -> dict:
        """Return per-scope hook configuration for every installed scope.

        Checks both the global scope (``self.claude_dir``) and the project-local
        scope (``self.project_claude_dir``). A scope is included only when its
        ``skills/safer-dependencies`` bundle directory exists. If the companion
        ``settings.json`` is absent or unparseable the scope is still included but
        with all-False ``hook_selections`` and an empty ``existing_entries`` dict.

        Returns:
            ``{"scopes": [scope, ...]}`` where each scope dict has:
            - ``use_global`` (bool) — True for the global scope.
            - ``hook_selections`` (dict) — keys ``intercept``, ``pre_install``,
              ``post_install``, ``post_agent``; values bool.
            - ``existing_entries`` (dict) — ``{command_str: inner_hook_dict}`` for
              every safer-dependencies hook entry found (includes ``timeout`` etc.).
            - ``bundle_dir`` (pathlib.Path) — resolved bundle directory.
            - ``settings_file`` (pathlib.Path) — settings.json path (may not exist).
        """
        scopes = []
        for use_global, base in ((True, self.claude_dir), (False, self.project_claude_dir)):
            bundle = base / "skills" / "safer-dependencies"
            if not bundle.exists():
                continue
            settings_file = base / "settings.json"
            selections: Dict[str, bool] = {
                k: False for k in ("intercept", "pre_install", "post_install", "post_agent")
            }
            existing_entries: Dict[str, Any] = {}
            if settings_file.exists():
                try:
                    data = json.loads(settings_file.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    data = {}
                hooks_section = data.get("hooks")
                if not isinstance(hooks_section, dict):
                    hooks_section = {}
                for groups in hooks_section.values():
                    if not isinstance(groups, list):
                        continue
                    for group in groups:
                        for h in (group.get("hooks", []) if isinstance(group, dict) else []):
                            cmd = (h or {}).get("command", "")
                            if "safer-dependencies" not in cmd:
                                continue
                            existing_entries[cmd] = h
                            for script, key in _HOOK_BY_SCRIPT.items():
                                if script in cmd:
                                    selections[key] = True
            scopes.append({
                "use_global": use_global,
                "hook_selections": selections,
                "existing_entries": existing_entries,
                "bundle_dir": bundle,
                "settings_file": settings_file,
            })
        return {"scopes": scopes}

    def version_info(self) -> dict:
        """
        Gather version information for the ``version`` subcommand.

        Always reports the installed version (single source: ``safedep.version``)
        and any detected install locations. When the network is reachable, also
        reports the latest upstream version on ``main`` and whether an upgrade is
        available. ANY network/lookup failure degrades to installed-version-only
        and is reflected as ``latest=None`` — this method never raises.

        Returns:
            dict with keys: ``installed`` (str), ``locations`` (list[str]),
            ``latest`` (str | None), ``update_available`` (bool).
        """
        try:
            from safedep.version import resolve_version
        except ImportError:
            import sys as _sys
            _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from safedep.version import resolve_version

        installed = resolve_version()
        locations = self._detect_install_locations()

        target = _resolve_upstream_target()
        latest = target["version"] if target is not None else None
        update_available = bool(latest) and latest != installed

        return {
            "installed": installed,
            "locations": locations,
            "latest": latest,
            "update_available": update_available,
        }

    def plan_update(self, force=False):
        """
        Determine whether an update is needed and what the target would be.

        Returns a dict with keys:
            installed  - currently installed version string
            target     - upstream target dict (from _resolve_upstream_target) or None
            up_to_date - True only when reachable, not forced, and installed == target version
            fallback   - True when target was resolved via fallback (sha instead of tag)
            reachable  - True when upstream was reachable
        """
        try:
            from safedep.version import resolve_version
        except ImportError:
            import sys as _sys
            _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from safedep.version import resolve_version
        installed = resolve_version()
        target = _resolve_upstream_target()
        reachable = target is not None
        up_to_date = bool(not force and reachable and installed == target["version"])
        return {"installed": installed, "target": target, "up_to_date": up_to_date,
                "fallback": bool(reachable and target["fallback"]), "reachable": reachable}

    def _print_version_report(self, info: dict) -> None:
        """Print a human-readable version report to stdout."""
        print(f"safer-dependencies {info['installed']}")

        if info["locations"]:
            print("Installed at:")
            for loc in info["locations"]:
                print(f"  - {loc}")
        else:
            print("Installed at: (no installed bundle detected — running from source?)")

        latest = info.get("latest")
        if latest is None:
            print("Latest upstream: unavailable (offline or lookup failed)")
        elif info.get("update_available"):
            print(f"Latest upstream (main): {latest} — update available")
            print("  run /safer-dependencies update to upgrade")
        else:
            print(f"Latest upstream (main): {latest} — up to date")

        # The upgrade itself is performed by self_update.
        print("To upgrade, run /safer-dependencies update (self-update from upstream).")

    def generate_stats_report(self, window="7d", by_project=False, top_n=12):
        """
        Generate stats report for safer-dependencies usage.

        Args:
            window (str): Time window for stats (default: "7d")
            by_project (bool): also compute the per-project breakdown (ranked dashboard)
            top_n (int): projects to show before rolling up the remainder (by-project only)

        Returns:
            dict: Complete stats structure with activity, findings, performance, and ecosystem data
        """
        logs = self._read_audit_logs_in_window(window)

        report = {
            'window': window,
            'activity': self._analyze_activity(logs),
            'findings': self._analyze_findings(logs),
            'performance': self._analyze_performance(logs),
            'ecosystems': self._analyze_ecosystems(logs),
            'by_model': self._analyze_by_model(logs),
            'ecosystem_findings': self._analyze_ecosystem_findings(logs),
            'signal_types': self._analyze_signal_types(logs),
            'transitive': self._analyze_transitive(logs),
        }
        if by_project:
            report['by_project'] = self._analyze_by_project(logs, top_n)
        return report

    def validate_installation(self):
        """
        Validate the safer-dependencies installation.

        Returns:
            dict: Validation result with valid flag, issues list, and a
            warnings list (non-fatal coverage gaps — the install still works,
            but the user should know what it does NOT cover).
        """
        existing = self.detect_existing_setup()
        issues = []
        warnings = []

        # Check for skill file
        if not existing['skill_file']['global'] and not existing['skill_file']['project']:
            issues.append("No skill file found in global or project .claude/skills/safer-dependencies/")

        # Check for at least one hook
        hooks = existing['hooks']
        if not any(hook['global'] or hook['project'] for hook in hooks.values()):
            issues.append("No hooks installed")

        # Check for settings configuration if hooks are installed
        any_hooks_installed = any(hook['global'] or hook['project'] for hook in hooks.values())
        if any_hooks_installed:
            if not existing['settings_configured']['global'] and not existing['settings_configured']['project']:
                issues.append("Hooks installed but no settings.json configuration found")

        # Transitive-coverage guard (issue #205): Intercept and Pre-Install
        # only ever see top-level, declared packages. Lockfiles / the resolved
        # transitive tree are audited ONLY by Post-Install (Scan A) and
        # Post-Agent. An Intercept-only setup looks protected but has zero
        # transitive-CVE coverage — surface that, loudly but non-fatally.
        def _installed(name):
            h = hooks.get(name) or {}
            return bool(h.get('global') or h.get('project'))

        if (_installed('intercept') or _installed('pre_install')) and not _installed('post_install'):
            warnings.append(
                "Intercept/Pre-Install are enabled without Post-Install — "
                "transitive/lockfile CVEs will NOT be audited (Intercept and "
                "Pre-Install only see top-level declared packages). Install the "
                "Post-Install hook to close this gap."
            )
        if _installed('post_install') and not _installed('post_agent'):
            warnings.append(
                "Post-Agent hooks are not installed — manifests and lockfiles "
                "written by subagents bypass the other hooks and will not be "
                "audited."
            )

        # issue #3: surface an un-remediated over-broad curl rule so "check
        # setup" tells the user to re-run the installer (or remove it by hand).
        for scope_dir in (self.claude_dir, self.project_claude_dir):
            try:
                data = json.loads((scope_dir / "settings.json").read_text(encoding="utf-8"))
                allow = data.get("permissions", {}).get("allow", [])
            except (OSError, json.JSONDecodeError, AttributeError):
                continue
            if self.LEGACY_MARKER in allow:
                warnings.append(
                    "settings.json still contains the over-broad rule "
                    "'Bash(curl -s --max-time 10 *)' (issue #3) — it pre-approves "
                    "curl to any host. Re-run the installer or 'update "
                    "safer-dependencies' to remove it, or delete it by hand."
                )
                break

        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings
        }

    def _read_audit_logs_in_window(self, window: str) -> List[Dict[str, Any]]:
        """
        Read audit logs within the specified time window.

        Args:
            window (str): Time window like "7d", "30d"

        Returns:
            List[Dict]: List of parsed audit log entries within the window
        """
        # Parse window to days
        days_match = re.match(r'^(\d+)d$', window)
        if not days_match:
            return []

        days = int(days_match.group(1))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        logs = []

        # Get log paths - try SAFE_DEP_AUDIT_LOG or monthly pattern
        log_paths = self._get_audit_log_paths(days)

        for log_path in log_paths:
            if not os.path.exists(log_path):
                continue

            try:
                with open(log_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            entry = json.loads(line)

                            # Parse timestamp and filter by window
                            if 'ts' not in entry:
                                continue

                            try:
                                ts = datetime.fromisoformat(entry['ts'].replace('Z', '+00:00'))
                                if ts >= cutoff:
                                    logs.append(entry)
                            except (ValueError, TypeError):
                                continue  # Skip malformed timestamps

                        except json.JSONDecodeError:
                            continue  # Skip malformed JSON lines

            except OSError:
                continue  # Skip unreadable files

        return logs

    def _get_audit_log_paths(self, days: int) -> List[str]:
        """Get list of audit log paths to check for the given time window."""
        paths = []

        # Check environment override first
        env_path = os.environ.get('SAFE_DEP_AUDIT_LOG')
        if env_path:
            paths.append(env_path)
        else:
            # Enumerate calendar months between cutoff and now. Stepping by
            # 30-day deltas skipped whole months (months are 28-31 days), so
            # e.g. a 120-day window ending May 31 never read the February log
            # and silently under-reported stats.
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(days=days)
            year, month = cutoff.year, cutoff.month
            while (year, month) <= (now.year, now.month):
                ym = f"{year:04d}-{month:02d}"
                log_path = os.path.join(
                    os.path.expanduser("~"),
                    ".claude",
                    f"safer-dependencies-audit-{ym}.log"
                )
                paths.append(log_path)
                month += 1
                if month == 13:
                    month = 1
                    year += 1

        return paths

    def _analyze_activity(self, logs: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Analyze activity metrics from audit logs.

        Args:
            logs: List of audit log entries

        Returns:
            Dict with total_audits, intercept_mode, pre_install, post_install counts
        """
        total_audits = len(logs)
        intercept_mode = 0
        pre_install = 0
        post_install = 0
        manual = 0

        for entry in logs:
            source = entry.get('source', {})
            component = source.get('component', '')

            if component == 'shim.posttooluse':
                intercept_mode += 1
            elif component == 'bash.pretooluse':
                pre_install += 1
            elif component in ('bash.posttooluse', 'agent.posttooluse'):
                post_install += 1
            elif component == 'manual.skill':
                manual += 1

        return {
            'total_audits': total_audits,
            'intercept_mode': intercept_mode,
            'pre_install': pre_install,
            'post_install': post_install,
            'manual': manual,
        }

    def _analyze_findings(self, logs: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Analyze security findings from audit logs.

        Args:
            logs: List of audit log entries

        Returns:
            Dict with packages_updated, cves_blocked, major_bumps_flagged counts
        """
        packages_updated = 0
        cves_blocked = 0
        major_bumps_flagged = 0

        for entry in logs:
            # Check both 'signals' and 'findings' fields for backward compatibility
            findings = entry.get('signals', []) or entry.get('findings', [])

            for finding in findings:
                finding_str = str(finding).upper()
                if 'UPDATED:' in finding_str:
                    packages_updated += 1
                if any(term in finding_str for term in ['CVE', 'GHSA', 'VULNERABILITY']):
                    cves_blocked += 1
                if 'REFACTOR-REQUIRED' in finding_str or 'MAJOR-UPDATE' in finding_str:
                    major_bumps_flagged += 1

        abandoned_blocked = sum(len(entry.get('abandoned', [])) for entry in logs)
        typosquats_detected = sum(len(entry.get('typosquat', [])) for entry in logs)

        return {
            'packages_updated': packages_updated,
            'cves_blocked': cves_blocked,
            'major_bumps_flagged': major_bumps_flagged,
            'abandoned_blocked': abandoned_blocked,
            'typosquats_detected': typosquats_detected,
        }

    def _analyze_performance(self, logs: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Analyze performance metrics from audit logs.

        Args:
            logs: List of audit log entries

        Returns:
            Dict with avg_duration_ms, fail_open_count
        """
        durations = []
        fail_open_count = 0

        for entry in logs:
            # Collect duration data
            duration_ms = entry.get('duration_ms')
            if duration_ms is not None and isinstance(duration_ms, (int, float)):
                durations.append(duration_ms)

            # Count fail-open scenarios (install errors)
            source = entry.get('source', {})
            if source.get('component') == 'shim.install_error':
                fail_open_count += 1

        avg_duration_ms = int(sum(durations) / len(durations)) if durations else 0

        return {
            'avg_duration_ms': avg_duration_ms,
            'fail_open_count': fail_open_count
        }

    def _analyze_ecosystems(self, logs: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Analyze ecosystem distribution from audit logs.

        Args:
            logs: List of audit log entries

        Returns:
            Dict mapping ecosystem names to counts
        """
        ecosystems = {}

        for entry in logs:
            ecosystem = entry.get('ecosystem')
            if ecosystem:
                eco = _normalize_ecosystem(ecosystem)
                ecosystems[eco] = ecosystems.get(eco, 0) + 1

        return ecosystems

    def _analyze_by_model(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Aggregate audit counts and entries-with-findings counts grouped by model name."""
        model_data: Dict[str, Dict[str, int]] = {}
        for entry in logs:
            model = entry.get('source', {}).get('model', 'unknown')
            if model not in model_data:
                model_data[model] = {'audits': 0, 'findings_count': 0}
            model_data[model]['audits'] += 1
            if entry.get('signals') or entry.get('findings'):
                model_data[model]['findings_count'] += 1
        return sorted(
            [{'model': m, 'audits': d['audits'], 'findings_count': d['findings_count']}
             for m, d in model_data.items()],
            key=lambda x: -x['findings_count'],
        )

    def _analyze_ecosystem_findings(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return per-ecosystem finding counts and top flagged packages, sorted by finding count."""
        eco_data: Dict[str, Dict] = {}
        for entry in logs:
            ecosystem = entry.get('ecosystem')
            if not ecosystem:
                continue
            findings = entry.get('signals', []) or entry.get('findings', [])
            if not findings:
                continue
            eco = _normalize_ecosystem(ecosystem)
            if eco not in eco_data:
                eco_data[eco] = {'count': 0, 'packages': {}}
            ecosystem = eco
            eco_data[ecosystem]['count'] += 1
            for f in findings:
                parts = f.split()
                if len(parts) >= 2:
                    pkg = parts[1].split('@')[0]
                    if pkg:
                        eco_data[ecosystem]['packages'][pkg] = \
                            eco_data[ecosystem]['packages'].get(pkg, 0) + 1
        result = []
        for eco, data in sorted(eco_data.items(), key=lambda x: -x[1]['count']):
            top_pkgs = [p for p, _ in sorted(
                data['packages'].items(), key=lambda x: -x[1])[:_TOP_PACKAGES_LIMIT]]
            result.append({
                'ecosystem': eco,
                'findings': data['count'],
                'top_packages': top_pkgs,
            })
        return result

    def _analyze_by_project(self, logs: List[Dict[str, Any]], top_n: int = 12) -> Dict[str, Any]:
        """Aggregate audit-log entries into per-project statistics.

        Delegates to :func:`safedep.projects.aggregate_projects`, which derives a
        project identity from each entry's ``file`` path. Entries with no project
        (Pre-Install ``bash:<command>`` denials) are counted as non-attributable,
        never invented as a project; every project kind — including the collapsed
        self-test temp-dir bucket — is shown, classified, never excluded.
        """
        return aggregate_projects(logs, top_n=top_n)

    def _print_stats_report(self, report: Dict[str, Any]) -> None:
        """
        Print a human-readable stats report to stdout.

        Args:
            report: Stats report dict from generate_stats_report()
        """
        window = report.get('window', '7d')
        activity = report.get('activity', {})
        findings = report.get('findings', {})
        performance = report.get('performance', {})
        ecosystems = report.get('ecosystems', {})
        by_model = report.get('by_model', [])
        ecosystem_findings = report.get('ecosystem_findings', [])
        signal_types = report.get('signal_types', {})
        transitive = report.get('transitive', {})

        # Label width must match across all sections (longest label = "By Ecosystem:")
        label_width = 16  # "By Ecosystem:   " aligns with "Activity:       " etc.

        def _label(name):
            return name.ljust(label_width)

        print(f"\nSafer Dependencies Stats ({window}):\n")

        # Activity section
        total = activity.get('total_audits', 0)
        intercept = activity.get('intercept_mode', 0)
        pre = activity.get('pre_install', 0)
        post = activity.get('post_install', 0)
        manual = activity.get('manual', 0)
        print(f"  {_label('Activity:')}{total} total audits")
        print(f"  {' ' * label_width}{intercept} intercept | {pre} pre-install | {post} post-install | {manual} manual")
        print()

        # Findings section
        cves = findings.get('cves_blocked', 0)
        updated = findings.get('packages_updated', 0)
        major = findings.get('major_bumps_flagged', 0)
        abandoned = findings.get('abandoned_blocked', 0)
        typosquats = findings.get('typosquats_detected', 0)
        print(f"  {_label('Findings:')}{cves} CVEs blocked")
        print(f"  {' ' * label_width}{updated} packages updated")
        print(f"  {' ' * label_width}{major} major-version refactors flagged")
        print(f"  {' ' * label_width}{abandoned} abandoned packages blocked")
        print(f"  {' ' * label_width}{typosquats} typosquats detected")
        print()

        # By Ecosystem (total audits) — existing section
        if ecosystems:
            sorted_ecos = sorted(ecosystems.items(), key=lambda x: -x[1])
            first = True
            for eco, count in sorted_ecos:
                if first:
                    print(f"  {_label('By Ecosystem:')}{eco:<10} {count} audits")
                    first = False
                else:
                    print(f"  {' ' * label_width}{eco:<10} {count} audits")
            print()

        # By Ecosystem (findings) — new section
        if ecosystem_findings:
            first = True
            for row in ecosystem_findings:
                eco = row.get('ecosystem', '')
                count = row.get('findings', 0)
                pkgs = row.get('top_packages', [])
                pkgs_str = f"  ({', '.join(pkgs)})" if pkgs else ""
                line = f"{eco:<10} {count} findings{pkgs_str}"
                if first:
                    print(f"  {_label('Eco Findings:')}{line}")
                    first = False
                else:
                    print(f"  {' ' * label_width}{line}")
            print()

        # By Model section — new section
        non_unknown = [m for m in by_model if m.get('model', 'unknown') != 'unknown']
        if non_unknown:
            first = True
            for row in non_unknown:
                model_name = row.get('model', '')
                fc = row.get('findings_count', 0)
                audits = row.get('audits', 0)
                line = f"{model_name:<12} {fc} findings | {audits} audits"
                if first:
                    print(f"  {_label('By Model:')}{line}")
                    first = False
                else:
                    print(f"  {' ' * label_width}{line}")
            print()

        # Signal Types section
        if signal_types and any(signal_types.values()):
            signal_labels = [
                ('UPDATED:', 'updated'),
                ('BLOCKED:', 'blocked'),
                ('STALE:', 'stale'),
                ('MAJOR-UPDATE-CONFIRM:', 'major-version bumps'),
                ('TYPOSQUAT-CONFIRM:', 'typosquats'),
                ('UNKNOWN:', 'unknown packages'),
                ('SIGNATURE:', 'signature warnings'),
            ]
            first = True
            for key, label in signal_labels:
                count = signal_types.get(key, 0)
                if count == 0:
                    continue
                if first:
                    print(f"  {_label('Signals:')}{count:>6}  {label}")
                    first = False
                else:
                    print(f"  {' ' * label_width}{count:>6}  {label}")
            if not first:
                print()

        # Transitive coverage section (issue #245) — computed from schema-2.2
        # lockfile entries; older logs simply show "no lockfile audits".
        lockfile_audits = transitive.get('lockfile_audits', 0)
        if lockfile_audits:
            direct = transitive.get('direct_checked', 0)
            trans = transitive.get('transitive_checked', 0)
            unk = transitive.get('unknown_checked', 0)
            t_findings = transitive.get('transitive_findings', 0)
            print(f"  {_label('Transitive:')}{lockfile_audits} lockfile audits")
            unk_str = f" | {unk} unknown" if unk else ""
            print(f"  {' ' * label_width}{direct} direct | {trans} transitive{unk_str} pkgs checked")
            print(f"  {' ' * label_width}{t_findings} transitive findings")
            top = transitive.get('top_flagged_transitive', [])
            if top:
                top_str = ", ".join(f"{row['package']} ({row['count']})" for row in top)
                print(f"  {' ' * label_width}top flagged: {top_str}")
        else:
            print(f"  {_label('Transitive:')}no lockfile audits recorded yet")
        print()

        # Performance section
        avg_ms = performance.get('avg_duration_ms', 0)
        print(f"  {_label('Performance:')}{avg_ms}ms avg duration")
        print()

    def _render_by_project(self, report: Dict[str, Any]) -> str:
        """Render the ranked per-project dashboard as a string.

        One row per project sorted by audits, a ``+N more`` rollup of the
        remainder, a GRAND TOTAL footer, and a footnote accounting for the
        non-attributable Pre-Install Bash denials. Column widths adapt to the
        data so the table always aligns (a 7-digit, comma-formatted count never
        overflows its column); the project label is capped at 24 chars.
        """
        agg = report.get('by_project') or {}
        window = report.get('window', '')
        top = agg.get('projects_top', [])
        roll = agg.get('more_rollup', {}) or {}
        gt = agg.get('grand_totals', {}) or {}
        distinct = agg.get('distinct_projects', 0)
        non_attr = agg.get('non_attributable', 0)

        LBL_CAP = 24

        def trunc(s: Any) -> str:
            s = str(s)
            return s if len(s) <= LBL_CAP else s[:LBL_CAP - 1] + '…'

        def fmt(n: Any) -> str:
            try:
                return f"{int(n):,}"
            except (TypeError, ValueError):
                return str(n)

        # Column order; the four count columns are right-aligned.
        ORDER = ['glyph', 'label', 'kind', 'aud', 'fnd', 'cve', 'upd', 'eco', 'last']
        RIGHT = {'aud', 'fnd', 'cve', 'upd'}
        header = {'glyph': '', 'label': 'PROJECT', 'kind': 'KIND', 'aud': 'AUDITS',
                  'fnd': 'FINDINGS', 'cve': 'CVEs', 'upd': 'UPDATED',
                  'eco': 'TOP-ECO', 'last': 'LAST-SEEN'}

        def drow(glyph, label, kind, aud, fnd, cve, upd, eco, last) -> Dict[str, str]:
            return {'glyph': glyph, 'label': trunc(label), 'kind': str(kind),
                    'aud': fmt(aud), 'fnd': fmt(fnd), 'cve': fmt(cve), 'upd': fmt(upd),
                    'eco': str(eco or '—'), 'last': str(last or '—')}

        data_rows = [
            drow('●' if p.get('kind') == 'repo' else '◌', p.get('label', ''), p.get('kind', ''),
                 p.get('audits', 0), p.get('findings', 0), p.get('cves', 0), p.get('updated', 0),
                 p.get('top_ecosystem'), p.get('last_active'))
            for p in top
        ]
        rollup_row = None
        if roll.get('count'):
            rollup_row = drow('+', f"{fmt(roll['count'])} more projects", 'mixed',
                              roll.get('audits', 0), roll.get('findings', 0),
                              roll.get('cves', 0), roll.get('updated', 0), None, None)
        grand_row = drow(' ', f"GRAND TOTAL ({fmt(gt.get('projects', 0))} proj)", 'ALL',
                         gt.get('audits', 0), gt.get('findings', 0),
                         gt.get('cves', 0), gt.get('updated', 0), None, None)

        # Column widths adapt to the data so the table always aligns, regardless of
        # number magnitude (a 7-digit comma-formatted count won't overflow its column).
        all_rows = [header] + data_rows + ([rollup_row] if rollup_row else []) + [grand_row]
        w = {c: max(len(r[c]) for r in all_rows) for c in ORDER}
        w['glyph'] = 1

        def render(d: Dict[str, str]) -> str:
            return ' '.join(
                (f"{d[c]:>{w[c]}}" if c in RIGHT else f"{d[c]:<{w[c]}}")
                for c in ORDER
            )

        width = len(render(header))
        rule, heavy = '─' * width, '━' * width

        lines = [
            rule,
            f"safer-dependencies · audits by project    {fmt(distinct)} projects    {window}"[:width],
            rule,
            render(header),
            rule,
        ]
        lines += [render(r) for r in data_rows]
        if rollup_row:
            lines += [rule, render(rollup_row)]
        lines += [heavy, render(grand_row), heavy]
        lines.append(
            f"  also flagged: {fmt(gt.get('abandoned', 0))} abandoned · "
            f"{fmt(gt.get('typosquat', 0))} typosquat · {fmt(gt.get('stale', 0))} stale · "
            f"{fmt(gt.get('pkgs_checked', 0))} pkgs checked")
        lines.append("  Note: ·self-tests = test-suite temp dirs (collapsed); shown, never dropped.")
        total_entries = gt.get('audits', 0) + non_attr
        lines.append(
            f"  footnote: +{fmt(non_attr)} non-attributable audits "
            f"(Pre-Install Bash denials, no project path).")
        lines.append(
            f"            {fmt(total_entries)} log entries = "
            f"{fmt(gt.get('audits', 0))} attributable + {fmt(non_attr)} not.")
        return "\n".join(lines)

    def _print_by_project(self, report: Dict[str, Any]) -> None:
        """Print the ranked per-project dashboard to stdout."""
        print()
        print(self._render_by_project(report))
        print()

    def _analyze_signal_types(self, logs: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count occurrences of each signal-type prefix across all log entries."""
        prefixes = [
            'UPDATED:', 'BLOCKED:', 'STALE:', 'TYPOSQUAT-CONFIRM:',
            'MAJOR-UPDATE-CONFIRM:', 'UNKNOWN:', 'SIGNATURE:',
        ]
        counts: Dict[str, int] = {p: 0 for p in prefixes}
        for entry in logs:
            for f in (entry.get('signals', []) or entry.get('findings', [])):
                for prefix in prefixes:
                    if f.startswith(prefix):
                        counts[prefix] += 1
                        break
        return counts

    def _analyze_transitive(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Transitive-coverage metrics from schema-2.2 lockfile entries (issue #245).

        Aggregates the ``relation_summary`` blocks written by the shim's
        lockfile path. Entries without ``"lockfile": true`` (all pre-2.2
        entries and every manifest audit) are skipped, so old logs remain
        readable and simply report zero lockfile audits.
        """
        lockfile_audits = 0
        direct = transitive = unknown = flagged = 0
        pkg_counts: Dict[str, int] = {}

        def _count(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        for entry in logs:
            if not entry.get('lockfile'):
                continue
            lockfile_audits += 1
            summary = entry.get('relation_summary') or {}
            if not isinstance(summary, dict):
                continue
            direct += _count(summary.get('direct_checked'))
            transitive += _count(summary.get('transitive_checked'))
            unknown += _count(summary.get('unknown_checked'))
            flagged += _count(summary.get('transitive_flagged'))
            for token in summary.get('transitive_flagged_pkgs') or []:
                if not isinstance(token, str) or not token:
                    continue
                # pkg@ver → pkg (scoped npm names keep their @scope/ prefix)
                if token.startswith('@'):
                    pkg = '@' + token[1:].split('@', 1)[0]
                else:
                    pkg = token.split('@', 1)[0]
                if pkg:
                    pkg_counts[pkg] = pkg_counts.get(pkg, 0) + 1

        top_flagged = [
            {'package': pkg, 'count': count}
            for pkg, count in sorted(pkg_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        ]
        return {
            'lockfile_audits': lockfile_audits,
            'direct_checked': direct,
            'transitive_checked': transitive,
            'unknown_checked': unknown,
            'transitive_findings': flagged,
            'top_flagged_transitive': top_flagged,
        }

    def _check_skill_file_locations(self):
        """
        Check for skill file in global and project locations.

        Returns:
            dict: Global and project skill file status
        """
        global_skill = self.claude_dir / "skills" / "safer-dependencies" / "SKILL.md"
        project_skill = self.project_claude_dir / "skills" / "safer-dependencies" / "SKILL.md"

        return {
            'global': global_skill.exists(),
            'project': project_skill.exists()
        }

    def _check_hook_installed(self, hook_filename):
        """
        Check if a hook is installed and executable.

        Args:
            hook_filename (str): Name of the hook file

        Returns:
            dict: Global and project hook installation status
        """
        global_hook = self.claude_dir / "skills" / "safer-dependencies" / hook_filename
        project_hook = self.project_claude_dir / "skills" / "safer-dependencies" / hook_filename

        return {
            'global': global_hook.exists() and global_hook.is_file(),
            'project': project_hook.exists() and project_hook.is_file()
        }

    def _check_paired_hooks(self, *hook_filenames):
        """Detect a hook that ships as a pair of scripts (e.g. Post-Agent).

        Returns ``{'global': bool, 'project': bool}`` where the flag is True
        only when ALL named files are present in that location. Used so a
        half-installed pair (one file present, one missing) reads as "not
        installed" — re-running the installer will then restore the pair.
        """
        per_file = [self._check_hook_installed(name) for name in hook_filenames]
        return {
            'global':  all(r['global']  for r in per_file),
            'project': all(r['project'] for r in per_file),
        }

    def _check_settings_json(self):
        """
        Check for settings.json configuration.

        Returns:
            dict: Global and project settings configuration status
        """
        global_settings = self.claude_dir / "settings.json"
        project_settings = self.project_claude_dir / "settings.json"

        return {
            'global': global_settings.exists(),
            'project': project_settings.exists()
        }

    def _check_permissions(self):
        """
        Check whether the required Bash allowlist entries are present in settings.json.

        Returns:
            dict with keys:
                configured: True if all required entries are present in either location
                global: True if global settings.json contains the full required allowlist
                project: True if project settings.json contains the full required allowlist
        """
        def _has_all(settings_path: Path) -> bool:
            if not settings_path.exists():
                return False
            try:
                data = json.loads(settings_path.read_text())
            except (json.JSONDecodeError, OSError):
                return False
            allow = data.get('permissions', {}).get('allow', [])
            return all(cmd in allow for cmd in self.REQUIRED_PERMISSIONS)

        global_ok = _has_all(self.claude_dir / "settings.json")
        project_ok = _has_all(self.project_claude_dir / "settings.json")
        return {
            'configured': global_ok or project_ok,
            'global': global_ok,
            'project': project_ok,
        }

    def _display_installation_header(self, existing):
        """
        Display installation header without prompting for scope.

        Args:
            existing (dict): Current installation state
        """
        print("\nSafer Dependencies Installation")
        print("="*50)

        if existing['skill_file']['global'] or existing['skill_file']['project']:
            print("Existing installation detected. Configuring additional components...")

    def _prompt_for_scope(self):
        """Ask the user whether to install globally or only into this project.

        Default is global (#149): a project-only install means the user has
        zero protection on any project where they forget to set up safer-
        dependencies. The audit log is already global, so global hook +
        global log is the most coherent default for individual users.
        Project install is still offered explicitly for team/CI use cases
        where the hooks should ride along in ``.claude/settings.json``.

        Returns:
            bool: True for global install, False for project-level install.
        """
        print("\nInstallation Scope")
        print("=" * 50)
        print("Install safer-dependencies for:")
        print("  [G] Global   — all your Claude Code sessions (recommended)")
        print("  [P] Project  — only this project (team-shared via .claude/)")
        print()

        while True:
            choice = input("Scope [G/p]: ").strip().lower()
            if choice == "" or choice in ("g", "global"):
                return True
            if choice in ("p", "project"):
                return False
            print("   Please enter 'G' for global or 'P' for project.")

    def _prompt_for_hooks(self):
        """
        Present hook options with exact spec descriptions and get user selections.
        Smart defaults: Intercept=Yes, Pre-Install=Yes, Post-Install=Yes, Post-Agent=Yes.

        Post-Install previously defaulted to "prompt explicitly" (no smart-default).
        That predated Scan B (issue #23, commit f8f4ba4), which made the hook the
        only fallback for manifest edits performed via Bash (sed/jq/python scripts)
        that bypass the Intercept Write/Edit hook. With Scan B in place the hook
        is load-bearing, not optional — so the default flipped to ON.

        Returns:
            dict: Hook selections with boolean values for intercept, pre_install, post_install
        """
        print("\nHook Configuration")
        print("="*50)
        print("Safer Dependencies can install hooks to automatically check dependencies.")
        print("Each hook provides different levels of protection with varying performance impact.\n")

        # Exact descriptions from spec lines 100-104
        hooks = {
            'intercept': {
                'name': 'Intercept Mode',
                'description': 'After Claude writes a manifest, audits and rewrites vulnerable versions in place',
                'cost': '~2–5s per manifest edit',  # en-dash, not hyphen
                'default': True  # Install by default (Yes)
            },
            'pre_install': {
                'name': 'Pre-Install Mode',
                'description': 'Checks package pins against OSV before fetch, denies vulnerable installs',
                'cost': '~250ms for non-PM commands; ~1–2s for installs',  # en-dash, not hyphen
                'default': True  # Install by default (Yes)
            },
            'post_install': {
                'name': 'Post-Install Mode',
                'description': 'After Bash commands: audits freshly-modified lockfiles (transitive CVEs after installs) and manifests edited via sed/jq/scripts (fallback for edits that bypass Intercept)',
                'cost': '~100–250ms early-filter on most Bash calls; ~1–3s when a fresh lockfile or manifest is detected',  # en-dash, not hyphen
                'default': True  # Install by default (Yes) — Scan B makes this load-bearing, not optional
            },
            'post_agent': {
                'name': 'Post-Agent Mode',
                'description': 'Re-audits manifests/lockfiles after subagent calls return — subagents bypass the other hooks (issue #147)',
                'cost': '~10ms sentinel touch per Agent call; ~0–3s if a subagent wrote a manifest',  # en-dash
                'default': True  # Install by default (Yes): the reactive safety net for subagent writes
            }
        }

        selections = {}

        for hook_key, hook_info in hooks.items():
            print(f"📋 {hook_info['name']}")
            print(f"   What: {hook_info['description']}")
            print(f"   Cost: {hook_info['cost']}")

            if hook_info['default'] is not None:
                default_text = "Y/n" if hook_info['default'] else "y/N"
                prompt = f"   Install {hook_info['name']}? [{default_text}]: "
            else:
                prompt = f"   Install {hook_info['name']}? [y/N]: "

            while True:
                choice = input(prompt).lower().strip()

                if choice == '':
                    # Use default if available
                    if hook_info['default'] is not None:
                        selections[hook_key] = hook_info['default']
                        break
                    else:
                        selections[hook_key] = False  # Default to No for post-install
                        break
                elif choice in ['y', 'yes']:
                    selections[hook_key] = True
                    break
                elif choice in ['n', 'no']:
                    selections[hook_key] = False
                    break
                else:
                    print("   Please enter 'y' for yes or 'n' for no.")

            print()

        return selections

    def _installed_skill_path(self):
        """Return the path of the installed SKILL.md (global preferred, then project)."""
        g = self.claude_dir / "skills" / "safer-dependencies" / "SKILL.md"
        p = self.project_claude_dir / "skills" / "safer-dependencies" / "SKILL.md"
        return g if g.exists() else p

    def _health_check(self, installed_manager, bundle_dir=None):
        """True only if the install is real: validate passes, manager runs, frontmatter is non-placeholder.

        When *bundle_dir* is provided the placeholder-text check reads
        ``bundle_dir / "SKILL.md"`` — the scope being validated — rather than
        the global-preferred path from ``_installed_skill_path()``.  This fixes
        the dual-scope gap (issue #299): without this, a project-scope
        placeholder would be invisible if a healthy global install existed.
        """
        import subprocess as _sp
        import sys as _sys
        if not self.validate_installation()["valid"]:
            return False
        if bundle_dir is not None:
            skill = bundle_dir / "SKILL.md"
            if not skill.exists():
                # The scope is installed (validate_installation passed) but this
                # bundle is missing SKILL.md — its core shipped artifact. That is
                # a broken/corrupt install, not a healthy one (issue #299 handled
                # placeholder *text* but an absent file fell through to "healthy"
                # because empty text contains no placeholder sentinel).
                return False
        else:
            skill = self._installed_skill_path()
        try:
            text = skill.read_text(encoding="utf-8") if skill and skill.exists() else ""
        except OSError:
            return False
        if "version: Alpha 1.0" in text or "Placeholder" in text:
            return False
        try:
            r = _sp.run([_sys.executable, str(installed_manager), "version"],
                        capture_output=True, text=True, timeout=20)
            return r.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    def _install_skill_file(self, use_global, allow_placeholder=True):
        """
        Install the main skill file.

        Args:
            use_global (bool): Whether to install globally
            allow_placeholder (bool): If False and source file is missing, raise instead
                of writing a placeholder stub. Set to False during updates so a working
                install is never silently downgraded to an inert placeholder.

        Returns:
            list: List of installed components
        """
        # Find the source skill file (self._source_dir is the configurable root —
        # the local checkout's skills/ by default, or a verified clone's skills/
        # during self_update).
        source_skill = self._source_dir / "safer-dependencies.md"

        # Determine target location
        if use_global:
            target_dir = self.claude_dir / "skills" / "safer-dependencies"
        else:
            target_dir = self.project_claude_dir / "skills" / "safer-dependencies"

        target_skill = target_dir / "SKILL.md"

        # Create directory if needed
        target_dir.mkdir(parents=True, exist_ok=True)

        # Copy skill file if source exists, otherwise create a placeholder
        if source_skill.exists():
            shutil.copy2(source_skill, target_skill)
        elif allow_placeholder:
            # Create a placeholder skill file
            placeholder_content = """---
name: safer-dependencies
version: Alpha 1.0
description: Security audit for package dependencies (installed via interactive setup)
---

# Safer Dependencies Skill

This skill was installed via the interactive installation process.
The full skill implementation should be available in your safer-dependencies installation.
"""
            target_skill.write_text(placeholder_content, encoding="utf-8")
        else:
            raise RuntimeError(f"source file missing: {source_skill}")

        return ["SKILL.md"]

    def _install_hooks(self, selections, use_global, allow_placeholder=True):
        """
        Install selected hook files.

        Args:
            selections (dict): Hook selections from _prompt_for_hooks
            use_global (bool): Whether to install globally
            allow_placeholder (bool): If False and a source hook is missing, raise instead
                of writing a placeholder stub. Set to False during updates so a working
                install is never silently downgraded to an inert placeholder.

        Returns:
            dict: Result with copied_files list
        """
        # Map selections to actual hook files. Post-Agent ships as a paired
        # PreToolUse+PostToolUse hook (sentinel + scan), so its entry holds
        # both filenames — _install_hooks iterates the tuple to copy each.
        hook_files = {
            'intercept':    ('safer-dependencies-shim.sh',),
            'pre_install':  ('safer-dependencies-pretooluse-bash.sh',),
            'post_install': ('safer-dependencies-posttooluse-bash.sh',),
            'post_agent':   ('safer-dependencies-pretooluse-agent.sh',
                             'safer-dependencies-posttooluse-agent.sh'),
        }

        # Determine target directory
        if use_global:
            target_dir = self.claude_dir / "skills" / "safer-dependencies"
        else:
            target_dir = self.project_claude_dir / "skills" / "safer-dependencies"

        # Create directory if needed
        target_dir.mkdir(parents=True, exist_ok=True)

        copied_files = []
        source_dir = self._source_dir

        for hook_key, selected in selections.items():
            if not selected:
                continue
            if hook_key not in hook_files:
                # Forward-compat: unknown hook keys are silently ignored so a
                # caller passing an extended selections dict doesn't crash.
                continue

            for hook_filename in hook_files[hook_key]:
                source_file = source_dir / hook_filename
                target_file = target_dir / hook_filename

                if source_file.exists():
                    # Copy actual hook file
                    shutil.copy2(source_file, target_file)
                    os.chmod(target_file, 0o755)
                elif allow_placeholder:
                    # Create placeholder hook file
                    placeholder_content = f"""#!/bin/bash
# {hook_filename} - installed via interactive setup
# This is a placeholder - the actual hook implementation should be provided
# by your safer-dependencies installation.

echo "Placeholder hook: {hook_filename}"
exit 0
"""
                    target_file.write_text(placeholder_content, encoding="utf-8")
                    os.chmod(target_file, 0o755)
                else:
                    raise RuntimeError(f"source file missing: {source_file}")

                copied_files.append(str(target_file))

        # Always re-sync scripts/ and references/ — both are referenced by SKILL.md
        # (registry-query helpers and the per-mode reference docs respectively),
        # not by hooks alone, so they must land on disk even for skill-only installs.
        for asset in ("scripts", "references"):
            asset_source = source_dir / asset
            asset_target = target_dir / asset
            if asset_source.exists():
                if asset_target.exists():
                    shutil.rmtree(asset_target)
                shutil.copytree(asset_source, asset_target)
                copied_files.append(str(asset_target))

        # Prune superseded legacy artifacts the current bundle no longer ships.
        # Old installs shipped the monolithic shim as ``shim.sh``; an in-place
        # update copies the new files but would otherwise leave that orphan
        # behind, where it shadowed the canonical ``safer-dependencies-shim.sh``
        # in the bash hook (running outdated audit code) and is dead weight even
        # after the hook's preference was flipped. Only prune once the canonical
        # shim is present on disk, so a malformed bundle never deletes the only
        # shim. self_update reaches this via apply_install -> _install_hooks.
        canonical_shim = target_dir / "safer-dependencies-shim.sh"
        if canonical_shim.exists():
            legacy_names = ["shim.sh"] + sorted(
                p.name for p in target_dir.glob("shim.sh.bak-*")
            )
            for legacy_name in legacy_names:
                legacy_path = target_dir / legacy_name
                if legacy_path.exists() and legacy_path.resolve() != canonical_shim.resolve():
                    try:
                        legacy_path.unlink()
                        copied_files.append(f"removed:{legacy_path}")
                    except OSError:
                        pass

        return {
            'copied_files': copied_files
        }

    def _configure_settings(self, selections, use_global, existing_entries=None):
        """
        Generate and merge settings.json configuration for selected hooks.

        Args:
            selections (dict): Hook selections
            use_global (bool): Whether configuring global settings
            existing_entries (dict | None): ``{command_str: inner_hook_dict}`` from Task 5
                _detect_installed_config. Non-command fields (e.g. timeout) are carried
                forward onto freshly-generated hook entries whose command path matches.

        Returns:
            dict: Settings configuration with updated flag
        """
        # Determine settings file location
        if use_global:
            settings_file = self.claude_dir / "settings.json"
            scripts_path = "${HOME}/.claude/skills/safer-dependencies"
        else:
            settings_file = self.project_claude_dir / "settings.json"
            scripts_path = "${CLAUDE_PROJECT_DIR}/.claude/skills/safer-dependencies"

        # Load existing settings or create new
        existing_settings = {}
        if settings_file.exists():
            try:
                existing_settings = json.loads(settings_file.read_text())
            except (json.JSONDecodeError, OSError):
                existing_settings = {}

        # Generate new hook configuration
        new_config = self._generate_hook_config(selections, scripts_path)

        # Merge-forward per-entry non-command fields (e.g. user-customized timeout)
        # from existing_entries onto the freshly-generated hooks, matched by command path.
        if existing_entries:
            for hook_type, groups in new_config['hooks'].items():
                for group in groups:
                    for h in group.get('hooks', []):
                        prior = existing_entries.get(h.get('command'))
                        if prior:
                            for k, v in prior.items():
                                if k != 'command':  # carry forward timeout + any extra fields
                                    h[k] = v

        # Initialize or update hooks section
        if 'hooks' not in existing_settings:
            existing_settings['hooks'] = {}

        # Remove any *previously-installed* safer-dependencies hooks so a re-install
        # doesn't accumulate duplicates — but preserve everything else. A matcher
        # group can legitimately contain a safer-deps hook AND a third-party hook
        # (e.g. a pr-quality-gate.py) in the same `hooks` array; dropping the whole
        # group to clear our entry would silently delete the user's other hook
        # (issue #259). Instead, strip only the safer-deps command(s) from each
        # group's inner list, and drop a group only when nothing else remains.
        for hook_type in ['PostToolUse', 'PreToolUse']:
            if hook_type not in existing_settings['hooks']:
                continue
            if not isinstance(existing_settings['hooks'][hook_type], list):
                continue
            cleaned_groups = []
            for group in existing_settings['hooks'][hook_type]:
                inner = group.get('hooks') if isinstance(group, dict) else None
                if not isinstance(inner, list):
                    # Unrecognised shape — never touch it.
                    cleaned_groups.append(group)
                    continue
                kept = [
                    h for h in inner
                    if 'safer-dependencies' not in (h or {}).get('command', '')
                ]
                if not kept:
                    # The group held ONLY safer-deps hooks → drop it (our new
                    # config re-adds a fresh equivalent below).
                    continue
                if len(kept) != len(inner):
                    # Co-located third-party hooks survived; rebuild the group
                    # around them without mutating the caller's original object.
                    group = {**group, 'hooks': kept}
                cleaned_groups.append(group)
            existing_settings['hooks'][hook_type] = cleaned_groups

        # Add new hook configurations
        for hook_type, hook_configs in new_config['hooks'].items():
            if hook_type not in existing_settings['hooks']:
                existing_settings['hooks'][hook_type] = []

            existing_settings['hooks'][hook_type].extend(hook_configs)

        # Write updated settings atomically (crash-safe; see _atomic_write_json).
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write_json(settings_file, existing_settings)

        # Return the settings structure for testing, but also indicate success
        existing_settings['_updated'] = True
        return existing_settings

    # Bash allowlist entries the Normal-mode skill needs to run registry queries
    # and vulnerability scans without per-call permission prompts.
    REQUIRED_PERMISSIONS = [
        # Safer profile (issue #3 hardening). Audit tools are pinned to their
        # exact read-only forms so `npm audit fix --force` / `bundle audit
        # ... --output` cannot match. curl / npm view / pip-audit / gem fetch /
        # dependency-check are deliberately NOT here — they cannot be safely
        # host-scoped by a permission prefix rule (see the Convenience profile
        # in INSTALLATION.md, which is opt-in only). The Normal-mode resolver
        # scripts (python3 .../scripts/*.py) are likewise NOT installer-written:
        # the installer has never written per-script rules (they are a manual /
        # Normal-mode addition documented in INSTALLATION.md). In the Safer
        # profile their upstream fetch (curl / npm view) is not pre-approved
        # anyway, so pre-approving the scripts would buy nothing.
        "Bash(npm audit --json)",
        "Bash(npm audit)",
        "Bash(bundle audit check)",
        "Bash(bundle audit check --update)",
    ]

    # Broad allowlist rules that installers at or below LAST_VULNERABLE_VERSION
    # wrote into settings.json (issue #3). The migration in _configure_permissions
    # deletes these — matched by EXACT string equality only, never parsed or
    # rewritten — but ONLY from a potentially vulnerable (or older) install (gated on
    # LEGACY_MARKER + LAST_VULNERABLE_VERSION). Newer installs are left untouched.
    LEGACY_INSTALLER_RULES = [
        "Bash(npm view *)",
        "Bash(curl -s --max-time 10 *)",
        "Bash(npm audit *)",
        "Bash(pip-audit *)",
        "Bash(bundle audit *)",
        "Bash(gem fetch *)",
    ]
    # Unique fingerprint of a potentially vulnerable install: no fixed version writes
    # this exact string and nobody hand-types `-s --max-time 10`, so its presence
    # means the allowlist was written by a potentially vulnerable installer.
    LEGACY_MARKER = "Bash(curl -s --max-time 10 *)"
    # Last release whose installer wrote the broad rules. Installs newer than this
    # are never modified by the migration.
    LAST_VULNERABLE_VERSION = "0.5.1"

    @staticmethod
    def _version_le(a, b):
        """True if dotted-int version ``a`` <= ``b``. Unparseable ``a`` counts as
        potentially vulnerable (True) so unknown/old installs are remediated, not skipped."""
        def _tup(v):
            return tuple(int(p) for p in re.split(r"[.+-]", str(v))[:3] if p.isdigit())
        ta, tb = _tup(a), _tup(b)
        return ta <= tb if ta else True

    def _installed_skill_version(self, use_global: bool = False):
        """Version in the SKILL frontmatter already on disk for this scope, read
        BEFORE any overwrite. None if not installed / unparseable. Gates the
        issue #3 permission migration so newer installs are left untouched."""
        base = (self.claude_dir if use_global else self.project_claude_dir) / "skills" / "safer-dependencies"
        for name in ("SKILL.md", "safer-dependencies.md"):
            try:
                text = (base / name).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            m = re.search(r"^version:\s*(.+?)\s*$", text, re.MULTILINE)
            if m:
                return m.group(1).strip()
        return None

    def _confirm_legacy_removal(self, use_global: bool = False, from_version=None):
        """issue #3 opt-in. Show the hardening notice and ask ONLY when this
        scope's settings.json actually holds removable legacy rules (a
        potentially vulnerable (or older) install with the curl marker). Returns True to remove
        (the recommended default) or False to keep. Returns True with no notice
        when there is nothing to remove, or when running non-interactively
        (headless updates still get hardened; apply_install prints what it removed)."""
        settings_file = (self.claude_dir if use_global else self.project_claude_dir) / "settings.json"
        try:
            allow = json.loads(settings_file.read_text(encoding="utf-8")).get("permissions", {}).get("allow", [])
        except (OSError, json.JSONDecodeError, AttributeError):
            return True
        version_vulnerable = from_version is None or self._version_le(from_version, self.LAST_VULNERABLE_VERSION)
        removable = [c for c in allow if c in self.LEGACY_INSTALLER_RULES]
        if not (version_vulnerable and self.LEGACY_MARKER in allow and removable):
            return True  # not a potentially vulnerable install with the rules present -> silent
        try:
            interactive = bool(sys.stdin) and sys.stdin.isatty()
        except (AttributeError, ValueError):
            interactive = False
        if not interactive:
            return True  # headless -> recommended default (remove); notice printed by apply_install

        added = [r for r in self.REQUIRED_PERMISSIONS if r not in allow]
        print("\n" + "=" * 60)
        print(" Security hardening - permissions")
        print("=" * 60)
        print(
            "This version tightens the permissions that safer-dependencies asks\n"
            "Claude Code to pre-approve. The initial release of this tool may have\n"
            "suggested rules in your settings.json that were broader than necessary.\n"
            "We recommend removing those rules; safer, precisely scoped rules are\n"
            "added in their place.\n"
        )
        print("Removed from your settings.json (only the rules found there are shown):")
        for r in removable:
            print(f"  - {r}")
        if added:
            print("\nAdded (safer, precisely scoped):")
            for r in added:
                print(f"  - {r}")
        print(f"\nLearn more:\n{PERMISSIONS_DOCS_URL}\n")
        print("  [R] Remove them  (recommended)")
        print("  [K] Keep my settings unchanged")
        try:
            ans = input("\nChoice [R]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return True
        return ans not in ("k", "keep", "n", "no")

    @staticmethod
    def _atomic_write_json(path, data):
        """Write ``data`` as JSON to ``path`` atomically: fully write a sibling
        temp file, then ``os.replace`` it into place, so a crash mid-write can
        never leave the destination (e.g. a user's settings.json) truncated or
        corrupt. ``os.replace`` is atomic on POSIX and Windows within a volume.
        """
        tmp = path.with_name(path.name + ".tmp")
        try:
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink()

    def _configure_permissions(self, use_global: bool = False, from_version=None, remove_legacy=True):
        """
        Merge the required Bash allowlist entries into settings.json's permissions.allow,
        idempotently. Re-runs do not produce duplicates.

        Returns:
            dict with:
                updated: True if any entry was added or settings.json was created
                permissions: the final {'allow': [...]} list as written
                added: entries that were newly added (empty list on a no-op)
        """
        settings_file = (self.claude_dir if use_global else self.project_claude_dir) / "settings.json"

        existing_settings: Dict[str, Any] = {}
        if settings_file.exists():
            try:
                existing_settings = json.loads(settings_file.read_text())
            except (json.JSONDecodeError, OSError):
                existing_settings = {}

        permissions = existing_settings.setdefault('permissions', {})
        allow_list = permissions.setdefault('allow', [])

        # issue #3 migration: remove the broad rules older installers wrote, but
        # only when BOTH gates pass, and only lines byte-for-byte identical to
        # ones we shipped (never parse or rewrite a user's rules):
        #   1. LEGACY_MARKER present — the fingerprint of a potentially vulnerable install, and
        #   2. from_version is unknown or <= LAST_VULNERABLE_VERSION.
        # A confirmed newer install is left completely untouched.
        removed = []
        version_vulnerable = from_version is None or self._version_le(from_version, self.LAST_VULNERABLE_VERSION)
        if remove_legacy and version_vulnerable and self.LEGACY_MARKER in allow_list:
            removed = [c for c in allow_list if c in self.LEGACY_INSTALLER_RULES]
            if removed:
                allow_list[:] = [c for c in allow_list if c not in self.LEGACY_INSTALLER_RULES]

        added = [cmd for cmd in self.REQUIRED_PERMISSIONS if cmd not in allow_list]
        allow_list.extend(added)

        if added or removed or not settings_file.exists():
            settings_file.parent.mkdir(parents=True, exist_ok=True)
            # When the migration REMOVES rules from an existing settings.json,
            # copy it to settings.json.bak first so the change is recoverable
            # (best-effort — never block the write on the backup).
            if removed and settings_file.exists():
                try:
                    shutil.copy2(settings_file,
                                 settings_file.with_name(settings_file.name + ".bak"))
                except OSError:
                    pass
            # Atomic write so a crash mid-write can never leave the live
            # settings.json truncated or corrupt.
            self._atomic_write_json(settings_file, existing_settings)

        return {
            'updated': bool(added or removed),
            'permissions': {'allow': list(allow_list)},
            'added': added,
            'removed': removed,
        }

    def _generate_hook_config(self, selections, scripts_path):
        """
        Generate hook configuration based on selections.

        Args:
            selections (dict): Hook selections
            scripts_path (str): Path to scripts directory with placeholders

        Returns:
            dict: Hook configuration for settings.json
        """
        hooks = {}

        # Configure PostToolUse hooks for intercept and post-install modes
        if selections.get('intercept') or selections.get('post_install'):
            hooks['PostToolUse'] = []

            if selections.get('intercept'):
                # Add Write and Edit hooks for intercept mode
                for matcher in ['Write', 'Edit']:
                    hooks['PostToolUse'].append({
                        'matcher': matcher,
                        'hooks': [{
                            'type': 'command',
                            'command': f'{scripts_path}/safer-dependencies-shim.sh',
                            'timeout': 60
                        }]
                    })

            if selections.get('post_install'):
                hooks['PostToolUse'].append({
                    'matcher': 'Bash',
                    'hooks': [{
                        'type': 'command',
                        'command': f'{scripts_path}/safer-dependencies-posttooluse-bash.sh',
                        'timeout': 30
                    }]
                })

        # Configure PreToolUse hooks for pre-install mode
        if selections.get('pre_install'):
            hooks.setdefault('PreToolUse', []).append({
                'matcher': 'Bash',
                'hooks': [{
                    'type': 'command',
                    'command': f'{scripts_path}/safer-dependencies-pretooluse-bash.sh',
                    'timeout': 10
                }]
            })

        # Post-Agent Mode (#147): pair of PreToolUse:Agent (sentinel touch,
        # 5s) + PostToolUse:Agent (mtime scan + shim dispatch, 120s). This is
        # the reactive safety net for subagent writes — subagents bypass the
        # other three hooks (anthropics/claude-code#25526).
        if selections.get('post_agent'):
            hooks.setdefault('PreToolUse', []).append({
                'matcher': 'Agent',
                'hooks': [{
                    'type': 'command',
                    'command': f'{scripts_path}/safer-dependencies-pretooluse-agent.sh',
                    'timeout': 5
                }]
            })
            hooks.setdefault('PostToolUse', []).append({
                'matcher': 'Agent',
                'hooks': [{
                    'type': 'command',
                    'command': f'{scripts_path}/safer-dependencies-posttooluse-agent.sh',
                    'timeout': 120
                }]
            })

        return {'hooks': hooks}

    # ── backup / restore (#274, #278) ──────────────────────────────────────

    def _backup_scope(self, scope, ts):
        """Snapshot bundle_dir + settings_file under ~/.claude/skills/.safer-dependencies-backups/<ts>/<global|project>/.

        Args:
            scope (dict): Scope dict with 'use_global', 'bundle_dir', 'settings_file'.
            ts (str): UTC timestamp string (e.g. "20260622T000000Z"), provided by the caller.

        Returns:
            Path: Backup root directory for this snapshot.
        """
        import shutil
        root = (
            self.claude_dir / "skills" / ".safer-dependencies-backups"
            / ts
            / ("global" if scope["use_global"] else "project")
        )
        root.mkdir(parents=True, exist_ok=True)
        if scope["bundle_dir"].exists():
            shutil.copytree(scope["bundle_dir"], root / "bundle", dirs_exist_ok=True)
        if scope["settings_file"].exists():
            shutil.copy2(scope["settings_file"], root / "settings.json")
        self._prune_backups(
            self.claude_dir / "skills" / ".safer-dependencies-backups", keep=3
        )
        return root

    def _restore_scope(self, backup_path, scope):
        """Restore bundle_dir and settings_file from a backup created by _backup_scope.

        settings.json is restored via os.replace for an atomic commit point (#278).

        Args:
            backup_path (Path): Backup root returned by _backup_scope.
            scope (dict): Scope dict with 'bundle_dir' and 'settings_file'.
        """
        import shutil, os
        if (backup_path / "bundle").exists():
            if scope["bundle_dir"].exists():
                shutil.rmtree(scope["bundle_dir"])
            shutil.copytree(backup_path / "bundle", scope["bundle_dir"])
        if (backup_path / "settings.json").exists():
            scope["settings_file"].parent.mkdir(parents=True, exist_ok=True)
            try:
                os.replace(backup_path / "settings.json", scope["settings_file"])  # atomic settings swap (#278)
            except OSError:
                shutil.copy2(backup_path / "settings.json", scope["settings_file"])  # cross-device fallback

    def _prune_backups(self, root, keep=3):
        """Delete oldest backup timestamp dirs, keeping only the most recent `keep`.

        Args:
            root (Path): Base backup directory (.safer-dependencies-backups/).
            keep (int): Number of most-recent backups to retain.
        """
        if not root.exists():
            return
        stamps = sorted([p for p in root.iterdir() if p.is_dir()])
        import shutil
        for old in stamps[:-keep]:
            shutil.rmtree(old, ignore_errors=True)


# ───────────────────── interactive X-menu (bare `/safer-dependencies`) ─────────────────────
# A bare `/safer-dependencies` renders a checkbox menu; the user marks ONE
# action with [x] and sends the menu (or just the marked line) back. The
# reply is parsed deterministically by `menu select` so routing never depends
# on LLM interpretation. `config menu` renders the policy grid with the
# CURRENT value of every key pre-marked [x]; the user moves marks (or edits
# the numbers) and `config apply` diffs the reply against the effective
# policy and writes only the changes.

# (verb, one-line description). Order is display order.
MENU_ACTIONS = [
    ("stats", "usage analytics (audits, findings, ecosystems)"),
    ("projects", "per-project ranked dashboard"),
    ("config", "view / edit policy"),
    ("validate", "installation health check"),
    ("install", "interactive installation / hook setup"),
    ("update", "self-update from the upstream repo"),
]

# Cell labels per key kind. Tier keys reuse safedep.config.TIERS.
_BOOL_CELLS = ("off", "on")

# Per-setting "what it means + why it matters" blurb, shown under each row in
# `config menu` so the grid is self-documenting (a user shouldn't have to read
# SKILL.md to know what a knob is or why it exists). Each entry states the
# concept and the security rationale; the per-VALUE effects live in
# CONFIG_VALUE_DESCRIPTIONS below.
CONFIG_KEY_DESCRIPTIONS = {
    "checks.cve": "Cross-references every pinned version against the OSV vulnerability database. Why it matters: known-vulnerable dependencies are the most common and most-exploited supply-chain weakness — this is the core check.",
    "checks.abandoned": "Flags packages a curated list marks abandoned/deprecated/replaced (e.g. `request`, `jwt-go`). Why it matters: abandoned packages stop getting security fixes and are prime targets for malicious takeover by a new 'maintainer'.",
    "checks.typosquat": "Detects names within 1–2 edits of a popular package (e.g. `reqeusts` vs `requests`). Why it matters: attackers publish look-alike names hoping you fumble a keystroke and pull in their malicious package instead.",
    "checks.existence": "Verifies the package actually exists on its registry (a 404 = no such package). Why it matters: a fabricated/mistyped name has no CVEs and no history, so it sails through every other check — a dependency-confusion / hallucinated-package vector.",
    "checks.first_publish_age": "Flags packages whose FIRST-ever release was < 30 days ago. Why it matters: brand-new packages have no track record, and malicious ones are usually caught and pulled within weeks — youth warrants extra scrutiny. Advisory: off disables; warn and block behave the same (it surfaces a finding, never auto-blocks).",
    "checks.hashes": "PyPI requirements.txt integrity. A declared `--hash=sha256:` pin is ALWAYS validated against PyPI's published digest and WARNs on mismatch (independent of this tier); this tier only controls a reminder NOTE when a requirements.txt has NO hash pins. No hard-stop.",
    "checks.signatures": "Reports whether Maven/RubyGems artifacts are cryptographically signed. Why it matters: a signature ties an artifact to a publisher; an unexpectedly-unsigned package can hint at a compromised or unofficial source. Advisory (adoption is low): off disables the report; warn and block both just report, never block.",
    "checks.stale": "Staleness = the package's newest release is older than the threshold (default 2 yrs), so the maintainer has likely moved on. Why it matters: an unmaintained package won't get a patch when the next CVE lands — you'd be stranded on a vulnerable version with no upstream fix.",
    "checks.transitive": "Controls whether the FULL resolved dependency tree (from lockfiles) is audited, not just the packages you declared. Why it matters: most real-world CVEs live in transitive deps you never named. off skips the lockfile audit; warn and block both run it — each finding then obeys its OWN check's tier (a transitive CVE blocks via checks.cve, etc.).",
    "cooloff.mode": "A release-age gate: holds back versions published too recently to be community-vetted (default < 7 days). Why it matters: compromised or broken releases are often yanked within days — a short wait lets the community surface problems before you adopt a version.",
    "cooloff.days": "The cooloff window length in days — a release younger than this is treated as not-yet-vetted by cooloff.mode. Why it matters: longer = safer but slower to adopt; shorter = faster but less vetting time. (Gate action set by cooloff.mode.)",
    "staleness.years": "How old a package's newest release must be (default 2 yrs) before checks.stale fires. Why it matters: lower catches unmaintained packages sooner but nags on stable 'finished' libraries; higher is quieter but lets truly-dead packages slip by longer.",
    "staleness.popularity_guard": "When on, a mature + widely-used package already at its latest version is NOT flagged STALE. Why it matters: some great libraries are simply 'done' and rarely release — this stops checks.stale crying wolf on them while still flagging genuinely-abandoned ones.",
}

# Per-VALUE effect: what safer-dependencies actually does when each option is
# selected, per setting. Drives the bullet lines under each grid row AND the
# option descriptions in the AskUserQuestion picker — one source of truth so the
# two never drift. Numeric keys (cooloff.days / staleness.years) have no
# enumerated values; their CONFIG_KEY_DESCRIPTIONS line already states the
# direction.
CONFIG_VALUE_DESCRIPTIONS = {
    "checks.cve": {
        "off":   "CVE scanning is skipped — vulnerable versions are written/installed as-is.",
        "warn":  "CVEs are surfaced as advisories; the pin is left unchanged for you to decide.",
        "block": "Vulnerable pins are auto-rewritten to the nearest safe version (or the install is denied pre-fetch).",
    },
    "checks.abandoned": {
        "off":   "The known-abandoned list is not consulted.",
        "warn":  "Abandoned packages are flagged with a replacement suggestion, but kept.",
        "block": "Abandoned packages are removed from the manifest and a replacement is named.",
    },
    "checks.typosquat": {
        "off":   "No name-similarity check is run.",
        "warn":  "A near-miss name pauses for you to confirm it's intentional before proceeding.",
        "block": "A suspected typosquat is rejected outright — never written.",
    },
    "checks.existence": {
        "off":   "Package names are not verified against the registry.",
        "warn":  "An unknown (404) name pauses for you to confirm it's a real / private package.",
        "block": "An unknown package name is rejected outright.",
    },
    "checks.first_publish_age": {
        "off":   "Package age is not checked.",
        "warn":  "A package first published < 30 days ago is flagged as a supply-chain risk, but kept.",
        "block": "Same as warn — advisory only; the shim has no block enforcement for this check.",
    },
    "checks.hashes": {
        "off":   "Silences the 'no --hash pins' reminder NOTE. (A declared hash is still validated for tampering.)",
        "warn":  "Emits a NOTE nudging you to add --hash pins when a requirements.txt has none.",
        "block": "Same as warn — no hard-stop; a declared-hash mismatch always WARNs regardless of this tier.",
    },
    "checks.signatures": {
        "off":   "Artifact signing is not reported.",
        "warn":  "Unsigned Maven (.asc) / RubyGems (.sig) artifacts are reported (informational).",
        "block": "Same as warn — signatures are informational; the shim does not hard-stop on unsigned artifacts.",
    },
    "checks.stale": {
        "off":   "Release-age staleness is not checked.",
        "warn":  "A package past the staleness threshold is flagged, but kept.",
        "block": "A stale package is removed from the manifest (BLOCKED).",
    },
    "checks.transitive": {
        "off":   "Lockfiles are not audited — only declared top-level packages are checked.",
        "warn":  "The resolved tree (lockfiles) IS audited; each finding surfaces under its own check's tier.",
        "block": "Same as warn — auditing the tree is on; a transitive finding blocks via its own check (e.g. checks.cve), not here.",
    },
    "cooloff.mode": {
        "off":   "No release-age gate — brand-new versions are accepted.",
        "warn":  "A too-new version emits COOLOFF-CONFIRM and pauses before proceeding.",
        "block": "A too-new version is rewritten to the newest release clearing the window (or denied pre-install).",
    },
    "staleness.popularity_guard": {
        "off": "Pure elapsed-time staleness — even big, finished packages get flagged once past the threshold.",
        "on":  "Mature, widely-used packages at their latest version are NOT flagged STALE (cuts false positives).",
    },
}

# dotted key -> env var that can override the file value (for apply warnings).
_ENV_OVERRIDES = {
    "cooloff.mode": "SAFE_DEP_COOLOFF_MODE",
    "cooloff.days": "SAFE_DEP_COOLOFF_DAYS",
    "checks.hashes": "SAFE_DEP_REQUIRE_HASHES",
    "staleness.years": "SAFE_DEP_STALE_YEARS",
    "staleness.popularity_guard": "SAFE_DEP_STALE_POPULARITY_GUARD",
}

_MARKED_CELL_RE = re.compile(r"\[([xX ])\]\s*([a-z]+)")


def _config_summary(policy: Dict[str, Any], limit: int = 3) -> str:
    """One-line current-configuration hint for the menu's config row."""
    def _fmt(v: Any) -> str:
        return str(v).lower() if isinstance(v, bool) else str(v)

    overrides = [(k, v) for k, (v, source) in sorted(policy.items())
                 if source != "default"]
    if not overrides:
        return "all defaults"
    shown = ", ".join(f"{k}={_fmt(v)}" for k, v in overrides[:limit])
    extra = len(overrides) - limit
    return f"{len(overrides)} override(s): {shown}" + (f" +{extra} more" if extra > 0 else "")


def render_menu() -> str:
    """The top-level X-menu shown for a bare `/safer-dependencies`."""
    from safedep import config as _sd_config
    policy = _sd_config.effective_policy()
    lines = [
        "Safer Dependencies — mark ONE action with [x] and send the menu (or just that line) back:",
        "",
    ]
    for verb, desc in MENU_ACTIONS:
        suffix = f"   ({_config_summary(policy)})" if verb == "config" else ""
        lines.append(f"  [ ] {verb:<9} — {desc}{suffix}")
    # `<action>` is deliberately not a verb: a full-menu paste of this line
    # must never register as a selection in parse_menu_selection().
    lines += ["", "Reply example:  [x] <action>   (e.g. mark the config line to view/edit settings)"]
    return "\n".join(lines)


def parse_menu_selection(reply: str) -> str:
    """Return the single verb marked [x] in a menu reply.

    Accepts the full menu, a single marked line, or a bare verb. Raises
    ValueError when no action or more than one action is selected.
    """
    verbs = {verb for verb, _ in MENU_ACTIONS}
    bare = reply.strip().lower()
    if bare in verbs:
        return bare
    selected = []
    for line in reply.splitlines():
        m = re.search(r"\[[xX]\]\s*([a-z-]+)", line)
        if m and m.group(1) in verbs:
            selected.append(m.group(1))
    if not selected:
        raise ValueError(
            "no action marked — put an [x] next to exactly one of: "
            + ", ".join(sorted(verbs)))
    if len(set(selected)) > 1:
        raise ValueError(
            "multiple actions marked (" + ", ".join(selected)
            + ") — mark exactly one")
    return selected[0]


def _policy_rows() -> List[Dict[str, Any]]:
    """Ordered config rows: {key, kind, value, source, cells}."""
    from safedep import config as _sd_config
    policy = _sd_config.effective_policy()
    rows = []
    for key, (value, source) in sorted(policy.items()):
        if key == "staleness.popularity_guard":
            rows.append({"key": key, "kind": "bool", "value": bool(value),
                         "source": source, "cells": _BOOL_CELLS})
        elif isinstance(value, str):  # tier keys (cooloff.mode, checks.*)
            rows.append({"key": key, "kind": "tier", "value": value,
                         "source": source, "cells": _sd_config.TIERS})
        else:  # numeric (cooloff.days, staleness.years)
            rows.append({"key": key, "kind": "number", "value": value,
                         "source": source, "cells": None})
    return rows


def render_config_menu() -> str:
    """The policy grid with the current value of every key marked [x]."""
    lines = [
        "Safer Dependencies config — current values are marked [x].",
        "Move a mark (or edit a number) and send the menu back; only changed keys are written.",
        "",
    ]
    for row in _policy_rows():
        if row["kind"] == "number":
            body = f"= {row['value']}"
        else:
            if row["kind"] == "bool":
                current = "on" if row["value"] else "off"
            else:
                current = row["value"]
            body = "   ".join(
                f"[{'x' if cell == current else ' '}] {cell}" for cell in row["cells"])
        lines.append(f"  {row['key']:<28} {body:<42} ({row['source']})")
        desc = CONFIG_KEY_DESCRIPTIONS.get(row["key"])
        if desc:
            # Indented sub-lines, intentionally NOT starting with the key name so
            # row-matching parsers/tests keying on the key still hit one line, and
            # never matching the key-row regex in parse_config_menu (anchored at
            # line start) so an edited grid still round-trips through `apply`.
            lines.append(f"      ↳ {desc}")
        values = CONFIG_VALUE_DESCRIPTIONS.get(row["key"])
        if values:
            for cell in row["cells"]:
                if cell in values:
                    lines.append(f"        • {cell:<5} — {values[cell]}")
    lines += ["", "Numbers (cooloff.days, staleness.years) are edited in place: change the value after `=`."]
    return "\n".join(lines)


def parse_config_menu(reply: str) -> Dict[str, str]:
    """Diff an edited config grid against the effective policy.

    Returns {dotted_key: new_value_string} for keys whose mark or number
    differs from the current effective value. Lines without any mark are
    treated as unchanged (a cleared row is not a deliberate edit). Raises
    ValueError when a row carries more than one [x].
    """
    rows = {row["key"]: row for row in _policy_rows()}
    changes: Dict[str, str] = {}
    for line in reply.splitlines():
        m = re.match(r"\s*([a-z_]+\.[a-z_]+)\b(.*)$", line.strip())
        if not m or m.group(1) not in rows:
            continue
        key, rest = m.group(1), m.group(2)
        row = rows[key]
        if row["kind"] == "number":
            n = re.search(r"=\s*([0-9][0-9.]*)", rest)
            if not n:
                continue
            if n.group(1) != str(row["value"]):
                changes[key] = n.group(1)
            continue
        marked = [cell for flag, cell in _MARKED_CELL_RE.findall(rest)
                  if flag in "xX" and cell in row["cells"]]
        if not marked:
            continue
        if len(set(marked)) > 1:
            raise ValueError(
                f"{key}: multiple cells marked ({', '.join(marked)}) — mark exactly one")
        current = ("on" if row["value"] else "off") if row["kind"] == "bool" else row["value"]
        if marked[0] != current:
            changes[key] = marked[0]
    return changes


def apply_config_menu(reply: str) -> List[str]:
    """Validate and write the changes from an edited config grid.

    All rows are validated before anything is written (a bad row aborts the
    whole apply). Returns the human-readable result lines.
    """
    from safedep import config as _sd_config
    from safedep import configfile as _sd_configfile
    changes = parse_config_menu(reply)  # raises ValueError on a bad row
    if not changes:
        return ["no changes"]
    out = []
    for key, value in sorted(changes.items()):
        _sd_configfile.set_key(key, value)
        out.append(f"set {key} = {value}")
        env_var = _ENV_OVERRIDES.get(key)
        if env_var and os.environ.get(env_var, "").strip():
            out.append(f"  note: {env_var} is set and overrides {key} until unset")
    _sd_config.invalidate_caches()
    return out


def main():
    """
    CLI interface for SaferDependenciesManager.

    Usage:
        python3 safer_dependencies_manager.py interactive_install
        python3 safer_dependencies_manager.py stats [--by-project] [--window Nd] [--top N | --all] [--json]
        python3 safer_dependencies_manager.py validate_installation
        python3 safer_dependencies_manager.py self_update [--check] [--force] [--rollback] [--yes]
            (without --yes, self_update only previews — it never clones/applies; #271)
        python3 safer_dependencies_manager.py menu [select]   (select reads the reply on stdin)
        python3 safer_dependencies_manager.py config [menu|apply|set|unset|reset|path]
        python3 safer_dependencies_manager.py version
    """
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 safer_dependencies_manager.py <command> [options]")
        print("Commands: interactive_install, apply_install, stats, validate_installation, self_update, menu, config, version")
        print("  stats options: [--by-project] [--window Nd] [--top N | --all] [--json]")
        sys.exit(1)

    command = sys.argv[1]
    manager = SaferDependenciesManager()

    try:
        if command == "interactive_install":
            result = manager.interactive_install()
            print(f"Installation result: {result['status']}")
            print(f"Summary: {result['summary']}")
            if result.get('installed'):
                print(f"Installed components: {', '.join(result['installed'])}")

        elif command in ("generate_stats_report", "stats"):
            rest = sys.argv[2:]
            by_project = ('--by-project' in rest) or ('projects' in rest)
            as_json = '--json' in rest
            window = "7d"
            top_n = 12
            i = 0
            while i < len(rest):
                arg = rest[i]
                if arg == '--window' and i + 1 < len(rest):
                    window = rest[i + 1]; i += 2; continue
                if arg.startswith('--window='):
                    window = arg.split('=', 1)[1]
                elif arg == '--top' and i + 1 < len(rest):
                    try:
                        top_n = int(rest[i + 1])
                    except ValueError:
                        print(f"Error: --top requires an integer, got {rest[i + 1]!r}")
                        sys.exit(2)
                    i += 2; continue
                elif arg.startswith('--top='):
                    raw = arg.split('=', 1)[1]
                    try:
                        top_n = int(raw)
                    except ValueError:
                        print(f"Error: --top requires an integer, got {raw!r}")
                        sys.exit(2)
                elif arg == '--all':
                    top_n = 10 ** 9
                i += 1
            result = manager.generate_stats_report(window=window, by_project=by_project, top_n=top_n)
            if as_json:
                # Machine-readable export of the full computed stats dict.
                print(json.dumps(result, indent=2))
            elif by_project:
                manager._print_by_project(result)
            else:
                manager._print_stats_report(result)

        elif command == "validate_installation":
            result = manager.validate_installation()
            if result['valid']:
                print("✓ Safer Dependencies installation is valid and configured correctly")
            else:
                print("⚠️ Safer Dependencies installation has issues:")
                for issue in result['issues']:
                    print(f"  - {issue}")
            for warning in result.get('warnings', []):
                print(f"  ⚠ coverage: {warning}")

        elif command == "self_update":
            rest = sys.argv[2:]
            # Applying upstream code requires an explicit opt-in (#271): --yes (or
            # its --non-interactive alias). Without it, self_update dry-runs the
            # plan and refuses to clone/apply — safe by default. The interactive
            # skill flow only passes --yes after the developer confirms the
            # previewed plan; autonomous sessions pass it per the implicit-YES rule.
            confirm = ("--yes" in rest) or ("--non-interactive" in rest)
            result = manager.self_update(check="--check" in rest, force="--force" in rest,
                                         rollback="--rollback" in rest, confirm=confirm)
            icon = {"success": "✓", "up_to_date": "✓", "rolled_back": "✓",
                    "check": "•", "offline": "•"}.get(result["status"], "✗")
            print(f"{icon} {result['summary']}")
            if result["status"] == "error":
                sys.exit(1)

        elif command == "menu":
            sub = sys.argv[2] if len(sys.argv) > 2 else ""
            if sub == "select":
                try:
                    print(f"SELECTED: {parse_menu_selection(sys.stdin.read())}")
                except ValueError as e:
                    print(f"error: {e}")
                    sys.exit(2)
            elif sub == "":
                print(render_menu())
            else:
                print(f"Unknown menu verb: {sub}")
                print("usage: menu [select]   (select reads the user's reply on stdin)")
                sys.exit(2)

        elif command == "version":
            info = manager.version_info()
            manager._print_version_report(info)

        elif command == "config":
            from safedep import config as _sd_config
            from safedep import configfile as _sd_configfile
            sub = sys.argv[2] if len(sys.argv) > 2 else "show"
            try:
                if sub == "show" or sub == "":
                    if _sd_config.config_file_unparseable():
                        print("config file unparseable — using defaults "
                              "(fix by hand or run 'config reset')")
                    for key, (value, source) in sorted(_sd_config.effective_policy().items()):
                        print(f"{key} = {value} ({source})")
                    for w in _sd_config.load_warnings():
                        print(w)
                elif sub == "menu":
                    print(render_config_menu())
                elif sub == "apply":
                    try:
                        for line in apply_config_menu(sys.stdin.read()):
                            print(line)
                    except ValueError as e:
                        print(f"error: {e}")
                        sys.exit(2)
                elif sub == "set":
                    if len(sys.argv) < 5:
                        print("usage: config set <key> <value>")
                        sys.exit(2)
                    _sd_configfile.set_key(sys.argv[3], sys.argv[4])
                    print(f"set {sys.argv[3]} = {sys.argv[4]}")
                elif sub == "unset":
                    if len(sys.argv) < 4:
                        print("usage: config unset <key>")
                        sys.exit(2)
                    _sd_configfile.unset_key(sys.argv[3])
                    print(f"unset {sys.argv[3]} (reverted to default)")
                elif sub == "reset":
                    if "--yes" in sys.argv[3:]:
                        answer = "y"
                    else:
                        try:
                            answer = input("Clear ALL safer-dependencies config? [y/N] ").strip().lower()
                        except (EOFError, RuntimeError):
                            answer = "n"
                    if answer == "y":
                        removed = _sd_configfile.reset()
                        if removed:
                            print("config cleared — all keys at defaults")
                        else:
                            print("managed keys cleared — unmanaged sections (e.g. [ecosystems]) preserved")
                    else:
                        print("cancelled")
                elif sub == "path":
                    print(_sd_config.user_config_path())
                else:
                    print(f"Unknown config verb: {sub}")
                    print("usage: config [show|menu|apply|set <key> <value>|unset <key>|reset|path]")
                    sys.exit(2)
            except (_sd_configfile.ConfigKeyError, _sd_configfile.ConfigValueError) as e:
                print(f"error: {e}")
                sys.exit(2)

        elif command == "apply_install":
            rest = sys.argv[2:]
            use_global = "--project" not in rest  # default global
            hooks_csv = ""
            for i, a in enumerate(rest):
                if a == "--hooks" and i + 1 < len(rest):
                    hooks_csv = rest[i + 1]
                elif a.startswith("--hooks="):
                    hooks_csv = a.split("=", 1)[1]
            keys = {"intercept", "pre_install", "post_install", "post_agent"}
            chosen = {k.strip() for k in hooks_csv.split(",") if k.strip()}
            unknown = chosen - keys
            if unknown:
                print(f"error: unknown hook(s): {', '.join(sorted(unknown))}")
                sys.exit(2)
            selections = {k: (k in chosen) for k in keys}
            result = manager.apply_install(use_global, selections)
            print(f"apply_install: {result['status']} — {result['summary']}")
            if result['status'] == 'error':
                sys.exit(1)

        else:
            print(f"Unknown command: {command}")
            print("Available commands: interactive_install, apply_install, stats, validate_installation, self_update, menu, config, version")
            print("  stats options: [--by-project] [--window Nd] [--top N | --all] [--json]")
            sys.exit(1)

    except Exception as e:
        print(f"Error executing {command}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
