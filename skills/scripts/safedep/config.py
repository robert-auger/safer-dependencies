"""Resolve which ecosystems are enabled and which policy tiers apply.

Three configuration sources, highest precedence first:

  1. Environment variables — per-key overrides. Suitable for CI one-offs.

  2. Project-level ``${CLAUDE_PROJECT_DIR or cwd}/safer-dependencies.toml``
     — committed repo config. **Monotonic hardening only**: may raise a
     check tier toward ``block``, increase cooloff days, tighten staleness
     thresholds, or disable an ecosystem. It can never lower a tier, shorten
     a cooloff, loosen staleness, or re-enable an ecosystem the user disabled.

  3. User-global ``~/.config/safer-dependencies/config.toml`` — personal
     baseline, honoured as-is.

``[ecosystems]`` schema (both files)::

    [ecosystems]
    npm = true        # default: true — all ecosystems enabled
    pypi = true
    rubygems = true
    maven = true
    go = true
    crates = true

A ``false`` value disables the ecosystem.  An ecosystem is disabled when
*either* the user file **or** the project file sets it to ``false`` (project
cannot re-enable what the user blocked).

The default — no config, no env var — is **everything enabled** so installs
that don't ship a config keep existing behaviour.

Public API: :func:`disabled_ecosystems`, :func:`check_tier`,
:func:`cooloff_mode`, :func:`cooloff_days`, :func:`stale_years`,
:func:`stale_popularity_guard`, :func:`fail_mode`, :func:`effective_policy`.
"""

from __future__ import annotations

import os

try:
    import tomllib as _tomllib
except ImportError:  # Python 3.10 and below
    try:
        import tomli as _tomllib  # type: ignore[import-not-found, no-redef]
    except ImportError:
        _tomllib = None  # type: ignore[assignment]


# Canonical ecosystem identifiers. Must match the keys of
# safer-dependencies-shim.sh's MANIFEST_ECOSYSTEM / OSV_ECOSYSTEM mappings
# and the PreToolUse helper's strategy ecosystem field (lowercased).
_KNOWN_ECOSYSTEMS = frozenset({"npm", "pypi", "rubygems", "maven", "go", "crates"})


# Module-level cache so back-to-back lookups in one shim invocation don't
# re-read the file. The cache key is the (project_dir, env_var) tuple so
# tests that flip env vars between calls see fresh resolution.
_CACHE: dict = {}


def _project_root() -> str:
    """Project root for config lookup. Falls back to cwd."""
    return os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()


def _user_config_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, "safer-dependencies", "config.toml")


def user_config_path() -> str:
    """Public alias for CLI consumers (the underscore original predates them)."""
    return _user_config_path()


def _load_toml(path: str) -> dict:
    if _tomllib is None or not os.path.isfile(path):
        return {}
    try:
        with open(path, "rb") as fh:
            return _tomllib.load(fh) or {}
    except Exception:
        # Malformed TOML must not break the hook — fail open to "enabled".
        return {}


def config_file_unparseable() -> bool:
    """True iff the user config file exists on disk but cannot be parsed.

    `_load_toml` fails open (malformed -> {}) so hooks keep running; this lets
    the CLI surface a one-line hint that `config show` is reporting defaults
    because the file could not be read (it is otherwise silent — only
    set/unset refuse outright). Returns False when the file is absent.
    """
    path = _user_config_path()
    if _tomllib is None or not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as fh:
            _tomllib.load(fh)
        return False
    except Exception:
        return True


def _ecosystems_section(data: dict) -> dict:
    section = data.get("ecosystems")
    return section if isinstance(section, dict) else {}


def _parse_env_disable(value: str) -> set:
    out: set = set()
    for token in value.split(","):
        name = token.strip().lower()
        if name and name in _KNOWN_ECOSYSTEMS:
            out.add(name)
    return out


def disabled_ecosystems() -> frozenset:
    """Return the set of disabled ecosystem identifiers.

    Combines TOML config (user, then project override) with the
    ``SAFE_DEP_DISABLE`` env var. Result is cached per (project_dir, env)
    pair for the lifetime of the process. Always returns a frozenset whose
    members are subset of ``_KNOWN_ECOSYSTEMS``; unknown ecosystem names are
    ignored silently (forward-compatible with future ecosystems).
    """
    project_dir = _project_root()
    env_disable = os.environ.get("SAFE_DEP_DISABLE", "")
    cache_key = (project_dir, env_disable)
    cached = _CACHE.get(cache_key)
    if cached is not None:
        return cached

    user = _ecosystems_section(_load_toml(_user_config_path()))
    project = _ecosystems_section(
        _load_toml(os.path.join(project_dir, "safer-dependencies.toml"))
    )
    # Monotonic hardening: disabled if either source disables — project cannot
    # re-enable an ecosystem the user has set to false (issue #250).
    disabled: set = set()
    for name in _KNOWN_ECOSYSTEMS:
        if user.get(name) is False or project.get(name) is False:
            disabled.add(name)
    disabled |= _parse_env_disable(env_disable)
    result = frozenset(disabled)
    _CACHE[cache_key] = result
    return result


def is_disabled(ecosystem: str) -> bool:
    """Convenience wrapper used by hooks."""
    if not ecosystem:
        return False
    return ecosystem.lower() in disabled_ecosystems()


def invalidate_caches() -> None:
    """Drop all resolution caches — call after the config file changes on
    disk (configfile writes) or between test scenarios."""
    _CACHE.clear()
    _POLICY_CACHE.clear()
    _LOAD_WARNINGS.clear()


# Backwards-compatible alias (existing tests use the old name).
_clear_cache_for_tests = invalidate_caches


# ───────────────────── policy oracle (issue #232) ─────────────────────
# Per-key resolution: env var > global config file > built-in default.
# Global-only by design (the project-level file is read ONLY for the
# grandfathered [ecosystems] section above). Fail-open: malformed values
# resolve to the default and are reported via load_warnings().

SCHEMA_VERSION_KEY = "schema"
TIERS = ("off", "warn", "block")

CHECK_DEFAULTS: dict = {
    "cve": "block",
    "abandoned": "block",
    "typosquat": "warn",
    "existence": "warn",
    "stale": "warn",
    "hashes": "warn",
    "signatures": "warn",
    "first_publish_age": "warn",
    "transitive": "warn",
}

COOLOFF_MODE_DEFAULT = "warn"
COOLOFF_DAYS_DEFAULT = 7
STALE_YEARS_DEFAULT = 2.0
STALE_POPULARITY_GUARD_DEFAULT = True

# Fail-mode policy (issue #290). Governs what hooks do when an audit cannot be
# completed (Python missing, OSV unreachable, malformed input, etc.).
#   "open"   — today's behaviour: allow the operation, record a log line.
#   "closed" — fail safe: Pre-Install denies the install; the manifest path
#              emits a visible AUDIT-INCOMPLETE: signal.
# Default MUST be "open" so existing installs see no behaviour change.
FAIL_MODES = ("open", "closed")
FAIL_MODE_DEFAULT = "open"

# NOTE: the five getters below share an env > file > default shape on purpose
# (5 keys; readable beats clever). If a sixth knob lands, fold them into a
# table-driven _resolve(key) that also powers effective_policy's sources.

_POLICY_CACHE: dict = {}
_LOAD_WARNINGS: list = []


def _policy_file_data() -> dict:
    key = ("__policy__", _user_config_path())
    cached = _POLICY_CACHE.get(key)
    if cached is not None:
        return cached
    data = _load_toml(_user_config_path())
    if not isinstance(data, dict):
        data = {}
    _POLICY_CACHE[key] = data
    return data


def _project_policy_file_data() -> dict:
    """Policy data from the project-level safer-dependencies.toml.

    Used for monotonic hardening (issue #250): project settings may only
    raise tiers, never lower them below the user/default level.
    Cache key includes the project root so tests that change CLAUDE_PROJECT_DIR
    see fresh data.
    """
    proj_dir = _project_root()
    key = ("__project_policy__", proj_dir)
    cached = _POLICY_CACHE.get(key)
    if cached is not None:
        return cached
    path = os.path.join(proj_dir, "safer-dependencies.toml")
    data = _load_toml(path)
    if not isinstance(data, dict):
        data = {}
    _POLICY_CACHE[key] = data
    return data


def _max_tier(a: str, b: str) -> str:
    """Return the stricter (higher-index) of two tier strings."""
    return a if TIERS.index(a) >= TIERS.index(b) else b


def _warn_once(key: str, raw: object, allowed: str) -> None:
    msg = (f"WARNING: safer-dependencies config: invalid value {raw!r} for "
           f"{key} (allowed: {allowed}) — using default")
    if msg not in _LOAD_WARNINGS:
        _LOAD_WARNINGS.append(msg)


def load_warnings() -> list:
    """One-line WARNING strings for malformed config values seen this
    session. Surfaces append these to their signal output once."""
    return list(_LOAD_WARNINGS)


def _tier_from(raw: object, key: str, default: str) -> str:
    if raw is None:
        return default
    if isinstance(raw, str) and raw.strip().lower() in TIERS:
        return raw.strip().lower()
    _warn_once(key, raw, "off|warn|block")
    return default


def check_tier(name: str) -> str:
    """Effective tier for a check: 'off' | 'warn' | 'block'.

    Precedence: env var > max(user config, project config) > default.
    Project config may only raise the tier, never lower it (issue #250).
    Raises KeyError for unknown check names.
    """
    if name not in CHECK_DEFAULTS:
        raise KeyError(f"unknown check {name!r}; known: {sorted(CHECK_DEFAULTS)}")
    if name == "hashes":
        env = os.environ.get("SAFE_DEP_REQUIRE_HASHES", "").strip().lower()
        if env:
            if env == "enforce":
                return "block"
            if env in TIERS:
                return env
            _warn_once("SAFE_DEP_REQUIRE_HASHES", env, "off|warn|block|enforce")
    section = _policy_file_data().get("checks")
    raw = section.get(name) if isinstance(section, dict) else None
    user_tier = _tier_from(raw, f"checks.{name}", CHECK_DEFAULTS[name])
    proj_section = _project_policy_file_data().get("checks")
    proj_raw = proj_section.get(name) if isinstance(proj_section, dict) else None
    if proj_raw is not None:
        proj_tier = _tier_from(proj_raw, f"checks.{name}", CHECK_DEFAULTS[name])
        return _max_tier(user_tier, proj_tier)
    return user_tier


def cooloff_mode() -> str:
    """Effective cooloff mode. Project may only raise toward block (issue #250)."""
    env = os.environ.get("SAFE_DEP_COOLOFF_MODE", "").strip().lower()
    if env in TIERS:
        return env
    if env:
        # Invalid env value: warn and FALL THROUGH to the configured value
        # (matching the checks/`hashes` path). Returning the default here would
        # silently discard a hardened user/project config on a mere typo.
        _warn_once("SAFE_DEP_COOLOFF_MODE", env, "off|warn|block")
    section = _policy_file_data().get("cooloff")
    raw = section.get("mode") if isinstance(section, dict) else None
    user_mode = _tier_from(raw, "cooloff.mode", COOLOFF_MODE_DEFAULT)
    proj_section = _project_policy_file_data().get("cooloff")
    proj_raw = proj_section.get("mode") if isinstance(proj_section, dict) else None
    if proj_raw is not None:
        proj_mode = _tier_from(proj_raw, "cooloff.mode", COOLOFF_MODE_DEFAULT)
        return _max_tier(user_mode, proj_mode)
    return user_mode


def fail_mode() -> str:
    """Effective fail-mode policy: 'open' (default) | 'closed' (issue #290).

    Precedence — env > max(user config, project config) > built-in default.
    Project may only harden toward 'closed' (issue #250). Default is 'open'
    so existing installs are unchanged.

    Config schema::

        [policy]
        fail_mode = "closed"
    """
    env = os.environ.get("SAFE_DEP_FAIL_MODE", "").strip().lower()
    if env in FAIL_MODES:
        return env
    if env:
        # Invalid env value: warn and FALL THROUGH to the configured value
        # (matching the checks/`hashes` path). Returning the default here would
        # silently flip a deliberately-hardened ``closed`` back to fail-open.
        _warn_once("SAFE_DEP_FAIL_MODE", env, "open|closed")
    section = _policy_file_data().get("policy")
    raw = section.get("fail_mode") if isinstance(section, dict) else None
    if raw is None:
        user_mode = FAIL_MODE_DEFAULT
    elif isinstance(raw, str) and raw.strip().lower() in FAIL_MODES:
        user_mode = raw.strip().lower()
    else:
        _warn_once("policy.fail_mode", raw, "open|closed")
        user_mode = FAIL_MODE_DEFAULT
    proj_section = _project_policy_file_data().get("policy")
    proj_raw = proj_section.get("fail_mode") if isinstance(proj_section, dict) else None
    if isinstance(proj_raw, str) and proj_raw.strip().lower() in FAIL_MODES:
        proj_mode = proj_raw.strip().lower()
        if FAIL_MODES.index(proj_mode) > FAIL_MODES.index(user_mode):
            return proj_mode
    return user_mode


def _non_negative_int(raw: object, key: str, default: int) -> int:
    if isinstance(raw, bool):
        _warn_once(key, raw, "integer >= 0")
        return default
    try:
        value = int(raw)  # type: ignore[call-overload]
        if value >= 0:
            return value
    except (TypeError, ValueError):
        pass
    _warn_once(key, raw, "integer >= 0")
    return default


def cooloff_days() -> int:
    """Effective cooloff window. Project may only increase (stricter) (issue #250)."""
    env = os.environ.get("SAFE_DEP_COOLOFF_DAYS", "").strip()
    if env:
        return _non_negative_int(env, "SAFE_DEP_COOLOFF_DAYS", COOLOFF_DAYS_DEFAULT)
    section = _policy_file_data().get("cooloff")
    raw = section.get("days") if isinstance(section, dict) else None
    user_days = COOLOFF_DAYS_DEFAULT if raw is None else _non_negative_int(raw, "cooloff.days", COOLOFF_DAYS_DEFAULT)
    proj_section = _project_policy_file_data().get("cooloff")
    proj_raw = proj_section.get("days") if isinstance(proj_section, dict) else None
    if proj_raw is not None:
        proj_days = _non_negative_int(proj_raw, "cooloff.days", COOLOFF_DAYS_DEFAULT)
        return max(user_days, proj_days)
    return user_days


def _positive_float(raw: object, key: str, default: float) -> float:
    if isinstance(raw, bool):
        _warn_once(key, raw, "number > 0")
        return default
    try:
        value = float(raw)  # type: ignore[arg-type]
        if 0 < value < float("inf"):
            return value
    except (TypeError, ValueError):
        pass
    _warn_once(key, raw, "number > 0")
    return default


def stale_years() -> float:
    """Effective staleness threshold. Project may only decrease (stricter) (issue #250)."""
    env = os.environ.get("SAFE_DEP_STALE_YEARS", "").strip()
    if env:
        return _positive_float(env, "SAFE_DEP_STALE_YEARS", STALE_YEARS_DEFAULT)
    section = _policy_file_data().get("staleness")
    raw = section.get("years") if isinstance(section, dict) else None
    user_years = STALE_YEARS_DEFAULT if raw is None else _positive_float(raw, "staleness.years", STALE_YEARS_DEFAULT)
    proj_section = _project_policy_file_data().get("staleness")
    proj_raw = proj_section.get("years") if isinstance(proj_section, dict) else None
    if proj_raw is not None:
        proj_years = _positive_float(proj_raw, "staleness.years", STALE_YEARS_DEFAULT)
        return min(user_years, proj_years)  # smaller threshold = stricter
    return user_years


def stale_popularity_guard() -> bool:
    """Effective popularity guard. Project may only disable (False = stricter) (issue #250)."""
    env = os.environ.get("SAFE_DEP_STALE_POPULARITY_GUARD", "").strip().lower()
    if env:
        return env not in ("0", "false", "no", "off")
    section = _policy_file_data().get("staleness")
    raw = section.get("popularity_guard") if isinstance(section, dict) else None
    if isinstance(raw, bool):
        user_guard = raw
    elif raw is not None:
        _warn_once("staleness.popularity_guard", raw, "true|false")
        user_guard = STALE_POPULARITY_GUARD_DEFAULT
    else:
        user_guard = STALE_POPULARITY_GUARD_DEFAULT
    proj_section = _project_policy_file_data().get("staleness")
    proj_raw = proj_section.get("popularity_guard") if isinstance(proj_section, dict) else None
    if isinstance(proj_raw, bool):
        return user_guard and proj_raw  # project can disable (False) but not re-enable
    if proj_raw is not None:
        _warn_once("staleness.popularity_guard", proj_raw, "true|false")
    return user_guard


def effective_policy() -> dict:
    """{dotted_key: (value, source)} with source in default|config|env.
    Used by the CLI's `config` (show) verb.

    Source reflects the value actually used: env/config sources that fail
    validation fall back to "default" here just as the getters do.
    """
    out: dict = {}

    def _valid(dotted_key: str, raw: object) -> bool:
        """True iff raw would be accepted (not trigger a warn+fallback)."""
        if dotted_key in ("cooloff.mode",) or dotted_key.startswith("checks."):
            return isinstance(raw, str) and raw.strip().lower() in TIERS
        if dotted_key == "checks.hashes_env":  # special alias – handled separately
            return isinstance(raw, str) and raw.strip().lower() in (*TIERS, "enforce")
        if dotted_key == "cooloff.days":
            return not isinstance(raw, bool) and _try_non_negative_int(raw)
        if dotted_key == "staleness.years":
            return not isinstance(raw, bool) and _try_positive_float(raw)
        if dotted_key == "staleness.popularity_guard":
            return isinstance(raw, bool)
        return False

    def _try_non_negative_int(raw: object) -> bool:
        try:
            return int(raw) >= 0  # type: ignore[call-overload]
        except (TypeError, ValueError):
            return False

    def _try_positive_float(raw: object) -> bool:
        try:
            v = float(raw)  # type: ignore[arg-type]
            return 0 < v < float("inf")
        except (TypeError, ValueError):
            return False

    def _source(dotted_key: str, env_var: "str | None", section: str, key: str) -> str:
        if env_var:
            env_raw = os.environ.get(env_var, "").strip()
            if env_raw:
                # hashes has its own aliases
                if dotted_key == "checks.hashes":
                    env_lc = env_raw.lower()
                    if env_lc in (*TIERS, "enforce"):
                        return "env"
                    return "default"
                # popularity_guard's env getter honors any non-empty string
                # (0/false/no/off -> False, anything else -> True); _valid's
                # bool-only rule governs only the config-file path below.
                if dotted_key == "staleness.popularity_guard":
                    return "env"
                if _valid(dotted_key, env_raw.lower() if dotted_key.endswith(".mode") else env_raw):
                    return "env"
                return "default"
        # User file
        user_sec = _policy_file_data().get(section)
        user_has_valid = (isinstance(user_sec, dict) and key in user_sec
                          and _valid(dotted_key, user_sec[key]))
        # Project file (monotonic hardening — issue #250)
        proj_sec = _project_policy_file_data().get(section)
        proj_has_valid = (isinstance(proj_sec, dict) and key in proj_sec
                          and _valid(dotted_key, proj_sec[key]))
        if not user_has_valid and not proj_has_valid:
            return "default"
        if not proj_has_valid:
            return "config"
        if not user_has_valid:
            return "project"
        # Both have valid values — project is the source only if it's stricter.
        u_raw = user_sec[key]  # type: ignore[index]
        p_raw = proj_sec[key]  # type: ignore[index]
        if dotted_key in ("cooloff.mode",) or dotted_key.startswith("checks."):
            u_idx = TIERS.index(u_raw.strip().lower())
            p_idx = TIERS.index(p_raw.strip().lower())
            return "project" if p_idx > u_idx else "config"
        if dotted_key == "cooloff.days":
            return "project" if p_raw > u_raw else "config"
        if dotted_key == "staleness.years":
            return "project" if p_raw < u_raw else "config"
        if dotted_key == "staleness.popularity_guard":
            return "project" if (p_raw is False and u_raw is True) else "config"
        return "config"

    out["cooloff.mode"] = (cooloff_mode(), _source("cooloff.mode", "SAFE_DEP_COOLOFF_MODE", "cooloff", "mode"))
    out["cooloff.days"] = (cooloff_days(), _source("cooloff.days", "SAFE_DEP_COOLOFF_DAYS", "cooloff", "days"))
    for name in CHECK_DEFAULTS:
        env_var = "SAFE_DEP_REQUIRE_HASHES" if name == "hashes" else None
        out[f"checks.{name}"] = (check_tier(name), _source(f"checks.{name}", env_var, "checks", name))
    out["staleness.years"] = (stale_years(), _source("staleness.years", "SAFE_DEP_STALE_YEARS", "staleness", "years"))
    out["staleness.popularity_guard"] = (
        stale_popularity_guard(),
        _source("staleness.popularity_guard", "SAFE_DEP_STALE_POPULARITY_GUARD", "staleness", "popularity_guard"))
    return out
