"""Read-modify-write for the global safer-dependencies config file.

Used only by the manager CLI (`/safer-dependencies config set|unset|reset`).
Hooks never import this module — they read policy via safedep.config.

stdlib has no TOML writer, so writes fully re-emit the file: comments and
formatting are NOT preserved. Only flat sections of scalar values
(bool | int | float | str) are managed; if the file holds anything else
(arrays, nested tables, non-table top-level keys other than ``schema``),
set/unset raise instead of silently corrupting it. Reads are strict for the
same reason: a file that cannot be parsed is never rewritten — the user must
fix it by hand or run ``config reset`` (the documented escape hatch, which
deletes a malformed file).
"""
from __future__ import annotations

import os
import tempfile

from safedep import config as _config
from safedep.config import _tomllib


class ConfigKeyError(Exception):
    """Unknown configuration key."""


class ConfigValueError(ValueError):
    """Value not allowed for this key."""


# Sections this tool owns; reset() removes exactly these and preserves
# everything else (e.g. [ecosystems]).
_MANAGED_SECTIONS = ("cooloff", "checks", "staleness")


# dotted key -> (validator, normalizer). Validators raise ConfigValueError.
def _tier(value: str) -> str:
    v = value.strip().lower()
    if v not in _config.TIERS:
        raise ConfigValueError(f"allowed: off | warn | block (got {value!r})")
    return v


def _nonneg_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise ConfigValueError(f"allowed: integer >= 0 (got {value!r})")
    if n < 0:
        raise ConfigValueError(f"allowed: integer >= 0 (got {value!r})")
    return n


def _pos_float(value: str) -> float:
    try:
        f = float(value)
    except ValueError:
        raise ConfigValueError(f"allowed: number > 0 (got {value!r})")
    if not (0 < f < float("inf")):
        raise ConfigValueError(f"allowed: number > 0 (got {value!r})")
    return f


def _boolean(value: str) -> bool:
    v = value.strip().lower()
    if v in ("true", "1", "yes", "on"):
        return True
    if v in ("false", "0", "no", "off"):
        return False
    raise ConfigValueError(f"allowed: true | false (got {value!r})")


def _known_keys() -> dict:
    keys: dict = {
        "cooloff.mode": _tier,
        "cooloff.days": _nonneg_int,
        "staleness.years": _pos_float,
        "staleness.popularity_guard": _boolean,
    }
    for name in _config.CHECK_DEFAULTS:
        keys[f"checks.{name}"] = _tier
    return keys


def _split(dotted: str) -> tuple:
    parsers = _known_keys()
    if dotted not in parsers:
        raise ConfigKeyError(
            f"unknown key {dotted!r}; known: {', '.join(sorted(parsers))}")
    section, key = dotted.split(".", 1)
    return section, key, parsers[dotted]


def _emit_toml(data: dict) -> str:
    for top, value in data.items():
        if top == _config.SCHEMA_VERSION_KEY:
            continue
        if not isinstance(value, dict):
            raise ConfigValueError(
                f"cannot rewrite config: top-level key {top!r} holds a "
                "non-section value this tool does not manage — edit the "
                "file by hand")
    lines = ["schema = 1", ""]
    for section in sorted(k for k in data if isinstance(data[k], dict)):
        body = data[section]
        if not body:
            continue
        lines.append(f"[{section}]")
        for key in sorted(body):
            value = body[key]
            if isinstance(value, bool):
                rendered = "true" if value else "false"
            elif isinstance(value, (int, float)):
                rendered = repr(value)
            elif isinstance(value, str):
                rendered = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
            else:
                raise ConfigValueError(
                    f"cannot rewrite config: section [{section}] key {key!r} "
                    "holds a non-scalar value this tool does not manage — "
                    "edit the file by hand")
            lines.append(f"{key} = {rendered}")
        lines.append("")
    return "\n".join(lines)


def _read_current() -> dict:
    """Strict parse of the user config file for read-modify-write.

    Deliberately does NOT reuse the fail-open `_config._load_toml` (which
    maps malformed TOML to {} so hooks keep running): rewriting on top of
    {} would silently discard the user's file. Missing file -> {}.
    """
    path = _config._user_config_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "rb") as fh:
            data = _tomllib.load(fh)
    except Exception:
        raise ConfigValueError(
            "config.toml is malformed — fix it by hand or run 'config reset' "
            "(set/unset refuse to touch a file they cannot parse)")
    return data if isinstance(data, dict) else {}


def _write(data: dict) -> None:
    path = _config._user_config_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    data.pop("schema", None)
    text = _emit_toml(data)  # may raise — before any temp file exists
    tmp = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=parent or ".", delete=False)
    try:
        with tmp:
            tmp.write(text)
        os.replace(tmp.name, path)
    except BaseException:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    _config.invalidate_caches()


def set_key(dotted: str, value: str) -> None:
    """Validate and persist one policy key to the global config file."""
    section, key, parse = _split(dotted)
    try:
        parsed = parse(value)
    except ConfigValueError as exc:
        raise ConfigValueError(f"{dotted}: {exc}") from None
    data = _read_current()
    data.setdefault(section, {})
    if not isinstance(data[section], dict):
        data[section] = {}
    data[section][key] = parsed
    _write(data)


def unset_key(dotted: str) -> None:
    """Remove one policy key from the global config file (no-op if absent)."""
    section, key, _parse = _split(dotted)
    data = _read_current()
    if isinstance(data.get(section), dict) and key in data[section]:
        del data[section][key]
        if not data[section]:
            del data[section]
        _write(data)


def reset() -> bool:
    """Revert all managed policy keys to defaults.

    Removes the managed sections ("cooloff", "checks", "staleness") from the
    global config file. Unmanaged sections (e.g. [ecosystems]) are preserved
    and written back. Returns True if the file was fully removed, False if
    unmanaged sections were preserved.
    """
    path = _config._user_config_path()
    try:
        data = _read_current()
    except ConfigValueError:
        # Malformed file: reset IS the documented escape hatch for a file
        # set/unset refuse to touch — delete it outright.
        data = {}
    data.pop("schema", None)
    for section in _MANAGED_SECTIONS:
        data.pop(section, None)
    if data:
        _write(data)
        return False
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    _config.invalidate_caches()
    return True
