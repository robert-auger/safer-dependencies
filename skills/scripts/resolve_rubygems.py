import json, re, sys, datetime
from safedep.constants import VERSION_AGE_GATE_DAYS
from safedep.prerelease import is_prerelease


def _effective_gate_days() -> int:
    """Cooloff window for selection (issue #232): mode=off disables the
    age filter; days from config/env; hard fallback to the constant."""
    try:
        from safedep.config import cooloff_days, cooloff_mode
        if cooloff_mode() == "off":
            return 0
        return cooloff_days()
    except Exception:
        return VERSION_AGE_GATE_DAYS


def _version_key(v: str) -> tuple:
    """Numeric-tuple sort key for RubyGems version string *v* (higher = better).

    Splits on non-digit separators and compares as integer tuples. RubyGems
    uses rational versioning (``X.Y.Z`` and ``X.Y.Z.W``), so integer-tuple
    comparison is authoritative for all stable releases.
    """
    try:
        return tuple(int(x) for x in re.split(r'[^0-9]+', v) if x)
    except Exception:
        return (0,)


try:
    now = datetime.datetime.now(datetime.timezone.utc)
    vs = json.load(sys.stdin)
    candidates = []
    for v in vs:
        if is_prerelease(v['number'], 'rubygems'): continue
        ts = v['created_at'][:10]
        age = (now - datetime.datetime.fromisoformat(ts+'T00:00:00+00:00')).days
        candidates.append((v['number'], ts, age))
    # Sort by version descending: highest semver first, regardless of the
    # order the RubyGems API returned the version list (issue #292).
    candidates.sort(key=lambda c: _version_key(c[0]), reverse=True)
    for c in candidates[:10]: print(f'{c[0]} {c[1]} ({c[2]}d)')
    _gate = _effective_gate_days()
    selected = [c for c in candidates if c[2] >= _gate]
    if selected: print(f'SELECTED: {selected[0][0]}')
    elif candidates: print(f'SELECTED: {candidates[0][0]}'); print(f'WARNING: no version >={_gate}d old, using newest available')
    else: print('ERROR: no stable versions found')
except (json.JSONDecodeError, AttributeError, KeyError, ValueError, TypeError):
    print('ERROR: invalid response')
