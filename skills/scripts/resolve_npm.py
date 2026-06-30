import json, re, sys, datetime
from safedep.constants import VERSION_AGE_GATE_DAYS
from safedep.http import _parse_dt
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
    """Numeric-tuple sort key for semver version string *v* (higher = better).

    Tries ``packaging.version.Version`` first (fully correct semver/PEP 440);
    falls back to splitting on non-digit characters and comparing as integer
    tuples. Either way the result is a sortable key, not a Version object.
    """
    try:
        from packaging.version import Version
        return Version(v)
    except Exception:
        try:
            return tuple(int(x) for x in re.split(r'[^0-9]+', v.split('+')[0]) if x)
        except Exception:
            return (0,)


try:
    d = json.load(sys.stdin)
    now = datetime.datetime.now(datetime.timezone.utc)
    candidates = []
    for k, ts in d.items():
        if not isinstance(ts, str): continue
        if k in ('created', 'modified') or is_prerelease(k, 'npm'): continue
        pub = _parse_dt(ts)
        age = (now - pub).days
        candidates.append((k, ts[:10], age))
    # Sort by semver descending so a backport patch published later on an LTS
    # branch does not shadow a higher major version (issue #292).
    candidates.sort(key=lambda c: _version_key(c[0]), reverse=True)
    for c in candidates[:10]: print(f'{c[0]} {c[1]} ({c[2]}d)')
    _gate = _effective_gate_days()
    selected = [c for c in candidates if c[2] >= _gate]
    if selected: print(f'SELECTED: {selected[0][0]}')
    elif candidates: print(f'SELECTED: {candidates[0][0]}'); print(f'WARNING: no version >={_gate}d old, using newest available')
    else: print('ERROR: no stable versions found')
except json.JSONDecodeError as e:
    print(f'ERROR: stdin was not valid JSON ({e}); expected `npm view <pkg> time --json` output')
except (AttributeError, KeyError) as e:
    print(f'ERROR: registry response missing expected fields ({type(e).__name__}: {e}); package may be unpublished or registry returned an unexpected shape')
except (ValueError, TypeError) as e:
    print(f'ERROR: failed to parse version timestamps ({type(e).__name__}: {e})')
