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
    """Numeric-tuple sort key for Maven version string *v* (higher = better).

    Extracts integer segments, ignoring qualifier strings (``-jre``,
    ``.RELEASE``, etc.) so that ``11.0.0-jre > 8.0.0-jre`` and
    ``2.0.0.RELEASE > 1.0.0.RELEASE`` are ordered correctly.
    """
    try:
        return tuple(int(x) for x in re.split(r'[^0-9]+', v) if x)
    except Exception:
        return (0,)


try:
    now = datetime.datetime.now(datetime.timezone.utc)
    docs = json.load(sys.stdin)['response']['docs']
    candidates = []
    for d in docs:
        v = d['v']
        if is_prerelease(v, 'maven'): continue
        ts = datetime.datetime.fromtimestamp(d['timestamp']/1000, datetime.timezone.utc)
        age = (now - ts).days
        tsf = ts.strftime('%Y-%m-%d')
        candidates.append((v, tsf, age))
    # Sort by version descending: highest version first, regardless of the
    # order Maven Central returned the search docs (issue #292).
    candidates.sort(key=lambda c: _version_key(c[0]), reverse=True)
    for c in candidates[:10]: print(f'{c[0]} {c[1]} ({c[2]}d)')
    _gate = _effective_gate_days()
    selected = [c for c in candidates if c[2] >= _gate]
    if selected: print(f'SELECTED: {selected[0][0]}')
    elif candidates: print(f'SELECTED: {candidates[0][0]}'); print(f'WARNING: no version >={_gate}d old, using newest available')
    else: print('ERROR: no stable versions found')
except (json.JSONDecodeError, AttributeError, KeyError, ValueError, TypeError):
    print('ERROR: invalid response')
