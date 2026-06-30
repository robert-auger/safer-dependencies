import json, sys, re, datetime
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


try:
    from packaging.version import Version as V
except ImportError:
    def V(s):  # noqa: N802
        """Minimal PEP 440 comparator used when *packaging* is not installed.

        Handles: epochs (``N!``), release segments, and post-releases
        (``.postN`` / ``-postN`` / ``_postN``). Trailing zeros are stripped
        so ``1.0`` == ``1.0.0`` as PEP 440 requires. Pre-releases and dev
        releases are filtered by ``is_prerelease()`` before this runs, so
        they are not handled here.
        """
        raw = s.split('+')[0]  # strip local version label
        # Extract epoch (e.g. "1!2.0" → epoch=1, raw="2.0")
        epoch = 0
        if '!' in raw:
            epoch_str, raw = raw.split('!', 1)
            try:
                epoch = int(epoch_str)
            except ValueError:
                epoch = 0
        # Extract post-release suffix (.postN, _postN, -postN)
        post = -1  # -1 means no post-release; sorts below .post0
        pm = re.search(r'[._-]?post(\d+)$', raw, re.I)
        if pm:
            post = int(pm.group(1))
            raw = raw[:pm.start()]
        # Release segment as integer tuple, trailing zeros stripped
        # (so "1.0" and "1.0.0" compare equal per PEP 440)
        parts = [int(x) for x in re.split(r'[^0-9]+', raw) if x]
        while parts and parts[-1] == 0:
            parts.pop()
        key = (epoch, tuple(parts), post)
        return type('V', (), {
            '_key': key,
            '__lt__': lambda a, b: a._key < b._key,
            '__gt__': lambda a, b: a._key > b._key,
            '__eq__': lambda a, b: a._key == b._key,
            '__le__': lambda a, b: a._key <= b._key,
            '__ge__': lambda a, b: a._key >= b._key,
            '__repr__': lambda a: s,
        })()
try:
    d = json.load(sys.stdin)
    now = datetime.datetime.now(datetime.timezone.utc)
    versions = []
    for v, files in d.get('releases', {}).items():
        if not files or is_prerelease(v, 'pypi'): continue
        ts = files[0]['upload_time']
        age = (now - _parse_dt(ts)).days
        versions.append((V(v), v, ts[:10], age))
    versions.sort(reverse=True)
    for ver, name, ts, age in versions[:10]: print(f'{name} {ts} ({age}d)')
    _gate = _effective_gate_days()
    selected = [x for x in versions if x[3] >= _gate]
    if selected: print(f'SELECTED: {selected[0][1]}')
    elif versions: print(f'SELECTED: {versions[0][1]}'); print(f'WARNING: no version >={_gate}d old, using newest available')
    else: print('ERROR: no stable versions found')
except (json.JSONDecodeError, AttributeError, KeyError, ValueError, TypeError):
    print('ERROR: invalid response')
