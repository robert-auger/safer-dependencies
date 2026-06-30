"""Persistent cross-invocation lookup cache for OSV / registry results.

The shim runs as a fresh Python subprocess on every Claude Code hook fire, so
the in-process `_OSV_CACHE` (safer-dependencies-shim.sh:206) is rebuilt from
scratch each invocation. For workspaces with many manifests (and many overlapping
deps) this drives orders of magnitude more network calls than necessary.

This module provides a small file-backed cache, keyed by stable, global facts
(ecosystem + package + version), so consecutive hook invocations on the same
machine can share lookup results.

Design constraints:

  * **User-home, not project-local.** Lookup results are global (PyPI's
    requests==2.31.0 is the same package no matter who asks). Project-local
    would defeat the cross-project hit rate that motivated the cache.
  * **Process-safe.** Multiple Claude sessions / IDE invocations can fire
    concurrently. Writes use fcntl.flock (advisory) and tempfile-then-rename
    so a partial write never replaces a good cache file. Reads are lockless
    and tolerant of corruption (parse failure → return empty cache, fall
    through to live lookup).
  * **Bounded.** The whole cache lives in one JSON file kept under a size cap.
    LRU eviction on write keeps it under one block read.
  * **Conservatively stale.** Each entry carries its own TTL. Defaults are
    short (24h for OSV, 6h for version metadata). `SAFE_DEP_CACHE_DISABLE=1`
    bypasses the cache entirely for correctness audits.

This module never raises on cache failure. The caller's path through to a
live network lookup must always work even if the cache disk is full,
read-only, gone, or owned by another user. Failures are silent by design.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any, Optional

try:
    import fcntl  # POSIX-only — absent on Windows
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False

try:
    import msvcrt  # Windows-only — absent on POSIX
    _HAS_MSVCRT = True
except ImportError:
    _HAS_MSVCRT = False

# True if the host has *some* file-locking primitive. False only on truly
# exotic platforms (e.g. Pyodide). Drives the lock-acquire fallback below.
_HAS_LOCKING = _HAS_FCNTL or _HAS_MSVCRT


# Default TTLs (seconds). Each entry carries its own ttl so a future change
# to the defaults doesn't invalidate already-written entries.
TTL_OSV = 24 * 3600           # 24h — vuln data is reasonably stable
TTL_VERSIONS = 6 * 3600       # 6h  — registries publish new versions often
TTL_NEGATIVE = 7 * 24 * 3600  # 7d  — registry 404s are very stable
TTL_POPULARITY = 24 * 3600    # 24h — weekly/cumulative download counts move
                              #       slowly; a day of staleness never flips a
                              #       popular/unpopular verdict at the threshold.

# Bounded cache file size. 10MB fits ~50k entries; LRU eviction kicks in
# above this. One JSON parse on a fresh-from-disk read should still be
# well under the 60-180s hook budget.
DEFAULT_MAX_BYTES = 10 * 1024 * 1024


def _cache_disabled() -> bool:
    """Read SAFE_DEP_CACHE_DISABLE on every call so tests can flip it mid-run."""
    val = os.environ.get("SAFE_DEP_CACHE_DISABLE", "").lower()
    return val in ("1", "true", "yes", "on")


def cache_dir() -> str:
    """Resolve the cache directory, honoring env overrides.

    Order:
      1. SAFE_DEP_CACHE_DIR (explicit override — used to scope per-project)
      2. XDG_CACHE_HOME/safe-dep
      3. ~/.cache/safe-dep
    """
    explicit = os.environ.get("SAFE_DEP_CACHE_DIR")
    if explicit:
        return explicit
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return os.path.join(xdg, "safe-dep")
    return os.path.join(os.path.expanduser("~"), ".cache", "safe-dep")


def _cache_file() -> str:
    return os.path.join(cache_dir(), "lookups.json")


def _max_bytes() -> int:
    raw = os.environ.get("SAFE_DEP_CACHE_MAX_BYTES")
    if not raw:
        return DEFAULT_MAX_BYTES
    try:
        n = int(raw)
        return n if n > 0 else DEFAULT_MAX_BYTES
    except ValueError:
        return DEFAULT_MAX_BYTES


def _now() -> int:
    return int(time.time())


def _read_all() -> dict:
    """Best-effort cache read. Always returns a dict; never raises.

    A partial write (e.g. another process is mid-rename) or any other
    parse failure returns an empty dict, causing the caller to fall
    through to a live network lookup. That's strictly safe — never wrong,
    only slower.
    """
    path = _cache_file()
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {}


def _write_all(data: dict) -> None:
    """Atomic write: tempfile in same dir, fsync, rename.

    Holds an advisory exclusive lock on a sidecar lock file for the duration
    of the read-modify-write cycle to keep concurrent writers from clobbering
    each other's evictions. POSIX uses ``fcntl.flock``; Windows uses
    ``msvcrt.locking`` on byte 0 of the lock file. On platforms with neither
    primitive (rare — Pyodide etc.) the lock is a no-op and the cache falls
    back to last-writer-wins via ``os.replace``, which is atomic but can
    lose evictions under concurrent writes.
    """
    cdir = cache_dir()
    try:
        os.makedirs(cdir, exist_ok=True)
    except OSError:
        return  # cache dir not writable — silent skip

    path = _cache_file()
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".lookups-", suffix=".json.tmp", dir=cdir)
        with os.fdopen(fd, "wb") as fh:
            fh.write(json.dumps(data, separators=(",", ":")).encode("utf-8"))
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass  # fsync not supported on every fs (e.g. tmpfs in some CI)
        os.replace(tmp, path)
        tmp = None  # ownership transferred to the cache file
    except OSError:
        pass  # mkstemp / write / rename all failed; silent skip
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _lock_path() -> str:
    """Lock file path. Separate from the cache file so the lock fd isn't
    invalidated by atomic rename of the cache itself."""
    return os.path.join(cache_dir(), ".lookups.lock")


def _try_acquire_exclusive(fh) -> bool:
    """Attempt non-blocking exclusive lock on ``fh``. Return True on success.

    Dispatches to ``fcntl.flock`` on POSIX and ``msvcrt.locking`` on Windows.
    On Windows the kernel locks a byte range, not the file as a whole, so we
    seek to byte 0 and lock 1 byte — a convention recognised by every other
    msvcrt-using process. The byte does not need to exist on disk; Windows'
    file-lock manager works above the data layer. On platforms with neither
    primitive, returns False (caller proceeds without a lock).
    """
    if _HAS_FCNTL:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False
    if _HAS_MSVCRT:
        try:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
            return True
        except OSError:
            return False
    return False


def _release_lock(fh) -> None:
    """Release a lock previously acquired via :func:`_try_acquire_exclusive`.

    Silent on any error — the caller's flow must not depend on lock release
    succeeding (process exit will release it anyway).
    """
    if _HAS_FCNTL:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        return
    if _HAS_MSVCRT:
        try:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
        except OSError:
            pass


class _FileLock:
    """Advisory exclusive lock with timeout. Cross-platform.

    Backend dispatch:
      * POSIX  → ``fcntl.flock`` (whole-file advisory lock)
      * Windows → ``msvcrt.locking`` (byte-range lock on byte 0 of sidecar)
      * Neither → no-op (cache falls back to last-writer-wins via os.replace,
                  which is atomic but can lose evictions under contention)
    """

    def __init__(self, timeout_s: float = 2.0):
        self.timeout_s = timeout_s
        self.fh = None
        self.held = False

    def __enter__(self):
        if not _HAS_LOCKING:
            return self
        try:
            os.makedirs(cache_dir(), exist_ok=True)
        except OSError:
            return self
        try:
            self.fh = open(_lock_path(), "a+b")
        except OSError:
            self.fh = None
            return self
        deadline = time.monotonic() + self.timeout_s
        while True:
            if _try_acquire_exclusive(self.fh):
                self.held = True
                return self
            if time.monotonic() >= deadline:
                # Timed out waiting for lock. Proceed without it; the write
                # itself is still atomic via tempfile+rename, so the worst
                # case is a lost eviction, not corruption.
                self._close()
                return self
            time.sleep(0.02)

    def __exit__(self, exc_type, exc, tb):
        if self.fh is None:
            return
        if self.held:
            _release_lock(self.fh)
            self.held = False
        self._close()

    def _close(self):
        if self.fh is not None:
            try:
                self.fh.close()
            except OSError:
                pass
            self.fh = None


def get(key: str) -> Optional[Any]:
    """Return the cached value for key, or None if absent / expired / disabled.

    `None` is also a possible *value* a caller might want to cache (e.g.
    "no vulnerabilities" represented as []), so callers should treat get()
    None as a cache miss and supply their own sentinel for "cached as None"
    if they need to. In practice safedep's results are list-typed (CVE IDs)
    or bool-typed (existence), and absence collapses cleanly to a miss.
    """
    if _cache_disabled():
        return None
    data = _read_all()
    entry = data.get(key)
    if not isinstance(entry, dict):
        return None
    ts = entry.get("ts")
    ttl = entry.get("ttl")
    if not isinstance(ts, int) or not isinstance(ttl, int):
        return None
    if _now() - ts > ttl:
        return None
    # Stamp last-access time for LRU. We don't write back on read for cost
    # reasons; LRU is approximated by ts (write time).
    return entry.get("v")


def put(key: str, value: Any, ttl: int) -> None:
    """Cache value under key with the given TTL (seconds).

    Read-modify-write under flock. Performs LRU eviction if the resulting
    file would exceed the size cap.
    """
    if _cache_disabled():
        return
    if not isinstance(ttl, int) or ttl <= 0:
        return
    with _FileLock():
        data = _read_all()
        data[key] = {"v": value, "ts": _now(), "ttl": ttl}
        _maybe_evict(data)
        _write_all(data)


def _maybe_evict(data: dict) -> None:
    """If the serialised cache would exceed the size cap, drop oldest entries.

    Eviction is approximate: we serialise once to measure, then drop the
    bottom 25% by ts. Cheaper than incremental sizing per entry; runs
    only on writes, which are infrequent compared to reads.
    """
    cap = _max_bytes()
    serialized = json.dumps(data, separators=(",", ":")).encode("utf-8")
    if len(serialized) <= cap:
        return
    items = sorted(
        data.items(),
        key=lambda kv: kv[1].get("ts", 0) if isinstance(kv[1], dict) else 0,
    )
    drop_n = max(1, len(items) // 4)
    for k, _ in items[:drop_n]:
        data.pop(k, None)


def get_or_compute(key: str, compute_fn, ttl: int) -> Any:
    """Memoize the result of compute_fn under key for ttl seconds.

    compute_fn is a zero-arg callable invoked on cache miss. Its return
    value is cached as-is; if it returns None, nothing is cached (treating
    None as a transient failure that should be re-tried on next call).
    """
    cached = get(key)
    if cached is not None:
        return cached
    value = compute_fn()
    if value is not None:
        put(key, value, ttl)
    return value


# Stable, collision-free key builders. Always use these — never hand-format.
def osv_key(ecosystem: str, package: str, version: str) -> str:
    return f"osv:{ecosystem}:{package}@{version}"


def versions_key(ecosystem: str, package: str) -> str:
    return f"versions:{ecosystem}:{package}"


def exists_key(ecosystem: str, package: str) -> str:
    return f"exists:{ecosystem}:{package}"


def popularity_key(ecosystem: str, package: str) -> str:
    return f"pop:{ecosystem}:{package}"
