"""HTTP + datetime helpers shared by the shim and the standalone CLI scripts.

These are the canonical versions extracted from safer-dependencies-shim.sh. The
shim's implementation is used as-is because it is strictly more robust than
the inline parsing previously embedded in the standalone scripts:
  * _parse_dt handles both the 'Z' suffix and explicit '+00:00' offsets,
    and falls back to UTC for naive timestamps.
  * _http_get / _http_get_text / _http_post_json set a User-Agent header,
    honour a timeout, and return None/"" on any error.

Strict variants (``*_strict``) raise :class:`HTTPLookupError` instead of
swallowing errors, so callers (e.g. the OSV vulnerability check) can
distinguish "rate-limited / network failure / bad JSON" from "the server
replied with a valid empty payload". This is the fix for #109: the old
lenient helpers collapsed 429s into ``None`` / ``""``, which downstream
code misread as "no CVEs found" — silently marking rate-limited packages
as safe.

Connection pooling (PR #119): requests are routed through a per-thread
``(scheme, host, port) -> HTTPSConnection`` pool so successive calls to
the same host reuse the TCP + TLS handshake. On a 100-package audit
touching ~5 hosts × ~5 calls each, this drops the per-invocation
handshake cost from ~75 s of TLS to ~0.75 s (5 cold + ~495 warm).

Thread-local pools (this revision, for the concurrent-fetches work):
``http.client.HTTPSConnection`` is NOT safe for concurrent ``request()``
calls on the same connection. Rather than wrap a shared pool in a lock
(contention on the hot path), each thread gets its own pool via
``threading.local``. Single-threaded callers see the same behavior as
before — the main thread's pool is just the "first" thread's pool.

The :func:`parallel_map` helper uses ``ThreadPoolExecutor.map`` so
callers (e.g. the 8 lockfile audit loops) can fan out HTTP work safely.

Transient retry (this revision): requests that come back with HTTP 429
(rate-limited) or 503 (service unavailable) are retried with exponential
backoff + jitter, up to ``_MAX_RETRIES`` times (default 2 retries, total 3
attempts). Honors the ``Retry-After`` response header when present, capped
at ``_MAX_BACKOFF_S`` so a 60 s hook budget cannot be blown by a single
slow registry. Transport-level errors (URLError / TimeoutError) are
retried under the same policy. 4xx other than 429 and 5xx other than 503
are NOT retried — they indicate persistent client / server bugs, and a
silent retry would just compound them.

Set ``SAFE_DEP_HTTP_RETRY_DISABLE=1`` to disable retry entirely (fail
fast — used by some CI smoke tests). Override ``_MAX_RETRIES`` via the
``SAFE_DEP_HTTP_MAX_RETRIES`` env var.
"""
import http.client
import json
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote as _urlquote
from urllib.parse import urlsplit
# Kept as importable names for back-compat with any caller / test that still
# references them — the pooled plumbing below is what the helpers now use.
from urllib.request import Request, urlopen  # noqa: F401


def quote_pkg(pkg: str, *, keep_slash: bool = False) -> str:
    """Percent-encode a package name for safe interpolation into a URL path segment.

    Flat registry tokens (PyPI / RubyGems / crates names, which are
    ``[A-Za-z0-9._-]``) are returned unchanged, so this is a no-op on the common
    path. Names that contain reserved characters — ``/``, ``@``, whitespace,
    ``?``, ``#`` — are encoded so a crafted or malformed name cannot break out of
    the intended path segment and corrupt the path or query string of the
    registry request. This matches the ad-hoc ``%40``/``%2F`` escaping the npm
    paths already did by hand.

    Pass ``keep_slash=True`` for ecosystems whose names legitimately contain
    ``/`` as a hierarchical separator (e.g. Packagist ``vendor/package``); the
    slash is preserved while every other reserved character is still encoded. Go
    module paths are NOT handled here — they use the proxy's case-encoding via
    :func:`safedep.goproxy.encode_module_path`.
    """
    return _urlquote(pkg, safe="/" if keep_slash else "")


class HTTPLookupError(Exception):
    """Raised by the strict HTTP helpers when a request cannot be completed.

    Attributes:
        url: the URL that was being fetched.
        status: integer HTTP status code if the server replied (e.g. 429,
            500), or ``None`` for pre-response failures (DNS, connection
            reset, timeout, URLError).
        reason: short human-readable explanation.
    """

    def __init__(self, url: str, status=None, reason: str = ""):
        self.url = url
        self.status = status
        self.reason = reason
        label = f"HTTP {status}" if status is not None else "network error"
        super().__init__(f"{label} for {url}: {reason}" if reason else f"{label} for {url}")


def _parse_dt(ts: str) -> datetime:
    """Parse an ISO 8601 timestamp to an aware datetime, handling the Z suffix."""
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ────────────────── pooled HTTP plumbing ──────────────────

_USER_AGENT = "safer-dependencies-shim/1.0"
_MAX_REDIRECTS = 3
_DEFAULT_MAX_WORKERS = 8

# ── Transient retry config ───────────────────────────────────────────────────
# Total attempts = 1 initial + _MAX_RETRIES retries. Capped backoff keeps the
# whole retry cycle under ~10 s so a single hook fire cannot exceed the 60 s
# default hook timeout even if every retry waits the full cap.
_DEFAULT_MAX_RETRIES = 2
_BASE_BACKOFF_S = 1.0
_MAX_BACKOFF_S = 5.0
_TRANSIENT_STATUSES = frozenset({429, 503})

# Status codes that are "transient with explicit guidance" — when the server
# replies with one of these AND a Retry-After header, we honor the header
# (capped). A bare 429 with no Retry-After uses the exponential schedule.

# Test seam: tests can monkeypatch _sleep / _jitter to make retry deterministic.
_sleep = time.sleep


def _jitter(base: float) -> float:
    """Return ``base ± 25 %`` to spread out colliding retries from many workers."""
    return base * (0.75 + random.random() * 0.5)


def _retry_disabled() -> bool:
    val = os.environ.get("SAFE_DEP_HTTP_RETRY_DISABLE", "").lower()
    return val in ("1", "true", "yes", "on")


def _resolve_max_retries() -> int:
    raw = os.environ.get("SAFE_DEP_HTTP_MAX_RETRIES")
    if raw and raw.strip().lstrip("-").isdigit():
        return max(0, min(int(raw), 5))
    return _DEFAULT_MAX_RETRIES


def _parse_retry_after(value: str) -> "float | None":
    """Parse a Retry-After header value. Returns seconds or None on garbage.

    RFC 7231 allows two formats: integer seconds (``"30"``) or HTTP-date
    (``"Wed, 21 Oct 2026 07:28:00 GMT"``). For simplicity — and because OSV /
    npm / PyPI all use the seconds form in practice — we honor only the
    integer form. Date form falls through to the exponential schedule, which
    is strictly safe (we'll wait *less* than the server suggested).
    """
    if not value:
        return None
    s = value.strip()
    try:
        n = float(s)
        if n < 0:
            return None
        return n
    except ValueError:
        return None


def _compute_backoff(attempt: int, retry_after_header: str = "") -> float:
    """Choose a sleep duration for the next retry attempt.

    ``attempt`` is 0-indexed: 0 = first retry, 1 = second retry, etc.
    Honors a numeric Retry-After header if provided, capped at
    ``_MAX_BACKOFF_S``. Otherwise: exponential ``base * 2**attempt``,
    also capped, with ±25 % jitter to spread colliding retries.
    """
    explicit = _parse_retry_after(retry_after_header)
    if explicit is not None:
        return min(explicit, _MAX_BACKOFF_S)
    raw = _BASE_BACKOFF_S * (2 ** attempt)
    return min(_jitter(raw), _MAX_BACKOFF_S)

# Thread-local storage for the connection pool. Each thread gets its own
# ``pool`` dict: (scheme, host, port) -> HTTPConnection/HTTPSConnection.
# http.client connections are not safe for concurrent request() calls, so
# threads must not share them. For back-compat with the previous single-dict
# interface, ``_CONN_POOL`` is exposed as a module-level proxy that resolves
# to the current thread's pool on access.
_TL = threading.local()


def _pool() -> dict:
    """Return the current thread's connection pool, creating it on first use."""
    d = getattr(_TL, "pool", None)
    if d is None:
        d = {}
        _TL.pool = d
    return d


class _ConnPoolProxy:
    """Module-level ``_CONN_POOL`` view that transparently resolves to the
    current thread's pool. Existing tests and callers that read / mutate
    ``_CONN_POOL`` keep working on the main thread; threaded callers see
    their own thread's pool. Read-only callers see the main thread's pool
    when accessed from the main thread."""

    def __getitem__(self, key):
        return _pool()[key]

    def __setitem__(self, key, value):
        _pool()[key] = value

    def __delitem__(self, key):
        del _pool()[key]

    def __contains__(self, key):
        return key in _pool()

    def __iter__(self):
        return iter(_pool())

    def __len__(self):
        return len(_pool())

    def get(self, key, default=None):
        return _pool().get(key, default)

    def pop(self, key, *args):
        return _pool().pop(key, *args)

    def values(self):
        return _pool().values()

    def items(self):
        return _pool().items()

    def keys(self):
        return _pool().keys()

    def clear(self):
        _pool().clear()


_CONN_POOL = _ConnPoolProxy()


def _new_conn(scheme: str, host: str, port, timeout: int):
    if scheme == "https":
        return http.client.HTTPSConnection(host, port or 443, timeout=timeout)
    return http.client.HTTPConnection(host, port or 80, timeout=timeout)


def _get_conn(scheme: str, host: str, port, timeout: int):
    pool = _pool()
    key = (scheme, host, port)
    conn = pool.get(key)
    if conn is None:
        conn = _new_conn(scheme, host, port, timeout)
        pool[key] = conn
    else:
        # http.client connection exposes `timeout` as a mutable attribute;
        # adjust per-call without rebuilding the socket.
        conn.timeout = timeout
    return conn, key


def _reset_conn(key, timeout: int):
    pool = _pool()
    old = pool.pop(key, None)
    if old is not None:
        try:
            old.close()
        except Exception:
            pass
    conn = _new_conn(key[0], key[1], key[2], timeout)
    pool[key] = conn
    return conn


def _single_pooled_request(method: str, url: str, body, headers: dict, timeout: int):
    """Execute ONE HTTP request on a pooled connection (no redirect handling).

    Returns ``(status, reason, headers, body_bytes)``. Raises
    :class:`urllib.error.URLError` on transport failure (after a single retry
    on idle-connection close).
    """
    parts = urlsplit(url)
    scheme = parts.scheme or "https"
    host = parts.hostname
    port = parts.port
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    # urlsplit returns Optional[str] for hostname — None for malformed inputs
    # like "https://" or schemes without an authority (e.g. file:///x).
    # Surface a clean URLError naming the bad URL rather than letting None
    # propagate into http.client.HTTPSConnection where it raises an opaque
    # TypeError from the stdlib's CVE-2019-18348 guard.
    if not host:
        raise URLError(f"no hostname in URL: {url!r}")

    full_headers = {"User-Agent": _USER_AGENT, "Connection": "keep-alive"}
    if headers:
        full_headers.update(headers)
    if body is not None and "Content-Length" not in full_headers:
        full_headers["Content-Length"] = str(len(body))

    conn, key = _get_conn(scheme, host, port, timeout)

    last_err = None
    for attempt in range(2):
        try:
            conn.request(method, path, body=body, headers=full_headers)
            response = conn.getresponse()
            data = response.read()
            return response.status, response.reason, response.headers, data
        except (http.client.RemoteDisconnected, ConnectionError, BrokenPipeError,
                http.client.BadStatusLine, OSError) as e:
            last_err = e
            if attempt == 0:
                conn = _reset_conn(key, timeout)
                continue
            raise URLError(f"connection error after retry: {e}") from e
    raise URLError(f"unreachable: {last_err}")


def _pooled_request(method: str, url: str, body=None, headers=None, timeout: int = 10):
    """Perform an HTTP request via the connection pool, following redirects.

    Returns ``(status, body_bytes)`` on a 2xx response. Raises
    :class:`urllib.error.HTTPError` on 4xx/5xx (after exhausting retries on
    429 / 503), :class:`urllib.error.URLError` on transport failure (after
    exhausting retries), :class:`TimeoutError` on connect/read timeout —
    same contract as ``urlopen`` so the existing except-clauses stay valid.

    Retries on 429 (rate-limited), 503 (unavailable), and transport-level
    URLError / TimeoutError. Capped at ``_MAX_RETRIES`` retries total (env
    override ``SAFE_DEP_HTTP_MAX_RETRIES``); honors numeric ``Retry-After``
    headers, capped at ``_MAX_BACKOFF_S``. Set ``SAFE_DEP_HTTP_RETRY_DISABLE=1``
    to fail fast (used by some CI smoke tests).
    """
    current_url = url
    current_method = method
    current_body = body
    max_retries = 0 if _retry_disabled() else _resolve_max_retries()

    for _ in range(_MAX_REDIRECTS + 1):
        # Inner retry loop — runs up to (1 + max_retries) attempts on
        # transient status codes / transport errors. Non-transient errors
        # break out immediately.
        attempt = 0
        while True:
            try:
                status, reason, resp_headers, data = _single_pooled_request(
                    current_method, current_url, current_body, headers, timeout
                )
            except (URLError, TimeoutError):
                # Transport error — count as a retryable attempt.
                if attempt >= max_retries:
                    raise
                _sleep(_compute_backoff(attempt))
                attempt += 1
                continue

            # Got a response. Check if its status is transient.
            if status in _TRANSIENT_STATUSES and attempt < max_retries:
                ra = ""
                # resp_headers may be a http.client.HTTPMessage (case-insensitive)
                # or a plain dict (in tests). Try both safely.
                try:
                    ra = resp_headers.get("Retry-After", "") if resp_headers else ""
                except Exception:
                    ra = ""
                _sleep(_compute_backoff(attempt, ra or ""))
                attempt += 1
                continue

            # Settled — non-transient or retries exhausted. Fall through.
            break

        if status in (301, 302, 303, 307, 308):
            location = resp_headers.get("Location")
            if location:
                if "://" not in location:
                    parts = urlsplit(current_url)
                    prefix = "" if location.startswith("/") else "/"
                    location = f"{parts.scheme}://{parts.netloc}{prefix}{location}"
                current_url = location
                if status == 303 and current_method != "GET":
                    current_method = "GET"
                    current_body = None
                continue
        if status >= 400:
            raise HTTPError(current_url, status, reason, resp_headers, None)
        return status, data
    raise URLError(f"too many redirects from {url}")


def _close_pool() -> None:
    """Close every pooled connection for the *current thread*. Primarily for
    test teardown. In a single-threaded shim run this closes everything;
    under :func:`parallel_map`, each worker thread's pool is closed when
    that thread exits."""
    pool = _pool()
    for conn in list(pool.values()):
        try:
            conn.close()
        except Exception:
            pass
    pool.clear()


# ────────────────── bounded-concurrency fan-out ──────────────────

def _resolve_max_workers(explicit):
    """Resolve the worker count from (in priority order):
    1. an explicit ``max_workers`` kwarg,
    2. the ``SAFE_DEP_MAX_WORKERS`` env var,
    3. :data:`_DEFAULT_MAX_WORKERS` (8).

    Clamped to ``[1, 32]`` to stop accidental misconfig from spawning
    absurd numbers of workers against well-behaved registries.
    """
    if explicit is not None:
        n = int(explicit)
    else:
        raw = os.environ.get("SAFE_DEP_MAX_WORKERS")
        n = int(raw) if raw and raw.strip().lstrip("-").isdigit() else _DEFAULT_MAX_WORKERS
    return max(1, min(n, 32))


def parallel_map(fn, items, max_workers=None):
    """Fan ``fn`` out over ``items`` using a bounded thread pool.

    Returns a list of results in the same order as ``items``. Exceptions
    raised by ``fn`` propagate at the corresponding position — callers that
    want per-item error capture should wrap ``fn`` themselves so the error
    semantics stay explicit at the call site.

    Each worker thread gets its own connection pool (see :func:`_pool`),
    so concurrent HTTP requests do not race on a shared
    ``http.client.HTTPSConnection``. On small ``items`` counts the
    executor is skipped for speed — there is no benefit to spawning
    threads for a single item.
    """
    items = list(items)
    if not items:
        return []
    if len(items) == 1:
        return [fn(items[0])]
    workers = min(_resolve_max_workers(max_workers), len(items))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))


# ────────────────── lenient helpers (None/"" on any error) ──────────────────

def _http_get_text(url: str, timeout: int = 10) -> str:
    """GET url, return response body as plain text or '' on any error."""
    try:
        _, body = _pooled_request("GET", url, timeout=timeout)
        return body.decode()
    except Exception:
        return ""


def _http_get(url: str, timeout: int = 10, headers: "dict | None" = None):
    """GET url, return parsed JSON or None on any error.

    ``headers`` is an optional dict of request headers (e.g. Authorization
    for GitHub API calls). Backward-compatible: existing callers that omit
    it get the previous behavior unchanged.
    """
    try:
        _, body = _pooled_request("GET", url, timeout=timeout, headers=headers)
        return json.loads(body.decode())
    except Exception:
        return None


def _http_get_status(url: str, timeout: int = 10) -> int:
    """GET url, return HTTP status code.

    Returns:
        the integer HTTP status (200, 404, 500, ...) on a completed response,
        0 on network failure / timeout / DNS error / etc.

    Used for existence probes where the caller specifically needs to
    distinguish "registry explicitly 404'd this package" from "could not
    reach the registry". A plain _http_get cannot make that distinction
    because it collapses both cases to None.
    """
    try:
        status, _ = _pooled_request("GET", url, timeout=timeout)
        return status
    except HTTPError as e:
        return e.code
    except Exception:
        return 0


def _http_post_json(url: str, payload: dict, timeout: int = 10):
    """POST JSON payload, return parsed response or None on any error."""
    try:
        _, body = _pooled_request(
            "POST", url,
            body=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        return json.loads(body.decode())
    except Exception:
        return None


# ────────────────── strict helpers (raise HTTPLookupError) ──────────────────

def _http_post_json_strict(url: str, payload: dict, timeout: int = 10):
    """POST JSON payload and return the parsed response.

    Raises :class:`HTTPLookupError` on any HTTP error (including 429), network
    failure, timeout, or JSON decode failure. Unlike :func:`_http_post_json`,
    this helper does **not** collapse errors into ``None``; callers need that
    distinction so a rate-limited vulnerability lookup is not misread as a
    clean response (#109).
    """
    data = json.dumps(payload).encode()
    try:
        _, body = _pooled_request(
            "POST", url, body=data,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
    except HTTPError as e:
        raise HTTPLookupError(url, status=e.code, reason=getattr(e, "reason", "") or str(e)) from e
    except URLError as e:
        raise HTTPLookupError(url, status=None, reason=str(getattr(e, "reason", e))) from e
    except TimeoutError as e:
        raise HTTPLookupError(url, status=None, reason="timeout") from e
    except Exception as e:
        raise HTTPLookupError(url, status=None, reason=f"{type(e).__name__}: {e}") from e
    try:
        return json.loads(body.decode())
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPLookupError(url, status=200, reason=f"invalid JSON: {e}") from e


def _http_get_strict(url: str, timeout: int = 10):
    """GET url and return the parsed JSON response.

    Raises :class:`HTTPLookupError` on any failure. Use this wherever a
    null/empty response would be misread as an authoritative negative result
    (#109). For best-effort registry lookups where ``None`` already triggers a
    visible ``WARNING`` downstream, the lenient :func:`_http_get` is still
    appropriate.
    """
    try:
        _, body = _pooled_request("GET", url, timeout=timeout)
    except HTTPError as e:
        raise HTTPLookupError(url, status=e.code, reason=getattr(e, "reason", "") or str(e)) from e
    except URLError as e:
        raise HTTPLookupError(url, status=None, reason=str(getattr(e, "reason", e))) from e
    except TimeoutError as e:
        raise HTTPLookupError(url, status=None, reason="timeout") from e
    except Exception as e:
        raise HTTPLookupError(url, status=None, reason=f"{type(e).__name__}: {e}") from e
    try:
        return json.loads(body.decode())
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPLookupError(url, status=200, reason=f"invalid JSON: {e}") from e
