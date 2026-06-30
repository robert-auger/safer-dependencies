"""Typosquat detection shared by the shim and the check_typosquat.py CLI.

Before this module existed, the same OSA distance algorithm, reference list,
normalisation rules, and threshold table lived in two places (~110 LOC
duplicated). Both copies have been collapsed here.

Public API:
    ``check(pkg, ecosystem) -> list[(distance, reference)]``
        All near-matches, sorted by distance then reference name. Used by the
        standalone CLI, which prints one ``TYPOSQUAT:`` line per hit.
    ``best_match(pkg, ecosystem) -> (distance, reference) | None``
        A thin view over ``check`` returning only the closest match. Used by
        the shim, where a single suggested package is what the hook signal
        carries.
    ``REFERENCE`` / ``normalize`` / ``osa_distance`` / ``threshold``
        Building blocks — exposed so future callers (and tests) can reach the
        individual pieces without going through ``check``.
"""
import re


# ---------------------------------------------------------------------------
# Reference lists — well-known packages per ecosystem. Typosquats of anything
# on these lists are flagged.
# ---------------------------------------------------------------------------
REFERENCE = {
    "npm": [
        "lodash", "express", "react", "axios", "chalk", "moment", "webpack",
        "babel-core", "colors", "left-pad", "event-stream", "cross-env",
        "dotenv", "uuid", "yargs", "minimist", "semver", "debug", "commander",
        "inquirer", "glob", "rimraf", "async", "request", "underscore",
        "jquery", "typescript", "eslint", "prettier", "jest", "mocha",
        "sinon", "chai", "angular", "vue", "next", "nuxt", "svelte",
        "webpack-cli", "babel", "rollup", "vite", "turbo",
    ],
    "pypi": [
        "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
        "setuptools", "six", "cryptography", "pillow", "sqlalchemy", "pytest",
        "click", "pydantic", "fastapi", "aiohttp", "httpx", "celery", "redis",
        "psycopg2", "pymongo", "colorama", "python-dateutil", "pytz",
        "certifi", "charset-normalizer", "idna", "packaging", "pip",
        "virtualenv", "tqdm", "scipy", "matplotlib", "paramiko", "fabric",
        "twisted", "scrapy", "beautifulsoup4", "lxml", "arrow",
    ],
    "rubygems": [
        "rails", "rake", "bundler", "nokogiri", "activerecord", "devise",
        "rspec", "sidekiq", "puma", "capistrano", "faker", "factory_bot",
        "rubocop", "httparty", "carrierwave", "pundit", "kaminari",
        "will_paginate", "paperclip", "cancancan", "ransack", "shrine",
        "dry-validation", "grape", "sinatra",
    ],
    "maven": [
        "org.springframework:spring-core",
        "com.google.guava:guava",
        "org.apache.commons:commons-lang3",
        "log4j:log4j",
        "org.slf4j:slf4j-api",
        "junit:junit",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.apache.commons:commons-io",
        "org.mockito:mockito-core",
        "org.projectlombok:lombok",
        "com.google.code.gson:gson",
        "org.apache.maven:maven-core",
    ],
    # crates.io is a flat-namespace registry (like npm), so name-distance
    # typosquats land in the same threat model. Go is intentionally not
    # listed: Go module identity is the full URL path
    # (``github.com/owner/repo``), not a bare name, and OSA-distance on
    # bare segments produces too many false positives there.
    "crates": [
        "serde", "tokio", "rand", "clap", "regex", "log",
        "anyhow", "thiserror", "chrono", "uuid", "futures", "async-trait",
        "reqwest", "actix-web", "rocket", "axum", "warp", "hyper",
        "tower", "tonic", "diesel", "sqlx", "sea-orm",
        "tracing", "env_logger", "slog",
        "syn", "quote", "proc-macro2",
        "serde_json", "serde_yaml", "toml", "bincode",
        "bytes", "smallvec", "indexmap", "hashbrown", "parking_lot",
        "crossbeam", "rayon", "lazy_static", "once_cell",
        "tokio-util", "tokio-stream",
        "wasm-bindgen", "yew", "leptos",
        "bevy", "egui",
    ],
}


_VERSION_STRIP = re.compile(r"[=><~!\[].*")


def normalize(name: str, ecosystem: str) -> str:
    """Strip version specifier, npm scope prefix, and lowercase.

    For crates.io, hyphens and underscores are interchangeable: Cargo treats
    ``env-logger`` and ``env_logger`` as the same crate.  We canonicalize to
    hyphens so the OSA-distance comparison never flags the legitimate hyphen
    form of an underscore-named reference crate (e.g. ``env-logger`` vs the
    reference entry ``env_logger`` would otherwise score distance 1 and be
    falsely flagged as a typosquat).
    """
    name = name.strip()
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        name = name.split("/", 1)[1]
    name = _VERSION_STRIP.sub("", name)
    if ecosystem == "npm" and "@" in name:
        name = name.split("@", 1)[0]
    name = name.lower()
    if ecosystem == "crates":
        name = name.replace("_", "-")
    return name


def osa_distance(a: str, b: str) -> int:
    """Optimal String Alignment (restricted Damerau-Levenshtein) distance.

    Treats insertions, deletions, substitutions, and transpositions as cost 1.
    """
    m, n = len(a), len(b)
    if abs(m - n) > 2:
        return abs(m - n)
    d = list(range(n + 1))
    # The transposition branch below reads prev_row_prev only when i > 1, by
    # which point line `prev_row_prev = prev_row` has already assigned a real
    # row from the previous iteration. Seed with a copy of the initial row
    # (never read on i == 1) instead of None so the type stays list[int] — a
    # None seed forced mypy into an unprovable Optional-narrowing false error.
    prev_row_prev: list[int] = d[:]
    for i in range(1, m + 1):
        prev_row = d[:]
        d[0] = i
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[j] = min(d[j] + 1, d[j - 1] + 1, prev_row[j - 1] + cost)
            if (i > 1 and j > 1 and a[i - 1] == b[j - 2]
                    and a[i - 2] == b[j - 1]):
                d[j] = min(d[j], prev_row_prev[j - 2] + cost)
        prev_row_prev = prev_row
    return d[n]


def threshold(length: int) -> int:
    """Edit-distance budget based on normalised name length.

    <4 chars: 0 (too short, false positives dominate).
    4-6 chars: 1.
    7+ chars: 2.
    """
    if length < 4:
        return 0
    if length < 7:
        return 1
    return 2


def check(pkg: str, ecosystem: str):
    """Return list of (distance, reference) hits, sorted by distance then name."""
    refs = REFERENCE.get(ecosystem)
    if not refs:
        return []
    norm = normalize(pkg, ecosystem)
    t = threshold(len(norm))
    if t == 0:
        return []
    hits = []
    for ref in refs:
        norm_ref = normalize(ref, ecosystem)
        if norm == norm_ref:
            return []  # exact match after normalisation — the real package
        dist = osa_distance(norm, norm_ref)
        if dist <= t:
            hits.append((dist, ref))
    hits.sort(key=lambda x: (x[0], x[1]))
    return hits


def best_match(pkg: str, ecosystem: str):
    """Return the closest typosquat match as (distance, reference), or None."""
    hits = check(pkg, ecosystem)
    return hits[0] if hits else None


def _popularity_suppresses(pkg: str, ecosystem: str) -> bool:
    """True if ``pkg`` is popular enough to suppress a typosquat match.

    Deferred import keeps the popularity module's network dependencies out
    of the import path of unit tests and offline callers.
    """
    from safedep.popularity import is_popular  # noqa: PLC0415
    return is_popular(pkg, ecosystem)


def check_guarded(pkg: str, ecosystem: str, *, skip_popularity: bool = False):
    """Same as check, but returns [] when ``pkg`` is itself known-popular.

    Used when the skill audits a single package such as ``pyarrow`` so it
    does not get a typosquat warning pointing at ``arrow`` — pyarrow has
    ~20M weekly PyPI downloads, a real typosquat could not accumulate that.

    ``skip_popularity=True`` disables the popularity lookup entirely and
    returns the raw ``check`` hits — useful for deterministic unit tests
    and for callers in environments without network access.
    """
    hits = check(pkg, ecosystem)
    if not hits or skip_popularity:
        return hits
    if _popularity_suppresses(pkg, ecosystem):
        return []
    return hits


def best_match_guarded(pkg: str, ecosystem: str, *, skip_popularity: bool = False):
    """Same as best_match, but suppresses the finding when ``pkg`` is itself a
    popular, known-legitimate package in its ecosystem.

    Motivation: prevents false positives of the ``pyarrow`` / ``arrow`` form,
    where two real packages share enough edit distance to trip the check but
    the candidate has enormous adoption itself. A real typosquat would not
    accumulate that kind of adoption before being flagged and removed.

    ``skip_popularity=True`` disables the popularity lookup entirely and
    falls back to raw best_match behaviour — useful when the caller has no
    network access, or for deterministic unit tests that should not hit
    external APIs.

    Returns (distance, reference) tuple when the finding should be surfaced,
    or None when:
      - there is no edit-distance match, OR
      - the candidate's download count in this ecosystem exceeds
        safedep.popularity.POPULARITY_THRESHOLD (suppressed).

    The popularity lookup fails open: network errors, 404s, and ecosystems
    without a canonical download source all fall through to the raw match.
    """
    hit = best_match(pkg, ecosystem)
    if hit is None or skip_popularity:
        return hit
    if _popularity_suppresses(pkg, ecosystem):
        return None
    return hit
