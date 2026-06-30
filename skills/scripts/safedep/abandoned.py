"""Curated map of packages known to be abandoned or deprecated.

Entries in this map short-circuit Layer 1 checks: any package whose name is
listed here is blocked regardless of OSV, staleness, or typosquat results,
and the orchestrator is instructed to use the named replacement instead.

Contribution policy for new entries:
  - Package must have no release in the last 3 years OR
    a public maintainer-abandonment announcement / upstream CVE.
  - Each entry must name a concrete replacement package or approach.
  - Keep the value string short (one line). Longer guidance belongs in
    skills/safer-dependencies.md under the "Curated intelligence" section.

Keying: the top-level dict is keyed by ecosystem tag matching the internal
typosquat-script convention (lowercase, no spaces): "npm", "pypi",
"rubygems", "go", "maven". The nested dict is keyed by the package name
exactly as it appears in its manifest. Lookup is case-insensitive on
package names — see lookup().
"""

from __future__ import annotations

from typing import Optional


KNOWN_ABANDONED: dict[str, dict[str, str]] = {
    "rubygems": {
        "paperclip": "Unmaintained since 2018 — use ActiveStorage (built into Rails)",
        "capybara-webkit": "Abandoned — use selenium-webdriver or cuprite",
    },
    "npm": {
        "request": "Deprecated by maintainer 2020 — use node-fetch, got, or axios",
        "node-uuid": "Renamed to 'uuid' — update your import",
        "request-promise": "Deprecated by maintainer (extends deprecated 'request') — use got, axios, or node-fetch",
        "node-sass": "Deprecated by maintainer — use 'sass' (Dart Sass) or 'sass-embedded'",
        "coffee-script": "Renamed to 'coffeescript' (no hyphen) — update your import",
        "bower": "End-of-life 2017 — use npm/yarn/pnpm directly; no front-end-only package manager needed",
    },
    "go": {
        "github.com/dgrijalva/jwt-go": "Abandoned, CVE-2020-26160 — use github.com/golang-jwt/jwt/v5",
    },
    "pypi": {
        "pycrypto": "Abandoned since 2014, use pycryptodome",
        "distribute": "Merged into setuptools — use setuptools directly",
    },
}


def lookup(pkg: str, ecosystem: str) -> Optional[str]:
    """Return the abandonment note for pkg in ecosystem, or None.

    Performs a case-insensitive match against the package name, matching
    the historical behavior of the shim's check_abandoned helper.
    """
    eco_map = KNOWN_ABANDONED.get(ecosystem, {})
    return eco_map.get(pkg.lower()) or eco_map.get(pkg)
