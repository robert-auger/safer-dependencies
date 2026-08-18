"""Lock-file parsers shared between the shim and manual-mode skill.

Scope of this first cut: yarn.lock and pnpm-lock.yaml — the two npm-family
lock formats that the shim previously skipped (``# yarn.lock: silently skip
(no parser yet)``). The six existing in-shim parsers (package-lock.json,
Pipfile.lock, poetry.lock, uv.lock, Gemfile.lock, go.sum) are not extracted
here to keep the change size small; a follow-on PR can move them once this
shape stabilises.

Each parser returns ``[(name, version), ...]`` and is tolerant of malformed
input: a parse failure returns an empty list rather than raising, so the
caller can audit best-effort entries without blowing up the hook.

These functions are pure — no network calls, no OSV lookups. The caller
(the shim's audit dispatcher or the skill's manual-mode CLI) is responsible
for running each parsed entry through the OSV check, same as for manifest
files.
"""

from __future__ import annotations

import re


# ────────────────────────────── yarn.lock ──────────────────────────────


# yarn.lock has two version-line shapes:
#
#   v1 (classic):          version "X.Y.Z"
#   Berry (v2/v3/v4 YAML): version: X.Y.Z      (occasionally quoted)
#
# Both sit under a top-level selector key:
#
#   <selector>[, <selector> ...]:
#     version "X.Y.Z"        # v1
#     version: X.Y.Z         # Berry
#     resolution/resolved ...
#
# The selector is e.g. ``express@^4.17.1`` (v1) or ``"express@npm:^4.18.0"``
# (Berry). Multiple selectors can share the same resolution; the version
# comes from the indented ``version`` line. Berry lockfiles also carry a
# ``__metadata:`` block whose own ``version:`` line is the lockfile format
# version — _YARN_KEY requires an ``@`` in the selector, so that block never
# sets a current package name and its version line is ignored.
_YARN_KEY = re.compile(r'^"?(@?[^\s",@]+(?:/[^\s",@]+)?)@')
_YARN_VERSION_V1 = re.compile(r'^\s+version\s+"([^"]+)"')
_YARN_VERSION_BERRY = re.compile(r'^\s+version:\s*"?([^"\s]+)"?\s*$')


def parse_yarn_lock(content: str) -> list:
    """Return [(name, version), ...] of resolved packages in yarn.lock.

    Deduplicated by (name, version). Selectors with the same resolution
    collapse to a single entry; selectors pointing at different resolved
    versions become distinct entries.
    """
    results: list = []
    seen = set()
    current_name = None
    for raw in content.splitlines():
        # Top-level keys are at column 0 and end with ':'
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            # Extract the first name from the (possibly comma-separated) selectors
            head = raw.split(",", 1)[0]
            m = _YARN_KEY.match(head)
            current_name = m.group(1) if m else None
            continue
        if current_name is None:
            continue
        m = _YARN_VERSION_V1.match(raw) or _YARN_VERSION_BERRY.match(raw)
        if m:
            version = m.group(1)
            key = (current_name, version)
            if key not in seen:
                seen.add(key)
                results.append(key)
            current_name = None  # one version per block
    return results


# ────────────────────────────── pnpm-lock.yaml ──────────────────────────────


# pnpm-lock.yaml keys each resolved package under ``packages:``:
#
#   v9 (current default):   <pkg>@<version>:          # no leading slash
#                           '@scope/<pkg>@<version>':
#   v6–v8:                  /<pkg>@<version>:
#                           /<pkg>@<version>(<peer>@<ver>):   # peer-dep context suffix
#                           /@scope/<pkg>@<version>:
#   v5:                     /<pkg>/<version>:
#
# This parser handles all three. The v9 pattern anchors on exactly two
# spaces of indent (entry keys), so 4-space-indented body lines
# (``resolution:``, ``engines:`` …) never match; peer-suffixed keys in the
# ``snapshots:`` section are excluded because the section gate below turns
# off at the next top-level key.
#
# v6–v8 differ from v9 in that the ``packages:`` section ITSELF carries the
# peer-dependency context as a ``(<peer>@<ver>)`` suffix on the key, e.g.
# ``/react-dom@18.2.0(react@18.2.0):`` (and multiple / nested groups like
# ``/a@1(b@2)(c@3):``). The v6 pattern therefore allows an optional trailing
# ``(...)`` group after the version. Without it the version token stopped at
# the ``(`` and the whole key failed to match, so every peer-dep'd package
# (react-dom, most of the Babel/ESLint/React ecosystem) parsed to nothing and
# was silently skipped from the CVE audit.
_PNPM_KEY_V9 = re.compile(
    r'^\s{2}[\'"]?(@[^/@\s]+/[^@\s]+|[^@\s/\'"]+)@([^\s\'"()]+)[\'"]?:'
)
_PNPM_KEY_V6 = re.compile(
    r'^\s{2}[\'"]?/(@[^/@]+/[^@\s]+|[^@\s/]+)@([^\s\'"()]+)(?:\(.*\))?[\'"]?:'
)
_PNPM_KEY_V5 = re.compile(
    r'^\s{2}[\'"]?/(@[^/]+/[^/]+|[^/]+)/([0-9][^\s\'"()]*)[\'"]?:'
)


def parse_pnpm_lock(content: str) -> list:
    """Return [(name, version), ...] of packages in pnpm-lock.yaml.

    Supports both v5 (/<pkg>/<version>) and v6+ (/<pkg>@<version>) key
    formats. Deduplicated.
    """
    results: list = []
    seen = set()
    in_packages = False
    for raw in content.splitlines():
        stripped = raw.strip()
        if not in_packages:
            if stripped == "packages:":
                in_packages = True
            continue
        # Exit the packages section when we hit a new top-level key
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            in_packages = False
            continue
        m = _PNPM_KEY_V6.match(raw) or _PNPM_KEY_V5.match(raw) or _PNPM_KEY_V9.match(raw)
        if m:
            key = (m.group(1), m.group(2))
            if key not in seen:
                seen.add(key)
                results.append(key)
    return results
