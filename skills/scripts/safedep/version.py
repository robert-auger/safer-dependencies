"""Version reporting for the safer-dependencies skill.

The version is shown to the user on every hook emission so they can tell
that a question/request was raised by safer-dependencies (and which
version of it). Both Python and bash hook surfaces need access — Python
uses ``resolve_version()``; bash hooks read ``SAFER_DEP_VERSION_FALLBACK``
directly as a literal when frontmatter parsing is not worth shelling out
for.

Resolution order:
  1. Parse ``version:`` from the SKILL frontmatter (safer-dependencies.md
     or SKILL.md alongside the skill bundle). This is the source of truth
     so a single edit to the markdown updates every surface.
  2. Fall back to the hardcoded ``SAFER_DEP_VERSION_FALLBACK`` constant.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Iterable, Optional

SAFER_DEP_VERSION_FALLBACK = "0.5.2"

_VERSION_LINE = re.compile(r"^version:\s*(.+?)\s*$", re.MULTILINE)


def _candidate_paths() -> Iterable[str]:
    """Yield plausible locations for the SKILL frontmatter file.

    Order: explicit override, sibling of safedep/, parent of scripts/,
    grandparent (repo root layout). First hit wins.
    """
    override = os.environ.get("SAFE_DEP_SKILL_MD")
    if override:
        yield override

    here = os.path.dirname(os.path.abspath(__file__))            # .../scripts/safedep
    scripts_dir = os.path.dirname(here)                          # .../scripts
    skill_dir = os.path.dirname(scripts_dir)                     # .../<skill bundle>

    for root in (skill_dir, scripts_dir, here):
        for name in ("SKILL.md", "safer-dependencies.md"):
            yield os.path.join(root, name)


def _parse_frontmatter_version(text: str) -> Optional[str]:
    """Return the ``version:`` value from a YAML frontmatter block, or None.

    Only looks inside the leading ``---`` … ``---`` block to avoid matching
    a stray "version:" elsewhere in the markdown body.
    """
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    fm = text[3:end]
    m = _VERSION_LINE.search(fm)
    if not m:
        return None
    return m.group(1).strip().strip('"').strip("'")


@lru_cache(maxsize=1)
def resolve_version() -> str:
    """Return the safer-dependencies version string for attribution.

    Result is cached for the process lifetime — version does not change
    between hook invocations.
    """
    for path in _candidate_paths():
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read(4096)
        except (OSError, UnicodeDecodeError):
            continue
        ver = _parse_frontmatter_version(text)
        if ver:
            return ver
    return SAFER_DEP_VERSION_FALLBACK


def attribution_header() -> str:
    """Return the single-line header prepended to every hook emission."""
    return f"[safer-dependencies {resolve_version()}]"
