"""Pre-release version detection shared by the shim and the resolve_*.py CLIs.

A single ``is_prerelease(version, ecosystem)`` entry point. Patterns here are
the UNION of what each copy previously checked independently — before this
module existed, the shim and the four per-ecosystem standalones maintained
their own regexes and had drifted:

* The shim's base keyword set (``snapshot|nightly|canary|next|experimental``)
  was missing from some standalones, so per-CLI resolution would silently
  accept versions the shim would reject.
* The standalones carried ecosystem-specific patterns the shim lacked:
  - ``resolve_maven.py`` had ``m[0-9]|cr[0-9]`` for the Maven milestone and
    candidate-release conventions (e.g. ``5.0-M1``, ``2.0-CR2``).
  - ``resolve_rubygems.py`` had ``pre`` for the RubyGems ``1.0.0.pre`` style.
  The shim accepted both of these as stable, which was a bug.

This module is the merged, canonical filter. Both callers import it and the
two copies cannot drift again.
"""
import re


# Base keyword set — shared across ecosystems. Longer alternatives first so
# ``preview`` is matched before ``pre`` on inputs like ``1.0.0-preview``.
_KW = re.compile(
    r"(?i)(alpha|beta|preview|rc|dev|snapshot|nightly|canary|next|experimental|pre)"
)

# Maven milestone and candidate-release conventions (e.g. 5.0-M1, 2.0-CR2,
# 5.0.M2, 2.0.CR3). Requires a separator (``-`` or ``.``) or start-of-string
# before the token, and a non-alphanumeric character or end-of-string after
# the digits — preventing false positives like ``1.0.m2x`` or ``1.0-m2rel``
# where the ``m<digit>`` is an embedded substring of an alphanumeric label.
_MAVEN_MILESTONE = re.compile(r"(?i)(?:[-.]|^)(m\d+|cr\d+)(?:[^a-zA-Z0-9]|$)")

# PyPI PEP 440 alpha/beta/rc suffixes. The dot is optional: both ``1.0.0a1``
# and ``1.0.0.a1`` are valid PEP 440 pre-release forms.
_PYPI_PEP440 = re.compile(r"\.?(?:a|b|rc)\d+$", re.I)

# Maven hyphen convention: any letter after a dash indicates a pre-release
# (``1.0.0-alpha``, ``1.0.0-beta.1``). Maven is NOT strict semver — it uses a
# dash for platform classifiers and build numbers too — so it keeps the
# letter-only rule plus the milestone/classifier handling below. The strict
# semver ecosystems use ``_semver_has_prerelease`` instead (see below).
_HYPHEN = re.compile(r"-[a-zA-Z]")

# Maven platform classifiers that LOOK like pre-releases but aren't:
# ``1.2.3-jre``, ``2.0-android``, ``1.0-jakarta``, ``1.0-native[0-9]*``.
_MAVEN_CLASSIFIER_OK = re.compile(r"-(?:jre|android|jakarta|native)\d*$", re.I)


def _semver_has_prerelease(version: str) -> bool:
    """True if a strict-semver version carries a pre-release identifier.

    Per the semver grammar, the version core is ``MAJOR.MINOR.PATCH`` (digits
    and dots only); a hyphen begins the pre-release identifiers and a ``+``
    begins build metadata. So, after stripping build metadata, ANY hyphen marks
    a pre-release — including a purely *numeric* identifier (``2.0.0-0``,
    ``1.0.0-1``), which sorts below the corresponding stable release and which
    the old letter-only rule (``-[a-zA-Z]``) wrongly accepted as stable. Build
    metadata is stripped first so a hyphen inside it (``2.0.0+sha-abc``) is not
    mistaken for a pre-release. Also catches Go pseudo-versions
    (``v0.0.0-20210101150405-abcdef``), which are pre-release by construction.
    """
    core = version.split("+", 1)[0]
    return "-" in core


def is_prerelease(version: str, ecosystem: str) -> bool:
    """Return True if ``version`` looks like a pre-release for ``ecosystem``."""
    if _KW.search(version):
        return True
    if ecosystem == "pypi":
        if _PYPI_PEP440.search(version):
            return True
        return False
    if ecosystem == "maven":
        if _MAVEN_MILESTONE.search(version):
            return True
        if _HYPHEN.search(version) and not _MAVEN_CLASSIFIER_OK.search(version):
            return True
        return False
    if ecosystem in ("npm", "rubygems", "crates", "packagist", "go"):
        # Cargo/crates.io, Composer/Packagist and Go versions are strict semver,
        # so any pre-release identifier after the hyphen — alphabetic
        # (``1.0.0-alpha``) OR numeric (``2.0.0-0``) — marks a pre-release.
        return _semver_has_prerelease(version)
    return False
