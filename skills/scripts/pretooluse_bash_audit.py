"""
PreToolUse:Bash audit for package-manager install commands.

Reads a bash command on argv[1], extracts package@version arguments from
recognized package-manager invocations, and emits a JSON object on stdout
describing how the parent hook should respond.

Output shape (stable contract with the bash entry point):

    {"action": "allow"}
    {"action": "allow", "notes": ["<note>", ...]}   (scaffolding / no pinned version)
    {"action": "deny", "reason": "<human-readable>", "findings": [...]}

The bash entry point translates "deny" into the Claude Code hookSpecificOutput
schema (permissionDecision: deny + permissionDecisionReason). "allow" with
notes is treated as allow by the bash layer; the notes are informational.

Supported ecosystems (matches the rest of the skill's scope):
  - npm:      npm/pnpm/yarn/bun install|i|add, npx/bunx (verbless),
              deno add npm:<pkg>[@ver]  →  pkg[@version], @scope/pkg[@version]
              yarn create <generator>  →  scaffolding note (no version pin)
  - PyPI:     pip/pip3/pipenv install, uv add, poetry add,
              pipx install|inject, uvx (verbless)  →  pkg[==version]
              (extras like pkg[extra]==1.0 normalize to pkg)
  - RubyGems: gem install [-v VER], bundle add [--version VER]
              (version is a separate flag, not part of the pkg name)
  - Go:       go get|install pkg[@vVERSION]  (modules: pkg may be a path
              with slashes; version typically vX.Y.Z)
  - Rust:     cargo add|install pkg[@VER]  (or --version VER); path/git
              deps are skipped (not registry-resolvable)
  - Maven:    not addressed here — Maven dependencies are typically
              declared in pom.xml/build.gradle (covered by the PostToolUse
              shim). Direct CLI downloads via
              `mvn dependency:get -Dartifact=group:art:version` and
              `mvn dependency:copy` are a known gap; the post-write shim
              still catches anything that lands in a manifest, but
              pre-fetch protection isn't applied to those mvn verbs yet.

The shim's PostToolUse hook still runs after a successful install, so this
pre-flight is a strict additional layer, not a replacement.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys

# Reuse the skill's pooled HTTP layer (parallel_map shares connections with
# the existing shim run) and the shared OSV client, so the single OSV /v1/query
# call lives in one place (safedep.osv) instead of being duplicated here and in
# the shim.
SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))
from safedep.http import parallel_map  # noqa: E402
from safedep.osv import query_vulns as _osv_query_vulns  # noqa: E402
# Same audit_log entry point the shim uses. Silent on errors, so logging
# failures cannot break the hook (preserves fail-open contract).
try:
    from safedep.audit_log import (  # noqa: E402
        build_source as _build_source,
        write_entry as _audit_log_write_entry,
    )
except Exception:  # pragma: no cover — defensive
    _build_source = None
    _audit_log_write_entry = None
try:
    from safedep.config import is_disabled as _ecosystem_is_disabled  # noqa: E402
except Exception:  # pragma: no cover — defensive (fail open)
    def _ecosystem_is_disabled(_eco: str) -> bool:  # type: ignore[no-redef]
        return False
# Supply-chain parity with the shim (issues #203 / #204): typosquat,
# existence, abandoned, and staleness checks at the pre-fetch gate. All four
# imports are individually fail-open — a missing module degrades to the
# OSV-only behaviour rather than breaking the hook.
try:
    from safedep.typosquat import best_match_guarded as _typosquat_match  # noqa: E402
except Exception:  # pragma: no cover — defensive (fail open)
    _typosquat_match = None  # type: ignore[assignment]
try:
    from safedep.existence import package_exists as _package_exists  # noqa: E402
except Exception:  # pragma: no cover — defensive (fail open)
    _package_exists = None  # type: ignore[assignment]
try:
    from safedep.abandoned import lookup as _abandoned_lookup  # noqa: E402
except Exception:  # pragma: no cover — defensive (fail open)
    _abandoned_lookup = None  # type: ignore[assignment]
try:
    from safedep.registry import latest_stable_release as _latest_stable_release  # noqa: E402
    from safedep.staleness import (  # noqa: E402
        is_stale as _is_stale,
        stale_threshold_days as _stale_threshold_days,
    )
except Exception:  # pragma: no cover — defensive (fail open)
    _latest_stable_release = None  # type: ignore[assignment]
    _is_stale = None  # type: ignore[assignment]
    _stale_threshold_days = None  # type: ignore[assignment]
# Policy tiers + cooloff gate (issue #232). Fail-open: a missing config
# module degrades to today's hard-coded per-check defaults.
try:
    from safedep.config import (  # noqa: E402
        check_tier as _check_tier,
        cooloff_days as _cooloff_days,
        cooloff_mode as _cooloff_mode,
    )
except Exception:  # pragma: no cover — defensive (fail to defaults)
    _check_tier = None  # type: ignore[assignment]
    _cooloff_days = None  # type: ignore[assignment]
    _cooloff_mode = None  # type: ignore[assignment]
try:
    from safedep.registry import release_date as _release_date  # noqa: E402
except Exception:  # pragma: no cover — defensive
    _release_date = None  # type: ignore[assignment]


def _tier(name: str, default: str) -> str:
    """Effective tier with hard fail-open to today's behavior."""
    if _check_tier is None:
        return default
    try:
        return _check_tier(name)
    except Exception:  # noqa: BLE001
        return default


# Stable identifier for this script in source.script. See SKILL.md / audit_log.py
# for the provenance schema.
_SOURCE_SCRIPT = "skills/scripts/pretooluse_bash_audit.py"


# ─────────────────────────── Per-PM strategy table ───────────────────────────
# Each entry maps an executable to:
#   ecosystem: OSV ecosystem string (https://ossf.github.io/osv-schema/)
#   verbs:     subcommands that, with positional pkg args, add a new dep
#   extract:   args -> [(name, version|None), ...] for that ecosystem
#
# `extract` returns concrete pins as strings; `_is_concrete_version_for`
# decides per-ecosystem whether a version is fully pinned and audit-eligible.
# Forward references resolved after the extractor functions are defined.
_PM_STRATEGIES: dict[str, dict] = {}  # populated below; see _build_strategies()


def _split_clauses(command: str) -> list[str]:
    """Split on &&, ||, ;, |, and newlines — honoring single- and double-quote boundaries.

    The previous naive string-replace approach would incorrectly fracture
    commands like ``pip install 'foo && bar'`` (the && inside the single-quoted
    string is not an operator). This implementation scans character-by-character,
    tracking quote state, so operators inside quoted strings are treated as
    literals.
    """
    clauses: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(command)

    while i < n:
        c = command[i]

        # Backslash outside single-quotes escapes the next character (never an operator).
        if c == "\\" and not in_single and i + 1 < n:
            current.append(c)
            current.append(command[i + 1])
            i += 2
            continue

        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
            i += 1
            continue

        if c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
            i += 1
            continue

        if in_single or in_double:
            current.append(c)
            i += 1
            continue

        # Outside quotes: two-char operators take priority over single-char.
        two = command[i : i + 2]
        if two in ("&&", "||"):
            clause = "".join(current).strip()
            if clause:
                clauses.append(clause)
            current = []
            i += 2
            continue

        if c in (";", "|", "\n"):
            clause = "".join(current).strip()
            if clause:
                clauses.append(clause)
            current = []
            i += 1
            continue

        current.append(c)
        i += 1

    clause = "".join(current).strip()
    if clause:
        clauses.append(clause)

    return clauses


def _strip_command_prefixes(tokens: list[str]) -> list[str]:
    """Drop leading cd/env/sudo/time/python-launcher so we can recognize
    the actual package-manager verb.

    Examples:
        `sudo -E npm install foo`           -> `npm install foo`
        `python -m pip install foo==1.0`    -> `pip install foo==1.0`
        `python3 -m pip install foo==1.0`   -> `pip install foo==1.0`
        `python3.11 -m pip install foo`     -> `pip install foo`
        `py -m pip install foo`             -> `pip install foo`
        `bunx pkg@1.0.0`                    -> `bun x pkg@1.0.0`
        `uvx --from ...`                    -> (unchanged; uvx handled by its own strategy if added later)
    """
    while tokens:
        t = tokens[0]
        if t in ("sudo", "time", "nohup"):
            tokens = tokens[1:]
            continue
        # ``command npm install …`` / ``command -p npm install …`` — the POSIX
        # ``command`` builtin runs its argument as an external command (a common
        # alias-bypass idiom). Drop it and any of its no-arg flags so the real
        # package manager is recognized.
        if t == "command":
            tokens = tokens[1:]
            while tokens and tokens[0] in ("-p", "-v", "-V"):
                tokens = tokens[1:]
            continue
        if t == "env":
            # env [-i] [VAR=val ...] cmd args
            tokens = tokens[1:]
            while tokens and (tokens[0].startswith("-") or "=" in tokens[0]):
                tokens = tokens[1:]
            continue
        if "=" in t and not t.startswith("-") and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
            # leading inline env assignment: FOO=bar cmd
            tokens = tokens[1:]
            continue
        # ``bunx`` is an alias for ``bun x`` (execute-and-install shorthand).
        # Rewrite it here so the downstream dispatcher sees ``bun x`` and
        # routes through the existing ``bun`` strategy with verb ``x``.
        if t == "bunx":
            tokens = ["bun", "x"] + tokens[1:]
            break
        # ``uvx`` has its own strategy entry (verbless, PyPI). Do NOT rewrite
        # it here — let it pass through to the ``uvx`` dispatcher directly.
        # Python launcher form: ``python -m pip install foo==1.0`` is the
        # canonical pip-via-stdlib invocation in CI scripts and any project
        # that doesn't trust the ``pip`` shim on PATH. Without this, the
        # most common Python install command form silently fails open.
        # Matches python, py, python3, python3.11, etc.
        # basename so path-qualified launchers (``.venv/bin/python -m pip``,
        # ``/usr/bin/python3 -m pip``) are peeled too.
        t_base = os.path.basename(t)
        is_python_launcher = (
            t_base in ("python", "python3", "py") or re.match(r"^python\d[\d.]*$", t_base)
        )
        if is_python_launcher and len(tokens) >= 2:
            nxt = tokens[1]
            if nxt == "-m":
                tokens = tokens[2:]
                continue
            # Glued form: `python -mpip install foo`. shlex keeps `-mpip`
            # as a single token; rewrite it to the module name so the rest
            # of the matcher sees the standard form.
            if nxt.startswith("-m") and len(nxt) > 2:
                tokens = [nxt[2:]] + tokens[2:]
                continue
        break
    return tokens


def _contains_command_substitution(clause: str) -> bool:
    """Return True if *clause* contains $(...) or backtick command substitution
    outside single-quoted strings.

    Command substitutions make the concrete package list unknowable at
    pre-flight time, so we surface a visible note rather than silently
    failing open.
    """
    in_single = False
    in_double = False
    i = 0
    n = len(clause)
    while i < n:
        c = clause[i]
        if c == "\\" and not in_single and i + 1 < n:
            i += 2
            continue
        if c == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if not in_single:
            if c == "`":
                return True
            if c == "$" and i + 1 < n and clause[i + 1] == "(":
                return True
        i += 1
    return False


# Executables recognized as shell wrappers for -c peeling.
_SHELL_WRAPPERS = frozenset({"sh", "bash", "dash", "zsh", "fish"})


def _peel_shell_wrapper(clause: str) -> list[str] | None:
    """If *clause* is ``sh -c 'cmd'`` (or bash/dash/zsh/fish -c), return the
    inner clauses produced by recursively splitting the command string.

    Returns None when the clause is not a recognized shell wrapper form so
    callers fall through to normal per-PM recognition.

    Handles combined flags (``bash -eu -c 'cmd'``, ``sh -euc 'cmd'``) and
    leading sudo/env/time prefixes stripped by ``_strip_command_prefixes``.
    """
    try:
        tokens = shlex.split(clause)
    except ValueError:
        return None
    tokens = _strip_command_prefixes(list(tokens))
    if not tokens or tokens[0] not in _SHELL_WRAPPERS:
        return None
    for idx, tok in enumerate(tokens[1:], 1):
        if tok == "-c" and idx + 1 < len(tokens):
            return _split_clauses(tokens[idx + 1])
        # Combined single-letter flags that include c: -ec, -uc, -euc, etc.
        if tok.startswith("-") and not tok.startswith("--") and "c" in tok[1:]:
            if idx + 1 < len(tokens):
                return _split_clauses(tokens[idx + 1])
    return None


def _looks_like_flag(arg: str) -> bool:
    return arg.startswith("-")


# Flags that take a value as the next argument. Skipping the value
# prevents us from reading e.g. `--prefix services/x` as if `services/x`
# were a package name.
_VALUE_FLAGS_NPM = {
    "--prefix", "--workspace", "-w", "--workspaces",
    "--registry", "--cache", "--otp", "--tag",
}


def _extract_npm_packages(args: list[str]) -> list[str]:
    """Extract `pkg[@ver]` positional arguments from an npm-family verb.

    Skips flag values, ignores boolean flags, leaves scope/path entries
    alone (we want them so OSV can match scoped names).
    """
    pkgs: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in _VALUE_FLAGS_NPM:
            i += 2  # skip the value
            continue
        if _looks_like_flag(a):
            # Includes things like --save, -D, -g; also --foo=bar (already
            # carries its value).
            i += 1
            continue
        # Skip filesystem paths and tarballs — `npm install ./local-pkg`
        # or `npm install ./pkg.tgz` aren't registry installs.
        if a.startswith("./") or a.startswith("../") or a.startswith("/"):
            i += 1
            continue
        if a.endswith(".tgz") or a.endswith(".tar.gz"):
            i += 1
            continue
        # Git URLs and similar — skip; OSV won't have a registry name.
        if "://" in a or a.startswith("git+") or a.startswith("github:"):
            i += 1
            continue
        pkgs.append(a)
        i += 1
    return pkgs


def _split_pkg_version_npm(arg: str) -> tuple[str, str | None]:
    """Split `name@version` into (name, version). Handles scoped pkgs.

    `lodash@4.17.20`     -> ("lodash", "4.17.20")
    `@scope/pkg@1.2.3`   -> ("@scope/pkg", "1.2.3")
    `lodash`             -> ("lodash", None)
    `@scope/pkg`         -> ("@scope/pkg", None)
    `lodash@^4`          -> ("lodash", "^4")  -- caret/tilde forwarded as-is;
                                                  OSV won't resolve it, treated as None.
    """
    if arg.startswith("@"):
        # Scoped: split on the SECOND @
        rest = arg[1:]
        if "@" not in rest:
            return arg, None
        name_rest, version = rest.split("@", 1)
        return "@" + name_rest, version
    if "@" not in arg:
        return arg, None
    name, version = arg.split("@", 1)
    return name, version


def _extract_npm(args: list[str]) -> list[tuple[str, str | None]]:
    return [_split_pkg_version_npm(p) for p in _extract_npm_packages(args)]


def _extract_npx(args: list[str]) -> list[tuple[str, str | None]]:
    """For `npx [flags] pkg[@ver] [cmd-args]` and friends (yarn dlx,
    pnpm dlx, bun x). Normally returns at most one package: npx-style
    commands fetch and execute one package, with subsequent positionals
    being arguments to that package's binary — not additional installs.

    Recognises the explicit ``-p`` / ``--package`` form used to install
    multiple helper packages before running a command:
      ``npx -p typescript -p ts-node ts-node src/index.ts``
    All ``-p`` / ``--package`` values are collected and audited — they
    are all fetched and installed, even though only one binary is
    executed.
    """
    explicit_pkgs: list[tuple[str, str | None]] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in _VALUE_FLAGS_NPM:
            i += 2
            continue
        if a in ("-p", "--package") and i + 1 < len(args):
            explicit_pkgs.append(_split_pkg_version_npm(args[i + 1]))
            i += 2
            continue
        if a.startswith("--package="):
            explicit_pkgs.append(_split_pkg_version_npm(a.split("=", 1)[1]))
            i += 1
            continue
        if _looks_like_flag(a):
            i += 1
            continue
        # File-path / tarball / git-URL / scope-shorthand sources: not
        # registry-resolvable, fail open quietly.
        if (
            a.startswith(("./", "../", "/"))
            or a.endswith((".tgz", ".tar.gz"))
            or "://" in a
            or a.startswith("git+")
            or a.startswith("github:")
        ):
            return []
        # If we already collected explicit -p packages, the first positional
        # is the command to run — not a package to install.
        if explicit_pkgs:
            break
        return [_split_pkg_version_npm(a)]
    return explicit_pkgs


# ───────────────────────────── PyPI extractor ─────────────────────────────
# pip / pip3 install [flags] pkg[==ver] ...
# uv add / poetry add use the same pkg==ver syntax (poetry also accepts
# pkg@ver, pkg^ver, pkg~ver — only `==` is treated as a concrete pin here).

_PIP_VALUE_FLAGS = {
    "-i", "--index-url",
    "--extra-index-url",
    "-f", "--find-links",
    "-t", "--target",
    "--prefix", "--root", "--src",
    "--cache-dir", "--proxy",
    "--upgrade-strategy",
    "--python", "-p",
}

_PIP_RANGE_OPS = (">=", "<=", "~=", "!=", ">", "<", "@", "~", "^")


def _strip_pip_extras(name: str) -> str:
    """`requests[security]` -> `requests`; also trims surrounding whitespace.

    Whitespace matters because PEP 508 allows it around the specifier operator
    (``requests == 2.19.0`` is a single shlex token), and an un-trimmed name
    like ``"requests "`` silently fails to match in OSV — turning a hard
    ``deny`` into a soft ``ask`` for a known-vulnerable pin.
    """
    return name.split("[", 1)[0].strip()


# Flags that take a path argument naming a requirements file. ``-c`` /
# ``--constraint`` is similar in spirit (constraints aren't installed by
# themselves, but `pip install -c constraints.txt foo` does enforce the
# constraint pin), and we read it the same way.
_PIP_REQUIREMENT_FLAGS = {"-r", "--requirement", "-c", "--constraint"}


def _parse_requirements_file_pins(
    path: str, _seen: set[str] | None = None
) -> list[tuple[str, str]]:
    """Read a requirements/constraints file and return [(pkg, ver), ...] for
    its ``pkg==ver`` pins. Mirrors parse_requirements_txt in the shim:
    accepts the optional PEP 508 extras bracket and discards it. Comments,
    options, and unpinned/range entries are skipped (only concrete ``==``
    pins are auditable against OSV).

    Nested ``-r``/``--requirement`` includes are followed once with cycle
    protection so a malicious self-referencing file can't loop us.
    Failures (missing file, permission denied, decode error) fail open —
    the post-write shim and the user's own audit step are the safety nets.
    """
    if _seen is None:
        _seen = set()
    try:
        absolute = os.path.abspath(path)
    except Exception:
        return []
    if absolute in _seen:
        return []
    _seen.add(absolute)
    try:
        with open(absolute, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return []
    pins: list[tuple[str, str]] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            # Nested include: -r child.txt   |   --requirement=child.txt
            parts = line.split(None, 1)
            target = parts[1].strip() if len(parts) > 1 else ""
            if "=" in parts[0]:
                target = parts[0].split("=", 1)[1].strip()
            if target:
                base_dir = os.path.dirname(absolute)
                child = target if os.path.isabs(target) else os.path.join(base_dir, target)
                pins.extend(_parse_requirements_file_pins(child, _seen))
            continue
        if line.startswith("-"):
            continue
        m = re.match(
            r"^([A-Za-z0-9_\-\.]+)(?:\s*\[[^\]]*\])?\s*===?\s*([^\s#;,\[=]+)",
            line,
        )
        if m:
            pins.append((m.group(1), m.group(2)))
    return pins


def _extract_pip(args: list[str]) -> list[tuple[str, str | None]]:
    pkgs: list[tuple[str, str | None]] = []
    i = 0
    while i < len(args):
        a = args[i]
        # ``-r requirements.txt`` / ``--requirement=requirements.txt`` —
        # follow the file and audit each ``pkg==ver`` it pins. Without this
        # branch, the most common Python install command (``pip install -r
        # requirements.txt``) extracts zero packages and the pre-install
        # hook fails open silently on every vulnerable pin in the file.
        if a in _PIP_REQUIREMENT_FLAGS and i + 1 < len(args):
            target = args[i + 1]
            for pkg, ver in _parse_requirements_file_pins(target):
                pkgs.append((pkg, ver))
            i += 2
            continue
        if "=" in a and (
            a.startswith("-r=")
            or a.startswith("--requirement=")
            or a.startswith("-c=")
            or a.startswith("--constraint=")
        ):
            target = a.split("=", 1)[1]
            for pkg, ver in _parse_requirements_file_pins(target):
                pkgs.append((pkg, ver))
            i += 1
            continue
        if a in _PIP_VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        if a.startswith("./") or a.startswith("../") or a.startswith("/"):
            i += 1
            continue
        if a.endswith(".whl") or a.endswith(".tar.gz") or a.endswith(".zip"):
            i += 1
            continue
        if "://" in a or a.startswith("git+"):
            i += 1
            continue
        if "===" in a or "==" in a:
            # PEP 440 arbitrary-equality ``foo===1.0.0`` is a concrete pin too;
            # split on ``===`` first so the version isn't left as ``=1.0.0``
            # (which fails the concreteness check and drops the pkg unaudited).
            sep = "===" if "===" in a else "=="
            name, ver = a.split(sep, 1)
            # Strip everything after the first comma — pip allows compound
            # specifiers like `foo==1.0,!=1.1` where the first `==` is the
            # concrete pin and the rest are exclusions.
            ver = ver.split(",", 1)[0].strip()
            pkgs.append((_strip_pip_extras(name), ver))
        else:
            # Range / unpinned — scan for the earliest range operator and
            # take just the name.
            split_at = len(a)
            for op in _PIP_RANGE_OPS:
                idx = a.find(op)
                if idx != -1 and idx < split_at:
                    split_at = idx
            pkgs.append((_strip_pip_extras(a[:split_at]), None))
        i += 1
    return pkgs


# ─────────────────────────── RubyGems extractor ───────────────────────────
# gem install foo [-v VER]  (or --version VER, or --version=VER)
# bundle add foo [--version VER]  (same syntax)
# Version is a separate flag; multiple positional pkgs receive the same
# version (matching gem/bundle semantics).

_GEM_BUNDLE_VALUE_FLAGS = {
    "-v", "--version",
    "-g", "--group",
    "--source",
    "--git", "--branch", "--ref", "--tag",
    "--path",
    "--require",
}


def _extract_ruby(args: list[str]) -> list[tuple[str, str | None]]:
    version: str | None = None
    pkgs: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        # Capture --version=X
        if a.startswith("--version=") or a.startswith("-v="):
            version = a.split("=", 1)[1]
            i += 1
            continue
        # Capture -v VER / --version VER
        if a in ("-v", "--version") and i + 1 < len(args):
            version = args[i + 1]
            i += 2
            continue
        # Skip other value-flags + their value
        if a in _GEM_BUNDLE_VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        if a.startswith("./") or a.startswith("/") or a.endswith(".gem"):
            i += 1
            continue
        pkgs.append(a)
        i += 1
    # gem version constraints can be ranges (`~> 1.0`, `>= 2.0`); only
    # treat fully-pinned `X.Y.Z` strings as concrete via the per-eco
    # _is_concrete check downstream.
    return [(p, version) for p in pkgs]


# ───────────────────────────── Go extractor ──────────────────────────────
# go get|install [flags] pkg[@vVERSION] ...
# Module paths typically contain slashes; version begins with `v`.

def _extract_go(args: list[str]) -> list[tuple[str, str | None]]:
    pkgs: list[tuple[str, str | None]] = []
    for a in args:
        if a.startswith("-"):
            continue
        if a.startswith("./") or a.startswith("/") or a.startswith("../"):
            continue
        if "@" in a:
            # rsplit so any `@` inside the module path (rare but legal in
            # version-suffixed paths like `mod/v2`) isn't misread.
            name, ver = a.rsplit("@", 1)
            pkgs.append((name, ver))
        else:
            pkgs.append((a, None))
    return pkgs


# ───────────────────────────── Cargo (Rust) extractor ─────────────────────
# cargo add foo[@VER] [--vers VER | --version VER]
# cargo install foo --version VER
# Path/git deps are skipped; --git / --path are flagged value-flags.

_CARGO_VALUE_FLAGS = {
    "--vers", "--version", "-V",
    "--git", "--path", "--registry", "--branch", "--tag", "--rev",
    "--features", "-F", "--target", "--root",
}


def _extract_cargo(args: list[str]) -> list[tuple[str, str | None]]:
    version: str | None = None
    pkgs: list[str] = []
    saw_path_or_git = False
    i = 0
    while i < len(args):
        a = args[i]
        # `--vers=X` / `--version=X`
        if a.startswith("--vers=") or a.startswith("--version="):
            version = a.split("=", 1)[1]
            i += 1
            continue
        if a in ("--vers", "--version") and i + 1 < len(args):
            version = args[i + 1]
            i += 2
            continue
        if a in ("--git", "--path"):
            saw_path_or_git = True
            i += 2
            continue
        if a in _CARGO_VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        if a.startswith("./") or a.startswith("/") or a.startswith("../"):
            saw_path_or_git = True
            i += 1
            continue
        pkgs.append(a)
        i += 1
    if saw_path_or_git:
        return []
    out: list[tuple[str, str | None]] = []
    for p in pkgs:
        if "@" in p:
            name, ver = p.split("@", 1)
            out.append((name, ver))
        else:
            out.append((p, version))
    return out


# ───────────────────────────── Composer (PHP) extractor ──────────────────
# composer require vendor/pkg[:CONSTRAINT] ...
# The version separator is ``:`` (not ``==`` or ``@``):
#   composer require monolog/monolog:1.2.3   → (monolog/monolog, 1.2.3)
#   composer require monolog/monolog:^1.2    → (monolog/monolog, ^1.2)  [range]
#   composer require monolog/monolog         → (monolog/monolog, None)
# Range-only constraints (^, ~, >=, *) flow through as non-concrete and are
# skipped by _is_concrete_version. Local path / VCS repos are configured via
# --repository / --source flags, captured as value-flags so their value isn't
# misread as a package.

_COMPOSER_VALUE_FLAGS = {
    "--repository", "--repository-url", "--source",
    "--prefer-install", "--working-dir", "-d",
}


def _extract_composer(args: list[str]) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in _COMPOSER_VALUE_FLAGS and i + 1 < len(args):
            i += 2
            continue
        if "=" in a and a.split("=", 1)[0] in _COMPOSER_VALUE_FLAGS:
            i += 1
            continue
        if a.startswith("-"):
            # Boolean flags (--dev, -W, --no-update, --prefer-source, ...).
            i += 1
            continue
        if a.startswith("./") or a.startswith("/") or a.startswith("../"):
            i += 1
            continue
        # ``vendor/pkg`` or ``vendor/pkg:constraint``. The constraint may itself
        # contain no extra ``:``; split once. A bare token with no ``/`` is not
        # a Packagist coordinate (e.g. a stray verb) — keep it so a no-version
        # entry is skipped downstream rather than misclassified.
        if ":" in a:
            name, ver = a.split(":", 1)
            out.append((name, ver))
        else:
            out.append((a, None))
        i += 1
    return out


# ─────────────────────────── uvx (uv tool run) extractor ─────────────────────
# uvx is a verbless tool runner for PyPI CLI tools.  Version can be pinned
# either with ``==`` (PEP 508) or with ``@`` (uv shorthand).
#
# Forms:
#   uvx pkg==1.0           → (pkg, 1.0)
#   uvx pkg@1.0            → (pkg, 1.0)
#   uvx --from pkg==1.0 cmd  → (pkg, 1.0)   [explicit package spec]
#   uvx --from pkg@1.0 cmd   → (pkg, 1.0)

_UVX_VALUE_FLAGS = {
    "--python", "-p",          # Python version selector
    "--with", "-w",            # extra packages alongside the tool
    "--index-url",
    "--extra-index-url",
    "--keyring-provider",
}


def _parse_uvx_spec(spec: str) -> tuple[str, str | None]:
    """Parse a uvx tool spec: pkg, pkg==ver, or pkg@ver."""
    if "==" in spec:
        name, ver = spec.split("==", 1)
        return (_strip_pip_extras(name), ver.split(",", 1)[0].strip())
    if "@" in spec:
        name, ver = spec.split("@", 1)
        return (_strip_pip_extras(name), ver)
    return (_strip_pip_extras(spec), None)


def _extract_uvx(args: list[str]) -> list[tuple[str, str | None]]:
    # Returns the tool package plus every `--with` package. `--with` installs
    # extra packages into the ephemeral env and is the bypass closed by #193;
    # they must be audited just like the tool itself.
    tool: tuple[str, str | None] | None = None
    from_seen = False
    extras: list[tuple[str, str | None]] = []
    i = 0
    while i < len(args):
        a = args[i]
        # --with / -w : extra package(s) alongside the tool — audit them.
        # Skip specs that parse to an empty name (e.g. a malformed "--with @1.0")
        # so we never issue an OSV query for a bogus package.
        if a in ("--with", "-w") and i + 1 < len(args):
            spec = _parse_uvx_spec(args[i + 1])
            if spec[0]:
                extras.append(spec)
            i += 2
            continue
        if a.startswith("--with="):
            spec = _parse_uvx_spec(a.split("=", 1)[1])
            if spec[0]:
                extras.append(spec)
            i += 1
            continue
        # --from / -f : names the tool package explicitly.
        if a in ("--from", "-f") and i + 1 < len(args):
            tool = _parse_uvx_spec(args[i + 1])
            from_seen = True
            i += 2
            continue
        if a.startswith("--from="):
            tool = _parse_uvx_spec(a.split("=", 1)[1])
            from_seen = True
            i += 1
            continue
        # Other value-taking flags (--python, --index-url, ...): skip flag+value.
        if a in _UVX_VALUE_FLAGS and i + 1 < len(args):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        # First bare positional is the tool, unless --from already named it
        # (in which case this positional is the command to run, not a package).
        if tool is None and not from_seen:
            tool = _parse_uvx_spec(a)
        break
    result: list[tuple[str, str | None]] = []
    if tool is not None:
        result.append(tool)
    result.extend(extras)
    return result


# ──────────────────────────── deno extractor ─────────────────────────────────
# ``deno add npm:pkg@ver`` and ``deno install npm:pkg@ver`` install npm
# registry packages.  JSR (``jsr:``), Node built-ins (``node:``), and bare
# specifiers are skipped — OSV doesn't have a registry entry for them.

def _extract_deno(args: list[str]) -> list[tuple[str, str | None]]:
    pkgs: list[tuple[str, str | None]] = []
    for a in args:
        if a.startswith("-"):
            continue
        if a.startswith("npm:"):
            pkgs.append(_split_pkg_version_npm(a[4:]))
        # jsr:, node:, https:, etc. — not npm registry; skip silently.
    return pkgs


def _is_concrete_version(version: str | None, ecosystem: str) -> bool:
    """True when version is a fully-pinned, audit-eligible string for OSV.

    npm / PyPI / RubyGems / Packagist: bare semver-ish (1.2.3, 1.2.3-rc1,
    1.2.3+meta). Composer/Packagist pins are the bare form (``vendor/pkg:1.2.3``
    — no ``v`` prefix, unlike Go).
    Go: must start with `v` (e.g. `v1.4.0`, `v3.2.0+incompatible`).
    Everything else (ranges, `latest`, commit SHAs, empty) is non-concrete.
    """
    if not version:
        return False
    if ecosystem == "Go":
        return bool(re.match(r"^v\d+\.\d+\.\d+([-+].+)?$", version))
    return bool(re.match(r"^\d+\.\d+(\.\d+)?([-+].+)?$", version))


# ─────────────────────── Non-registry source detection ──────────────────────
# Per-ecosystem flag forms whose VALUE is itself a non-registry source ref
# (worth surfacing as a separate note). The scanner emits "flag value" when
# matched and consumes both tokens.
_NON_REGISTRY_VALUE_FLAGS: dict[str, set[str]] = {
    "crates.io": {"--git", "--path"},
    "RubyGems":  {"--git", "--path"},
    "PyPI":      {"-e", "--editable"},
    "Packagist": {"--repository", "--source"},
}

# Per-ecosystem flags whose value should NOT be inspected by the scanner as
# a positional ref (so a config value like ``--target /tmp/dist`` or
# ``-r ./requirements.txt`` isn't misclassified as a non-registry source).
_SCANNER_VALUE_FLAGS: dict[str, set[str]] = {
    "npm":       _VALUE_FLAGS_NPM,
    "PyPI":      _PIP_VALUE_FLAGS | _PIP_REQUIREMENT_FLAGS,
    "RubyGems":  _GEM_BUNDLE_VALUE_FLAGS,
    "crates.io": _CARGO_VALUE_FLAGS,
    "Packagist": _COMPOSER_VALUE_FLAGS,
}


def _scan_non_registry_refs(args: list[str], ecosystem: str) -> list[str]:
    """Detect non-registry source refs in args that the extractor would skip.

    Each extractor silently drops local paths, git URLs, tarball URLs, and
    similar non-registry refs because OSV can't resolve them. That fail-open
    behaviour is correct (the install proceeds), but silent is wrong — the
    user has no signal that the audit didn't apply (issue #154).

    Returns descriptions like ``["./mylocalpkg", "git+https://...",
    "--git https://..."]``. Mirrors the extractors' skip patterns and is
    conservative: false-negatives are preferred over false-positives so a
    clean install isn't flagged with a misleading note.
    """
    refs: list[str] = []
    value_flags = _SCANNER_VALUE_FLAGS.get(ecosystem, set())
    nr_flags = _NON_REGISTRY_VALUE_FLAGS.get(ecosystem, set())

    i = 0
    while i < len(args):
        a = args[i]
        # Non-registry value flag (e.g. cargo --git URL, pip -e ./local).
        if a in nr_flags and i + 1 < len(args):
            refs.append(f"{a} {args[i+1]}")
            i += 2
            continue
        # Glued form: --git=URL.
        if "=" in a:
            flag = a.split("=", 1)[0]
            if flag in nr_flags:
                refs.append(a)
                i += 1
                continue
            if flag in value_flags:
                # Glued config-value flag — skip without inspecting the value.
                i += 1
                continue
        # Plain value flag — skip flag and its value (don't read value as ref).
        if a in value_flags and i + 1 < len(args):
            i += 2
            continue
        # Other boolean flags — skip.
        if a.startswith("-"):
            i += 1
            continue
        # Positional arg — flag if it matches a non-registry pattern.
        if (
            a.startswith(("./", "../", "/", "git+", "git://", "git@",
                          "file:", "http://", "https://"))
            or a.endswith((".tgz", ".tar.gz", ".whl", ".zip", ".gem"))
        ):
            refs.append(a)
        i += 1
    return refs


def _build_strategies() -> dict[str, dict]:
    return {
        # ``dlx`` (yarn / pnpm) and ``x`` (bun) fetch + execute a package
        # in one step, like npx. They're verb-based (the verb is dlx/x),
        # so the standard dispatch path works once the verb is in the set.
        "npm":    {"ecosystem": "npm",      "verbs": {"install", "i", "add"}, "extract": _extract_npm},
        "pnpm":   {"ecosystem": "npm",      "verbs": {"install", "i", "add", "dlx"}, "extract": _extract_npm,
                   "execute_verbs": {"dlx"}, "extract_execute": _extract_npx},
        # ``yarn create <generator>`` is a scaffolding command: it fetches
        # create-<generator> from npm and runs it. No version pin is typical.
        # ``scaffold_verbs`` marks verbs where subsequent positionals are app
        # arguments (not additional packages); we use _extract_npx to capture
        # only the first positional, then emit a note rather than silently
        # allowing when no concrete pin is present.
        "yarn":   {
            "ecosystem": "npm",
            "verbs": {"add", "dlx", "create"},
            "extract": _extract_npm,
            "scaffold_verbs": {"create"},
            "extract_scaffold": _extract_npx,
            "execute_verbs": {"dlx"},
            "extract_execute": _extract_npx,
        },
        "bun":    {"ecosystem": "npm",      "verbs": {"install", "i", "add", "x"}, "extract": _extract_npm,
                   "execute_verbs": {"x"}, "extract_execute": _extract_npx},
        # npx / uvx are verbless: the package is the first positional.
        # The dispatcher handles ``verbless: True`` by passing tokens[1:]
        # straight to the extractor.
        "npx":    {"ecosystem": "npm",      "verbless": True,                  "extract": _extract_npx},
        "uvx":    {"ecosystem": "PyPI",     "verbless": True,                  "extract": _extract_uvx},
        # deno add/install only audits npm: prefixed specs.
        "deno":   {"ecosystem": "npm",      "verbs": {"add", "install"},       "extract": _extract_deno},
        "pip":    {"ecosystem": "PyPI",     "verbs": {"install"},             "extract": _extract_pip},
        "pip3":   {"ecosystem": "PyPI",     "verbs": {"install"},             "extract": _extract_pip},
        # pipx install / inject — verbs that put packages onto PATH or into
        # an existing venv. ``inject`` takes the venv name as its first arg
        # followed by packages; _extract_pip will parse it as an unpinned
        # package name (no version → skipped) then pick up any pkg==ver args.
        "pipx":   {"ecosystem": "PyPI",     "verbs": {"install", "inject"},   "extract": _extract_pip},
        "pipenv": {"ecosystem": "PyPI",     "verbs": {"install"},             "extract": _extract_pip},
        "uv":     {"ecosystem": "PyPI",     "verbs": {"add"},                 "extract": _extract_pip},
        "poetry": {"ecosystem": "PyPI",     "verbs": {"add"},                 "extract": _extract_pip},
        "gem":    {"ecosystem": "RubyGems", "verbs": {"install"},             "extract": _extract_ruby},
        "bundle": {"ecosystem": "RubyGems", "verbs": {"add"},                 "extract": _extract_ruby},
        "go":     {"ecosystem": "Go",       "verbs": {"get", "install"},      "extract": _extract_go},
        "cargo":  {"ecosystem": "crates.io","verbs": {"add", "install"},      "extract": _extract_cargo},
        "composer": {"ecosystem": "Packagist", "verbs": {"require", "update"}, "extract": _extract_composer},
    }


_PM_STRATEGIES = _build_strategies()


def _osv_query(package: str, version: str, ecosystem: str) -> list[dict]:
    """Query OSV for a single (package, version, ecosystem).

    ``ecosystem`` is the OSV-schema string (e.g. ``"PyPI"``, ``"crates.io"``)
    carried by the per-PM strategy table. Fail-open (``strict=False``): a
    network blip returns ``[]`` and the post-write shim still re-audits after
    the install completes.
    """
    return _osv_query_vulns(package, version, ecosystem, strict=False, timeout=8)


def _summarize_vulns(vulns: list[dict]) -> list[dict]:
    out = []
    for v in vulns:
        ids = [v.get("id")] + list(v.get("aliases") or [])
        ids = [x for x in ids if x]
        severity = ""
        for s in v.get("severity") or []:
            severity = s.get("score") or severity
        out.append({
            "id": ids[0] if ids else "UNKNOWN",
            "aliases": ids[1:],
            "severity": severity,
            "summary": (v.get("summary") or "")[:140],
        })
    return out


def _signal_for_finding(f: dict) -> list[str]:
    """Build BLOCKED: signal lines for one package finding (one per vuln)."""
    out = []
    for v in f["vulns"]:
        sev = f" ({v['severity']})" if v.get("severity") else ""
        summary = v.get("summary") or ""
        out.append(f"BLOCKED: {f['package']}@{f['version']} {v['id']}{sev}: {summary}")
    return out


def _emit_fail_open_diagnostic(reason: str) -> None:
    """Write a fail-open diagnostic when safedep.audit_log is unavailable.

    Schema v2.0 compatible. Matches the shape used by the shell-level
    emit_fail_open functions in safer-dependencies-pretooluse-bash.sh.
    """
    import json, os, datetime
    log_path = os.environ.get(
        "SAFE_DEP_AUDIT_LOG",
        os.path.join(
            os.environ.get("HOME", "/tmp"),
            f".claude/safer-dependencies-audit-{datetime.datetime.now(datetime.timezone.utc):%Y-%m}.log"
        )
    )
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
    except OSError:
        return
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema": "2.0",
        "source": {
            "component": "bash.pretooluse",
            "script": "skills/scripts/pretooluse_bash_audit.py",
            "hook": "PreToolUse",
            "tool": "Bash",
            "mode": "fail_open",
        },
        "fail_open": {"reason": reason},
    }
    try:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        return


def _log_audit(
    clause: str,
    ecosystem: str,
    checked: list[str],
    findings: list[dict],
    notes: list[str] | None = None,
    extra_signals: list[str] | None = None,
    cwd: str | None = None,
) -> None:
    """Append one canonical audit-log entry for this Bash pre-flight.

    file_path is recorded as ``bash:<command>`` (truncated) since there's
    no manifest file. ``notes`` carries non-registry source descriptions
    (issue #154) so the log entry is non-silent even when nothing was
    queried against OSV. ``extra_signals`` carries supply-chain parity
    signals (UNKNOWN / BLOCKED-abandoned / TYPOSQUAT-CONFIRM / STALE,
    issues #203/#204) already in canonical form. Silent on any error —
    logging must never affect the hook's exit behaviour.
    """
    if _audit_log_write_entry is None or _build_source is None:
        _emit_fail_open_diagnostic("audit_log_import_failed")
        return
    try:
        signals = []
        for n in notes or []:
            signals.append(f"UNRESOLVABLE: {n}")
        for f in findings:
            signals.extend(_signal_for_finding(f))
        signals.extend(extra_signals or [])
        truncated = clause if len(clause) <= 120 else clause[:117] + "..."
        source = _build_source(
            component="bash.pretooluse",
            script=_SOURCE_SCRIPT,
            hook="PreToolUse",
            tool="Bash",
            mode="intercept",
        )
        _audit_log_write_entry(
            file_path=f"bash:{truncated}",
            ecosystem=ecosystem,
            checked=checked,
            signals=signals,
            source=source,
            cwd=cwd or None,
        )
    except Exception:
        pass


# Flags that point an install at a non-default package source. When present,
# the public-registry name checks (existence / typosquat / abandoned /
# staleness) would judge a private package against the wrong universe — skip
# them. The OSV CVE check still runs (public advisories can apply to mirrored
# packages and skipping it would regress existing coverage).
# Per-ecosystem (review finding: -f is pip's --find-links but npm's --force;
# -i is pip's --index-url but gem's --install-dir — a shared set both
# over-matched and under-matched).
_CUSTOM_SOURCE_FLAGS_BY_ECO: dict[str, tuple[str, ...]] = {
    "pypi": ("-i", "--index-url", "--extra-index-url", "-f", "--find-links",
             "--default-index", "--index"),
    "npm": ("--registry",),
    "rubygems": ("--source", "-s", "--clear-sources"),
    "crates": ("--registry", "--index"),
    "go": (),
    "packagist": ("--repository", "--repository-url"),
}

# Environment variables that retarget an ecosystem's registry without any
# CLI flag (the canonical private-index patterns).
_CUSTOM_SOURCE_ENV_BY_ECO: dict[str, tuple[str, ...]] = {
    "pypi": ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL",
             "UV_DEFAULT_INDEX"),
    "npm": ("npm_config_registry", "NPM_CONFIG_REGISTRY"),
    "rubygems": ("BUNDLE_MIRROR__ALL",),
    "crates": ("CARGO_REGISTRIES_DEFAULT",),
    "go": (),
}

# Requirements-file option lines that retarget the index (review finding:
# `pip install -r requirements.txt` with `--index-url https://pypi.corp/`
# inside the file is the standard private-index layout).
_REQ_FILE_INDEX_OPTS = ("-i", "--index-url", "--extra-index-url",
                        "-f", "--find-links")


def _requirements_files_use_custom_source(extract_args: list[str]) -> bool:
    """True when any -r/--requirement/-c/--constraint file (followed one
    level, fail-open) carries an index-retargeting option line."""
    paths: list[str] = []
    i = 0
    while i < len(extract_args):
        tok = extract_args[i]
        if tok in _PIP_REQUIREMENT_FLAGS and i + 1 < len(extract_args):
            paths.append(extract_args[i + 1])
            i += 2
            continue
        for flag in _PIP_REQUIREMENT_FLAGS:
            if tok.startswith(flag + "="):
                paths.append(tok.split("=", 1)[1])
        i += 1
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line.startswith("-"):
                        continue
                    head = line.split(None, 1)[0]
                    if head.split("=", 1)[0] in _REQ_FILE_INDEX_OPTS or \
                            (head.startswith("-i") and len(head) > 2):
                        return True
        except OSError:
            continue
    return False


def _uses_custom_source(extract_args: list[str], internal_eco: str) -> bool:
    flags = _CUSTOM_SOURCE_FLAGS_BY_ECO.get(internal_eco, ())
    for tok in extract_args:
        if tok in flags:
            return True
        if any(tok.startswith(flag + "=") for flag in flags
               if flag.startswith("--")):
            return True
        # pip's optparse accepts the glued short form: -ihttps://corp/simple
        if internal_eco == "pypi" and tok.startswith("-i") and len(tok) > 2:
            return True
    for var in _CUSTOM_SOURCE_ENV_BY_ECO.get(internal_eco, ()):
        if os.environ.get(var, "").strip():
            return True
    if internal_eco == "pypi" and _requirements_files_use_custom_source(extract_args):
        return True
    return False


def _go_module_is_private(module: str) -> bool:
    """True when GOPRIVATE marks this module path as private (Go semantics:
    comma-separated glob patterns matched as path prefixes)."""
    import fnmatch
    patterns = os.environ.get("GOPRIVATE", "")
    for pat in patterns.split(","):
        pat = pat.strip()
        if not pat:
            continue
        if fnmatch.fnmatch(module, pat) or fnmatch.fnmatch(module, pat + "/*"):
            return True
    return False


def _typosquat_corroborated(name: str, internal_eco: str) -> bool:
    """A typosquat ask needs corroborating popularity DATA (review finding):
    best_match_guarded fails open to raising the finding when the popularity
    lookup errors, which would interrupt installs of popular packages (e.g.
    pyarrow) on every pypistats/npmjs outage. At the pre-install gate we ask
    only when the data positively shows the package is NOT popular; an
    inconclusive lookup stays silent (the post-write shim still flags it)."""
    try:
        from safedep.popularity import POPULARITY_THRESHOLD, downloads
        threshold = POPULARITY_THRESHOLD.get(internal_eco)
        if threshold is None:
            return True  # no popularity source for this ecosystem
        count = downloads(name, internal_eco)
        if count is None:
            return False  # inconclusive — do not interrupt
        return count < threshold
    except Exception:  # noqa: BLE001
        return False


def _supply_chain_checks(
    to_query: list[tuple[str, str]], internal_eco: str
) -> tuple[list[str], list[str]]:
    """Shim-parity supply-chain checks for concrete pins (issues #203/#204).

    Returns ``(deny_signals, ask_signals)``:
      deny — ``BLOCKED: … — abandoned: …`` (curated dead packages — offline,
             definitive; blocks in the shim, blocks here).
      ask  — ``TYPOSQUAT-CONFIRM:``, ``STALE:``, and ``UNKNOWN:`` (registry
             404). UNKNOWN is ask rather than deny because a public-registry
             404 can also be a private package configured via channels this
             hook cannot see (.npmrc, pip.conf); the confirm gate still
             stops fabricated names before their install scripts run.

    Per-package check order mirrors cost and certainty: abandoned (offline,
    curated) → typosquat (offline list; popularity data fetched only on a
    hit, and the ask requires positive corroboration) → one registry GET
    that serves BOTH staleness (release list parsed) and existence (a
    parsed list proves existence; only a None result pays the dedicated
    404 probe). Go runs only the offline checks (proxy 404 is not proof of
    non-existence). Everything is fail-open: network errors yield no signal.
    """
    deny: list[str] = []
    ask: list[str] = []
    if not internal_eco:
        return deny, ask

    def _check_one(nv: tuple[str, str]) -> tuple[list[str], list[str]]:
        name, version = nv
        d: list[str] = []
        a: list[str] = []
        try:
            if internal_eco == "go" and _go_module_is_private(name):
                return d, a  # GOPRIVATE module — public name checks don't apply
            abandoned_tier = _tier("abandoned", "block")
            if _abandoned_lookup is not None and abandoned_tier != "off":
                reason = _abandoned_lookup(name, internal_eco)
                if reason:
                    if abandoned_tier == "block":
                        sig = f"BLOCKED: {name} — abandoned: {reason}"
                        d.append(sig)
                    else:
                        # Demoted to the warn/ask tier: a non-blocking prompt
                        # must not embed the literal BLOCKED: prefix.
                        sig = (f"ABANDONED-CONFIRM: {name} — abandoned: {reason} "
                               f"— verify before proceeding")
                        a.append(sig)
                    return d, a
            typosquat_tier = _tier("typosquat", "warn")
            if _typosquat_match is not None and typosquat_tier != "off":
                ts = _typosquat_match(name, internal_eco)
                if ts and _typosquat_corroborated(name, internal_eco):
                    dist, ref = ts
                    sig = (f"TYPOSQUAT-CONFIRM: {name}@{version} may be a typosquat "
                           f"of '{ref}' (edit distance {dist}) — verify this package "
                           f"name is intentional before proceeding")
                    (d if typosquat_tier == "block" else a).append(sig)
                    return d, a
            # One registry GET serves both staleness AND existence (review
            # finding: separate probes doubled per-pin latency). A parsed
            # release list proves the package exists; only a None result
            # needs the dedicated existence probe to distinguish "network
            # failure" (fail-open) from "404" (fabricated name — ask).
            # Both skipped for Go: proxy.golang.org fetches on demand, so a
            # 404 does not prove non-existence (private modules legitimately
            # 404); the go tool itself fails clearly on a missing module.
            if internal_eco == "go":
                return d, a
            latest = None
            if _latest_stable_release is not None:
                latest = _latest_stable_release(name, internal_eco)
            if latest is not None:
                stale_tier = _tier("stale", "warn")
                if (_is_stale is not None and _stale_threshold_days is not None
                        and stale_tier != "off"):
                    threshold = _stale_threshold_days()
                    stale, last_date = _is_stale(latest[1], threshold_days=threshold)
                    if stale:
                        years = max(1, threshold // 365)
                        sig = (f"STALE: {name} — last release {last_date}, "
                               f"no updates in {years}+ years")
                        (d if stale_tier == "block" else a).append(sig)
            elif _package_exists is not None and (
                    existence_tier := _tier("existence", "warn")) != "off":
                if _package_exists(name, internal_eco) is False:
                    # Ask by default, not deny (review finding): a public-
                    # registry 404 can also be a private package configured
                    # via .npmrc / pip.conf or other channels invisible to
                    # this hook. The confirm gate still stops a fabricated
                    # name before its install scripts run, without
                    # hard-blocking legitimate private-registry installs.
                    sig = (f"UNKNOWN: {name}@{version} — not found in {internal_eco} "
                           f"registry (typo, fabricated name, or a private package "
                           f"this hook cannot see) — verify before proceeding")
                    (d if existence_tier == "block" else a).append(sig)
                    return d, a
            # Cooloff (issue #232): only when name checks found nothing and a
            # release date is resolvable. Fail-open on unknown dates.
            # A co-fired warn-tier finding (stale ask in `a`) intentionally
            # short-circuits cooloff — first-finding-wins per pin.
            if (not d and not a and _cooloff_mode is not None
                    and _release_date is not None):
                mode = _cooloff_mode()
                if mode != "off":
                    rd = _release_date(name, version, internal_eco)
                    if rd is not None:
                        from datetime import datetime, timezone
                        age = (datetime.now(timezone.utc) - rd).days
                        window = _cooloff_days() if _cooloff_days is not None else 7
                        if age < window:
                            ago = f"{age} day{'' if age == 1 else 's'} ago"
                            sig = (f"COOLOFF: {name}@{version} was published "
                                   f"{ago} (window: {window}d) — too new "
                                   f"to be community-vetted")
                            (d if mode == "block" else a).append(sig)
        except Exception:  # noqa: BLE001 — fail-open per check
            pass
        return d, a

    for d, a in parallel_map(_check_one, to_query):
        deny.extend(d)
        ask.extend(a)
    return deny, ask


def _normalize_clause_tokens(clause: str) -> list[str] | None:
    """Tokenize a clause and normalize the package-manager binary token.

    Returns the token list with the leading binary reduced to a recognizable
    form, or ``None`` if the clause can't be tokenized / is empty after
    stripping. Centralizes three normalizations so a vulnerable install can't
    slip past the strategy lookup via a non-bare invocation form:

    * leading ``cd``/``env``/``sudo``/``command``/python-launcher prefixes are
      peeled (``_strip_command_prefixes``);
    * the binary is reduced to its basename, so path-qualified invocations
      (``.venv/bin/pip``, ``/usr/bin/pip3``, ``/usr/local/bin/npm``,
      ``./node_modules/.bin/npm``) are recognized;
    * ``uv pip install …`` is routed through the ``pip`` strategy (the ``pip``
      subcommand pushes the install verb to the third token, which the ``uv``
      strategy would otherwise miss).
    """
    try:
        tokens = shlex.split(clause)
    except ValueError:
        # Malformed quoting — let bash handle it; we have nothing to audit.
        return None
    tokens = _strip_command_prefixes(tokens)
    if not tokens:
        return None
    tokens = [os.path.basename(tokens[0]), *tokens[1:]]
    if tokens[0] == "uv" and len(tokens) >= 2 and tokens[1] == "pip":
        tokens = ["pip"] + tokens[2:]
    return tokens


def _audit_clause(clause: str, cwd: str | None = None) -> dict | None:
    """Audit one shell clause.

    Returns:
      None                         → allow silently (not a recognized PM, or
                                     install-from-manifest with no concrete pins)
      {"note": "<str>"}            → allow but surface an informational note
                                     (scaffolding command with no version pin)
      {"ask": "<str>"}             → ask the user to confirm (typosquat / stale
                                     advisory — issues #203/#204)
      {"reason":..., "findings":[…]} → deny (vulnerable pinned version, abandoned
                                     package, or unregistered name)

    Side effect: appends one entry to the audit log when at least one
    concrete pin was checked (clean or vulnerable). Clauses that don't
    reach OSV (early-returns for unrecognized PM, no-args install,
    range-only pins) leave no log entry — there was nothing to audit.
    """
    tokens = _normalize_clause_tokens(clause)
    if not tokens:
        return None
    pm = tokens[0]
    strategy = _PM_STRATEGIES.get(pm)
    if not strategy:
        return None

    is_scaffold = False
    if strategy.get("verbless"):
        # ``npx pkg@ver`` / ``uvx pkg==ver`` — no install verb; the package
        # is the first positional. Pass the entire tail to the extractor.
        extract_args = tokens[1:]
        extract_fn = strategy["extract"]
    else:
        if len(tokens) < 2:
            return None
        verb = tokens[1]
        if verb not in strategy["verbs"]:
            return None
        extract_args = tokens[2:]
        # Scaffolding verbs (e.g. ``yarn create``) fetch and run a generator
        # package; subsequent positionals are arguments to the generator, not
        # additional packages to install.  Use the scaffold extractor (which
        # returns only the first positional arg) and flag so we can emit a
        # note when no concrete version is pinned.
        if verb in strategy.get("scaffold_verbs", set()):
            is_scaffold = True
            extract_fn = strategy.get("extract_scaffold", strategy["extract"])
        elif verb in strategy.get("execute_verbs", set()):
            # Execute-and-run verbs (yarn/pnpm ``dlx``, bun ``x``) take ONE
            # package; subsequent positionals are arguments to the executed
            # tool. The npm-add extractor would audit those arguments as
            # packages too — spurious OSV queries and potential false-positive
            # denials for args that merely look like pkg@ver. Use the
            # npx-style extractor (first positional only), matching how
            # ``npx`` itself is handled.
            extract_fn = strategy.get("extract_execute", strategy["extract"])
        else:
            extract_fn = strategy["extract"]

    ecosystem = strategy["ecosystem"]

    # Honour project / user configuration: silently skip ecosystems disabled
    # via safer-dependencies.toml or SAFE_DEP_DISABLE. The strategy ecosystem
    # field uses OSV-style names ("PyPI", "RubyGems", "crates.io") — map to
    # the internal lowercase identifiers the config module recognises.
    _internal_eco = {
        "npm": "npm", "PyPI": "pypi", "RubyGems": "rubygems",
        "Maven": "maven", "Go": "go", "crates.io": "crates",
        "Packagist": "packagist",
    }.get(ecosystem, "")
    if _internal_eco and _ecosystem_is_disabled(_internal_eco):
        return None

    raw_pkgs = extract_fn(extract_args)

    # Detect non-registry source refs alongside the registry extraction.
    # When an install references a git URL, local path, or tarball URL, the
    # registry extractor silently drops it — the user should still know the
    # audit didn't apply to that source (issue #154). Scaffolding verbs
    # treat subsequent positionals as scaffold arguments, not install sources,
    # so we skip the scan in that mode to avoid false positives.
    nonregistry_refs: list[str] = (
        [] if is_scaffold else _scan_non_registry_refs(extract_args, ecosystem)
    )

    if not raw_pkgs and not nonregistry_refs:
        # PM verb with no positional args = install-from-manifest (npm/pnpm
        # `install`, `bundle install`, etc.). Already audited by the
        # PostToolUse-on-Write shim when the manifest was written.
        return None

    checked: list[str] = []
    to_query: list[tuple[str, str]] = []
    for name, version in raw_pkgs:
        if not _is_concrete_version(version, ecosystem):
            # No version pinned, or a range. The post-write shim will audit
            # whatever the PM actually resolves and writes.
            continue
        checked.append(f"{name}@{version}")
        to_query.append((name, version))

    # Scaffolding command with no concrete pin: the generator is fetched at
    # latest without a version lock — we can't run an OSV check, but we
    # surface a note so the user knows the audit was skipped.
    if not to_query and is_scaffold and raw_pkgs:
        pkg_name = raw_pkgs[0][0]
        verb = tokens[1] if len(tokens) > 1 else ""
        return {"note": (
            f"scaffolding command: {pm} {verb} {pkg_name}; "
            "version not pinned — OSV audit skipped"
        )}

    # Fan OSV calls out across a thread pool (same pattern the shim uses
    # for its per-package work). _osv_query is fail-open (returns []) so
    # per-item exceptions cannot escape; safe to use without wrapping.
    # parallel_map skips the executor for len <= 1 so single-package
    # installs don't pay thread-spawn overhead.
    # Tier gate (issue #232): checks.cve = off skips the OSV queries
    # entirely; warn keeps the queries (findings still recorded + logged)
    # but demotes the response from deny to ask further down.
    cve_tier = _tier("cve", "block")
    if cve_tier == "off":
        vulns_results = [[] for _ in to_query]
    else:
        vulns_results = parallel_map(
            lambda nv: _osv_query(nv[0], nv[1], ecosystem),
            to_query,
        )

    findings: list[dict] = []
    for (name, version), vulns in zip(to_query, vulns_results):
        if vulns:
            findings.append({
                "package": name,
                "version": version,
                "vulns": _summarize_vulns(vulns),
            })

    # Supply-chain parity with the shim (issues #203/#204): typosquat,
    # existence, abandoned, staleness — on the same concrete pins. Skipped
    # when the install points at a custom index/registry: a private package
    # judged against the public registry would be a guaranteed false positive.
    deny_signals: list[str] = []
    ask_signals: list[str] = []
    if to_query and not _uses_custom_source(extract_args, _internal_eco):
        deny_signals, ask_signals = _supply_chain_checks(to_query, _internal_eco)

    # Log the audit attempt whenever there is something meaningful to record:
    # a concrete pin was checked, OR a non-registry source ref was noted.
    # Mirrors the shim's behaviour of logging every audited manifest pass.
    if checked or nonregistry_refs:
        _log_audit(clause, ecosystem, checked, findings, notes=nonregistry_refs,
                   extra_signals=deny_signals + ask_signals, cwd=cwd)

    if not findings and not deny_signals and not ask_signals:
        if nonregistry_refs:
            note = (
                "install command references a non-registry source "
                f"({', '.join(nonregistry_refs)}); safer-dependencies "
                "cannot audit packages from this source — confirm origin "
                "trust manually before proceeding"
            )
            return {"note": note}
        return None

    _nonregistry_note = (
        "install command also references a non-registry source "
        f"({', '.join(nonregistry_refs)}); safer-dependencies "
        "cannot audit packages from this source — confirm origin "
        "trust manually before proceeding"
    ) if nonregistry_refs else None

    # CVE findings are deny-class only at the default block tier; under
    # warn they fold into the ask path below (the audit log above already
    # recorded them regardless of tier — that invariant is tier-independent).
    findings_are_deny = bool(findings) and cve_tier == "block"
    if findings_are_deny or deny_signals:
        lines = ["safer-dependencies pre-flight audit blocked this install."]
        if findings:
            lines.append("Vulnerable pinned version(s) detected:")
            for sig in (s for f in findings for s in _signal_for_finding(f)):
                # Reformat the BLOCKED: signal as a bullet for the deny reason
                # (preserves the same package/version/id/severity/summary fields).
                lines.append("  - " + sig[len("BLOCKED: "):])
        for sig in deny_signals:
            lines.append("  - " + sig)
        # Ask-tier advisories ride along when the clause is denied anyway —
        # the user should see the full picture in one message.
        for sig in ask_signals:
            lines.append("  - " + sig)
        if findings:
            lines.append(
                "Re-run with a patched version, or invoke the safer-dependencies "
                "skill for a recommended pin."
            )
        else:
            lines.append(
                "Choose a maintained, correctly-named alternative, or invoke "
                "the safer-dependencies skill for a recommendation."
            )
        result: dict = {"reason": "\n".join(lines), "findings": findings}
        if _nonregistry_note:
            result["note"] = _nonregistry_note
        return result

    # CVE findings under warn-tier fold into the ask path: same signal text
    # as the deny bullets (package/version/id/severity/summary), demoted to
    # a confirmation rather than a hard block.
    if findings and cve_tier == "warn":
        for f in findings:
            for sig in _signal_for_finding(f):
                ask_signals.append(sig[len("BLOCKED: "):])

    # Ask-only: typosquat suspicion or staleness advisory with no hard block.
    lines = ["safer-dependencies pre-flight audit needs confirmation for this install:"]
    for sig in ask_signals:
        lines.append("  - " + sig)
    lines.append(
        "Proceed only if this is intentional; or invoke the safer-dependencies "
        "skill for a recommended alternative."
    )
    result = {"ask": "\n".join(lines)}
    if _nonregistry_note:
        result["note"] = _nonregistry_note
    return result


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"action": "skip", "reason": "no command provided"}))
        return 0
    command = sys.argv[1]
    # argv[2] carries the hook cwd (injected by pretooluse-bash.sh since schema 2.1)
    cwd: str | None = sys.argv[2] if len(sys.argv) >= 3 else None

    notes: list[str] = []
    deny: list[dict] = []
    asks: list[str] = []

    # Expand top-level clauses: peel sh -c wrappers so the inner commands
    # are audited directly. Clauses that cannot be expanded are kept as-is.
    raw_clauses = _split_clauses(command)
    clauses: list[str] = []
    for raw in raw_clauses:
        inner = _peel_shell_wrapper(raw)
        if inner is not None:
            clauses.extend(inner)
        else:
            clauses.append(raw)

    for clause in clauses:
        # Command substitution makes the package list unknowable at pre-flight
        # time. Surface a visible note so the gap is not a silent allow.
        if _contains_command_substitution(clause):
            notes.append(
                "safer-dependencies: could not analyze command (contains command "
                f"substitution — package versions unknown at pre-flight time): "
                f"{clause[:200]}"
            )
            continue

        result = _audit_clause(clause, cwd=cwd)
        if result is None:
            continue
        # A clause can carry a note (non-registry source detected) alongside
        # findings (vulnerable pin); collect both so a mixed clause surfaces
        # the note even when the install is denied.
        if "note" in result:
            notes.append(result["note"])
        if "findings" in result:
            deny.append(result)
        if "ask" in result:
            asks.append(result["ask"])

    if not deny:
        if asks:
            # Confirm-tier advisories (typosquat / stale — issues #203/#204):
            # the bash wrapper translates "ask" into permissionDecision "ask".
            output_ask: dict = {"action": "ask", "reason": "\n\n".join(asks)}
            if notes:
                output_ask["notes"] = notes
            print(json.dumps(output_ask))
            return 0
        if notes:
            print(json.dumps({"action": "allow", "notes": notes}))
        else:
            print(json.dumps({"action": "allow"}))
        return 0

    # Multiple clauses denied — concatenate the reasons. Ask-tier advisories
    # from other clauses ride along in the deny reason so nothing is lost.
    reason = "\n\n".join(d["reason"] for d in deny)
    if asks:
        reason += "\n\n" + "\n\n".join(asks)
    findings = [f for d in deny for f in d["findings"]]
    output: dict = {"action": "deny", "reason": reason, "findings": findings}
    if notes:
        output["notes"] = notes
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
