#!/usr/bin/env python3
"""migrate_legacy_audit_log.py — one-time migration of the pre-#101 audit log.

Before PR #101 (merged 2026-04-30) the shim wrote every audit entry to
``~/.claude/safer-dependencies-audit.log`` — a single file with no
rotation. After #101 the default path became
``~/.claude/safer-dependencies-audit-YYYY-MM.log`` (one file per UTC
month).

If a developer upgraded the installed shim mid-period (eg. installed in
April 2026, then deployed current ``main`` in May 2026), they end up
with months of entries silently stranded in the legacy file while the
new-shim's queries against the month-suffixed files appear empty for
those months. The FAQ entry "Why are my audit log queries returning no
results?" was written assuming the legacy file never exists — which is
true for fresh installs but wrong for upgrades.

This script closes the gap:

  1. Read the legacy single-file log (if present)
  2. Group each JSONL entry by its UTC year-month from the ``ts`` field
  3. *Append* each group to the matching ``…-YYYY-MM.log`` file
     (existing month-file content is never modified)
  4. Rename the legacy file to ``…-audit.log.migrated`` so subsequent
     runs are idempotent and the original is preserved as evidence

The script is safe to run repeatedly. If the legacy file is absent
(fresh install) the script exits 0 with a clear message and does
nothing.

Usage:
  python3 migrate_legacy_audit_log.py [--dry-run] [--legacy PATH] [--log-dir DIR]

Exit codes:
  0  successful migration, or nothing to migrate
  1  argument / permission / parse error (legacy file unreadable, etc.)
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable


LEGACY_NAME = "safer-dependencies-audit.log"
ROTATED_PREFIX = "safer-dependencies-audit-"
ROTATED_SUFFIX = ".log"
BACKUP_SUFFIX = ".migrated"


def _group_by_month(lines: Iterable[str]) -> tuple[dict[str, list[str]], int]:
    """Group JSONL lines by ``ts[:7]`` (YYYY-MM). Returns (groups, bad_count).

    Lines that fail to parse, or have no ``ts`` field, or have a ``ts``
    that doesn't match the YYYY-MM prefix shape, are counted as bad and
    skipped. We deliberately do NOT drop them entirely — see
    ``--strict``-mode follow-up below — but for now skipping is the
    right default because (a) the audit log is append-only so any
    corruption is bounded and (b) failing the whole migration on one
    bad line would punish users for unrelated past bugs.
    """
    groups: dict[str, list[str]] = defaultdict(list)
    bad = 0
    for line in lines:
        s = line.strip()
        if not s:
            continue
        try:
            d = json.loads(s)
        except Exception:
            bad += 1
            continue
        ts = d.get("ts")
        if not isinstance(ts, str) or len(ts) < 7 or ts[4] != "-":
            bad += 1
            continue
        ym = ts[:7]
        # End the line with exactly one newline regardless of input form.
        groups[ym].append(s + "\n")
    return dict(groups), bad


def migrate(legacy_path: Path, log_dir: Path, dry_run: bool) -> int:
    if not legacy_path.exists():
        print(f"No legacy log at {legacy_path} — nothing to migrate.")
        return 0
    if not legacy_path.is_file():
        print(f"Legacy path exists but is not a regular file: {legacy_path}",
              file=sys.stderr)
        return 1
    try:
        with legacy_path.open("r", encoding="utf-8") as f:
            groups, bad = _group_by_month(f)
    except OSError as e:
        print(f"Could not read {legacy_path}: {e}", file=sys.stderr)
        return 1

    total = sum(len(v) for v in groups.values())
    print(
        f"Read {total} entries, {bad} unparseable, across "
        f"{len(groups)} month(s) from {legacy_path}"
    )

    if total == 0:
        # Nothing to migrate (legacy file empty or all-corrupt). Still
        # rename it so this script is idempotent on the next run.
        if not dry_run:
            backup = legacy_path.with_name(legacy_path.name + BACKUP_SUFFIX)
            legacy_path.rename(backup)
            print(f"Renamed {legacy_path} → {backup}")
        return 0

    if dry_run:
        for ym in sorted(groups):
            target = log_dir / f"{ROTATED_PREFIX}{ym}{ROTATED_SUFFIX}"
            print(f"  [dry-run] would append {len(groups[ym])} lines to {target}")
        return 0

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"Could not create log dir {log_dir}: {e}", file=sys.stderr)
        return 1

    for ym in sorted(groups):
        target = log_dir / f"{ROTATED_PREFIX}{ym}{ROTATED_SUFFIX}"
        try:
            with target.open("a", encoding="utf-8") as f:
                f.writelines(groups[ym])
        except OSError as e:
            print(f"Could not append to {target}: {e}", file=sys.stderr)
            return 1
        print(f"  Appended {len(groups[ym])} lines to {target}")

    backup = legacy_path.with_name(legacy_path.name + BACKUP_SUFFIX)
    try:
        legacy_path.rename(backup)
    except OSError as e:
        print(f"Could not rename {legacy_path} to {backup}: {e}", file=sys.stderr)
        return 1
    print(f"Renamed {legacy_path} → {backup} (original preserved as evidence)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--legacy",
        default=str(Path.home() / ".claude" / LEGACY_NAME),
        help="Path to the legacy single-file audit log (default: "
             "~/.claude/safer-dependencies-audit.log).",
    )
    p.add_argument(
        "--log-dir",
        default=str(Path.home() / ".claude"),
        help="Directory containing the month-suffixed audit logs "
             "(default: ~/.claude).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would happen but do not modify any files.",
    )
    args = p.parse_args(argv)
    return migrate(Path(args.legacy), Path(args.log_dir), args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
