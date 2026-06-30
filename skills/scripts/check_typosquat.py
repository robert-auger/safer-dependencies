#!/usr/bin/env python3
"""
check_typosquat.py — deterministic typosquat detection for safer-dependencies skill.

Usage:
    python3 check_typosquat.py <pkg> [--ecosystem npm|pypi|rubygems|maven]
    echo "<pkg>" | python3 check_typosquat.py [--ecosystem npm|pypi|rubygems|maven]
    python3 check_typosquat.py <pkg> --ecosystem pypi --no-popularity-guard

Output (stdout):
    CLEAN                                    no near-match in reference list
    TYPOSQUAT: <input> is N edit from <ref>  one line per hit, sorted by distance

By default the popularity guard is on: if ``<pkg>`` itself has enough
adoption in its ecosystem (weekly downloads above the per-ecosystem
threshold in safedep.popularity), the typosquat finding is suppressed
and CLEAN is printed instead. This prevents false positives like
``pyarrow`` (20M+ weekly PyPI downloads) being flagged as a typosquat of
``arrow``.

Pass --no-popularity-guard to force the raw edit-distance result without
any suppression — useful when the caller is offline, or when verifying
the underlying typosquat logic independently of download-count state.

The matching logic lives in safedep.typosquat so the shim and this CLI
stay in sync.
"""
import sys, argparse
from safedep.typosquat import check, check_guarded


def main():
    parser = argparse.ArgumentParser(description='Deterministic typosquat check.')
    parser.add_argument('package', nargs='?', help='Package name (or pipe via stdin)')
    parser.add_argument('--ecosystem', default='npm',
                        choices=['npm', 'pypi', 'rubygems', 'maven', 'crates'])
    parser.add_argument('--no-popularity-guard', action='store_true',
                        help='Disable the popularity suppression; return raw edit-distance hits.')
    args = parser.parse_args()

    pkg = args.package if args.package else sys.stdin.read().strip()
    if not pkg:
        print('ERROR: no package name provided', file=sys.stderr)
        sys.exit(1)

    if args.no_popularity_guard:
        hits = check(pkg, args.ecosystem)
    else:
        hits = check_guarded(pkg, args.ecosystem)

    if not hits:
        print('CLEAN')
    else:
        for dist, ref in hits:
            plural = 's' if dist != 1 else ''
            print(f'TYPOSQUAT: {pkg} is {dist} edit{plural} from {ref}')


if __name__ == '__main__':
    main()
