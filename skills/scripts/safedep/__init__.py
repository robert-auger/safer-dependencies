"""Shared helpers used by safer-dependencies-shim.sh and the standalone CLI scripts.

Kept deliberately small so both callers share a single source of truth for
registry I/O, timestamp parsing, pre-release detection, typosquat checks,
and other logic that previously lived in two places.
"""
