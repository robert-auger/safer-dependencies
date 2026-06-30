"""Append one canonical audit-log entry from a JSON object on stdin.

Used by SKILL.md Step 8 so Normal-mode runs (the parent agent following the
inline procedure) write to the same audit log, with the same schema, as the
shim's intercept-mode runs. The shim itself does not call this script — it
imports ``safedep.audit_log.write_entry`` directly. Both surfaces share the
same library.

Stdin: one JSON object with keys ``file_path``, ``ecosystem``, ``checked``,
``signals``, and optional ``dry_run`` and ``model``. Anything else is silently ignored.

Stdout / stderr: empty on success. The caller is the LLM, and any chatter
would clutter the conversation. Audit-log failures (unwritable path,
malformed input, ...) are silent on purpose — the entry is best-effort, not
load-bearing for the security check itself.

Exit code: always 0. The audit log must never break the flow it observes.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from safedep.audit_log import build_source, write_entry  # noqa: E402


# Stable identifier for this script in source.script — relative to repo root
# so log consumers can trace a line back to a file path without depending on
# the shim's install location. Manual runs have no hook/tool — those fields
# are None.
_SOURCE_SCRIPT = "skills/scripts/audit_log_append.py"


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        dry_run = bool(payload.get("dry_run", False))
        source = build_source(
            component="manual.skill",
            script=_SOURCE_SCRIPT,
            hook=None,
            tool=None,
            mode="dry_run" if dry_run else "manual",
            model=payload.get("model") or None,
        )
        write_entry(
            file_path=payload["file_path"],
            ecosystem=payload["ecosystem"],
            checked=payload["checked"],
            signals=payload["signals"],
            source=source,
            dry_run=dry_run,
        )
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
