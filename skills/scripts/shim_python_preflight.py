# -*- coding: utf-8 -*-
"""Python-version preflight launcher for the shim (issue #211).

The shim's audit logic targets Python >= 3.9. On an older interpreter the
heredoc fails to *compile* (SyntaxError, non-zero exit, stderr swallowed by
the hook harness) — the user gets zero diagnostics and silently loses all
audit coverage. An in-file check cannot catch that (the whole file is
compiled before any line runs), so the shim execs THIS launcher instead:

    python3 shim_python_preflight.py <audit-script.py>

On a too-old interpreter it emits a clear PREFLIGHT-ERROR via
hookSpecificOutput.additionalContext, appends a fail-open audit-log entry,
and exits 0 (Shape C: a broken hook never blocks the write). On a supported
interpreter it runs the audit script in-process via runpy (stdin — the hook
JSON — flows through untouched).

This file must stay syntax-compatible with every Python 3.x (and parse on
2.7): no f-strings, no annotations, no walrus — it is exactly the code that
must still run when the interpreter is ancient.
"""

import sys

MIN_PYTHON = (3, 9)


def _audit_log_path():
    import os
    override = os.environ.get("SAFE_DEP_AUDIT_LOG")
    if override:
        return override
    import datetime
    try:
        ym = datetime.datetime.utcnow().strftime("%Y-%m")
    except Exception:
        return None
    return os.path.join(os.path.expanduser("~"), ".claude",
                        "safer-dependencies-audit-" + ym + ".log")


def _write_fail_open_entry(found_version):
    """Best-effort fail-open audit entry; silent on any error (issue #211)."""
    try:
        import datetime
        import json
        import os
        path = _audit_log_path()
        if not path:
            return
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        entry = {
            "ts": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "schema": "2.0",
            "source": {
                "component": "shim.posttooluse",
                "script": "skills/scripts/shim_python_preflight.py",
                "hook": "PostToolUse",
                "tool": None,
                "mode": "fail_open",
            },
            "fail_open": {
                "reason": "python_too_old",
                "detail": "found Python " + found_version + ", need >= "
                          + ".".join(str(p) for p in MIN_PYTHON),
            },
        }
        fh = open(path, "a")
        try:
            fh.write(json.dumps(entry) + "\n")
        finally:
            fh.close()
        try:
            os.chmod(path, 0o600)  # issue #210: never world-readable
        except OSError:
            pass
    except Exception:
        pass


def main(argv, version_info=None, min_python=MIN_PYTHON):
    vi = version_info if version_info is not None else sys.version_info
    if (vi[0], vi[1]) < min_python:
        import json
        found = "%d.%d" % (vi[0], vi[1])
        need = ".".join(str(p) for p in min_python)
        msg = ("PREFLIGHT-ERROR: safer-dependencies requires Python >= " + need
               + " but python3 is " + found + " — dependency audit SKIPPED for "
               "this write. Upgrade python3 (or put a newer interpreter first "
               "on PATH) to restore audit coverage.")
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": msg,
            }
        }))
        _write_fail_open_entry(found)
        return 0
    if len(argv) < 2:
        return 0
    import runpy
    runpy.run_path(argv[1], run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
