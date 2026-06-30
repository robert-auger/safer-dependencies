## Troubleshooting

### Common Issues

#### Hooks Not Triggering

**Symptom:** Manifest files are written but no safety checks run

**Causes:**
1. `.claude/settings.json` not configured with PostToolUse hooks
2. Shim not installed or not executable at the path in the hook command
3. `CLAUDE_PROJECT_DIR` path resolves incorrectly

**Solutions:**
1. Verify `.claude/settings.json` has `PostToolUse` hooks with `type: command`
2. Check the shim is executable:
   ```bash
   ls -l .claude/skills/safer-dependencies/shim.sh
   chmod +x .claude/skills/safer-dependencies/shim.sh
   ```
3. Confirm `CLAUDE_PROJECT_DIR` is set in the hook environment by checking the
   Claude Code hook execution log (Help → Hook Logs in the IDE extension)
4. Confirm the hook fires at all: edit a `package.json` and look for the
   "PostToolUse hook modified file" notice that Claude Code emits when the shim
   rewrites a file

#### Signals Not Appearing

**Symptom:** UPDATED signals not appearing after a manifest write

**Causes:**
1. Shim ran but found no CVEs in the declared versions (clean manifest — this is correct)
2. Network error prevented the OSV query from completing (shim emits WARNING: instead)
3. Shim hook not configured in `.claude/settings.json`

**Solutions:**
1. If expecting a signal but none appeared, the version may already be safe — verify
   by checking OSV directly: `https://osv.dev/list?q=<package>&ecosystem=npm`
2. Check whether a `WARNING:` signal appeared instead — that indicates a network or
   parse failure; the manifest was not modified
3. Re-run the audit manually by invoking the shim against the file:
   ```bash
   echo '{"tool_input":{"file_path":"package.json"}}' | bash .claude/skills/safer-dependencies/shim.sh
   ```

#### Version Updates Not Happening

**Symptom:** Shim ran but manifest file still has the original (vulnerable) version

**Causes:**
1. Version was already clean (no update needed)
2. OSV query returned no results for this package/version
3. No safe version exists — every candidate also has CVEs (shim emits BLOCKED: instead)

**Solutions:**
1. Check whether a `BLOCKED:` signal appeared — that means there is no clean version
   available; the dependency should be removed or replaced
2. Verify manifest format is supported (see Supported Manifest Files)
3. Run the shim manually (see above) and inspect stdout for WARNING: or BLOCKED: lines

#### Registry Connection Issues

**Symptom:** Commands timeout or fail with "Connection refused" errors

**Causes:**
1. Network connectivity issue
2. Registry endpoint temporarily down
3. Rate limiting from registry

**Solutions:**
1. Verify internet connection: `curl -s https://registry.npmjs.org -o /dev/null && echo OK`
2. Check registry status:
   - npm: https://status.npmjs.org
   - PyPI: https://status.python.org
   - RubyGems: https://status.rubygems.org
   - Maven: https://search.maven.org
3. If rate limited, wait 10-15 minutes before retrying
4. For Python, ensure `requests` library installed: `python3 -c "import requests; print('OK')"`

#### Signature Verification Failures

**Symptom:** "Signature verification failed" or "tampered" warnings

**Causes:**
1. Package was modified after signing (potential security issue)
2. Signature algorithm not supported by local system
3. Signer's key not in local trust store

**Solutions:**
1. **DO NOT proceed** if signature marked as tampered — this is a CRITICAL security issue
2. If signature algorithm unsupported, consult the registry documentation
3. For Ruby, add signer's certificate: `gem cert --add <cert-path>`
4. This is rare — if persistent, file an issue with the package maintainer

#### Atomic Updates Failing

**Symptom:** Intercept mode runs but manifest file is partially updated or rolled back

**Causes:**
1. File permission issue (manifest file not writable)
2. Manifest parser encountered unexpected format
3. Version string failed to replace (regex mismatch)
4. Concurrent writes to manifest (race condition)

**Solutions:**
1. Check file permissions: `ls -la package.json` should show write permission
2. Verify manifest format matches expected structure (JSON, TOML, YAML, XML, etc.)
3. Check `~/.claude/safer-dependencies-audit-$(date +%Y-%m).log` for the most recent entry on this file — the `findings` and `checked` arrays show what the shim attempted
4. Ensure only one process is writing to manifest at a time (use file locks if needed)

#### Cross-Ecosystem Contamination

**Symptom:** Wrong ecosystem tools run for a package, or Python tools run on npm packages

**Causes:**
1. Manifest detector fails to identify file type correctly
2. Package specified without ecosystem indicator
3. Manifest file has unexpected name or location

**Solutions:**
1. Verify manifest file is in standard location:
   - npm: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
   - Python: `requirements.txt`, `setup.py`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`
   - Ruby: `Gemfile`, `Gemfile.lock`
   - Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
2. If manifest is in non-standard location, tell Claude the ecosystem explicitly when asking for the audit (e.g. "audit express@4.18.2 as an npm package")
3. Check the most recent entry in `~/.claude/safer-dependencies-audit-$(date +%Y-%m).log` — the `ecosystem` field records what the shim detected for the file

### Log File

The shim and the Normal-mode CLI helper both append to monthly-rotated JSONL audit logs:

```
~/.claude/safer-dependencies-audit-YYYY-MM.log
```

For example, May 2026 writes to `~/.claude/safer-dependencies-audit-2026-05.log`. A new file is created automatically at the start of each calendar month. Override the full path with the `SAFE_DEP_AUDIT_LOG` environment variable. One entry is written per invocation (clean or not), so the log doubles as a record of what was checked and what was found.

**Audit log entry format:**
```json
{
  "ts": "2026-04-19T12:34:56Z",
  "file": "/Users/username/my-project/requirements.txt",
  "ecosystem": "pypi",
  "checked": ["aiohttp@3.8.5", "requests@2.31.0"],
  "findings": ["UPDATED: aiohttp 3.8.5 → 3.9.0 (HIGH: 33 CVEs fixed)"],
  "abandoned": [],
  "stale": [],
  "typosquat": [],
  "unknown": [],
  "signatures": [],
  "clean": ["requests@2.31.0"]
}
```

**Audit log fields:**
- `ts` — UTC timestamp of the check (ISO 8601, second precision)
- `file` — Absolute path to the manifest that was audited
- `ecosystem` — One of `npm`, `pypi`, `rubygems`, `maven`, `go`
- `checked` — Every `pkg@version` the shim looked at on this run
- `findings` — Every signal that named a finding (UPDATED, MAJOR-UPDATE, BLOCKED, TYPOSQUAT-CONFIRM, UNKNOWN, SIGNATURE)
- `abandoned` — Subset of signals tagged with `— abandoned:`
- `stale` — Subset of signals tagged with `— stale:`
- `typosquat` — Subset of signals starting with `TYPOSQUAT-CONFIRM:`
- `unknown` — Subset of signals starting with `UNKNOWN:`
- `signatures` — Subset of signals starting with `SIGNATURE:`
- `clean` — Packages from `checked` that produced no finding
- `mode` (optional) — Present and equal to `"dry_run"` when `SAFE_DEP_DRY_RUN` was set

**To query the audit log:**
```bash
# Last 50 entries
tail -50 ~/.claude/safer-dependencies-audit-$(date +%Y-%m).log

# Every npm check
grep '"ecosystem": "npm"' ~/.claude/safer-dependencies-audit-$(date +%Y-%m).log

# Every run that produced at least one finding
jq 'select(.findings | length > 0)' ~/.claude/safer-dependencies-audit-$(date +%Y-%m).log

# All version updates the shim made
jq 'select(.findings | length > 0) | {file, ecosystem, findings}' ~/.claude/safer-dependencies-audit-$(date +%Y-%m).log

# Specific package history
jq 'select(.checked[] | startswith("express@"))' ~/.claude/safer-dependencies-audit-$(date +%Y-%m).log

# Dry-run-only invocations
jq 'select(.mode == "dry_run")' ~/.claude/safer-dependencies-audit-$(date +%Y-%m).log
```

---
