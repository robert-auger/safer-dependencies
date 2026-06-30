## Integration with Claude Code Workflows

### Automated Shim-Based Workflow (intercept mode)

1. User writes code that adds a package:
   ```python
   # app.py
   import aiohttp  # not yet declared
   ```

2. Claude writes to `requirements.txt`:
   ```
   aiohttp==3.8.5
   ```

3. PostToolUse hook fires → `safer-dependencies-shim.sh` receives hook JSON on stdin
4. Shim reads `requirements.txt` from disk, queries OSV for `aiohttp==3.8.5`
5. OSV reports CVE-2024-23829; shim resolves safe version `3.9.5`
6. Shim rewrites `requirements.txt` to `aiohttp==3.9.5` and emits:
   ```
   UPDATED: aiohttp 3.8.5 → 3.9.5 (HIGH: CVE-2024-23829)
   ```
7. Claude receives the `UPDATED:` signal, checks API changes, runs tests, commits

### Manual Audit Workflow

1. User: "Check if lodash 4.17.15 is safe"
2. Claude runs the version resolution step from this skill inline
3. Queries OSV for `lodash@4.17.15` → reports CVE-2021-23337
4. Resolves safe version (4.17.21+), presents recommendation
5. User confirms → Claude updates package.json and tests

### Recommendation Workflow for Existing Deps

1. User: "We need the new Promise.all behaviour from Node 18"
2. Claude identifies the minimum required version and runs all 4 check layers on it
3. Presents a recommendation with version, age, and vuln status
4. User reviews breaking changes
5. Claude refactors code, runs tests, commits update

---

## Performance & Optimization

### Execution time breakdown

For a typical package check with intercept mode:

| Step | Time | Notes |
|------|------|-------|
| Registry query | 1–2s | Network latency to npm/PyPI/RubyGems/Maven |
| Version parsing & filtering | 0.2s | Local Python processing |
| Vulnerability scan | 1–2s | OSV API query or local tool (npm audit, etc.) |
| Signature verification | 0.5s | Optional, ecosystem-dependent |
| Manifest update | 0.1s | Atomic file operation |
| Total per package | **2–5s** | Fully deterministic, no LLM interpretation |

### Zero-overhead for non-manifest files

- **Non-manifest files:** Instant exit (< 100ms)
- **Hooks fire on all file writes** but safer-dependencies checks the filename and returns immediately if not a manifest
- No network calls, no vulnerability scans
- CPU-bound only (filename pattern matching)

### Large project optimization

For projects with 100+ dependencies, the relevant primitives that already exist:

- **Lock-file ecosystem coverage** is automatic — the shim parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `Gemfile.lock`, etc. when those files are written, with no per-invocation flag needed.
- **Ecosystem detection** is automatic from the manifest filename — there is no manual selector. If you only ever write `package.json`, only npm is queried.
- **Report-only mode** is available via `SAFE_DEP_DRY_RUN=1` (see `configuration.md`), which runs every check but does not rewrite the manifest. Useful for CI gates that should surface findings but not auto-correct.

### Network timeouts

All registry queries have a **10-second per-query timeout**. The hook itself has a separate timeout configured in `.claude/settings.json` (default 60 seconds; raise it for very large lock-file diffs).

If a registry is slow:
- Query times out after 10s
- Skill falls back to OSV API (slower but always available)
- User sees warning but check completes
- No hanging or indefinite waits

### Caching strategy

The skill **does cache** registry queries between runs. A persistent file-backed cache (`safedep/cache.py`, default location `~/.cache/safe-dep/lookups.json`) is wired into the shim with conservative, per-entry-type TTLs:

- **OSV vulnerability lookups:** 24 hours (vuln data is reasonably stable)
- **Version-list / metadata lookups:** 6 hours (registries publish new versions often)
- **Negative results (registry 404s):** 7 days (very stable)

The TTLs are deliberately short for CVE-relevant data so a fresh disclosure is picked up within a day at worst, while repeat audits of the same packages within a session (or across sessions) avoid redundant network round-trips.

Overrides:
- `SAFE_DEP_CACHE_DISABLE=1` — bypass the cache entirely (every query hits the live registry)
- `SAFE_DEP_CACHE_DIR` — relocate the cache directory (e.g. per-project or per-tenant scoping)

If you're checking the same packages repeatedly:
- Results are logged to `~/.claude/safer-dependencies-audit-YYYY-MM.log` (monthly-rotated; override the full path via `SAFE_DEP_AUDIT_LOG`)
- You can query the log with `jq` instead of re-running checks (see `references/troubleshooting.md` for the schema)

### Typical project overhead

Numbers below assume the default `max_workers=3`. Halve them roughly for `max_workers=8` (lockfile path default) and multiply by ~3 for `SAFE_DEP_MAX_WORKERS=1`.

| Project size | Packages | Time (first run, `max_workers=3`) | Time (intercept mode, one new package) |
|---|---|---|---|
| Micro (< 5 deps) | 5 | 3–8s | 2–5s |
| Small (5–20 deps) | 20 | 10–30s | 2–5s (per package) |
| Medium (20–50 deps) | 50 | 30–90s | 2–5s (per package) |
| Large (50–200 deps) | 200 | 130–350s | 2–5s (per package) + 10–30s transitive |
| Enterprise (200+ deps) | 500+ | Lock-file diff (automatic on lock-file writes) | 2–5s (per package) |

**Transitive dependencies** (pulled in by lock files) are checked with reduced rules (CRITICAL/HIGH vulns only, no typosquat checks, no cooldown checks).

### Best practices for performance

1. **Let lock-file writes carry the diff.** When the package manager rewrites `package-lock.json` / `yarn.lock` / `Pipfile.lock` / etc., the shim parses the diff against the previous version on disk and only audits new or changed entries. No manual invocation needed.

2. **Raise the hook timeout for very large lock-file rewrites.** The default `timeout: 60` in `.claude/settings.json` is comfortable for typical writes; first-run audits on large repos may need 120 or higher.

3. **Per-package fetches fan out concurrently, capped at 3 workers by default.** Each manifest audit runs its per-package metadata phase through `safedep.http.parallel_map` with `max_workers=3` — measured ~2× faster than serial on a 50-pkg manifest. The cap is deliberately below the lockfile-audit path's default of 8 so interactive `Write`/`Edit` hooks stay polite on public registries. Override via `SAFE_DEP_MAX_WORKERS` (clamped to `[1, 32]`); power users on private mirrors can raise it, CI runners that want to serialize for reproducibility can set `1`.

