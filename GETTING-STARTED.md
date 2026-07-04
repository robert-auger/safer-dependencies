# Getting Started

safer-dependencies is a Claude Code skill that security-checks every package Claude adds to your project — CVEs, typosquats, abandoned packages, too-new releases — and auto-corrects vulnerable versions in place. It covers npm, PyPI, RubyGems, Maven, Go, Rust, and PHP (Composer).

This page gets you from zero to a working install in about five minutes. For the full picture, see the [README](README.md); for every install variant, see [INSTALLATION.md](INSTALLATION.md).

## 1. Prerequisites

- Claude Code
- Python 3.9+
- `curl`

Ecosystem tools (`npm`, `pip-audit`, `bundle`) are optional — the skill falls back to the OSV API when they're missing.

## 2. Install

Clone the repo and run the interactive installer:

```bash
git clone https://github.com/robert-auger/safer-dependencies /tmp/safer-dependencies
python3 /tmp/safer-dependencies/skills/scripts/safer_dependencies_manager.py interactive_install
```

The installer asks for a scope (global is recommended), explains each hook, writes the `settings.json` configuration for you, and validates the result. That configuration includes the **Bash permissions allowlist** — pre-approval for the skill's read-only check commands (`curl`, `npm view`, `pip-audit`, …). Without it, Claude prompts you to approve every one of those commands on every audit, so if you install manually instead, don't skip that step ([INSTALLATION.md → Permissions allowlist](INSTALLATION.md#permissions-allowlist)).

**Which hooks to pick:** say yes to all of them unless you have a reason not to. In particular, install **Post-Install alongside Intercept/Pre-Install** — Intercept and Pre-Install only audit the packages you declare, while Post-Install audits the resolved lockfile, which is where most real-world CVEs (transitive dependencies) actually live.

## 3. Verify it works

Start a fresh Claude Code session and ask Claude to add a known-vulnerable version to a manifest, e.g. `"lodash": "4.17.10"` in a `package.json`. You should see an `UPDATED:` signal and a corrected version on disk.

If nothing happens, run the health check:

```bash
python3 ~/.claude/skills/safer-dependencies/scripts/safer_dependencies_manager.py validate_installation
```

or just ask Claude: **"check safer-dependencies setup"**.

## 4. Everyday use

Once installed, the hooks run automatically — you don't have to do anything. For manual checks, ask Claude in natural language:

- **"is django 5.0.0 safe?"** — audit a specific version before adding it
- **"what's the safest current flask?"** — get a recommended version
- **"show safer-dependencies stats"** — usage analytics from the audit logs

Or use the slash command: `/safer-dependencies` opens a menu of actions (`stats`, `projects`, `config`, `validate`, `update`).

Security policy — the release-age cooldown and per-check `off`/`warn`/`block` tiers — is edited with `/safer-dependencies config`.

## 5. Where to go next

- [README.md](README.md) — the five modes, warning levels, and how the signals work
- [CAPABILITIES.md](CAPABILITIES.md) — exactly what is and isn't covered
- [INSTALLATION.md](INSTALLATION.md) — manual/global/project installs, Windows setup, updating
- [FAQ.md](FAQ.md) — common questions

All audit activity is logged to `~/.claude/safer-dependencies-audit-YYYY-MM.log` (JSONL, one file per month).
