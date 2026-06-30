# Execution Contexts

Beyond the five operating modes (Normal, Intercept, Pre-Install, Post-Install, Post-Agent), the skill must behave correctly in two distinct execution contexts:

| Context | Description | Orchestrator behaviour |
|---------|-------------|----------------------|
| **Interactive** | User is present; Claude runs with normal permission prompts | Ask user for `MAJOR-UPDATE-CONFIRM` and `BLOCKED` decisions via text prompt; wait for the reply before applying step 3a–3e of the full HARD GATE flow. |
| **Autonomous** | `bypassPermissions` active and no human turn is expected between the signal and the next tool call (batch instructions, CI-assisted development) | Apply the deterministic **autonomous-session rule**: default to implicit YES (minimum tier — bump the manifest pin), include the CVE ID in the commit message, surface the pending full-migration tier in the response. Honor an explicit earlier deferral as NO (write the skip-file entry). |

**Detecting autonomous context.** An orchestrator is autonomous (for this purpose) when ANY of the following hold: the user has issued a batch instruction with no expected pause ("build everything and commit"), `bypassPermissions` is set with no human turn pending, or text questions surfaced in `additionalContext` will not reach a human before the next tool call. When in doubt, treat the session as autonomous — silent inaction is the failure mode this rule prevents.

**Why the rule exists.** In an autonomous session the agent reads `additionalContext` signals as a system reminder and continues toward its goal. There is no conversational turn waiting for a human response. The legacy instruction "ask the developer and wait" is mechanically unenforceable in that mode — and worse, the zero-cost "If NO → leave version as-is" path makes silent inaction behaviorally equivalent to NO, but without the skip-file artifact, CVE acknowledgment, or audit trail. Observed sessions have committed 8+ files with unresolved CVEs after `MAJOR-UPDATE-CONFIRM` fired 105 times across them.

**Critical rule (autonomous):** Do NOT commit a vulnerable version in autonomous mode without one of the two artifacts:
- minimum-tier YES applied (manifest bumped, CVE ID in commit message), or
- explicit NO recorded (skip-file entry under `~/.claude/sd-skipped-{SESSION_ID}.json` AND `CVE-DEFERRED: <GHSA-id>` in the commit message).

Silent commit with no artifact is a regression and must be treated as a bug, not a default.

For unattended CI runs where no developer is present to answer at all, use `SAFE_DEP_DRY_RUN=1` plus a `jq` gate against the audit log to fail the build when a finding fires (see `references/configuration.md`). A human then reviews and lands the change in a separate PR.
