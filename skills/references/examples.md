## Examples

### Example 1: Python Package with CVE

**Scenario:** Adding aiohttp 3.8.5 to a web scraper project

**User request:** "Add aiohttp to handle async HTTP requests"

**Claude runs the inline procedure** (Steps 1–8 in `safer-dependencies.md`) — queries PyPI for `aiohttp` version metadata, then runs Layer 1–4 checks against `aiohttp 3.8.5`.

**What Claude reports back to the user:**
```
[safer-dependencies 0.6.1] ⚠️  CRITICAL — aiohttp@3.8.5 (PyPI)
   Issue: [layer 3] 33 unmitigated CVEs in this version
   Detail: 
     - CVE-2023-32315 (HIGH): Multipart form data injection
     - CVE-2023-30943 (MEDIUM): Path traversal in dispatcher
     - 31 other CVEs ranging from HIGH to LOW
   Action: Stepping back to aiohttp@3.9.0 (clean)

[safer-dependencies 0.6.1] ✓ aiohttp@3.9.0 (PyPI) — clean
   All four security layers passed
   Version age: 120 days ✓
   No CVEs found
   Registry existence verified (pypi.org) ✓
```

**Claude's action:** Adds `aiohttp==3.9.0` to requirements.txt instead of requested 3.8.5

**If intercept mode was enabled:**
```
UPDATED: aiohttp 3.8.5 → 3.9.0 (CRITICAL: 33 CVEs fixed)
```

Claude would then:
1. Find all files importing aiohttp
2. Check if APIs changed between 3.8.5 and 3.9.0 (they didn't)
3. Run tests to verify compatibility
4. Commit with: "security: update aiohttp from 3.8.5 to 3.9.0 (CVE-2023-32315 and 32 others)"

---

### Example 2: npm Scoped Package Update

**Scenario:** Adding @apollo/client 3.7.0 to a React project

**User request:** "Install Apollo Client for GraphQL"

**Claude runs the inline procedure** — queries the npm registry for `@apollo/client` metadata and runs Layer 1–4 checks against `3.7.0`.

**What Claude reports back to the user:**
```
[safer-dependencies 0.6.1] ✓ @apollo/client@3.7.0 (npm) — clean
   Layer 1a: Official registry (npmjs.org) ✓
   Layer 1b: No typosquat (similar to known packages: apollo, react-apollo)
   Layer 2: Version age: 95 days ✓
   Layer 3: No CVEs in vulnerability database ✓
   Layer 4: hash-pin check n/a for package.json (signatures intentionally not checked)
```

**Claude's action:** Adds `"@apollo/client": "3.7.0"` to package.json

**Lock file update:**
```bash
npm install
```

When lock file is generated, skill auto-checks transitive dependencies:
```
[safer-dependencies 0.6.1] ✓ 47 transitive dependencies clean (npm)
[safer-dependencies 0.6.1] ⚠️  HIGH [transitive] — ua-parser-js@1.0.29 (npm)
   Issue: [layer 1c] Package first published 15 days ago
   Detail: Published: 2026-03-24. Still within initial vetting period.
   Action: Proceeding — transitive dependency added by browserslist
```

---

### Example 3: Ruby Gem Version Update

**Scenario:** Updating Rails from 6.1.0 to 7.0.4 in a legacy app

**User request:** "We need Rails 7.0.4 for security fixes"

**Claude runs the inline procedure** (Steps 1–8 in `safer-dependencies.md`) — queries RubyGems for `rails` version metadata, runs Layer 1–4 checks against `rails 7.0.4`, and presents the recommendation without modifying the manifest.

**Output:**
```
[safer-dependencies 0.6.1] 📦 RECOMMENDED — rails 6.1.0 → 7.0.4 (MAJOR bump) (RubyGems)
   Reason: Rails 7.0.4 contains fixes for 8 HIGH severity CVEs not in 6.1.0
   Vuln check: 
     - rails 6.1.0: CVE-2023-22794 (HIGH), CVE-2023-22795 (HIGH), ...
     - rails 7.0.4: Clean ✓
   Age: 145 days ✓
   To update: bundle update rails --major
   
   ⚠️  Major version bump: Rails 7.0 contains breaking changes including:
       - ActiveRecord query changes
       - JavaScript compilation changes
       - Session cookie changes
   Review: https://guides.rubyonrails.org/upgrading_ruby_on_rails.html#rails-7-0
```

**Claude's action:** Presents recommendation and waits for user response

**After user confirms:** Claude updates Gemfile and reviews breaking changes

```
Reviewing breaking changes between Rails 6.1.0 and 7.0.4...
Found usages in:
  - app/models/user.rb: 2 ActiveRecord queries may need adjustment
  - app/javascript/: May need webpack changes
  - config/initializers/session_store.rb: Session cookie format changed

Refactoring changes needed:
1. app/models/user.rb: Updated find_by syntax for new query API
2. Updated CSS asset pipeline configuration
3. Regenerated secrets for new session format

Running tests...
✓ All 127 tests pass
✓ Integration tests pass
✓ Security tests pass

Committing...
security: update rails from 6.1.0 to 7.0.4

Major version upgrade to address 8 HIGH severity CVEs.
No longer vulnerable to CVE-2023-22794, CVE-2023-22795, ...

Breaking changes addressed:
- Updated ActiveRecord query syntax in models
- Updated JavaScript asset compilation
- Updated session cookie initialization

Co-Authored-By: safer-dependencies skill
```

---

### Example 4: Java Dependency Update

**Scenario:** Adding log4j-core 2.14.1 to a Spring Boot project (a version affected by Log4Shell)

**User request:** "Add logging framework for application logs"

**Claude runs the inline procedure** — queries Maven Central for `org.apache.logging.log4j:log4j-core` metadata and runs Layer 1–4 checks against `2.14.1`.

**What Claude reports back to the user:**
```
[safer-dependencies 0.6.1] ⚠️  CRITICAL — log4j-core@2.14.1 (Maven)
   Issue: [layer 3] Critical RCE vulnerability (Log4Shell)
   Detail: 
     - CVE-2021-44228 (CRITICAL): Remote code execution via JNDI injection
     - CVE-2021-45046 (CRITICAL): Additional RCE via incomplete fix
   Action: Updating to log4j-core@2.20.0 (clean)

[safer-dependencies 0.6.1] ✓ log4j-core@2.20.0 (Maven) — clean
   All security checks passed
   Version age: 120 days ✓
   No CVEs in vulnerability database ✓
   Maven Central .asc signature present ✓ (presence only — not cryptographically verified)
```

**Claude's action:** Adds to pom.xml:
```xml
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.20.0</version>
</dependency>
```

**If intercept mode:**
```
UPDATED: log4j-core 2.14.1 → 2.20.0 (CRITICAL: CVE-2021-44228 CVE-2021-45046 fixed)
```

Claude refactors any code that might be exploitable by the CVE and runs `mvn test` to verify.

---

### Example 5: Typosquat Detection

**Scenario:** Accidentally trying to add "reqests" instead of "requests"

**User request:** "Add requests library for HTTP calls"

**Claude runs the inline procedure** — runs the typosquat check (`python3 <skill-dir>/scripts/check_typosquat.py reqests --ecosystem pypi`) before any other layer, and gets back a 1-edit hit on `requests`.

**What Claude reports back to the user:**
```
\033[1;31mALERT TYPOSQUAT\033[0m
[safer-dependencies 0.6.1] 🛑 BLOCKED — reqests (PyPI)
   Issue: [layer 1b] Possible typosquat detected
   Detail: "reqests" is 1 edit from "requests" (well-known package)

   What would you like to do?
     A. I meant "requests" — run checks on the correct name and add it to the manifest
     B. "reqests" is intentional — proceed with this name as-is
     C. Don't add anything — abort, no manifest change
```

**User chooses A:** "I meant requests"

**Skill restarts from Step 1 with "requests", all checks pass, writes to manifest:**
```
[safer-dependencies 0.6.1] ✓ requests@2.31.0 (PyPI) — clean
```
`requests==2.31.0` is written to `requirements.txt`. `reqests` is never written anywhere.

**If user chooses B** (intentional — very rare):
```
[safer-dependencies 0.6.1] ✓ reqests@<version> (PyPI) — clean
   Note: proceeding with user-confirmed name. Audit log signals entry: "NOTE: user confirmed override of typosquat warning for reqests"
```

**If user chooses C** (abort):
No package is added. User is informed they can investigate `reqests` before retrying.

---

### Example 6: Transitive Dependency Warning

**Scenario:** Adding express to a Node.js project, exposes transitive dependency with old package

**Manifest update:**
```json
{
  "dependencies": {
    "express": "4.18.2"
  }
}
```

**Lock file generated, skill checks transitive deps:**
```
[safer-dependencies 0.6.1] ✓ express@4.18.2 (npm) — clean

[safer-dependencies 0.6.1] ✓ 50 transitive dependencies clean (npm)

[safer-dependencies 0.6.1] ⚠️  HIGH [transitive] — minimist@1.2.5 (npm)
   Issue: [layer 3] Prototype pollution in argument parsing
   Detail: CVE-2021-44906: Prototype pollution via __proto__
   Action: Proceeding — minimist arrived transitively through express's
           dependency tree (will auto-update when the parent releases a patch)
```

**Claude's action:** 
1. Notes that minimist is transitive, not direct
2. Checks if express has released a patch (4.18.3+) with minimist@1.2.8
3. If available: recommends updating express to get fixed transitive
4. If not available: accepts the warning and documents it
5. Commits: "deps: add express 4.18.2 (with noted transitive minimist CVE)"

---
