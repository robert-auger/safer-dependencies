# Trigger examples

Detailed examples of phrases / actions that should fire the safer-dependencies
skill. The frontmatter `description` in `safer-dependencies.md` carries the
canonical trigger list — this file is a longer-form reference for edge cases.

Fire this skill when the user's request resembles any of:

**Adds:**
- "Add axios to package.json" / "add aiohttp to requirements.txt" / "bring in lodash" / "pull in dayjs"
- `npm install <pkg>`, `yarn add <pkg>`, `pnpm add <pkg>`
- `pip install <pkg>`, `pipenv install <pkg>`, `poetry add <pkg>`, `uv add <pkg>`, `uv sync`
- `bundle add <gem>`, `bundle install`, `gem install <gem>`
- `go get <module>`
- `mvn dependency:add` / editing a Maven `<dependency>` block / adding a Gradle `implementation` line

**Upgrades / downgrades / replacements:**
- "Upgrade flask to the latest version" / "bump lodash" / "refresh my dependencies" / "update everything"
- "Pin express to 4.17.0" / "downgrade axios to 0.21.0" / "rollback grpc to v1.50" *(pin-to-older is a CVE-creation path — still audit)*
- "Replace moment with dayjs" / "switch from pytorch to tensorflow" *(add + remove — audit the new one)*

**Manifest writes:**
- About to Write or Edit a dependency manifest or lockfile (full list in the frontmatter above)
- Writing a `Dockerfile` or `.github/workflows/*.yml` that embeds `pip install <pkg>` / `npm install <pkg>` with pinned versions
- Code being written contains `import X` / `require('X')` / `use X;` for a package not already declared in the repo's manifest

**Audits of existing manifests:**
- "Is flask 2.0.0 still safe?" / "what's the safest current Django?" / "audit my package.json" / "check for CVEs in my deps"
- Pre-release gates — "scan for vulnerable packages before we ship"

**Selection & recommendation:**
- "What's a good HTTP client for Python?" / "recommend a logging library for Go"
- "Should I use axios or node-fetch?" / "which is better, moment or dayjs?" / "moment vs dayjs?"
- "What's the best ORM for Express?" / "which React state manager should I use?" / "compare X and Y"
- "What package handles JWT in Node?" / "what library does CSV parsing in Python?"
- "What version of Django should I use?" / "latest stable Flask?"

**Intent-to-use (pre-add signals):**
- "I want to use FastAPI for this" / "I'm thinking of adding Celery"
- "We're planning to use Prisma as the ORM" / "we're looking at using Redis"
- "I'm going to bring in lodash for utilities" / "let's use Tailwind"

**Package health & trust:**
- "Is moment.js still maintained?" / "is this gem still supported?"
- "Is X abandoned?" / "is X EOL?" / "can I trust this package?" / "is this gem still active?"
- "When was faker last updated?" / "is this actively developed?" / "is this library still maintained?"

**Scaffolding:**
- `npx create-react-app myapp`, `npm create vite@latest`, `npx create-next-app`
- `django-admin startproject`, `rails new myapp`, `cargo new myapp` + `cargo add`
- "Bootstrap a new FastAPI project" / "set up a new Express server from scratch"

**Implicit package adds (feature requests):**
- "Add Redis caching to the app" / "connect to Postgres from this service"
- "Add JWT authentication to the API" / "write code to send emails"
- "Add a job queue for background processing"
- Writing a `Dockerfile` with `RUN pip install pandas==1.3.0`
- A GitHub Actions step: `run: npm install express@4.0.0`

**Migration & porting:**
- "Migrate from requests to httpx" / "move from CRA to Vite"
- "Port this project from moment to date-fns"

Do NOT fire when:

- Reading a manifest only to answer a question about it (no Write/Edit planned)
- Discussing packages academically with no install intent ("how does webpack's module resolution work?", "explain React's reconciler internals") — note: comparison/selection questions ("should I use X or Y?") DO trigger
- Reformatting, sorting, or whitespace-only edits to a manifest/lockfile with no version changes
- Editing only non-dependency fields of a manifest (`name`, `description`, `scripts`, `keywords`, `author`, `repository`, `license` in `package.json`; `[tool.*]` metadata blocks in `pyproject.toml`; etc.)
- The user is installing an OS application / runtime / IDE extension, not a library — "install Python 3.12", "install Docker", "install Homebrew", "install the Prettier VS Code extension"

**If intercept mode is configured for this project** (PostToolUse hook + shim — see the project's `.claude/settings.json`), do NOT run Normal-mode Steps 1–8 inline before the write. Write the declared version; the shim will audit and auto-correct on disk, then emit signals back. Running both duplicates every check, doubles OSV traffic, and wastes the 60 s hook budget. Normal mode is for *manual* audits (the "audit my package.json" / "is X safe?" flows above), not for pre-emptively shadowing every manifest write.

**If the target ecosystem is not yet audited** — PHP (`composer.json`), Elixir (`mix.exs`), Dart (`pubspec.yaml`), Clojure (`deps.edn` / `project.clj`), Haskell (`cabal.project`), Crystal (`shards.yml`), and similar — the skill fires conceptually but the shim has no auditor for those manifests. Surface this gap explicitly to the developer ("safer-dependencies has no auditor for PHP yet; consider `composer audit` manually") rather than silently no-opping as if the manifest were clean.
