# Supported manifest files — per-language reference

Read this file when you need exact format details, pinning strategies, or
syntax examples for a specific ecosystem's manifest. The skill body in
`safer-dependencies.md` keeps a high-level summary; everything below is
the long-form lookup table.

The skill automatically detects and audits the following manifest file types:

## Python

| File | Format | Type | Example |
|------|--------|------|---------|
| `requirements.txt` | Plain text, one per line | Pinned versions | `aiohttp==3.9.0` |
| `setup.py` | Python code | Package metadata | `install_requires=['aiohttp>=3.8.0']` |
| `setup.cfg` | INI | Alternative setup config | `install_requires = aiohttp>=3.8.0` |
| `pyproject.toml` | TOML | PEP 518 modern config | `dependencies = ["aiohttp>=3.8.0"]` |
| `Pipfile` | TOML | Pipenv manifest | `aiohttp = ">=3.8.0"` |
| `Pipfile.lock` | JSON | Pipenv lockfile | `"aiohttp": {"version": "==3.9.0", ...}` |
| `poetry.lock` | TOML | Poetry lockfile | Nested TOML structure |
| `uv.lock` | TOML | uv lockfile | Nested TOML structure |

**Pinning strategies:**
- Pinned exact: `aiohttp==3.9.0` (recommended by safer-dependencies)
- Range: `aiohttp>=3.8.0` (avoid, less predictable)
- Caret: `aiohttp^3.8.0` (in poetry, allows minor/patch bumps)

## npm / Node.js

| File | Format | Type | Example |
|------|--------|------|---------|
| `package.json` | JSON | Manifest | `"axios": "1.7.0"` |
| `package-lock.json` | JSON | npm lockfile | Nested dependency tree with hashes |
| `yarn.lock` | Plain text | Yarn lockfile | `axios@1.7.0: version "1.7.0"` |
| `pnpm-lock.yaml` | YAML | pnpm lockfile | Flattened dependency structure |

**Pinned versions (recommended):**
```json
{
  "dependencies": {
    "express": "4.22.1"
  }
}
```

**Avoid ranges in production:**
```json
{
  "express": "^4.18.0",  // Caret: allows minor/patch bumps
  "lodash": "~4.17.0",   // Tilde: allows patch bumps only
  "react": "*"           // Wildcard: ANY version (dangerous)
}
```

## Ruby

| File | Format | Type | Example |
|------|--------|------|---------|
| `Gemfile` | Ruby code | Gem manifest | `gem 'rails', '7.1.3'` |
| `*.gemspec` | Ruby code | Gem specification | `spec.add_dependency 'nokogiri', '~> 1.13'` |
| `Gemfile.lock` | Plain text | Bundler lockfile | `GEM rails (7.1.3)` |

**Pinning strategies:**
```ruby
gem 'rails', '7.1.3'           # Exact (recommended)
gem 'rails', '~> 7.1.0'        # Pessimistic: ~X.Y.Z allows Z bumps only
gem 'rails', '>= 7.1.0'        # Range (avoid in production)
```

## Java

| File | Format | Type | Example |
|------|--------|------|---------|
| `pom.xml` | XML | Maven project object | `<version>3.12.0</version>` |
| `build.gradle` | Groovy | Gradle build | `implementation 'org.springframework:spring-core:6.1.0'` |
| `build.gradle.kts` | Kotlin DSL | Gradle Kotlin | `implementation("org.springframework:spring-core:6.1.0")` |
| `libs.versions.toml` | TOML | Gradle Version Catalog | `commons-text = { module = "...", version.ref = "..." }` |

The Gradle Version Catalog parser accepts all three documented library forms:
`{ module = "group:artifact", ... }`, the split `{ group = "...", name = "..." }`
form, and rich-version notation `version = { strictly/require/prefer = "..." }`
(in addition to inline `version = "..."` and `version.ref`).

**pom.xml format:**
```xml
<dependency>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <version>3.12.0</version>
</dependency>
```

**gradle format:**
```gradle
dependencies {
  implementation 'org.apache.commons:commons-lang3:3.12.0'
}
```

**Avoid ranges in Java (pom.xml only):**
```xml
<!-- This is allowed in Maven but not recommended -->
<version>[3.12.0,)</version>  <!-- Means >= 3.12.0 -->
<version>[3.12.0,3.13.0)</version>  <!-- Means >= 3.12 and < 3.13 -->
```

## Go

| File | Format | Type | Example |
|------|--------|------|---------|
| `go.mod` | Go module file | Manifest | `require example.com/pkg v1.2.3` |
| `go.sum` | Plain text | Checksum file | `example.com/pkg v1.2.3 h1:...` |

**Pinning syntax (go.mod):**
```go
require example.com/pkg v1.2.3
```

Go modules are always pinned to an exact version in `go.mod` (the `v` prefix is
mandatory per Go module versioning). `go get example.com/pkg@v1.2.3` updates
the pin; `@latest` resolves to the newest tagged version at fetch time.

## Rust

| File | Format | Type | Example |
|------|--------|------|---------|
| `Cargo.toml` | TOML | Manifest | `serde = "1.0.200"` |
| `Cargo.lock` | TOML | Cargo lockfile | `name = "serde"` / `version = "1.0.200"` |

**Pinning syntax (Cargo.toml `[dependencies]`):**
```toml
[dependencies]
serde = "1.0.200"                      # shorthand
serde = { version = "1.0.200" }        # table form (use when adding features)
```

Note: a bare `"1.0.200"` in Cargo is a caret requirement (allows `>=1.0.200,
<2.0.0` at resolution time); prefix with `=` (`serde = "=1.0.200"`) for an
exact pin.

## PHP

| File | Format | Type | Example |
|------|--------|------|---------|
| `composer.json` | JSON | Composer manifest | `"monolog/monolog": "2.9.1"` |
| `composer.lock` | JSON | Composer lockfile | `{"name": "monolog/monolog", "version": "2.9.1"}` |

**Pinning syntax (`composer.json` `require`):**
```json
{
  "require": {
    "monolog/monolog": "2.9.1",        // exact
    "guzzlehttp/guzzle": "^7.5"        // caret range (avoid for reproducible builds)
  }
}
```

Composer packages are audited against OSV's `Packagist` ecosystem (CVE,
staleness, existence) and auto-corrected like the other ecosystems. Typosquat
detection does not yet cover Packagist.

All supported files are automatically intercepted by the hooks when configured in `.claude/settings.json`.
