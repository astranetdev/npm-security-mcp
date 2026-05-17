# Roadmap

## v1.0 — Current

Core npm security tooling:
- 6 adapters (OSV, npm advisory, npm registry, Socket MCP, Socket API, GitHub Advisory)
- 13 MCP tools covering scan, diff, watch, SBOM, intel
- Persistent state with cache and watchlists
- CycloneDX 1.5 + SPDX 2.3 SBOM output
- Smoke test suite against live APIs

---

## v1.1 — Policy Gates

**Goal:** First-class CI/CD support with configurable fail conditions.

### Policy configuration file (`.npm-security-policy.json`)

```json
{
  "failOn": "high",
  "maxSupplyChainRisk": 70,
  "allowList": ["GHSA-p6mc-m468-83gw"],
  "requireSocketScore": true,
  "ignoreDev": true
}
```

### New tool: `evaluate_policy`

```
evaluate_policy({ lockfile_content, policy })
→ PASS / FAIL + list of policy violations
→ Exit code semantics for CI
```

### Improvements
- `scan_lockfile` and `scan_dependencies` accept a `policy` param
- Output includes `POLICY PASS` / `POLICY FAIL` block
- JSON output mode (`format: "json"`) for machine-readable CI consumption

---

## v1.2 — Cache & Performance

**Goal:** Handle large lockfiles (1000+ packages) without hitting rate limits.

- Persistent cache for OSV responses (currently in-memory across requests, not across restarts)
- Batch size tuning per adapter
- Cache warming: pre-fetch advisories for all watched packages on startup
- Parallelism cap: `--max-concurrent-adapters` to avoid flooding APIs
- File-level locking for `state.json` (`flock`-based) for multi-process safety

---

## v1.3 — GitHub Integration

**Goal:** Surface security context directly from repository activity.

- `scan_repo({ owner, repo })`: scan the `package-lock.json` from a GitHub repo
- `watch_repo({ owner, repo })`: monitor a repo's dependency changes via GitHub Events API
- PR comment mode: post `scan_lockfile` output as a GitHub PR comment via GitHub Actions
- Dependabot alert correlation: cross-reference with `GITHUB_TOKEN`-authenticated Dependabot alerts

---

## v2.0 — Multi-Ecosystem

The adapter interface is ecosystem-agnostic. OSV and Socket already support multiple ecosystems. Expanding requires:

1. Ecosystem-specific registry adapters
2. Ecosystem-specific lockfile parsers
3. Updated tool schemas to accept `ecosystem` param

### Target ecosystems (priority order)

| Ecosystem | Adapter needed | OSV support | Socket support |
|-----------|---------------|-------------|---------------|
| **PyPI** (Python) | PyPI JSON API | ✅ | ✅ |
| **Cargo** (Rust) | crates.io API | ✅ | Partial |
| **Go modules** | proxy.golang.org | ✅ | Partial |
| **Maven** (Java) | Maven Central | ✅ | ✅ |
| **RubyGems** | rubygems.org API | ✅ | Partial |
| **NuGet** (.NET) | nuget.org API | ✅ | ❌ |

### New tools in v2.0
- `scan_requirements_txt` — Python pip requirements
- `scan_cargo_lock` — Rust Cargo.lock
- `scan_go_sum` — Go go.sum
- `scan_pom_xml` — Maven POM

### Architecture note
The core dedup, format, semver-check, and state management are already ecosystem-agnostic. Only adapter and lockfile parser layers need ecosystem-specific work.

---

## v2.1 — Behavioral Analysis (Experimental)

**Goal:** Detect risks that have no CVE yet.

- Integration with Socket.dev's package inspection API (when available) for per-file behavioral signals
- Script content analysis: detect common exfiltration patterns in install scripts (env var access + network call)
- Diff of `node_modules` file count between versions (sudden large increase = suspicious)
- Entropy analysis of minified files (high entropy = possible obfuscation)

**Caveat:** This remains static analysis. No sandboxed execution. Behavioral heuristics have false positive risk and will be clearly labeled as `experimental`.

---

## v3.0 — Enterprise Features

- **LDAP/SSO-gated policy**: policy decisions validated against org-level rules
- **Audit logging**: all tool invocations logged with user context for compliance
- **Custom advisory feeds**: ingest private advisory databases (e.g., internal security team findings)
- **Exemption workflows**: `allow_list` entries require approver metadata + expiry date
- **Dashboard integration**: export scan history to Grafana, DataDog, or custom webhook

---

## Non-Goals (Permanent)

These are intentionally out of scope and will not be added:

- **Auto-fix / auto-upgrade**: modifying `package.json` or running `npm install` is out of scope. This tool reports — humans decide.
- **Runtime monitoring**: no agent, no sidecar, no process injection.
- **Vulnerability database hosting**: no local copy of advisory databases. Always queries upstream (current data > stale local copy).
- **Code scanning (SAST)**: source code analysis is a separate domain. This tool focuses on dependency metadata and advisory data.
