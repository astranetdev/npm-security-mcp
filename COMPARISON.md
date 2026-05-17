# Why not npm audit?

`npm audit` is a good start. It is not sufficient.

## Feature Comparison

| Feature | `npm audit` | `npm-security-mcp` |
|---------|:-----------:|:------------------:|
| **Vulnerability detection** | ✅ npm advisory DB only | ✅ OSV + npm + GitHub Advisory (3 sources, cross-referenced) |
| **Supply chain analysis** | ❌ | ✅ Socket.dev scores (malware, typosquatting, obfuscation signals) |
| **Maintainer risk profiling** | ❌ | ✅ `check_maintainer`: package count, recent activity, install scripts |
| **Version diffing** | ❌ | ✅ `diff_versions`: scripts, maintainers, deps, integrity |
| **Watchlists** | ❌ | ✅ `watch_add/check`: ongoing monitoring with change detection |
| **SBOM generation** | ❌ | ✅ CycloneDX 1.5 + SPDX 2.3 |
| **Advisory search** | ❌ | ✅ By CVE, GHSA, package name, keyword |
| **Vuln explanation** | ❌ | ✅ CVSS breakdown, attack vector, mitigation, PoC refs |
| **Multi-source correlation** | ❌ | ✅ Deduplicates advisories across all sources |
| **Transitive dep coverage** | ✅ | ✅ |
| **semver range validation** | ✅ | ✅ `semver.satisfies()` — only flags actually-vulnerable installs |
| **Security intel feed** | ❌ | ✅ `security_intel_summary`: recent npm advisories in N days |
| **Works without package-lock** | ❌ | ✅ `scan_dependencies` works from `package.json` alone |
| **AI-native output** | ❌ JSON/text | ✅ Structured markdown, rendered in Claude |
| **Offline advisory DB** | ✅ Cached locally | ❌ Requires network (by design — always current) |
| **Fix commands** | ✅ `npm audit fix` | ❌ Reports only, no auto-fix |

## The Core Problem with `npm audit`

### 1. Single data source

`npm audit` queries only the npm advisory database. OSV and GitHub Advisory track vulnerabilities that npm has not yet published — sometimes with days or weeks of lag. Multi-source correlation catches more, earlier.

### 2. No supply chain signals

A package can have zero CVEs and still be malicious. `npm audit` gives it a clean bill of health. Socket.dev detects:
- Install scripts that exfiltrate env vars
- Packages that phone home on install
- Obfuscated code hidden in minified bundles
- Typosquatted names targeting popular packages

`npm audit` sees none of this.

### 3. No maintainer visibility

The `event-stream` attack (2018), `ua-parser-js` (2021), `node-ipc` (2022), `colors`/`faker` (2022) — all involved maintainer actions on legitimate packages with no CVE at time of attack. `npm audit` would have shown zero vulnerabilities. `diff_versions` and `watch_check` would have flagged the maintainer changes and new install scripts.

### 4. No ongoing monitoring

`npm audit` is a point-in-time snapshot. A package that was clean on Monday may have a critical advisory by Friday. `watch_check` monitors your key dependencies and surfaces changes as they happen.

### 5. No explainability

`npm audit` tells you there's a vulnerability. It does not explain the attack vector, CVSS breakdown, whether your specific code path is actually exploitable, or what a realistic exploit looks like. `explain_vuln` fills this gap.

---

## Comparison with Other Tools

| Tool | Strength | Gap vs npm-security-mcp |
|------|----------|------------------------|
| `npm audit` | Built-in, fast | Single source, no supply chain |
| `snyk` | Deep vuln DB, fix PRs | Proprietary, cloud-dependent, expensive at scale |
| `socket.dev CLI` | Best supply chain signals | No CVE correlation, no SBOM, no watchlists |
| `trivy` | Multi-ecosystem, container scanning | No maintainer analysis, no version diffing |
| `grype` | Excellent CVE coverage via Grype DB | No supply chain, no npm-specific signals |
| `osvscanner` | OSV native, multi-ecosystem | No supply chain, no maintainer risk, no MCP |

**npm-security-mcp** uniquely combines:
- CVE coverage (3 sources)
- Supply chain behavioral analysis (Socket.dev)
- npm-specific metadata analysis (registry adapter)
- MCP native integration (works directly in Claude, Claude Code)
- Stateful monitoring (watchlists)
- SBOM output

No single other tool does all of this.

---

## When to Use Each Tool

| Scenario | Recommended |
|----------|-------------|
| Quick check in CI with no setup | `npm audit` |
| Full security assessment before release | `npm-security-mcp scan_lockfile` |
| Evaluating a new dependency before adding | `npm-security-mcp scan_package` + `check_maintainer` |
| Suspicious package investigation | `npm-security-mcp diff_versions` + `explain_vuln` |
| Compliance / SBOM requirement | `npm-security-mcp generate_sbom` |
| Ongoing production monitoring | `npm-security-mcp watch_add/check` |
| Security intel briefing | `npm-security-mcp security_intel_summary` |

The tools are complementary, not mutually exclusive. `npm audit` has zero setup cost and should still run in CI. `npm-security-mcp` goes deeper when it matters.
