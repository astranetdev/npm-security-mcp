# Security Model

## Threat Model

### Threats Detected

#### 1. Vulnerable Dependencies
Known CVEs and GHSAs in direct and transitive dependencies. Detected via OSV, npm advisory bulk, and GitHub Advisory Database. Version ranges validated with `semver.satisfies()` — only flags packages where the installed version actually falls in the vulnerable range (not just any version of the package).

#### 2. Malicious Packages
Packages flagged by Socket.dev as containing malware, obfuscated code, or known-bad behavior. Socket MCP and Socket API adapters provide signals: `malware`, `obfuscated-code`, `bin-script-shell`, `telemetry`, `network-access`, and others.

#### 3. Typosquatting
Socket.dev scores surface packages that appear to impersonate popular packages by name similarity. The `check_maintainer` tool detects accounts that have published many packages in a short window — a common typosquat campaign pattern.

#### 4. Maintainer Compromise / Account Takeover
`diff_versions` compares maintainer lists between two versions. `watch_check` detects maintainer additions since the last check. Both flag new maintainers as `🚨 HIGH RISK` because account takeover is the primary vector for malicious version publishing (see: `event-stream`, `ua-parser-js`, `node-ipc`).

#### 5. Suspicious Install Scripts
`preinstall`, `install`, `postinstall`, `prepare`, and `prepack` scripts execute automatically on `npm install`. `diff_versions` shows script content when new ones appear. `watch_check` detects script hash changes between versions. `scan_package` surfaces install scripts from the npm registry metadata.

#### 6. Dependency Confusion
Packages with the same name as internal packages published to the public registry with a higher version number. Detected indirectly via maintainer analysis (unknown maintainer publishing a package that matches internal naming patterns) and via Socket.dev alerts.

#### 7. Protestware / Intentional Sabotage
Advisory databases (OSV, GitHub) track known protestware incidents. Socket.dev behavioral analysis flags packages that conditionally execute different code based on environment (a common sabotage pattern).

---

### Threats NOT Detected

**Be explicit about the boundaries:**

| Threat | Why not covered |
|--------|----------------|
| **Runtime malware** | This tool performs static/metadata analysis only. It cannot detect malicious behavior that only manifests at runtime. |
| **Zero-days** | Coverage is limited to publicly disclosed advisories. A vulnerability with no CVE/GHSA and no Socket.dev signal will not be detected. |
| **Sandboxed execution analysis** | No code is executed or sandboxed. Install scripts are shown as text, not run. |
| **Custom private registry packages** | Adapters query public registries. Private packages on Verdaccio, Artifactory, etc. are not analyzed unless their metadata is mirrored publicly. |
| **License compliance enforcement** | License fields are collected for SBOM output, but no legal analysis or policy enforcement is performed. |
| **Build-time code injection** | Tampering that happens in the build pipeline (CI compromise, artifact substitution) after the package is published is outside scope. |
| **100% supply chain guarantee** | Transitive dependency trees can be deep. While `scan_lockfile` covers all resolved packages, novel attack vectors in the supply chain may not yet have advisories. |

---

## Severity Model

### Severity Levels

| Level | Symbol | Criteria |
|-------|--------|----------|
| **critical** | 🔴 | CVSS ≥ 9.0, or known active exploitation, or confirmed malware |
| **high** | 🟠 | CVSS 7.0–8.9, or significant supply chain signal |
| **moderate** | 🟡 | CVSS 4.0–6.9, limited exploitability |
| **low** | 🔵 | CVSS < 4.0, theoretical or chained risk only |
| **supply-chain-risk** | ⚠️ | No CVE, but behavioral/metadata signal (Socket score, install scripts, maintainer change) |
| **info** | ℹ️ | Informational: outdated package, deprecated, missing integrity |

### Composite Risk Score

When multiple data sources are available, the effective risk of a package is a combination of:

```
composite_risk = max(
  cvss_score_normalized,          // 0–10 → 0–100
  (1 - socket_overall_score) * 100,  // low Socket score = high risk
  maintainer_risk_score,          // 0–100 (check_maintainer tool)
  advisory_count_weight           // each advisory adds weight by severity
)
```

**Priority order for remediation:**

1. `critical` CVE with known PoC → patch immediately
2. `critical` CVE without PoC → patch within 24h
3. `high` CVE + low Socket score → patch within 72h
4. `high` CVE alone → patch within 1 week
5. `supply-chain-risk` (no CVE) → investigate, consider `diff_versions` + `check_maintainer`
6. `moderate` → patch in next release cycle
7. `low` + `info` → track, patch opportunistically

---

## Data Source Trust Hierarchy

Sources are not equally authoritative. When data conflicts, apply this ordering:

```
1. OSV (canonical, cross-referenced CVE/GHSA)
2. GitHub Advisory Database (authoritative for GHSAs)
3. npm Advisory Bulk (npm-ecosystem-specific, fast)
4. Socket.dev (behavioral signals, no CVE assignment)
5. npm Registry metadata (raw metadata, not curated)
```

Advisories are deduplicated by ID across sources. When the same advisory appears in multiple sources, fields are merged preferring the most complete record (higher severity wins, more references merged).

---

## Policy Gates (CI/CD)

For automated pipelines, treat severity thresholds as hard gates:

| Policy | Behavior |
|--------|----------|
| `fail_on: critical` | Exit non-zero if any critical advisory found |
| `fail_on: high` | Exit non-zero on critical or high |
| `fail_on: any` | Exit non-zero on any advisory |
| `max_supply_chain_risk: 70` | Fail if any package has Socket score below 0.30 |
| `allow_list: ["GHSA-..."]` | Suppress specific known/accepted advisories |

These gates are not yet first-class CLI flags but can be implemented in CI by parsing `scan_lockfile` or `scan_package` output:

```bash
# Fail on critical or high
node -e "
  import { scanLockfile } from './src/tools/scan-lockfile.js';
  import { readFile } from 'fs/promises';
  const content = await readFile('package-lock.json', 'utf8');
  const result = await scanLockfile({ content });
  console.log(result);
  if (/🔴|🟠/.test(result)) process.exit(1);
" --input-type=module
```

---

## Known Limitations

1. **Rate limits** — Without `GITHUB_TOKEN`, GitHub API is limited to 60 requests/hour. High-volume scans (large lockfiles) may hit this limit. Always provide `GITHUB_TOKEN` in CI.

2. **Advisory lag** — OSV and GitHub may take hours to days to publish new advisories after a CVE is assigned. For zero-day coverage, Socket.dev behavioral analysis provides earlier signals.

3. **Version range accuracy** — Advisories sometimes use imprecise version ranges. `semver.satisfies()` is accurate for standard semver ranges, but non-standard strings (e.g., `"all"`, `"< 0"`) are handled conservatively.

4. **Transitive depth** — `scan_lockfile` covers the full resolved tree. `scan_dependencies` only covers what's listed in `package.json` — transitive deps require a lockfile for complete coverage.
