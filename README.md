# npm-security-mcp

MCP server for npm package security scanning, advisory lookup, supply chain risk analysis, and SBOM generation.

> **Multi-source.** OSV + npm advisory + GitHub Advisory + Socket.dev — no single provider is authoritative.  
> **No single point of failure.** Each adapter fails independently. Others continue.  
> **AI-native.** Designed for Claude and Claude Code via MCP stdio transport.

📖 [Architecture](ARCHITECTURE.md) · [Security Model](SECURITY_MODEL.md) · [Comparison vs npm audit](COMPARISON.md) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md)

## Features

| Tool | Description |
|------|-------------|
| `scan_package` | Scan a package for CVEs, supply chain risk, metadata red flags |
| `scan_lockfile` | Scan all packages in a `package-lock.json` |
| `scan_dependencies` | Scan `package.json` dependencies with Socket.dev scores |
| `diff_versions` | Compare two versions for script/maintainer/dep changes |
| `search_advisory` | Look up CVE, GHSA, package name, or keyword |
| `check_maintainer` | Risk profile for an npm maintainer account |
| `watch_add` | Add package to watchlist |
| `watch_remove` | Remove from watchlist |
| `watch_list` | List watched packages |
| `watch_check` | Check for new versions, advisories, maintainer changes |
| `generate_sbom` | Generate CycloneDX 1.5 or SPDX 2.3 SBOM |
| `explain_vuln` | Detailed CVE/GHSA explanation with CVSS breakdown |
| `security_intel_summary` | Recent npm security advisories for the past N days |

## Data Sources

| Adapter | What it provides | API Key |
|---------|-----------------|---------|
| OSV (`api.osv.dev`) | CVEs, GHSAs, version ranges | None |
| npm Advisory Bulk | npm-specific advisories | None |
| npm Registry | Metadata, scripts, maintainers | None |
| GitHub Advisory | GHSAs, GraphQL queries | Optional (`GITHUB_TOKEN`) |
| Socket MCP (`mcp.socket.dev`) | Supply chain scores, malware signals | Optional (`SOCKET_API_KEY`) |
| Socket API (`api.socket.dev`) | Supply chain scores (REST fallback) | `SOCKET_API_KEY` |

If an adapter fails, others continue. Each response reports which sources were consulted and which failed.

## Requirements

- Node.js 18+
- npm

## Installation

```bash
git clone git@github.com:astranetdev/npm-security-mcp.git
cd npm-security-mcp
npm install
```

## Environment Variables

```bash
SOCKET_API_KEY=sk-...        # Optional: enables Socket API adapter, improves Socket MCP auth
GITHUB_TOKEN=ghp_...         # Optional: 5000 req/h GitHub rate limit (vs 60 without)
NPM_SECURITY_STATE=/path/    # Optional: custom directory for state.json (default: ~/.npm-security-mcp/)
```

## Configuration

### Claude Desktop

**Linux:** `~/.config/claude-desktop/config.json`  
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "npm-security": {
      "command": "node",
      "args": ["/absolute/path/to/npm-security-mcp/src/index.js"],
      "env": {
        "SOCKET_API_KEY": "sk-...",
        "GITHUB_TOKEN": "ghp_..."
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add npm-security -- node /absolute/path/to/npm-security-mcp/src/index.js
```

With env vars:

```bash
claude mcp add npm-security -e SOCKET_API_KEY=sk-... -e GITHUB_TOKEN=ghp_... -- node /absolute/path/to/npm-security-mcp/src/index.js
```

### CI/CD — GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  npm-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install npm-security-mcp
        run: |
          cd /tmp
          git clone https://github.com/astranetdev/npm-security-mcp.git
          cd npm-security-mcp && npm install

      - name: Scan lockfile for vulnerabilities
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          LOCKFILE=$(cat package-lock.json)
          RESULT=$(node -e "
            import('./src/tools/scan-lockfile.js').then(async m => {
              const result = await m.scanLockfile({ content: process.env.LOCKFILE_CONTENT });
              console.log(result);
              // Exit 1 if critical or high vulns found
              if (result.includes('🔴') || result.match(/\d+ critical/)) process.exit(1);
              if (result.match(/\d+ high/)) process.exit(1);
            });
          " <<'JSEOF'
          JSEOF
          )
          echo "$RESULT"

      # Alternative: use the script directly with stdin
      - name: Scan lockfile (direct script)
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          node -e "
            import { scanLockfile } from '/tmp/npm-security-mcp/src/tools/scan-lockfile.js';
            import { readFile } from 'fs/promises';
            const content = await readFile('package-lock.json', 'utf8');
            const result = await scanLockfile({ content });
            console.log(result);
            const hasCritical = result.includes('critical') && !result.includes('0 critical');
            const hasHigh = result.includes('high') && !result.includes('0 high');
            if (hasCritical || hasHigh) {
              console.error('Critical or high vulnerabilities found — failing build');
              process.exit(1);
            }
          " --input-type=module
```

## Threat Model

Detects: known CVEs · malicious packages · typosquatting · maintainer compromise · suspicious install scripts · dependency confusion · protestware.

Does NOT detect: runtime malware · zero-days · private registry packages · build-time injection.

→ Full threat model and severity scoring: [SECURITY_MODEL.md](SECURITY_MODEL.md)

## Why not `npm audit`?

| | `npm audit` | `npm-security-mcp` |
|--|:-----------:|:------------------:|
| Vuln data sources | 1 (npm only) | 3 (OSV + npm + GitHub) |
| Supply chain analysis | ❌ | ✅ Socket.dev |
| Maintainer risk | ❌ | ✅ |
| Version diffing | ❌ | ✅ |
| Watchlists | ❌ | ✅ |
| SBOM | ❌ | ✅ CycloneDX + SPDX |
| Vuln explanation | ❌ | ✅ CVSS breakdown + mitigation |

→ Full comparison: [COMPARISON.md](COMPARISON.md)

## Smoke Tests

Runs real API calls to verify all tools work end-to-end:

```bash
npm run smoke
```

Expected output:
```
✅ PASS scan_package lodash@4.17.15 finds prototype pollution
✅ PASS scan_package lodash@4.17.21 has 0 critical vulns
✅ PASS scan_lockfile detects advisories for handlebars@4.7.6
✅ PASS diff_versions lodash 4.17.15→4.17.21 finds no new install scripts
✅ PASS search_advisory GHSA-p6mc-m468-83gw returns lodash advisory
✅ PASS security_intel_summary returns recent npm advisories
✅ PASS watch_add → watch_check → watch_remove completes without error
```

## State File

Persisted at `~/.npm-security-mcp/state.json`:

- **watchlist** — packages under active monitoring
- **scanHistory** — last 100 scan results
- **cache** — API responses (1h TTL for vulns, 15min for metadata)

Override path with `NPM_SECURITY_STATE=/custom/dir/`.

## Architecture

```
src/
  index.js              ← McpServer + StdioTransport, tool registration
  adapters/
    base.js             ← BaseAdapter, AdapterResult, retry, timeout helpers
    osv.js              ← api.osv.dev batch queries + vuln hydration
    npm-bulk-advisory.js ← npm advisory bulk endpoint
    npm-registry.js     ← registry metadata, maintainer search
    socket-mcp.js       ← mcp.socket.dev depscore tool
    socket-api.js       ← api.socket.dev/v0/purl REST
    github-advisory.js  ← GitHub REST + GraphQL advisory queries
  tools/                ← one file per tool, pure async functions
  state/
    manager.js          ← read/write state.json with cache TTL
  utils/
    semver-check.js     ← isVulnerable(), extractFixVersion()
    dedup.js            ← merge advisories from multiple sources by ID
    format.js           ← markdown formatters, severity emoji
```

Each adapter implements `available()` and `fetch(packages)`. If `available()` returns false (missing API key, etc.), the orchestrator skips it. All adapter failures are isolated — a failing adapter never crashes a tool.

Retry: 3 attempts with exponential backoff (500ms, 1000ms, 2000ms).  
Timeouts: 10s for npm/OSV, 15s for Socket.

## License

Copyright (c) 2026 AstranetDev

Licensed under the [Apache License, Version 2.0](LICENSE).

You may use, copy, modify, distribute, and sublicense this software freely under the terms of the Apache 2.0 License. See [LICENSE](LICENSE) for the full text.
