# Architecture

## Overview

`npm-security-mcp` is an **orchestrator with pluggable adapters**. No single data source is authoritative. Each source is an independent adapter that can fail without affecting others. The orchestrator merges, deduplicates, and formats results from all available sources.

```
┌──────────────────────────────────────────────────────────┐
│                    MCP Client (Claude)                    │
└─────────────────────────┬────────────────────────────────┘
                          │ stdio (JSON-RPC 2.0)
┌─────────────────────────▼────────────────────────────────┐
│                  McpServer (index.js)                     │
│              13 tools registered via Zod schemas          │
└──────┬──────────┬──────────┬───────────┬─────────────────┘
       │          │          │           │
  ┌────▼───┐ ┌───▼────┐ ┌───▼────┐ ┌───▼──────────┐
  │ Tools  │ │ Tools  │ │ Tools  │ │    Tools     │
  │ scan_* │ │ diff_* │ │watch_* │ │explain/intel │
  └────┬───┘ └───┬────┘ └───┬────┘ └───┬──────────┘
       │          │          │           │
       └──────────┴──────────┴───────────┘
                          │
              ┌───────────▼───────────┐
              │      Adapters         │
              │ ┌───────────────────┐ │
              │ │ OsvAdapter        │ │  api.osv.dev
              │ │ NpmBulkAdvisory   │ │  registry.npmjs.org
              │ │ NpmRegistryAdapter│ │  registry.npmjs.org
              │ │ SocketMcpAdapter  │ │  mcp.socket.dev
              │ │ SocketApiAdapter  │ │  api.socket.dev
              │ │ GitHubAdvisory    │ │  api.github.com
              │ └───────────────────┘ │
              └───────────┬───────────┘
                          │
              ┌───────────▼───────────┐
              │     Utils             │
              │  dedup · format       │
              │  semver-check         │
              └───────────┬───────────┘
                          │
              ┌───────────▼───────────┐
              │   StateManager        │
              │  ~/.npm-security-mcp/ │
              │  state.json           │
              └───────────────────────┘
```

---

## Adapter Interface

Every adapter extends `BaseAdapter`:

```javascript
class BaseAdapter {
  name: string
  available(): boolean        // false = skip this adapter silently
  fetch(packages): Promise<AdapterResult>
  withRetry(fn, opts)        // 3 attempts, exponential backoff
  fetchWithTimeout(url, opts, ms)  // AbortController-based timeout
}

class AdapterResult {
  source: string
  data: Advisory[]
  errors: string[]
  ok: boolean                // errors.length === 0
}
```

`available()` checks environment at call time (not at construction). Reason: env vars may be injected after module load in some MCP client configurations.

---

## Data Flow

### scan_package example

```
scan_package({ name: "lodash", version: "4.17.15" })
  │
  ├─► OsvAdapter.fetch()          → [Advisory, ...]
  ├─► NpmBulkAdvisoryAdapter.fetch() → [Advisory, ...]  ← semver check applied here
  ├─► SocketMcpAdapter.fetch()    → [SocketScore, ...]  (or SocketApiAdapter fallback)
  └─► NpmRegistryAdapter.getPackage() → metadata + risk signals
          │
          ▼
  dedupAdvisories([osvData, npmData])
          │
          ▼
  format.js → markdown output
          │
          ▼
  stateManager.addScanHistory()
          │
          ▼
  MCP response: { content: [{ type: "text", text: markdown }] }
```

### Advisory deduplication

Advisories are matched by `id` (GHSA or CVE). When the same advisory appears from multiple sources:
- Higher severity wins
- References arrays are merged and deduplicated
- All source names are tracked in `sources[]`
- Missing fields are filled from the secondary source

---

## State Management

`state.json` is a single JSON file with three sections:

```typescript
interface State {
  watchlist: Record<string, WatchEntry>
  scanHistory: ScanRecord[]   // capped at 100 entries (FIFO)
  cache: Record<string, CacheEntry>
}

interface CacheEntry {
  data: unknown
  fetchedAt: string  // ISO timestamp
}
```

**Cache TTL:**
- Vulnerability data: 1 hour (`osv:*`, `npm-advisory:*`)
- Registry metadata: 15 minutes (`meta:*`)

**Locking:** Write operations are sequential (no concurrent writes). The state manager uses a simple in-memory write queue. For multi-process scenarios (unlikely in MCP stdio model), file locking via `flock` is not yet implemented (see ROADMAP).

**Path resolution:**
1. `NPM_SECURITY_STATE` env var (directory)
2. `~/.npm-security-mcp/state.json`

---

## Error Handling Strategy

```
Tool invocation
  │
  ├─ Adapter A fails (network error, 5xx, timeout)
  │    └─► Caught in adapter.fetch(), returns AdapterResult({ errors: [...] })
  │         Tool continues with remaining adapters
  │
  ├─ Adapter B succeeds
  │    └─► data merged into result
  │
  └─ All adapters fail
       └─► Tool returns output with empty advisories + sources-failed section
            Never throws to MCP layer
```

Errors are surfaced in the markdown output as:

```
---
**Sources consulted:** OSV, npm-advisory
**Sources failed:** socket-mcp
```

The MCP `isError: true` flag is only set for tool-level exceptions (parse errors, invalid input), not adapter failures.

---

## MCP Protocol

Transport: **stdio** (JSON-RPC 2.0 over stdin/stdout).

All tool schemas are defined as Zod schemas and passed to `server.tool()`. The SDK handles schema-to-JSON-Schema conversion and input validation. Invalid inputs return a schema validation error before the tool function is called.

Tool responses always return:
```json
{
  "content": [{ "type": "text", "text": "<markdown>" }]
}
```

Markdown is the canonical output format — never raw JSON. Rationale: MCP clients (Claude, Claude Code) render markdown; raw JSON is unreadable in chat.

---

## Security of the Tool Itself

- No credentials are stored. API keys are read from environment variables on each request.
- `state.json` contains only package names, versions, and advisory IDs — no secrets.
- All outbound requests use HTTPS only.
- No eval, no dynamic imports beyond module initialization.
- The tool makes outbound HTTP requests to public APIs. In locked-down environments, allowlist: `api.osv.dev`, `registry.npmjs.org`, `mcp.socket.dev`, `api.socket.dev`, `api.github.com`.

---

## Adding a New Adapter

1. Create `src/adapters/my-source.js` extending `BaseAdapter`
2. Implement `available()` and `fetch(packages)` returning `AdapterResult`
3. Import in the relevant tool file(s)
4. Run it in parallel with other adapters using `Promise.all()`
5. Pass its data to `dedupAdvisories()`

No changes needed to `index.js` or the MCP registration layer — adapters are wired at the tool level.

---

## Adding a New Tool

1. Create `src/tools/my-tool.js` — export `myToolSchema` (Zod) and `myTool(args)` (async fn returning markdown string)
2. In `src/index.js`:
   ```javascript
   import { myTool, myToolSchema } from './tools/my-tool.js';
   server.tool('my_tool', 'Description', myToolSchema.shape, wrapTool(myTool));
   ```
3. Add smoke test case to `src/smoke-tests.js`

---

## Adding a New Ecosystem

The adapter interface is ecosystem-agnostic. To add PyPI support:

1. Create `src/adapters/pypi-advisory.js`
2. Map PyPI package refs to `{ name, version, ecosystem: "PyPI" }` — OSV and Socket already support multiple ecosystems
3. The `OsvAdapter` already accepts `ecosystem` in its query — just change the `ecosystem` field from `"npm"` to `"PyPI"`
4. Create tools or extend existing ones with an `ecosystem` parameter

The main constraint: `NpmBulkAdvisoryAdapter` and `NpmRegistryAdapter` are npm-specific. For other ecosystems, equivalent adapters would be needed.
