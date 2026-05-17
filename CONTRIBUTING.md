# Contributing

## Setup

```bash
git clone <repo>
cd npm-security-mcp
npm install
```

Node.js 18+ required. All code is ESM (`"type": "module"`).

## Running the smoke tests

```bash
npm run smoke
```

Smoke tests make real HTTP requests to live APIs. They will fail without network access. Expected: 7/7 pass. Do not mock — the point is to verify real API contracts.

`GITHUB_TOKEN` is not required for smoke tests but avoids GitHub rate limit warnings if you run them repeatedly.

## Project structure

```
src/
  index.js              ← tool registration only, no business logic
  adapters/             ← one file per data source
  tools/                ← one file per MCP tool
  state/manager.js      ← state.json read/write
  utils/                ← pure functions, no side effects
```

## Adding an adapter

1. Create `src/adapters/my-source.js` extending `BaseAdapter`
2. Implement `available()`: return `false` if required env var is missing
3. Implement `fetch(packages)`: return `AdapterResult`
4. Call `this.withRetry()` and `this.fetchWithTimeout()` — do not use raw `fetch` directly
5. Normalize output to the advisory shape (see existing adapters for the schema)
6. Wire into relevant tools in `src/tools/`

## Adding a tool

1. Create `src/tools/my-tool.js`
2. Export a Zod schema (`myToolSchema`) and an async function (`myTool(args)`) returning a markdown string
3. Register in `src/index.js` via `server.tool()` + `wrapTool()`
4. Add a smoke test case in `src/smoke-tests.js`

## Code style

- ESM only: `import`/`export`, no `require()`
- No TypeScript — plain JS with JSDoc where helpful
- No comments explaining what the code does — names do that
- Comments only for non-obvious WHY (workaround for API quirk, hidden constraint)
- Adapter failures: catch and return `AdapterResult({ errors: [...] })` — never throw to the tool layer
- Tool errors: return markdown error message — never throw to the MCP layer
- Output: always markdown, never raw JSON

## Adapter output schema (advisory)

```javascript
{
  id: string,              // canonical ID (GHSA or CVE preferred)
  ghsaId: string | null,
  cveId: string | null,
  aliases: string[],
  title: string,
  description: string | null,
  severity: 'critical' | 'high' | 'moderate' | 'low' | 'unknown',
  cvssScore: number | null,
  cweIds: string[],
  packageName: string | null,
  vulnerableVersions: string | null,  // semver range
  patchedVersions: string | null,     // semver range
  fixVersion: string | null,          // extracted from patchedVersions
  references: string[],
  publishedAt: string | null,         // ISO timestamp
  modifiedAt: string | null,
  source: string,                     // adapter name
}
```

## Pull requests

- One PR per concern — do not bundle unrelated changes
- Smoke tests must pass before merging
- If adding a new adapter: include a note on whether it requires API keys and what the rate limits are
- If changing advisory output shape: update `utils/dedup.js` and `utils/format.js` accordingly

## Reporting a security issue

Do not open a public issue for vulnerabilities in this tool itself. Email the maintainer directly or use GitHub private security advisories. For vulnerabilities in packages detected by the tool, open a public issue referencing the CVE/GHSA.
