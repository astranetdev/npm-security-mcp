import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { scanPackage, scanPackageSchema } from './tools/scan-package.js';
import { scanLockfile, scanLockfileSchema } from './tools/scan-lockfile.js';
import { scanDependencies, scanDependenciesSchema } from './tools/scan-dependencies.js';
import { diffVersions, diffVersionsSchema } from './tools/diff-versions.js';
import { searchAdvisory, searchAdvisorySchema } from './tools/search-advisory.js';
import { checkMaintainer, checkMaintainerSchema } from './tools/check-maintainer.js';
import {
  watchAdd, watchAddSchema,
  watchRemove, watchRemoveSchema,
  watchList, watchListSchema,
  watchCheck, watchCheckSchema,
} from './tools/watch.js';
import { generateSbom, generateSbomSchema } from './tools/generate-sbom.js';
import { explainVuln, explainVulnSchema } from './tools/explain-vuln.js';
import { securityIntelSummary, securityIntelSchema } from './tools/security-intel.js';

const server = new McpServer({
  name: 'npm-security-mcp',
  version: '1.0.0',
});

function wrapTool(fn) {
  return async (args) => {
    try {
      const result = await fn(args);
      return { content: [{ type: 'text', text: result }] };
    } catch (err) {
      return {
        content: [{ type: 'text', text: `## Error\n\n${err.message}` }],
        isError: true,
      };
    }
  };
}

server.tool(
  'scan_package',
  'Scan an npm package for known vulnerabilities, supply chain risks, and metadata red flags',
  scanPackageSchema.shape,
  wrapTool(scanPackage)
);

server.tool(
  'scan_lockfile',
  'Scan all packages in a package-lock.json for vulnerabilities (direct and transitive)',
  scanLockfileSchema.shape,
  wrapTool(scanLockfile)
);

server.tool(
  'scan_dependencies',
  'Scan dependencies listed in a package.json for vulnerabilities and supply chain scores',
  scanDependenciesSchema.shape,
  wrapTool(scanDependencies)
);

server.tool(
  'diff_versions',
  'Compare two versions of an npm package for security-relevant changes (scripts, maintainers, dependencies)',
  diffVersionsSchema.shape,
  wrapTool(diffVersions)
);

server.tool(
  'search_advisory',
  'Search for a security advisory by CVE ID, GHSA ID, package name, or keyword',
  searchAdvisorySchema.shape,
  wrapTool(searchAdvisory)
);

server.tool(
  'check_maintainer',
  'Analyze the security risk profile of an npm maintainer account',
  checkMaintainerSchema.shape,
  wrapTool(checkMaintainer)
);

server.tool(
  'watch_add',
  'Add a package to the security watchlist for ongoing monitoring',
  watchAddSchema.shape,
  wrapTool(watchAdd)
);

server.tool(
  'watch_remove',
  'Remove a package from the security watchlist',
  watchRemoveSchema.shape,
  wrapTool(watchRemove)
);

server.tool(
  'watch_list',
  'List all packages currently on the security watchlist',
  watchListSchema.shape,
  wrapTool(watchList)
);

server.tool(
  'watch_check',
  'Check watched packages for new versions, advisories, maintainer changes, or script changes',
  watchCheckSchema.shape,
  wrapTool(watchCheck)
);

server.tool(
  'generate_sbom',
  'Generate a Software Bill of Materials (SBOM) in CycloneDX or SPDX format from package.json',
  generateSbomSchema.shape,
  wrapTool(generateSbom)
);

server.tool(
  'explain_vuln',
  'Get a detailed explanation of a CVE or GHSA advisory including attack vector, CVSS breakdown, and mitigation',
  explainVulnSchema.shape,
  wrapTool(explainVuln)
);

server.tool(
  'security_intel_summary',
  'Get a summary of recent npm security advisories and supply chain threats for the past N days',
  securityIntelSchema.shape,
  wrapTool(securityIntelSummary)
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write('npm-security-mcp running on stdio\n');
}

main().catch(err => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});
