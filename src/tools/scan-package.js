import { z } from 'zod';
import { OsvAdapter } from '../adapters/osv.js';
import { NpmBulkAdvisoryAdapter } from '../adapters/npm-bulk-advisory.js';
import { SocketMcpAdapter } from '../adapters/socket-mcp.js';
import { SocketApiAdapter } from '../adapters/socket-api.js';
import { NpmRegistryAdapter } from '../adapters/npm-registry.js';
import { dedupAdvisories } from '../utils/dedup.js';
import { formatAdvisory, formatSources, summarySeverityBlock, formatTable, severityEmoji } from '../utils/format.js';
import { stateManager } from '../state/manager.js';

export const scanPackageSchema = z.object({
  name: z.string().min(1).describe('Package name'),
  version: z.string().optional().describe('Specific version (default: latest)'),
});

const osv = new OsvAdapter();
const npmAdvisory = new NpmBulkAdvisoryAdapter();
const socketMcp = new SocketMcpAdapter();
const socketApi = new SocketApiAdapter();
const npmRegistry = new NpmRegistryAdapter();

export async function scanPackage({ name, version }) {
  // Resolve version
  let resolvedVersion = version;
  if (!resolvedVersion) {
    try {
      resolvedVersion = await npmRegistry.getLatestVersion(name);
    } catch {
      resolvedVersion = 'latest';
    }
  }

  const pkg = [{ name, version: resolvedVersion }];
  const consulted = [];
  const failed = [];

  // Run all adapters in parallel
  const [osvResult, npmResult, socketResult, registryData] = await Promise.all([
    osv.fetch(pkg).then(r => { consulted.push('OSV'); if (!r.ok) failed.push('OSV'); return r; }),
    npmAdvisory.fetch(pkg).then(r => { consulted.push('npm-advisory'); if (!r.ok) failed.push('npm-advisory'); return r; }),
    (socketMcp.available()
      ? socketMcp.fetch(pkg).then(r => { consulted.push('socket-mcp'); if (!r.ok) failed.push('socket-mcp'); return r; })
      : socketApi.available()
        ? socketApi.fetch(pkg).then(r => { consulted.push('socket-api'); if (!r.ok) failed.push('socket-api'); return r; })
        : Promise.resolve(null)
    ),
    npmRegistry.getPackage(name).catch(() => null),
  ]);

  // Consolidate advisories
  const allAdvisories = dedupAdvisories([
    osvResult.data || [],
    npmResult.data?.filter(a => a.isVulnerable !== false) || [],
  ]);

  // Socket scores
  const socketScores = socketResult?.data?.[0] || null;

  // Risk signals from registry
  const riskSignals = registryData ? npmRegistry.extractRiskSignals(registryData, resolvedVersion) : [];

  // Count by severity
  const counts = { critical: 0, high: 0, moderate: 0, low: 0 };
  for (const adv of allAdvisories) {
    const sev = (adv.severity || '').toLowerCase();
    if (sev in counts) counts[sev]++;
  }

  // Save to history
  await stateManager.addScanHistory('package', `${name}@${resolvedVersion}`, counts).catch(() => {});

  // Build output
  const lines = [];
  lines.push(`## Security Scan: \`${name}@${resolvedVersion}\``);
  lines.push(`\n${summarySeverityBlock(counts)}\n`);

  if (socketScores) {
    lines.push(`### Socket.dev Scores`);
    const scoreRows = [];
    if (socketScores.socketScore != null) scoreRows.push(['Overall', `${Math.round(socketScores.socketScore * 100)}%`]);
    if (socketScores.supplyChainScore != null) scoreRows.push(['Supply Chain', `${Math.round(socketScores.supplyChainScore * 100)}%`]);
    if (socketScores.qualityScore != null) scoreRows.push(['Quality', `${Math.round(socketScores.qualityScore * 100)}%`]);
    if (socketScores.maintenanceScore != null) scoreRows.push(['Maintenance', `${Math.round(socketScores.maintenanceScore * 100)}%`]);
    if (socketScores.licenseScore != null) scoreRows.push(['License', `${Math.round(socketScores.licenseScore * 100)}%`]);
    if (scoreRows.length) {
      lines.push(formatTable(['Category', 'Score'], scoreRows));
    }
    if (socketScores.alerts?.length) {
      lines.push(`\n**Alerts:** ${socketScores.alerts.map(a => `\`${a.type || a}\``).join(', ')}`);
    }
    lines.push('');
  }

  if (riskSignals.length) {
    lines.push(`### ⚠️ Registry Risk Signals`);
    for (const s of riskSignals) {
      lines.push(`- ${severityEmoji(s.severity)} **${s.type}**: ${s.detail}`);
    }
    lines.push('');
  }

  if (allAdvisories.length === 0) {
    lines.push(`### Vulnerabilities\n\n✅ No known vulnerabilities found.`);
  } else {
    lines.push(`### Vulnerabilities (${allAdvisories.length})\n`);
    for (const adv of allAdvisories) {
      lines.push(formatAdvisory(adv));
      lines.push('');
    }
  }

  lines.push(formatSources(consulted, failed));
  return lines.join('\n');
}
