import { z } from 'zod';
import { OsvAdapter } from '../adapters/osv.js';
import { SocketMcpAdapter } from '../adapters/socket-mcp.js';
import { SocketApiAdapter } from '../adapters/socket-api.js';
import { dedupAdvisories } from '../utils/dedup.js';
import { formatTable, formatSources, summarySeverityBlock, severityEmoji } from '../utils/format.js';
import { stateManager } from '../state/manager.js';

export const scanDependenciesSchema = z.object({
  package_json: z.string().min(1).describe('Contents of package.json'),
  include_dev: z.boolean().optional().default(false).describe('Include devDependencies'),
});

const osv = new OsvAdapter();
const socketMcp = new SocketMcpAdapter();
const socketApi = new SocketApiAdapter();

export async function scanDependencies({ package_json, include_dev = false }) {
  let pkg;
  try {
    pkg = JSON.parse(package_json);
  } catch {
    return '## Scan Error\n\nInvalid JSON in package.json';
  }

  const deps = {
    ...pkg.dependencies,
    ...(include_dev ? pkg.devDependencies : {}),
  };

  if (!Object.keys(deps).length) {
    return '## Dependency Scan\n\nNo dependencies found in package.json.';
  }

  const packages = Object.entries(deps).map(([name, range]) => ({
    name,
    version: range.replace(/^[\^~>=<]/, '').split(' ')[0],
    range,
    isRange: /[\^~><=*x]/.test(range),
  }));

  const consulted = [];
  const failed = [];

  const socket = socketMcp.available()
    ? socketMcp
    : socketApi.available() ? socketApi : null;

  const [osvResult, socketResult] = await Promise.all([
    osv.fetch(packages).then(r => { consulted.push('OSV'); if (!r.ok) failed.push('OSV'); return r; }),
    socket
      ? socket.fetch(packages).then(r => {
          consulted.push(socket.name);
          if (!r.ok) failed.push(socket.name);
          return r;
        })
      : Promise.resolve(null),
  ]);

  const allAdvisories = dedupAdvisories([osvResult.data || []]);

  // Build vuln map by package
  const vulnByPkg = new Map();
  for (const adv of allAdvisories) {
    if (!vulnByPkg.has(adv.packageName)) vulnByPkg.set(adv.packageName, []);
    vulnByPkg.get(adv.packageName).push(adv);
  }

  // Build socket score map
  const socketByPkg = new Map();
  if (socketResult?.data) {
    for (const s of socketResult.data) {
      if (s.name) socketByPkg.set(s.name, s);
    }
  }

  const counts = { critical: 0, high: 0, moderate: 0, low: 0 };
  let supplyChainRisk = 0;
  const rows = [];

  for (const p of packages) {
    const advs = vulnByPkg.get(p.name) || [];
    const socket = socketByPkg.get(p.name);
    const worstSev = worstSeverity(advs);
    if (worstSev in counts) counts[worstSev]++;

    const socketScore = socket?.socketScore != null
      ? `${Math.round(socket.socketScore * 100)}%`
      : '—';
    const supplyScore = socket?.supplyChainScore;
    if (supplyScore != null && supplyScore < 0.5) supplyChainRisk++;

    const fix = advs.map(a => a.fixVersion || a.patchedVersions).filter(Boolean)[0] || '—';

    rows.push([
      `\`${p.name}\``,
      p.isRange ? `${p.range} ⚠️` : p.range,
      socketScore,
      advs.length ? `${advs.length}` : '0',
      advs.length ? `${severityEmoji(worstSev)} ${worstSev}` : '—',
      fix,
    ]);
  }

  await stateManager.addScanHistory('deps', pkg.name || 'unknown', counts).catch(() => {});

  const lines = [];
  lines.push(`## Dependency Security Scan: \`${pkg.name || 'package.json'}\``);
  lines.push(`\n${summarySeverityBlock(counts)}\n`);
  lines.push(`**Total:** ${packages.length} packages · **Vulnerable:** ${[...vulnByPkg.keys()].length} · **Supply chain risk:** ${supplyChainRisk}\n`);

  if (packages.some(p => p.isRange)) {
    lines.push(`> ⚠️ Packages marked ⚠️ use version ranges. Analysis is based on the minimum version satisfying the range — install actual versions for precise results.\n`);
  }

  lines.push(formatTable(
    ['Package', 'Version/Range', 'Socket Score', 'Vulns', 'Severity', 'Fix'],
    rows
  ));

  lines.push(formatSources(consulted, failed));
  return lines.join('\n');
}

function worstSeverity(advs) {
  const order = ['critical', 'high', 'moderate', 'medium', 'low'];
  for (const s of order) {
    if (advs.some(a => (a.severity || '').toLowerCase() === s)) return s;
  }
  return 'unknown';
}
