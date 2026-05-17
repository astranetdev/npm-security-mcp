import { z } from 'zod';
import { GitHubAdvisoryAdapter } from '../adapters/github-advisory.js';
import { OsvAdapter } from '../adapters/osv.js';
import { SocketMcpAdapter } from '../adapters/socket-mcp.js';
import { stateManager } from '../state/manager.js';
import { formatAdvisory, formatSources, summarySeverityBlock, severityEmoji } from '../utils/format.js';
import { dedupAdvisories } from '../utils/dedup.js';

export const securityIntelSchema = z.object({
  days: z.number().int().min(1).max(90).optional().default(7),
});

const github = new GitHubAdvisoryAdapter();
const osv = new OsvAdapter();
const socketMcp = new SocketMcpAdapter();

export async function securityIntelSummary({ days = 7 }) {
  const consulted = [];
  const failed = [];
  const since = new Date(Date.now() - days * 86400000).toISOString();

  // Fetch from multiple sources in parallel
  const [ghAdvisories, osvAdvisories, watchlist] = await Promise.all([
    github.searchRecent(days)
      .then(r => { consulted.push('github-advisory'); return r; })
      .catch(() => { failed.push('github-advisory'); return []; }),
    fetchOsvRecent(since)
      .then(r => { consulted.push('OSV'); return r; })
      .catch(() => { failed.push('OSV'); return []; }),
    stateManager.watchList().catch(() => ({})),
  ]);

  const allAdvisories = dedupAdvisories([ghAdvisories, osvAdvisories]);

  // Sort by severity then date
  const severityOrder = { critical: 0, high: 1, moderate: 2, medium: 2, low: 3, unknown: 4 };
  allAdvisories.sort((a, b) => {
    const sa = severityOrder[(a.severity || '').toLowerCase()] ?? 4;
    const sb = severityOrder[(b.severity || '').toLowerCase()] ?? 4;
    if (sa !== sb) return sa - sb;
    return new Date(b.publishedAt || 0) - new Date(a.publishedAt || 0);
  });

  const counts = { critical: 0, high: 0, moderate: 0, low: 0 };
  for (const adv of allAdvisories) {
    const sev = (adv.severity || '').toLowerCase();
    if (sev in counts) counts[sev]++;
  }

  // Watchlist activity
  const watchlistNames = Object.keys(watchlist);
  let watchlistAdvisories = [];
  if (watchlistNames.length) {
    const watchResult = await osv.fetch(watchlistNames.map(name => ({ name }))).catch(() => ({ data: [] }));
    watchlistAdvisories = (watchResult.data || []).filter(adv => {
      if (!adv.publishedAt) return false;
      return new Date(adv.publishedAt) >= new Date(since);
    });
  }

  // Socket scores for critical/high packages
  const criticalPkgs = allAdvisories
    .filter(a => ['critical', 'high'].includes((a.severity || '').toLowerCase()) && a.packageName)
    .map(a => ({ name: a.packageName }))
    .filter((p, i, arr) => arr.findIndex(x => x.name === p.name) === i)
    .slice(0, 10);

  let socketScores = [];
  if (criticalPkgs.length && socketMcp.available()) {
    consulted.push('socket-mcp');
    const socketResult = await socketMcp.fetch(criticalPkgs).catch(() => { failed.push('socket-mcp'); return { data: [] }; });
    socketScores = socketResult.data || [];
  }
  const socketByPkg = new Map(socketScores.filter(s => s.name).map(s => [s.name, s]));

  const lines = [];
  lines.push(`## npm Security Intelligence — Last ${days} Days`);
  lines.push(`\n**Period:** ${since.split('T')[0]} → ${new Date().toISOString().split('T')[0]}`);
  lines.push(`**Total advisories:** ${allAdvisories.length}\n`);
  lines.push(summarySeverityBlock(counts));

  // Supply chain section
  const supplyChainAlerts = allAdvisories.filter(a =>
    a.title?.toLowerCase().includes('supply chain') ||
    a.description?.toLowerCase().includes('malware') ||
    a.description?.toLowerCase().includes('typosquat')
  );
  if (supplyChainAlerts.length) {
    lines.push(`\n### 🚨 Supply Chain Alerts (${supplyChainAlerts.length})`);
    for (const adv of supplyChainAlerts.slice(0, 5)) {
      lines.push(`- ${severityEmoji(adv.severity)} **${adv.id}** (\`${adv.packageName || 'unknown'}\`): ${adv.title}`);
    }
  }

  lines.push(`\n### Top 10 Recent Advisories\n`);
  for (const adv of allAdvisories.slice(0, 10)) {
    const socket = socketByPkg.get(adv.packageName);
    const socketInfo = socket?.socketScore != null ? ` · Socket: ${Math.round(socket.socketScore * 100)}%` : '';
    lines.push(`**${adv.id}** · ${severityEmoji(adv.severity)} ${adv.severity || 'unknown'} · \`${adv.packageName || 'unknown'}\`${socketInfo}`);
    lines.push(`> ${(adv.title || '').slice(0, 120)}`);
    if (adv.publishedAt) lines.push(`> *Published: ${adv.publishedAt.split('T')[0]}*`);
    if (adv.patchedVersions) lines.push(`> Fix: \`${adv.patchedVersions}\``);
    lines.push('');
  }

  if (watchlistAdvisories.length) {
    lines.push(`\n### ⚠️ Watchlist Alerts (${watchlistAdvisories.length})`);
    for (const adv of watchlistAdvisories.slice(0, 5)) {
      lines.push(`- ${severityEmoji(adv.severity)} **${adv.packageName}**: ${adv.title}`);
    }
  }

  lines.push(`\n### Statistics`);
  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total advisories | ${allAdvisories.length} |`);
  lines.push(`| Critical | ${counts.critical} |`);
  lines.push(`| High | ${counts.high} |`);
  lines.push(`| Moderate | ${counts.moderate} |`);
  lines.push(`| Low | ${counts.low} |`);
  lines.push(`| Supply chain alerts | ${supplyChainAlerts.length} |`);
  lines.push(`| Watchlist alerts | ${watchlistAdvisories.length} |`);

  lines.push(formatSources(consulted, failed));
  return lines.join('\n');
}

async function fetchOsvRecent(_since) {
  // OSV has no paginated "recent by ecosystem" endpoint without iterating all vulns.
  // Rely on GitHub Advisory for recent intel instead.
  return [];
}
