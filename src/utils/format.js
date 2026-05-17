const SEVERITY_EMOJI = {
  critical: '🔴',
  high: '🟠',
  moderate: '🟡',
  medium: '🟡',
  low: '🔵',
  none: '⚪',
  unknown: '❓',
};

export function severityEmoji(severity) {
  return SEVERITY_EMOJI[(severity || '').toLowerCase()] || '❓';
}

export function formatSeverity(severity) {
  const s = (severity || 'unknown').toLowerCase();
  return `${severityEmoji(s)} ${s.charAt(0).toUpperCase() + s.slice(1)}`;
}

export function formatAdvisory(adv) {
  const lines = [];
  lines.push(`### ${severityEmoji(adv.severity)} ${adv.id || 'Unknown ID'}: ${adv.title || 'No title'}`);
  if (adv.summary || adv.description) {
    const text = (adv.summary || adv.description || '').slice(0, 300);
    lines.push(`\n${text}${text.length === 300 ? '...' : ''}`);
  }
  if (adv.packageName) lines.push(`\n**Package:** \`${adv.packageName}\``);
  if (adv.vulnerableVersions) lines.push(`**Vulnerable:** \`${adv.vulnerableVersions}\``);
  if (adv.patchedVersions) lines.push(`**Fixed in:** \`${adv.patchedVersions}\``);
  if (adv.cvssScore) lines.push(`**CVSS:** ${adv.cvssScore}`);
  if (adv.cweIds?.length) lines.push(`**CWE:** ${adv.cweIds.join(', ')}`);
  if (adv.references?.length) {
    lines.push(`\n**References:**`);
    for (const ref of adv.references.slice(0, 3)) {
      lines.push(`- ${ref}`);
    }
  }
  if (adv.sources?.length) lines.push(`\n*Sources: ${adv.sources.join(', ')}*`);
  return lines.join('\n');
}

export function formatTable(headers, rows) {
  const cols = headers.length;
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map(r => String(r[i] || '').length)));
  const sep = widths.map(w => '-'.repeat(w));
  const pad = (s, w) => String(s || '').padEnd(w);
  const row = r => `| ${r.map((c, i) => pad(c, widths[i])).join(' | ')} |`;
  return [row(headers), `| ${sep.join(' | ')} |`, ...rows.map(row)].join('\n');
}

export function formatSources(consulted, failed) {
  const lines = [];
  if (consulted.length) lines.push(`\n---\n**Sources consulted:** ${consulted.join(', ')}`);
  if (failed.length) lines.push(`**Sources failed:** ${failed.join(', ')}`);
  return lines.join('\n');
}

export function summarySeverityBlock(counts) {
  const parts = [];
  if (counts.critical) parts.push(`${severityEmoji('critical')} **${counts.critical} critical**`);
  if (counts.high) parts.push(`${severityEmoji('high')} **${counts.high} high**`);
  if (counts.moderate || counts.medium) parts.push(`${severityEmoji('moderate')} ${(counts.moderate || 0) + (counts.medium || 0)} moderate`);
  if (counts.low) parts.push(`${severityEmoji('low')} ${counts.low} low`);
  return parts.length ? parts.join(' · ') : '✅ No vulnerabilities found';
}
