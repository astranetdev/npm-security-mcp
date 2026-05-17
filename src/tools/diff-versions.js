import { z } from 'zod';
import { NpmRegistryAdapter } from '../adapters/npm-registry.js';
import { OsvAdapter } from '../adapters/osv.js';
import { formatSources, severityEmoji } from '../utils/format.js';

export const diffVersionsSchema = z.object({
  name: z.string().min(1),
  from_version: z.string().min(1),
  to_version: z.string().min(1),
});

const registry = new NpmRegistryAdapter();
const osv = new OsvAdapter();

export async function diffVersions({ name, from_version, to_version }) {
  const consulted = ['npm-registry', 'OSV'];
  const failed = [];

  const [fromMeta, toMeta, osvResult] = await Promise.all([
    registry.getVersionMetadata(name, from_version).catch(e => { failed.push(`npm-registry(${from_version})`); return null; }),
    registry.getVersionMetadata(name, to_version).catch(e => { failed.push(`npm-registry(${to_version})`); return null; }),
    osv.fetch([
      { name, version: from_version },
      { name, version: to_version },
    ]).catch(() => { failed.push('OSV'); return { data: [] }; }),
  ]);

  if (!fromMeta && !toMeta) {
    return `## Diff Error\n\nCould not fetch metadata for \`${name}\` from npm registry.`;
  }

  const lines = [];
  lines.push(`## Version Diff: \`${name}\` · \`${from_version}\` → \`${to_version}\``);

  // Scripts diff
  const fromScripts = fromMeta?.scripts || {};
  const toScripts = toMeta?.scripts || {};
  const riskyScripts = ['preinstall', 'install', 'postinstall', 'prepack', 'prepare'];
  const newRiskyScripts = riskyScripts.filter(s => toScripts[s] && !fromScripts[s]);
  const changedRiskyScripts = riskyScripts.filter(s => toScripts[s] && fromScripts[s] && toScripts[s] !== fromScripts[s]);
  const removedScripts = Object.keys(fromScripts).filter(s => !toScripts[s]);
  const addedScripts = Object.keys(toScripts).filter(s => !fromScripts[s]);

  if (newRiskyScripts.length) {
    lines.push(`\n### 🚨 NEW INSTALL SCRIPTS (HIGH RISK)`);
    for (const s of newRiskyScripts) {
      lines.push(`\`${s}\`:\n\`\`\`\n${toScripts[s]}\n\`\`\``);
    }
  }
  if (changedRiskyScripts.length) {
    lines.push(`\n### ⚠️ Changed Install Scripts`);
    for (const s of changedRiskyScripts) {
      lines.push(`**${s}:**`);
      lines.push(`- Before: \`${fromScripts[s]}\``);
      lines.push(`- After:  \`${toScripts[s]}\``);
    }
  }
  if (addedScripts.filter(s => !riskyScripts.includes(s)).length) {
    lines.push(`\n**New scripts:** ${addedScripts.filter(s => !riskyScripts.includes(s)).map(s => `\`${s}\``).join(', ')}`);
  }
  if (removedScripts.length) {
    lines.push(`**Removed scripts:** ${removedScripts.map(s => `\`${s}\``).join(', ')}`);
  }
  if (!newRiskyScripts.length && !changedRiskyScripts.length && !addedScripts.length && !removedScripts.length) {
    lines.push(`\n### Scripts\n✅ No script changes`);
  }

  // Maintainers diff
  const fromMaintainers = (fromMeta?.maintainers || []).map(m => m.name || m.email || String(m));
  const toMaintainers = (toMeta?.maintainers || []).map(m => m.name || m.email || String(m));
  const addedMaintainers = toMaintainers.filter(m => !fromMaintainers.includes(m));
  const removedMaintainers = fromMaintainers.filter(m => !toMaintainers.includes(m));

  lines.push(`\n### Maintainers`);
  if (addedMaintainers.length) {
    lines.push(`🚨 **Added:** ${addedMaintainers.join(', ')}`);
  }
  if (removedMaintainers.length) {
    lines.push(`**Removed:** ${removedMaintainers.join(', ')}`);
  }
  if (!addedMaintainers.length && !removedMaintainers.length) {
    lines.push(`✅ No maintainer changes`);
  }

  // Dependencies diff
  const fromDeps = fromMeta?.dependencies || {};
  const toDeps = toMeta?.dependencies || {};
  const addedDeps = Object.entries(toDeps).filter(([k]) => !fromDeps[k]);
  const removedDeps = Object.entries(fromDeps).filter(([k]) => !toDeps[k]);
  const changedDeps = Object.entries(toDeps).filter(([k, v]) => fromDeps[k] && fromDeps[k] !== v);

  lines.push(`\n### Dependencies`);
  if (addedDeps.length) lines.push(`**Added:** ${addedDeps.map(([k, v]) => `\`${k}@${v}\``).join(', ')}`);
  if (removedDeps.length) lines.push(`**Removed:** ${removedDeps.map(([k]) => `\`${k}\``).join(', ')}`);
  if (changedDeps.length) lines.push(`**Updated:** ${changedDeps.map(([k, v]) => `\`${k}\`: \`${fromDeps[k]}\` → \`${v}\``).join(', ')}`);
  if (!addedDeps.length && !removedDeps.length && !changedDeps.length) lines.push(`✅ No dependency changes`);

  // Integrity
  lines.push(`\n### Package Integrity`);
  if (fromMeta?.dist?.integrity) lines.push(`- \`${from_version}\` integrity: \`${fromMeta.dist.integrity}\``);
  if (toMeta?.dist?.integrity) lines.push(`- \`${to_version}\` integrity: \`${toMeta.dist.integrity}\``);

  // Size change
  const fromSize = fromMeta?.dist?.unpackedSize;
  const toSize = toMeta?.dist?.unpackedSize;
  if (fromSize && toSize) {
    const changePct = Math.round((toSize - fromSize) / fromSize * 100);
    const emoji = Math.abs(changePct) > 50 ? '⚠️' : 'ℹ️';
    lines.push(`\n${emoji} **Size change:** ${fromSize.toLocaleString()} → ${toSize.toLocaleString()} bytes (${changePct > 0 ? '+' : ''}${changePct}%)`);
  }

  // Vulnerability advisories
  const osvData = osvResult?.data || [];
  if (osvData.length) {
    lines.push(`\n### Known Advisories`);
    for (const adv of osvData) {
      lines.push(`- ${severityEmoji(adv.severity)} **${adv.id}**: ${adv.title} (affects \`${adv.vulnerableVersions || 'unknown range'}\`)`);
    }
  }

  lines.push(formatSources(consulted, failed));
  return lines.join('\n');
}
