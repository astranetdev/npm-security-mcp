import { z } from 'zod';
import { OsvAdapter } from '../adapters/osv.js';
import { NpmBulkAdvisoryAdapter } from '../adapters/npm-bulk-advisory.js';
import { dedupAdvisories } from '../utils/dedup.js';
import { isVulnerable, extractFixVersion } from '../utils/semver-check.js';
import { formatTable, formatSources, summarySeverityBlock, severityEmoji } from '../utils/format.js';
import { stateManager } from '../state/manager.js';

export const scanLockfileSchema = z.object({
  content: z.string().min(1).describe('Contents of package-lock.json'),
});

const osv = new OsvAdapter();
const npmAdvisory = new NpmBulkAdvisoryAdapter();

function parseLockfile(content) {
  let lock;
  try {
    lock = JSON.parse(content);
  } catch {
    throw new Error('Invalid JSON in lockfile');
  }

  const packages = [];
  const directDeps = new Set([
    ...Object.keys(lock.dependencies || {}),
    ...Object.keys(lock.packages?.['']?.dependencies || {}),
    ...Object.keys(lock.packages?.['']?.devDependencies || {}),
  ]);

  // lockfileVersion 2 and 3: use "packages" key
  if (lock.packages) {
    for (const [path, meta] of Object.entries(lock.packages)) {
      if (!path || path === '') continue; // root
      if (meta.link) continue; // symlinks
      const name = meta.name || path.replace(/^node_modules\//, '').replace(/\/node_modules\//g, '/');
      const version = meta.version;
      if (!name || !version) continue;
      packages.push({
        name,
        version,
        isDirect: directDeps.has(name),
        path,
      });
    }
  } else if (lock.dependencies) {
    // lockfileVersion 1 fallback
    function extractV1(deps, depth = 0) {
      for (const [name, meta] of Object.entries(deps || {})) {
        packages.push({ name, version: meta.version, isDirect: depth === 0 });
        if (meta.dependencies) extractV1(meta.dependencies, depth + 1);
      }
    }
    extractV1(lock.dependencies);
  }

  return packages;
}

export async function scanLockfile({ content }) {
  let packages;
  try {
    packages = parseLockfile(content);
  } catch (err) {
    return `## Lockfile Scan Error\n\n${err.message}`;
  }

  if (!packages.length) return '## Lockfile Scan\n\nNo packages found in lockfile.';

  const consulted = [];
  const failed = [];

  const [osvResult, npmResult] = await Promise.all([
    osv.fetch(packages).then(r => { consulted.push('OSV'); if (!r.ok) failed.push('OSV'); return r; }),
    npmAdvisory.fetch(packages).then(r => { consulted.push('npm-advisory'); if (!r.ok) failed.push('npm-advisory'); return r; }),
  ]);

  // Map advisories to packages
  const pkgMap = new Map(packages.map(p => [p.name, p]));
  const vulnMap = new Map();

  const allAdvisories = dedupAdvisories([
    osvResult.data || [],
    (npmResult.data || []).filter(a => a.isVulnerable !== false),
  ]);

  for (const adv of allAdvisories) {
    const pkg = pkgMap.get(adv.packageName);
    if (!pkg) continue;
    const installed = pkg.version;
    if (adv.vulnerableVersions && !isVulnerable(installed, adv.vulnerableVersions)) continue;

    if (!vulnMap.has(adv.packageName)) vulnMap.set(adv.packageName, []);
    vulnMap.get(adv.packageName).push(adv);
  }

  // Count by severity
  const counts = { critical: 0, high: 0, moderate: 0, low: 0 };
  const worstSeverity = (advs) => {
    const order = ['critical', 'high', 'moderate', 'low', 'unknown'];
    for (const s of order) {
      if (advs.some(a => (a.severity || '').toLowerCase() === s)) return s;
    }
    return 'unknown';
  };

  for (const advs of vulnMap.values()) {
    const sev = worstSeverity(advs);
    if (sev in counts) counts[sev]++;
  }

  await stateManager.addScanHistory('lockfile', `${packages.length} packages`, counts).catch(() => {});

  const lines = [];
  lines.push(`## Lockfile Security Scan`);
  lines.push(`\n**Total packages scanned:** ${packages.length} (${packages.filter(p => p.isDirect).length} direct, ${packages.filter(p => !p.isDirect).length} transitive)\n`);
  lines.push(summarySeverityBlock(counts));

  if (vulnMap.size === 0) {
    lines.push(`\n\n✅ No vulnerable packages found.`);
  } else {
    lines.push(`\n\n### Vulnerable Packages (${vulnMap.size})\n`);
    const rows = [];
    for (const [pkgName, advs] of [...vulnMap.entries()].sort()) {
      const pkg = pkgMap.get(pkgName);
      const sev = worstSeverity(advs);
      const fix = advs.map(a => a.fixVersion || extractFixVersion(a.patchedVersions)).filter(Boolean)[0] || '—';
      rows.push([
        `\`${pkgName}\``,
        pkg.version,
        advs.length.toString(),
        `${severityEmoji(sev)} ${sev}`,
        fix,
        pkg.isDirect ? 'direct' : 'transitive',
      ]);
    }
    lines.push(formatTable(
      ['Package', 'Installed', 'Advisories', 'Worst Severity', 'Fix', 'Type'],
      rows
    ));

    lines.push(`\n### Advisory Details\n`);
    for (const [, advs] of vulnMap.entries()) {
      for (const adv of advs) {
        lines.push(`**${adv.id}** (${adv.packageName}): ${adv.title} — ${severityEmoji(adv.severity)} ${adv.severity}`);
        if (adv.patchedVersions) lines.push(`  Fix: \`${adv.patchedVersions}\``);
      }
    }
  }

  lines.push(formatSources(consulted, failed));
  return lines.join('\n');
}
