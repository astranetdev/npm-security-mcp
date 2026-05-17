import { z } from 'zod';
import { NpmRegistryAdapter } from '../adapters/npm-registry.js';
import { GitHubAdvisoryAdapter } from '../adapters/github-advisory.js';
import { formatTable, formatSources, severityEmoji } from '../utils/format.js';

export const checkMaintainerSchema = z.object({
  username: z.string().min(1).describe('npm username'),
});

const registry = new NpmRegistryAdapter();
const github = new GitHubAdvisoryAdapter();

export async function checkMaintainer({ username }) {
  const consulted = ['npm-registry'];
  const failed = [];

  let packages = [];
  try {
    const results = await registry.searchByMaintainer(username);
    packages = results.map(r => ({
      name: r.package?.name,
      version: r.package?.version,
      description: r.package?.description,
      date: r.package?.date,
      downloads: r.downloads?.monthly,
    })).filter(p => p.name);
  } catch (err) {
    failed.push('npm-registry');
  }

  const now = Date.now();
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

  // Fetch metadata for each package to check install scripts
  const detailedPackages = await Promise.all(
    packages.slice(0, 50).map(async (p) => {
      try {
        const meta = await registry.getPackage(p.name);
        const latestVersion = meta['dist-tags']?.latest;
        const latestMeta = latestVersion ? meta.versions?.[latestVersion] : null;
        const scripts = latestMeta?.scripts || {};
        const riskyScripts = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack'];
        const hasInstallScript = riskyScripts.some(s => scripts[s]);
        const publishDate = meta.time?.[latestVersion];
        const isRecent = publishDate && (now - new Date(publishDate).getTime() < sevenDaysMs);
        return { ...p, hasInstallScript, publishDate, isRecent, latestVersion };
      } catch {
        return { ...p, hasInstallScript: false, isRecent: false };
      }
    })
  );

  // Risk scoring
  let riskScore = 0;
  const riskFactors = [];

  if (packages.length > 50) {
    riskScore += 30;
    riskFactors.push(`🚨 Maintains **${packages.length}** packages (>50 — high impact attack surface)`);
  } else if (packages.length > 20) {
    riskScore += 10;
    riskFactors.push(`⚠️ Maintains **${packages.length}** packages`);
  }

  const recentPackages = detailedPackages.filter(p => p.isRecent);
  if (recentPackages.length > 3) {
    riskScore += 25;
    riskFactors.push(`🚨 **${recentPackages.length}** packages published in last 7 days`);
  }

  const installScriptPackages = detailedPackages.filter(p => p.hasInstallScript);
  if (installScriptPackages.length > 0) {
    riskScore += 20;
    riskFactors.push(`⚠️ **${installScriptPackages.length}** packages have install scripts`);
  }

  // GitHub advisories if token available
  let ghAdvisories = [];
  if (github.token) {
    consulted.push('github-advisory');
    ghAdvisories = await github.searchKeyword(username).catch(() => { failed.push('github-advisory'); return []; });
  }

  const lines = [];
  lines.push(`## Maintainer Report: \`${username}\``);
  lines.push(`\n**Risk Score:** ${Math.min(riskScore, 100)}/100\n`);

  if (riskFactors.length) {
    lines.push(`### Risk Factors`);
    for (const f of riskFactors) lines.push(`- ${f}`);
    lines.push('');
  }

  lines.push(`### Packages (${packages.length} total)\n`);

  if (detailedPackages.length) {
    const rows = detailedPackages.slice(0, 30).map(p => [
      `\`${p.name}\``,
      p.latestVersion || p.version || '—',
      p.publishDate ? new Date(p.publishDate).toISOString().split('T')[0] : '—',
      p.hasInstallScript ? '⚠️ yes' : 'no',
    ]);
    lines.push(formatTable(['Package', 'Latest', 'Published', 'Install Script'], rows));
    if (detailedPackages.length > 30) {
      lines.push(`\n*...and ${detailedPackages.length - 30} more packages*`);
    }
  } else {
    lines.push('No packages found.');
  }

  if (ghAdvisories.length) {
    lines.push(`\n### Related Advisories (GitHub)`);
    for (const adv of ghAdvisories.slice(0, 5)) {
      lines.push(`- ${severityEmoji(adv.severity)} **${adv.id}**: ${adv.title}`);
    }
  }

  lines.push(formatSources(consulted, failed));
  return lines.join('\n');
}
