import { z } from 'zod';
import { OsvAdapter } from '../adapters/osv.js';
import { GitHubAdvisoryAdapter } from '../adapters/github-advisory.js';
import { formatAdvisory, formatSources } from '../utils/format.js';

export const searchAdvisorySchema = z.object({
  query: z.string().min(1).describe('CVE ID, GHSA ID, package name, or keyword'),
});

const osv = new OsvAdapter();
const github = new GitHubAdvisoryAdapter();

export async function searchAdvisory({ query }) {
  const consulted = [];
  const failed = [];
  const advisories = [];

  const isCve = query.startsWith('CVE-');
  const isGhsa = query.startsWith('GHSA-');

  if (isCve || isGhsa) {
    // Direct ID lookup
    if (isGhsa) {
      consulted.push('OSV', 'github-advisory');
      const [osvRaw, ghAdv] = await Promise.all([
        osv.fetchById(query).catch(e => { failed.push('OSV'); return null; }),
        github.getById(query).catch(e => { failed.push('github-advisory'); return null; }),
      ]);
      if (osvRaw) advisories.push(osv._normalize(osvRaw, { name: null }));
      if (ghAdv) advisories.push(ghAdv);
    } else {
      // CVE — search OSV by alias
      consulted.push('OSV');
      try {
        const res = await osv.fetchById(query);
        advisories.push(osv._normalize(res, { name: null }));
      } catch {
        failed.push('OSV');
        // Try GitHub
        consulted.push('github-advisory');
        const ghRes = await github.searchKeyword(query).catch(() => { failed.push('github-advisory'); return []; });
        advisories.push(...ghRes.filter(a => a.cveId === query));
      }
    }
  } else if (/^[a-z0-9@._/-]+$/i.test(query) && !query.includes(' ')) {
    // Package name lookup
    consulted.push('OSV', 'github-advisory');
    const [osvResult, ghResult] = await Promise.all([
      osv.fetch([{ name: query }]).catch(() => { failed.push('OSV'); return { data: [] }; }),
      github.fetch([{ name: query }]).catch(() => { failed.push('github-advisory'); return { data: [] }; }),
    ]);
    advisories.push(...(osvResult.data || []));
    advisories.push(...(ghResult.data || []));
  } else {
    // Keyword search
    consulted.push('github-advisory');
    const ghResult = await github.searchKeyword(query).catch(() => { failed.push('github-advisory'); return []; });
    advisories.push(...ghResult);
  }

  if (!advisories.length) {
    return `## Advisory Search: \`${query}\`\n\nNo advisories found.${formatSources(consulted, failed)}`;
  }

  // Deduplicate by ID
  const seen = new Set();
  const unique = [];
  for (const adv of advisories) {
    const id = adv.id || adv.ghsaId || adv.cveId;
    if (id && !seen.has(id)) { seen.add(id); unique.push(adv); }
    else if (!id) unique.push(adv);
  }

  const lines = [];
  lines.push(`## Advisory Search: \`${query}\`\n\n**Found:** ${unique.length} advisory/advisories\n`);
  for (const adv of unique) {
    lines.push(formatAdvisory(adv));
    lines.push('');
  }
  lines.push(formatSources(consulted, failed));
  return lines.join('\n');
}
