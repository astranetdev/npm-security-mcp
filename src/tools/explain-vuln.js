import { z } from 'zod';
import { OsvAdapter } from '../adapters/osv.js';
import { GitHubAdvisoryAdapter } from '../adapters/github-advisory.js';
import { formatSources, severityEmoji } from '../utils/format.js';

export const explainVulnSchema = z.object({
  id: z.string().min(1).describe('CVE ID or GHSA ID'),
});

const osv = new OsvAdapter();
const github = new GitHubAdvisoryAdapter();

const CVSS_METRICS = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', R: 'Required' },
  S: { U: 'Unchanged', C: 'Changed' },
  C: { N: 'None', L: 'Low', H: 'High' },
  I: { N: 'None', L: 'Low', H: 'High' },
  A: { N: 'None', L: 'Low', H: 'High' },
};

function parseCvssVector(vector) {
  if (!vector) return null;
  const parts = vector.split('/').slice(1); // skip CVSS:3.x
  const result = {};
  for (const part of parts) {
    const [k, v] = part.split(':');
    result[k] = { code: v, label: CVSS_METRICS[k]?.[v] || v };
  }
  return result;
}

export async function explainVuln({ id }) {
  const consulted = [];
  const failed = [];
  let osvRaw = null;
  let ghAdv = null;

  const isGhsa = id.startsWith('GHSA-');

  await Promise.all([
    osv.fetchById(id).then(r => { consulted.push('OSV'); osvRaw = r; }).catch(() => { failed.push('OSV'); }),
    (isGhsa ? github.getById(id).then(r => { consulted.push('github-advisory'); ghAdv = r; }) : Promise.resolve())
      .catch(() => { if (isGhsa) failed.push('github-advisory'); }),
  ]);

  if (!osvRaw && !ghAdv) {
    return `## ${id}\n\nNo advisory data found.${formatSources(consulted, failed)}`;
  }

  const adv = osvRaw ? osv._normalize(osvRaw, { name: null }) : ghAdv;
  const cvssVector = ghAdv?.cvssVector || adv.cvssVector || null;
  const cvssMetrics = parseCvssVector(cvssVector);

  // Extract PoC references
  const allRefs = [...(adv.references || []), ...(ghAdv?.references || [])];
  const pocRefs = allRefs.filter(r =>
    typeof r === 'string' &&
    (r.includes('proof-of-concept') || r.includes('exploit') || r.includes('poc') || r.includes('demo'))
  );

  const lines = [];
  lines.push(`## ${severityEmoji(adv.severity)} ${adv.id}: ${adv.title}`);
  lines.push(`\n**Severity:** ${adv.severity?.toUpperCase() || 'Unknown'}${adv.cvssScore ? ` (CVSS ${adv.cvssScore})` : ''}`);
  if (adv.packageName) lines.push(`**Package:** \`${adv.packageName}\``);
  if (adv.aliases?.length) lines.push(`**Also known as:** ${adv.aliases.join(', ')}`);
  lines.push('');

  // Simple explanation
  lines.push(`### What is this vulnerability?`);
  const desc = adv.description || osvRaw?.details || 'No description available.';
  lines.push(desc.slice(0, 1000) + (desc.length > 1000 ? '...' : ''));
  lines.push('');

  // Attack vector
  lines.push(`### Attack Vector`);
  if (cvssMetrics) {
    const av = cvssMetrics.AV?.label;
    const ac = cvssMetrics.AC?.label;
    const pr = cvssMetrics.PR?.label;
    const ui = cvssMetrics.UI?.label;
    if (av) lines.push(`- **Access:** ${av} (can be exploited ${av === 'Network' ? 'remotely over the internet' : av === 'Local' ? 'with local system access' : 'via adjacent network'})`);
    if (ac) lines.push(`- **Complexity:** ${ac}`);
    if (pr) lines.push(`- **Privileges required:** ${pr}`);
    if (ui) lines.push(`- **User interaction:** ${ui}`);
  } else {
    lines.push('CVSS vector not available for detailed breakdown.');
  }
  lines.push('');

  // CVSS breakdown
  if (cvssMetrics && adv.cvssScore) {
    lines.push(`### CVSS ${adv.cvssScore} Breakdown`);
    if (cvssVector) lines.push(`\`${cvssVector}\``);
    const impact = [cvssMetrics.C, cvssMetrics.I, cvssMetrics.A]
      .map((m, i) => `${['Confidentiality', 'Integrity', 'Availability'][i]}: **${m?.label || 'N/A'}**`)
      .join(' · ');
    lines.push(`\n**Impact:** ${impact}`);
    lines.push('');
  }

  // Mitigation
  lines.push(`### Mitigation`);
  if (adv.patchedVersions) {
    lines.push(`✅ **Fix available:** Upgrade to \`${adv.patchedVersions}\``);
    if (adv.fixVersion) lines.push(`**Minimum safe version:** \`${adv.fixVersion}\``);
  } else if (adv.vulnerableVersions) {
    lines.push(`⚠️ **Vulnerable range:** \`${adv.vulnerableVersions}\``);
    lines.push('No patch version identified. Check the advisory for workarounds.');
  }
  lines.push('');

  // PoC references (only if public)
  if (pocRefs.length) {
    lines.push(`### Public PoC / References`);
    lines.push(`> These are publicly available — not generated content.`);
    for (const ref of pocRefs.slice(0, 3)) lines.push(`- ${ref}`);
    lines.push('');
  }

  // All references
  const uniqueRefs = [...new Set(allRefs.filter(r => typeof r === 'string'))];
  if (uniqueRefs.length) {
    lines.push(`### References`);
    for (const ref of uniqueRefs.slice(0, 8)) lines.push(`- ${ref}`);
  }

  lines.push(formatSources(consulted, failed));
  return lines.join('\n');
}
