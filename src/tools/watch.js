import { z } from 'zod';
import { createHash } from 'node:crypto';
import { NpmRegistryAdapter } from '../adapters/npm-registry.js';
import { OsvAdapter } from '../adapters/osv.js';
import { stateManager } from '../state/manager.js';
import { formatTable, severityEmoji } from '../utils/format.js';

export const watchAddSchema = z.object({ name: z.string().min(1) });
export const watchRemoveSchema = z.object({ name: z.string().min(1) });
export const watchListSchema = z.object({});
export const watchCheckSchema = z.object({ name: z.string().optional() });

const registry = new NpmRegistryAdapter();
const osv = new OsvAdapter();

function hashScripts(scripts) {
  return createHash('sha256').update(JSON.stringify(scripts || {})).digest('hex').slice(0, 16);
}

export async function watchAdd({ name }) {
  try {
    const pkgData = await registry.getPackage(name);
    const latest = pkgData['dist-tags']?.latest;
    const versionMeta = latest ? pkgData.versions?.[latest] : null;
    const maintainers = (pkgData.maintainers || []).map(m => m.name || m.email || String(m));
    const scripts = versionMeta?.scripts || {};

    await stateManager.watchAdd(name, latest, maintainers, hashScripts(scripts));
    return `## Watch Added: \`${name}\`\n\n- **Latest version:** ${latest || 'unknown'}\n- **Maintainers:** ${maintainers.join(', ') || 'unknown'}\n- **Install scripts:** ${['preinstall','install','postinstall'].filter(s => scripts[s]).join(', ') || 'none'}\n\nPackage is now being monitored. Run \`watch_check\` to check for changes.`;
  } catch (err) {
    return `## Error\n\nFailed to add \`${name}\` to watchlist: ${err.message}`;
  }
}

export async function watchRemove({ name }) {
  const watchlist = await stateManager.watchList();
  if (!watchlist[name]) {
    return `\`${name}\` is not in the watchlist.`;
  }
  await stateManager.watchRemove(name);
  return `✅ Removed \`${name}\` from watchlist.`;
}

export async function watchList() {
  const watchlist = await stateManager.watchList();
  const entries = Object.entries(watchlist);
  if (!entries.length) {
    return '## Watchlist\n\nNo packages are being monitored. Use `watch_add` to start watching a package.';
  }
  const rows = entries.map(([name, meta]) => [
    `\`${name}\``,
    meta.lastVersion || '—',
    meta.lastCheck ? new Date(meta.lastCheck).toISOString().split('T')[0] : '—',
    meta.addedAt ? new Date(meta.addedAt).toISOString().split('T')[0] : '—',
  ]);
  return `## Watchlist (${entries.length} packages)\n\n${formatTable(['Package', 'Last Version', 'Last Check', 'Added'], rows)}`;
}

export async function watchCheck({ name }) {
  const watchlist = await stateManager.watchList();
  const toCheck = name
    ? (watchlist[name] ? { [name]: watchlist[name] } : {})
    : watchlist;

  if (!Object.keys(toCheck).length) {
    return name
      ? `\`${name}\` is not in the watchlist.`
      : '## Watch Check\n\nNo packages in watchlist.';
  }

  const lines = [];
  lines.push(`## Watch Check Report\n`);
  const checkTime = new Date().toISOString();

  for (const [pkgName, meta] of Object.entries(toCheck)) {
    const changes = [];
    lines.push(`### \`${pkgName}\``);

    try {
      const pkgData = await registry.getPackage(pkgName);
      const latest = pkgData['dist-tags']?.latest;
      const versionMeta = latest ? pkgData.versions?.[latest] : null;
      const currentMaintainers = (pkgData.maintainers || []).map(m => m.name || m.email || String(m));
      const scripts = versionMeta?.scripts || {};
      const currentScriptHash = hashScripts(scripts);

      // Version change
      if (latest && latest !== meta.lastVersion) {
        changes.push(`📦 **New version:** \`${meta.lastVersion}\` → \`${latest}\``);

        // Auto diff
        if (meta.lastVersion) {
          const oldMeta = await registry.getVersionMetadata(pkgName, meta.lastVersion).catch(() => null);
          const newMeta = await registry.getVersionMetadata(pkgName, latest).catch(() => null);
          if (oldMeta && newMeta) {
            const riskyScripts = ['preinstall', 'install', 'postinstall'];
            const newRisky = riskyScripts.filter(s => newMeta.scripts?.[s] && !oldMeta.scripts?.[s]);
            if (newRisky.length) {
              changes.push(`  🚨 **NEW install scripts in ${latest}:** ${newRisky.join(', ')}`);
              for (const s of newRisky) {
                changes.push(`  \`${s}\`: \`${newMeta.scripts[s].slice(0, 100)}\``);
              }
            }
          }
        }
      } else {
        changes.push(`✅ Version unchanged: \`${latest}\``);
      }

      // Maintainer change
      const prevMaintainers = meta.lastMaintainers || [];
      const addedM = currentMaintainers.filter(m => !prevMaintainers.includes(m));
      const removedM = prevMaintainers.filter(m => !currentMaintainers.includes(m));
      if (addedM.length) changes.push(`🚨 **New maintainers:** ${addedM.join(', ')}`);
      if (removedM.length) changes.push(`⚠️ **Removed maintainers:** ${removedM.join(', ')}`);

      // Script hash change
      if (meta.scriptHash && currentScriptHash !== meta.scriptHash) {
        changes.push(`⚠️ **Install scripts changed** (hash: ${meta.scriptHash} → ${currentScriptHash})`);
      }

      // New advisories since lastCheck
      const osvResult = await osv.fetch([{ name: pkgName, version: latest }]).catch(() => ({ data: [] }));
      const newAdvs = (osvResult.data || []).filter(adv => {
        if (!meta.lastCheck || !adv.publishedAt) return true;
        return new Date(adv.publishedAt) > new Date(meta.lastCheck);
      });
      if (newAdvs.length) {
        changes.push(`🔴 **${newAdvs.length} new advisory/advisories since last check:**`);
        for (const adv of newAdvs.slice(0, 3)) {
          changes.push(`  - ${severityEmoji(adv.severity)} ${adv.id}: ${adv.title}`);
        }
      }

      // Update state
      await stateManager.watchUpdate(pkgName, {
        lastVersion: latest,
        lastCheck: checkTime,
        lastMaintainers: currentMaintainers,
        scriptHash: currentScriptHash,
      });

    } catch (err) {
      changes.push(`❌ Error checking: ${err.message}`);
    }

    for (const c of changes) lines.push(c);
    lines.push('');
  }

  lines.push(`*Checked at: ${checkTime}*`);
  return lines.join('\n');
}
