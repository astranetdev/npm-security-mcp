import { BaseAdapter, AdapterResult } from './base.js';
import { isVulnerable, extractFixVersion } from '../utils/semver-check.js';

const BULK_URL = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk';
const TIMEOUT = 10000;

export class NpmBulkAdvisoryAdapter extends BaseAdapter {
  constructor() {
    super('npm-advisory');
  }

  available() { return true; }

  async fetch(packages) {
    try {
      const data = await this.withRetry(() => this._fetchBulk(packages));
      return new AdapterResult({ source: this.name, data });
    } catch (err) {
      return new AdapterResult({ source: this.name, errors: [err.message] });
    }
  }

  async _fetchBulk(packages) {
    // Build body: { "pkg-name": ["version1", "version2"] }
    const body = {};
    for (const pkg of packages) {
      if (!body[pkg.name]) body[pkg.name] = [];
      if (pkg.version && !body[pkg.name].includes(pkg.version)) {
        body[pkg.name].push(pkg.version);
      }
    }

    const res = await this.fetchWithTimeout(BULK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }, TIMEOUT);

    if (!res.ok) throw new Error(`npm advisory bulk HTTP ${res.status}`);
    const json = await res.json();

    const results = [];
    for (const [pkgName, advisories] of Object.entries(json)) {
      for (const adv of advisories) {
        const installedVersion = body[pkgName]?.[0];
        const vulnerable = installedVersion
          ? isVulnerable(installedVersion, adv.vulnerable_versions)
          : true;

        results.push({
          id: adv.github_advisory_id || String(adv.id),
          npmId: adv.id,
          ghsaId: adv.github_advisory_id || null,
          cveId: adv.cve || null,
          title: adv.title,
          severity: (adv.severity || 'unknown').toLowerCase(),
          packageName: pkgName,
          vulnerableVersions: adv.vulnerable_versions,
          patchedVersions: adv.patched_versions,
          fixVersion: extractFixVersion(adv.patched_versions),
          cweIds: adv.cwe ? [adv.cwe] : [],
          url: adv.url,
          references: adv.url ? [adv.url] : [],
          isVulnerable: vulnerable,
          source: 'npm-advisory',
        });
      }
    }
    return results;
  }
}
