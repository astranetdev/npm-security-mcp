import { BaseAdapter, AdapterResult } from './base.js';

const REGISTRY = 'https://registry.npmjs.org';
const TIMEOUT_PKG = 10000;

export class NpmRegistryAdapter extends BaseAdapter {
  constructor() {
    super('npm-registry');
  }

  available() { return true; }

  async fetch(packages) {
    const results = [];
    const errors = [];
    await Promise.all(packages.map(async (pkg) => {
      try {
        const data = await this.withRetry(() => this.getPackage(pkg.name, pkg.version));
        results.push(data);
      } catch (err) {
        errors.push(`${pkg.name}: ${err.message}`);
      }
    }));
    return new AdapterResult({ source: this.name, data: results, errors });
  }

  async getPackage(name, version) {
    const url = version
      ? `${REGISTRY}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`
      : `${REGISTRY}/${encodeURIComponent(name)}`;

    const res = await this.fetchWithTimeout(url, {
      headers: { 'Accept': 'application/json' },
    }, TIMEOUT_PKG);

    if (!res.ok) throw new Error(`npm registry HTTP ${res.status} for ${name}`);
    return await res.json();
  }

  async getLatestVersion(name) {
    const data = await this.getPackage(name);
    return data['dist-tags']?.latest || null;
  }

  async getVersionMetadata(name, version) {
    const data = await this.getPackage(name, version);
    return {
      name,
      version,
      scripts: data.scripts || {},
      dependencies: data.dependencies || {},
      devDependencies: data.devDependencies || {},
      maintainers: data.maintainers || [],
      dist: data.dist || {},
      publishedAt: data.time?.[version] || null,
      description: data.description,
      license: data.license,
      repository: data.repository,
    };
  }

  async searchByMaintainer(username) {
    const url = `${REGISTRY}/-/v1/search?text=maintainer:${encodeURIComponent(username)}&size=250`;
    const res = await this.fetchWithTimeout(url, {
      headers: { 'Accept': 'application/json' },
    }, TIMEOUT_PKG);
    if (!res.ok) throw new Error(`npm search HTTP ${res.status}`);
    const json = await res.json();
    return json.objects || [];
  }

  extractRiskSignals(pkgData, version) {
    const versionData = version ? pkgData : null;
    const scripts = versionData?.scripts || pkgData?.versions?.[Object.keys(pkgData.versions || {}).pop()]?.scripts || {};
    const signals = [];

    const riskyScripts = ['preinstall', 'install', 'postinstall', 'prepack', 'prepare'];
    for (const s of riskyScripts) {
      if (scripts[s]) {
        signals.push({ type: 'install-script', severity: 'high', detail: `${s}: ${scripts[s].slice(0, 100)}` });
      }
    }

    const maintainers = pkgData.maintainers || [];
    if (maintainers.length === 1) {
      signals.push({ type: 'single-maintainer', severity: 'low', detail: `Only 1 maintainer: ${maintainers[0]?.name}` });
    }

    return signals;
  }
}
