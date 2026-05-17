import { BaseAdapter, AdapterResult } from './base.js';

const GH_API = 'https://api.github.com';
const TIMEOUT = 10000;

export class GitHubAdvisoryAdapter extends BaseAdapter {
  constructor() {
    super('github-advisory');
    this.token = process.env.GITHUB_TOKEN || null;
  }

  available() { return true; }

  get headers() {
    const h = {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    };
    if (this.token) h['Authorization'] = `Bearer ${this.token}`;
    return h;
  }

  async fetch(packages) {
    const results = [];
    const errors = [];
    await Promise.all(packages.map(async (pkg) => {
      try {
        const vulns = await this.withRetry(() => this._graphqlQuery(pkg.name));
        results.push(...vulns);
      } catch (err) {
        errors.push(`${pkg.name}: ${err.message}`);
      }
    }));
    return new AdapterResult({ source: this.name, data: results, errors });
  }

  async _graphqlQuery(packageName) {
    const query = `
      query($pkg: String!) {
        securityVulnerabilities(ecosystem: NPM, package: $pkg, first: 20) {
          nodes {
            advisory {
              ghsaId
              summary
              description
              severity
              cvss { score vectorString }
              cwes(first: 5) { nodes { cweId name } }
              identifiers { type value }
              references { url }
              publishedAt
              updatedAt
            }
            firstPatchedVersion { identifier }
            vulnerableVersionRange
          }
        }
      }
    `;

    const res = await this.fetchWithTimeout(`${GH_API}/graphql`, {
      method: 'POST',
      headers: { ...this.headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, variables: { pkg: packageName } }),
    }, TIMEOUT);

    if (!res.ok) throw new Error(`GitHub GraphQL HTTP ${res.status}`);
    const json = await res.json();
    if (json.errors?.length) throw new Error(json.errors[0].message);

    const nodes = json.data?.securityVulnerabilities?.nodes || [];
    return nodes.map(n => this._normalizeGraphQL(n, packageName));
  }

  _normalizeGraphQL(node, packageName) {
    const adv = node.advisory;
    const cveId = adv.identifiers?.find(i => i.type === 'CVE')?.value || null;
    return {
      id: adv.ghsaId,
      ghsaId: adv.ghsaId,
      cveId,
      title: adv.summary,
      description: adv.description,
      severity: (adv.severity || 'unknown').toLowerCase(),
      cvssScore: adv.cvss?.score ?? null,
      cvssVector: adv.cvss?.vectorString || null,
      cweIds: adv.cwes?.nodes?.map(c => c.cweId) || [],
      packageName,
      vulnerableVersions: node.vulnerableVersionRange,
      patchedVersions: node.firstPatchedVersion?.identifier
        ? `>=${node.firstPatchedVersion.identifier}`
        : null,
      fixVersion: node.firstPatchedVersion?.identifier || null,
      references: adv.references?.map(r => r.url) || [],
      publishedAt: adv.publishedAt,
      modifiedAt: adv.updatedAt,
      source: 'github-advisory',
    };
  }

  async searchRecent(days = 7) {
    const since = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];
    const url = `${GH_API}/advisories?ecosystem=npm&published=>=${since}&per_page=100`;
    const res = await this.withRetry(() =>
      this.fetchWithTimeout(url, { headers: this.headers }, TIMEOUT)
    );
    if (!res.ok) throw new Error(`GitHub advisories HTTP ${res.status}`);
    const json = await res.json();
    return (json || []).map(adv => this._normalizeRest(adv));
  }

  async searchKeyword(query) {
    const url = `${GH_API}/advisories?q=${encodeURIComponent(query)}&ecosystem=npm&per_page=30`;
    const res = await this.withRetry(() =>
      this.fetchWithTimeout(url, { headers: this.headers }, TIMEOUT)
    );
    if (!res.ok) throw new Error(`GitHub advisory search HTTP ${res.status}`);
    const json = await res.json();
    return (json || []).map(adv => this._normalizeRest(adv));
  }

  async getById(id) {
    const res = await this.withRetry(() =>
      this.fetchWithTimeout(`${GH_API}/advisories/${id}`, { headers: this.headers }, TIMEOUT)
    );
    if (!res.ok) throw new Error(`GitHub advisory ${id} HTTP ${res.status}`);
    return this._normalizeRest(await res.json());
  }

  _normalizeRest(adv) {
    const npmVulns = (adv.vulnerabilities || []).filter(v => v.package?.ecosystem === 'npm');
    const firstVuln = npmVulns[0] || {};
    const cveId = (adv.cve_id || adv.identifiers?.find(i => i.type === 'CVE')?.value) || null;
    return {
      id: adv.ghsa_id || adv.id,
      ghsaId: adv.ghsa_id,
      cveId,
      title: adv.summary,
      description: adv.description,
      severity: (adv.severity || 'unknown').toLowerCase(),
      cvssScore: adv.cvss?.score ?? null,
      cvssVector: adv.cvss?.vector_string || null,
      cweIds: (adv.cwes || []).map(c => c.cwe_id),
      packageName: firstVuln.package?.name || null,
      vulnerableVersions: firstVuln.vulnerable_version_range || null,
      patchedVersions: firstVuln.first_patched_version
        ? `>=${firstVuln.first_patched_version}`
        : null,
      fixVersion: firstVuln.first_patched_version || null,
      references: (adv.references || []),
      publishedAt: adv.published_at,
      modifiedAt: adv.updated_at,
      source: 'github-advisory',
    };
  }
}
