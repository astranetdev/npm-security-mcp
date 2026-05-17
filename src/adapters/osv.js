import { BaseAdapter, AdapterResult } from './base.js';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';
const BATCH_SIZE = 1000;
const TIMEOUT = 10000;

export class OsvAdapter extends BaseAdapter {
  constructor() {
    super('OSV');
  }

  available() { return true; }

  async fetch(packages) {
    try {
      const results = await this.withRetry(() => this._fetchBatched(packages));
      return new AdapterResult({ source: this.name, data: results });
    } catch (err) {
      return new AdapterResult({ source: this.name, errors: [err.message] });
    }
  }

  async _fetchBatched(packages) {
    const all = [];
    for (let i = 0; i < packages.length; i += BATCH_SIZE) {
      const chunk = packages.slice(i, i + BATCH_SIZE);
      const queries = chunk.map(p => ({
        package: { name: p.name, ecosystem: 'npm' },
        ...(p.version ? { version: p.version } : {}),
      }));

      const res = await this.fetchWithTimeout(OSV_BATCH_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries }),
      }, TIMEOUT);

      if (!res.ok) throw new Error(`OSV querybatch HTTP ${res.status}`);
      const json = await res.json();

      const results = json.results || [];
      for (let j = 0; j < results.length; j++) {
        const pkg = chunk[j];
        const vulns = results[j]?.vulns || [];
        for (const v of vulns) {
          all.push(this._normalize(v, pkg));
        }
      }
    }
    return all;
  }

  async fetchById(id) {
    const res = await this.withRetry(() =>
      this.fetchWithTimeout(`${OSV_VULN_URL}/${id}`, {}, TIMEOUT)
    );
    if (!res.ok) throw new Error(`OSV vulns/${id} HTTP ${res.status}`);
    return await res.json();
  }

  _normalize(vuln, pkg) {
    const severity = this._extractSeverity(vuln);
    const { vulnerable, patched } = this._extractVersionRanges(vuln, pkg?.name);
    const aliases = vuln.aliases || [];
    const cveId = aliases.find(a => a.startsWith('CVE-'));
    const ghsaId = aliases.find(a => a.startsWith('GHSA-'));

    return {
      id: vuln.id,
      cveId: cveId || null,
      ghsaId: ghsaId || null,
      aliases,
      title: vuln.summary || vuln.id,
      description: vuln.details,
      severity,
      cvssScore: this._extractCvss(vuln),
      cweIds: this._extractCwe(vuln),
      packageName: pkg?.name,
      vulnerableVersions: vulnerable,
      patchedVersions: patched,
      references: (vuln.references || []).map(r => r.url).filter(Boolean),
      publishedAt: vuln.published,
      modifiedAt: vuln.modified,
      source: 'OSV',
    };
  }

  _extractSeverity(vuln) {
    if (vuln.severity?.length) {
      for (const s of vuln.severity) {
        if (s.type === 'CVSS_V3' || s.type === 'CVSS_V2') {
          return this._cvssToSeverity(s.score);
        }
      }
    }
    if (vuln.database_specific?.severity) {
      return vuln.database_specific.severity.toLowerCase();
    }
    return 'unknown';
  }

  _extractCvss(vuln) {
    for (const s of vuln.severity || []) {
      if (s.type === 'CVSS_V3') {
        const match = s.score.match(/\/(\d+\.\d+)$/);
        if (match) return parseFloat(match[1]);
      }
    }
    return null;
  }

  _extractCwe(vuln) {
    const cwes = [];
    for (const affected of vuln.affected || []) {
      const cwe = affected.database_specific?.cwes || [];
      cwes.push(...cwe.map(c => c.cweId || c));
    }
    return [...new Set(cwes)];
  }

  _cvssToSeverity(score) {
    const match = score.match(/\/(\d+\.\d+)$/);
    if (!match) return 'unknown';
    const v = parseFloat(match[1]);
    if (v >= 9.0) return 'critical';
    if (v >= 7.0) return 'high';
    if (v >= 4.0) return 'moderate';
    if (v > 0) return 'low';
    return 'none';
  }

  _extractVersionRanges(vuln, pkgName) {
    for (const affected of vuln.affected || []) {
      if (affected.package?.name !== pkgName && pkgName) continue;
      const ranges = affected.ranges || [];
      const events = ranges.flatMap(r => r.events || []);
      let introduced = null, fixed = null;
      for (const e of events) {
        if (e.introduced && e.introduced !== '0') introduced = e.introduced;
        if (e.fixed) fixed = e.fixed;
      }
      const vulnerable = introduced
        ? fixed ? `>=${introduced} <${fixed}` : `>=${introduced}`
        : fixed ? `<${fixed}` : null;
      const patched = fixed ? `>=${fixed}` : null;
      return { vulnerable, patched };
    }
    return { vulnerable: null, patched: null };
  }
}
