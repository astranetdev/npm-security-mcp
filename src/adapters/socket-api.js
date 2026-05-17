import { BaseAdapter, AdapterResult } from './base.js';

const SOCKET_API_URL = 'https://api.socket.dev/v0/purl';
const TIMEOUT = 15000;

export class SocketApiAdapter extends BaseAdapter {
  constructor() {
    super('socket-api');
    this.apiKey = process.env.SOCKET_API_KEY || null;
  }

  available() {
    return !!this.apiKey;
  }

  async fetch(packages) {
    if (!this.available()) {
      return new AdapterResult({ source: this.name, errors: ['SOCKET_API_KEY not set'] });
    }
    try {
      const data = await this.withRetry(() => this._fetchPurl(packages));
      return new AdapterResult({ source: this.name, data });
    } catch (err) {
      return new AdapterResult({ source: this.name, errors: [err.message] });
    }
  }

  async _fetchPurl(packages) {
    const components = packages.map(p => ({
      purl: `pkg:npm/${encodeURIComponent(p.name)}${p.version ? `@${p.version}` : ''}`,
    }));

    const res = await this.fetchWithTimeout(
      `${SOCKET_API_URL}?alerts=true&compact=false`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({ components }),
      },
      TIMEOUT
    );

    if (!res.ok) throw new Error(`Socket API HTTP ${res.status}`);
    const json = await res.json();
    return this._normalize(json, packages);
  }

  _normalize(json, packages) {
    const results = [];
    const items = json.results || json.data || (Array.isArray(json) ? json : []);

    for (const item of items) {
      const pkg = item.purl || '';
      const nameMatch = pkg.match(/pkg:npm\/([^@]+)@?(.*)/);
      results.push({
        name: nameMatch?.[1] || item.name,
        version: nameMatch?.[2] || item.version,
        socketScore: item.score?.overall ?? null,
        supplyChainScore: item.score?.supplyChain ?? null,
        qualityScore: item.score?.quality ?? null,
        maintenanceScore: item.score?.maintenance ?? null,
        vulnerabilityScore: item.score?.vulnerability ?? null,
        licenseScore: item.score?.license ?? null,
        alerts: item.alerts || [],
        source: 'socket-api',
      });
    }

    if (!results.length) {
      for (const pkg of packages) {
        results.push({ name: pkg.name, version: pkg.version, source: 'socket-api', socketScore: null });
      }
    }

    return results;
  }
}
