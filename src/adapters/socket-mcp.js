import { BaseAdapter, AdapterResult } from './base.js';

const SOCKET_MCP_URL = 'https://mcp.socket.dev/v1/mcp';
const TIMEOUT = 15000;

export class SocketMcpAdapter extends BaseAdapter {
  constructor() {
    super('socket-mcp');
    this.apiKey = process.env.SOCKET_API_KEY || null;
  }

  available() { return true; }

  async fetch(packages) {
    try {
      const data = await this.withRetry(() => this._callDepscore(packages));
      return new AdapterResult({ source: this.name, data });
    } catch (err) {
      return new AdapterResult({ source: this.name, errors: [err.message] });
    }
  }

  async _callDepscore(packages) {
    const pkgList = packages.map(p => ({
      ecosystem: p.ecosystem || 'npm',
      depname: p.name,
      version: p.version || 'latest',
    }));

    const body = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'depscore',
        arguments: { packages: pkgList },
      },
    };

    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
    };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const res = await this.fetchWithTimeout(SOCKET_MCP_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    }, TIMEOUT);

    if (!res.ok) throw new Error(`Socket MCP HTTP ${res.status}`);

    const contentType = res.headers.get('content-type') || '';
    let json;

    if (contentType.includes('text/event-stream')) {
      const text = await res.text();
      json = this._parseSSE(text);
    } else {
      json = await res.json();
    }

    return this._normalize(json, packages);
  }

  _parseSSE(text) {
    const lines = text.split('\n');
    for (const line of lines) {
      if (line.startsWith('data: ')) {
        try {
          return JSON.parse(line.slice(6));
        } catch { continue; }
      }
    }
    throw new Error('No valid JSON in SSE stream');
  }

  _normalize(json, packages) {
    const results = [];
    const content = json?.result?.content || json?.params?.content || [];

    for (const item of content) {
      if (item.type === 'text') {
        try {
          const parsed = JSON.parse(item.text);
          const scores = Array.isArray(parsed) ? parsed : [parsed];
          for (const score of scores) {
            results.push({
              name: score.name || score.package,
              version: score.version,
              socketScore: score.score ?? score.socketScore ?? null,
              supplyChainScore: score.supplyChain ?? score.supply_chain ?? null,
              qualityScore: score.quality ?? null,
              maintenanceScore: score.maintenance ?? null,
              vulnerabilityScore: score.vulnerability ?? null,
              licenseScore: score.license ?? null,
              alerts: score.alerts || [],
              source: 'socket-mcp',
            });
          }
        } catch { continue; }
      }
    }

    // If no structured data returned, return minimal placeholders
    if (!results.length) {
      for (const pkg of packages) {
        results.push({ name: pkg.name, version: pkg.version, source: 'socket-mcp', socketScore: null });
      }
    }

    return results;
  }
}
