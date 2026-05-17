import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';

const SCAN_HISTORY_LIMIT = 100;
const VULN_CACHE_TTL_MS = 60 * 60 * 1000;       // 1 hour
const META_CACHE_TTL_MS = 15 * 60 * 1000;        // 15 minutes

function getStatePath() {
  const base = process.env.NPM_SECURITY_STATE
    ? process.env.NPM_SECURITY_STATE
    : join(homedir(), '.npm-security-mcp');
  return join(base, 'state.json');
}

const DEFAULT_STATE = {
  watchlist: {},
  scanHistory: [],
  cache: {},
};

export class StateManager {
  constructor() {
    this._path = getStatePath();
    this._state = null;
  }

  async load() {
    if (this._state) return this._state;
    try {
      const raw = await readFile(this._path, 'utf8');
      this._state = JSON.parse(raw);
    } catch (err) {
      if (err.code === 'ENOENT') {
        this._state = structuredClone(DEFAULT_STATE);
      } else {
        throw err;
      }
    }
    return this._state;
  }

  async save() {
    const dir = this._path.replace(/\/[^/]+$/, '');
    await mkdir(dir, { recursive: true });
    const tmp = this._path + '.tmp';
    await writeFile(tmp, JSON.stringify(this._state, null, 2), 'utf8');
    await rename(tmp, this._path);
  }

  async getCache(key, isMetadata = false) {
    await this.load();
    const entry = this._state.cache[key];
    if (!entry) return null;
    const ttl = isMetadata ? META_CACHE_TTL_MS : VULN_CACHE_TTL_MS;
    if (Date.now() - new Date(entry.fetchedAt).getTime() > ttl) {
      delete this._state.cache[key];
      return null;
    }
    return entry.data;
  }

  async setCache(key, data) {
    await this.load();
    this._state.cache[key] = { data, fetchedAt: new Date().toISOString() };
    await this._pruneCache();
  }

  async _pruneCache() {
    const entries = Object.entries(this._state.cache);
    const now = Date.now();
    for (const [k, v] of entries) {
      const isMetadata = k.startsWith('meta:');
      const ttl = isMetadata ? META_CACHE_TTL_MS : VULN_CACHE_TTL_MS;
      if (now - new Date(v.fetchedAt).getTime() > ttl) {
        delete this._state.cache[k];
      }
    }
  }

  async addScanHistory(type, target, summary) {
    await this.load();
    const entry = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      type,
      target,
      summary,
    };
    this._state.scanHistory.unshift(entry);
    if (this._state.scanHistory.length > SCAN_HISTORY_LIMIT) {
      this._state.scanHistory = this._state.scanHistory.slice(0, SCAN_HISTORY_LIMIT);
    }
    await this.save();
    return entry.id;
  }

  async watchAdd(name, version, maintainers, scriptHash) {
    await this.load();
    this._state.watchlist[name] = {
      addedAt: new Date().toISOString(),
      lastVersion: version,
      lastCheck: new Date().toISOString(),
      lastMaintainers: maintainers || [],
      scriptHash: scriptHash || null,
    };
    await this.save();
  }

  async watchRemove(name) {
    await this.load();
    delete this._state.watchlist[name];
    await this.save();
  }

  async watchList() {
    await this.load();
    return this._state.watchlist;
  }

  async watchUpdate(name, updates) {
    await this.load();
    if (this._state.watchlist[name]) {
      Object.assign(this._state.watchlist[name], updates);
      await this.save();
    }
  }

  async getScanHistory() {
    await this.load();
    return this._state.scanHistory;
  }
}

export const stateManager = new StateManager();
