export class AdapterResult {
  constructor({ source, data = [], errors = [], raw = null }) {
    this.source = source;
    this.data = data;
    this.errors = errors;
    this.raw = raw;
    this.ok = errors.length === 0;
  }
}

export class BaseAdapter {
  constructor(name) {
    this.name = name;
  }

  available() {
    return true;
  }

  async fetch(_packages) {
    throw new Error(`${this.name}.fetch() not implemented`);
  }

  async withRetry(fn, { attempts = 3, baseDelay = 500 } = {}) {
    let lastError;
    for (let i = 0; i < attempts; i++) {
      try {
        return await fn();
      } catch (err) {
        lastError = err;
        if (i < attempts - 1) {
          await new Promise(r => setTimeout(r, baseDelay * Math.pow(2, i)));
        }
      }
    }
    throw lastError;
  }

  async fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...options, signal: controller.signal });
      return res;
    } finally {
      clearTimeout(timer);
    }
  }
}
