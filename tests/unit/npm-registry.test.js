import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { NpmRegistryAdapter } from '../../src/adapters/npm-registry.js';

const __dir = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => JSON.parse(readFileSync(join(__dir, '../fixtures', name), 'utf8'));

const registry = new NpmRegistryAdapter();

describe('extractRiskSignals — version lookup correctness', () => {
  test('version 1.0.0 has postinstall script → signal reported', () => {
    const pkgData = fixture('registry-full.json');
    const signals = registry.extractRiskSignals(pkgData, '1.0.0');
    const installSignal = signals.find(s => s.type === 'install-script');
    assert.ok(installSignal, 'postinstall on v1.0.0 should be detected');
    assert.ok(installSignal.detail.includes('postinstall'));
  });

  test('version 2.0.0 has no install scripts → no install-script signal', () => {
    const pkgData = fixture('registry-full.json');
    const signals = registry.extractRiskSignals(pkgData, '2.0.0');
    const installSignal = signals.find(s => s.type === 'install-script');
    assert.equal(installSignal, undefined, 'v2.0.0 has no risky scripts');
  });

  test('no version specified → uses dist-tags.latest (2.0.0)', () => {
    const pkgData = fixture('registry-full.json'); // latest = 2.0.0, no scripts
    const signals = registry.extractRiskSignals(pkgData, undefined);
    const installSignal = signals.find(s => s.type === 'install-script');
    assert.equal(installSignal, undefined, 'latest (2.0.0) has no risky scripts');
  });

  test('version not in versions map → no crash, no signals', () => {
    const pkgData = fixture('registry-full.json');
    const signals = registry.extractRiskSignals(pkgData, '99.0.0');
    assert.ok(Array.isArray(signals));
    assert.equal(signals.find(s => s.type === 'install-script'), undefined);
  });

  test('single maintainer → single-maintainer signal', () => {
    const pkgData = fixture('registry-full.json');
    // v1.0.0 has 1 maintainer in versions map, but pkgData.maintainers has 2
    // extractRiskSignals uses pkgData.maintainers for the maintainer check
    // fixture-pkg has 2 maintainers → no signal
    const signals = registry.extractRiskSignals(pkgData, '2.0.0');
    const maintSignal = signals.find(s => s.type === 'single-maintainer');
    assert.equal(maintSignal, undefined, '2 maintainers → no signal');
  });

  test('single maintainer package → signal', () => {
    const pkgData = {
      ...fixture('registry-full.json'),
      maintainers: [{ name: 'solo', email: 'solo@example.com' }],
    };
    const signals = registry.extractRiskSignals(pkgData, '2.0.0');
    const maintSignal = signals.find(s => s.type === 'single-maintainer');
    assert.ok(maintSignal, 'single maintainer should trigger signal');
    assert.equal(maintSignal.severity, 'low');
  });

  test('all risky script types detected', () => {
    const pkgData = {
      'dist-tags': { latest: '1.0.0' },
      maintainers: [{ name: 'a' }, { name: 'b' }],
      versions: {
        '1.0.0': {
          scripts: {
            preinstall: 'pre.sh',
            install: 'install.sh',
            postinstall: 'post.sh',
            prepack: 'prepack.sh',
            prepare: 'prepare.sh',
          },
        },
      },
    };
    const signals = registry.extractRiskSignals(pkgData, '1.0.0');
    const scriptTypes = signals.filter(s => s.type === 'install-script').map(s => s.detail.split(':')[0]);
    for (const expected of ['preinstall', 'install', 'postinstall', 'prepack', 'prepare']) {
      assert.ok(scriptTypes.some(t => t === expected), `${expected} should be detected`);
    }
  });
});
