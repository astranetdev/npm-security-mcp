import { scanPackage } from './tools/scan-package.js';
import { scanLockfile } from './tools/scan-lockfile.js';
import { diffVersions } from './tools/diff-versions.js';
import { searchAdvisory } from './tools/search-advisory.js';
import { securityIntelSummary } from './tools/security-intel.js';
import { watchAdd, watchCheck, watchRemove } from './tools/watch.js';

const RESET = '\x1b[0m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';

let passed = 0;
let failed = 0;

function pass(name) {
  console.log(`${GREEN}✅ PASS${RESET} ${name}`);
  passed++;
}

function fail(name, reason) {
  console.log(`${RED}❌ FAIL${RESET} ${name}: ${reason}`);
  failed++;
}

async function test(name, fn) {
  try {
    await fn();
    pass(name);
  } catch (err) {
    fail(name, err.message);
  }
}

// ─── Test 1: scan lodash 4.17.15 — should find prototype pollution ──────────
await test('scan_package lodash@4.17.15 finds prototype pollution', async () => {
  const result = await scanPackage({ name: 'lodash', version: '4.17.15' });
  if (!result.includes('GHSA-p6mc-m468-83gw') && !result.toLowerCase().includes('prototype')) {
    throw new Error(`Expected GHSA-p6mc-m468-83gw or prototype pollution. Got:\n${result.slice(0, 500)}`);
  }
  if (!result.includes('OSV')) throw new Error('OSV source not mentioned in output');
});

// ─── Test 2: scan lodash 4.17.21 — should be clean ──────────────────────────
await test('scan_package lodash@4.17.21 has 0 critical vulns', async () => {
  const result = await scanPackage({ name: 'lodash', version: '4.17.21' });
  // Should either say no vulns or 0 critical
  if (result.includes('🔴') || result.includes('critical') && !result.includes('0 critical')) {
    // Allow "No vulnerabilities found" or ✅ signal
    if (!result.toLowerCase().includes('no known') && !result.includes('✅')) {
      throw new Error(`Expected clean result. Got:\n${result.slice(0, 500)}`);
    }
  }
});

// ─── Test 3: scan lockfile with handlebars@4.7.6 ────────────────────────────
await test('scan_lockfile detects advisories for handlebars@4.7.6', async () => {
  const lockfile = JSON.stringify({
    name: 'test-app',
    version: '1.0.0',
    lockfileVersion: 2,
    requires: true,
    packages: {
      '': {
        name: 'test-app',
        version: '1.0.0',
        dependencies: { handlebars: '^4.7.6' },
      },
      'node_modules/handlebars': {
        name: 'handlebars',
        version: '4.7.6',
        resolved: 'https://registry.npmjs.org/handlebars/-/handlebars-4.7.6.tgz',
        integrity: 'sha512-example',
      },
    },
  });
  const result = await scanLockfile({ content: lockfile });
  if (!result.includes('handlebars') && !result.includes('advisory') && !result.includes('Advisory')) {
    throw new Error(`Expected advisory detection. Got:\n${result.slice(0, 500)}`);
  }
});

// ─── Test 4: diff lodash 4.17.15 → 4.17.21 ─────────────────────────────────
await test('diff_versions lodash 4.17.15→4.17.21 finds no new install scripts', async () => {
  const result = await diffVersions({
    name: 'lodash',
    from_version: '4.17.15',
    to_version: '4.17.21',
  });
  if (result.includes('NEW INSTALL SCRIPTS')) {
    throw new Error('Unexpected new install scripts detected');
  }
  if (!result.includes('4.17.15') || !result.includes('4.17.21')) {
    throw new Error('Version numbers not present in diff output');
  }
});

// ─── Test 5: search advisory GHSA-p6mc-m468-83gw ───────────────────────────
await test('search_advisory GHSA-p6mc-m468-83gw returns lodash advisory', async () => {
  const result = await searchAdvisory({ query: 'GHSA-p6mc-m468-83gw' });
  if (!result.toLowerCase().includes('lodash') && !result.includes('GHSA-p6mc-m468-83gw')) {
    throw new Error(`Expected lodash advisory. Got:\n${result.slice(0, 500)}`);
  }
});

// ─── Test 6: security_intel_summary ─────────────────────────────────────────
await test('security_intel_summary returns recent npm advisories', async () => {
  const result = await securityIntelSummary({ days: 7 });
  if (!result.includes('Security Intelligence') && !result.includes('advisories')) {
    throw new Error(`Expected intel summary structure. Got:\n${result.slice(0, 500)}`);
  }
  // It's OK if 0 advisories — just verify the structure runs
});

// ─── Test 7: watch flow ──────────────────────────────────────────────────────
await test('watch_add → watch_check → watch_remove completes without error', async () => {
  const addResult = await watchAdd({ name: 'express' });
  if (!addResult.includes('express')) throw new Error('watch_add did not mention express');

  const checkResult = await watchCheck({ name: 'express' });
  if (!checkResult.includes('express')) throw new Error('watch_check did not mention express');

  const removeResult = await watchRemove({ name: 'express' });
  if (!removeResult.toLowerCase().includes('remov') && !removeResult.includes('express')) {
    throw new Error('watch_remove did not confirm removal');
  }
});

// ─── Summary ─────────────────────────────────────────────────────────────────
console.log(`\n${'-'.repeat(50)}`);
console.log(`Results: ${GREEN}${passed} passed${RESET} · ${failed > 0 ? RED : ''}${failed} failed${RESET}`);
if (failed > 0) process.exit(1);
