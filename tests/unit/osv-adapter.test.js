import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { OsvAdapter } from '../../src/adapters/osv.js';

const __dir = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => JSON.parse(readFileSync(join(__dir, '../fixtures', name), 'utf8'));

const osv = new OsvAdapter();

describe('OsvAdapter._extractVersionRanges', () => {
  test('multi-range advisory produces || joined range', () => {
    const vuln = fixture('osv-multi-range.json');
    const result = osv._extractVersionRanges(vuln, 'test-pkg');
    assert.equal(result.vulnerable, '>=1.0.0 <1.5.0 || >=2.0.0 <2.3.0');
    assert.equal(result.patched, '>=2.3.0');
  });

  test('introduced=0 produces <fixed only', () => {
    const vuln = fixture('osv-single-range.json');
    const result = osv._extractVersionRanges(vuln, 'single-pkg');
    assert.equal(result.vulnerable, '<4.17.21');
    assert.equal(result.patched, '>=4.17.21');
  });

  test('open-ended range (no fixed) produces >=introduced', () => {
    const vuln = fixture('osv-open-range.json');
    const result = osv._extractVersionRanges(vuln, 'open-pkg');
    assert.equal(result.vulnerable, '>=3.0.0');
    assert.equal(result.patched, null);
  });

  test('last_affected produces <=last_affected range', () => {
    const vuln = fixture('osv-last-affected.json');
    const result = osv._extractVersionRanges(vuln, 'last-pkg');
    assert.equal(result.vulnerable, '>=1.0.0 <=1.9.9');
    assert.equal(result.patched, null);
  });

  test('GIT range type is ignored', () => {
    const vuln = {
      affected: [{
        package: { name: 'git-only', ecosystem: 'npm' },
        ranges: [{ type: 'GIT', events: [{ introduced: 'abc123' }, { fixed: 'def456' }] }],
      }],
    };
    const result = osv._extractVersionRanges(vuln, 'git-only');
    assert.equal(result.vulnerable, null);
    assert.equal(result.patched, null);
  });

  test('wrong package name → skip affected entry', () => {
    const vuln = fixture('osv-multi-range.json');
    const result = osv._extractVersionRanges(vuln, 'other-pkg');
    assert.equal(result.vulnerable, null);
    assert.equal(result.patched, null);
  });

  test('no pkgName filter → uses first affected entry', () => {
    const vuln = fixture('osv-single-range.json');
    const result = osv._extractVersionRanges(vuln, null);
    assert.ok(result.vulnerable, 'should produce a range when pkgName is null');
  });
});

describe('OsvAdapter._cvssToSeverity', () => {
  const cases = [
    ['CVSS:3.1/.../9.8', 'critical'],
    ['CVSS:3.1/.../9.0', 'critical'],
    ['CVSS:3.1/.../8.9', 'high'],
    ['CVSS:3.1/.../7.0', 'high'],
    ['CVSS:3.1/.../6.9', 'moderate'],
    ['CVSS:3.1/.../4.0', 'moderate'],
    ['CVSS:3.1/.../3.9', 'low'],
    ['CVSS:3.1/.../0.1', 'low'],
    ['CVSS:3.1/.../0.0', 'none'],
    ['not-a-score', 'unknown'],
  ];
  for (const [score, expected] of cases) {
    test(`${score} → ${expected}`, () => {
      assert.equal(osv._cvssToSeverity(score), expected);
    });
  }
});

describe('OsvAdapter._normalize', () => {
  test('extracts CVE and GHSA aliases', () => {
    const vuln = fixture('osv-multi-range.json');
    const normalized = osv._normalize(vuln, { name: 'test-pkg', version: '1.2.0' });
    assert.equal(normalized.cveId, 'CVE-2021-99999');
    assert.equal(normalized.ghsaId, 'GHSA-mult-rang-test');
    assert.equal(normalized.packageName, 'test-pkg');
    assert.equal(normalized.source, 'OSV');
  });

  test('severity from CVSS_V3 score', () => {
    const vuln = fixture('osv-multi-range.json'); // score /9.8
    const normalized = osv._normalize(vuln, { name: 'test-pkg' });
    assert.equal(normalized.severity, 'critical');
  });

  test('severity falls back to database_specific.severity', () => {
    const vuln = fixture('osv-open-range.json'); // no CVSS, database_specific.severity = HIGH
    const normalized = osv._normalize(vuln, { name: 'open-pkg' });
    assert.equal(normalized.severity, 'high');
  });

  test('multi-range embedded in normalized vulnerable field', () => {
    const vuln = fixture('osv-multi-range.json');
    const normalized = osv._normalize(vuln, { name: 'test-pkg' });
    assert.equal(normalized.vulnerableVersions, '>=1.0.0 <1.5.0 || >=2.0.0 <2.3.0');
  });
});
