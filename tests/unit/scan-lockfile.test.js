import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseLockfile } from '../../src/tools/scan-lockfile.js';
import { isVulnerable } from '../../src/utils/semver-check.js';

const __dir = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => readFileSync(join(__dir, '../fixtures', name), 'utf8');

describe('parseLockfile — v2 format', () => {
  test('parses all package instances including duplicate names', () => {
    const packages = parseLockfile(fixture('lockfile-multi-version.json'));
    const vulnInstances = packages.filter(p => p.name === 'vuln-pkg');
    assert.equal(vulnInstances.length, 2, 'both versions of vuln-pkg must be present');
    const versions = vulnInstances.map(p => p.version).sort();
    assert.deepEqual(versions, ['3.10.1', '4.17.21']);
  });

  test('symlink entries are skipped', () => {
    const packages = parseLockfile(fixture('lockfile-multi-version.json'));
    assert.ok(!packages.some(p => p.name === 'symlink-pkg'), 'symlinks must be skipped');
  });

  test('root entry is skipped', () => {
    const packages = parseLockfile(fixture('lockfile-multi-version.json'));
    assert.ok(!packages.some(p => !p.name || p.version === undefined), 'root entry must be skipped');
  });

  test('direct deps flagged correctly', () => {
    const packages = parseLockfile(fixture('lockfile-multi-version.json'));
    const direct = packages.find(p => p.name === 'vuln-pkg' && p.version === '4.17.21');
    const transitive = packages.find(p => p.name === 'vuln-pkg' && p.version === '3.10.1');
    assert.equal(direct?.isDirect, true);
    assert.equal(transitive?.isDirect, false);
  });

  test('safe-pkg included', () => {
    const packages = parseLockfile(fixture('lockfile-multi-version.json'));
    assert.ok(packages.some(p => p.name === 'safe-pkg' && p.version === '1.5.0'));
  });
});

describe('parseLockfile — v1 format', () => {
  test('parses v1 dependencies', () => {
    const packages = parseLockfile(fixture('lockfile-v1.json'));
    assert.ok(packages.some(p => p.name === 'express' && p.version === '4.18.0'));
    assert.ok(packages.some(p => p.name === 'lodash' && p.version === '4.17.21'));
  });

  test('nested v1 deps parsed with isDirect=false', () => {
    const packages = parseLockfile(fixture('lockfile-v1.json'));
    const ms = packages.find(p => p.name === 'ms');
    assert.ok(ms, 'nested ms dep must be present');
    assert.equal(ms.isDirect, false);
  });

  test('top-level v1 deps flagged as direct', () => {
    const packages = parseLockfile(fixture('lockfile-v1.json'));
    const express = packages.find(p => p.name === 'express');
    assert.equal(express?.isDirect, true);
  });
});

describe('parseLockfile — edge cases', () => {
  test('invalid JSON throws', () => {
    assert.throws(() => parseLockfile('{not json}'), /Invalid JSON/);
  });

  test('empty packages object returns empty array', () => {
    const content = JSON.stringify({ lockfileVersion: 2, packages: { '': {} } });
    const packages = parseLockfile(content);
    assert.equal(packages.length, 0);
  });
});

describe('advisory matching — multi-version correctness', () => {
  test('only vulnerable version matched, safe version skipped', () => {
    const packages = parseLockfile(fixture('lockfile-multi-version.json'));
    const pkgsByName = new Map();
    for (const p of packages) {
      if (!pkgsByName.has(p.name)) pkgsByName.set(p.name, []);
      pkgsByName.get(p.name).push(p);
    }

    const adv = { packageName: 'vuln-pkg', vulnerableVersions: '>=3.0.0 <4.0.0' };
    const vulnMap = new Map();
    for (const pkg of pkgsByName.get(adv.packageName) || []) {
      if (!isVulnerable(pkg.version, adv.vulnerableVersions)) continue;
      const key = `${pkg.name}@${pkg.version}`;
      if (!vulnMap.has(key)) vulnMap.set(key, { pkg, advs: [] });
      vulnMap.get(key).advs.push(adv);
    }

    assert.equal(vulnMap.size, 1, 'only one instance should be vulnerable');
    assert.ok(vulnMap.has('vuln-pkg@3.10.1'), '3.10.1 is vulnerable');
    assert.ok(!vulnMap.has('vuln-pkg@4.17.21'), '4.17.21 is NOT vulnerable');
  });

  test('advisory with || range hits both vulnerable instances', () => {
    const packages = [
      { name: 'multi', version: '1.3.0' },
      { name: 'multi', version: '2.1.0' },
      { name: 'multi', version: '3.0.0' },
    ];
    const pkgsByName = new Map([['multi', packages]]);
    const adv = { packageName: 'multi', vulnerableVersions: '>=1.0.0 <1.5.0 || >=2.0.0 <2.3.0' };
    const vulnMap = new Map();
    for (const pkg of pkgsByName.get(adv.packageName)) {
      if (!isVulnerable(pkg.version, adv.vulnerableVersions)) continue;
      const key = `${pkg.name}@${pkg.version}`;
      if (!vulnMap.has(key)) vulnMap.set(key, { pkg, advs: [] });
      vulnMap.get(key).advs.push(adv);
    }
    assert.equal(vulnMap.size, 2);
    assert.ok(vulnMap.has('multi@1.3.0'));
    assert.ok(vulnMap.has('multi@2.1.0'));
    assert.ok(!vulnMap.has('multi@3.0.0'));
  });
});
