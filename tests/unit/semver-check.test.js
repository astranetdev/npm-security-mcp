import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { isVulnerable, extractFixVersion, compareVersions } from '../../src/utils/semver-check.js';

describe('isVulnerable', () => {
  test('version inside single range → true', () => {
    assert.equal(isVulnerable('4.17.20', '>=4.0.0 <4.17.21'), true);
  });

  test('version at upper bound (exclusive) → false', () => {
    assert.equal(isVulnerable('4.17.21', '>=4.0.0 <4.17.21'), false);
  });

  test('version below lower bound → false', () => {
    assert.equal(isVulnerable('3.9.9', '>=4.0.0 <4.17.21'), false);
  });

  test('|| compound range — version in first segment → true', () => {
    assert.equal(isVulnerable('1.3.0', '>=1.0.0 <1.5.0 || >=2.0.0 <2.3.0'), true);
  });

  test('|| compound range — version in second segment → true', () => {
    assert.equal(isVulnerable('2.1.0', '>=1.0.0 <1.5.0 || >=2.0.0 <2.3.0'), true);
  });

  test('|| compound range — version between segments → false', () => {
    assert.equal(isVulnerable('1.8.0', '>=1.0.0 <1.5.0 || >=2.0.0 <2.3.0'), false);
  });

  test('|| compound range — version above all segments → false', () => {
    assert.equal(isVulnerable('4.0.0', '>=1.0.0 <1.5.0 || >=2.0.0 <2.3.0'), false);
  });

  test('<fixed-only range', () => {
    assert.equal(isVulnerable('4.17.20', '<4.17.21'), true);
    assert.equal(isVulnerable('4.17.21', '<4.17.21'), false);
  });

  test('non-semver version → false (no crash)', () => {
    assert.equal(isVulnerable('workspace:*', '>=1.0.0'), false);
    assert.equal(isVulnerable('latest', '>=1.0.0'), false);
  });

  test('null inputs → false', () => {
    assert.equal(isVulnerable(null, '>=1.0.0'), false);
    assert.equal(isVulnerable('1.0.0', null), false);
    assert.equal(isVulnerable(null, null), false);
  });

  test('open-ended >=x range', () => {
    assert.equal(isVulnerable('3.0.0', '>=3.0.0'), true);
    assert.equal(isVulnerable('99.0.0', '>=3.0.0'), true);
    assert.equal(isVulnerable('2.9.9', '>=3.0.0'), false);
  });
});

describe('extractFixVersion', () => {
  test('>=x.y.z range → x.y.z', () => {
    assert.equal(extractFixVersion('>=4.17.21'), '4.17.21');
  });

  test('>x.y.z range → next semver', () => {
    const result = extractFixVersion('>4.17.20');
    assert.ok(result, 'should return something');
  });

  test('null input → null', () => {
    assert.equal(extractFixVersion(null), null);
  });

  test('empty string → null', () => {
    assert.equal(extractFixVersion(''), null);
  });
});

describe('compareVersions', () => {
  test('a < b → -1', () => assert.equal(compareVersions('1.0.0', '2.0.0'), -1));
  test('a === b → 0', () => assert.equal(compareVersions('1.5.0', '1.5.0'), 0));
  test('a > b → 1', () => assert.equal(compareVersions('2.0.0', '1.9.9'), 1));
});
