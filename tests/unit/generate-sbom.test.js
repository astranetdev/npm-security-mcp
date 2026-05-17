import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { resolveExactVersion } from '../../src/tools/generate-sbom.js';

describe('resolveExactVersion', () => {
  describe('exact versions', () => {
    test('bare version → identity', () => assert.equal(resolveExactVersion('1.5.0'), '1.5.0'));
    test('pre-release → identity', () => assert.equal(resolveExactVersion('2.0.0-rc.1'), '2.0.0-rc.1'));
  });

  describe('ranges → min version', () => {
    test('^1.2.3 → 1.2.3', () => assert.equal(resolveExactVersion('^1.2.3'), '1.2.3'));
    test('~2.0.0 → 2.0.0', () => assert.equal(resolveExactVersion('~2.0.0'), '2.0.0'));
    test('>=1.2.3 <2.0.0 → 1.2.3', () => assert.equal(resolveExactVersion('>=1.2.3 <2.0.0'), '1.2.3'));
    test('>=3 → 3.0.0', () => assert.equal(resolveExactVersion('>=3'), '3.0.0'));
  });

  describe('unresolvable → null', () => {
    test('latest → null', () => assert.equal(resolveExactVersion('latest'), null));
    test('* → null', () => assert.equal(resolveExactVersion('*'), null));
    test('null → null', () => assert.equal(resolveExactVersion(null), null));
    test('empty string → null', () => assert.equal(resolveExactVersion(''), null));
    test('workspace:* → null', () => assert.equal(resolveExactVersion('workspace:*'), null));
    test('file:../pkg → null', () => assert.equal(resolveExactVersion('file:../pkg'), null));
    test('git+https://... → null', () => assert.equal(resolveExactVersion('git+https://github.com/x/y'), null));
    test('github:org/repo → null', () => assert.equal(resolveExactVersion('github:org/repo'), null));
  });
});
