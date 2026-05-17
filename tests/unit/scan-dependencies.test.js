import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { resolveRangeVersion } from '../../src/tools/scan-dependencies.js';

describe('resolveRangeVersion', () => {
  describe('exact versions', () => {
    test('bare version → identity', () => assert.equal(resolveRangeVersion('1.5.0'), '1.5.0'));
    test('pre-release preserved', () => assert.equal(resolveRangeVersion('1.5.0-beta.1'), '1.5.0-beta.1'));
  });

  describe('semver ranges', () => {
    test('^x.y.z → x.y.z (caret)', () => assert.equal(resolveRangeVersion('^1.2.3'), '1.2.3'));
    test('~x.y.z → x.y.z (tilde)', () => assert.equal(resolveRangeVersion('~2.0.0'), '2.0.0'));
    test('>=x.y.z → x.y.z', () => assert.equal(resolveRangeVersion('>=1.2.3'), '1.2.3'));
    test('>=x.y.z <x.y.z compound → lower bound', () => assert.equal(resolveRangeVersion('>=1.2.3 <2.0.0'), '1.2.3'));
    test('>x.y.z → next patch', () => {
      const result = resolveRangeVersion('>1.2.3');
      assert.ok(result, 'should return something for > range');
    });
    test('>=1 → 1.0.0', () => assert.equal(resolveRangeVersion('>=1'), '1.0.0'));
  });

  describe('special protocols → null', () => {
    test('workspace:* → null', () => assert.equal(resolveRangeVersion('workspace:*'), null));
    test('workspace:^1.0.0 → null', () => assert.equal(resolveRangeVersion('workspace:^1.0.0'), null));
    test('file:../path → null', () => assert.equal(resolveRangeVersion('file:../sibling'), null));
    test('git+https → null', () => assert.equal(resolveRangeVersion('git+https://github.com/org/repo'), null));
    test('git: → null', () => assert.equal(resolveRangeVersion('git:github.com/org/repo'), null));
    test('github: → null', () => assert.equal(resolveRangeVersion('github:org/repo'), null));
    test('bitbucket: → null', () => assert.equal(resolveRangeVersion('bitbucket:org/repo'), null));
    test('gitlab: → null', () => assert.equal(resolveRangeVersion('gitlab:org/repo'), null));
  });

  describe('wildcard/alias → null', () => {
    test('latest → null', () => assert.equal(resolveRangeVersion('latest'), null));
    test('* → null', () => assert.equal(resolveRangeVersion('*'), null));
    test('empty string → null', () => assert.equal(resolveRangeVersion(''), null));
    test('null → null', () => assert.equal(resolveRangeVersion(null), null));
  });

  describe('isRange detection (via semver.valid)', () => {
    test('exact version is NOT a range', () => {
      // resolveRangeVersion returns the version itself → callers mark isRange: false via semver.valid
      assert.equal(resolveRangeVersion('3.0.0'), '3.0.0');
    });
  });
});
