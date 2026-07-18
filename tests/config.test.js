/**
 * Config normalization: a .vibe-audit.json can come from a REMOTE repo being
 * scanned (fetchRemoteConfig), so it is untrusted input. Non-string entries in
 * its arrays must be dropped — downstream code calls .replace()/.includes() on
 * them and a number/object entry crashes the whole scan (TypeError).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { normalizeConfig } from '../src/config.js';

describe('config: normalizeConfig untrusted-input hardening', () => {
  it('drops non-string entries from ignore/rules/exclude arrays', () => {
    const config = normalizeConfig({
      ignore: ['reports', 123, null, {}, 'legacy'],
      rules: ['missing-auth', false],
      exclude: [42, 'noisy-rule'],
    });
    assert.deepEqual(config.ignore, ['reports', 'legacy']);
    assert.deepEqual(config.rules, ['missing-auth']);
    assert.deepEqual(config.exclude, ['noisy-rule']);
  });

  it('drops non-string entries from disableForPaths pattern lists', () => {
    const config = normalizeConfig({
      disableForPaths: {
        'missing-auth': ['public/', 7, null],
        'empty-rule': [null, {}],
        'not-an-array': 'oops',
      },
    });
    assert.deepEqual(config.disableForPaths['missing-auth'], ['public/']);
    assert.equal(config.disableForPaths['empty-rule'], undefined);
    assert.equal(config.disableForPaths['not-an-array'], undefined);
  });

  it('falls back to defaults for missing or wrong-typed fields', () => {
    const config = normalizeConfig({});
    assert.deepEqual(config.ignore, []);
    assert.deepEqual(config.rules, []);
    assert.equal(config.format, 'terminal');
    assert.equal(config.strict, false);
    assert.deepEqual(config.disableForPaths, {});
  });

  it('rejects a disableForPaths that is itself an array', () => {
    const config = normalizeConfig({ disableForPaths: ['public/'] });
    assert.deepEqual(config.disableForPaths, {});
  });
});
