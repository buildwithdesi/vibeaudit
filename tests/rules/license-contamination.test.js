import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  licenseContamination as rule,
  classifyLicense,
  packageNameFromLockPath,
} from '../../src/rules/license-contamination.js';

function mk(relativePath, obj, _config) {
  const content = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  return { path: '/proj/' + relativePath, relativePath, content, lines: content.split('\n'), _config };
}

const lock = (packages) => ({ lockfileVersion: 3, packages: { '': { name: 'app' }, ...packages } });

describe('classifyLicense', () => {
  it('passes ordinary permissive licenses', () => {
    for (const id of ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC', '0BSD', 'Unlicense']) {
      assert.equal(classifyLicense(id).tier, 'pass', id);
    }
  });

  it('blocks GPL with no permissive escape', () => {
    assert.equal(classifyLicense('GPL-3.0-or-later').tier, 'block');
    assert.equal(classifyLicense('GPL-2.0-only').tier, 'block');
  });

  it('blocks AGPL and SSPL, the network-copyleft ones that catch SaaS', () => {
    assert.equal(classifyLicense('AGPL-3.0-only').tier, 'block');
    assert.equal(classifyLicense('SSPL-1.0').tier, 'block');
  });

  it('does not confuse LGPL with GPL', () => {
    assert.equal(classifyLicense('LGPL-3.0-or-later').tier, 'warn');
  });

  it('warns (not blocks) weak copyleft: LGPL, MPL', () => {
    assert.equal(classifyLicense('MPL-2.0').tier, 'warn');
    assert.equal(classifyLicense('LGPL-2.1-only').tier, 'warn');
  });

  it('warns on a dual-licensed GPL package because the permissive branch is electable', () => {
    const v = classifyLicense('(MIT OR GPL-3.0-or-later)');
    assert.equal(v.tier, 'warn');
    assert.match(v.reason, /MIT/);
  });

  it('handles a real-world compound expression: Apache-2.0 AND LGPL-3.0-or-later', () => {
    // sharp's actual license string — AND means both apply, no OR escape hatch,
    // but LGPL alone (no GPL/AGPL/SSPL present) is only weak copyleft.
    assert.equal(classifyLicense('Apache-2.0 AND LGPL-3.0-or-later').tier, 'warn');
  });

  it('blocks a GPL package ANDed with something else — no OR means no escape', () => {
    assert.equal(classifyLicense('MIT AND GPL-3.0-only').tier, 'block');
  });

  it('flags missing, empty, and UNLICENSED as unknown, not safe', () => {
    assert.equal(classifyLicense(undefined).tier, 'flag');
    assert.equal(classifyLicense('').tier, 'flag');
    assert.equal(classifyLicense('UNLICENSED').tier, 'flag');
  });

  it('flags an unrecognized expression rather than assuming it is safe', () => {
    assert.equal(classifyLicense('Some-Made-Up-License-9.0').tier, 'flag');
  });
});

describe('license-contamination rule', () => {
  it('reports nothing for an all-permissive tree', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/react': { version: '19.0.0', license: 'MIT' },
      'node_modules/next': { version: '15.0.0', license: 'MIT' },
    }));
    assert.equal(rule.check(f).length, 0);
  });

  it('flags a GPL runtime dependency as critical', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/copyleft-thing': { version: '1.0.0', license: 'GPL-3.0-or-later' },
    }));
    const found = rule.check(f);
    assert.equal(found.length, 1);
    assert.equal(found[0].severity, 'critical');
    assert.match(found[0].message, /copyleft-thing@1\.0\.0/);
    assert.match(found[0].fix, /allowedLicenses/);
  });

  it('drops severity a tier for a dev-only dependency', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/copyleft-devtool': { version: '1.0.0', license: 'GPL-3.0-only', dev: true },
    }));
    assert.equal(rule.check(f)[0].severity, 'warning');
    assert.match(rule.check(f)[0].message, /development-only/);
  });

  it('reports a weak-copyleft package as warning, not critical', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/@img/sharp-win32-x64': { version: '0.35.3', license: 'Apache-2.0 AND LGPL-3.0-or-later' },
    }));
    const found = rule.check(f);
    assert.equal(found.length, 1);
    assert.equal(found[0].severity, 'warning');
  });

  it('reports a dual-licensed GPL package as warning, dual-license is electable', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/jszip': { version: '3.10.1', license: '(MIT OR GPL-3.0-or-later)' },
    }));
    assert.equal(rule.check(f)[0].severity, 'warning');
  });

  it('flags a package with no license field', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/busboy': { version: '1.6.0' },
    }));
    const found = rule.check(f);
    assert.equal(found.length, 1);
    assert.equal(found[0].severity, 'warning');
    assert.match(found[0].message, /no license declared/);
  });

  it('honors allowedLicenses from config, downgrades to info without hiding the finding', () => {
    const packages = { 'node_modules/reviewed-gpl-tool': { version: '1.0.0', license: 'GPL-3.0-only' } };
    assert.equal(rule.check(mk('package-lock.json', lock(packages))).length, 1);
    const cleared = rule.check(mk('package-lock.json', lock(packages), { allowedLicenses: ['reviewed-gpl-tool'] }));
    assert.equal(cleared.length, 1);
    assert.equal(cleared[0].severity, 'info');
  });

  it('deduplicates the same package@version hoisted to several paths', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/gpl-thing': { version: '1.0.0', license: 'GPL-3.0-only' },
      'node_modules/other/node_modules/gpl-thing': { version: '1.0.0', license: 'GPL-3.0-only' },
    }));
    assert.equal(rule.check(f).length, 1, 'one package, one finding');
  });

  it('reports differing versions of the same package separately', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/gpl-thing': { version: '1.0.0', license: 'GPL-3.0-only' },
      'node_modules/old/node_modules/gpl-thing': { version: '0.9.0', license: 'GPL-3.0-only' },
    }));
    assert.equal(rule.check(f).length, 2);
  });

  it('ignores the root project entry', () => {
    const f = mk('package-lock.json', lock({}));
    assert.equal(rule.check(f).length, 0);
  });

  it('ignores files that are not a package-lock', () => {
    assert.equal(rule.check(mk('package.json', lock({ 'node_modules/x': { license: 'GPL-3.0-only' } }))).length, 0);
  });

  it('does not crash on malformed or v1 lockfiles', () => {
    assert.equal(rule.check(mk('package-lock.json', '{ not json')).length, 0);
    assert.equal(rule.check(mk('package-lock.json', { lockfileVersion: 1, dependencies: {} })).length, 0);
  });
});

describe('packageNameFromLockPath (license-contamination copy)', () => {
  it('resolves scoped and nested package names', () => {
    assert.equal(packageNameFromLockPath('node_modules/@scope/pkg'), '@scope/pkg');
    assert.equal(packageNameFromLockPath('node_modules/a/node_modules/b'), 'b');
    assert.equal(packageNameFromLockPath(''), '');
  });
});
