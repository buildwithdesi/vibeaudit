import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  installScriptDependency as rule,
  packageNameFromLockPath,
} from '../../src/rules/install-script-dependency.js';

function mk(relativePath, obj, _config) {
  const content = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  return { path: '/proj/' + relativePath, relativePath, content, lines: content.split('\n'), _config };
}

const lock = (packages) => ({ lockfileVersion: 3, packages });

describe('install-script-dependency', () => {
  it('flags an unexpected package that runs code at install time', () => {
    const f = mk('package-lock.json', lock({
      '': { name: 'app' },
      'node_modules/left-pad': { version: '9.9.9', hasInstallScript: true },
    }));
    const found = rule.check(f);
    assert.equal(found.length, 1);
    assert.equal(found[0].severity, 'warning');
    assert.match(found[0].message, /left-pad@9\.9\.9/);
    assert.match(found[0].fix, /ignore-scripts/);
  });

  it('reports a known native-build package as info, not a warning', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/esbuild': { version: '0.25.12', hasInstallScript: true },
    }));
    const found = rule.check(f);
    assert.equal(found.length, 1);
    assert.equal(found[0].severity, 'info', 'expected install hooks stay visible but must not cry wolf');
  });

  it('says nothing about dependencies with no install script', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/react': { version: '19.0.0' },
      'node_modules/zod': { version: '3.23.8', hasInstallScript: false },
    }));
    assert.equal(rule.check(f).length, 0);
  });

  it('resolves scoped and nested package names', () => {
    assert.equal(packageNameFromLockPath('node_modules/@scope/pkg'), '@scope/pkg');
    assert.equal(packageNameFromLockPath('node_modules/a/node_modules/b'), 'b');
    assert.equal(packageNameFromLockPath(''), '');
  });

  it('treats a nested copy of a known package as known', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/tsx/node_modules/esbuild': { version: '0.28.1', hasInstallScript: true },
    }));
    assert.equal(rule.check(f)[0].severity, 'info');
  });

  it('honors allowedInstallScripts from config', () => {
    const packages = { 'node_modules/our-native-thing': { version: '1.0.0', hasInstallScript: true } };
    assert.equal(rule.check(mk('package-lock.json', lock(packages))).length, 1);
    assert.equal(
      rule.check(mk('package-lock.json', lock(packages), { allowedInstallScripts: ['our-native-thing'] }))[0].severity,
      'info',
    );
  });

  it('deduplicates the same package@version hoisted to several paths', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/fsevents': { version: '2.3.3', hasInstallScript: true },
      'node_modules/playwright/node_modules/fsevents': { version: '2.3.3', hasInstallScript: true },
    }));
    assert.equal(rule.check(f).length, 1, 'one package, one finding');
  });

  it('reports differing versions of the same package separately', () => {
    const f = mk('package-lock.json', lock({
      'node_modules/fsevents': { version: '2.3.3', hasInstallScript: true },
      'node_modules/old/node_modules/fsevents': { version: '2.3.2', hasInstallScript: true },
    }));
    assert.equal(rule.check(f).length, 2);
  });

  it('ignores files that are not a package-lock', () => {
    assert.equal(rule.check(mk('package.json', lock({ 'node_modules/x': { hasInstallScript: true } }))).length, 0);
  });

  it('does not crash on malformed or v1 lockfiles', () => {
    assert.equal(rule.check(mk('package-lock.json', '{ not json')).length, 0);
    assert.equal(rule.check(mk('package-lock.json', { lockfileVersion: 1, dependencies: {} })).length, 0);
  });
});
