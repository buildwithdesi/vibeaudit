/**
 * Doctrine rules (2026-10): minimum-release-age, dependency-bloat, php-stack.
 * Fire and no-fire directions for each, plus the project-context pass that
 * turns minimum-release-age's per-file candidates into one project verdict.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { minimumReleaseAge } from '../../src/rules/minimum-release-age.js';
import { dependencyBloat } from '../../src/rules/dependency-bloat.js';
import { phpStack } from '../../src/rules/php-stack.js';
import { createProjectContext, collectProjectFact, applyProjectContext } from '../../src/project-context.js';

function mk(relativePath, content) {
  return { path: `/project/${relativePath}`, relativePath, content, lines: content.split('\n') };
}
const pkg = (o) => JSON.stringify(o, null, 2);

/** A v3 package-lock.json with `total` installed packages, optionally with extras by name. */
function npmLock(total, extra = {}) {
  const packages = { '': { name: 'fixture', version: '1.0.0', dependencies: { a: '1.0.0' }, devDependencies: { b: '1.0.0' } } };
  for (let i = 0; i < total; i++) packages[`node_modules/pkg-${i}`] = { version: '1.0.0' };
  for (const [name, entry] of Object.entries(extra)) packages[`node_modules/${name}`] = entry;
  return pkg({ name: 'fixture', version: '1.0.0', lockfileVersion: 3, packages });
}

describe('minimum-release-age: the no-gate candidate', () => {
  const run = (p, s) => minimumReleaseAge.check(mk(p, s));

  it('emits one info candidate on the root package.json and on a root lockfile', () => {
    const a = run('package.json', pkg({ name: 'x', dependencies: { zod: '4.0.0' } }));
    assert.equal(a.length, 1);
    assert.equal(a[0].severity, 'info');
    assert.equal(a[0].ruleId, 'minimum-release-age');
    assert.match(a[0].message, /No dependency release-age cooldown/);
    assert.match(a[0].fix, /minimumReleaseAge: 4320/);
    assert.equal(run('package-lock.json', npmLock(3)).length, 1);
    assert.equal(run('pnpm-lock.yaml', 'lockfileVersion: "9.0"\n').length, 1);
    assert.equal(run('yarn.lock', '# yarn\n').length, 1);
  });

  it('does NOT emit the candidate on nested manifests, source files, or an empty file', () => {
    assert.equal(run('packages/app/package.json', pkg({ name: 'x' })).length, 0);
    assert.equal(run('src/index.js', 'console.log(1)').length, 0);
    assert.equal(run('empty.js', '').length, 0);
  });
});

describe('minimum-release-age: gates written in config files', () => {
  const run = (p, s) => minimumReleaseAge.check(mk(p, s));

  it('flags a pnpm cooldown under 3 days as a warning, with the length in the message', () => {
    const f = run('pnpm-workspace.yaml', 'packages:\n  - "packages/*"\nminimumReleaseAge: 1440\n')[0];
    assert.equal(f.severity, 'warning');
    assert.match(f.message, /1440 minutes \(1 day\)/);
    assert.equal(run('pnpm-workspace.yaml', 'minimumReleaseAge: 0\n')[0].severity, 'warning');
  });

  it('flags a short .npmrc minimum-release-age and a too-recent npm before date', () => {
    assert.equal(run('.npmrc', 'minimum-release-age=60\n')[0].severity, 'warning');
    // Midday UTC, two whole days back. A 2.5-day offset can floor to 3 calendar
    // days once Date.parse drops the clock, which is no longer "shorter than 3".
    const recentDate = new Date(Date.now() - 2 * 86400000);
    recentDate.setUTCHours(12, 0, 0, 0);
    const recent = recentDate.toISOString().slice(0, 10);
    const f = run('.npmrc', `before=${recent}\n`)[0];
    assert.equal(f.severity, 'warning');
    assert.match(f.message, /"before" gate is only 2 days/);
  });

  it('flags a short Bun cooldown (seconds are converted)', () => {
    const f = run('bunfig.toml', '[install]\nminimumReleaseAge = 3600\n')[0];
    assert.equal(f.severity, 'warning');
    assert.match(f.message, /60 minutes/);
  });

  it('is silent when the gate meets the 3-day floor, and when a config file sets no gate', () => {
    assert.equal(run('pnpm-workspace.yaml', 'minimumReleaseAge: 4320\n').length, 0);
    assert.equal(run('pnpm-workspace.yaml', 'minimumReleaseAge: 10080\n').length, 0);
    assert.equal(run('pnpm-workspace.yaml', 'packages:\n  - "packages/*"\n').length, 0);
    assert.equal(run('.npmrc', 'minimum-release-age=4320\n').length, 0);
    assert.equal(run('.npmrc', 'registry=https://registry.npmjs.org/\n').length, 0);
    assert.equal(run('bunfig.toml', '[install]\nminimumReleaseAge = 259200\n').length, 0);
    const old = new Date(Date.now() - 10 * 86400000).toISOString().slice(0, 10);
    assert.equal(run('.npmrc', `before=${old}\n`).length, 0);
  });
});

describe('minimum-release-age: project-context resolution', () => {
  const candidate = (file) => minimumReleaseAge.check(mk(file, file.endsWith('.json') && file !== 'package-lock.json' ? pkg({ name: 'x' }) : npmLock(2)))[0];

  it('drops every candidate when any config file in the project sets a gate', () => {
    const ctx = createProjectContext();
    collectProjectFact(mk('pnpm-workspace.yaml', 'minimumReleaseAge: 10080\n'), ctx);
    const out = applyProjectContext([candidate('package.json'), candidate('package-lock.json')], ctx);
    assert.equal(out.length, 0);
  });

  it('drops every candidate when the gate exists but is too short (the warning carries it)', () => {
    const ctx = createProjectContext();
    collectProjectFact(mk('.npmrc', 'minimum-release-age=60\n'), ctx);
    assert.equal(applyProjectContext([candidate('package.json')], ctx).length, 0);
  });

  it('keeps exactly one candidate when no gate exists anywhere, ignoring gate-less configs', () => {
    const ctx = createProjectContext();
    collectProjectFact(mk('.npmrc', 'registry=https://registry.npmjs.org/\n'), ctx);
    collectProjectFact(mk('pnpm-workspace.yaml', 'packages:\n  - "packages/*"\n'), ctx);
    const out = applyProjectContext([candidate('package.json'), candidate('package-lock.json')], ctx);
    assert.equal(out.length, 1);
    assert.equal(out[0].ruleId, 'minimum-release-age');
  });
});

describe('dependency-bloat: npm lockfiles', () => {
  const run = (p, s) => dependencyBloat.check(mk(p, s));

  it('is silent for a small tree with no micro-packages', () => {
    assert.equal(run('package-lock.json', npmLock(12)).length, 0);
  });

  it('reports an info finding at 250+ packages with direct and total counts', () => {
    const f = run('package-lock.json', npmLock(300))[0];
    assert.equal(f.severity, 'info');
    assert.match(f.message, /installs 300 packages \(2 direct/);
  });

  it('escalates to a warning at 1000+ packages', () => {
    const f = run('package-lock.json', npmLock(1200))[0];
    assert.equal(f.severity, 'warning');
    assert.match(f.message, /installs 1200 packages/);
  });

  it('counts a v1 lockfile tree recursively', () => {
    const v1 = pkg({ lockfileVersion: 1, dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '1.0.0' } } } } });
    assert.equal(run('package-lock.json', v1).length, 0); // 2 packages, under the floor
    const big = { lockfileVersion: 1, dependencies: {} };
    for (let i = 0; i < 260; i++) big.dependencies[`p-${i}`] = { version: '1.0.0' };
    assert.match(run('package-lock.json', pkg(big))[0].message, /installs 260 packages/);
  });

  it('ignores an unparseable lockfile and files it does not own', () => {
    assert.equal(run('package-lock.json', '{not json').length, 0);
    assert.equal(run('src/app.js', 'node_modules/is-odd').length, 0);
    assert.equal(run('empty.js', '').length, 0);
  });
});

describe('dependency-bloat: micro-packages and other lockfiles', () => {
  const run = (p, s) => dependencyBloat.check(mk(p, s));

  it('flags a micro-package even in a small tree, naming the built-in', () => {
    const f = run('package-lock.json', npmLock(5, { 'is-odd': { version: '3.0.1' }, 'left-pad': { version: '1.3.0' } }))
      .filter((x) => /one-function/.test(x.message));
    assert.equal(f.length, 2);
    assert.match(f.find((x) => x.message.includes('is-odd')).fix, /Remove "is-odd"/);
    assert.match(f.find((x) => x.message.includes('left-pad')).message, /padStart/);
  });

  it('counts pnpm-lock.yaml snapshots, including scoped names', () => {
    const entries = ['snapshots:'];
    for (let i = 0; i < 260; i++) entries.push(`  pkg-${i}@1.0.0:`, '    resolution: {}');
    entries.push('  is-even@2.0.0:', '    resolution: {}');
    const out = run('pnpm-lock.yaml', entries.join('\n'));
    assert.match(out[0].message, /installs 261 packages/);
    assert.ok(out.some((x) => x.message.includes('"is-even"')));
  });

  it('counts yarn.lock v1 blocks', () => {
    const entries = ['# yarn lockfile v1', ''];
    for (let i = 0; i < 255; i++) entries.push(`pkg-${i}@^1.0.0:`, '  version "1.0.0"', '');
    const out = run('yarn.lock', entries.join('\n'));
    assert.match(out[0].message, /installs 255 packages/);
  });
});

describe('php-stack', () => {
  const run = (p, s) => phpStack.check(mk(p, s));

  it('flags composer.json as a warning, wherever it lives', () => {
    const f = run('composer.json', pkg({ name: 'acme/site', require: { php: '>=8.2' } }))[0];
    assert.equal(f.severity, 'warning');
    assert.match(f.message, /PHP application/);
    assert.match(f.fix, /8\.5\.12/);
    assert.equal(run('apps/legacy/composer.json', pkg({ name: 'x/y' })).length, 1);
  });

  it('notes a .php source file at info severity', () => {
    const f = run('public/index.php', '<?php echo 1;')[0];
    assert.equal(f.severity, 'info');
    assert.equal(f.ruleId, 'php-stack');
  });

  it('flags PHP base images in Dockerfiles and PHP images in compose files', () => {
    const f = run('Dockerfile', 'FROM php:8.1-fpm\nRUN docker-php-ext-install pdo')[0];
    assert.equal(f.severity, 'warning');
    assert.match(f.message, /container is what ships/);
    assert.equal(run('docker-compose.yml', 'services:\n  web:\n    image: php:8.2-apache\n').length, 1);
    assert.equal(run('docker-compose.yaml', 'services:\n  web:\n    image: "wordpress:latest"\n').length, 0); // only literal php images in v1
  });

  it('does NOT flag non-PHP stacks or unrelated files', () => {
    assert.equal(run('Dockerfile', 'FROM node:24\nRUN npm ci').length, 0);
    assert.equal(run('docker-compose.yml', 'services:\n  web:\n    image: node:24\n').length, 0);
    assert.equal(run('src/index.js', 'const php = "not a stack";').length, 0);
    assert.equal(run('empty.js', '').length, 0);
  });
});
