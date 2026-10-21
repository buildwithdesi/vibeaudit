/**
 * known-vulnerable-versions: the dated "vendor said update" list. Fire and no-fire
 * directions for package.json, package-lock.json, Dockerfile, .nvmrc and Python pins.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { knownVulnerableVersions as rule } from '../../src/rules/known-vulnerable-versions.js';

function mk(relativePath, content) {
  return { path: `/project/${relativePath}`, relativePath, content, lines: content.split('\n') };
}
const run = (path, src) => rule.check(mk(path, src));
const pkg = (o) => JSON.stringify(o, null, 2);

describe('known-vulnerable-versions: Next.js and sharp in package.json', () => {
  it('flags next below the fixed 16.x and 15.x versions, judged by the range floor', () => {
    assert.equal(run('package.json', pkg({ dependencies: { next: '16.3.2' } })).length, 1);
    assert.equal(run('package.json', pkg({ dependencies: { next: '^15.0.0' } })).length, 1);
    const f = run('package.json', pkg({ dependencies: { next: '^16.1.6' } }))[0];
    assert.equal(f.severity, 'critical');
    assert.match(f.message, /below the fixed version 16\.4\.1/);
    assert.match(f.fix, /npm install next@16\.4\.1 --ignore-scripts/);
    assert.match(f.fix, /vendor page/);
  });
  it('flags a Next major with no fixed release as end of life', () => {
    const f = run('package.json', pkg({ dependencies: { next: '^14.2.0' } }))[0];
    assert.match(f.message, /no security fix/);
  });
  it('does NOT flag fixed or newer versions, or unrelated packages', () => {
    assert.equal(run('package.json', pkg({ dependencies: { next: '16.4.1' } })).length, 0);
    assert.equal(run('package.json', pkg({ dependencies: { next: '^16.4.1' } })).length, 0);
    assert.equal(run('package.json', pkg({ dependencies: { next: '15.5.28' } })).length, 0);
    assert.equal(run('package.json', pkg({ dependencies: { next: '17.0.0', react: '19.2.8', zod: '4.1.12' } })).length, 0);
  });
  it('flags sharp below 0.35.5 and clears 0.35.5', () => {
    assert.equal(run('package.json', pkg({ dependencies: { sharp: '^0.34.0' } })).length, 1);
    assert.equal(run('package.json', pkg({ dependencies: { sharp: '0.35.5' } })).length, 0);
  });
  it('ignores a package.json it cannot parse and a wild range it cannot judge', () => {
    assert.equal(run('package.json', '{not json').length, 0);
    assert.equal(run('package.json', pkg({ dependencies: { next: 'latest' } })).length, 0); // unpinned-dependencies owns that
  });
});

describe('known-vulnerable-versions: package-lock.json is the source of truth', () => {
  it('flags the resolved version even when the range would pass, and clears a fixed resolved version', () => {
    const behind = pkg({ packages: { 'node_modules/next': { version: '16.2.11' } } });
    const fixed = pkg({ packages: { 'node_modules/next': { version: '16.4.1' } } });
    assert.equal(run('package-lock.json', behind).length, 1);
    assert.match(run('package-lock.json', behind)[0].message, /locked at 16\.2\.11/);
    assert.equal(run('package-lock.json', fixed).length, 0);
  });
  it('is quiet when the lock holds none of the watched packages', () => {
    assert.equal(run('package-lock.json', pkg({ packages: { 'node_modules/zod': { version: '4.1.12' } } })).length, 0);
  });
});

describe('known-vulnerable-versions: Node pins that differ from the scanning machine', () => {
  it('flags engines.node, .nvmrc and Dockerfile pins below the fixed line or on an end-of-life line', () => {
    assert.equal(run('package.json', pkg({ engines: { node: '>=20' } })).length, 1);
    assert.equal(run('package.json', pkg({ engines: { node: '>=24.19.0' } })).length, 1);
    assert.equal(run('.nvmrc', '20.18.1\n').length, 1);
    assert.equal(run('.nvmrc', 'v24.19.0').length, 1);
    assert.equal(run('Dockerfile', 'FROM node:20-alpine\nRUN npm ci').length, 1);
    assert.equal(run('Dockerfile', 'FROM node:24.19.0-slim AS build\nFROM node:24.19.0-slim').length, 2);
    const f = run('Dockerfile', 'FROM node:22.23.0')[0];
    assert.match(f.message, /below the fixed version 22\.23\.4/);
    assert.match(f.fix, /container is what ships/);
  });
  it('does NOT flag fixed pins, floating tags on a fixed line, or non-node images', () => {
    assert.equal(run('package.json', pkg({ engines: { node: '>=24.22.1' } })).length, 0);
    assert.equal(run('.nvmrc', '24.22.1').length, 0);
    assert.equal(run('Dockerfile', 'FROM node:24\nFROM node:24-alpine').length, 0);
    assert.equal(run('Dockerfile', 'FROM python:3.13-slim\nFROM nginx:1.27').length, 0);
    assert.equal(run('Dockerfile', '# FROM node:18 was here\nFROM node:26.12.1').length, 0);
  });
});

describe('known-vulnerable-versions: Python pins', () => {
  it('flags the poisoned LiteLLM builds as critical and a loose LiteLLM pin as a warning', () => {
    const f = run('requirements.txt', 'requests==2.32.3\nlitellm==1.107.0\n')[0];
    assert.equal(f.severity, 'critical');
    assert.match(f.fix, /litellm==1\.106\.2/);
    assert.equal(run('pyproject.toml', '"litellm==1.82.7",')[0].severity, 'critical');
    assert.equal(run('requirements.txt', 'litellm>=1.86.2,<2.0').length, 1);
    assert.equal(run('requirements.txt', 'litellm>=1.86.2,<2.0')[0].severity, 'warning');
    assert.equal(run('requirements.txt', 'litellm\n').length, 1);
  });
  it('does NOT flag a safe exact LiteLLM pin, and flags old certifi only', () => {
    assert.equal(run('requirements.txt', 'litellm==1.106.2').length, 0);
    assert.equal(run('requirements.txt', 'certifi==2026.7.22').length, 1);
    assert.equal(run('requirements.txt', 'certifi==2025.1.31').length, 1);
    assert.equal(run('requirements.txt', 'certifi==2026.10.19').length, 0);
    assert.equal(run('requirements.txt', '# litellm==1.107.0 removed\nfastapi==0.115.0').length, 0);
  });
});

describe('known-vulnerable-versions: scope', () => {
  it('ignores files it does not own', () => {
    assert.equal(run('src/app.js', 'const next = "16.0.0";').length, 0);
    assert.equal(run('README.md', 'FROM node:18').length, 0);
  });
  it('carries CWE and OWASP tags and the advisory date on every finding', () => {
    const f = run('package.json', pkg({ dependencies: { next: '16.0.0' } }))[0];
    assert.equal(f.cweId, 'CWE-1104');
    assert.equal(f.owaspCategory, 'A06:2021');
    assert.match(f.fix, /2026-10-21/);
  });
});
