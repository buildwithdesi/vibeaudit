import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { dockerRootUser } from '../../src/rules/docker-root-user.js';
import { exposedDatabasePort } from '../../src/rules/exposed-database-port.js';

function makeFile(relativePath, content) {
  return { path: `/project/${relativePath}`, relativePath, content, lines: content.split('\n') };
}

// ── docker-root-user ────────────────────────────────────────────────────────

describe('docker-root-user', () => {
  it('detects missing USER directive', () => {
    const file = makeFile('Dockerfile', 'FROM node:18\nCOPY . .\nCMD ["node", "server.js"]');
    const findings = dockerRootUser.check(file);
    assert.ok(findings.length > 0, 'Should flag Dockerfile with no USER directive');
    assert.match(findings[0].message, /no USER directive/i);
  });

  it('detects USER root without switch back', () => {
    const file = makeFile('Dockerfile', 'FROM node:18\nUSER root\nRUN apt-get update\nCMD ["node", "server.js"]');
    const findings = dockerRootUser.check(file);
    assert.ok(findings.length > 0, 'Should flag USER root as final directive');
  });

  it('passes with non-root user', () => {
    const file = makeFile('Dockerfile', 'FROM node:18\nRUN adduser -S app\nUSER app\nCMD ["node", "server.js"]');
    assert.equal(dockerRootUser.check(file).length, 0);
  });

  it('passes multi-stage with final non-root user', () => {
    const file = makeFile('Dockerfile', [
      'FROM node:18 AS build', 'USER root', 'RUN npm run build',
      'FROM node:18-slim', 'USER app', 'CMD ["node", "server.js"]',
    ].join('\n'));
    assert.equal(dockerRootUser.check(file).length, 0);
  });

  it('matches Dockerfile.dev and Dockerfile.prod', () => {
    const dev = makeFile('Dockerfile.dev', 'FROM node:18\nCMD ["node", "server.js"]');
    const prod = makeFile('Dockerfile.prod', 'FROM node:18\nCMD ["node", "server.js"]');
    assert.ok(dockerRootUser.check(dev).length > 0);
    assert.ok(dockerRootUser.check(prod).length > 0);
  });

  it('ignores non-Dockerfile files', () => {
    const file = makeFile('src/app.js', 'FROM node:18\nCMD ["node", "server.js"]');
    assert.equal(dockerRootUser.check(file).length, 0);
  });
});

// ── exposed-database-port ───────────────────────────────────────────────────

describe('exposed-database-port', () => {
  it('detects PostgreSQL port exposed', () => {
    const file = makeFile('docker-compose.yml', [
      'services:', '  db:', '    image: postgres', '    ports:', '      - "5432:5432"',
    ].join('\n'));
    const findings = exposedDatabasePort.check(file);
    assert.ok(findings.length > 0, 'Should flag exposed PostgreSQL port');
    assert.match(findings[0].message, /PostgreSQL/);
  });

  it('detects MySQL port exposed', () => {
    const file = makeFile('docker-compose.yml', [
      'services:', '  db:', '    image: mysql', '    ports:', '      - 3306:3306',
    ].join('\n'));
    assert.ok(exposedDatabasePort.check(file).length > 0);
  });

  it('detects Redis port exposed', () => {
    const file = makeFile('docker-compose.yml', [
      'services:', '  cache:', '    image: redis', '    ports:', '      - 6379:6379',
    ].join('\n'));
    assert.ok(exposedDatabasePort.check(file).length > 0);
  });

  it('detects MongoDB port exposed', () => {
    const file = makeFile('docker-compose.yml', [
      'services:', '  mongo:', '    image: mongo', '    ports:', '      - "27017:27017"',
    ].join('\n'));
    assert.ok(exposedDatabasePort.check(file).length > 0);
  });

  it('passes with expose instead of ports', () => {
    const file = makeFile('docker-compose.yml', [
      'services:', '  db:', '    image: postgres', '    expose:', '      - "5432"',
    ].join('\n'));
    assert.equal(exposedDatabasePort.check(file).length, 0);
  });

  it('passes non-DB port exposed', () => {
    const file = makeFile('docker-compose.yml', [
      'services:', '  web:', '    image: nginx', '    ports:', '      - "80:80"',
    ].join('\n'));
    assert.equal(exposedDatabasePort.check(file).length, 0);
  });

  it('ignores non-compose files', () => {
    const file = makeFile('config.yml', 'ports:\n  - 5432:5432');
    assert.equal(exposedDatabasePort.check(file).length, 0);
  });

  it('matches docker-compose.dev.yml', () => {
    const file = makeFile('docker-compose.dev.yml', [
      'services:', '  db:', '    image: postgres', '    ports:', '      - "5432:5432"',
    ].join('\n'));
    assert.ok(exposedDatabasePort.check(file).length > 0);
  });
});
