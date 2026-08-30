import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import { runOsvAdapter, discoverOsvLockfiles } from '../src/adapters/osv.js';
import { getDefaultConfig } from '../src/config.js';
import { audit } from '../src/index.js';

function approvedTestVerifier(executable) {
  return {
    path: executable,
    version: '2.5.1',
    sha256: 'approved-test-verifier',
  };
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-osv-test-'));
  const files = {
    npm: join(root, 'web', 'package-lock.json'),
    python: join(root, 'worker', 'requirements.txt'),
    pythonLock: join(root, 'worker', 'Pipfile.lock'),
    go: join(root, 'service', 'go.mod'),
    rust: join(root, 'cli', 'Cargo.lock'),
    container: join(root, 'Dockerfile'),
    sbom: join(root, 'image', 'bom.json'),
  };
  for (const [name, path] of Object.entries(files)) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, name === 'sbom'
      ? JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [] })
      : `${name} fixture\n`);
  }
  const fakeSbom = join(root, 'notes', 'bom.json');
  mkdirSync(dirname(fakeSbom), { recursive: true });
  writeFileSync(fakeSbom, JSON.stringify({ title: 'ordinary application data' }));
  writeFileSync(join(root, 'notes.txt'), 'not a dependency manifest\n');
  return { root, files };
}

test('OSV inventory recognizes requested ecosystems and validates SBOM content', () => {
  const { root, files } = fixture();
  try {
    const inventory = discoverOsvLockfiles(root);
    assert.deepEqual(inventory.map((file) => file.relativePath).sort(), [
      'Dockerfile',
      'cli/Cargo.lock',
      'image/bom.json',
      'service/go.mod',
      'web/package-lock.json',
      'worker/Pipfile.lock',
      'worker/requirements.txt',
    ]);
    assert.deepEqual([...new Set(inventory.map((file) => file.ecosystem))].sort(), [
      'Go', 'JavaScript', 'Python', 'Rust', 'SBOM', 'container',
    ]);
    assert.equal(inventory.some((file) => file.absolutePath === files.npm), true);
    assert.equal(inventory.some((file) => file.relativePath === 'notes/bom.json'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('OSV adapter fails closed without claiming unavailable inputs were scanned', () => {
  const { root } = fixture();
  try {
    const result = runOsvAdapter(root, { findExecutable: () => null });
    assert.equal(result.tool, 'osv-scanner');
    assert.equal(result.status, 'unavailable');
    assert.equal(result.coverage.complete, false);
    assert.equal(result.coverage.discovered, 6);
    assert.equal(result.coverage.scanned, 0);
    assert.equal(result.coverage.sboms, 1);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].severity, 'warning');
    assert.match(result.findings[0].message, /trusted OSV-Scanner/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('OSV adapter rejects a forged executable before running it', () => {
  const { root } = fixture();
  const toolRoot = mkdtempSync(join(tmpdir(), 'vibeaudit-osv-tool-'));
  const executable = join(toolRoot, process.platform === 'win32' ? 'osv-scanner.exe' : 'osv-scanner');
  writeFileSync(executable, 'forged osv scanner');
  let ran = false;
  try {
    const result = runOsvAdapter(root, {
      findExecutable: () => executable,
      runner: () => {
        ran = true;
        return { status: 0, stdout: JSON.stringify({ results: [] }), stderr: '' };
      },
    });
    assert.equal(result.status, 'failed');
    assert.equal(result.coverage.complete, false);
    assert.equal(ran, false);
    assert.match(result.coverage.reason, /approved OSV-Scanner 2\.5\.1 release digest/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(toolRoot, { recursive: true, force: true });
  }
});

test('OSV adapter stages only recognized inputs and maps transitive vulnerability groups', () => {
  const { root } = fixture();
  let invocation;
  try {
    const result = runOsvAdapter(root, {
      findExecutable: () => 'C:/trusted/osv-scanner.exe',
      prepareVerifier: approvedTestVerifier,
      runner(executable, args, options) {
        invocation = { executable, args, options };
        const lockfileArg = args.find((arg) => arg.endsWith('package-lock.json'));
        assert.ok(lockfileArg);
        const requirementsArg = args.find((arg) => arg.endsWith('requirements.txt'));
        const pipfileArg = args.find((arg) => arg.endsWith('Pipfile.lock'));
        const sbomArg = args.find((arg) => arg.endsWith('bom.json'));
        assert.match(requirementsArg, /^--lockfile=requirements\.txt:/);
        assert.doesNotMatch(pipfileArg, /^--lockfile=requirements\.txt:/);
        assert.ok(sbomArg);
        const lockfile = lockfileArg.slice('--lockfile='.length).replace(/^:/, '');
        assert.equal(lockfile.includes(root), false);
        return {
          status: 1,
          stderr: 'human output must never be copied into findings',
          stdout: JSON.stringify({
            results: [{
              source: { path: lockfile, type: 'lockfile' },
              packages: [{
                package: { name: 'transitive-demo', version: '1.2.3', ecosystem: 'npm' },
                vulnerabilities: [
                  {
                    id: 'GHSA-demo-0000-0000',
                    aliases: ['CVE-2099-0001'],
                    summary: 'Demo package vulnerability',
                    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
                    affected: [
                      { package: { name: 'other-package', ecosystem: 'npm' }, ranges: [{ events: [{ fixed: '9.9.9' }] }] },
                      { package: { name: 'transitive-demo', ecosystem: 'npm' }, ranges: [{ events: [{ fixed: '1.2.4' }] }] },
                    ],
                  },
                  {
                    id: 'CVE-2099-0001',
                    aliases: ['GHSA-demo-0000-0000'],
                    summary: 'Duplicate alias record',
                  },
                ],
                groups: [{ ids: ['GHSA-demo-0000-0000', 'CVE-2099-0001'] }],
              }],
            }],
          }),
        };
      },
    });
    assert.equal(result.status, 'completed');
    assert.equal(result.toolVersion, '2.5.1');
    assert.equal(result.toolSha256, 'approved-test-verifier');
    assert.equal(result.coverage.complete, false);
    assert.equal(result.coverage.scanned, 6);
    assert.equal(result.coverage.vulnerabilities, 1);
    assert.equal(result.findings.length, 2);
    assert.equal(result.findings[0].severity, 'critical');
    assert.equal(result.findings[0].cvssScore, 9.8);
    assert.equal(result.findings[0].file, 'web/package-lock.json');
    assert.match(result.findings[0].message, /transitive-demo@1\.2\.3/);
    assert.match(result.findings[0].fix, /1\.2\.4/);
    assert.doesNotMatch(result.findings[0].fix, /9\.9\.9/);
    assert.equal(JSON.stringify(result).includes('human output'), false);
    assert.equal(invocation.executable, 'C:/trusted/osv-scanner.exe');
    assert.deepEqual(invocation.args.slice(0, 3), ['scan', 'source', '--format=json']);
    assert.ok(invocation.args.includes('--no-ignore'));
    assert.ok(invocation.args.includes('--no-call-analysis=go'));
    assert.equal(invocation.options.shell, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('OSV adapter accepts a clean report and records completed coverage', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-osv-clean-'));
  writeFileSync(join(root, 'go.mod'), 'module example.test/clean\n\ngo 1.23\n');
  try {
    const result = runOsvAdapter(root, {
      findExecutable: () => '/trusted/osv-scanner',
      prepareVerifier: approvedTestVerifier,
      runner: () => ({ status: 0, stdout: JSON.stringify({ results: [] }), stderr: '' }),
    });
    assert.equal(result.status, 'completed');
    assert.equal(result.coverage.complete, true);
    assert.equal(result.coverage.discovered, 1);
    assert.equal(result.coverage.scanned, 1);
    assert.equal(result.coverage.vulnerabilities, 0);
    assert.deepEqual(result.findings, []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('OSV adapter fails closed on malformed output without exposing stderr', () => {
  const { root } = fixture();
  try {
    const result = runOsvAdapter(root, {
      findExecutable: () => '/trusted/osv-scanner',
      prepareVerifier: approvedTestVerifier,
      runner: () => ({ status: 0, stdout: '{not-json}', stderr: 'private endpoint details' }),
    });
    assert.equal(result.status, 'failed');
    assert.equal(result.coverage.complete, false);
    assert.equal(result.coverage.scanned, 0);
    assert.match(result.coverage.reason, /invalid JSON/i);
    assert.equal(JSON.stringify(result).includes('private endpoint'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('audit pipeline runs OSV and preserves adapter CVSS metadata', async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-osv-pipeline-'));
  writeFileSync(join(root, 'go.mod'), 'module example.test/pipeline\n\ngo 1.23\n');
  writeFileSync(join(root, 'safe.js'), 'export const answer = 42;\n');
  const originalLog = console.log;
  console.log = () => {};
  try {
    const result = await audit(root, {
      format: 'json',
      strict: true,
      config: { ...getDefaultConfig(), osv: true },
      osvOptions: {
        findExecutable: () => '/trusted/osv-scanner',
        prepareVerifier: approvedTestVerifier,
        runner(_executable, args) {
          const goArg = args.find((arg) => arg.endsWith('go.mod'));
          const path = goArg.slice('--lockfile='.length).replace(/^:/, '');
          return {
            status: 1,
            stdout: JSON.stringify({
              results: [{
                source: { path, type: 'lockfile' },
                packages: [{
                  package: { name: 'example.test/dependency', version: '1.0.0', ecosystem: 'Go' },
                  vulnerabilities: [{
                    id: 'GO-2099-0001',
                    summary: 'Pipeline fixture',
                    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
                  }],
                }],
              }],
            }),
            stderr: '',
          };
        },
      },
    });
    const finding = result.findings.find((item) => item.osvId === 'GO-2099-0001');
    assert.ok(finding);
    assert.equal(finding.source, 'osv-scanner');
    assert.equal(finding.file, 'go.mod');
    assert.equal(finding.cvssScore, 9.8);
    assert.equal(result.exitCode, 1);
  } finally {
    console.log = originalLog;
    rmSync(root, { recursive: true, force: true });
  }
});
