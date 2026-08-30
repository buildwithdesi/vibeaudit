import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { COSIGN_RELEASE_SHA256 } from '../src/adapters/cosign.js';
import { formatDoctor, runDoctor } from '../src/doctor.js';

test('doctor rejects a forged Cosign executable without running it', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-doctor-'));
  const executable = join(root, process.platform === 'win32' ? 'cosign.exe' : 'cosign');
  writeFileSync(executable, 'forged cosign');
  try {
    const report = runDoctor({
      targetDir: root,
      findExecutable(name) {
        return name === 'cosign' ? executable : join(root, name);
      },
    });
    const cosign = report.checks.find((check) => check.id === 'cosign');
    assert.equal(cosign.status, 'rejected');
    assert.equal(cosign.versionPolicy, '=3.1.3');
    assert.equal(cosign.expectedSha256, COSIGN_RELEASE_SHA256[`${process.platform}-${process.arch}`]);
    assert.match(cosign.fix, /does not match the approved Cosign 3\.1\.3 release digest/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('doctor does not call an unauthenticated OSV executable ready', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-doctor-'));
  const executable = join(root, process.platform === 'win32' ? 'osv-scanner.exe' : 'osv-scanner');
  writeFileSync(executable, 'unverified osv scanner');
  try {
    const report = runDoctor({
      targetDir: root,
      findExecutable(name) {
        return name === 'osv-scanner' ? executable : null;
      },
    });
    const osv = report.checks.find((check) => check.id === 'osv-scanner');
    assert.equal(osv.status, 'available-unverified');
    assert.equal(report.status, 'attention');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('doctor gives a supported-environment fix for unsupported Cosign platforms', () => {
  const report = runDoctor({
    findExecutable(name) {
      return name === 'cosign' ? '/security/cosign' : null;
    },
    inspectCosign() {
      return { status: 'unsupported', reason: 'No approved Cosign digest exists for this platform.' };
    },
  });
  const cosign = report.checks.find((check) => check.id === 'cosign');
  assert.equal(cosign.status, 'unsupported');
  assert.match(cosign.fix, /supported platform/i);
  assert.doesNotMatch(cosign.fix, /reinstall/i);
});

test('doctor does not recommend installing Cosign on an unsupported platform', () => {
  const report = runDoctor({
    cosignExpectedSha256: null,
    findExecutable() {
      return null;
    },
  });
  const cosign = report.checks.find((check) => check.id === 'cosign');
  assert.equal(cosign.status, 'unsupported');
  assert.match(cosign.fix, /supported platform/i);
  assert.doesNotMatch(cosign.fix, /install Cosign/i);
});

test('doctor stays usable while warning about an unauthenticated OSV executable', () => {
  const report = runDoctor({
    findExecutable(name) {
      return name === 'gitleaks' ? null : `/security/${name}`;
    },
    inspectCosign() {
      return { status: 'ready', sha256: 'a'.repeat(64) };
    },
  });
  assert.equal(report.status, 'usable-with-warnings');
  assert.equal(report.operational, true);
});

test('doctor text shows the observed Cosign digest', () => {
  const output = formatDoctor({
    status: 'ready',
    checks: [{
      id: 'cosign',
      name: 'Cosign',
      status: 'ready',
      required: true,
      sha256: 'b'.repeat(64),
      source: 'https://example.test/cosign',
    }],
  });
  assert.match(output, new RegExp(`Actual SHA-256: ${'b'.repeat(64)}`));
});
