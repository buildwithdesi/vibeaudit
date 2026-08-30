import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { COSIGN_RELEASE_SHA256 } from '../src/adapters/cosign.js';
import { runDoctor } from '../src/doctor.js';

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
