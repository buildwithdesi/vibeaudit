import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  buildOfficialSkillBaseline,
  officialSkillAssetPaths,
  verifyOfficialSkillBundle,
} from '../src/agent-bundle.js';
import {
  createCosignVerificationSession,
  publisherIdentityForVersion,
  VIBEAUDIT_OIDC_ISSUER,
} from '../src/adapters/cosign.js';

const PUBLISHER_IDENTITY = publisherIdentityForVersion('1.4.0');

test('official skill baseline deterministically binds package version, path, size, and digest', () => {
  const paths = officialSkillAssetPaths();
  const expected = buildOfficialSkillBaseline();
  const committed = JSON.parse(readFileSync(paths.baseline, 'utf8'));

  assert.deepEqual(committed, expected);
  assert.deepEqual(Object.keys(committed), ['schemaVersion', 'kind', 'publisher', 'package', 'version', 'files']);
  assert.deepEqual(committed.files, [{
    path: 'src/data/agent-skill.md',
    sha256: '310eede00da410197f525c732e1f506dc475e41509aea2b3c928be55e5b3c83d',
    size: 2108,
  }]);
});

test('official skill verification requires valid Cosign bundles for the skill and its hash baseline', () => {
  const paths = officialSkillAssetPaths();
  const calls = [];
  const result = verifyOfficialSkillBundle({
    verifyArtifact(artifact, bundle) {
      calls.push([artifact, bundle]);
      const content = readFileSync(artifact);
      return {
        tool: 'cosign',
        status: 'verified',
        verified: true,
        artifact,
        bundle,
        artifactSha256: createHash('sha256').update(content).digest('hex'),
        artifactSize: content.length,
        publisherIdentityPolicy: PUBLISHER_IDENTITY,
        oidcIssuer: VIBEAUDIT_OIDC_ISSUER,
        transparencyLogVerified: true,
      };
    },
  });

  assert.deepEqual(calls, [
    [paths.baseline, paths.baselineBundle],
    [paths.skill, paths.skillBundle],
  ]);
  assert.equal(result.verified, true);
  assert.equal(result.transparencyLogVerified, true);
  assert.deepEqual(result.baseline, buildOfficialSkillBaseline());
});

test('official skill verification rejects evidence for different bytes', () => {
  assert.throws(() => verifyOfficialSkillBundle({
    verifyArtifact(artifact, bundle) {
      return {
        tool: 'cosign',
        status: 'verified',
        verified: true,
        artifact,
        bundle,
        artifactSha256: '0'.repeat(64),
        artifactSize: 1,
        publisherIdentityPolicy: PUBLISHER_IDENTITY,
        oidcIssuer: VIBEAUDIT_OIDC_ISSUER,
        transparencyLogVerified: true,
      };
    },
  }), /verified bytes do not match/i);
});

test('one Cosign session authenticates its verifier once across repeated signed bundle checks', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-agent-bundle-session-'));
  const dataDir = join(root, 'src', 'data');
  mkdirSync(dataDir, { recursive: true });
  const skill = Buffer.from('# Trusted skill\n');
  const baseline = {
    schemaVersion: 1,
    kind: 'vibeaudit-agent-skill-baseline',
    publisher: 'https://github.com/buildwithdesi/vibeaudit',
    package: '@jackdog668/vibeaudit',
    version: '1.4.0',
    files: [{
      path: 'src/data/agent-skill.md',
      sha256: createHash('sha256').update(skill).digest('hex'),
      size: skill.length,
    }],
  };
  writeFileSync(join(root, 'package.json'), '{"version":"1.4.0"}\n');
  writeFileSync(join(dataDir, 'agent-skill.md'), skill);
  writeFileSync(join(dataDir, 'agent-skill.md.sigstore.json'), '{}\n');
  writeFileSync(join(dataDir, 'agent-skill-baseline.json'), `${JSON.stringify(baseline)}\n`);
  writeFileSync(join(dataDir, 'agent-skill-baseline.json.sigstore.json'), '{}\n');

  let preparations = 0;
  let verifications = 0;
  const session = createCosignVerificationSession({
    targetDir: root,
    findExecutable: () => '/trusted/cosign',
    prepareVerifier(executable) {
      preparations += 1;
      return { path: executable, version: '3.1.3', sha256: 'approved-test-verifier' };
    },
    runner() {
      verifications += 1;
      return { status: 0, stdout: 'Verified OK\n', stderr: '' };
    },
  });
  try {
    verifyOfficialSkillBundle({ root, verificationSession: session });
    verifyOfficialSkillBundle({ root, verificationSession: session });
    assert.equal(preparations, 1);
    assert.equal(verifications, 4);
  } finally {
    session.close();
    rmSync(root, { recursive: true, force: true });
  }
});
