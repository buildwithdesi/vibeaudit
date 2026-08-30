import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  VIBEAUDIT_OIDC_ISSUER,
  VIBEAUDIT_PUBLISHER_IDENTITY_REGEXP,
  verifyCosignArtifact,
} from '../src/adapters/cosign.js';

test('Cosign verifies artifact digest, publisher identity, and bundled transparency proof offline', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-cosign-'));
  const artifact = join(root, 'agent-skill.md');
  const bundle = join(root, 'agent-skill.md.sigstore.json');
  writeFileSync(artifact, '# trusted skill\n');
  writeFileSync(bundle, '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n');
  let invocation;
  try {
    const result = verifyCosignArtifact(artifact, bundle, {
      targetDir: root,
      env: { PATH: 'C:/trusted-tools', SECRET_TOKEN: 'must-not-leak' },
      findExecutable: () => 'C:/trusted-tools/cosign.exe',
      runner(executable, args, options) {
        invocation = { executable, args, options };
        return { status: 0, stdout: 'Verified OK\n', stderr: '' };
      },
    });

    assert.deepEqual(result, {
      tool: 'cosign',
      status: 'verified',
      verified: true,
      artifact,
      bundle,
      publisherIdentity: VIBEAUDIT_PUBLISHER_IDENTITY_REGEXP,
      oidcIssuer: VIBEAUDIT_OIDC_ISSUER,
      transparencyLogVerified: true,
    });
    assert.equal(invocation.executable, 'C:/trusted-tools/cosign.exe');
    assert.deepEqual(invocation.args, [
      'verify-blob',
      artifact,
      '--bundle', bundle,
      '--certificate-identity-regexp', VIBEAUDIT_PUBLISHER_IDENTITY_REGEXP,
      '--certificate-oidc-issuer', VIBEAUDIT_OIDC_ISSUER,
      '--offline',
    ]);
    assert.equal(invocation.options.shell, false);
    assert.equal(invocation.options.env.SECRET_TOKEN, undefined);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('Cosign fails closed when no trusted verifier is installed', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-cosign-missing-'));
  const artifact = join(root, 'agent-skill.md');
  const bundle = join(root, 'agent-skill.md.sigstore.json');
  writeFileSync(artifact, '# trusted skill\n');
  writeFileSync(bundle, '{}\n');
  try {
    const result = verifyCosignArtifact(artifact, bundle, {
      targetDir: root,
      findExecutable: () => null,
    });
    assert.equal(result.status, 'unavailable');
    assert.equal(result.verified, false);
    assert.equal(result.transparencyLogVerified, false);
    assert.match(result.reason, /trusted Cosign executable/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('Cosign rejects failed verification without exposing tool output', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-cosign-rejected-'));
  const artifact = join(root, 'agent-skill.md');
  const bundle = join(root, 'agent-skill.md.sigstore.json');
  writeFileSync(artifact, '# altered skill\n');
  writeFileSync(bundle, '{}\n');
  try {
    const result = verifyCosignArtifact(artifact, bundle, {
      targetDir: root,
      findExecutable: () => '/trusted/cosign',
      runner: () => ({
        status: 1,
        stdout: '',
        stderr: 'private machine path and certificate internals',
      }),
    });
    assert.equal(result.status, 'failed');
    assert.equal(result.verified, false);
    assert.match(result.reason, /rejected the artifact signature/i);
    assert.equal(JSON.stringify(result).includes('private machine path'), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
