import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  VIBEAUDIT_OIDC_ISSUER,
  publisherIdentityForVersion,
  verifyCosignArtifact,
} from '../src/adapters/cosign.js';

const VERSION = '1.4.0';
const PUBLISHER_IDENTITY = publisherIdentityForVersion(VERSION);

function sha256(content) {
  return createHash('sha256').update(content).digest('hex');
}

function approvedTestVerifier(executable) {
  return {
    path: executable,
    version: '3.1.3',
    sha256: 'approved-test-verifier',
  };
}

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
      expectedVersion: VERSION,
      env: { PATH: 'C:/trusted-tools', SECRET_TOKEN: 'must-not-leak' },
      findExecutable: () => 'C:/trusted-tools/cosign.exe',
      prepareVerifier: approvedTestVerifier,
      runner(executable, args, options) {
        assert.equal(readFileSync(args[1], 'utf8'), '# trusted skill\n');
        assert.equal(readFileSync(args[3], 'utf8'), '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n');
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
      artifactSha256: sha256('# trusted skill\n'),
      artifactSize: 16,
      bundleSha256: sha256('{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n'),
      bundleSize: 62,
      publisherIdentityPolicy: PUBLISHER_IDENTITY,
      oidcIssuer: VIBEAUDIT_OIDC_ISSUER,
      transparencyLogVerified: true,
      verifierVersion: '3.1.3',
      verifierSha256: 'approved-test-verifier',
    });
    assert.equal(invocation.executable, 'C:/trusted-tools/cosign.exe');
    assert.equal(invocation.args[0], 'verify-blob');
    assert.notEqual(invocation.args[1], artifact);
    assert.equal(invocation.args[2], '--bundle');
    assert.notEqual(invocation.args[3], bundle);
    assert.deepEqual(invocation.args.slice(4), [
      '--certificate-identity', PUBLISHER_IDENTITY,
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
      expectedVersion: VERSION,
      findExecutable: () => null,
    });
    assert.equal(result.status, 'unavailable');
    assert.equal(result.verified, false);
    assert.equal(result.transparencyLogVerified, false);
    assert.match(result.reason, /external Cosign executable/i);
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
      expectedVersion: VERSION,
      findExecutable: () => '/trusted/cosign',
      prepareVerifier: approvedTestVerifier,
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

test('Cosign rejects a forged PATH executable before running it', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-cosign-forged-'));
  const toolRoot = mkdtempSync(join(tmpdir(), 'vibeaudit-cosign-tool-'));
  const artifact = join(root, 'agent-skill.md');
  const bundle = join(root, 'agent-skill.md.sigstore.json');
  const executable = join(toolRoot, process.platform === 'win32' ? 'cosign.exe' : 'cosign');
  writeFileSync(artifact, '# trusted skill\n');
  writeFileSync(bundle, '{}\n');
  writeFileSync(executable, 'malicious verifier');
  let ran = false;
  try {
    const result = verifyCosignArtifact(artifact, bundle, {
      targetDir: root,
      expectedVersion: VERSION,
      findExecutable: () => executable,
      runner: () => {
        ran = true;
        return { status: 0 };
      },
    });
    assert.equal(result.verified, false);
    assert.equal(ran, false);
    assert.match(result.reason, /approved Cosign 3\.1\.3 release digest/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(toolRoot, { recursive: true, force: true });
  }
});

test('Cosign rejects source bytes changed while verification runs', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeaudit-cosign-race-'));
  const artifact = join(root, 'agent-skill.md');
  const bundle = join(root, 'agent-skill.md.sigstore.json');
  writeFileSync(artifact, '# trusted skill\n');
  writeFileSync(bundle, '{}\n');
  try {
    const result = verifyCosignArtifact(artifact, bundle, {
      targetDir: root,
      expectedVersion: VERSION,
      findExecutable: () => '/trusted/cosign',
      prepareVerifier: approvedTestVerifier,
      runner: () => {
        writeFileSync(artifact, '# swapped skill\n');
        return { status: 0 };
      },
    });
    assert.equal(result.verified, false);
    assert.match(result.reason, /changed during Cosign verification/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
