import { spawnSync } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  rmSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import { findTrustedExecutable } from '../trusted-tools.js';

const MAX_ARTIFACT_BYTES = 5 * 1024 * 1024;
const MAX_BUNDLE_BYTES = 10 * 1024 * 1024;
const MAX_COSIGN_BYTES = 256 * 1024 * 1024;

export const COSIGN_VERSION = '3.1.3';
export const VIBEAUDIT_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';

// Official v3.1.3 release checksums from sigstore/cosign's cosign_checksums.txt.
// Vibe Audit accepts only these binaries, then executes a private staged copy.
export const COSIGN_RELEASE_SHA256 = Object.freeze({
  'darwin-x64': '2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c',
  'darwin-arm64': '5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76',
  'linux-x64': '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71',
  'linux-arm64': 'c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a',
  'win32-x64': '9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be',
});

export function publisherIdentityForVersion(version) {
  if (!/^\d+\.\d+\.\d+$/.test(version || '')) {
    throw new Error(`Cosign requires an exact stable package version, received: ${version || 'missing'}`);
  }
  return `https://github.com/buildwithdesi/vibeaudit/.github/workflows/ci.yml@refs/tags/v${version}`;
}

/** Authenticate a local Cosign binary by digest without executing it. */
export function inspectCosignExecutable(executable) {
  try {
    const inspected = snapshotCosignExecutable(executable);
    if (!inspected.expectedSha256) {
      return {
        status: 'unsupported',
        executable: inspected.source,
        versionPolicy: `=${COSIGN_VERSION}`,
        sha256: inspected.sha256,
        expectedSha256: null,
        reason: `Cosign ${COSIGN_VERSION} is not approved for ${process.platform}-${process.arch}.`,
      };
    }
    return {
      status: inspected.approved ? 'ready' : 'rejected',
      executable: inspected.source,
      versionPolicy: `=${COSIGN_VERSION}`,
      sha256: inspected.sha256,
      expectedSha256: inspected.expectedSha256,
      ...(inspected.approved ? {} : {
        reason: `The executable does not match the approved Cosign ${COSIGN_VERSION} release digest.`,
      }),
    };
  } catch {
    return {
      status: 'rejected',
      executable: resolve(executable),
      versionPolicy: `=${COSIGN_VERSION}`,
      expectedSha256: COSIGN_RELEASE_SHA256[`${process.platform}-${process.arch}`] || null,
      reason: 'The external Cosign executable could not be authenticated.',
    };
  }
}

/**
 * Verify one official Vibe Audit blob against its Sigstore bundle. The files
 * and approved verifier are copied into a private workspace before execution,
 * so writable package files and PATH tools cannot change after approval.
 */
export function createCosignVerificationSession(options = {}) {
  const targetDir = resolve(options.targetDir || process.cwd());
  const findExecutable = options.findExecutable
    || ((name, target) => findTrustedExecutable(name, target, options.env));
  let executable;
  try {
    executable = findExecutable('cosign', targetDir);
  } catch {
    executable = null;
  }

  const workspace = mkdtempSync(join(tmpdir(), 'vibeaudit-cosign-session-'));
  let verifier;
  let preparationReason;
  if (executable) {
    try {
      verifier = (options.prepareVerifier || prepareApprovedCosign)(executable, workspace);
    } catch (error) {
      preparationReason = safePreparationFailure(error);
    }
  }
  let closed = false;

  return {
    verifyArtifact(artifactPath, bundlePath, verificationOptions = {}) {
      if (closed) throw new Error('The Cosign verification session is closed.');
      return verifyWithSession({
        artifactPath,
        bundlePath,
        verificationOptions,
        sessionOptions: options,
        workspace,
        executable,
        verifier,
        preparationReason,
      });
    },
    close() {
      if (closed) return;
      closed = true;
      rmSync(workspace, { recursive: true, force: true });
    },
  };
}

export function verifyCosignArtifact(artifactPath, bundlePath, options = {}) {
  const session = createCosignVerificationSession({
    ...options,
    targetDir: options.targetDir || dirname(resolve(artifactPath)),
  });
  try {
    return session.verifyArtifact(artifactPath, bundlePath, options);
  } finally {
    session.close();
  }
}

function verifyWithSession({
  artifactPath,
  bundlePath,
  verificationOptions,
  sessionOptions,
  workspace,
  executable,
  verifier,
  preparationReason,
}) {
  const artifact = snapshotRegularFile(artifactPath, MAX_ARTIFACT_BYTES, 'artifact');
  const bundle = snapshotRegularFile(bundlePath, MAX_BUNDLE_BYTES, 'signature bundle');
  const publisherIdentityPolicy = publisherIdentityForVersion(verificationOptions.expectedVersion);
  if (!executable) {
    return evidence({
      status: 'unavailable',
      reason: 'An external Cosign executable was not found outside the artifact directory.',
      artifact,
      bundle,
      publisherIdentityPolicy,
    });
  }
  if (!verifier) {
    return evidence({
      status: 'failed',
      reason: preparationReason || 'The external Cosign executable could not be authenticated.',
      artifact,
      bundle,
      publisherIdentityPolicy,
    });
  }

  const verificationDir = mkdtempSync(join(workspace, 'artifact-'));
  try {
    const stagedArtifact = join(verificationDir, 'artifact.blob');
    const stagedBundle = join(verificationDir, 'bundle.sigstore.json');
    writeFileSync(stagedArtifact, artifact.bytes, { flag: 'wx', mode: 0o600 });
    writeFileSync(stagedBundle, bundle.bytes, { flag: 'wx', mode: 0o600 });

    const args = [
      'verify-blob',
      stagedArtifact,
      '--bundle', stagedBundle,
      '--certificate-identity', publisherIdentityPolicy,
      '--certificate-oidc-issuer', VIBEAUDIT_OIDC_ISSUER,
      '--offline',
    ];
    const runner = sessionOptions.runner
      || ((command, commandArgs, runOptions) => spawnSync(command, commandArgs, runOptions));
    let run;
    try {
      run = runner(verifier.path, args, {
        cwd: verificationDir,
        env: isolatedEnvironment(sessionOptions.env),
        encoding: 'utf8',
        timeout: sessionOptions.timeoutMs || 30_000,
        maxBuffer: 1024 * 1024,
        windowsHide: true,
        shell: false,
      });
    } catch (error) {
      return evidence({
        status: 'failed',
        reason: error?.code === 'ETIMEDOUT' ? 'Cosign verification timed out.' : 'Cosign verification could not start.',
        artifact,
        bundle,
        publisherIdentityPolicy,
        verifier,
      });
    }
    if (run?.error || run?.signal || run?.status !== 0) {
      return evidence({
        status: 'failed',
        reason: run?.error?.code === 'ETIMEDOUT'
          ? 'Cosign verification timed out.'
          : 'Cosign rejected the artifact signature, publisher identity, or transparency proof.',
        artifact,
        bundle,
        publisherIdentityPolicy,
        verifier,
      });
    }
    if (!sourceStillMatches(artifact) || !sourceStillMatches(bundle)) {
      return evidence({
        status: 'failed',
        reason: 'The artifact or signature bundle changed during Cosign verification.',
        artifact,
        bundle,
        publisherIdentityPolicy,
        verifier,
      });
    }
    return evidence({
      status: 'verified',
      verified: true,
      transparencyLogVerified: true,
      artifact,
      bundle,
      publisherIdentityPolicy,
      verifier,
    });
  } finally {
    rmSync(verificationDir, { recursive: true, force: true });
  }
}

function snapshotRegularFile(filePath, limit, label) {
  const path = resolve(filePath);
  let info;
  try {
    info = lstatSync(path);
  } catch {
    throw new Error(`Cosign ${label} is missing: ${path}`);
  }
  if (info.isSymbolicLink() || normalizePath(realpathSync(path)) !== normalizePath(path)) {
    throw new Error(`Refusing symbolic-link Cosign ${label}: ${path}`);
  }
  if (!info.isFile()) throw new Error(`Cosign ${label} is not a regular file: ${path}`);
  if (info.size > limit) throw new Error(`Cosign ${label} exceeds the ${limit} byte safety limit: ${path}`);
  const bytes = readFileSync(path);
  if (bytes.length > limit) throw new Error(`Cosign ${label} exceeds the ${limit} byte safety limit: ${path}`);
  return {
    path,
    bytes,
    size: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}

function sourceStillMatches(snapshot) {
  try {
    const current = snapshotRegularFile(snapshot.path, snapshot.bytes.length, 'source file');
    return current.size === snapshot.size && current.sha256 === snapshot.sha256;
  } catch {
    return false;
  }
}

function prepareApprovedCosign(executable, workspace) {
  const staged = join(workspace, process.platform === 'win32' ? 'cosign.exe' : 'cosign');
  const inspected = snapshotCosignExecutable(executable, staged);
  if (!inspected.expectedSha256 || !inspected.approved) {
    throw new Error(`The executable does not match the approved Cosign ${COSIGN_VERSION} release digest.`);
  }
  chmodSync(staged, 0o700);
  return { path: staged, version: COSIGN_VERSION, sha256: inspected.sha256 };
}

function snapshotCosignExecutable(executable, stagedPath) {
  const source = resolve(executable);
  const info = lstatSync(source);
  if (info.isSymbolicLink() || normalizePath(realpathSync(source)) !== normalizePath(source) || !info.isFile()) {
    throw new Error('The external Cosign executable is not a regular, direct file.');
  }
  if (info.size > MAX_COSIGN_BYTES) throw new Error('The external Cosign executable exceeds its safety limit.');

  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(64 * 1024);
  let sourceHandle;
  let stagedHandle;
  try {
    sourceHandle = openSync(source, 'r');
    const opened = fstatSync(sourceHandle);
    if (!opened.isFile() || opened.size > MAX_COSIGN_BYTES) throw new Error('The external Cosign executable is invalid.');
    if (stagedPath) stagedHandle = openSync(stagedPath, 'wx', 0o700);
    let total = 0;
    while (true) {
      const count = readSync(sourceHandle, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
      if (stagedHandle !== undefined) writeAll(stagedHandle, buffer, count);
      total += count;
      if (total > MAX_COSIGN_BYTES) throw new Error('The external Cosign executable exceeds its safety limit.');
    }
  } finally {
    if (sourceHandle !== undefined) closeSync(sourceHandle);
    if (stagedHandle !== undefined) closeSync(stagedHandle);
  }

  const digest = hash.digest('hex');
  const expected = COSIGN_RELEASE_SHA256[`${process.platform}-${process.arch}`];
  const approved = expected
    && timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(expected, 'hex'));
  return {
    source,
    sha256: digest,
    expectedSha256: expected || null,
    approved: Boolean(approved),
  };
}

function writeAll(handle, buffer, length) {
  let offset = 0;
  while (offset < length) offset += writeSync(handle, buffer, offset, length - offset);
}

function safePreparationFailure(error) {
  if (/approved Cosign|regular, direct file|safety limit|invalid/.test(error?.message || '')) return error.message;
  return 'The external Cosign executable could not be authenticated.';
}

function evidence({
  status,
  verified = false,
  transparencyLogVerified = false,
  reason,
  artifact,
  bundle,
  publisherIdentityPolicy,
  verifier,
}) {
  return {
    tool: 'cosign',
    status,
    verified,
    artifact: artifact.path,
    bundle: bundle.path,
    artifactSha256: artifact.sha256,
    artifactSize: artifact.size,
    bundleSha256: bundle.sha256,
    bundleSize: bundle.size,
    publisherIdentityPolicy,
    oidcIssuer: VIBEAUDIT_OIDC_ISSUER,
    transparencyLogVerified,
    ...(verifier ? { verifierVersion: verifier.version, verifierSha256: verifier.sha256 } : {}),
    ...(reason ? { reason } : {}),
  };
}

function normalizePath(value) {
  const path = resolve(value);
  return process.platform === 'win32' ? path.toLowerCase() : path;
}

function isolatedEnvironment(source = process.env) {
  const allowed = ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'LANG', 'LC_ALL'];
  return Object.fromEntries(allowed.filter((key) => source?.[key] !== undefined).map((key) => [key, source[key]]));
}
