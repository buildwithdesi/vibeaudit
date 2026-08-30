import { spawnSync } from 'node:child_process';
import { lstatSync, realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { findTrustedExecutable } from '../trusted-tools.js';

const MAX_ARTIFACT_BYTES = 5 * 1024 * 1024;
const MAX_BUNDLE_BYTES = 10 * 1024 * 1024;

export const VIBEAUDIT_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
export const VIBEAUDIT_PUBLISHER_IDENTITY_REGEXP = '^https://github\\.com/buildwithdesi/vibeaudit/\\.github/workflows/ci\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$';

/**
 * Verify one official Vibe Audit blob against its Sigstore bundle. A valid
 * result binds the artifact digest to the release workflow identity and the
 * transparency-log proof stored inside the bundle.
 */
export function verifyCosignArtifact(artifactPath, bundlePath, options = {}) {
  const artifact = inspectRegularFile(artifactPath, MAX_ARTIFACT_BYTES, 'artifact');
  const bundle = inspectRegularFile(bundlePath, MAX_BUNDLE_BYTES, 'signature bundle');
  const targetDir = resolve(options.targetDir || dirname(artifact));
  const findExecutable = options.findExecutable
    || ((name, target) => findTrustedExecutable(name, target, options.env));
  let executable;
  try {
    executable = findExecutable('cosign', targetDir);
  } catch {
    executable = null;
  }
  if (!executable) return failed('A trusted Cosign executable was not found outside the artifact directory.', artifact, bundle, 'unavailable');

  const args = [
    'verify-blob',
    artifact,
    '--bundle', bundle,
    '--certificate-identity-regexp', VIBEAUDIT_PUBLISHER_IDENTITY_REGEXP,
    '--certificate-oidc-issuer', VIBEAUDIT_OIDC_ISSUER,
    '--offline',
  ];
  const runner = options.runner || ((command, commandArgs, runOptions) => spawnSync(command, commandArgs, runOptions));
  let run;
  try {
    run = runner(executable, args, {
      cwd: targetDir,
      env: isolatedEnvironment(options.env),
      encoding: 'utf8',
      timeout: options.timeoutMs || 30_000,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
      shell: false,
    });
  } catch (error) {
    return failed(error?.code === 'ETIMEDOUT' ? 'Cosign verification timed out.' : 'Cosign verification could not start.', artifact, bundle);
  }
  if (run?.error || run?.signal || run?.status !== 0) {
    return failed(run?.error?.code === 'ETIMEDOUT'
      ? 'Cosign verification timed out.'
      : 'Cosign rejected the artifact signature, publisher identity, or transparency proof.', artifact, bundle);
  }
  return {
    tool: 'cosign',
    status: 'verified',
    verified: true,
    artifact,
    bundle,
    publisherIdentity: VIBEAUDIT_PUBLISHER_IDENTITY_REGEXP,
    oidcIssuer: VIBEAUDIT_OIDC_ISSUER,
    transparencyLogVerified: true,
  };
}

function inspectRegularFile(filePath, limit, label) {
  const absolute = resolve(filePath);
  let info;
  try {
    info = lstatSync(absolute);
  } catch {
    throw new Error(`Cosign ${label} is missing: ${absolute}`);
  }
  if (info.isSymbolicLink() || normalizePath(realpathSync(absolute)) !== normalizePath(absolute)) {
    throw new Error(`Refusing symbolic-link Cosign ${label}: ${absolute}`);
  }
  if (!info.isFile()) throw new Error(`Cosign ${label} is not a regular file: ${absolute}`);
  if (info.size > limit) throw new Error(`Cosign ${label} exceeds the ${limit} byte safety limit: ${absolute}`);
  return absolute;
}

function normalizePath(value) {
  const path = resolve(value);
  return process.platform === 'win32' ? path.toLowerCase() : path;
}

function failed(reason, artifact, bundle, status = 'failed') {
  return {
    tool: 'cosign',
    status,
    verified: false,
    artifact,
    bundle,
    publisherIdentity: VIBEAUDIT_PUBLISHER_IDENTITY_REGEXP,
    oidcIssuer: VIBEAUDIT_OIDC_ISSUER,
    transparencyLogVerified: false,
    reason,
  };
}

function isolatedEnvironment(source = process.env) {
  const allowed = ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'PATH', 'Path', 'LANG', 'LC_ALL'];
  return Object.fromEntries(allowed.filter((key) => source?.[key] !== undefined).map((key) => [key, source[key]]));
}
