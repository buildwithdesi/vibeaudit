import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  publisherIdentityForVersion,
  VIBEAUDIT_OIDC_ISSUER,
  verifyCosignArtifact,
} from './adapters/cosign.js';

export const OFFICIAL_SKILL_BASELINE_SCHEMA = 1;
export const OFFICIAL_PUBLISHER = 'https://github.com/buildwithdesi/vibeaudit';
export const OFFICIAL_PACKAGE = '@jackdog668/vibeaudit';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MAX_METADATA_BYTES = 1024 * 1024;
const MAX_SKILL_BYTES = 5 * 1024 * 1024;

export function officialSkillAssetPaths(root = packageRoot) {
  const skill = join(root, 'src', 'data', 'agent-skill.md');
  const baseline = join(root, 'src', 'data', 'agent-skill-baseline.json');
  return {
    root,
    packageJson: join(root, 'package.json'),
    skill,
    skillBundle: `${skill}.sigstore.json`,
    baseline,
    baselineBundle: `${baseline}.sigstore.json`,
  };
}

export function buildOfficialSkillBaseline(root = packageRoot) {
  const paths = officialSkillAssetPaths(root);
  const packageJson = JSON.parse(readFileSync(paths.packageJson, 'utf8'));
  const skill = readFileSync(paths.skill);
  return {
    schemaVersion: OFFICIAL_SKILL_BASELINE_SCHEMA,
    kind: 'vibeaudit-agent-skill-baseline',
    publisher: OFFICIAL_PUBLISHER,
    package: OFFICIAL_PACKAGE,
    version: packageJson.version,
    files: [{
      path: 'src/data/agent-skill.md',
      sha256: createHash('sha256').update(skill).digest('hex'),
      size: skill.length,
    }],
  };
}

/** Verify the signed baseline first, then the exact skill digest it names. */
export function verifyOfficialSkillBundle(options = {}) {
  const paths = officialSkillAssetPaths(options.root || packageRoot);
  const verifyArtifact = options.verifyArtifact || verifyCosignArtifact;
  const packageSnapshot = snapshotFile(paths.packageJson, MAX_METADATA_BYTES, 'package metadata');
  const packageJson = parseJson(packageSnapshot.bytes, 'package metadata');
  const expectedIdentity = publisherIdentityForVersion(packageJson.version);
  const verifierOptions = {
    ...(options.cosignOptions || {}),
    targetDir: paths.root,
    expectedVersion: packageJson.version,
  };

  const baselineSnapshot = snapshotFile(paths.baseline, MAX_METADATA_BYTES, 'official skill baseline');
  const baselineVerification = verifyArtifact(paths.baseline, paths.baselineBundle, verifierOptions);
  assertVerified(baselineVerification, baselineSnapshot, 'official skill baseline', expectedIdentity);

  const baseline = parseJson(baselineSnapshot.bytes, 'official skill baseline');
  validateBaseline(baseline, packageJson.version);

  const skillSnapshot = snapshotFile(paths.skill, MAX_SKILL_BYTES, 'official skill');
  const expectedSkill = baseline.files[0];
  if (expectedSkill.sha256 !== skillSnapshot.sha256 || expectedSkill.size !== skillSnapshot.size) {
    throw new Error('The signed official skill baseline does not match the packaged skill bytes.');
  }

  const skillVerification = verifyArtifact(paths.skill, paths.skillBundle, verifierOptions);
  assertVerified(skillVerification, skillSnapshot, 'official skill', expectedIdentity);
  assertUnchanged(packageSnapshot);
  assertUnchanged(baselineSnapshot);
  assertUnchanged(skillSnapshot);
  return {
    verified: true,
    transparencyLogVerified: baselineVerification.transparencyLogVerified === true
      && skillVerification.transparencyLogVerified === true,
    publisherIdentityPolicy: baselineVerification.publisherIdentityPolicy,
    oidcIssuer: baselineVerification.oidcIssuer,
    baseline,
    artifacts: {
      baseline: baselineVerification,
      skill: skillVerification,
    },
  };
}

function assertVerified(result, snapshot, label, expectedIdentity) {
  if (!result?.verified || result.transparencyLogVerified !== true) {
    throw new Error(`Cosign could not verify the ${label}: ${result?.reason || 'verification failed'}`);
  }
  if (result.artifactSha256 !== snapshot.sha256 || result.artifactSize !== snapshot.size) {
    throw new Error(`Cosign verified bytes do not match the reviewed ${label}.`);
  }
  if (result.publisherIdentityPolicy !== expectedIdentity || result.oidcIssuer !== VIBEAUDIT_OIDC_ISSUER) {
    throw new Error(`Cosign verified the ${label} against an unexpected publisher policy.`);
  }
}

function validateBaseline(baseline, expectedVersion) {
  const file = baseline?.files?.[0];
  const valid = baseline?.schemaVersion === OFFICIAL_SKILL_BASELINE_SCHEMA
    && baseline.kind === 'vibeaudit-agent-skill-baseline'
    && baseline.publisher === OFFICIAL_PUBLISHER
    && baseline.package === OFFICIAL_PACKAGE
    && baseline.version === expectedVersion
    && Array.isArray(baseline.files)
    && baseline.files.length === 1
    && file?.path === 'src/data/agent-skill.md'
    && /^[a-f0-9]{64}$/.test(file.sha256 || '')
    && Number.isSafeInteger(file.size)
    && file.size >= 0
    && sameKeys(baseline, ['schemaVersion', 'kind', 'publisher', 'package', 'version', 'files'])
    && sameKeys(file, ['path', 'sha256', 'size']);
  if (!valid) throw new Error('The signed official skill baseline has an invalid or unexpected policy.');
}

function snapshotFile(filePath, limit, label) {
  const path = resolve(filePath);
  const info = lstatSync(path);
  if (info.isSymbolicLink() || normalizePath(realpathSync(path)) !== normalizePath(path) || !info.isFile()) {
    throw new Error(`Refusing non-regular ${label}: ${path}`);
  }
  if (info.size > limit) throw new Error(`${label} exceeds the ${limit} byte safety limit: ${path}`);
  const bytes = readFileSync(path);
  if (bytes.length > limit) throw new Error(`${label} exceeds the ${limit} byte safety limit: ${path}`);
  return {
    path,
    label,
    limit,
    bytes,
    size: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}

function assertUnchanged(snapshot) {
  const current = snapshotFile(snapshot.path, snapshot.limit, snapshot.label);
  if (current.size !== snapshot.size || current.sha256 !== snapshot.sha256) {
    throw new Error(`${snapshot.label} changed during publisher verification.`);
  }
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`The ${label} is not valid JSON.`);
  }
}

function sameKeys(value, keys) {
  return value && JSON.stringify(Object.keys(value)) === JSON.stringify(keys);
}

function normalizePath(value) {
  const path = resolve(value);
  return process.platform === 'win32' ? path.toLowerCase() : path;
}
