import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyCosignArtifact } from './adapters/cosign.js';

export const OFFICIAL_SKILL_BASELINE_SCHEMA = 1;
export const OFFICIAL_PUBLISHER = 'https://github.com/buildwithdesi/vibeaudit';
export const OFFICIAL_PACKAGE = '@jackdog668/vibeaudit';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

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
      size: statSync(paths.skill).size,
    }],
  };
}

/** Verify the signed baseline first, then the exact skill digest it names. */
export function verifyOfficialSkillBundle(options = {}) {
  const paths = officialSkillAssetPaths(options.root || packageRoot);
  const verifyArtifact = options.verifyArtifact || verifyCosignArtifact;
  const verifierOptions = { targetDir: paths.root, ...(options.cosignOptions || {}) };
  const baselineVerification = verifyArtifact(paths.baseline, paths.baselineBundle, verifierOptions);
  assertVerified(baselineVerification, 'official skill baseline');

  const baseline = JSON.parse(readFileSync(paths.baseline, 'utf8'));
  const expected = buildOfficialSkillBaseline(paths.root);
  if (JSON.stringify(baseline) !== JSON.stringify(expected)) {
    throw new Error('The signed official skill baseline does not match this package version and skill digest.');
  }

  const skillVerification = verifyArtifact(paths.skill, paths.skillBundle, verifierOptions);
  assertVerified(skillVerification, 'official skill');
  return {
    verified: true,
    transparencyLogVerified: baselineVerification.transparencyLogVerified === true
      && skillVerification.transparencyLogVerified === true,
    publisherIdentity: baselineVerification.publisherIdentity,
    oidcIssuer: baselineVerification.oidcIssuer,
    baseline,
    artifacts: {
      baseline: baselineVerification,
      skill: skillVerification,
    },
  };
}

function assertVerified(result, label) {
  if (!result?.verified || result.transparencyLogVerified !== true) {
    throw new Error(`Cosign could not verify the ${label}: ${result?.reason || 'verification failed'}`);
  }
}
