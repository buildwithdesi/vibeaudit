import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  buildOfficialSkillBaseline,
  officialSkillAssetPaths,
  verifyOfficialSkillBundle,
} from '../src/agent-bundle.js';

test('official skill baseline deterministically binds package version, path, size, and digest', () => {
  const paths = officialSkillAssetPaths();
  const expected = buildOfficialSkillBaseline();
  const committed = JSON.parse(readFileSync(paths.baseline, 'utf8'));

  assert.deepEqual(committed, expected);
  assert.deepEqual(Object.keys(committed), ['schemaVersion', 'kind', 'publisher', 'package', 'version', 'files']);
  assert.deepEqual(committed.files, [{
    path: 'src/data/agent-skill.md',
    sha256: '102cfe2f18b14bfece6406050218e8db70300be0b13d9b931a568be30e99b269',
    size: 1788,
  }]);
});

test('official skill verification requires valid Cosign bundles for the skill and its hash baseline', () => {
  const paths = officialSkillAssetPaths();
  const calls = [];
  const result = verifyOfficialSkillBundle({
    verifyArtifact(artifact, bundle) {
      calls.push([artifact, bundle]);
      return {
        tool: 'cosign',
        status: 'verified',
        verified: true,
        artifact,
        bundle,
        publisherIdentity: 'release workflow identity',
        oidcIssuer: 'GitHub Actions',
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
