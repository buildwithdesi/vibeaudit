import { verifyOfficialSkillBundle } from '../src/agent-bundle.js';

try {
  const result = verifyOfficialSkillBundle();
  console.log(JSON.stringify({
    verified: result.verified,
    transparencyLogVerified: result.transparencyLogVerified,
    publisherIdentityPolicy: result.publisherIdentityPolicy,
    oidcIssuer: result.oidcIssuer,
    version: result.baseline.version,
    skillSha256: result.baseline.files[0].sha256,
  }, null, 2));
} catch (error) {
  console.error(`Official agent bundle verification failed: ${error.message}`);
  process.exitCode = 1;
}
