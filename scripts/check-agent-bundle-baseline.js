import { readFileSync, writeFileSync } from 'node:fs';

import { buildOfficialSkillBaseline, officialSkillAssetPaths } from '../src/agent-bundle.js';

const paths = officialSkillAssetPaths();
const expected = `${JSON.stringify(buildOfficialSkillBaseline(), null, 2)}\n`;

if (process.argv.includes('--write')) {
  writeFileSync(paths.baseline, expected, 'utf8');
  console.log(`Updated ${paths.baseline}`);
} else {
  const actual = readFileSync(paths.baseline, 'utf8');
  if (actual !== expected) {
    console.error('The official skill baseline is stale. Run npm run bundle:update, review the diff, then sign a tagged release.');
    process.exitCode = 1;
  } else {
    console.log('Official skill baseline matches the packaged skill and package version.');
  }
}
