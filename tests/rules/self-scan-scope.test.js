/**
 * Regression guard for the self-scan measurement bug.
 *
 * The portfolio morning-scan fetches files over the GitHub API. On that path a failed
 * remote .vibe-audit.json fetch (rate limit, 404, unreachable raw HEAD ref) silently
 * falls back to an EMPTY ignore list — so the scanner graded its OWN reports/ and test
 * fixtures as criticals (Grade F). audit()'s `extraIgnore` option is the hard baseline
 * that must drop those paths regardless of whether the remote config fetch lands.
 *
 * Both directions are locked:
 *   - WITH the baseline: reports/ and fixtures are ignored, real code is still graded.
 *   - WITHOUT it: the empty-ignore fallback DOES flag them (reproduces the bug).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { audit } from '../../src/index.js';
import { getDefaultConfig } from '../../src/config.js';

// A trigger with no path filter (sensitive-browser-storage fires on any file), so the
// ONLY thing that can suppress it is the ignore logic under test — not extension/path skips.
const TRIGGER = 'localStorage.setItem("authToken", token)';

async function* fakeRemoteFiles() {
  for (const relativePath of [
    'src/app.js',              // real code — MUST still be graded
    'reports/morning-scan.js', // generated artifact — MUST be ignored
    'tests/fixtures/bad.js',   // deliberately-vulnerable fixture — MUST be ignored
  ]) {
    yield {
      path: `github://o/r/${relativePath}`,
      relativePath,
      content: TRIGGER,
      lines: TRIGGER.split('\n'),
    };
  }
}

/** Run audit with console.log silenced — audit() prints the report to stdout. */
async function silentAudit(opts) {
  const orig = console.log;
  console.log = () => {};
  try {
    return await audit('owner/repo', opts);
  } finally {
    console.log = orig;
  }
}

const inReports = (f) => f.startsWith('reports/');
const inTests = (f) => f.split('/').includes('tests') || f.split('/').includes('fixtures');

describe('self-scan scope: extraIgnore baseline', () => {
  it('drops findings from reports/ and test fixtures, keeps real code', async () => {
    const { findings } = await silentAudit({
      format: 'json',
      skipSca: true,
      fileSource: fakeRemoteFiles(),
      config: getDefaultConfig(), // empty ignore — mirrors a failed remote-config fetch
      extraIgnore: ['reports', 'tests', 'fixtures'],
    });
    const files = findings.map((f) => f.file);
    assert.ok(files.includes('src/app.js'), 'real code should still be graded');
    assert.ok(!files.some(inReports), 'reports/ must be ignored');
    assert.ok(!files.some(inTests), 'test fixtures must be ignored');
  });

  it('without the baseline, the empty-ignore fallback DOES flag reports/ and fixtures (the bug)', async () => {
    const { findings } = await silentAudit({
      format: 'json',
      skipSca: true,
      fileSource: fakeRemoteFiles(),
      config: getDefaultConfig(), // empty ignore, no extraIgnore
    });
    const files = findings.map((f) => f.file);
    assert.ok(files.some(inReports), 'baseline off: reports/ is scanned (reproduces the bug)');
    assert.ok(files.some(inTests), 'baseline off: fixtures are scanned (reproduces the bug)');
  });
});
