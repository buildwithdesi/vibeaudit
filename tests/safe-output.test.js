import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeNewOutput } from '../src/safe-output.js';

describe('safe generated output', () => {
  it('never overwrites an existing report target', async () => {
    const root = mkdtempSync(join(tmpdir(), 'vibeaudit-output-test-'));
    const preferred = join(root, 'report.md');
    writeFileSync(preferred, 'keep me');
    try {
      const actual = await writeNewOutput(preferred, 'new report');
      assert.notEqual(actual, preferred);
      assert.equal(readFileSync(preferred, 'utf8'), 'keep me');
      assert.equal(readFileSync(actual, 'utf8'), 'new report');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
