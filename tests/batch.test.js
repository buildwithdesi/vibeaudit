import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { batchAudit } from '../src/batch.js';

describe('batch', () => {
  it('handles invalid repo targets gracefully', async () => {
    const { results, summary } = await batchAudit(['/not/a/repo'], { concurrency: 1 });

    assert.equal(results.length, 1);
    assert.equal(results[0].status, 'error');
    assert.equal(summary.reposErrored, 1);
    assert.equal(summary.reposScanned, 0);
  });

  it('builds summary with correct structure', async () => {
    const { summary } = await batchAudit([], { concurrency: 1 });

    assert.equal(summary.reposScanned, 0);
    assert.equal(summary.reposErrored, 0);
    assert.equal(summary.totalFindings, 0);
    assert.deepEqual(summary.grades, { A: 0, C: 0, D: 0, F: 0 });
    assert.ok(Array.isArray(summary.topOffenders));
    assert.ok(Array.isArray(summary.topRules));
    assert.ok(Array.isArray(summary.errors));
  });

  it('calls onResult callback for each repo', async () => {
    const called = [];
    await batchAudit(['/bad1', '/bad2'], {
      concurrency: 2,
      onResult(result) { called.push(result.repo); },
    });

    assert.equal(called.length, 2);
  });
});
