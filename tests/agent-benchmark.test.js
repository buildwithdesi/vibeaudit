import assert from 'node:assert/strict';
import test from 'node:test';

import { runBenchmark } from '../scripts/agent-benchmark.js';

test('safe Agent Shield benchmark keeps required cases green and records known gaps', () => {
  const report = runBenchmark();

  assert.equal(report.mode, 'safe-agent-shield-benchmark');
  assert.equal(report.summary.requiredFailures, 0);
  assert.equal(report.summary.benignPass, report.summary.benign);
  assert.equal(report.summary.falsePositives, 0);
  assert.equal(report.summary.incompleteBlocked, report.summary.incomplete);
  assert.ok(report.summary.knownGaps >= 1);
});

test('benchmark classifications expose the expected malicious detection gap', () => {
  const report = runBenchmark();
  const gap = report.cases.find((item) => item.id === 'known-gap-obfuscated-instruction');

  assert.ok(gap);
  assert.equal(gap.evaluation, 'known-gap');
  assert.equal(gap.expectedDecision, 'block');
  assert.equal(gap.actualDecision, 'pass');
  assert.equal(gap.knownGap, true);
  assert.deepEqual(gap.findings, []);
});

