import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import test from 'node:test';

import { runGitleaksAdapter } from '../src/adapters/gitleaks.js';
import { runSecurityAdapters } from '../src/adapters/index.js';

const files = [{ path: 'C:/backup/.claude/skills/demo/SKILL.md', content: 'token = "example"\n' }];

test('Gitleaks adapter reports unavailable as incomplete coverage', () => {
  const result = runGitleaksAdapter(files, { findExecutable: () => null });
  assert.equal(result.status, 'unavailable');
  assert.equal(result.coverage.complete, false);
  assert.deepEqual(result.findings, []);
});

test('Gitleaks adapter stages only supplied files and strips secret values from reports', () => {
  let invocation;
  const result = runGitleaksAdapter(files, {
    findExecutable: () => 'C:/trusted/gitleaks.exe',
    runner(executable, args, options) {
      invocation = { executable, args, options };
      const reportPath = args[args.indexOf('--report-path') + 1];
      writeFileSync(reportPath, JSON.stringify([{
        RuleID: 'generic-api-key',
        Description: 'Generic API key',
        File: '000000-SKILL.md',
        StartLine: 1,
        EndLine: 1,
        Secret: 'do-not-return-this',
        Match: 'token = do-not-return-this',
        Line: 'token = do-not-return-this',
        Fingerprint: 'also-sensitive',
        Tags: ['key'],
      }]));
      return { status: 1, stdout: '', stderr: '' };
    },
  });
  assert.equal(result.status, 'completed');
  assert.equal(result.coverage.complete, true);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].file, files[0].path);
  assert.equal(result.findings[0].secret, undefined);
  assert.equal(JSON.stringify(result).includes('do-not-return-this'), false);
  assert.equal(invocation.executable, 'C:/trusted/gitleaks.exe');
  assert.ok(invocation.args.includes('--config'));
  assert.ok(invocation.args.includes('--redact=100'));
  assert.equal(invocation.args.includes('C:/backup'), false);
  assert.equal(invocation.options.env.GITLEAKS_CONFIG, undefined);
});

test('Gitleaks adapter fails closed on a tool error', () => {
  const result = runGitleaksAdapter(files, {
    findExecutable: () => '/trusted/gitleaks',
    runner: () => ({ status: 2, stdout: '', stderr: 'bad config' }),
  });
  assert.equal(result.status, 'failed');
  assert.equal(result.coverage.complete, false);
  assert.match(result.coverage.reason, /exit code 2/i);
  assert.equal(JSON.stringify(result).includes('bad config'), false);
});

test('security adapter registry keeps external tools behind one interface', () => {
  const calls = [];
  const results = runSecurityAdapters(files, {
    enabled: ['one', 'two'],
    adapters: {
      one(input) { calls.push(['one', input]); return { tool: 'one', status: 'completed', coverage: { complete: true }, findings: [] }; },
      two(input) { calls.push(['two', input]); return { tool: 'two', status: 'unavailable', coverage: { complete: false }, findings: [] }; },
    },
  });
  assert.deepEqual(calls.map(([name]) => name), ['one', 'two']);
  assert.equal(results.complete, false);
  assert.equal(results.results.length, 2);
});
