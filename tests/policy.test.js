import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { audit } from '../src/index.js';

async function quietAudit(root, options) {
  const originalLog = console.log;
  console.log = () => {};
  try {
    return await audit(root, { format: 'json', skipSca: true, ...options });
  } finally {
    console.log = originalLog;
  }
}

describe('untrusted target policy', () => {
  it('ignores a target-controlled exclude list unless explicitly trusted', async () => {
    const root = mkdtempSync(join(tmpdir(), 'vibeaudit-policy-test-'));
    writeFileSync(join(root, '.vibe-audit.json'), JSON.stringify({ exclude: ['missing-auth'] }));
    mkdirSync(join(root, 'app', 'api', 'things'), { recursive: true });
    writeFileSync(join(root, 'app', 'api', 'things', 'route.ts'), 'export async function GET(req) { return Response.json({ url: req.url }); }');
    try {
      const safeDefault = await quietAudit(root, { rules: ['missing-auth'] });
      assert.ok(safeDefault.findings.some((finding) => finding.ruleId === 'missing-auth'));

      const explicitlyTrusted = await quietAudit(root, { rules: ['missing-auth'], trustTargetConfig: true });
      assert.equal(explicitlyTrusted.findings.length, 0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('ignores inline target suppressions unless target policy is trusted', async () => {
    const root = mkdtempSync(join(tmpdir(), 'vibeaudit-suppression-test-'));
    writeFileSync(join(root, '.vibe-audit.json'), '{}');
    mkdirSync(join(root, 'app', 'api', 'things'), { recursive: true });
    writeFileSync(join(root, 'app', 'api', 'things', 'route.ts'), [
      '// vibe-audit-ignore-next-line missing-auth',
      'export async function GET(req) { return Response.json({ url: req.url }); }',
    ].join('\n'));
    try {
      const safeDefault = await quietAudit(root, { rules: ['missing-auth'] });
      assert.ok(safeDefault.findings.some((finding) => finding.ruleId === 'missing-auth'));

      const explicitlyTrusted = await quietAudit(root, { rules: ['missing-auth'], trustTargetConfig: true });
      assert.equal(explicitlyTrusted.findings.length, 0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('rejects unknown rule IDs instead of silently running zero rules', async () => {
    const root = mkdtempSync(join(tmpdir(), 'vibeaudit-unknown-rule-test-'));
    mkdirSync(join(root, 'src'));
    writeFileSync(join(root, 'src', 'app.js'), 'console.log("hello")');
    try {
      await assert.rejects(
        () => quietAudit(root, { rules: ['not-a-real-rule'] }),
        /Unknown rule ID: not-a-real-rule/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
