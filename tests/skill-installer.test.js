import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  applySkillInstallPlan,
  createSkillInstallPlan,
  detectAgents,
  readSkillMarkdown,
} from '../src/skill.js';

async function fakeHome(agentDirs = []) {
  const home = await mkdtemp(join(tmpdir(), 'vibeaudit-skill-'));
  for (const dir of agentDirs) await mkdir(join(home, dir), { recursive: true });
  return home;
}

test('skill plan shows source and target hashes before any write', async () => {
  const home = await fakeHome(['.claude']);
  try {
    const plan = await createSkillInstallPlan({ home, only: ['claude'] });
    assert.match(plan.sourceHash, /^[a-f0-9]{64}$/);
    assert.equal(plan.targets[0].action, 'install');
    assert.equal(plan.targets[0].beforeHash, null);
    await assert.rejects(readFile(plan.targets[0].installPath, 'utf8'));
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('skill install requires the exact reviewed source hash and verifies its write', async () => {
  const home = await fakeHome(['.claude']);
  const baselinePath = join(home, 'security-state', 'baseline.json');
  try {
    const plan = await createSkillInstallPlan({ home, only: ['claude'] });
    await assert.rejects(
      applySkillInstallPlan(plan, { confirmedSourceHash: 'wrong', baselinePath }),
      /confirmation hash/i,
    );
    const result = await applySkillInstallPlan(plan, { confirmedSourceHash: plan.sourceHash, baselinePath });
    assert.equal(result[0].status, 'installed');
    assert.equal(result[0].verifiedHash, plan.sourceHash);
    assert.equal(await readFile(plan.targets[0].installPath, 'utf8'), await readSkillMarkdown());
    assert.ok(JSON.parse(await readFile(baselinePath, 'utf8')).files);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('modified skill produces a reviewable diff and a backup before replacement', async () => {
  const home = await fakeHome(['.codex']);
  const baselinePath = join(home, 'security-state', 'baseline.json');
  try {
    let plan = await createSkillInstallPlan({ home, only: ['codex'] });
    await applySkillInstallPlan(plan, { confirmedSourceHash: plan.sourceHash, baselinePath });
    const target = plan.targets[0].installPath;
    await writeFile(target, '# My edited skill\nKeep this note.\n');

    plan = await createSkillInstallPlan({ home, only: ['codex'] });
    assert.equal(plan.targets[0].action, 'replace');
    assert.match(plan.targets[0].diff, /- # My edited skill/);
    assert.match(plan.targets[0].diff, /\+ ---/);

    const result = await applySkillInstallPlan(plan, { confirmedSourceHash: plan.sourceHash, baselinePath });
    assert.equal(result[0].status, 'updated');
    assert.ok(result[0].backupPath);
    assert.equal(await readFile(result[0].backupPath, 'utf8'), '# My edited skill\nKeep this note.\n');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('skill installer refuses a stale plan when a target changes after review', async () => {
  const home = await fakeHome(['.claude']);
  try {
    const plan = await createSkillInstallPlan({ home, only: ['claude'] });
    const target = plan.targets[0].installPath;
    await mkdir(join(home, '.claude', 'skills', 'vibeaudit'), { recursive: true });
    await writeFile(target, 'changed after review');
    await assert.rejects(
      applySkillInstallPlan(plan, { confirmedSourceHash: plan.sourceHash, baselinePath: join(home, 'baseline.json') }),
      /changed after the install preview/i,
    );
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('agent detection uses reviewable skills directories', async () => {
  const home = await fakeHome(['.claude', '.codex', '.cursor']);
  try {
    const agents = detectAgents(home);
    assert.deepEqual(agents.filter((agent) => agent.detected).map((agent) => agent.id), ['claude', 'codex', 'cursor']);
    assert.ok(agents.every((agent) => agent.installPath.endsWith(join('skills', 'vibeaudit', 'SKILL.md'))));
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
