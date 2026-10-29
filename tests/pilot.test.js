import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { approvePilot, assertPilotIsolation, reviewPilot, revokePilot, runPilot } from '../src/guard/pilot.js';

const image = `node@sha256:${'a'.repeat(64)}`;
const entrySource = "import { add } from './helper.mjs';\nconsole.log(add(2, 3));\n";

test('pilot accepts Docker-normalized capabilities but refuses extra privileges or missing restrictions', () => {
  const review = { entry: 'run.mjs', policy: { seconds: 30 } };
  const mounts = ['skill', 'input', 'runner'].map((name) => ({ source: `/staged/${name}`, target: `/${name}` }));
  const inspection = {
    Image: 'sha256:fixture',
    Config: { User: '0:0', WorkingDir: '/tmp', Entrypoint: ['/usr/local/bin/node'],
      Cmd: ['/runner/supervisor.mjs', '/skill/run.mjs', '30'],
      Labels: { 'dev.vibeaudit.pilot': 'fixture' }, Healthcheck: { Test: ['NONE'] }, Env: ['NODE_OPTIONS='] },
    HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, PidMode: '', IpcMode: 'none',
      RestartPolicy: { Name: 'no' }, AutoRemove: false, CapDrop: ['ALL'], CapAdd: ['CAP_SETUID', 'CAP_KILL', 'CAP_SETGID'],
      SecurityOpt: ['no-new-privileges:true'], PidsLimit: 64, Memory: 268435456, MemorySwap: 268435456, NanoCpus: 1000000000,
      LogConfig: { Type: 'none' }, Tmpfs: { '/tmp': 'rw,noexec,nosuid,nodev,size=16m,mode=1777' },
      Mounts: mounts.map(({ source, target }) => ({ Type: 'bind', Source: source, Target: target, ReadOnly: true })) },
    Mounts: mounts.map(({ target }) => ({ Type: 'bind', Destination: target, RW: false })),
  };
  assert.doesNotThrow(() => assertPilotIsolation(inspection, review, 'fixture', mounts, 'sha256:fixture'));
  for (const change of [
    (v) => v.HostConfig.CapAdd.push('CAP_SYS_ADMIN'),
    (v) => { v.HostConfig.CapDrop = []; },
    (v) => { v.HostConfig.NetworkMode = 'bridge'; },
    (v) => { v.HostConfig.ReadonlyRootfs = false; },
    (v) => { v.HostConfig.SecurityOpt = []; },
    (v) => { v.HostConfig.Mounts[0].Source = '/host-home'; },
    (v) => { v.Mounts[0].RW = true; },
    (v) => { v.Config.Env.push('HTTP_PROXY=http://host'); },
    (v) => { v.HostConfig.PidsLimit = 0; },
  ]) {
    const changed = structuredClone(inspection);
    change(changed);
    assert.throws(() => assertPilotIsolation(changed, review, 'fixture', mounts, 'sha256:fixture'), /isolation policy/);
  }
});

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'vibeguard-pilot-test-'));
  const skill = join(root, 'skill');
  const input = join(root, 'input');
  const store = join(root, 'state');
  mkdirSync(skill);
  mkdirSync(input);
  writeFileSync(join(skill, 'SKILL.md'), '# Addition skill\nAdd the supplied numbers.\n');
  writeFileSync(join(skill, 'run.mjs'), entrySource);
  writeFileSync(join(skill, 'helper.mjs'), 'export const add = (left, right) => left + right;\n');
  writeFileSync(join(input, 'numbers.json'), '[2, 3]\n');
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, skill, input, store, image };
}

async function approvedFixture(t) {
  const options = fixture(t);
  const review = await reviewPilot(options);
  approvePilot(review.id, { store: options.store, accept: review.id });
  return { ...options, review };
}

function editState(file, edit) {
  const state = JSON.parse(readFileSync(file, 'utf8'));
  edit(state);
  writeFileSync(file, `${JSON.stringify(state)}\n`);
}

function assertBlocked(receipt) {
  assert.equal(receipt.status, 'blocked');
  assert.equal(typeof receipt.error, 'string');
  assert.ok(receipt.error.length > 0);
  assert.ok(receipt.runId);
  assert.ok(receipt.receiptPath);
  const saved = JSON.parse(readFileSync(receipt.receiptPath, 'utf8'));
  assert.equal(saved.status, receipt.status);
  assert.equal(saved.runId, receipt.runId);
}

test('pilot review binds the skill, imports, and input bytes to a content digest without Docker', async (t) => {
  const options = fixture(t);
  const review = await reviewPilot(options);
  assert.match(review.id, /^[a-f0-9]{64}$/);
  assert.deepEqual(review.manifest.skill.map((file) => file.path).sort(), ['SKILL.md', 'helper.mjs', 'run.mjs'].sort());
  assert.deepEqual(review.manifest.input.map((file) => file.path), ['numbers.json']);
  const entry = review.manifest.skill.find((file) => file.path === 'run.mjs');
  assert.equal(entry.sha256, createHash('sha256').update(entrySource).digest('hex'));
  assert.equal(entry.size, Buffer.byteLength(entrySource));
  assert.ok(Array.isArray(review.findings));
  assert.ok(review.policy);
  assert.ok(existsSync(join(options.store, 'reviews', `${review.id}.json`)));
  assert.equal(existsSync(join(options.store, 'approvals', `${review.id}.json`)), false);
});

test('pilot review ID changes when the exact input or execution limit changes', async (t) => {
  const options = fixture(t);
  const original = await reviewPilot(options);
  assert.equal((await reviewPilot(options)).id, original.id);
  writeFileSync(join(options.input, 'numbers.json'), '[20, 30]\n');
  const changedInput = await reviewPilot(options);
  assert.notEqual(changedInput.id, original.id);
  const changedLimit = await reviewPilot({ ...options, seconds: 10 });
  assert.notEqual(changedLimit.id, changedInput.id);
  const changedImage = await reviewPilot({ ...options, image: `node@sha256:${'b'.repeat(64)}` });
  assert.notEqual(changedImage.id, changedInput.id);
});

test('pilot approval requires the complete exact review acknowledgement', async (t) => {
  const { store, ...options } = fixture(t);
  const review = await reviewPilot({ ...options, store });
  for (const accept of [undefined, true, 'yes', review.id.slice(0, 12), 'b'.repeat(64)]) {
    assert.throws(() => approvePilot(review.id, { store, accept }));
    assert.equal(existsSync(join(store, 'approvals', `${review.id}.json`)), false);
  }
  approvePilot(review.id, { store, accept: review.id });
  const approval = JSON.parse(readFileSync(join(store, 'approvals', `${review.id}.json`), 'utf8'));
  assert.equal(approval.id, review.id);
  assert.ok(approval.expiresAt > approval.createdAt);
});

test('pilot rejects mutable tags and image references outside the pinned Node allowlist', async (t) => {
  const options = fixture(t);
  for (const candidate of ['node:22', 'node:latest', 'node', 'node@sha256:abc', `untrusted/node@sha256:${'a'.repeat(64)}`, `${image} --privileged`]) {
    await assert.rejects(reviewPilot({ ...options, image: candidate }));
  }
});

test('pilot requires a root SKILL.md and a local .mjs entry', async (t) => {
  const options = fixture(t);
  for (const entry of ['../run.mjs', join(options.root, 'run.mjs'), 'run.js', 'missing.mjs']) {
    await assert.rejects(reviewPilot({ ...options, entry }));
  }
  rmSync(join(options.skill, 'SKILL.md'));
  await assert.rejects(reviewPilot(options));
});

test('pilot refuses overlapping source roots and policy storage', async (t) => {
  const options = fixture(t);
  await assert.rejects(reviewPilot({ ...options, input: options.skill }));
  await assert.rejects(reviewPilot({ ...options, store: join(options.skill, 'policy') }));
  await assert.rejects(reviewPilot({ ...options, store: join(options.input, 'policy') }));
  await assert.rejects(reviewPilot({ ...options, store: options.root }));
});

test('pilot refuses hidden files and repository metadata rather than copying host secrets', async (t) => {
  const options = fixture(t);
  writeFileSync(join(options.input, '.env'), 'FAKE_SECRET=pilot-test-only\n');
  await assert.rejects(reviewPilot(options));
  rmSync(join(options.input, '.env'));
  mkdirSync(join(options.skill, '.git'));
  writeFileSync(join(options.skill, '.git', 'config'), '[core]\n');
  await assert.rejects(reviewPilot(options));
});

test('pilot rejects a junction or symlink out of the skill directory', async (t) => {
  const options = fixture(t);
  const outside = join(options.root, 'outside');
  mkdirSync(outside);
  writeFileSync(join(outside, 'secret.txt'), 'FAKE_HOST_SECRET_DO_NOT_COPY\n');
  symlinkSync(outside, join(options.skill, 'outside'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(reviewPilot(options));
});

test('pilot rejects case-colliding source paths', { skip: process.platform === 'win32' ? 'Windows fixtures use a case-insensitive filesystem' : false }, async (t) => {
  const options = fixture(t);
  writeFileSync(join(options.skill, 'Helper.mjs'), 'export const add = () => 0;\n');
  await assert.rejects(reviewPilot(options));
});

test('pilot enforces the combined source file limit', async (t) => {
  const options = fixture(t);
  for (let index = 0; index < 253; index += 1) {
    writeFileSync(join(options.input, `extra-${index}.txt`), 'safe fixture\n');
  }
  // Three skill files, one original input, and 253 extras exceed 256.
  await assert.rejects(reviewPilot(options));
});

test('pilot enforces the combined byte limit before creating an approval', async (t) => {
  const options = fixture(t);
  writeFileSync(join(options.input, 'large.txt'), Buffer.alloc(10 * 1024 * 1024 + 1, 'x'));
  await assert.rejects(reviewPilot(options));
});

test('pilot blocks unapproved and unknown review IDs with persisted evidence', async (t) => {
  const options = fixture(t);
  const review = await reviewPilot(options);
  assertBlocked(await runPilot(review.id, { store: options.store }));
  assertBlocked(await runPilot('b'.repeat(64), { store: options.store }));
});

test('pilot rejects IDs containing traversal before accessing state', async (t) => {
  const { store } = fixture(t);
  for (const id of ['../../outside', 'x', `../${'a'.repeat(64)}`]) {
    assert.throws(() => approvePilot(id, { store, accept: id }));
    assert.throws(() => revokePilot(id, { store }));
    await assert.rejects(runPilot(id, { store }));
  }
});

for (const [label, source, name, content] of [
  ['entry point', 'skill', 'run.mjs', 'console.log("changed after approval");\n'],
  ['imported module', 'skill', 'helper.mjs', 'export const add = () => 500;\n'],
  ['input data', 'input', 'numbers.json', '[100, 200]\n'],
  ['new file', 'skill', 'extra.mjs', 'export const surprise = true;\n'],
]) {
  test(`pilot blocks a changed ${label} and consumes the exact one-time approval`, async (t) => {
    const options = await approvedFixture(t);
    writeFileSync(join(options[source], name), content);
    assertBlocked(await runPilot(options.review.id, { store: options.store }));
    const replay = await runPilot(options.review.id, { store: options.store });
    assertBlocked(replay);
    assert.match(replay.error, /approval|approved|consum|used/i);
    assert.equal(existsSync(join(options.store, 'approvals', `${options.review.id}.json`)), false);
  });
}

test('pilot revoked approval cannot start a workload', async (t) => {
  const { review, store } = await approvedFixture(t);
  revokePilot(review.id, { store });
  assertBlocked(await runPilot(review.id, { store }));
});

test('pilot expired approval cannot start a workload', async (t) => {
  const { review, store } = await approvedFixture(t);
  editState(join(store, 'approvals', `${review.id}.json`), (approval) => { approval.expiresAt = 1; });
  assertBlocked(await runPilot(review.id, { store }));
});

test('pilot rejects approval state for another content digest', async (t) => {
  const { review, store } = await approvedFixture(t);
  editState(join(store, 'approvals', `${review.id}.json`), (approval) => { approval.id = 'b'.repeat(64); });
  assertBlocked(await runPilot(review.id, { store }));
});

test('pilot refuses an approval with no valid expiry', async (t) => {
  const { review, store } = await approvedFixture(t);
  editState(join(store, 'approvals', `${review.id}.json`), (approval) => { delete approval.expiresAt; });
  assertBlocked(await runPilot(review.id, { store }));
});

for (const [label, mutate] of [
  ['policy', (review) => { review.policy.seconds = 9999; }],
  ['manifest', (review) => { review.manifest.input[0].sha256 = 'b'.repeat(64); }],
  ['stored payload', (review) => { review.bundles.skill.find((file) => file.path === 'run.mjs').data = Buffer.from('console.log("tampered");\n').toString('base64'); }],
]) {
  test(`pilot blocks tampered review ${label} before Docker`, async (t) => {
    const { review, store } = await approvedFixture(t);
    editState(join(store, 'reviews', `${review.id}.json`), mutate);
    assertBlocked(await runPilot(review.id, { store }));
  });
}

test('pilot concurrent replay attempts cannot reuse an approval after a source change', async (t) => {
  const { review, store, input } = await approvedFixture(t);
  writeFileSync(join(input, 'numbers.json'), '[99]\n');
  const attempts = await Promise.all([runPilot(review.id, { store }), runPilot(review.id, { store })]);
  for (const receipt of attempts) assertBlocked(receipt);
  assert.notEqual(attempts[0].runId, attempts[1].runId);
  assert.ok(attempts.some((receipt) => /approval|approved|consum|used/i.test(receipt.error)));
  assert.equal(existsSync(join(store, 'approvals', `${review.id}.json`)), false);
});

test('vibeguard pilot help exposes review, approval, execution, and revocation', () => {
  const result = spawnSync(process.execPath, [resolve('bin/vibeguard.js'), 'pilot', '--help'], {
    encoding: 'utf8',
    timeout: 120_000,
  });
  assert.equal(result.status, 0, result.stderr);
  for (const command of ['review', 'approve', 'run', 'revoke']) assert.match(result.stdout, new RegExp(command));
});
