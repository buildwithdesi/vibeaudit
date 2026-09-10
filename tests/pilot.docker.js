import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { clearTimeout, setTimeout } from 'node:timers';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { approvePilot, recoverPilot, reviewPilot, runPilot, statusPilot } from '../src/guard/pilot.js';
import { findTrustedExecutable } from '../src/trusted-tools.js';

// This file is deliberately outside the ordinary *.test.js gate. It requires a
// real Linux Docker engine and a pre-pulled image; missing prerequisites fail.
const image = process.env.VIBEGUARD_PILOT_IMAGE;
const cli = fileURLToPath(new URL('../bin/vibeguard.js', import.meta.url));
const example = fileURLToPath(new URL('../examples/protection-pilot/', import.meta.url));
const host = process.platform === 'win32'
  ? 'npipe:////./pipe/dockerDesktopLinuxEngine' : 'unix:///var/run/docker.sock';
const reportPath = fileURLToPath(new URL('../reports/pilot-runtime.json', import.meta.url));
const evidence = {
  schemaVersion: 1, status: 'failed', image: image || null, platform: process.platform,
  startedAt: new Date().toISOString(), dockerVersion: null, cases: [],
};
let currentCase;

function saveEvidence() {
  mkdirSync(dirname(reportPath), { recursive: true });
  writeFileSync(reportPath, `${JSON.stringify(evidence, null, 2)}\n`);
}

function recordReceipt(receipt) {
  currentCase?.receipts.push({
    status: receipt.status, isolationVerified: receipt.isolationVerified,
    cleanupVerified: receipt.cleanupVerified, exitCode: receipt.workload?.exitCode ?? null,
    oomKilled: receipt.workload?.oomKilled ?? null,
  });
}

function safeEnvironment() {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    /^(?:PATH|SystemRoot|WINDIR|TEMP|TMP|HOME|USERPROFILE)$/i.test(key)));
}

function command(executable, args, { cwd, timeout = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    let stdout = '', stderr = '', failure;
    const child = spawn(executable, args, {
      cwd, env: safeEnvironment(), shell: false, windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const timer = setTimeout(() => {
      failure = new Error(`Acceptance helper exceeded ${timeout}ms: ${args[0]}`);
      child.kill('SIGKILL');
    }, timeout);
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', (error) => { failure = error; });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (failure) reject(failure);
      else resolve({ code, stdout, stderr });
    });
  });
}

function fixture(t, source) {
  const caseEvidence = currentCase;
  const root = mkdtempSync(join(tmpdir(), 'vibeguard-docker-'));
  const skill = join(root, 'skill'), input = join(root, 'input'), store = join(root, 'state');
  const client = join(root, 'client');
  for (const path of [skill, input, store, client]) mkdirSync(path);
  writeFileSync(join(client, 'config.json'), '{}\n');
  writeFileSync(join(skill, 'SKILL.md'), '# Disposable protection acceptance skill\nRun only in the reviewed pilot container.\n');
  if (source) writeFileSync(join(skill, 'run.mjs'), source);
  t.after(async () => {
    // Recover only runs created by this fixture, before deleting their mounts.
    // If recovery fails, retain evidence instead of hiding a live container.
    try {
      for (const run of statusPilot({ store }).runs) {
        if (!run.cleanupVerified) await recoverPilot(run.runId, { store });
      }
      rmSync(root, { recursive: true, force: true });
    } catch (error) {
      if (caseEvidence) {
        caseEvidence.status = 'failed';
        caseEvidence.failure = 'CleanupError';
      }
      evidence.status = 'failed';
      saveEvidence();
      throw error;
    }
  });
  const executable = findTrustedExecutable('docker', root);
  assert.ok(executable, 'A trusted Docker executable outside the disposable fixture is required.');
  const docker = async (args, options) => {
    const result = await command(executable, ['--config', client, '--host', host, ...args], { cwd: root, ...options });
    assert.equal(result.code, 0, `Docker ${args[0]} failed: ${result.stderr}`);
    return result.stdout.trim();
  };
  return { root, skill, input, store, image, docker };
}

async function approved(options, seconds = 10) {
  const review = await reviewPilot({ ...options, seconds });
  approvePilot(review.id, { store: options.store, accept: review.id });
  return review;
}

function checkedReceipt(receipt, { status, exitCode }) {
  recordReceipt(receipt);
  assert.equal(receipt.status, status, JSON.stringify(receipt));
  assert.equal(receipt.isolationVerified, true);
  assert.equal(receipt.cleanupVerified, true);
  assert.equal(receipt.workload.exitCode, exitCode);
  assert.equal(receipt.workload.oomKilled, false);
  assert.equal(receipt.workload.trust, 'untrusted-output');
  assert.equal(receipt.policy.network, 'none');
  assert.equal(receipt.policy.hostCredentials, false);
  assert.equal(receipt.policy.workloadUid, 65534);
  assert.equal(receipt.image, image);
  assert.match(receipt.imageId, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(JSON.parse(readFileSync(receipt.receiptPath, 'utf8')), receipt);
}

async function waitFor(check, timeout, description) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await delay(250);
  }
  assert.fail(`Timed out waiting for ${description}`);
}

// Source is written into a disposable skill. It is never imported or executed
// by the host test process. Assertions, not a self-reported success string,
// determine the container exit status.
const isolationSource = String.raw`
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { createConnection } from 'node:net';
import { Resolver } from 'node:dns/promises';
import { isAbsolute } from 'node:path';
import { setTimeout, clearTimeout } from 'node:timers';

const targets = JSON.parse(readFileSync('/input/targets.json', 'utf8'));
assert.equal(process.getuid(), 65534);
assert.equal(process.getgid(), 65534);
const status = readFileSync('/proc/self/status', 'utf8');
assert.match(status, /^NoNewPrivs:\s+1$/m);
assert.match(status, /^CapEff:\s+0+$/m);
assert.deepEqual(Object.keys(networkInterfaces()), ['lo']);
assert.equal(process.env.FAKE_PILOT_HOST_TOKEN, undefined);
let deniedReads = 0, deniedWrites = 0;
for (const path of targets.reads) {
  assert.throws(() => readFileSync(path), (error) => ['ENOENT', 'EACCES', 'EPERM', 'ENOTDIR'].includes(error.code), path);
  deniedReads++;
}
for (const path of ['/skill/run.mjs', '/input/targets.json', '/runner/supervisor.mjs', ...targets.writes]) {
  assert.throws(() => writeFileSync(path, 'benign-test-overwrite'),
    (error) => ['EROFS', 'EACCES', 'EPERM', 'ENOENT', 'ENOTDIR'].includes(error.code), path);
  deniedWrites++;
}
// A Windows path is a relative scratch filename inside Linux. It cannot address
// the host drive; the host separately verifies both canaries remain unchanged.
for (const path of targets.literalWindowsPaths) {
  assert.equal(isAbsolute(path), false);
  writeFileSync(path, 'scratch filename only');
  assert.equal(readFileSync(path, 'utf8'), 'scratch filename only');
}
assert.throws(() => process.kill(1, 'SIGSTOP'), { code: 'EPERM' });

function attemptSend(host) {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host, port: 443 });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('bounded network timeout')); }, 1500);
    socket.once('error', (error) => { clearTimeout(timer); reject(error); });
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.end('VIBEGUARD_BENIGN_NETWORK_PROBE');
      resolve();
    });
  });
}
for (const host of ['198.51.100.1', '2001:db8::1', 'host.docker.internal']) {
  await assert.rejects(attemptSend(host), undefined, 'network connection unexpectedly succeeded: ' + host);
}
const resolver = new Resolver({ timeout: 1000, tries: 1 });
resolver.setServers(['192.0.2.53']);
const dnsDeadline = setTimeout(() => resolver.cancel(), 1500);
try { await assert.rejects(resolver.resolve4('pilot-probe.invalid')); }
finally { clearTimeout(dnsDeadline); }
writeFileSync('/tmp/result.txt', 'scratch works');
assert.equal(readFileSync('/tmp/result.txt', 'utf8'), 'scratch works');
console.log(JSON.stringify({ deniedReads, deniedWrites, literalWindowsPaths: targets.literalWindowsPaths.length,
  networkAttempts: 4, scratch: true }));
`;

const deadlineSource = String.raw`
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
assert.equal(process.getuid(), 65534);
assert.throws(() => process.kill(1, 'SIGSTOP'), { code: 'EPERM' });
assert.throws(() => writeFileSync('/runner/supervisor.mjs', 'process.exit(0)'),
  (error) => ['EROFS', 'EACCES', 'EPERM'].includes(error.code));
// Blocking this event loop must not block the root-owned supervisor deadline.
while (true) { /* disposable CPU-bound workload */ }
`;

test('protection pilot real Docker acceptance', { timeout: 180_000 }, async (t) => {
  saveEvidence();
  async function runCase(name, options, callback) {
    const result = { name, status: 'failed', receipts: [] };
    evidence.cases.push(result);
    await t.test(name, options, async (context) => {
      currentCase = result;
      try {
        await callback(context);
        result.status = 'passed';
      } catch (error) {
        result.failure = error.name;
        throw error;
      } finally {
        currentCase = undefined;
        saveEvidence();
      }
    });
  }
  try {
  assert.match(image || '', /^node@sha256:[a-f0-9]{64}$/,
    'Set VIBEGUARD_PILOT_IMAGE to a pre-pulled node@sha256:<digest>; this suite never skips or pulls.');
  const prerequisites = fixture(t);
  assert.equal(await prerequisites.docker(['info', '--format', '{{.OSType}}']), 'linux',
    'A running local Linux Docker engine is required.');
  const [availableImage] = JSON.parse(await prerequisites.docker(['image', 'inspect', image]));
  assert.equal(availableImage.Os, 'linux');
  evidence.dockerVersion = await prerequisites.docker(['version', '--format', '{{.Server.Version}}']);
  const doctorResult = await command(process.execPath, [cli, 'pilot', 'doctor', '--image', image, '--json'], {
    cwd: prerequisites.root, timeout: 35_000,
  });
  assert.equal(doctorResult.code, 0, doctorResult.stdout || doctorResult.stderr);
  const doctor = JSON.parse(doctorResult.stdout);
  assert.equal(doctor.status, 'ready');
  assert.equal(doctor.reasonCode, 'runtime_ready');
  assert.equal(doctor.isolationVerified, false);
  assert.equal(doctor.clientCleanupVerified, true);
  evidence.doctor = { status: doctor.status, reasonCode: doctor.reasonCode,
    isolationVerified: doctor.isolationVerified, clientCleanupVerified: doctor.clientCleanupVerified };
  evidence.prerequisites = 'passed';

  await runCase('the shipped notes skill returns the actual expected summary', { timeout: 30_000 }, async (context) => {
    const options = fixture(context);
    cpSync(join(example, 'skill'), options.skill, { recursive: true });
    cpSync(join(example, 'input'), options.input, { recursive: true });
    const review = await approved(options);
    const receipt = await runPilot(review.id, { store: options.store });
    checkedReceipt(receipt, { status: 'completed', exitCode: 0 });
    assert.deepEqual(JSON.parse(receipt.workload.stdout), {
      title: 'Protection pilot notes', lineCount: 3, wordCount: 21,
      items: [
        'Approve the exact skill and input contents.',
        'Run the skill with networking disabled.',
        'Review the host-written receipt before accepting the result.',
      ],
    });
    assert.equal(receipt.workload.stderr, '');
  });

  await runCase('untrusted skill cannot access host canaries, change policy, signal its supervisor, or reach a network',
    { timeout: 45_000 }, async (context) => {
      const options = fixture(context, isolationSource);
      const canary = join(options.root, 'fake-host-secret.txt');
      const policy = join(options.store, 'host-policy-canary.json');
      const canaryText = `FAKE_TEST_ONLY_${randomUUID()}`;
      const policyText = '{"network":"none","fakePolicyCanary":true}\n';
      writeFileSync(canary, canaryText);
      writeFileSync(policy, policyText);
      const hostPaths = (path) => /^([A-Za-z]):/.test(path)
        ? ['/host_mnt', '/run/desktop/mnt/host', '/mnt', ''].map((prefix) =>
          `${prefix}/${path[0].toLowerCase()}${path.slice(2).replaceAll('\\', '/')}`)
        : [path, `/host_mnt${path}`];
      const reads = [...new Set([canary, ...hostPaths(canary), policy, ...hostPaths(policy), '/var/run/docker.sock', '/run/docker.sock',
        '/host_mnt/c/Users/pilot-fixture-only/fake-host-secret.txt'])];
      const writes = hostPaths(policy);
      const literalWindowsPaths = process.platform === 'win32' ? [canary, policy] : [];
      writeFileSync(join(options.input, 'targets.json'), JSON.stringify({ reads, writes, literalWindowsPaths }));
      const review = await approved(options, 15);
      const reviewPath = join(options.store, 'reviews', `${review.id}.json`);
      const policyBefore = readFileSync(reviewPath, 'utf8');
      const previousToken = process.env.FAKE_PILOT_HOST_TOKEN;
      let receipt;
      try {
        process.env.FAKE_PILOT_HOST_TOKEN = canaryText;
        receipt = await runPilot(review.id, { store: options.store });
      } finally {
        if (previousToken === undefined) delete process.env.FAKE_PILOT_HOST_TOKEN;
        else process.env.FAKE_PILOT_HOST_TOKEN = previousToken;
      }
      checkedReceipt(receipt, { status: 'completed', exitCode: 0 });
      assert.deepEqual(JSON.parse(receipt.workload.stdout), {
        deniedReads: reads.length, deniedWrites: writes.length + 3, literalWindowsPaths: literalWindowsPaths.length,
        networkAttempts: 4, scratch: true,
      });
      assert.equal(readFileSync(canary, 'utf8'), canaryText);
      assert.equal(readFileSync(policy, 'utf8'), policyText);
      assert.equal(readFileSync(reviewPath, 'utf8'), policyBefore);
      assert.equal(JSON.stringify(receipt).includes(canaryText), false, 'Fake host secret appeared in the receipt.');
    });

  await runCase('nonzero workload exit remains failed despite a success claim in its output', { timeout: 30_000 }, async (context) => {
    const options = fixture(context, 'console.log("{\\"protected\\":true}");\nprocess.exit(23);\n');
    const review = await approved(options);
    const receipt = await runPilot(review.id, { store: options.store });
    checkedReceipt(receipt, { status: 'failed', exitCode: 23 });
    assert.deepEqual(JSON.parse(receipt.workload.stdout), { protected: true });
    assert.match(receipt.error, /exit 23/);
  });

  await runCase('a CPU-bound skill cannot cancel the independent deadline', { timeout: 30_000 }, async (context) => {
    const options = fixture(context, deadlineSource);
    const review = await approved(options, 2);
    const receipt = await runPilot(review.id, { store: options.store });
    checkedReceipt(receipt, { status: 'failed', exitCode: 124 });
    assert.match(receipt.error, /exit 124/);
  });

  await runCase('killing the host CLI preserves the container deadline and recovery verifies cleanup', { timeout: 40_000 }, async (context) => {
    const options = fixture(context, deadlineSource);
    const review = await approved(options, 6);
    const child = spawn(process.execPath, [cli, 'pilot', 'run', review.id, '--store', options.store, '--json'], {
      cwd: options.root, env: safeEnvironment(), shell: false, windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    // Drain pipes so killing the CLI is the only interruption under test.
    child.stdout.resume();
    child.stderr.resume();
    const closed = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    try {
      const receipt = await waitFor(async () => {
        const runs = join(options.store, 'runs');
        if (!existsSync(runs)) return false;
        for (const id of readdirSync(runs)) {
          let current;
          try { current = JSON.parse(readFileSync(join(runs, id, 'receipt.json'), 'utf8')); }
          catch (error) { if (error.code === 'ENOENT' || error instanceof SyntaxError) continue; throw error; }
          if (current.status !== 'active') continue;
          const [inspection] = JSON.parse(await options.docker(['inspect', current.containerName]));
          assert.equal(inspection.Config.Labels['dev.vibeaudit.pilot'], current.containerName);
          if (inspection.State.Running) return current;
        }
        return false;
      }, 15_000, 'an active, ownership-labelled pilot container');
      assert.equal(receipt.isolationVerified, true);
      assert.equal(child.kill('SIGKILL'), true);
      await closed;
      const finished = await waitFor(async () => {
        const [inspection] = JSON.parse(await options.docker(['inspect', receipt.containerName]));
        return inspection.State.Running ? false : inspection;
      }, (review.policy.seconds + 5) * 1000, 'the container deadline after loss of the host CLI');
      assert.equal(finished.State.ExitCode, 124);
      assert.equal(finished.State.OOMKilled, false);
      assert.equal(statusPilot({ store: options.store }).runs[0].status, 'unverified');
      const recovered = await recoverPilot(receipt.runId, { store: options.store });
      recordReceipt({ ...recovered, workload: { exitCode: finished.State.ExitCode, oomKilled: finished.State.OOMKilled } });
      assert.equal(recovered.status, 'interrupted');
      assert.equal(recovered.cleanupVerified, true);
      assert.ok(recovered.recoveredAt);
      assert.deepEqual(JSON.parse(readFileSync(recovered.receiptPath, 'utf8')), recovered);
      assert.equal(await options.docker(['ps', '--all', '--filter',
        `label=dev.vibeaudit.pilot=${receipt.containerName}`, '--format', '{{.Names}}']), '');
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await closed;
    }
  });
  evidence.status = evidence.cases.length === 5 && evidence.cases.every((result) => result.status === 'passed') ? 'passed' : 'failed';
  } catch (error) {
    evidence.prerequisites ||= 'failed';
    evidence.failure = error.name;
    throw error;
  } finally {
    evidence.finishedAt = new Date().toISOString();
    saveEvidence();
  }
});
