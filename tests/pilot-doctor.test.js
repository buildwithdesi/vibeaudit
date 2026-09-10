import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import test from 'node:test';
import { doctorPilot } from '../src/guard/pilot.js';

const image = `node@sha256:${'a'.repeat(64)}`;
const imageId = `sha256:${'b'.repeat(64)}`;
const imageInfo = { Id: imageId, Os: 'linux', Config: { Volumes: null, Env: ['PATH=/usr/local/bin:/usr/bin:/bin', 'NODE_VERSION=22.0.0'] } };
const response = (value) => ({ code: 0, stdout: JSON.stringify(value), stderr: '' });
const host = process.platform === 'win32' ? 'npipe:////./pipe/dockerDesktopLinuxEngine' : 'unix:///var/run/docker.sock';

// Mocked inspection proves diagnostic behavior only, never runtime containment.
function commands(replies = [response('linux'), response([imageInfo])]) {
  const calls = [];
  return { calls, dependencies: {
    resolveExecutable: (name, forbidden) => {
      assert.equal(name, 'docker');
      assert.equal(forbidden, process.cwd());
      return process.execPath;
    },
    command: async (executable, args, options) => {
      calls.push({ executable, args, options });
      assert.deepEqual(args.slice(0, 4), ['--config', join(options.cwd, 'client'), '--host', host]);
      assert.equal(readFileSync(join(options.cwd, 'client', 'config.json'), 'utf8'), '{}\n');
      assert.ok(isAbsolute(executable));
      assert.ok(isAbsolute(options.cwd));
      assert.equal(options.timeout, 15000);
      assert.equal(options.maxBytes, 512 * 1024);
      assert.deepEqual(args.slice(4), calls.length === 1
        ? ['info', '--format', '{{json .OSType}}'] : ['image', 'inspect', image]);
      assert.ok(replies.length, 'Doctor must not run any additional Docker commands.');
      return replies.shift();
    },
  } };
}

function assertDiagnostic(result, status, reasonCode) {
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.status, status);
  assert.equal(result.reasonCode, reasonCode);
  assert.equal(result.isolationVerified, false);
  assert.equal(result.clientCleanupVerified, true);
  assert.ok(result.message.length > 0);
  assert.ok(result.nextStep.length > 0);
  assert.match(result.note, /not active or verified/);
  assert.ok(result.checks.some((check) => check.reasonCode === reasonCode) || reasonCode === 'runtime_ready');
}

test('doctor checks readiness without Docker mutations, store access, or inherited Docker configuration', async (t) => {
  const fixture = mkdtempSync(join(tmpdir(), 'pilot-doctor-test-'));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const store = join(fixture, 'state');
  mkdirSync(store);
  writeFileSync(join(store, 'approval.json'), '{"fixture":"leave untouched"}\n');
  const before = readFileSync(join(store, 'approval.json'), 'utf8');
  const fakeEnvironment = { DOCKER_HOST: 'tcp://untrusted.invalid:2375', DOCKER_CONTEXT: 'untrusted',
    DOCKER_CONFIG: store, DOCKER_CERT_PATH: store, DOCKER_AUTH_CONFIG: 'FAKE_TEST_AUTH',
    HTTP_PROXY: 'http://untrusted.invalid', NODE_OPTIONS: '--inspect', OPENAI_API_KEY: 'FAKE_TEST_ONLY' };
  const previous = Object.fromEntries(Object.keys(fakeEnvironment).map((key) => [key, process.env[key]]));
  Object.assign(process.env, fakeEnvironment);
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
  const { calls, dependencies } = commands();
  const result = await doctorPilot({ image, store }, dependencies);
  assertDiagnostic(result, 'ready', 'runtime_ready');
  assert.equal(result.imageId, imageId);
  assert.equal(result.host, host);
  assert.equal(calls.length, 2);
  assert.deepEqual(result.checks.map((check) => check.name), ['image_reference', 'docker', 'engine', 'image']);
  for (const call of calls) {
    for (const key of Object.keys(fakeEnvironment)) assert.equal(call.options.env[key], undefined, `${key} must not reach Docker`);
    assert.equal(existsSync(call.options.cwd), false, 'Temporary client must be removed after doctor returns.');
  }
  assert.equal(readFileSync(join(store, 'approval.json'), 'utf8'), before);
  assert.deepEqual(readdirSync(store), ['approval.json']);
  assert.equal(existsSync(join(fixture, 'unused-store')), false);
});

test('doctor rejects missing, mutable, or malformed image references before resolving Docker', async () => {
  for (const candidate of [undefined, 'node:22', 'node', 'node@sha256:abc', `untrusted/${image}`, `${image}\n--privileged`]) {
    const result = await doctorPilot({ image: candidate }, {
      resolveExecutable: () => assert.fail('Invalid images must not reach executable resolution.'),
    });
    assertDiagnostic(result, 'blocked', 'invalid_image');
  }
});

test('doctor requires a trusted executable outside cwd and never accepts relative paths', async () => {
  for (const executable of [null, 'docker', join(process.cwd(), 'docker.exe')]) {
    const result = await doctorPilot({ image }, {
      resolveExecutable: () => executable,
      command: () => assert.fail('An untrusted executable must never run.'),
    });
    assertDiagnostic(result, 'unavailable', 'docker_unavailable');
    assert.match(result.nextStep, /outside the skill and checkout/);
  }
});

for (const [label, reply, status, reasonCode] of [
  ['stopped engine', { code: 1, stderr: 'FAKE_PRIVATE_DIAGNOSTIC' }, 'unavailable', 'engine_unavailable'],
  ['Windows engine', response('windows'), 'blocked', 'linux_engine_required'],
  ['malformed engine response', { code: 0, stdout: 'linux' }, 'blocked', 'engine_response_invalid'],
  ['unknown engine response', response('unexpected'), 'blocked', 'engine_response_invalid'],
  ['empty engine response', response(null), 'blocked', 'engine_response_invalid'],
  ['engine timeout', { code: null, failure: 'timeout', failureCode: 'command_timeout' }, 'unavailable', 'command_timeout'],
  ['engine output limit', { code: null, failure: 'limit', failureCode: 'output_limit_exceeded' }, 'blocked', 'output_limit_exceeded'],
  ['disappearing executable', { code: -1, failure: 'unavailable', failureCode: 'docker_unavailable' }, 'unavailable', 'docker_unavailable'],
]) {
  test(`doctor diagnoses ${label} without touching images or approvals`, async () => {
    const { calls, dependencies } = commands([reply]);
    const result = await doctorPilot({ image }, dependencies);
    assertDiagnostic(result, status, reasonCode);
    assert.equal(calls.length, 1);
    assert.equal(existsSync(calls[0].options.cwd), false);
    assert.doesNotMatch(JSON.stringify(result), /FAKE_PRIVATE_DIAGNOSTIC/);
  });
}

for (const [label, reply, status, reasonCode] of [
  ['missing image', { code: 1, stderr: `Error: No such image: ${image}` }, 'unavailable', 'image_missing'],
  ['image inspection failure', { code: 1, stderr: 'FAKE_PRIVATE_DIAGNOSTIC' }, 'unavailable', 'image_inspection_failed'],
  ['image timeout', { code: null, failure: 'timeout', failureCode: 'command_timeout' }, 'unavailable', 'command_timeout'],
  ['image output limit', { code: null, failure: 'limit', failureCode: 'output_limit_exceeded' }, 'blocked', 'output_limit_exceeded'],
  ['malformed image JSON', { code: 0, stdout: '{' }, 'blocked', 'image_response_invalid'],
  ['empty image list', response([]), 'blocked', 'image_response_invalid'],
  ['null image', response([null]), 'blocked', 'image_response_invalid'],
  ['multiple images', response([imageInfo, imageInfo]), 'blocked', 'image_response_invalid'],
  ['missing image configuration', response([{ Id: imageId, Os: 'linux' }]), 'blocked', 'image_response_invalid'],
  ['invalid image ID', response([{ ...imageInfo, Id: 'mutable' }]), 'blocked', 'image_response_invalid'],
  ['invalid image volumes', response([{ ...imageInfo, Config: { Volumes: [] } }]), 'blocked', 'image_response_invalid'],
  ['invalid image environment', response([{ ...imageInfo, Config: { Env: [null] } }]), 'blocked', 'image_response_invalid'],
  ['Windows image', response([{ ...imageInfo, Os: 'windows' }]), 'blocked', 'image_unsuitable'],
  ['extra image volumes', response([{ ...imageInfo, Config: { Volumes: { '/data': {} } } }]), 'blocked', 'image_unsuitable'],
  ['unsupported image environment', response([{ ...imageInfo, Config: { Env: ['HTTP_PROXY=http://untrusted.invalid'] } }]), 'blocked', 'image_unsuitable'],
]) {
  test(`doctor fails closed for ${label}`, async () => {
    const { calls, dependencies } = commands([response('linux'), reply]);
    const result = await doctorPilot({ image }, dependencies);
    assertDiagnostic(result, status, reasonCode);
    assert.equal(calls.length, 2);
    assert.equal(existsSync(calls[0].options.cwd), false);
    assert.doesNotMatch(JSON.stringify(result), /FAKE_PRIVATE_DIAGNOSTIC/);
    if (reasonCode === 'image_missing') assert.ok(result.nextStep.includes(`docker --host ${host} pull ${image}`));
  });
}

test('doctor cleans its temporary client even when command execution throws unexpectedly', async () => {
  let directory;
  const result = await doctorPilot({ image }, {
    resolveExecutable: () => process.execPath,
    command: (_executable, _args, options) => {
      directory = options.cwd;
      throw new Error('FAKE_PRIVATE_DIAGNOSTIC');
    },
  });
  assertDiagnostic(result, 'blocked', 'client_check_failed');
  assert.equal(existsSync(directory), false);
  assert.doesNotMatch(JSON.stringify(result), /FAKE_PRIVATE_DIAGNOSTIC/);
});

test('real pilot doctor CLI has actionable text, stable JSON and help without requiring Docker', () => {
  const cli = (args) => spawnSync(process.execPath, [resolve('bin/vibeguard.js'), 'pilot', ...args], {
    encoding: 'utf8', timeout: 120_000,
  });
  const help = cli(['doctor', '--help']);
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /pilot doctor --image/);
  assert.match(help.stdout, /readiness does not verify active isolation/);
  const invalid = cli(['doctor', '--image', 'node:latest', '--json']);
  assert.equal(invalid.status, 4, invalid.stderr);
  assertDiagnostic(JSON.parse(invalid.stdout), 'blocked', 'invalid_image');
  const plain = cli(['doctor', '--image', 'node:latest']);
  assert.equal(plain.status, 4, plain.stderr);
  assert.match(plain.stdout, /^BLOCKED:/);
  assert.match(plain.stdout, /Next step: Choose and review an official Node image digest/);
  assert.match(plain.stdout, /not active or verified/);
  const extra = cli(['doctor', '--image', image, '--store', 'unexpected']);
  assert.equal(extra.status, 4);
  assert.match(extra.stderr, /does not read or change a pilot store/);
});
