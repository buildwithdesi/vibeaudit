import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout, clearTimeout } from 'node:timers';
import { findTrustedExecutable } from '../trusted-tools.js';
import { analyzeAgentControlContent } from './agent-files.js';

const SUPERVISOR = fileURLToPath(new URL('./pilot-supervisor.mjs', import.meta.url));
const MAX_BYTES = 10 * 1024 * 1024;
const MAX_FILES = 256;
const ID = /^[a-f0-9]{64}$/;
const RUN_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const IMAGE = /^node@sha256:[a-f0-9]{64}$/;
const NODE_IMAGE_ENV = /^(?:PATH|NODE_VERSION|YARN_VERSION|NODE_OPTIONS|NODE_PATH)=/;
const hash = (data) => createHash('sha256').update(data).digest('hex');
const json = (value) => JSON.stringify(value);
const inside = (parent, child) => {
  const rel = relative(resolve(parent), resolve(child));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
};

function noLinks(path) {
  for (let current = resolve(path); ; current = dirname(current)) {
    try {
      if (lstatSync(current).isSymbolicLink()) throw new Error('Symbolic links and junctions are not allowed.');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (dirname(current) === current) break;
  }
}

function stateRoot(store) {
  const root = resolve(store || join(homedir(), '.vibeaudit', 'pilot'));
  noLinks(root);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  return realpathSync(root);
}

function put(path, value, exclusive = false) {
  noLinks(path);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: exclusive ? 'wx' : 'w' });
}

function get(path) {
  noLinks(path);
  if (lstatSync(path).size > MAX_BYTES * 2) throw new Error('Pilot record is too large.');
  return JSON.parse(readFileSync(path, 'utf8'));
}

function policyFor(seconds = 30) {
  if (!Number.isInteger(seconds) || seconds < 1 || seconds > 60) throw new Error('Deadline must be 1–60 whole seconds.');
  return {
    version: 1, backend: 'docker-linux-local', network: 'none', hostCredentials: false,
    skill: 'read-only', input: 'read-only', scratchMiB: 16, memoryMiB: 256,
    cpus: 1, pids: 64, workloadUid: 65534, seconds,
    supervisorSha256: hash(readFileSync(SUPERVISOR)),
  };
}

function fileName(path) {
  if (!path || path.length > 240 || path.split('/').some((part) =>
    !/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(part) || /[.]$/.test(part))) {
    throw new Error('File names must be plain relative paths; hidden files and traversal are not allowed.');
  }
}

function snapshot(root, budget) {
  noLinks(root);
  if (!lstatSync(root).isDirectory()) throw new Error('Skill and input must be directories.');
  const files = [];
  const names = new Set();
  function walk(directory, prefix = '') {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      budget.entries = (budget.entries || 0) + 1;
      if (budget.entries > 512) throw new Error('Pilot bundle exceeds 512 directory entries.');
      const path = `${prefix}${entry.name}`;
      fileName(path);
      if (names.has(path.toLowerCase())) throw new Error('Case-colliding paths are not allowed.');
      names.add(path.toLowerCase());
      const full = join(directory, entry.name);
      const stat = lstatSync(full);
      if (stat.isSymbolicLink()) throw new Error('Symbolic links and junctions are not allowed.');
      if (stat.isDirectory()) { walk(full, `${path}/`); continue; }
      if (!stat.isFile() || stat.nlink > 1) throw new Error('Special files and hard links are not allowed.');
      if (++budget.count > MAX_FILES || (budget.bytes += stat.size) > MAX_BYTES) throw new Error('Pilot bundle exceeds 256 files or 10 MiB.');
      const bytes = readFileSync(full);
      if (bytes.length !== stat.size) throw new Error('A source file changed while being read. Review again.');
      files.push({ path, size: bytes.length, sha256: hash(bytes), data: bytes.toString('base64') });
    }
  }
  walk(root);
  return files;
}

function manifestOf(bundles) {
  return Object.fromEntries(['skill', 'input'].map((key) => [key,
    bundles[key].map(({ path, size, sha256 }) => ({ path, size, sha256 })),
  ]));
}

function reviewId(review) {
  return hash(json({ version: 1, skillRoot: review.skillRoot, inputRoot: review.inputRoot,
    entry: review.entry, image: review.image, policy: review.policy, manifest: review.manifest,
    findings: review.findings }));
}

function checkRoots(skill, input, root) {
  for (const path of [skill, input]) {
    noLinks(path);
    if (inside(path, root) || inside(root, path)) throw new Error('Pilot state must stay outside skill and input directories.');
  }
  if (inside(skill, input) || inside(input, skill)) throw new Error('Use separate skill and input directories.');
}

/** Review data only. This never starts Docker or executes a skill. */
export async function reviewPilot({ skill, input, entry = 'run.mjs', image, store, seconds = 30 }) {
  if (!skill || !input) throw new Error('Provide a skill directory and --input directory.');
  if (!IMAGE.test(image || '')) throw new Error('Use a pre-pulled official Node image pinned as node@sha256:<64 hex characters>.');
  fileName(entry);
  if (!entry.endsWith('.mjs')) throw new Error('The offline pilot entry must be a .mjs file.');
  const root = stateRoot(store);
  const skillRoot = resolve(skill), inputRoot = resolve(input);
  checkRoots(skillRoot, inputRoot, root);
  const budget = { bytes: 0, count: 0 };
  const bundles = { skill: snapshot(skillRoot, budget), input: snapshot(inputRoot, budget) };
  if (!bundles.skill.some((file) => file.path === 'SKILL.md') || !bundles.skill.some((file) => file.path === entry)) {
    throw new Error('The skill must contain SKILL.md and the selected entry file.');
  }
  const findings = bundles.skill.filter((file) => /\.(?:md|mjs|js|cjs|json)$/i.test(file.path)).flatMap((file) =>
    analyzeAgentControlContent(Buffer.from(file.data, 'base64').toString('utf8'), file.path));
  const review = { skillRoot, inputRoot, entry, image, policy: policyFor(seconds),
    manifest: manifestOf(bundles), findings, bundles };
  review.id = reviewId(review);
  put(join(root, 'reviews', `${review.id}.json`), review);
  const summary = { ...review };
  delete summary.bundles;
  return summary;
}

function loadReview(id, root) {
  if (!ID.test(id || '')) throw new Error('Invalid review ID.');
  const review = get(join(root, 'reviews', `${id}.json`));
  if (review.id !== id || reviewId(review) !== id || !IMAGE.test(review.image) ||
      json(review.policy) !== json(policyFor(review.policy?.seconds))) throw new Error('Review or protection policy changed. Review again.');
  fileName(review.entry);
  checkRoots(review.skillRoot, review.inputRoot, root);
  const budget = { count: 0, bytes: 0 };
  for (const key of ['skill', 'input']) {
    const names = new Set();
    for (const file of review.bundles[key]) {
      fileName(file.path);
      if (names.has(file.path.toLowerCase())) throw new Error('Duplicate bundle path.');
      names.add(file.path.toLowerCase());
      const bytes = Buffer.from(file.data, 'base64');
      if (++budget.count > MAX_FILES || (budget.bytes += bytes.length) > MAX_BYTES ||
          bytes.length !== file.size || hash(bytes) !== file.sha256) throw new Error('Reviewed bytes changed. Review again.');
    }
  }
  if (json(manifestOf(review.bundles)) !== json(review.manifest)) throw new Error('Review manifest changed.');
  return review;
}

export function approvePilot(id, { store, accept } = {}) {
  if (accept !== id) throw new Error('Approval requires --accept with the exact reviewed digest.');
  const root = stateRoot(store);
  loadReview(id, root);
  const now = Date.now();
  const approval = { id, createdAt: now, expiresAt: now + 10 * 60 * 1000 };
  put(join(root, 'approvals', `${id}.json`), approval, true);
  return approval;
}

export function revokePilot(id, { store } = {}) {
  if (!ID.test(id || '')) throw new Error('Invalid review ID.');
  const path = join(stateRoot(store), 'approvals', `${id}.json`);
  noLinks(path);
  rmSync(path, { force: true });
  return { id, status: 'revoked', note: 'Pending approval revoked. Use recover with a run ID to stop an active run.' };
}

function dockerEnvironment() {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    /^(?:PATH|SystemRoot|WINDIR|TEMP|TMP|HOME|USERPROFILE)$/i.test(key)));
}

function execute(executable, args, { cwd, env = dockerEnvironment(), timeout = 15000, maxBytes = 512 * 1024 } = {}) {
  return new Promise((resolveResult) => {
    let stdout = '', stderr = '', bytes = 0, failure, failureCode;
    const child = spawn(executable, args, { cwd, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const timer = setTimeout(() => { failure = 'Docker command timed out'; failureCode = 'command_timeout'; child.kill('SIGKILL'); }, timeout);
    for (const stream of ['stdout', 'stderr']) child[stream].on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > maxBytes) { failure = 'Output limit exceeded'; failureCode = 'output_limit_exceeded'; child.kill('SIGKILL'); return; }
      if (stream === 'stdout') stdout += chunk.toString('utf8'); else stderr += chunk.toString('utf8');
    });
    child.on('error', () => { failure = 'Docker executable unavailable'; failureCode = 'docker_unavailable'; });
    child.on('close', (code) => { clearTimeout(timer); resolveResult({ code, stdout, stderr, failure, failureCode }); });
  });
}

class PilotReadinessError extends Error {
  constructor(check, status, reasonCode, message, nextStep) {
    super(message);
    Object.assign(this, { check, status, reasonCode, nextStep });
  }
}

const localDockerHost = () => process.platform === 'win32'
  ? 'npipe:////./pipe/dockerDesktopLinuxEngine' : 'unix:///var/run/docker.sock';
const startEngine = () => process.platform === 'win32'
  ? 'Open Docker Desktop, select Linux containers, and wait until its engine is running. Then rerun pilot doctor.'
  : 'Start the local Linux Docker daemon and confirm your account can access /var/run/docker.sock. Then rerun pilot doctor.';

function dockerClient(directory, forbidden = [], { command = execute, resolveExecutable = findTrustedExecutable } = {}) {
  // The working directory can be attacker-controlled even when it is not the skill root.
  const executable = resolveExecutable('docker', process.cwd());
  if (!executable || !isAbsolute(executable) || [process.cwd(), ...forbidden].some((path) => inside(path, executable))) {
    throw new PilotReadinessError('docker', 'unavailable', 'docker_unavailable',
      'Trusted Docker executable unavailable outside the working and source directories.',
      'Install or repair Docker through its official setup, with its executable on an absolute PATH directory outside the skill and checkout. Then rerun pilot doctor.');
  }
  const config = join(directory, 'client');
  mkdirSync(config, { recursive: true, mode: 0o700 });
  put(join(config, 'config.json'), {});
  // Fixed local endpoints avoid remote contexts and inherited DOCKER_HOST.
  const host = localDockerHost();
  const call = (args, options) => command(executable, ['--config', config, '--host', host, ...args], {
    cwd: directory, env: dockerEnvironment(), timeout: 15000, maxBytes: 512 * 1024, ...options,
  });
  const checked = async (args, options) => {
    const result = await call(args, options);
    if (result.code !== 0 || result.failure) throw new Error(result.failure || `Docker ${args[0]} failed; check the local Linux engine and pinned image.`);
    return result.stdout.trim();
  };
  return { call, checked, host };
}

async function inspectPilotRuntime(docker, image, checks = []) {
  const failure = (check, result) => {
    if (result.failureCode === 'command_timeout') throw new PilotReadinessError(check, 'unavailable',
      'command_timeout', `Docker ${check} inspection timed out.`, startEngine());
    if (result.failureCode === 'output_limit_exceeded') throw new PilotReadinessError(check, 'blocked',
      'output_limit_exceeded', `Docker ${check} inspection exceeded its output limit.`,
      'Inspect the local Docker installation and its response before retrying. Do not approve a skill yet.');
    if (result.failureCode === 'docker_unavailable') throw new PilotReadinessError('docker', 'unavailable',
      'docker_unavailable', 'The trusted Docker executable could not be started.',
      'Repair the local Docker executable and rerun pilot doctor.');
  };
  const engine = await docker.call(['info', '--format', '{{json .OSType}}']);
  failure('engine', engine);
  if (engine.code !== 0 || engine.failure) throw new PilotReadinessError('engine', 'unavailable',
    'engine_unavailable', 'The fixed local Docker engine is unavailable.', startEngine());
  let os;
  try { os = JSON.parse(engine.stdout); } catch { /* Invalid responses must never establish readiness. */ }
  if (typeof os !== 'string' || !['linux', 'windows'].includes(os)) throw new PilotReadinessError('engine', 'blocked',
    'engine_response_invalid', 'Docker returned an invalid engine inspection response.',
    'Check the local Docker installation and rerun pilot doctor after its engine inspection is working.');
  if (os !== 'linux') throw new PilotReadinessError('engine', 'blocked', 'linux_engine_required',
    'The pilot requires a local Linux Docker engine.', startEngine());
  checks.push({ name: 'engine', status: 'ready', reasonCode: 'linux_engine_ready', message: 'The fixed local endpoint reports a Linux engine.' });

  const imageResult = await docker.call(['image', 'inspect', image]);
  failure('image', imageResult);
  if (imageResult.code !== 0 || imageResult.failure) {
    if (/no such (?:image|object)/i.test(imageResult.stderr || '')) throw new PilotReadinessError('image', 'unavailable',
      'image_missing', 'The approved pinned image is not present in the local engine.',
      `Provision the reviewed digest explicitly with docker --host ${docker.host} pull ${image}, then rerun pilot doctor.`);
    throw new PilotReadinessError('image', 'unavailable', 'image_inspection_failed',
      'Docker could not inspect the approved pinned image.',
      'Check the local engine and the exact image digest. Rerun pilot doctor before reviewing or approving a skill.');
  }
  let images;
  try { images = JSON.parse(imageResult.stdout); } catch { /* Fail closed below. */ }
  const imageInfo = Array.isArray(images) && images.length === 1 ? images[0] : null;
  const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
  const present = (value) => value !== null && value !== undefined;
  if (!object(imageInfo) || typeof imageInfo.Os !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(imageInfo.Id || '') ||
      !object(imageInfo.Config) || (present(imageInfo.Config.Volumes) && !object(imageInfo.Config.Volumes)) ||
      (present(imageInfo.Config.Env) && (!Array.isArray(imageInfo.Config.Env) || imageInfo.Config.Env.some((value) => typeof value !== 'string')))) {
    throw new PilotReadinessError('image', 'blocked', 'image_response_invalid',
      'Docker returned an invalid image inspection response.',
      'Inspect the exact image and local Docker installation. Do not approve a skill until pilot doctor succeeds.');
  }
  if (imageInfo.Os !== 'linux' || Object.keys(imageInfo.Config.Volumes || {}).length ||
      (imageInfo.Config.Env || []).some((value) => !NODE_IMAGE_ENV.test(value))) {
    throw new PilotReadinessError('image', 'blocked', 'image_unsuitable',
      'The pinned image must use Linux, declare no extra volumes, and use only the pilot-supported Node environment.',
      'Select and provision a reviewed official Node Linux image without declared volumes or extra environment variables, then rerun pilot doctor with its digest.');
  }
  checks.push({ name: 'image', status: 'ready', reasonCode: 'pinned_image_ready', message: 'The pinned image is present and meets the inspected runtime requirements.' });
  return imageInfo;
}

/** Readiness only: no approval records, image pulls, containers, or host configuration changes.
 * The second argument is an internal command seam for source tests, never a CLI option. */
export async function doctorPilot({ image } = {}, dependencies = {}) {
  const result = { schemaVersion: 1, status: 'blocked', reasonCode: 'invalid_image', image: image || null,
    host: localDockerHost(), isolationVerified: false, clientCleanupVerified: true, checks: [],
    note: 'Readiness only. Isolation is not active or verified; run verifies each container before execution.' };
  let directory;
  try {
    if (!IMAGE.test(image || '')) throw new PilotReadinessError('image_reference', 'blocked', 'invalid_image',
      'Use an official Node image pinned as node@sha256:<64 lowercase hexadecimal characters>.',
      'Choose and review an official Node image digest, then pass its exact node@sha256 reference with --image.');
    result.checks.push({ name: 'image_reference', status: 'ready', reasonCode: 'image_reference_valid', message: 'The image reference uses an exact Node digest.' });
    directory = mkdtempSync(join(tmpdir(), 'vibeguard-pilot-doctor-'));
    result.clientCleanupVerified = false;
    const docker = dockerClient(directory, [], dependencies);
    result.checks.push({ name: 'docker', status: 'ready', reasonCode: 'docker_found', message: 'A Docker executable was resolved outside the working directory.' });
    const imageInfo = await inspectPilotRuntime(docker, image, result.checks);
    Object.assign(result, { status: 'ready', reasonCode: 'runtime_ready', imageId: imageInfo.Id,
      message: 'Local runtime prerequisites are ready.', nextStep: 'Run pilot review, inspect the exact files and policy, then approve only that review digest.' });
  } catch (error) {
    const problem = error instanceof PilotReadinessError ? error : new PilotReadinessError('client', 'blocked',
      'client_check_failed', 'The isolated Docker client check could not complete.',
      'Check access to the system temporary directory and the local Docker installation, then rerun pilot doctor.');
    Object.assign(result, { status: problem.status, reasonCode: problem.reasonCode, message: problem.message, nextStep: problem.nextStep });
    result.checks.push({ name: problem.check, status: problem.status, reasonCode: problem.reasonCode,
      message: problem.message, nextStep: problem.nextStep });
  } finally {
    if (directory) {
      try {
        rmSync(directory, { recursive: true, force: true });
        result.clientCleanupVerified = !existsSync(directory);
      } catch { /* An unverified cleanup cannot return ready. */ }
      if (!result.clientCleanupVerified) Object.assign(result, { status: 'blocked', reasonCode: 'client_cleanup_failed',
        message: 'Temporary Docker client cleanup could not be verified.',
        nextStep: 'Check access to the system temporary directory and remove the abandoned vibeguard-pilot-doctor directory before retrying.' });
    }
  }
  return result;
}

function stage(review, directory) {
  const mounts = [];
  for (const key of ['skill', 'input']) {
    const destination = join(directory, key);
    mkdirSync(destination, { mode: 0o755 });
    for (const file of review.bundles[key]) {
      const path = join(destination, file.path);
      mkdirSync(dirname(path), { recursive: true, mode: 0o755 });
      writeFileSync(path, Buffer.from(file.data, 'base64'), { flag: 'wx', mode: 0o444 });
    }
    mounts.push({ source: destination, target: `/${key}` });
  }
  const runner = join(directory, 'runner');
  mkdirSync(runner, { mode: 0o755 });
  writeFileSync(join(runner, 'supervisor.mjs'), readFileSync(SUPERVISOR), { flag: 'wx', mode: 0o444 });
  mounts.push({ source: runner, target: '/runner' });
  if (mounts.some(({ source }) => /[,\r\n]/.test(source))) throw new Error('Pilot store path cannot contain commas or newlines.');
  return mounts;
}

function createArgs(review, name, mounts) {
  return ['create', '--pull=never', '--name', name, '--label', `dev.vibeaudit.pilot=${name}`,
    '--network=none', '--read-only', '--cap-drop=ALL', '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=KILL',
    '--security-opt=no-new-privileges:true', '--user=0:0', '--pids-limit=64', '--memory=256m', '--memory-swap=256m',
    '--cpus=1', '--ipc=none', '--restart=no', '--no-healthcheck', '--log-driver=none',
    '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777', '--workdir=/tmp',
    '--env=NODE_OPTIONS=', '--env=NODE_PATH=', '--entrypoint=/usr/local/bin/node',
    ...mounts.flatMap(({ source, target }) => ['--mount', `type=bind,source=${source},target=${target},readonly`]),
    review.image, '/runner/supervisor.mjs', `/skill/${review.entry}`, String(review.policy.seconds)];
}

export function assertPilotIsolation(container, review, name, mounts, imageId) {
  const h = container.HostConfig, c = container.Config;
  const equalSet = (actual, expected) => json([...(actual || [])].map((v) => v.toUpperCase()).sort()) === json([...expected].sort());
  // Docker normalizes SETUID to CAP_SETUID in its inspection response.
  const capabilities = (values) => (values || []).map((value) => value.replace(/^CAP_/i, ''));
  const actualMounts = container.Mounts || [];
  const requestedMounts = h.Mounts || [];
  if (container.Image !== imageId || c.User !== '0:0' || c.WorkingDir !== '/tmp' ||
      json(c.Entrypoint) !== json(['/usr/local/bin/node']) ||
      json(c.Cmd) !== json(['/runner/supervisor.mjs', `/skill/${review.entry}`, String(review.policy.seconds)]) ||
      c.Labels?.['dev.vibeaudit.pilot'] !== name || json(c.Healthcheck?.Test) !== json(['NONE']) ||
      h.NetworkMode !== 'none' || !h.ReadonlyRootfs || h.Privileged || h.PidMode || h.IpcMode !== 'none' ||
      h.RestartPolicy?.Name !== 'no' || h.AutoRemove || !equalSet(capabilities(h.CapDrop), ['ALL']) ||
      !equalSet(capabilities(h.CapAdd), ['KILL', 'SETGID', 'SETUID']) ||
      !equalSet(h.SecurityOpt, ['NO-NEW-PRIVILEGES:TRUE']) || h.PidsLimit !== 64 ||
      h.Memory !== 256 * 1024 * 1024 || h.MemorySwap !== h.Memory || h.NanoCpus !== 1e9 ||
      h.LogConfig?.Type !== 'none' || Object.keys(h.Tmpfs || {}).length !== 1 ||
      h.Tmpfs['/tmp'] !== 'rw,noexec,nosuid,nodev,size=16m,mode=1777' ||
      (h.Devices || []).length || (h.Binds || []).length || (h.VolumesFrom || []).length ||
      requestedMounts.length !== mounts.length || mounts.some((mount) => !requestedMounts.some((actual) =>
        actual.Type === 'bind' && actual.Target === mount.target && actual.ReadOnly === true &&
        (actual.Source === mount.source || (process.platform === 'win32' &&
          actual.Source === `/run/desktop/mnt/host/${mount.source[0].toLowerCase()}${mount.source.slice(2).replace(/\\/g, '/')}`)))) ||
      actualMounts.length !== mounts.length || mounts.some((mount) => !actualMounts.some((actual) =>
        actual.Type === 'bind' && actual.Destination === mount.target && actual.RW === false)) ||
      (c.Env || []).some((value) => !NODE_IMAGE_ENV.test(value))) {
    throw new Error('Docker did not apply the required isolation policy. Execution blocked.');
  }
}

export async function runPilot(id, { store } = {}) {
  if (!ID.test(id || '')) throw new Error('Invalid review ID.');
  const root = stateRoot(store), runId = randomUUID();
  const directory = join(root, 'runs', runId);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const receiptPath = join(directory, 'receipt.json');
  const receipt = { schemaVersion: 1, runId, reviewId: id, status: 'blocked', startedAt: new Date().toISOString(),
    containerName: `vibeguard-pilot-${runId}`, isolationVerified: false, cleanupVerified: false, receiptPath };
  put(receiptPath, receipt);
  let docker, created = false;
  try {
    const approvalPath = join(root, 'approvals', `${id}.json`);
    noLinks(approvalPath);
    // Atomic rename gives exactly one concurrent caller the one-use approval.
    renameSync(approvalPath, join(directory, 'approval.json'));
    const approval = get(join(directory, 'approval.json'));
    if (approval.id !== id || !Number.isFinite(approval.expiresAt) ||
        !Number.isFinite(approval.createdAt) || approval.createdAt > Date.now() ||
        approval.expiresAt <= Date.now() || approval.expiresAt - approval.createdAt > 600000) throw new Error('Approval expired or invalid.');
    const review = loadReview(id, root);
    const budget = { bytes: 0, count: 0 };
    const current = { skill: snapshot(review.skillRoot, budget), input: snapshot(review.inputRoot, budget) };
    if (json(manifestOf(current)) !== json(review.manifest)) throw new Error('Skill or input changed after review. Review again.');
    receipt.policy = review.policy;
    receipt.image = review.image;
    const mounts = stage(review, directory);
    receipt.status = 'unavailable';
    docker = dockerClient(directory, [review.skillRoot, review.inputRoot, root]);
    const imageInfo = await inspectPilotRuntime(docker, review.image);
    receipt.imageId = imageInfo.Id;
    receipt.status = 'starting';
    put(receiptPath, receipt);
    created = true; // Also clean up a create request whose response was lost.
    await docker.checked(createArgs(review, receipt.containerName, mounts));
    const [inspection] = JSON.parse(await docker.checked(['inspect', receipt.containerName]));
    assertPilotIsolation(inspection, review, receipt.containerName, mounts, imageInfo.Id);
    receipt.isolationVerified = true;
    receipt.enforced = { network: inspection.HostConfig.NetworkMode, readOnlyRootfs: inspection.HostConfig.ReadonlyRootfs,
      securityOptions: inspection.HostConfig.SecurityOpt, capDrop: inspection.HostConfig.CapDrop, capAdd: inspection.HostConfig.CapAdd,
      memoryBytes: inspection.HostConfig.Memory, pids: inspection.HostConfig.PidsLimit,
      mounts: inspection.Mounts.map(({ Destination, RW, Type }) => ({ destination: Destination, writable: RW, type: Type })) };
    receipt.status = 'active';
    put(receiptPath, receipt);
    const result = await docker.call(['start', '--attach', receipt.containerName], {
      timeout: (review.policy.seconds + 15) * 1000, maxBytes: 128 * 1024,
    });
    const [finished] = JSON.parse(await docker.checked(['inspect', receipt.containerName]));
    receipt.workload = { trust: 'untrusted-output', stdout: result.stdout, stderr: result.stderr,
      exitCode: finished.State.ExitCode, oomKilled: finished.State.OOMKilled };
    if (result.failure || result.code !== 0 || finished.State.Running || !finished.State.FinishedAt ||
        finished.State.OOMKilled || finished.State.ExitCode !== 0) throw new Error(result.failure || `Workload failed (exit ${finished.State.ExitCode}).`);
    receipt.status = 'completed';
  } catch (error) {
    if (['active', 'starting'].includes(receipt.status)) receipt.status = 'failed';
    if (error instanceof PilotReadinessError) Object.assign(receipt, {
      status: error.status, reasonCode: error.reasonCode, nextStep: error.nextStep,
    });
    receipt.error = error.code === 'ENOENT' ? 'Review or one-use approval missing. Review and approve before running.' : error.message;
  } finally {
    if (created && docker) {
      const removal = await docker.call(['rm', '--force', receipt.containerName]);
      receipt.cleanupVerified = removal.code === 0 && !removal.failure;
      if (!receipt.cleanupVerified) { receipt.status = 'failed'; receipt.error = 'Container cleanup unverified. Use pilot recover with this run ID.'; }
    } else receipt.cleanupVerified = true;
    receipt.finishedAt = new Date().toISOString();
    put(receiptPath, receipt);
  }
  return receipt;
}

export function statusPilot({ store } = {}) {
  const root = stateRoot(store), directory = join(root, 'runs');
  noLinks(directory);
  if (!existsSync(directory)) return { runs: [] };
  const runs = readdirSync(directory).filter((id) => RUN_ID.test(id)).map((id) => {
    const receipt = get(join(directory, id, 'receipt.json'));
    return { runId: id, reviewId: receipt.reviewId,
      status: ['active', 'starting'].includes(receipt.status) ? 'unverified' : receipt.status,
      cleanupVerified: receipt.cleanupVerified, receiptPath: receipt.receiptPath };
  });
  return { runs, note: 'Interrupted runs remain unverified until recovered. Completed means exit 0 with checked isolation and cleanup; inspect output to verify task success.' };
}

export async function recoverPilot(runId, { store } = {}) {
  if (!RUN_ID.test(runId || '')) throw new Error('Invalid run ID.');
  const root = stateRoot(store), directory = join(root, 'runs', runId);
  const path = join(directory, 'receipt.json'), receipt = get(path);
  const name = `vibeguard-pilot-${runId}`;
  const docker = dockerClient(directory, [root]);
  // An unavailable daemon is never evidence that a container is gone.
  await docker.checked(['info', '--format', '{{.OSType}}']);
  const existing = await docker.checked(['ps', '--all', '--filter', `name=^/${name}$`, '--format', '{{.Names}}']);
  if (existing) {
    const [inspection] = JSON.parse(await docker.checked(['inspect', name]));
    if (inspection.Config.Labels?.['dev.vibeaudit.pilot'] !== name) throw new Error('Container ownership label does not match.');
    await docker.checked(['rm', '--force', name]);
  }
  receipt.cleanupVerified = true;
  if (receipt.status !== 'completed') receipt.status = 'interrupted';
  receipt.recoveredAt = new Date().toISOString();
  put(path, receipt);
  return receipt;
}
