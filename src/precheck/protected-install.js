import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { setTimeout, clearTimeout } from 'node:timers';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { assertSafeSpec, precheck } from './index.js';
import { assertProjectUnchanged, readProject, validateLock, validateManifest } from './npm-project.js';
import { startRegistryBroker } from './npm-registry-broker.js';
import { createIsolatedNpmEnv, findTrustedNpmCli, NPM_REGISTRY } from '../trusted-tools.js';

const ID = /^[a-f0-9]{64}$/;
const MAX_RECORD = 32 * 1024 * 1024;
const NAMES = ['node_modules', 'package-lock.json', 'package.json'];
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const encode = (value) => `${JSON.stringify(value, null, 2)}\n`;
const inside = (parent, child) => { const rel = relative(parent, child); return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel)); };

function noLinks(path) {
  for (let current = resolve(path); ; current = dirname(current)) {
    try { if (lstatSync(current).isSymbolicLink()) throw new Error('Symbolic links and junctions are not supported.'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (dirname(current) === current) break;
  }
}

function rootFor(store, project) {
  const root = resolve(store || join(homedir(), '.vibeaudit', 'npm'));
  noLinks(root);
  if (project && (inside(project, root) || inside(root, project))) throw new Error('The npm review store must be outside the project.');
  mkdirSync(root, { recursive: true, mode: 0o700 });
  return realpathSync(root);
}

function put(path, value, exclusive = false) {
  noLinks(path);
  if (exclusive) writeFileSync(path, encode(value), { flag: 'wx', mode: 0o600 });
  else {
    const temporary = `${path}.next`;
    noLinks(temporary);
    writeFileSync(temporary, encode(value), { mode: 0o600 });
    renameSync(temporary, path);
  }
}

function get(path) {
  noLinks(path);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_RECORD) throw new Error('Invalid or oversized npm review record.');
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** The supported Node/npm installation is trusted; target scripts and config are not. */
export function npmIdentity() {
  const cli = findTrustedNpmCli();
  if (!cli) throw new Error('A trusted npm installation beside Node is required.');
  const npmPackage = JSON.parse(readFileSync(join(dirname(cli), '..', 'package.json'), 'utf8'));
  return { node: process.version, npm: npmPackage.version, cliSha256: hash(readFileSync(cli)), platform: process.platform, arch: process.arch };
}

export function isolatedInstallEnv(directory) {
  // Do not inherit NODE_OPTIONS, tokens, proxy credentials, or application secrets.
  const source = {};
  for (const key of ['SystemRoot', 'SYSTEMROOT', 'WINDIR', 'ComSpec', 'COMSPEC', 'TEMP', 'TMP', 'TMPDIR', 'PATH', 'Path']) {
    if (process.env[key] !== undefined) source[key] = process.env[key];
  }
  source.HOME = directory;
  source.USERPROFILE = directory;
  source.NODE_USE_SYSTEM_CA = '1';
  return createIsolatedNpmEnv(source, { userConfig: join(directory, 'user.npmrc'), globalConfig: join(directory, 'global.npmrc') });
}

function prepareDirectory(directory) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  for (const name of ['.npmrc', 'user.npmrc', 'global.npmrc']) writeFileSync(join(directory, name), '', { mode: 0o600, flag: 'wx' });
}

export function runProtectedNpm(args, { cwd, cache, registry = NPM_REGISTRY }) {
  const cli = findTrustedNpmCli();
  if (!cli) throw new Error('A trusted npm installation beside Node is required.');
  return new Promise((fulfill, reject) => {
    const child = spawn(process.execPath, [cli, ...args, '--ignore-scripts', '--no-audit', '--no-fund',
      '--update-notifier=false', '--workspaces=false', '--include=dev', '--include=optional', '--include=peer',
      `--git=${join(cwd, 'disabled-git')}`, `--script-shell=${join(cwd, 'disabled-script-shell')}`,
      '--replace-registry-host=never', '--fetch-retries=0', '--logs-max=0', `--cache=${cache}`, `--prefix=${cwd}`, `--registry=${registry}`], {
      cwd, env: isolatedInstallEnv(cwd), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    let size = 0;
    let failure;
    const timer = setTimeout(() => { failure = 'timeout'; child.kill(); }, 120000);
    const collect = (chunk, isError) => {
      size += chunk.length;
      if (size > 2 * 1024 * 1024) { failure = 'output limit'; child.kill(); return; }
      if (isError) stderr += chunk.toString('utf8');
    };
    child.stdout.on('data', (chunk) => collect(chunk, false));
    child.stderr.on('data', (chunk) => collect(chunk, true));
    child.once('error', () => { clearTimeout(timer); reject(new Error('The trusted npm process could not start.')); });
    child.once('close', (status) => {
      clearTimeout(timer);
      if (status === 0 && !failure) { fulfill(); return; }
      // npm output can quote package scripts. Expose only a diagnostic code.
      const code = /\b(?:E[A-Z0-9_]{2,40})\b/.exec(stderr)?.[0];
      reject(new Error(`npm ${args[0]} failed (${failure || code || status || 'unknown'}). Project files were not installed by npm.`));
    });
  });
}

function loadReview(id, store) {
  if (!ID.test(id || '')) throw new Error('Use the complete review ID.');
  const root = rootFor(store);
  const directory = join(root, id);
  const plan = get(join(directory, 'review.json'));
  if (hash(encode(plan)) !== id || plan.version !== 1) throw new Error('Review changed; create a new review.');
  rootFor(store, plan.snapshot.project);
  return { root, directory, plan };
}

function summary(id, directory, plan) {
  return { id, status: plan.report.exitCode === 2 ? 'blocked' : 'ready', project: plan.snapshot.project,
    spec: plan.spec, expiresAt: plan.expiresAt, scripts: 'disabled', total: plan.report.total,
    packages: plan.report.results, reviewPath: join(directory, 'review.json'),
    note: 'Review covers exact package bytes and known advisories. It does not prove runtime safety. Installation scripts stay disabled.' };
}

/** Resolve against a snapshot of the real project. No target file or package code is executed. */
export async function reviewInstall({ project, spec, dev = false, store }, dependencies = {}) {
  assertSafeSpec(spec);
  if (/\.(?:tgz|tar|tar\.gz)$/i.test(spec)) throw new Error('Local archive specs are not supported. Use a public registry package name and version.');
  const snapshot = readProject(project || process.cwd());
  const root = rootFor(store, snapshot.project);
  const temporary = mkdtempSync(join(root, '.review-'));
  const workspace = join(temporary, 'resolve');
  const artifacts = join(temporary, 'artifacts');
  const runNpm = dependencies.runNpm || runProtectedNpm;
  const identity = (dependencies.identity || npmIdentity)();
  try {
    prepareDirectory(workspace);
    mkdirSync(artifacts, { mode: 0o700 });
    writeFileSync(join(workspace, 'package.json'), snapshot.files['package.json']);
    if (snapshot.files['package-lock.json'] !== null) writeFileSync(join(workspace, 'package-lock.json'), snapshot.files['package-lock.json']);
    // Validate registry metadata before npm sees it: a transitive URL must not
    // trigger an external fetch or local file read during dependency resolution.
    const broker = dependencies.runNpm ? null : await startRegistryBroker({ fetchImpl: dependencies.fetchImpl });
    try {
      await runNpm(['install', spec, '--package-lock-only', '--save-exact', dev ? '--save-dev' : '--save-prod'], {
        cwd: workspace, cache: join(workspace, 'cache'), registry: broker?.url || NPM_REGISTRY,
      });
    } finally {
      if (broker) { await broker.close(); broker.assertHealthy(); }
    }
    const manifest = readFileSync(join(workspace, 'package.json'), 'utf8');
    const lock = readFileSync(join(workspace, 'package-lock.json'), 'utf8');
    validateManifest(JSON.parse(manifest));
    const resolved = validateLock(JSON.parse(lock));
    const tree = [...new Map(resolved.map(({ name, version }) => [`${name}@${version}`, { name, version }])).values()];
    if (tree.length > 500) throw new Error('This pilot supports at most 500 distinct package versions.');
    const approvedArtifacts = new Map();
    let downloaded = 0;
    const report = await (dependencies.precheck || precheck)(spec, {
      resolve: () => tree, fetchImpl: dependencies.fetchImpl, reviewAll: true,
      onVerifiedArchive: ({ name, version, integrity, archive }) => {
        if ((downloaded += archive.length) > 200 * 1024 * 1024) throw new Error('The reviewed archives exceed the 200 MiB pilot limit.');
        if (`sha512-${createHash('sha512').update(archive).digest('base64')}` !== integrity) throw new Error('Verified archive changed.');
        const matching = resolved.filter((entry) => entry.name === name && entry.version === version);
        if (!matching.length || matching.some((entry) => entry.integrity !== integrity)) throw new Error('Resolved lockfile and registry archive integrity disagree.');
        const file = `${hash(`${name}@${version}:${integrity}`)}.tgz`;
        writeFileSync(join(artifacts, file), archive, { mode: 0o600, flag: 'wx' });
        approvedArtifacts.set(`${name}@${version}`, { name, version, integrity, file });
      },
    });
    if (report.exitCode !== 2 && (approvedArtifacts.size !== tree.length || report.results.length !== tree.length)) throw new Error('Artifact review is incomplete.');
    assertProjectUnchanged(snapshot);
    const now = (dependencies.now || Date.now)();
    const plan = { version: 1, spec, snapshot, manifest, lock, identity, createdAt: now, expiresAt: now + 10 * 60 * 1000,
      artifacts: [...approvedArtifacts.values()].sort((a, b) => a.file.localeCompare(b.file)), report };
    const id = hash(encode(plan));
    put(join(temporary, 'review.json'), plan, true);
    // Only delete the private resolver directory created above, never project data.
    noLinks(workspace);
    rmSync(workspace, { recursive: true, force: true });
    const directory = join(root, id);
    renameSync(temporary, directory);
    return summary(id, directory, plan);
  } catch (error) {
    noLinks(temporary);
    rmSync(temporary, { recursive: true, force: true });
    throw error;
  }
}

/** Hash installed output for conflict-aware rollback; never follow package links. */
function fingerprint(path) {
  if (!existsSync(path)) return null;
  const digest = createHash('sha256');
  let count = 0;
  let bytes = 0;
  function walk(current, name) {
    const stat = lstatSync(current);
    if (++count > 100000 || (bytes += stat.size) > 1024 * 1024 * 1024) throw new Error('Installed output exceeds the pilot verification limit.');
    digest.update(encode({ name, type: stat.isDirectory() ? 'directory' : stat.isSymbolicLink() ? 'link' : 'file' }));
    if (stat.isSymbolicLink()) {
      const target = readlinkSync(current);
      if (!inside(path, resolve(dirname(current), target))) throw new Error('Installed package links outside node_modules.');
      digest.update(target);
    } else if (stat.isDirectory()) {
      for (const child of readdirSync(current).sort()) walk(join(current, child), `${name}/${child}`);
    } else if (stat.isFile() && stat.nlink === 1) digest.update(readFileSync(current));
    else throw new Error('Installed output contains an unsupported file.');
  }
  walk(path, '');
  return digest.digest('hex');
}

function lockPath(_root, project) { return join(dirname(project), `.vibeguard-npm-${hash(project)}.lock`); }
function processIsRunning(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code !== 'ESRCH'; }
}
function releaseLock(root, project, id) {
  const path = lockPath(root, project);
  if (existsSync(path) && get(path).id === id) rmSync(path);
}

function verifyStage(stage, project) {
  if (dirname(stage) !== dirname(project) || !/^\.vibeguard-npm-[A-Za-z0-9]+$/.test(relative(dirname(project), stage))) throw new Error('Invalid installation recovery path.');
  noLinks(stage);
}

function restore(plan, attempt) {
  const project = plan.snapshot.project;
  verifyStage(attempt.stage, project);
  const journalPath = join(attempt.stage, 'journal.json');
  if (!existsSync(journalPath)) return { status: 'rolled-back', conflicts: [] };
  const journal = get(journalPath);
  if (!Array.isArray(journal.entries) || journal.entries.length !== NAMES.length || journal.entries.some((e, i) => e.name !== NAMES[i])) throw new Error('Invalid recovery journal.');
  const conflicts = [];
  // Check every path first so a user edit cannot produce a half-restored tree.
  for (const entry of journal.entries) {
    const target = join(project, entry.name);
    const backup = join(attempt.stage, 'backup', entry.name);
    const prepared = join(attempt.stage, 'output', entry.name);
    noLinks(target); noLinks(backup); noLinks(prepared);
    if (entry.hadOriginal && !existsSync(backup)) continue;
    if (existsSync(target) && (existsSync(prepared) || fingerprint(target) !== entry.installedHash)) conflicts.push(entry.name);
  }
  if (conflicts.length) return { status: 'recovery-required', conflicts };
  for (const entry of [...journal.entries].reverse()) {
    const target = join(project, entry.name);
    const backup = join(attempt.stage, 'backup', entry.name);
    const prepared = join(attempt.stage, 'output', entry.name);
    noLinks(target); noLinks(backup); noLinks(prepared);
    // With no backup, an original was never moved. Leave it alone.
    if (entry.hadOriginal && !existsSync(backup)) continue;
    if (existsSync(target)) {
      if (existsSync(prepared) || fingerprint(target) !== entry.installedHash) { conflicts.push(entry.name); continue; }
      renameSync(target, prepared);
    }
    if (existsSync(backup)) renameSync(backup, target);
  }
  const status = conflicts.length ? 'recovery-required' : 'rolled-back';
  put(journalPath, { ...journal, status });
  return { status, conflicts };
}

/** Install offline from the reviewed archives, then promote three prepared paths. */
export async function installReviewed(id, { accept, store } = {}, dependencies = {}) {
  if (accept !== id) throw new Error('Review the report, then provide --accept with the exact review ID.');
  const { root, directory, plan } = loadReview(id, store);
  if (plan.report.exitCode === 2) throw new Error('The review is blocked; it cannot be installed.');
  if ((dependencies.now || Date.now)() > plan.expiresAt) throw new Error('Review expired. Create a fresh review.');
  if (encode((dependencies.identity || npmIdentity)()) !== encode(plan.identity)) throw new Error('Node or npm changed. Review again.');
  assertProjectUnchanged(plan.snapshot);
  const project = plan.snapshot.project;
  const attemptPath = join(directory, 'attempt.json');
  if (existsSync(attemptPath)) throw new Error('This review already had an installation attempt. Use status or rollback, then review again.');
  const projectLock = lockPath(root, project);
  if (existsSync(`${projectLock}.recovery`)) throw new Error('A recovery claim exists for this project. Inspect recovery before installing.');
  try { put(projectLock, { id, pid: process.pid }, true); }
  catch (error) { if (error.code === 'EEXIST') throw new Error('Another installation holds this project. Inspect its status or rollback before continuing.'); throw error; }
  let attempt;
  try {
    const stage = mkdtempSync(join(dirname(project), '.vibeguard-npm-'));
    attempt = { id, stage, status: 'preparing', startedAt: Date.now() };
    put(attemptPath, attempt, true);
    const output = join(stage, 'output');
    prepareDirectory(output);
    mkdirSync(join(stage, 'backup'));
    mkdirSync(join(stage, 'archives'));
    writeFileSync(join(output, 'package.json'), plan.manifest);
    writeFileSync(join(output, 'package-lock.json'), plan.lock);
    const archivePaths = plan.artifacts.map((artifact) => {
      if (!/^[a-f0-9]{64}\.tgz$/.test(artifact.file)) throw new Error('Invalid reviewed artifact path.');
      const source = join(directory, 'artifacts', artifact.file);
      noLinks(source);
      const stat = lstatSync(source);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > 20 * 1024 * 1024) throw new Error('Invalid reviewed archive.');
      const bytes = readFileSync(source);
      if (`sha512-${createHash('sha512').update(bytes).digest('base64')}` !== artifact.integrity) throw new Error('Reviewed archive changed. Review again.');
      const target = join(stage, 'archives', artifact.file);
      writeFileSync(target, bytes, { flag: 'wx', mode: 0o600 });
      return target;
    });
    const runNpm = dependencies.runNpm || runProtectedNpm;
    const options = { cwd: output, cache: join(stage, 'cache') };
    // A fresh, private cache receives only authenticated tarballs. No re-resolution.
    for (let offset = 0; offset < archivePaths.length; offset += 20) {
      await runNpm(['cache', 'add', ...archivePaths.slice(offset, offset + 20), '--offline'], options); // vibe-audit-ignore perf-no-await-parallel
    }
    await runNpm(['ci', '--offline'], options);
    if (readFileSync(join(output, 'package.json'), 'utf8') !== plan.manifest || readFileSync(join(output, 'package-lock.json'), 'utf8') !== plan.lock) throw new Error('npm changed the approved manifests.');
    const lockDocument = JSON.parse(plan.lock);
    const locked = validateLock(lockDocument);
    const installed = [];
    const omittedOptional = [];
    for (const entry of locked) {
      const packagePath = join(output, entry.location, 'package.json');
      if (!existsSync(packagePath)) {
        if (!lockDocument.packages[entry.location].optional) throw new Error('npm omitted a required reviewed package.');
        omittedOptional.push(entry.location);
        continue;
      }
      noLinks(packagePath);
      const actual = JSON.parse(readFileSync(packagePath, 'utf8'));
      if (actual.name !== entry.name || actual.version !== entry.version) throw new Error('Installed package identity differs from review.');
      installed.push(entry.location);
    }
    const journal = { status: 'publishing', entries: NAMES.map((name) => {
      noLinks(join(project, name));
      return { name, hadOriginal: existsSync(join(project, name)), installedHash: fingerprint(join(output, name)) };
    }) };
    put(join(stage, 'journal.json'), journal, true);
    attempt = { ...attempt, status: 'publishing' };
    put(attemptPath, attempt);
    assertProjectUnchanged(plan.snapshot);
    // npm never writes into the user's project. Keep every original for rollback.
    for (const entry of journal.entries) {
      const target = join(project, entry.name);
      noLinks(target);
      if (entry.hadOriginal) {
        const backup = join(stage, 'backup', entry.name);
        renameSync(target, backup);
        if (entry.name !== 'node_modules' && readFileSync(backup, 'utf8') !== plan.snapshot.files[entry.name]) throw new Error('Project changed during installation; restoring captured user files.');
      }
      renameSync(join(output, entry.name), target);
    }
    for (const name of NAMES.slice(1)) {
      const backup = join(stage, 'backup', name);
      if (existsSync(backup) && readFileSync(backup, 'utf8') !== plan.snapshot.files[name]) throw new Error('Project changed during installation; restoring captured user files.');
    }
    put(join(stage, 'journal.json'), { ...journal, status: 'installed' });
    attempt = { ...attempt, status: 'installed', completedAt: Date.now(), scripts: 'disabled', installed, omittedOptional,
      projectFingerprint: readProject(project).fingerprint, backupPath: join(stage, 'backup'),
      note: 'Installation verified. Application execution and runtime safety were not tested.' };
    put(attemptPath, attempt);
    return { ...attempt, receiptPath: attemptPath };
  } catch (error) {
    if (!attempt) throw error;
    let recovery;
    try { recovery = restore(plan, attempt); }
    catch { recovery = { status: 'recovery-required', conflicts: ['Recovery could not finish; retained files require inspection.'] }; }
    attempt = { ...attempt, ...recovery, status: recovery.status === 'rolled-back' ? 'failed' : recovery.status, error: error.message };
    put(attemptPath, attempt);
    return { ...attempt, receiptPath: attemptPath };
  } finally {
    if (!attempt || attempt.status !== 'recovery-required') releaseLock(root, project, id);
    else put(projectLock, { id, pid: null });
  }
}

export function installStatus(id, { store } = {}) {
  const { directory, plan } = loadReview(id, store);
  const path = join(directory, 'attempt.json');
  return { ...summary(id, directory, plan), attempt: existsSync(path) ? get(path) : null };
}

export function rollbackInstall(id, { store } = {}) {
  const { root, directory, plan } = loadReview(id, store);
  const attemptPath = join(directory, 'attempt.json');
  const attempt = get(attemptPath);
  const path = lockPath(root, plan.snapshot.project);
  const claim = `${path}.recovery`;
  try { put(claim, { id, pid: process.pid }, true); }
  catch (error) { if (error.code === 'EEXIST') throw new Error('A recovery claim already exists. Inspect the retained recovery process and files before continuing.'); throw error; }
  try {
    if (existsSync(path)) {
      const owner = get(path);
      if (owner.id !== id) throw new Error('Another installation owns this project.');
      if (processIsRunning(owner.pid)) throw new Error('The installation process is still running. Stop it before rollback.');
      put(path, { id, pid: process.pid });
    } else put(path, { id, pid: process.pid }, true);
    const recovery = restore(plan, attempt);
    const result = { ...attempt, ...recovery, receiptPath: attemptPath };
    put(attemptPath, result);
    if (recovery.status !== 'recovery-required') releaseLock(root, plan.snapshot.project, id);
    else put(path, { id, pid: null });
    return result;
  } catch (error) {
    if (existsSync(path) && get(path).id === id && get(path).pid === process.pid) put(path, { id, pid: null });
    throw error;
  } finally { rmSync(claim); }
}
