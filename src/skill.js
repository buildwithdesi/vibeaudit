import { createHash, randomUUID } from 'node:crypto';
import {
  copyFile,
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { analyzeAgentControlContent } from './guard/agent-files.js';
import { trustOneAgentFile } from './guard/baseline.js';
import { verifyOfficialSkillBundle } from './agent-bundle.js';

const MAX_SKILL_BYTES = 2 * 1024 * 1024;
const AGENTS = [
  { id: 'claude', displayName: 'Claude Code', dirName: '.claude' },
  { id: 'codex', displayName: 'Codex', dirName: '.codex' },
  { id: 'cursor', displayName: 'Cursor', dirName: '.cursor' },
];

function hash(content) {
  return createHash('sha256').update(content).digest('hex');
}

function sourcePath() {
  return join(dirname(fileURLToPath(import.meta.url)), 'data', 'agent-skill.md');
}

async function readBounded(path) {
  const info = await stat(path);
  if (!info.isFile()) throw new Error(`Skill path is not a file: ${path}`);
  if (info.size > MAX_SKILL_BYTES) throw new Error(`Skill file exceeds the ${MAX_SKILL_BYTES} byte review limit: ${path}`);
  return readFile(path, 'utf8');
}

async function currentFile(path) {
  try {
    if ((await lstat(path)).isSymbolicLink()) throw new Error(`Refusing symbolic-link skill target: ${path}`);
    const content = await readBounded(path);
    return { exists: true, content, hash: hash(content) };
  } catch (error) {
    if (error.code === 'ENOENT') return { exists: false, content: '', hash: null };
    throw error;
  }
}

function simpleDiff(before, after) {
  if (before === after) return '';
  const oldLines = before.split(/\r?\n/);
  const newLines = after.split(/\r?\n/);
  return [
    ...oldLines.map((line) => `- ${line}`),
    ...newLines.map((line) => `+ ${line}`),
  ].join('\n');
}

export function detectAgents(home = homedir()) {
  return AGENTS.map(({ id, displayName, dirName }) => {
    const configDir = join(resolve(home), dirName);
    const installPath = join(configDir, 'skills', 'vibeaudit', 'SKILL.md');
    return {
      id,
      displayName,
      configDir,
      installPath,
      detected: existsSync(configDir),
      skillInstalled: existsSync(installPath),
    };
  });
}

export async function readSkillMarkdown() {
  return readBounded(sourcePath());
}

/** Build a no-write preview that binds every target to its current hash. */
export async function createSkillInstallPlan({ home = homedir(), only = [], signatureOptions = {} } = {}) {
  const unknown = only.filter((id) => !AGENTS.some((agent) => agent.id === id));
  if (unknown.length) throw new Error(`Unsupported agent target: ${unknown.join(', ')}`);
  const publisherVerification = verifyOfficialSkillBundle(signatureOptions);
  const source = await readSkillMarkdown();
  const sourceHash = hash(source);
  const sourceFindings = analyzeAgentControlContent(source, sourcePath());
  const critical = sourceFindings.filter((finding) => finding.severity === 'critical');
  if (critical.length) throw new Error(`Packaged skill failed its security review: ${critical[0].message}`);

  const selected = detectAgents(home).filter((item) => only.length === 0 || only.includes(item.id));
  const targets = await Promise.all(selected.map(async (agent) => {
    if (!agent.detected) {
      return { ...agent, action: 'not-detected', beforeHash: null, diff: '' };
    }
    const current = await currentFile(agent.installPath);
    return {
      ...agent,
      action: !current.exists ? 'install' : current.hash === sourceHash ? 'unchanged' : 'replace',
      beforeHash: current.hash,
      diff: simpleDiff(current.content, source),
      currentFindings: current.exists ? analyzeAgentControlContent(current.content, agent.installPath) : [],
    };
  }));
  return { schemaVersion: 1, home: resolve(home), sourcePath: sourcePath(), sourceHash, sourceFindings, publisherVerification, targets };
}

async function rollbackTarget(target, backupPath) {
  await rm(target.installPath, { force: true });
  if (backupPath) await copyFile(backupPath, target.installPath);
}

/** Apply only the exact plan and source hash the person just reviewed. */
export async function applySkillInstallPlan(plan, { confirmedSourceHash, baselinePath, signatureOptions = {} } = {}) {
  if (!plan || plan.schemaVersion !== 1) throw new Error('Unsupported skill install plan.');
  if (confirmedSourceHash !== plan.sourceHash) throw new Error('The confirmation hash does not match the reviewed skill source.');
  const publisherVerification = verifyOfficialSkillBundle(signatureOptions);
  if (publisherVerification.baseline.files[0]?.sha256 !== plan.sourceHash) {
    throw new Error('The verified official skill digest no longer matches the reviewed install plan. Run the preview again.');
  }
  const source = await readSkillMarkdown();
  if (hash(source) !== plan.sourceHash) throw new Error('The packaged skill changed after the install preview. Run the preview again.');
  const allowedTargets = new Map(detectAgents(plan.home).map((agent) => [agent.id, agent.installPath]));
  return applySkillTargetsSequentially(plan.targets, 0, { plan, source, allowedTargets, baselinePath });
}

async function applySkillTargetsSequentially(targets, index, context) {
  if (index >= targets.length) return [];
  // Keep writes serialized because every successful target updates one shared baseline.
  const current = await applyOneSkillTarget(targets[index], context);
  const remaining = await applySkillTargetsSequentially(targets, index + 1, context);
  return [current, ...remaining];
}

async function applyOneSkillTarget(target, { plan, source, allowedTargets, baselinePath }) {
  if (target.action === 'not-detected') return { id: target.id, status: 'not-detected' };
  if (allowedTargets.get(target.id) !== target.installPath) throw new Error(`Unexpected skill install path: ${target.installPath}`);
  const current = await currentFile(target.installPath);
  if (current.hash !== target.beforeHash) throw new Error(`${target.installPath} changed after the install preview. Run the preview again.`);
  if (target.action === 'unchanged') {
    return { id: target.id, status: 'unchanged', verifiedHash: current.hash, installPath: target.installPath };
  }

  await mkdir(dirname(target.installPath), { recursive: true });
  const nonce = randomUUID();
  const temporary = `${target.installPath}.vibeaudit-${nonce}.tmp`;
  const backupPath = current.exists ? `${target.installPath}.vibeaudit-backup-${nonce}` : null;
  await writeFile(temporary, source, { encoding: 'utf8', flag: 'wx' });
  try {
    if (current.exists) await rename(target.installPath, backupPath);
    await rename(temporary, target.installPath);
    const installed = await currentFile(target.installPath);
    if (installed.hash !== plan.sourceHash) throw new Error(`Post-write hash verification failed for ${target.installPath}.`);
    trustOneAgentFile(target.installPath, baselinePath ? { baselinePath } : {});
    return {
      id: target.id,
      status: current.exists ? 'updated' : 'installed',
      installPath: target.installPath,
      backupPath,
      verifiedHash: installed.hash,
    };
  } catch (error) {
    await rollbackTarget(target, backupPath);
    throw error;
  } finally {
    await rm(temporary, { force: true });
  }
}
