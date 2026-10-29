import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { analyzeCommand, normalizeCommand } from './command.js';

const APPROVAL_LIFETIME_MS = 10 * 60 * 1000;
const MAX_APPROVALS = 50;

export function defaultApprovalPath(env = process.env) {
  return env.VIBEGUARD_APPROVALS || join(homedir(), '.vibeaudit', 'command-approvals.json');
}

function commandHash(command) {
  return createHash('sha256').update(normalizeCommand(command)).digest('hex');
}

function refuseSymlink(filePath) {
  try {
    if (lstatSync(filePath).isSymbolicLink()) {
      throw new Error(`Refusing to use a symbolic-link approval file: ${filePath}`);
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

function readState(filePath) {
  refuseSymlink(filePath);
  try {
    const state = JSON.parse(readFileSync(filePath, 'utf8'));
    if (state.schemaVersion !== 1 || !Array.isArray(state.approvals)) {
      throw new Error('unsupported approval format');
    }
    return state;
  } catch (error) {
    if (error.code === 'ENOENT') return { schemaVersion: 1, approvals: [] };
    throw new Error(`Could not read command approvals: ${error.message}`);
  }
}

function writeState(filePath, state) {
  const absolute = resolve(filePath);
  mkdirSync(dirname(absolute), { recursive: true });
  refuseSymlink(absolute);
  const temporary = `${absolute}.${process.pid}.tmp`;
  refuseSymlink(temporary);
  try {
    writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    renameSync(temporary, absolute);
  } finally {
    try {
      unlinkSync(temporary);
    } catch {
      // The rename already removed the temporary path.
    }
  }
}

/**
 * Approve one exact review-level command for one PowerShell process.
 * Dangerous commands cannot be approved through this mechanism.
 */
export function approveReviewCommand(command, options = {}) {
  const analysis = analyzeCommand(command);
  if (analysis.decision === 'deny') {
    throw new Error(`Dangerous commands cannot be approved. ${analysis.summary}`);
  }
  if (analysis.decision !== 'review') {
    throw new Error('This command does not need a VibeGuard approval.');
  }
  const now = options.now ?? Date.now();
  const shellPid = options.shellPid ?? process.ppid;
  const approvalPath = options.approvalPath || defaultApprovalPath();
  const state = readState(approvalPath);
  const live = state.approvals.filter((entry) => entry.expiresAt > now);
  live.push({
    hash: commandHash(command),
    shellPid,
    createdAt: now,
    expiresAt: now + APPROVAL_LIFETIME_MS,
  });
  state.approvals = live.slice(-MAX_APPROVALS);
  writeState(approvalPath, state);
  return { shellPid, expiresAt: now + APPROVAL_LIFETIME_MS, analysis };
}

/** Consume one matching approval. An approval cannot be replayed. */
export function consumeReviewApproval(command, options = {}) {
  const now = options.now ?? Date.now();
  const shellPid = options.shellPid ?? process.ppid;
  const approvalPath = options.approvalPath || defaultApprovalPath();
  const state = readState(approvalPath);
  const hash = commandHash(command);
  const live = state.approvals.filter((entry) => entry.expiresAt > now);
  const index = live.findIndex((entry) => entry.hash === hash && entry.shellPid === shellPid);
  if (index < 0) {
    if (live.length !== state.approvals.length) {
      state.approvals = live;
      writeState(approvalPath, state);
    }
    return false;
  }
  live.splice(index, 1);
  state.approvals = live;
  writeState(approvalPath, state);
  return true;
}
