import { lstatSync, mkdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import {
  analyzeAgentControlContent,
  collectAgentControlFiles,
  defaultAgentRoots,
  normalizeAgentPath,
  sha256,
} from './agent-files.js';

export const BASELINE_SCHEMA_VERSION = 1;

/** @param {NodeJS.ProcessEnv} [env] */
export function defaultBaselinePath(env = process.env) {
  return env.VIBEGUARD_BASELINE || join(homedir(), '.vibeaudit', 'agent-baseline.json');
}

/** @param {string} baselinePath */
export function readBaseline(baselinePath = defaultBaselinePath()) {
  try {
    if (lstatSync(baselinePath).isSymbolicLink()) {
      throw new Error('symbolic-link baseline files are not trusted');
    }
    const parsed = JSON.parse(readFileSync(baselinePath, 'utf8'));
    if (parsed.schemaVersion !== BASELINE_SCHEMA_VERSION || !parsed.files || typeof parsed.files !== 'object') {
      throw new Error('unsupported baseline format');
    }
    return parsed;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw new Error(`Could not read VibeGuard baseline: ${error.message}`);
  }
}

function refuseSymlink(filePath) {
  try {
    if (lstatSync(filePath).isSymbolicLink()) {
      throw new Error(`Refusing to write through a symbolic link: ${filePath}`);
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

/** @param {string} baselinePath @param {object} payload */
export function writeBaseline(baselinePath, payload) {
  const absolute = resolve(baselinePath);
  mkdirSync(dirname(absolute), { recursive: true });
  refuseSymlink(absolute);
  const temporary = `${absolute}.${process.pid}.tmp`;
  refuseSymlink(temporary);
  try {
    writeFileSync(temporary, `${JSON.stringify(payload, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
    renameSync(temporary, absolute);
  } finally {
    try {
      unlinkSync(temporary);
    } catch {
      // The rename already removed the temporary path.
    }
  }
}

function indexFiles(files) {
  return Object.fromEntries(files.map((file) => [normalizeAgentPath(resolve(file.path)), {
    path: resolve(file.path),
    sha256: file.hash,
    size: file.size,
    mtimeMs: file.mtimeMs,
    ctimeMs: file.ctimeMs,
  }]));
}

/**
 * @param {{cwd?:string,roots?:string[],baselinePath?:string,authorityOnly?:boolean,forceReview?:boolean}} [options]
 */
export function inspectAgentBaseline(options = {}) {
  const roots = options.roots || defaultAgentRoots(options.cwd);
  const baselinePath = options.baselinePath || defaultBaselinePath();
  const baseline = readBaseline(baselinePath);
  const scan = collectAgentControlFiles(roots, {
    knownFiles: options.forceReview ? {} : (baseline?.files || {}),
    authorityOnly: options.authorityOnly === true,
  });
  const current = indexFiles(scan.files);
  const added = [];
  const changed = [];
  const suspicious = [];

  for (const file of scan.files) {
    const key = normalizeAgentPath(resolve(file.path));
    const previous = baseline?.files?.[key];
    if (!previous) added.push(file.path);
    else if (previous.sha256 !== file.hash) changed.push(file.path);

    if (options.forceReview || !previous || previous.sha256 !== file.hash) {
      for (const issue of analyzeAgentControlContent(file.content || '', file.path)) suspicious.push(issue);
    }
  }

  return {
    ok: Boolean(baseline) && added.length === 0 && changed.length === 0 && suspicious.length === 0 && scan.errors.length === 0,
    baselinePath,
    baselineExists: Boolean(baseline),
    scanned: scan.files.length,
    roots,
    current,
    added,
    changed,
    suspicious,
    errors: scan.errors,
  };
}

function commandPathCandidates(command, cwd) {
  const candidates = new Set();
  const userRoot = homedir();
  const tokens = String(command || '').match(/"[^"]+"|'[^']+'|[^\s;|&]+/g) || [];
  for (const raw of tokens) {
    let token = raw.replace(/^["']|["']$/g, '');
    token = token
      .replace(/^~(?=[\\/])/, userRoot)
      .replace(/^%USERPROFILE%(?=[\\/])/i, userRoot)
      .replace(/^\$env:USERPROFILE(?=[\\/])/i, userRoot);
    if (!/[\\/]/.test(token) || !/\.(?:js|mjs|cjs|ts|tsx|py|rb|go|rs|ps1|psm1|sh|bash|zsh|fish|bat|cmd|vbs|wsf)$/i.test(token)) continue;
    candidates.add(normalizeAgentPath(isAbsolute(token) ? resolve(token) : resolve(cwd, token)));
  }
  return candidates;
}

/**
 * Verify an agent-owned script only when a command is about to execute it.
 * @param {string} command
 * @param {{cwd?:string,baselinePath?:string}} [options]
 */
export function inspectReferencedAgentFiles(command, options = {}) {
  const baseline = readBaseline(options.baselinePath);
  if (!baseline) return { ok: false, changed: [], missing: [], reason: 'baseline missing' };
  const cwd = resolve(options.cwd || process.cwd());
  const candidates = commandPathCandidates(command, cwd);
  const normalizedCommand = normalizeAgentPath(command);
  const userRoot = normalizeAgentPath(homedir());

  for (const key of Object.keys(baseline.files)) {
    const homeRelative = key.startsWith(`${userRoot}/`) ? `~/${key.slice(userRoot.length + 1)}` : '';
    if (normalizedCommand.includes(key) || (homeRelative && normalizedCommand.includes(homeRelative))) {
      candidates.add(key);
    }
  }

  const changed = [];
  const missing = [];
  const suspicious = [];
  for (const candidate of candidates) {
    const expected = baseline.files[candidate];
    if (!expected) continue;
    try {
      if (lstatSync(expected.path).isSymbolicLink()) {
        changed.push(expected.path);
        continue;
      }
      const stats = statSync(expected.path);
      const content = readFileSync(expected.path);
      const actual = normalizeAgentPath(resolve(expected.path));
      if (!stats.isFile() || actual !== candidate || sha256(content) !== expected.sha256) changed.push(expected.path);
      else suspicious.push(...analyzeAgentControlContent(content.toString('utf8'), expected.path));
    } catch {
      missing.push(expected.path);
    }
  }
  return { ok: changed.length === 0 && missing.length === 0 && suspicious.length === 0, changed, missing, suspicious };
}

/**
 * Trust the current hashes only after the human reviewed the files.
 * Existing entries are retained so moving between projects does not erase trust.
 *
 * @param {{cwd?:string,roots?:string[],baselinePath?:string}} [options]
 */
export function trustCurrentAgentFiles(options = {}) {
  const inspection = inspectAgentBaseline(options);
  if (inspection.errors.length > 0) {
    throw new Error(`Agent file scan was incomplete:\n${inspection.errors.join('\n')}`);
  }
  const critical = inspection.suspicious.filter((issue) => issue.severity === 'critical');
  if (critical.length > 0) {
    throw new Error(`Refusing to trust suspicious agent instructions:\n${critical.map((issue) => `${issue.file}:${issue.line} ${issue.message}`).join('\n')}`);
  }
  const old = readBaseline(inspection.baselinePath);
  const payload = {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    updatedAt: new Date().toISOString(),
    files: { ...(old?.files || {}), ...inspection.current },
  };
  writeBaseline(inspection.baselinePath, payload);
  return { ...inspection, ok: true, trusted: Object.keys(inspection.current).length };
}

/**
 * @param {string} filePath
 * @param {{baselinePath?:string}} [options]
 */
export function trustOneAgentFile(filePath, options = {}) {
  const absolute = resolve(filePath);
  const scan = collectAgentControlFiles([absolute], { maxFiles: 1 });
  if (scan.errors.length || scan.files.length !== 1) {
    throw new Error(scan.errors[0] || `${absolute} is not a recognized agent control file.`);
  }
  const file = scan.files[0];
  const suspicious = analyzeAgentControlContent(file.content, file.path);
  const critical = suspicious.filter((issue) => issue.severity === 'critical');
  if (critical.length > 0) {
    throw new Error(`Refusing to trust suspicious agent instructions: ${critical[0].message}`);
  }
  const baselinePath = options.baselinePath || defaultBaselinePath();
  const old = readBaseline(baselinePath) || { schemaVersion: BASELINE_SCHEMA_VERSION, files: {} };
  const key = normalizeAgentPath(absolute);
  const payload = {
    ...old,
    schemaVersion: BASELINE_SCHEMA_VERSION,
    updatedAt: new Date().toISOString(),
    files: {
      ...old.files,
      [key]: {
        path: absolute,
        sha256: file.hash,
        size: file.size,
        mtimeMs: file.mtimeMs,
        ctimeMs: file.ctimeMs,
      },
    },
  };
  writeBaseline(baselinePath, payload);
  return { ...payload.files[key], warnings: suspicious.filter((issue) => issue.severity === 'warning') };
}
