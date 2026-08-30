import { existsSync, lstatSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, parse, relative, resolve } from 'node:path';

import {
  analyzeAgentControlContent,
  collectAgentControlFiles,
  identifyAgentCapabilities,
  normalizeAgentPath,
} from './agent-files.js';
import {
  BASELINE_SCHEMA_VERSION,
  readBaseline,
  writeBaseline,
} from './baseline.js';
import { runSecurityAdapters } from '../adapters/index.js';

function assertReadableRoot(rootPath) {
  const absolute = resolve(rootPath);
  let stats;
  try {
    stats = lstatSync(absolute);
  } catch (error) {
    throw new Error(`Could not read scan target ${absolute}: ${error.code || error.message}`);
  }
  if (stats.isSymbolicLink()) throw new Error(`Refusing symbolic-link scan target: ${absolute}`);
  if (!stats.isDirectory() && !stats.isFile()) throw new Error(`Scan target is not a file or directory: ${absolute}`);
  return absolute;
}

function isInside(parent, candidate) {
  const rel = relative(resolve(parent), resolve(candidate));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

function physicalDestination(filePath) {
  let existing = resolve(filePath);
  const missing = [];
  const volumeRoot = parse(existing).root;
  while (!existsSync(existing)) {
    missing.unshift(basename(existing));
    const parent = dirname(existing);
    if (parent === existing || existing === volumeRoot) break;
    existing = parent;
  }
  return resolve(realpathSync(existing), ...missing);
}

function assertExternalBaseline(root, baselinePath) {
  const output = resolve(baselinePath);
  const physicalRoot = realpathSync(root);
  const physicalOutput = physicalDestination(output);
  if (isInside(root, output) || isInside(physicalRoot, physicalOutput)) {
    throw new Error('The integrity baseline must stay outside the scanned backup.');
  }
  return output;
}

function fileRecord(file) {
  return {
    path: resolve(file.path),
    sha256: file.hash,
    size: file.size,
    mtimeMs: file.mtimeMs,
    ctimeMs: file.ctimeMs,
  };
}

function capabilityChainFindings(files) {
  const nodes = files.map((file) => ({
    ...file,
    normalizedContent: String(file.content || '').replace(/\\/g, '/').toLowerCase(),
    capabilities: identifyAgentCapabilities(file.content || ''),
  }));
  const findings = [];
  const seen = new Set();
  for (const source of nodes) {
    for (const target of nodes) {
      if (source.path === target.path) continue;
      const targetName = target.path.replace(/\\/g, '/').split('/').at(-1).toLowerCase();
      if (!targetName || !source.normalizedContent.includes(targetName)) continue;
      const combined = {};
      for (const name of ['network', 'execution', 'credential', 'credentialAccess', 'stealth', 'persistence']) {
        combined[name] = source.capabilities[name].present || target.capabilities[name].present;
      }
      if (!combined.network || !combined.execution || (!combined.stealth && !combined.persistence && !combined.credentialAccess)) continue;
      const key = `${source.path}\0${target.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const line = source.normalizedContent.split(/\r?\n/).findIndex((value) => value.includes(targetName)) + 1;
      findings.push({
        id: 'agent-cross-file-capability-chain',
        severity: combined.stealth || combined.persistence ? 'critical' : 'warning',
        message: `Agent instructions link to ${target.path} and combine execution, networking, and credential, concealment, or persistence capabilities across files.`,
        line: Math.max(line, 1),
        file: source.path,
        relatedFile: target.path,
      });
    }
  }
  return findings;
}

/**
 * Inspect an offline backup or directory without loading its configuration or
 * executing any referenced command. Incomplete coverage is a blocking result.
 *
 * @param {string} rootPath
 * @param {{maxFiles?:number,maxBytes?:number,externalTools?:string[],adapters?:Record<string,Function>,adapterOptions?:object}} [options]
 */
export function scanAgentControlPlane(rootPath, options = {}) {
  const root = assertReadableRoot(rootPath);
  const scan = collectAgentControlFiles([root], {
    maxFiles: options.maxFiles,
    maxBytes: options.maxBytes,
    includeStaging: true,
  });
  const findings = [];
  for (const file of scan.files) {
    findings.push(...analyzeAgentControlContent(file.content || '', file.path));
  }
  findings.push(...capabilityChainFindings(scan.files));
  const critical = findings.filter((finding) => finding.severity === 'critical');
  const warnings = findings.filter((finding) => finding.severity === 'warning');
  const adapters = runSecurityAdapters(
    scan.files.map((file) => ({ path: file.path, content: file.content || '' })),
    {
      enabled: options.externalTools || [],
      adapters: options.adapters,
      adapterOptions: {
        ...(options.adapterOptions || {}),
        gitleaks: { targetDir: root, ...(options.adapterOptions?.gitleaks || {}) },
        semgrep: { targetDir: root, ...(options.adapterOptions?.semgrep || {}) },
      },
    },
  );
  const complete = scan.errors.length === 0 && adapters.complete;
  const externalFindings = adapters.results.flatMap((adapter) => adapter.findings || []);
  const decision = !complete || critical.length > 0 || externalFindings.length > 0
    ? 'block'
    : warnings.length > 0 ? 'review' : 'pass';
  return {
    schemaVersion: 1,
    mode: 'offline-agent-control-plane',
    root,
    decision,
    coverage: {
      complete,
      scanned: scan.files.length,
      errors: scan.errors,
    },
    files: scan.files.map(fileRecord),
    findings,
    adapters,
  };
}

/**
 * Save a reviewed, target-specific SHA-256 inventory outside the scanned tree.
 * @param {string} rootPath
 * @param {string} baselinePath
 */
export function createAgentIntegrityBaseline(rootPath, baselinePath) {
  const root = assertReadableRoot(rootPath);
  const output = assertExternalBaseline(root, baselinePath);
  const scan = scanAgentControlPlane(root);
  if (scan.decision === 'block') {
    const reason = scan.coverage.errors[0] || scan.findings.find((finding) => finding.severity === 'critical')?.message;
    throw new Error(`Refusing to baseline an unsafe or incomplete agent scan: ${reason || 'blocked'}`);
  }
  const files = Object.fromEntries(scan.files.map((file) => [normalizeAgentPath(file.path), file]));
  writeBaseline(output, {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    kind: 'agent-integrity-baseline',
    scopeRoot: root,
    updatedAt: new Date().toISOString(),
    files,
  });
  return { ok: true, root, baselinePath: output, trusted: scan.files.length, warnings: scan.findings };
}

/**
 * Re-scan an offline tree and compare every recognized control to its baseline.
 * @param {string} rootPath
 * @param {string} baselinePath
 */
export function verifyAgentIntegrityBaseline(rootPath, baselinePath) {
  const root = assertReadableRoot(rootPath);
  const checkedBaselinePath = assertExternalBaseline(root, baselinePath);
  const baseline = readBaseline(checkedBaselinePath);
  if (!baseline || baseline.kind !== 'agent-integrity-baseline' || !baseline.scopeRoot) {
    throw new Error('The selected file is not an agent integrity baseline.');
  }
  if (normalizeAgentPath(baseline.scopeRoot) !== normalizeAgentPath(root)) {
    throw new Error(`Baseline scope mismatch. Expected ${baseline.scopeRoot}, received ${root}.`);
  }
  const scan = scanAgentControlPlane(root);
  const current = Object.fromEntries(scan.files.map((file) => [normalizeAgentPath(file.path), file]));
  const added = [];
  const changed = [];
  const missing = [];
  for (const [key, file] of Object.entries(current)) {
    if (!baseline.files[key]) added.push(file.path);
    else if (baseline.files[key].sha256 !== file.sha256) changed.push(file.path);
  }
  for (const [key, file] of Object.entries(baseline.files)) {
    if (!current[key]) missing.push(file.path);
  }
  const hasCritical = scan.findings.some((finding) => finding.severity === 'critical');
  const ok = scan.coverage.complete && !hasCritical && added.length === 0 && changed.length === 0 && missing.length === 0;
  return {
    ok,
    root,
    baselinePath: checkedBaselinePath,
    decision: ok ? 'pass' : 'block',
    coverage: scan.coverage,
    added,
    changed,
    missing,
    findings: scan.findings,
  };
}
