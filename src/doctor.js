import { resolve } from 'node:path';

import {
  COSIGN_RELEASE_SHA256,
  COSIGN_VERSION,
  inspectCosignExecutable,
} from './adapters/cosign.js';
import { findTrustedExecutable } from './trusted-tools.js';

const MINIMUM_NODE = [18, 19, 0];

const TOOL_POLICIES = [
  {
    id: 'cosign',
    name: 'Cosign',
    required: true,
    requiredFor: 'installing official Vibe Audit agent skills',
    versionPolicy: `=${COSIGN_VERSION}`,
    expectedSha256: COSIGN_RELEASE_SHA256[`${process.platform}-${process.arch}`] || null,
    verification: 'pinned-sha256',
    source: `https://github.com/sigstore/cosign/releases/tag/v${COSIGN_VERSION}`,
    fix: `Install Cosign ${COSIGN_VERSION} from Sigstore's official release, then rerun vibeaudit doctor.`,
  },
  {
    id: 'osv-scanner',
    name: 'OSV-Scanner',
    required: true,
    requiredFor: 'the default dependency vulnerability audit',
    verification: 'external-path-only',
    source: 'https://github.com/google/osv-scanner/releases',
    fix: 'Install OSV-Scanner from Google\'s official release, verify its provenance, then rerun vibeaudit doctor.',
  },
  {
    id: 'gitleaks',
    name: 'Gitleaks',
    required: false,
    requiredFor: 'optional secret scanning of restored agent controls',
    verification: 'external-path-only',
    source: 'https://github.com/gitleaks/gitleaks/releases',
    fix: 'Install Gitleaks from its official release when you want optional restored-secret scanning.',
  },
];

/** Report local security-tool readiness without downloading or executing tools. */
export function runDoctor(options = {}) {
  const targetDir = resolve(options.targetDir || process.cwd());
  const findExecutable = options.findExecutable
    || ((name, target) => findTrustedExecutable(name, target, options.env));
  const node = nodeCheck(options.nodeVersion || process.versions.node);
  const tools = TOOL_POLICIES.map((policy) => toolCheck(policy, targetDir, findExecutable));
  const requiredReady = [node, ...tools.filter((tool) => tool.required)]
    .every((check) => check.status === 'ready' || check.status === 'available');
  return {
    schemaVersion: 1,
    status: requiredReady ? 'ready' : 'attention',
    downloadsPerformed: false,
    installersExecuted: false,
    checks: [node, ...tools],
  };
}

function nodeCheck(version) {
  const parts = String(version).replace(/^v/, '').split('.').map((part) => Number.parseInt(part, 10));
  const ready = compareVersions(parts, MINIMUM_NODE) >= 0;
  return {
    id: 'node',
    name: 'Node.js',
    status: ready ? 'ready' : 'unsupported',
    required: true,
    requiredFor: 'running Vibe Audit',
    version: String(version).replace(/^v/, ''),
    versionPolicy: '>=18.19.0',
    fix: ready ? 'No action needed.' : 'Install Node.js 18.19.0 or newer, then rerun vibeaudit doctor.',
    source: 'https://nodejs.org/en/download',
  };
}

function toolCheck(policy, targetDir, findExecutable) {
  let executable = null;
  try {
    executable = findExecutable(policy.id, targetDir);
  } catch {
    executable = null;
  }
  const base = {
    ...policy,
    executable,
  };
  if (!executable) return { ...base, status: 'missing' };
  if (policy.id !== 'cosign') return { ...base, status: 'available' };
  const inspected = inspectCosignExecutable(executable);
  return {
    ...base,
    ...inspected,
    fix: inspected.status === 'ready'
      ? 'No action needed.'
      : `${inspected.reason} Reinstall it from ${policy.source}, then rerun vibeaudit doctor.`,
  };
}

function compareVersions(actual, minimum) {
  for (let index = 0; index < minimum.length; index += 1) {
    if ((actual[index] || 0) > minimum[index]) return 1;
    if ((actual[index] || 0) < minimum[index]) return -1;
  }
  return 0;
}
