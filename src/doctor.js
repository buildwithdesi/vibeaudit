import { resolve } from 'node:path';

import {
  COSIGN_RELEASE_SHA256,
  COSIGN_VERSION,
  inspectCosignExecutable,
} from './adapters/cosign.js';
import {
  inspectOsvExecutable,
  OSV_RELEASE_SHA256,
  OSV_VERSION,
} from './adapters/osv.js';
import { findTrustedExecutable } from './trusted-tools.js';

const MINIMUM_NODE = [18, 19, 0];

function toolPolicies(inspectCosign, cosignExpectedSha256, inspectOsv, osvExpectedSha256) {
  return [{
    id: 'cosign',
    name: 'Cosign',
    required: true,
    requiredFor: 'installing official Vibe Audit agent skills',
    versionPolicy: `=${COSIGN_VERSION}`,
    expectedSha256: cosignExpectedSha256,
    supported: cosignExpectedSha256 !== null,
    verification: 'pinned-sha256',
    source: `https://github.com/sigstore/cosign/releases/tag/v${COSIGN_VERSION}`,
    missingFix: `Install Cosign ${COSIGN_VERSION} from Sigstore's official release, then rerun vibeaudit doctor.`,
    unsupportedFix: 'Run Vibe Audit on a supported platform: darwin-x64, darwin-arm64, linux-x64, linux-arm64, or win32-x64.',
    inspect(executable, policy) {
      const inspected = inspectCosign(executable);
      let fix = 'No action needed.';
      if (inspected.status === 'unsupported') {
        fix = `${inspected.reason} Run Vibe Audit on a supported platform: darwin-x64, darwin-arm64, linux-x64, linux-arm64, or win32-x64.`;
      } else if (inspected.status !== 'ready') {
        fix = `${inspected.reason} Reinstall it from ${policy.source}, then rerun vibeaudit doctor.`;
      }
      return { ...inspected, fix };
    },
  },
  {
    id: 'osv-scanner',
    name: 'OSV-Scanner',
    required: true,
    requiredFor: 'the default dependency vulnerability audit',
    versionPolicy: `=${OSV_VERSION}`,
    expectedSha256: osvExpectedSha256,
    supported: osvExpectedSha256 !== null,
    verification: 'pinned-sha256',
    source: `https://github.com/google/osv-scanner/releases/tag/v${OSV_VERSION}`,
    missingFix: `Install OSV-Scanner ${OSV_VERSION} from Google's official release, then rerun vibeaudit doctor.`,
    unsupportedFix: 'Run Vibe Audit on a supported platform: darwin-x64, darwin-arm64, linux-x64, linux-arm64, win32-x64, or win32-arm64.',
    inspect(executable, policy) {
      const inspected = inspectOsv(executable);
      let fix = 'No action needed.';
      if (inspected.status === 'unsupported') {
        fix = `${inspected.reason} Run Vibe Audit on a supported platform: darwin-x64, darwin-arm64, linux-x64, linux-arm64, win32-x64, or win32-arm64.`;
      } else if (inspected.status !== 'ready') {
        fix = `${inspected.reason} Reinstall it from ${policy.source}, then rerun vibeaudit doctor.`;
      }
      return { ...inspected, fix };
    },
  },
  {
    id: 'gitleaks',
    name: 'Gitleaks',
    required: false,
    requiredFor: 'optional secret scanning of restored agent controls',
    verification: 'external-path-only',
    source: 'https://github.com/gitleaks/gitleaks/releases',
    missingFix: 'Install Gitleaks from its official release when you want optional restored-secret scanning.',
    inspect() {
      return {
        status: 'available-unverified',
        fix: 'Verify this Gitleaks binary against its official release before relying on it.',
      };
    },
  },
  ];
}

/** Report local security-tool readiness without downloading or executing tools. */
export function runDoctor(options = {}) {
  const targetDir = resolve(options.targetDir || process.cwd());
  const findExecutable = options.findExecutable
    || ((name, target) => findTrustedExecutable(name, target, options.env));
  const node = nodeCheck(options.nodeVersion || process.versions.node);
  const inspectCosign = options.inspectCosign || inspectCosignExecutable;
  const inspectOsv = options.inspectOsv || inspectOsvExecutable;
  const cosignExpectedSha256 = options.cosignExpectedSha256 === undefined
    ? (COSIGN_RELEASE_SHA256[`${process.platform}-${process.arch}`] || null)
    : options.cosignExpectedSha256;
  const osvExpectedSha256 = options.osvExpectedSha256 === undefined
    ? (OSV_RELEASE_SHA256[`${process.platform}-${process.arch}`] || null)
    : options.osvExpectedSha256;
  const tools = toolPolicies(inspectCosign, cosignExpectedSha256, inspectOsv, osvExpectedSha256)
    .map((policy) => toolCheck(policy, targetDir, findExecutable));
  const checks = [node, ...tools];
  const operational = checks.filter((check) => check.required)
    .every((check) => check.status === 'ready');
  const hasWarnings = checks.some((check) => check.status === 'available-unverified');
  return {
    schemaVersion: 1,
    status: operational ? (hasWarnings ? 'usable-with-warnings' : 'ready') : 'attention',
    operational,
    downloadsPerformed: false,
    installersExecuted: false,
    checks,
  };
}

/** Format a doctor report for people while preserving its trust evidence. */
export function formatDoctor(report) {
  const lines = [`Vibe Audit Doctor: ${report.status.toUpperCase()}`];
  for (const check of report.checks) {
    lines.push(`${check.status.toUpperCase()}: ${check.name}${check.executable ? `, ${check.executable}` : ''}`);
    if (check.version) lines.push(`  Version: ${check.version}`);
    if (check.versionPolicy) lines.push(`  Version policy: ${check.versionPolicy}`);
    if (check.verification) lines.push(`  Verification: ${check.verification}`);
    if (check.expectedSha256) lines.push(`  Expected SHA-256: ${check.expectedSha256}`);
    if (check.sha256) lines.push(`  Actual SHA-256: ${check.sha256}`);
    lines.push(`  Source: ${check.source}`);
    if (check.status !== 'ready') lines.push(`  Fix: ${check.fix}`);
  }
  lines.push('No tools were downloaded and no installers were executed.');
  return lines.join('\n');
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
  const {
    inspect,
    missingFix,
    supported = true,
    unsupportedFix,
    ...visiblePolicy
  } = policy;
  if (!supported) {
    return {
      ...visiblePolicy,
      executable: null,
      status: 'unsupported',
      fix: unsupportedFix,
    };
  }
  let executable = null;
  try {
    executable = findExecutable(policy.id, targetDir);
  } catch {
    executable = null;
  }
  const base = { ...visiblePolicy, executable };
  if (!executable) return { ...base, status: 'missing', fix: missingFix };
  return {
    ...base,
    ...inspect(executable, visiblePolicy),
  };
}

function compareVersions(actual, minimum) {
  for (let index = 0; index < minimum.length; index += 1) {
    if ((actual[index] || 0) > minimum[index]) return 1;
    if ((actual[index] || 0) < minimum[index]) return -1;
  }
  return 0;
}
