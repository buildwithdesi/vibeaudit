/**
 * SCA (Software Composition Analysis) module.
 *
 * Checks project dependencies for known vulnerabilities using:
 *   - `npm audit --json` for Node.js projects
 *   - package.json parsing for fresh lockfile and pinning signals
 *   - OSV-Scanner for independent multi-ecosystem coverage
 *
 * Returns findings in the same format as SAST rules.
 */

import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { createIsolatedNpmEnv, findTrustedNpmCli, NPM_REGISTRY } from '../trusted-tools.js';
import { runOsvAdapter } from '../adapters/osv.js';

/** @typedef {import('../rules/types.js').Finding} Finding */

/**
 * Run SCA analysis on a project directory.
 *
 * @param {string} targetDir - Absolute path to the project root
 * @param {{osv?:boolean,osvOptions?:object}} [options]
 * @returns {Promise<Finding[]>}
 */
export async function runSCA(targetDir, options = {}) {
  const findings = [];

  // Node.js project detection
  const pkgPath = join(targetDir, 'package.json');
  if (existsSync(pkgPath)) {
    const npmFindings = await auditNpm(targetDir, pkgPath);
    findings.push(...npmFindings);
  }

  // Python project detection
  const reqPath = join(targetDir, 'requirements.txt');
  if (existsSync(reqPath)) {
    const pyFindings = checkPythonDeps(reqPath);
    findings.push(...pyFindings);
  }

  // OSV is the default second dependency-intelligence layer. An unavailable
  // or incomplete run becomes a warning instead of silently reducing coverage.
  if (options.osv === true) {
    const osvResult = runOsvAdapter(targetDir, {
      ...(options.osvOptions || {}),
      targetDir,
    });
    findings.push(...osvResult.findings);
  }

  return findings;
}

/**
 * Parse npm audit JSON output into findings.
 * Shared by the success and error paths so there's no duplication.
 */
function parseNpmAudit(raw) {
  const findings = [];
  try {
    const audit = JSON.parse(raw);
    if (audit.vulnerabilities) {
      for (const [name, vuln] of Object.entries(audit.vulnerabilities)) {
        const severity = mapNpmSeverity(vuln.severity);
        const via = Array.isArray(vuln.via)
          ? vuln.via.filter((v) => typeof v === 'object').map((v) => v.title || v.name).join(', ')
          : String(vuln.via);

        findings.push({
          ruleId: 'vulnerable-dependency',
          ruleName: 'Vulnerable Dependency',
          severity,
          message: `${name}@${vuln.range || 'unknown'}: ${via || vuln.severity} vulnerability.`,
          file: 'package.json',
          fix: vuln.fixAvailable
            ? `Run: npm audit fix (or npm install ${name}@latest for a major update).`
            : `No automatic fix available. Check https://www.npmjs.com/advisories for manual remediation.`,
        });
      }
    }
    return { findings, valid: true };
  } catch {
    return { findings: [], valid: false };
  }
}

function incompleteNpmAudit(message) {
  return [{
    ruleId: 'vulnerable-dependency',
    ruleName: 'Dependency Audit Incomplete',
    severity: 'warning',
    message,
    file: 'package-lock.json',
    fix: 'Run a vulnerability audit with the matching package manager from a trusted installation and registry. Treat this scan as incomplete until it succeeds.',
  }];
}

/**
 * Run npm audit and convert results to findings.
 *
 * Uses execSync with a STATIC command string (no interpolation → no injection
 * surface). execFileSync is NOT an option here: npm resolves to npm.cmd on
 * Windows, and since the CVE-2024-27980 hardening Node refuses to spawn
 * .bat/.cmd via execFile (ENOENT/EINVAL), which would silently kill SCA on
 * Windows. stderr is dropped via stdio config (portable) instead of a
 * Unix-only `2>/dev/null` redirect.
 *
 * Residual: npm reads .npmrc from cwd, so a hostile scanned repo could point
 * the audit request at a malicious registry. Response flows into findings,
 * which are sanitized at the reporter layer — accepted risk.
 */
async function auditNpm(targetDir, pkgPath) {
  const npmLockPath = join(targetDir, 'package-lock.json');
  const hasNpmLock = existsSync(npmLockPath);
  const hasOtherLock = existsSync(join(targetDir, 'yarn.lock')) || existsSync(join(targetDir, 'pnpm-lock.yaml'));

  if (!hasNpmLock) {
    const direct = checkPackageJsonDirect(pkgPath);
    if (hasOtherLock) {
      direct.push(...incompleteNpmAudit('A yarn or pnpm lockfile exists, but npm audit cannot verify that dependency graph.'));
    }
    return direct;
  }

  const cli = findTrustedNpmCli();
  if (!cli) return incompleteNpmAudit('npm-cli.js was not found in a trusted Node installation. No PATH fallback was used.');

  const auditDir = mkdtempSync(join(tmpdir(), 'vibeaudit-sca-'));
  try {
    copyFileSync(pkgPath, join(auditDir, 'package.json'));
    copyFileSync(npmLockPath, join(auditDir, 'package-lock.json'));
    const userConfig = join(auditDir, 'user.npmrc');
    const globalConfig = join(auditDir, 'global.npmrc');
    writeFileSync(userConfig, '');
    writeFileSync(globalConfig, '');
    const result = execFileSync(process.execPath, [
      cli,
      'audit',
      '--json',
      '--ignore-scripts',
      `--registry=${NPM_REGISTRY}`,
    ], {
      cwd: auditDir,
      encoding: 'utf-8',
      timeout: 30000,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: createIsolatedNpmEnv(process.env, { userConfig, globalConfig }),
    });
    const parsed = parseNpmAudit(result);
    return parsed.valid ? parsed.findings : incompleteNpmAudit('npm audit returned unreadable output.');
  } catch (err) {
    // npm audit exits 1 when it finds vulnerabilities — stdout still has the data
    if (err.stdout) {
      const parsed = parseNpmAudit(err.stdout);
      if (parsed.valid) return parsed.findings;
    }
    return incompleteNpmAudit('npm audit failed before it could produce a complete result.');
  } finally {
    rmSync(auditDir, { recursive: true, force: true });
  }
}

/**
 * Basic package.json checks when no lockfile exists.
 */
function checkPackageJsonDirect(pkgPath) {
  const findings = [];

  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

    // Check for wildcard versions
    for (const [name, version] of Object.entries(allDeps)) {
      if (version === '*' || version === 'latest') {
        findings.push({
          ruleId: 'vulnerable-dependency',
          ruleName: 'Vulnerable Dependency',
          severity: 'warning',
          message: `${name} uses "${version}" version — unpinned dependency can introduce breaking changes or vulnerabilities.`,
          file: 'package.json',
          fix: `Pin the version: npm install ${name}@latest --save-exact.`,
        });
      }
    }

    // Flag missing lockfile
    if (Object.keys(allDeps).length > 0) {
      findings.push({
        ruleId: 'vulnerable-dependency',
        ruleName: 'Vulnerable Dependency',
        severity: 'info',
        message: 'No lockfile found (package-lock.json, yarn.lock, or pnpm-lock.yaml). Full vulnerability audit requires a lockfile.',
        file: 'package.json',
        fix: 'Run npm install to generate package-lock.json, then run npm audit for a full vulnerability scan.',
      });
    }
  } catch {
    // Invalid package.json — skip
  }

  return findings;
}

/**
 * Check Python requirements.txt for known insecure patterns.
 */
function checkPythonDeps(reqPath) {
  const findings = [];

  try {
    const content = readFileSync(reqPath, 'utf-8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;

      // Unpinned dependencies
      if (!line.includes('==') && !line.includes('>=') && !line.includes('~=')) {
        const name = line.split(/[<>=!]/)[0].trim();
        if (name) {
          findings.push({
            ruleId: 'vulnerable-dependency',
            ruleName: 'Vulnerable Dependency',
            severity: 'info',
            message: `${name} is unpinned — version may vary between installs.`,
            file: 'requirements.txt',
            line: i + 1,
            fix: `Pin the version: ${name}==X.Y.Z. Run: pip freeze > requirements.txt for exact versions.`,
          });
        }
      }
    }
  } catch {
    // File read error — skip
  }

  return findings;
}

/**
 * Map npm audit severity to vibe-audit severity.
 */
function mapNpmSeverity(npmSeverity) {
  switch (npmSeverity) {
    case 'critical':
    case 'high':
      return 'critical';
    case 'moderate':
      return 'warning';
    case 'low':
    case 'info':
    default:
      return 'info';
  }
}
