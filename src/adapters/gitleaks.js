import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { findTrustedExecutable } from '../trusted-tools.js';

const MAX_REPORT_BYTES = 10 * 1024 * 1024;

function isolatedEnvironment(source = process.env) {
  const allowed = ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'LANG', 'LC_ALL'];
  return Object.fromEntries(allowed.filter((key) => source[key] !== undefined).map((key) => [key, source[key]]));
}

function safeFinding(finding, pathMap) {
  return {
    ruleId: String(finding.RuleID || 'unknown'),
    description: String(finding.Description || 'Potential secret'),
    file: pathMap.get(basename(String(finding.File || ''))) || 'unknown staged agent file',
    startLine: Number.isInteger(finding.StartLine) ? finding.StartLine : 0,
    endLine: Number.isInteger(finding.EndLine) ? finding.EndLine : 0,
    tags: Array.isArray(finding.Tags) ? finding.Tags.map(String).slice(0, 20) : [],
  };
}

function failed(reason) {
  return {
    tool: 'gitleaks',
    status: 'failed',
    coverage: { complete: false, reason },
    findings: [],
  };
}

/**
 * Run Gitleaks against a sanitized staging tree containing only agent files.
 * Target configuration, ignore files, inline allow comments, and inherited
 * Gitleaks environment variables cannot weaken this scan.
 *
 * @param {Array<{path:string,content:string}>} files
 * @param {{findExecutable?:Function,runner?:Function,env?:NodeJS.ProcessEnv,timeoutMs?:number,targetDir?:string}} [options]
 */
export function runGitleaksAdapter(files, options = {}) {
  const findExecutable = options.findExecutable || ((name) => findTrustedExecutable(name));
  const executable = findExecutable('gitleaks', options.targetDir);
  if (!executable) {
    return {
      tool: 'gitleaks',
      status: 'unavailable',
      coverage: { complete: false, reason: 'A trusted Gitleaks executable was not found outside the scan target.' },
      findings: [],
    };
  }
  if (files.length === 0) {
    return { tool: 'gitleaks', status: 'completed', coverage: { complete: true, scanned: 0 }, findings: [] };
  }

  const workspace = mkdtempSync(join(tmpdir(), 'vibeaudit-gitleaks-'));
  const staged = join(workspace, 'agent-files');
  const reportPath = join(workspace, 'report.json');
  const ignorePath = join(workspace, 'trusted-empty.gitleaksignore');
  const configPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'gitleaks.toml');
  const pathMap = new Map();
  try {
    mkdirSync(staged, { recursive: true });
    files.forEach((file, index) => {
      const extension = extname(file.path).slice(0, 12);
      const name = `${String(index).padStart(6, '0')}-${basename(file.path, extname(file.path)).replace(/[^a-z0-9_.-]/gi, '_').slice(0, 80)}${extension}`;
      writeFileSync(join(staged, name), String(file.content ?? ''), { encoding: 'utf8', flag: 'wx' });
      pathMap.set(name, file.path);
    });
    writeFileSync(ignorePath, '', { encoding: 'utf8', flag: 'wx' });

    const args = [
      'dir', staged,
      '--config', configPath,
      '--gitleaks-ignore-path', ignorePath,
      '--ignore-gitleaks-allow',
      '--report-format', 'json',
      '--report-path', reportPath,
      '--no-banner',
      '--no-color',
      '--redact=100',
      '--max-target-megabytes', '2',
      '--max-decode-depth', '2',
      '--timeout', '60',
    ];
    const runner = options.runner || ((command, commandArgs, runOptions) => spawnSync(command, commandArgs, runOptions));
    const run = runner(executable, args, {
      cwd: workspace,
      env: isolatedEnvironment(options.env),
      encoding: 'utf8',
      timeout: options.timeoutMs || 70_000,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
      shell: false,
    });
    if (run.error || run.signal || ![0, 1].includes(run.status)) {
      return failed(run.error?.code === 'ETIMEDOUT' ? 'Gitleaks timed out.' : `Gitleaks exited with exit code ${run.status ?? 'unknown'}.`);
    }
    try {
      if (statSync(reportPath).size > MAX_REPORT_BYTES) return failed('Gitleaks report exceeded the 10 MiB safety limit.');
    } catch {
      return failed('Gitleaks did not produce its required JSON report.');
    }
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(reportPath, 'utf8'));
      if (!Array.isArray(parsed)) throw new Error('not an array');
    } catch {
      return failed('Gitleaks produced an invalid JSON report.');
    }
    const findings = parsed.map((finding) => safeFinding(finding, pathMap));
    if (run.status === 1 && findings.length === 0) return failed('Gitleaks reported leaks but returned no reviewable findings.');
    return {
      tool: 'gitleaks',
      status: 'completed',
      coverage: { complete: true, scanned: files.length, config: 'bundled-default-rules' },
      findings,
    };
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}
