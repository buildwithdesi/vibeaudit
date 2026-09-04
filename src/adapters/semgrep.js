import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { findTrustedExecutable } from '../trusted-tools.js';

const MAX_REPORT_BYTES = 10 * 1024 * 1024;
const MAX_FINDINGS = 5000;
const MAX_INPUT_FILES = 512;
const MAX_INPUT_BYTES = 50 * 1024 * 1024;
const SUPPORTED_EXTENSIONS = new Set(['.cjs', '.js', '.jsx', '.mjs', '.py', '.ts', '.tsx']);

function isolatedEnvironment(source = process.env) {
  const allowed = ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'Path', 'LANG', 'LC_ALL'];
  return Object.fromEntries(allowed
    .filter((key) => source?.[key] !== undefined)
    .map((key) => [key, source[key]]));
}

function safeText(value, fallback, max = 500) {
  if (value === undefined || value === null) return fallback;
  const text = String(value).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  return text ? text.slice(0, max) : fallback;
}

function normalizePath(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase();
}

function safeLine(value, fallback = 0) {
  return Number.isInteger(value) && value >= 0 && value <= 1_000_000 ? value : fallback;
}

function mapFindingPath(value, pathMap) {
  const normalized = normalizePath(value);
  if (pathMap.has(normalized)) return safePath(pathMap.get(normalized));
  const name = basename(normalized);
  return safePath(pathMap.get(name), 'unknown staged agent script');
}

function safePath(value, fallback = 'unknown staged agent script') {
  if (value === undefined || value === null) return fallback;
  const path = String(value).replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return path ? path.slice(0, 2048) : fallback;
}

function mapSeverity(value) {
  const normalized = safeText(value, '').toLowerCase();
  if (normalized.includes('error') || normalized.includes('critical') || normalized.includes('high')) return 'critical';
  if (normalized.includes('info') || normalized.includes('low')) return 'info';
  return 'warning';
}

function metadataTags(metadata = {}) {
  const tags = [];
  if (typeof metadata.category === 'string') tags.push(metadata.category);
  if (Array.isArray(metadata.technology)) tags.push(...metadata.technology);
  return tags.map((tag) => safeText(tag, '')).filter(Boolean).slice(0, 20);
}

function safeFinding(finding, pathMap) {
  const extra = finding?.extra && typeof finding.extra === 'object' ? finding.extra : {};
  const metadata = extra.metadata && typeof extra.metadata === 'object' ? extra.metadata : {};
  return {
    ruleId: safeText(finding?.check_id, 'unknown-semgrep-rule'),
    description: safeText(extra.message, 'Semgrep identified a risky agent-code flow.'),
    file: mapFindingPath(finding?.path, pathMap),
    startLine: safeLine(finding?.start?.line),
    endLine: safeLine(finding?.end?.line, safeLine(finding?.start?.line)),
    severity: mapSeverity(extra.severity),
    tags: metadataTags(metadata),
  };
}

function failed(reason) {
  return {
    tool: 'semgrep',
    status: 'failed',
    coverage: { complete: false, reason },
    findings: [],
  };
}

/**
 * Run Semgrep against a sanitized staging tree containing only supported
 * agent scripts and hooks. The target's configuration and ignore files are
 * never copied into the scanner workspace.
 *
 * @param {Array<{path:string,content:string}>} files
 * @param {{findExecutable?:Function,runner?:Function,env?:NodeJS.ProcessEnv,timeoutMs?:number,targetDir?:string}} [options]
 */
export function runSemgrepAdapter(files, options = {}) {
  const findExecutable = options.findExecutable || ((name, targetDir) => findTrustedExecutable(name, targetDir, options.env));
  let executable;
  try {
    executable = findExecutable('semgrep', options.targetDir);
  } catch {
    executable = null;
  }
  if (!executable) {
    return {
      tool: 'semgrep',
      status: 'unavailable',
      coverage: { complete: false, reason: 'A trusted Semgrep executable was not found outside the scan target.' },
      findings: [],
    };
  }

  const supportedFiles = files.filter((file) => file && SUPPORTED_EXTENSIONS.has(extname(String(file.path || '')).toLowerCase()));
  if (supportedFiles.length === 0) {
    return {
      tool: 'semgrep',
      status: 'completed',
      coverage: { complete: true, scanned: 0, reason: 'No supported agent scripts or hooks were found.' },
      findings: [],
    };
  }
  if (supportedFiles.length > MAX_INPUT_FILES) return failed(`Semgrep received more than ${MAX_INPUT_FILES} supported agent scripts.`);
  const inputBytes = supportedFiles.reduce((total, file) => total + Buffer.byteLength(String(file.content ?? ''), 'utf8'), 0);
  if (inputBytes > MAX_INPUT_BYTES) return failed('Semgrep input exceeded the 50 MiB safety limit.');

  const workspace = mkdtempSync(join(tmpdir(), 'vibeaudit-semgrep-'));
  const staged = join(workspace, 'agent-files');
  const bundledConfigPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'semgrep-agent.yml');
  const configPath = join(workspace, 'semgrep-agent.yml');
  const pathMap = new Map();
  try {
    writeFileSync(configPath, readFileSync(bundledConfigPath), { encoding: 'utf8', flag: 'wx' });
    mkdirSync(staged, { recursive: true });
    supportedFiles.forEach((file, index) => {
      const originalPath = String(file.path || 'unknown agent script');
      const extension = extname(originalPath).slice(0, 12);
      const stem = basename(originalPath, extname(originalPath)).replace(/[^a-z0-9_.-]/gi, '_').slice(0, 80);
      const name = `${String(index).padStart(6, '0')}-${stem || 'agent-script'}${extension}`;
      writeFileSync(join(staged, name), String(file.content ?? ''), { encoding: 'utf8', flag: 'wx' });
      pathMap.set(normalizePath(name), originalPath);
      pathMap.set(normalizePath(join(staged, name)), originalPath);
    });

    const args = [
      'scan',
      '--config', configPath,
      '--json',
      '--metrics=off',
      '--disable-version-check',
      '--no-git-ignore',
      staged,
    ];
    const runner = options.runner || ((command, commandArgs, runOptions) => spawnSync(command, commandArgs, runOptions));
    let run;
    try {
      run = runner(executable, args, {
        cwd: workspace,
        env: isolatedEnvironment(options.env),
        encoding: 'utf8',
        timeout: options.timeoutMs || 90_000,
        maxBuffer: MAX_REPORT_BYTES + 1024 * 1024,
        windowsHide: true,
        shell: false,
      });
    } catch (error) {
      return failed(error?.code === 'ETIMEDOUT' ? 'Semgrep timed out.' : 'Semgrep could not be started.');
    }
    if (run?.error || run?.signal || ![0, 1].includes(run?.status)) {
      return failed(run?.error?.code === 'ETIMEDOUT'
        ? 'Semgrep timed out.'
        : `Semgrep exited with exit code ${run?.status ?? 'unknown'}.`);
    }

    const raw = typeof run.stdout === 'string'
      ? run.stdout
      : Buffer.isBuffer(run.stdout) ? run.stdout.toString('utf8') : '';
    if (Buffer.byteLength(raw, 'utf8') > MAX_REPORT_BYTES) return failed('Semgrep report exceeded the 10 MiB safety limit.');
    let report;
    try {
      report = JSON.parse(raw);
    } catch {
      return failed('Semgrep returned invalid JSON.');
    }
    if (!report || !Array.isArray(report.results)) return failed('Semgrep returned a JSON report without a results array.');
    if (report.errors !== undefined && !Array.isArray(report.errors)) return failed('Semgrep returned a malformed errors field.');
    const errors = Array.isArray(report.errors) ? report.errors : [];
    if (errors.length > 0) {
      return failed(`Semgrep reported ${errors.length} scan error${errors.length === 1 ? '' : 's'}.`);
    }
    if (report.results.length > MAX_FINDINGS) return failed(`Semgrep returned more than ${MAX_FINDINGS} findings.`);

    const findings = report.results.map((finding) => safeFinding(finding, pathMap));
    if (run.status === 1 && findings.length === 0) return failed('Semgrep reported findings but returned no reviewable results.');
    return {
      tool: 'semgrep',
      status: 'completed',
      coverage: { complete: true, scanned: supportedFiles.length, config: 'bundled-agent-flow-rules' },
      findings,
    };
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

export const SEMGREP_SUPPORTED_EXTENSIONS = Object.freeze([...SUPPORTED_EXTENSIONS]);
