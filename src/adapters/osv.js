import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';

import { findTrustedExecutable } from '../trusted-tools.js';

const MAX_REPORT_BYTES = 10 * 1024 * 1024;
const MAX_INPUT_BYTES = 10 * 1024 * 1024;
const MAX_INPUTS = 512;
const MAX_FINDINGS = 5000;

const INPUT_MATCHERS = [
  { ecosystem: 'JavaScript', test: (name) => ['bun.lock', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'].includes(name.toLowerCase()) },
  { ecosystem: 'Python', test: (name) => ['pipfile.lock', 'poetry.lock', 'pdm.lock', 'pylock.toml', 'uv.lock'].includes(name.toLowerCase()) },
  { ecosystem: 'Python', parser: 'requirements.txt', test: (name) => /^requirements(?:[-_.].*)?\.txt$/i.test(name) },
  { ecosystem: 'Go', test: (name) => name.toLowerCase() === 'go.mod' },
  { ecosystem: 'Rust', test: (name) => name.toLowerCase() === 'cargo.lock' },
  { ecosystem: 'SBOM', kind: 'sbom', test: isSbomName },
];

const CONTAINER_MATCHER = (name) => {
  const lower = name.toLowerCase();
  return lower === 'dockerfile'
    || lower === 'containerfile'
    || lower === 'docker-compose.yml'
    || lower === 'docker-compose.yaml'
    || lower === 'compose.yml'
    || lower === 'compose.yaml';
};

const SKIP_DIRECTORIES = new Set([
  '.git', '.hg', '.svn', 'node_modules', '.next', '.nuxt', 'dist', 'build',
  'coverage', '__pycache__', '.venv', 'venv',
]);

/**
 * Discover only allowlisted dependency inputs. Generic bom.json/bom.xml names
 * must also contain a real CycloneDX or SPDX document to prevent false claims.
 *
 * @param {string} targetDir
 * @returns {Array<{absolutePath:string,relativePath:string,ecosystem:string,kind:'lockfile'|'sbom'|'container',parser?:string}>}
 */
export function discoverOsvLockfiles(targetDir) {
  return collectOsvInputs(targetDir).files;
}

function collectOsvInputs(targetDir) {
  const root = resolve(targetDir);
  const files = [];
  const errors = [];

  function walk(dir) {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      errors.push(`Could not read ${relative(root, dir) || '.'}: ${error.code || 'read error'}`);
      return;
    }

    for (const entry of entries) {
      if (files.length >= MAX_INPUTS) {
        errors.push(`More than ${MAX_INPUTS} supported dependency files were found.`);
        return;
      }
      const absolutePath = join(dir, entry.name);
      const relativePath = relative(root, absolutePath).replace(/\\/g, '/');
      if (entry.isDirectory()) {
        if (!SKIP_DIRECTORIES.has(entry.name.toLowerCase())) walk(absolutePath);
        continue;
      }
      if (entry.isSymbolicLink()) {
        if (isRecognizedName(entry.name)) errors.push(`Skipped symbolic-link dependency file ${relativePath}.`);
        continue;
      }
      if (!entry.isFile()) continue;

      const input = matchInput(entry.name);
      const container = CONTAINER_MATCHER(entry.name);
      if (!input && !container) continue;

      try {
        const stats = lstatSync(absolutePath);
        if (stats.size > MAX_INPUT_BYTES) {
          errors.push(`${relativePath} exceeds the ${MAX_INPUT_BYTES} byte safety limit.`);
          continue;
        }
        if (input?.kind === 'sbom' && !isValidSbom(absolutePath, entry.name)) continue;
        files.push({
          absolutePath,
          relativePath,
          ecosystem: input?.ecosystem || 'container',
          kind: input?.kind || (input ? 'lockfile' : 'container'),
          ...(input?.parser ? { parser: input.parser } : {}),
        });
      } catch (error) {
        errors.push(`Could not inspect ${relativePath}: ${error.code || 'read error'}`);
      }
    }
  }

  try {
    const rootStats = statSync(root);
    if (!rootStats.isDirectory()) errors.push('OSV target is not a directory.');
    else walk(root);
  } catch (error) {
    errors.push(`Could not inspect OSV target: ${error.code || 'read error'}`);
  }

  return { files, errors };
}

function matchInput(name) {
  return INPUT_MATCHERS.find((matcher) => matcher.test(name)) || null;
}

function isRecognizedName(name) {
  return Boolean(matchInput(name) || CONTAINER_MATCHER(name));
}

function isSbomName(name) {
  const lower = name.toLowerCase();
  return lower === 'bom.json'
    || lower === 'bom.xml'
    || lower.endsWith('.cdx.json')
    || lower.endsWith('.cdx.xml')
    || lower.endsWith('.spdx.json')
    || lower.endsWith('.spdx')
    || lower.endsWith('.spdx.yml')
    || lower.endsWith('.spdx.yaml')
    || lower.endsWith('.spdx.rdf')
    || lower.endsWith('.spdx.rdf.xml');
}

function isValidSbom(path, name) {
  const raw = readFileSync(path, 'utf8');
  const lower = name.toLowerCase();
  if (lower.endsWith('.json')) {
    try {
      const parsed = JSON.parse(raw);
      return parsed?.bomFormat === 'CycloneDX' || /^SPDX-/i.test(parsed?.spdxVersion || '');
    } catch {
      return false;
    }
  }
  if (lower.endsWith('.spdx') || lower.endsWith('.spdx.yml') || lower.endsWith('.spdx.yaml')) {
    return /(?:^|\n)\s*SPDXVersion\s*:/i.test(raw) || /(?:^|\n)\s*spdxVersion\s*:/i.test(raw);
  }
  return /<\s*(?:\w+:)?bom\b[^>]*(?:cyclonedx|http:\/\/cyclonedx\.org)/i.test(raw)
    || /(?:spdx\.org\/rdf|<\s*(?:\w+:)?SpdxDocument\b)/i.test(raw);
}

/**
 * Run a trusted OSV-Scanner executable against a staged allowlist. The target
 * repository's OSV config, ignores, executable shims, and unrelated files are
 * never copied into the scanner workspace.
 */
export function runOsvAdapter(targetDir, options = {}) {
  const inventory = collectOsvInputs(targetDir);
  const scanInputs = inventory.files.filter((file) => file.kind === 'lockfile' || file.kind === 'sbom');
  const containers = inventory.files.filter((file) => file.kind === 'container');

  if (inventory.errors.length > 0) {
    return failed(`OSV dependency inventory is incomplete: ${inventory.errors[0]}`, inventory);
  }
  if (scanInputs.length === 0) {
    const containerFinding = containers.length > 0 ? [containerCoverageFinding(containers[0])] : [];
    return {
      tool: 'osv-scanner',
      status: 'completed',
      coverage: coverage(containers.length === 0, scanInputs, containers, 0,
        containers.length > 0
          ? 'Container manifests were found, but no supported dependency lockfile or SBOM was available.'
          : 'No OSV-supported dependency inputs were found.'),
      findings: containerFinding,
    };
  }

  const findExecutable = options.findExecutable || ((name, scannedTarget) => findTrustedExecutable(name, scannedTarget, options.env));
  let executable;
  try {
    executable = findExecutable('osv-scanner', targetDir);
  } catch {
    executable = null;
  }
  if (!executable) {
    const reason = 'A trusted OSV-Scanner executable was not found outside the scan target.';
    return {
      tool: 'osv-scanner',
      status: 'unavailable',
      coverage: coverage(false, scanInputs, containers, 0, reason),
      findings: [unavailableFinding(scanInputs[0])],
    };
  }

  const workspace = mkdtempSync(join(tmpdir(), 'vibeaudit-osv-'));
  const stagedRoot = join(workspace, 'inputs');
  const pathMap = new Map();
  try {
    mkdirSync(stagedRoot, { recursive: true });
    for (const file of scanInputs) {
      const stagedPath = join(stagedRoot, file.relativePath.replace(/\//g, sep));
      mkdirSync(dirname(stagedPath), { recursive: true });
      const realSource = realpathSync(file.absolutePath);
      if (normalizePath(realSource) !== normalizePath(file.absolutePath)) {
        return failed(`Refused to stage symbolic-link dependency file ${file.relativePath}.`, inventory);
      }
      copyFileSync(realSource, stagedPath);
      pathMap.set(normalizePath(stagedPath), file.relativePath);
    }

    // Disable call analysis. This adapter inventories lockfiles and SBOMs only;
    // it must never invoke a language toolchain or target-controlled build step.
    const args = ['scan', 'source', '--format=json', '--no-ignore', '--no-call-analysis=go'];
    for (const file of scanInputs) {
      const stagedPath = join(stagedRoot, file.relativePath.replace(/\//g, sep));
      args.push(`--lockfile=${formatInputArg(file, stagedPath)}`);
    }
    const runner = options.runner || ((command, commandArgs, runOptions) => spawnSync(command, commandArgs, runOptions));
    let run;
    try {
      run = runner(executable, args, {
        cwd: workspace,
        env: isolatedEnvironment(options.env),
        encoding: 'utf8',
        timeout: options.timeoutMs || 90_000,
        maxBuffer: MAX_REPORT_BYTES,
        windowsHide: true,
        shell: false,
      });
    } catch (error) {
      return failed(error?.code === 'ETIMEDOUT' ? 'OSV-Scanner timed out.' : 'OSV-Scanner could not be started.', inventory);
    }
    if (run?.error || run?.signal || ![0, 1].includes(run?.status)) {
      return failed(run?.error?.code === 'ETIMEDOUT'
        ? 'OSV-Scanner timed out.'
        : `OSV-Scanner exited with exit code ${run?.status ?? 'unknown'}.`, inventory);
    }

    const raw = typeof run.stdout === 'string' ? run.stdout : '';
    if (Buffer.byteLength(raw, 'utf8') > MAX_REPORT_BYTES) {
      return failed('OSV-Scanner report exceeded the 10 MiB safety limit.', inventory);
    }
    let report;
    try {
      report = JSON.parse(raw);
    } catch {
      return failed('OSV-Scanner returned invalid JSON.', inventory);
    }
    if (!report || !Array.isArray(report.results)) {
      return failed('OSV-Scanner returned a JSON report without a results array.', inventory);
    }

    const parsed = parseOsvReport(report, pathMap);
    if (parsed.length > MAX_FINDINGS) {
      return failed(`OSV-Scanner returned more than ${MAX_FINDINGS} findings.`, inventory);
    }
    if (run.status === 1 && parsed.length === 0 && reportContainsVulnerabilities(report)) {
      return failed('OSV-Scanner reported vulnerabilities that could not be converted into reviewable findings.', inventory);
    }
    const findings = [...parsed];
    if (containers.length > 0) findings.push(containerCoverageFinding(containers[0]));
    return {
      tool: 'osv-scanner',
      status: 'completed',
      coverage: {
        ...coverage(containers.length === 0, scanInputs, containers, scanInputs.length,
          containers.length > 0 ? 'Container manifests require a lockfile or SBOM tied to the built image.' : undefined),
        vulnerabilities: parsed.length,
      },
      findings,
    };
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

function reportContainsVulnerabilities(report) {
  return report.results.some((result) => result?.packages?.some((entry) =>
    Array.isArray(entry?.vulnerabilities) && entry.vulnerabilities.length > 0));
}

function coverage(complete, inputs, containers, scanned, reason) {
  return {
    complete,
    discovered: inputs.length,
    scanned,
    lockfiles: inputs.filter((file) => file.kind === 'lockfile').length,
    sboms: inputs.filter((file) => file.kind === 'sbom').length,
    ecosystems: [...new Set(inputs.map((file) => file.ecosystem))].sort(),
    containers: containers.length,
    ...(reason ? { reason } : {}),
  };
}

function formatInputArg(file, stagedPath) {
  if (file.parser) return `${file.parser}:${stagedPath}`;
  return process.platform === 'win32' ? `:${stagedPath}` : stagedPath;
}

function failed(reason, inventory) {
  const inputs = inventory.files.filter((file) => file.kind === 'lockfile' || file.kind === 'sbom');
  const containers = inventory.files.filter((file) => file.kind === 'container');
  return {
    tool: 'osv-scanner',
    status: 'failed',
    coverage: coverage(false, inputs, containers, 0, reason),
    findings: [incompleteFinding(reason, inputs[0])],
  };
}

function isolatedEnvironment(source = process.env) {
  const allowed = ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'PATH', 'Path', 'LANG', 'LC_ALL'];
  return Object.fromEntries(allowed.filter((key) => source?.[key] !== undefined).map((key) => [key, source[key]]));
}

/** Convert OSV's stable JSON report into Vibe Audit findings. */
export function parseOsvReport(input, pathMap = new Map()) {
  let report = input;
  if (typeof input === 'string') {
    try {
      report = JSON.parse(input);
    } catch {
      return [];
    }
  }
  if (!report || !Array.isArray(report.results)) return [];

  const findings = [];
  const seen = new Set();
  for (const result of report.results) {
    const sourcePath = safeText(result?.source?.path, 'dependency lockfile');
    const file = mapSourcePath(sourcePath, pathMap);
    const packages = Array.isArray(result?.packages) ? result.packages : [];
    const groupMap = new Map();
    for (const entry of packages) {
      for (const group of Array.isArray(entry?.groups) ? entry.groups : []) {
        const ids = Array.isArray(group?.ids) ? group.ids.map((id) => safeText(id, '')).filter(Boolean) : [];
        const representative = [...ids].sort()[0];
        for (const id of ids) groupMap.set(id, representative || id);
      }
    }
    for (const entry of packages) {
      const pkg = entry?.package || {};
      const name = safeText(pkg.name, 'unknown package');
      const version = safeText(pkg.version || pkg.commit, 'unknown version');
      for (const vulnerability of Array.isArray(entry?.vulnerabilities) ? entry.vulnerabilities : []) {
        const id = safeText(vulnerability?.id, 'unknown OSV vulnerability');
        const groupId = groupMap.get(id) || id;
        const key = `${file}|${name}|${version}|${groupId}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const aliases = Array.isArray(vulnerability?.aliases)
          ? vulnerability.aliases.map((alias) => safeText(alias, '')).filter(Boolean).slice(0, 10)
          : [];
        const fixed = findFixedVersion(vulnerability, pkg);
        const summary = safeText(vulnerability?.summary || vulnerability?.details, 'Known vulnerability reported by OSV.');
        const severityInfo = mapOsvSeverity(vulnerability);
        findings.push({
          ruleId: 'vulnerable-dependency',
          ruleName: 'OSV Vulnerable Dependency',
          severity: severityInfo.severity,
          message: `${name}@${version} (${safeText(pkg.ecosystem, 'unknown ecosystem')}) has ${id}${aliases.length ? ` (${aliases.join(', ')})` : ''}: ${summary}`,
          file,
          fix: fixed
            ? `Upgrade ${name} to ${fixed} or later, then rerun OSV-Scanner.`
            : `No fixed version was reported. Review ${id} at https://osv.dev/${encodeURIComponent(id)} and rerun OSV-Scanner.`,
          source: 'osv-scanner',
          osvId: id,
          aliases,
          ...(severityInfo.cvssScore === undefined ? {} : { cvssScore: severityInfo.cvssScore }),
        });
      }
    }
  }
  return findings;
}

function mapSourcePath(sourcePath, pathMap) {
  const normalized = normalizePath(sourcePath);
  if (pathMap.has(normalized)) return pathMap.get(normalized);
  for (const [staged, original] of pathMap.entries()) {
    if (normalized.endsWith(`/${staged.split('/').slice(-2).join('/')}`) || normalized.endsWith(`/${basename(staged)}`)) return original;
  }
  return safeText(sourcePath.replace(/\\/g, '/').split('/').pop(), 'dependency lockfile');
}

function normalizePath(value) {
  return resolve(String(value).replace(/^file:\/\//i, '')).replace(/\\/g, '/').toLowerCase();
}

function findFixedVersion(vulnerability, pkg) {
  const affectedEntries = Array.isArray(vulnerability?.affected) ? vulnerability.affected : [];
  const matching = affectedEntries.filter((affected) => {
    const affectedPkg = affected?.package || {};
    if (!affectedPkg.name && !affectedPkg.ecosystem) return true;
    return (!affectedPkg.name || affectedPkg.name === pkg.name)
      && (!affectedPkg.ecosystem || String(affectedPkg.ecosystem).toLowerCase() === String(pkg.ecosystem).toLowerCase());
  });
  const candidates = [];
  for (const affected of matching) {
    for (const range of Array.isArray(affected?.ranges) ? affected.ranges : []) {
      for (const event of Array.isArray(range?.events) ? range.events : []) {
        if (event?.fixed) candidates.push(event.fixed);
      }
    }
  }
  if (vulnerability?.database_specific?.fixed) candidates.push(vulnerability.database_specific.fixed);
  return safeText(candidates.find(Boolean), '');
}

function mapOsvSeverity(vulnerability) {
  const values = [vulnerability?.database_specific?.severity, vulnerability?.severity]
    .flatMap((value) => Array.isArray(value) ? value : [value])
    .map((value) => typeof value === 'object' ? value?.score || value?.severity : value)
    .filter(Boolean)
    .map(String);
  const scored = values.map(cvssScore).find((value) => value !== undefined);
  if (scored !== undefined) {
    return { severity: scored >= 7 ? 'critical' : scored >= 4 ? 'warning' : 'info', cvssScore: scored };
  }
  const labels = values.map((value) => value.toLowerCase());
  if (labels.some((value) => value.includes('critical') || value.includes('high'))) return { severity: 'critical' };
  if (labels.some((value) => value.includes('medium') || value.includes('moderate'))) return { severity: 'warning' };
  if (labels.some((value) => value.includes('low'))) return { severity: 'info' };
  return { severity: 'warning' };
}

function cvssScore(value) {
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric >= 0 && numeric <= 10) return numeric;
  if (!/^CVSS:3\.[01]\//i.test(value)) return undefined;
  const metrics = Object.fromEntries(value.split('/').slice(1).map((part) => part.split(':')));
  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metrics.AV];
  const ac = { L: 0.77, H: 0.44 }[metrics.AC];
  const ui = { N: 0.85, R: 0.62 }[metrics.UI];
  const scopeChanged = metrics.S === 'C';
  const pr = scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }[metrics.PR]
    : { N: 0.85, L: 0.62, H: 0.27 }[metrics.PR];
  const c = { H: 0.56, L: 0.22, N: 0 }[metrics.C];
  const i = { H: 0.56, L: 0.22, N: 0 }[metrics.I];
  const a = { H: 0.56, L: 0.22, N: 0 }[metrics.A];
  if ([av, ac, ui, pr, c, i, a].some((metric) => metric === undefined)) return undefined;
  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const base = scopeChanged ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
  return Math.ceil(base * 10) / 10;
}

function unavailableFinding(file) {
  return incompleteFinding('A trusted OSV-Scanner executable was not found outside the scan target.', file);
}

function containerCoverageFinding(file) {
  return {
    ruleId: 'scan-incomplete',
    ruleName: 'Container Dependency Scan Incomplete',
    severity: 'warning',
    message: `Container manifest ${file.relativePath} was inventoried, but it cannot prove which packages entered the built image.`,
    file: file.relativePath,
    fix: 'Generate a CycloneDX or SPDX SBOM for the built image, then rerun Vibe Audit. Never execute an untrusted image to inspect it.',
    source: 'osv-scanner',
  };
}

function incompleteFinding(message, file) {
  return {
    ruleId: 'scan-incomplete',
    ruleName: 'OSV Dependency Audit Incomplete',
    severity: 'warning',
    message: safeText(message, 'OSV dependency analysis did not complete.'),
    file: file?.relativePath || 'dependency manifests',
    fix: 'Install OSV-Scanner from a trusted release, verify its provenance, and rerun. Use --skip-osv only for an explicit exception.',
    source: 'osv-scanner',
  };
}

function safeText(value, fallback, max = 320) {
  if (value === undefined || value === null) return fallback;
  const text = String(value).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  return text ? text.slice(0, max) : fallback;
}

export const OSV_SUPPORTED_ECOSYSTEMS = ['JavaScript', 'Python', 'Go', 'Rust', 'SBOM'];
