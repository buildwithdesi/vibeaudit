import { discoverFiles } from './scanner.js';
import { resolveRules } from './rules/index.js';
import { report } from './reporter.js';
import { loadConfig } from './config.js';
import { CWE_MAP } from './data/cwe-map.js';
import { runSCA } from './sca/index.js';

/**
 * Run rules against a file iterator (local or remote).
 * @param {AsyncIterable} fileSource
 * @param {Array} rules
 * @param {boolean} deep
 * @returns {Promise<{ findings: Array, filesScanned: number }>}
 */
async function runRules(fileSource, rules, deep) {
  const findings = [];
  let filesScanned = 0;

  for await (const file of fileSource) {
    filesScanned++;
    if (deep) file._deepMode = true;
    for (const rule of rules) {
      try {
        const ruleFindings = rule.check(file);
        findings.push(...ruleFindings);
      } catch {
        // A rule should never crash the entire audit.
      }
    }
  }

  return { findings, filesScanned };
}

/**
 * Run the full audit pipeline.
 *
 * @param {string} targetDir - Absolute path to project root (or display label for remote)
 * @param {Object} [cliOptions] - Options from CLI flags (override config)
 * @param {string} [cliOptions.format]
 * @param {string[]} [cliOptions.rules]
 * @param {string[]} [cliOptions.exclude]
 * @param {boolean} [cliOptions.strict]
 * @param {boolean} [cliOptions.skipSca]
 * @param {boolean} [cliOptions.deep]
 * @param {boolean} [cliOptions.quiet]
 * @param {AsyncIterable} [cliOptions.fileSource] - Custom file source (e.g. GitHub API). If provided, skips local file discovery.
 * @returns {Promise<{ findings: import('./rules/types.js').Finding[], exitCode: number }>}
 */
export async function audit(targetDir, cliOptions = {}) {
  const start = performance.now();

  // Load config — for remote scans, use defaults since there's no local config file.
  const config = cliOptions.fileSource ? { ignore: [], rules: [], exclude: [], format: 'terminal', strict: false } : await loadConfig(targetDir);
  const format = cliOptions.format || config.format;
  const ruleIds = cliOptions.rules?.length ? cliOptions.rules : config.rules;
  const excludeIds = cliOptions.exclude?.length ? cliOptions.exclude : config.exclude;
  const strict = cliOptions.strict ?? config.strict;
  const skipSca = cliOptions.skipSca ?? false;
  const deep = cliOptions.deep ?? false;
  const quiet = cliOptions.quiet ?? false;

  // Resolve which rules to run.
  const rules = resolveRules(ruleIds, excludeIds);

  // Scan files and run rules — use custom file source or local discovery.
  const fileSource = cliOptions.fileSource || discoverFiles(targetDir, config.ignore);
  const { findings, filesScanned } = await runRules(fileSource, rules, deep);

  // SCA: Dependency vulnerability scanning (only for local scans).
  if (!skipSca && !cliOptions.fileSource) {
    try {
      const scaFindings = await runSCA(targetDir);
      findings.push(...scaFindings);
    } catch {
      // SCA failure should not crash the audit.
    }
  }

  const durationMs = Math.round(performance.now() - start);

  // Enrich findings with CWE/CVSS/OWASP metadata.
  for (const f of findings) {
    const meta = CWE_MAP[f.ruleId];
    if (meta) {
      f.cweId = meta.cweId;
      f.cvssScore = meta.cvssScore;
      f.owaspCategory = meta.owaspCategory;
    }
  }

  // Sort: criticals first, then warnings, then info.
  const severityOrder = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Report (skip when running headless/batch).
  if (!quiet) {
    await report(findings, format, {
      filesScanned,
      rulesRun: rules.length,
      durationMs,
      targetDir,
    });
  }

  // Exit code: 1 if criticals found, 1 if warnings + strict mode, 0 otherwise.
  const hasCritical = findings.some((f) => f.severity === 'critical');
  const hasWarning = findings.some((f) => f.severity === 'warning');
  const exitCode = hasCritical ? 1 : strict && hasWarning ? 1 : 0;

  return { findings, exitCode };
}
