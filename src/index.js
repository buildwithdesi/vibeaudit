import { discoverFiles } from './scanner.js';
import { resolveRules } from './rules/index.js';
import { report } from './reporter.js';
import { loadConfig, getDefaultConfig } from './config.js';
import { CWE_MAP } from './data/cwe-map.js';
import { runSCA } from './sca/index.js';
import { isSuppressed, pathDisabledFor } from './suppress.js';
import { parseGitHubTarget, fetchRemoteConfig } from './github.js';

/**
 * Check whether a relative path has any path segment matching one of the ignore
 * patterns. Applied uniformly to local AND remote file sources — local discovery
 * already skips ignored directories at walk time (this is a harmless no-op there),
 * but remote sources (GitHub API) fetch everything up front, so this is the only
 * place that actually honors a project's .vibe-audit.json "ignore" list for them.
 *
 * @param {string} relativePath
 * @param {string[]} ignore
 * @returns {boolean}
 */
function isIgnoredPath(relativePath, ignore) {
  if (!ignore || ignore.length === 0) return false;
  const segments = relativePath.split('/');
  return ignore.some((pattern) => {
    const name = pattern.replace(/\/$/, '');
    return segments.includes(name);
  });
}

/**
 * Run rules against a file iterator (local or remote).
 * @param {AsyncIterable} fileSource
 * @param {Array} rules
 * @param {boolean} deep
 * @param {object} [config] - resolved config (exposes customEscapers / customAuthGuards / disableForPaths to rules via file._config)
 * @returns {Promise<{ findings: Array, filesScanned: number }>}
 */
async function runRules(fileSource, rules, deep, config = {}) {
  const findings = [];
  let filesScanned = 0;

  for await (const file of fileSource) {
    if (isIgnoredPath(file.relativePath, config.ignore)) continue;
    filesScanned++;
    if (deep) file._deepMode = true;
    file._config = config;
    for (const rule of rules) {
      if (pathDisabledFor(config, rule.id, file.relativePath)) continue;
      try {
        const ruleFindings = rule.check(file) || [];
        for (const finding of ruleFindings) {
          if (!isSuppressed(file, finding)) findings.push(finding);
        }
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
 * @param {AsyncIterable} [cliOptions.fileSource] - Custom file source (e.g. GitHub API). If provided, skips local file discovery.
 * @param {string[]} [cliOptions.extraIgnore] - Baseline ignore patterns merged on top of the resolved config's ignore list. Applied to every file source, so a self/portfolio scan can always exclude reports/ and test fixtures even when a remote .vibe-audit.json fetch fails open to an empty ignore list.
 * @param {import('./config.js').VibeAuditConfig} [cliOptions.config] - Pre-resolved config. Skips loadConfig()/fetchRemoteConfig() entirely (used by tests and callers that already resolved config).
 * @returns {Promise<{ findings: import('./rules/types.js').Finding[], exitCode: number }>}
 */
export async function audit(targetDir, cliOptions = {}) {
  const start = performance.now();

  // Load config. For remote scans (GitHub-fetched files), fetch the target repo's own
  // .vibe-audit.json over the API so remote runs respect the same ignore/rules/exclude
  // config a local `vibeaudit .` run would — otherwise test fixtures containing fake
  // secrets get flagged as if they were production code.
  // `cliOptions.config` lets callers (tests, or callers that already resolved config)
  // skip both the local file read and the remote API round-trip.
  let config;
  if (cliOptions.config) {
    config = cliOptions.config;
  } else if (cliOptions.fileSource) {
    // targetDir may be "owner/repo" (morning-scan.js) or "github://owner/repo" (CLI) — try both.
    const target = parseGitHubTarget(targetDir.replace(/^github:\/\//, '')) || parseGitHubTarget(targetDir);
    const remoteConfig = target ? await fetchRemoteConfig(target.owner, target.repo) : null;
    config = remoteConfig || getDefaultConfig();
  } else {
    config = await loadConfig(targetDir);
  }

  // Baseline ignores that always apply on top of the resolved config. Remote scans
  // (GitHub API) rely on fetchRemoteConfig() to supply a repo's ignore list, but that
  // call fails open — a rate limit, 404, or an unreachable raw HEAD ref returns null and
  // falls back to getDefaultConfig()'s EMPTY ignore. That is exactly how the portfolio
  // self-scan graded its own reports/ and test fixtures as criticals. A caller-supplied
  // baseline guarantees those paths never count, regardless of whether the fetch lands.
  if (cliOptions.extraIgnore?.length) {
    config = { ...config, ignore: [...(config.ignore || []), ...cliOptions.extraIgnore] };
  }

  const format = cliOptions.format || config.format;
  const ruleIds = cliOptions.rules?.length ? cliOptions.rules : config.rules;
  const excludeIds = cliOptions.exclude?.length ? cliOptions.exclude : config.exclude;
  const strict = cliOptions.strict ?? config.strict;
  const skipSca = cliOptions.skipSca ?? false;
  const deep = cliOptions.deep ?? false;

  // Resolve which rules to run.
  const rules = resolveRules(ruleIds, excludeIds);

  // Scan files and run rules — use custom file source or local discovery.
  const fileSource = cliOptions.fileSource || discoverFiles(targetDir, config.ignore);
  const { findings, filesScanned } = await runRules(fileSource, rules, deep, config);

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

  // Report.
  await report(findings, format, {
    filesScanned,
    rulesRun: rules.length,
    durationMs,
    targetDir,
  });

  // Exit code: 1 if criticals found, 1 if warnings + strict mode, 0 otherwise.
  const hasCritical = findings.some((f) => f.severity === 'critical');
  const hasWarning = findings.some((f) => f.severity === 'warning');
  const exitCode = hasCritical ? 1 : strict && hasWarning ? 1 : 0;

  return { findings, exitCode };
}
