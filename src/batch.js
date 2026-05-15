import { audit } from './index.js';
import { fetchRepoFiles, parseGitHubTarget } from './github.js';
import { readFile } from 'node:fs/promises';

/**
 * @typedef {Object} BatchConfig
 * @property {string[]} repos - List of "owner/repo" or GitHub URLs
 * @property {number} [concurrency] - Max parallel scans (default 5)
 * @property {string[]} [rules] - Only run these rule IDs
 * @property {string[]} [exclude] - Exclude these rule IDs
 * @property {boolean} [strict] - Fail on warnings too
 */

/**
 * @typedef {Object} RepoResult
 * @property {string} repo - "owner/repo"
 * @property {string} grade
 * @property {number} critical
 * @property {number} warning
 * @property {number} info
 * @property {number} total
 * @property {number} filesScanned
 * @property {number} durationMs
 * @property {import('./rules/types.js').Finding[]} findings
 * @property {string|null} error
 */

/**
 * Load batch config from a JSON file.
 * @param {string} configPath
 * @returns {Promise<BatchConfig>}
 */
export async function loadBatchConfig(configPath) {
  const raw = await readFile(configPath, 'utf-8');
  const parsed = JSON.parse(raw);

  if (!Array.isArray(parsed.repos) || parsed.repos.length === 0) {
    throw new Error('Batch config must contain a non-empty "repos" array');
  }

  return {
    repos: parsed.repos,
    concurrency: parsed.concurrency ?? 5,
    rules: parsed.rules ?? [],
    exclude: parsed.exclude ?? [],
    strict: parsed.strict ?? false,
  };
}

function gradeFromFindings(findings) {
  const criticals = findings.filter((f) => f.severity === 'critical').length;
  const warnings = findings.filter((f) => f.severity === 'warning').length;
  const infos = findings.filter((f) => f.severity === 'info').length;
  if (criticals > 0) return 'F';
  if (warnings > 5) return 'D';
  if (warnings > 0) return 'C';
  if (infos > 0) return 'B';
  return 'A';
}

/**
 * Scan a single repo via the GitHub API.
 * @param {string} repoSpec
 * @param {{ rules?: string[], exclude?: string[], strict?: boolean }} options
 * @returns {Promise<RepoResult>}
 */
async function scanOneRepo(repoSpec, options) {
  const start = performance.now();
  const gh = parseGitHubTarget(repoSpec);
  if (!gh) {
    return {
      repo: repoSpec,
      grade: '-',
      critical: 0,
      warning: 0,
      info: 0,
      total: 0,
      filesScanned: 0,
      durationMs: 0,
      findings: [],
      error: `Invalid repo identifier: ${repoSpec}`,
    };
  }

  const label = `${gh.owner}/${gh.repo}`;

  try {
    const result = await audit(`github://${label}`, {
      format: 'json',
      fileSource: fetchRepoFiles(gh.owner, gh.repo),
      skipSca: true,
      silent: true,
      rules: options.rules?.length ? options.rules : undefined,
      exclude: options.exclude?.length ? options.exclude : undefined,
      strict: options.strict,
    });

    const { findings, filesScanned, durationMs } = result;
    const critical = findings.filter((f) => f.severity === 'critical').length;
    const warning = findings.filter((f) => f.severity === 'warning').length;
    const info = findings.filter((f) => f.severity === 'info').length;

    return {
      repo: label,
      grade: gradeFromFindings(findings),
      critical,
      warning,
      info,
      total: findings.length,
      filesScanned,
      durationMs,
      findings,
      error: null,
    };
  } catch (err) {
    const durationMs = Math.round(performance.now() - start);
    return {
      repo: label,
      grade: '-',
      critical: 0,
      warning: 0,
      info: 0,
      total: 0,
      filesScanned: 0,
      durationMs,
      findings: [],
      error: err.message,
    };
  }
}

/**
 * Run batch scan across multiple repos with concurrency control.
 * @param {BatchConfig} config
 * @param {(status: { repo: string, done: number, total: number, result?: RepoResult }) => void} [onProgress]
 * @returns {Promise<RepoResult[]>}
 */
export async function batchScan(config, onProgress) {
  const { repos, concurrency, rules, exclude, strict } = config;
  const results = [];
  let done = 0;
  const total = repos.length;

  // Process repos in chunks for concurrency control.
  for (let i = 0; i < repos.length; i += concurrency) {
    const chunk = repos.slice(i, i + concurrency);
    const chunkResults = await Promise.all(
      chunk.map(async (repoSpec) => {
        if (onProgress) onProgress({ repo: repoSpec, done, total });
        const result = await scanOneRepo(repoSpec, { rules, exclude, strict });
        done++;
        if (onProgress) onProgress({ repo: repoSpec, done, total, result });
        return result;
      })
    );
    results.push(...chunkResults);
  }

  // Sort: worst grades first (F, D, C, B, A), then by total findings desc.
  const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4, '-': 5 };
  results.sort((a, b) => {
    const g = gradeOrder[a.grade] - gradeOrder[b.grade];
    if (g !== 0) return g;
    return b.total - a.total;
  });

  return results;
}

/**
 * Print batch results to terminal.
 * @param {RepoResult[]} results
 * @param {number} totalDurationMs
 */
export function reportBatchTerminal(results, totalDurationMs) {
  const totalRepos = results.length;
  const failed = results.filter((r) => r.error).length;
  const totalFindings = results.reduce((s, r) => s + r.total, 0);
  const totalCritical = results.reduce((s, r) => s + r.critical, 0);
  const totalWarning = results.reduce((s, r) => s + r.warning, 0);

  console.log('');
  console.log('  \x1b[1m⚗️  VIBE AUDIT — BATCH SCAN\x1b[0m');
  console.log('  \x1b[2m─────────────────────────────────────────────────────────────\x1b[0m');
  console.log('');
  console.log(`  \x1b[1m${totalRepos}\x1b[0m repos scanned  ·  \x1b[31m\x1b[1m${totalCritical}\x1b[0m critical  ·  \x1b[33m${totalWarning}\x1b[0m warnings  ·  ${totalFindings} total findings`);
  if (failed > 0) console.log(`  \x1b[31m${failed} repo(s) failed to scan\x1b[0m`);
  console.log(`  \x1b[2mCompleted in ${(totalDurationMs / 1000).toFixed(1)}s\x1b[0m`);
  console.log('');

  // Table header
  console.log('  \x1b[2mGRADE  REPO                                      CRIT   WARN   INFO  TOTAL  TIME\x1b[0m');
  console.log('  \x1b[2m─────  ────────────────────────────────────────  ─────  ─────  ────  ─────  ────\x1b[0m');

  for (const r of results) {
    if (r.error) {
      console.log(`  \x1b[2m  -  \x1b[0m  ${r.repo.padEnd(40)}  \x1b[31mERROR: ${r.error.slice(0, 50)}\x1b[0m`);
      continue;
    }

    const gradeColors = { A: '\x1b[32m', B: '\x1b[32m', C: '\x1b[33m', D: '\x1b[33m', F: '\x1b[31m' };
    const gc = gradeColors[r.grade] || '';
    const critStr = r.critical > 0 ? `\x1b[31m\x1b[1m${String(r.critical).padStart(5)}\x1b[0m` : '    0';
    const warnStr = r.warning > 0 ? `\x1b[33m${String(r.warning).padStart(5)}\x1b[0m` : '    0';
    const infoStr = String(r.info).padStart(4);
    const totalStr = String(r.total).padStart(5);
    const timeStr = `${(r.durationMs / 1000).toFixed(1)}s`;

    console.log(`  ${gc}\x1b[1m  ${r.grade}  \x1b[0m  ${r.repo.padEnd(40)}  ${critStr}  ${warnStr}  ${infoStr}  ${totalStr}  \x1b[2m${timeStr}\x1b[0m`);
  }

  console.log('');

  if (totalCritical > 0) {
    console.log('  \x1b[31m\x1b[1m⛔ Critical issues found across repos. Review immediately.\x1b[0m');
  } else if (totalWarning > 0) {
    console.log('  \x1b[33m\x1b[1m⚠️  Warnings found. Review before deploying.\x1b[0m');
  } else {
    console.log('  \x1b[32m\x1b[1m✅ All repos clean.\x1b[0m');
  }
  console.log('');
}

/**
 * Return batch results as JSON string.
 * @param {RepoResult[]} results
 * @param {number} totalDurationMs
 * @returns {string}
 */
export function reportBatchJSON(results, totalDurationMs) {
  const summary = {
    totalRepos: results.length,
    scanned: results.filter((r) => !r.error).length,
    failed: results.filter((r) => r.error).length,
    totalFindings: results.reduce((s, r) => s + r.total, 0),
    totalCritical: results.reduce((s, r) => s + r.critical, 0),
    totalWarning: results.reduce((s, r) => s + r.warning, 0),
    totalInfo: results.reduce((s, r) => s + r.info, 0),
    durationMs: totalDurationMs,
    timestamp: new Date().toISOString(),
  };

  const repos = results.map((r) => ({
    repo: r.repo,
    grade: r.grade,
    critical: r.critical,
    warning: r.warning,
    info: r.info,
    total: r.total,
    durationMs: r.durationMs,
    error: r.error,
    findings: r.findings.map((f) => ({
      ruleId: f.ruleId,
      severity: f.severity,
      file: f.file,
      line: f.line,
      message: f.message,
      cweId: f.cweId,
      cvssScore: f.cvssScore,
      owaspCategory: f.owaspCategory,
    })),
  }));

  return JSON.stringify({ summary, repos }, null, 2);
}
