import { audit } from './index.js';
import { fetchRepoFiles, parseGitHubTarget } from './github.js';

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
 * @typedef {Object} BatchOptions
 * @property {number} [concurrency=4]
 * @property {string[]} [rules]
 * @property {string[]} [exclude]
 * @property {boolean} [strict]
 * @property {(event: {type: string, repo: string, result?: RepoResult, error?: string, done: number, total: number}) => void} [onProgress]
 */

function gradeFromFindings(findings) {
  const c = findings.filter(f => f.severity === 'critical').length;
  const w = findings.filter(f => f.severity === 'warning').length;
  const i = findings.filter(f => f.severity === 'info').length;
  if (c > 0) return 'F';
  if (w > 5) return 'D';
  if (w > 0) return 'C';
  if (i > 0) return 'B';
  return 'A';
}

/**
 * Scan a single GitHub repo and return a structured result.
 */
async function scanOneRepo(repoSpec, options = {}) {
  const start = performance.now();
  const gh = parseGitHubTarget(repoSpec);
  if (!gh) {
    return {
      repo: repoSpec,
      grade: '-',
      critical: 0, warning: 0, info: 0, total: 0,
      filesScanned: 0, durationMs: 0, findings: [],
      error: `Invalid repo: ${repoSpec}`,
    };
  }

  const label = `${gh.owner}/${gh.repo}`;

  try {
    const fileSource = fetchRepoFiles(gh.owner, gh.repo);
    const { findings } = await audit(`github://${label}`, {
      format: 'silent',
      fileSource,
      skipSca: true,
      rules: options.rules,
      exclude: options.exclude,
      strict: options.strict,
    });

    const critical = findings.filter(f => f.severity === 'critical').length;
    const warning = findings.filter(f => f.severity === 'warning').length;
    const info = findings.filter(f => f.severity === 'info').length;
    const durationMs = Math.round(performance.now() - start);

    return {
      repo: label,
      grade: gradeFromFindings(findings),
      critical, warning, info,
      total: findings.length,
      filesScanned: findings.length > 0 ? new Set(findings.map(f => f.file)).size : 0,
      durationMs,
      findings,
      error: null,
    };
  } catch (err) {
    return {
      repo: label,
      grade: '-',
      critical: 0, warning: 0, info: 0, total: 0,
      filesScanned: 0,
      durationMs: Math.round(performance.now() - start),
      findings: [],
      error: err.message,
    };
  }
}

/**
 * Run vibe-audit across multiple repos with concurrency control.
 *
 * @param {string[]} repos - List of "owner/repo" or GitHub URLs
 * @param {BatchOptions} [options]
 * @returns {Promise<RepoResult[]>}
 */
export async function batchScan(repos, options = {}) {
  const { concurrency = 4, onProgress } = options;
  const results = [];
  let done = 0;
  const total = repos.length;

  // Process in batches of `concurrency`
  for (let i = 0; i < repos.length; i += concurrency) {
    const chunk = repos.slice(i, i + concurrency);
    const chunkResults = await Promise.all(
      chunk.map(async (repo) => {
        if (onProgress) {
          onProgress({ type: 'start', repo, done, total });
        }
        const result = await scanOneRepo(repo, options);
        done++;
        if (onProgress) {
          onProgress({
            type: result.error ? 'error' : 'done',
            repo,
            result,
            error: result.error,
            done,
            total,
          });
        }
        return result;
      })
    );
    results.push(...chunkResults);
  }

  // Sort: worst grade first (F, D, C, B, A), then by critical count desc
  const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4, '-': 5 };
  results.sort((a, b) => {
    const gd = gradeOrder[a.grade] - gradeOrder[b.grade];
    if (gd !== 0) return gd;
    return b.critical - a.critical;
  });

  return results;
}

/**
 * Build aggregate stats from batch results.
 */
export function aggregateResults(results) {
  const successful = results.filter(r => !r.error);
  const failed = results.filter(r => r.error);

  let totalCritical = 0, totalWarning = 0, totalInfo = 0, totalFindings = 0;
  const gradeCounts = { A: 0, B: 0, C: 0, D: 0, F: 0 };

  for (const r of successful) {
    totalCritical += r.critical;
    totalWarning += r.warning;
    totalInfo += r.info;
    totalFindings += r.total;
    if (gradeCounts[r.grade] !== undefined) gradeCounts[r.grade]++;
  }

  // Top recurring rules across all repos
  const ruleCounts = new Map();
  for (const r of successful) {
    for (const f of r.findings) {
      ruleCounts.set(f.ruleId, (ruleCounts.get(f.ruleId) || 0) + 1);
    }
  }
  const topRules = [...ruleCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  return {
    reposScanned: successful.length,
    reposFailed: failed.length,
    totalCritical,
    totalWarning,
    totalInfo,
    totalFindings,
    gradeCounts,
    topRules,
  };
}
