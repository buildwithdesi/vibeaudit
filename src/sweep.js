import { audit } from './index.js';
import { parseGitHubTarget, fetchRepoFiles } from './github.js';
import { readFile } from 'node:fs/promises';

/**
 * Scan multiple GitHub repos in parallel with a concurrency limit.
 *
 * @param {Array<string | { repo: string, branch?: string }>} repos
 * @param {Object} options
 * @param {number}   [options.concurrency=5]
 * @param {string[]} [options.rules]
 * @param {string[]} [options.exclude]
 * @param {boolean}  [options.strict]
 * @param {(result: RepoResult) => void} [options.onResult]
 * @returns {Promise<SweepResult>}
 *
 * @typedef {{ name: string, grade: string, findings: import('./rules/types.js').Finding[], critical: number, warning: number, info: number, filesScanned: number, durationMs: number, error?: string }} RepoResult
 * @typedef {{ repos: RepoResult[], summary: { totalRepos: number, scanned: number, failed: number, totalFindings: number, totalCritical: number, totalWarning: number, totalInfo: number, durationMs: number } }} SweepResult
 */
export async function sweep(repos, options = {}) {
  const { concurrency = 5, rules, exclude, strict, onResult } = options;
  const start = performance.now();

  const normalized = repos.map((r) =>
    typeof r === 'string' ? { repo: r } : r
  );

  const results = [];
  let idx = 0;

  async function worker() {
    while (idx < normalized.length) {
      const item = normalized[idx++];
      const result = await scanOne(item, { rules, exclude, strict });
      results.push(result);
      if (onResult) onResult(result);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, normalized.length) }, () => worker());
  await Promise.all(workers);

  const durationMs = Math.round(performance.now() - start);

  const scanned = results.filter((r) => !r.error);
  const summary = {
    totalRepos: normalized.length,
    scanned: scanned.length,
    failed: results.length - scanned.length,
    totalFindings: scanned.reduce((s, r) => s + r.findings.length, 0),
    totalCritical: scanned.reduce((s, r) => s + r.critical, 0),
    totalWarning: scanned.reduce((s, r) => s + r.warning, 0),
    totalInfo: scanned.reduce((s, r) => s + r.info, 0),
    durationMs,
  };

  results.sort((a, b) => b.critical - a.critical || b.warning - a.warning);

  return { repos: results, summary };
}

function gradeFor(criticals, warnings, infos) {
  if (criticals > 0) return 'F';
  if (warnings > 5) return 'D';
  if (warnings > 0) return 'C';
  if (infos > 0) return 'B';
  return 'A';
}

async function scanOne(item, { rules, exclude, strict }) {
  const gh = parseGitHubTarget(item.repo);
  if (!gh) {
    return {
      name: item.repo,
      grade: '?',
      findings: [],
      critical: 0,
      warning: 0,
      info: 0,
      filesScanned: 0,
      durationMs: 0,
      error: `Not a valid GitHub repo: ${item.repo}`,
    };
  }

  const name = `${gh.owner}/${gh.repo}`;
  const repoStart = performance.now();

  try {
    const fileSource = fetchRepoFiles(gh.owner, gh.repo, { branch: item.branch || 'HEAD' });
    const { findings } = await audit(`github://${name}`, {
      format: 'json',
      rules,
      exclude,
      strict,
      skipSca: true,
      fileSource,
      _silent: true,
    });

    const critical = findings.filter((f) => f.severity === 'critical').length;
    const warning = findings.filter((f) => f.severity === 'warning').length;
    const info = findings.filter((f) => f.severity === 'info').length;
    const durationMs = Math.round(performance.now() - repoStart);

    return {
      name,
      grade: gradeFor(critical, warning, info),
      findings,
      critical,
      warning,
      info,
      filesScanned: 0,
      durationMs,
    };
  } catch (err) {
    return {
      name,
      grade: '?',
      findings: [],
      critical: 0,
      warning: 0,
      info: 0,
      filesScanned: 0,
      durationMs: Math.round(performance.now() - repoStart),
      error: err.message,
    };
  }
}

/**
 * Load a repos list from a JSON file.
 * Supports:
 *   - string[] of "owner/repo"
 *   - { repos: string[] }
 *   - { repos: [{ repo: string, branch?: string }] }
 *
 * @param {string} filePath
 * @returns {Promise<Array<string | { repo: string, branch?: string }>>}
 */
export async function loadRepoList(filePath) {
  const raw = await readFile(filePath, 'utf-8');
  const data = JSON.parse(raw);

  if (Array.isArray(data)) return data;
  if (data.repos && Array.isArray(data.repos)) return data.repos;

  throw new Error(`Invalid repos file: expected an array or { repos: [...] }`);
}
