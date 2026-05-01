import { fetchRepoFiles } from './github.js';
import { audit } from './index.js';
import { readFile } from 'node:fs/promises';

/**
 * Fetch all non-fork, non-archived repos for a GitHub org or user.
 * Paginates through all pages automatically.
 *
 * @param {string} org - GitHub org or user name
 * @param {{ token?: string, includeForks?: boolean, includeArchived?: boolean }} options
 * @returns {Promise<Array<{ owner: string, repo: string, fullName: string, defaultBranch: string, stars: number, pushedAt: string }>>}
 */
export async function fetchOrgRepos(org, { token, includeForks = false, includeArchived = false } = {}) {
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    // Try org endpoint first, fall back to user endpoint.
    let url = `https://api.github.com/orgs/${org}/repos?per_page=${perPage}&page=${page}&sort=pushed&direction=desc`;
    let res = await fetch(url, { headers });

    if (res.status === 404) {
      url = `https://api.github.com/users/${org}/repos?per_page=${perPage}&page=${page}&sort=pushed&direction=desc`;
      res = await fetch(url, { headers });
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API error fetching repos for "${org}" (${res.status}): ${body}`);
    }

    const data = await res.json();
    if (data.length === 0) break;

    for (const r of data) {
      if (!includeForks && r.fork) continue;
      if (!includeArchived && r.archived) continue;

      repos.push({
        owner: r.owner.login,
        repo: r.name,
        fullName: r.full_name,
        defaultBranch: r.default_branch,
        stars: r.stargazers_count,
        pushedAt: r.pushed_at,
      });
    }

    if (data.length < perPage) break;
    page++;
  }

  return repos;
}

/**
 * Load a repos list from a file (one owner/repo per line, # comments allowed).
 *
 * @param {string} filePath
 * @returns {Promise<Array<{ owner: string, repo: string }>>}
 */
export async function loadReposFile(filePath) {
  const raw = await readFile(filePath, 'utf-8');
  const repos = [];

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parts = trimmed.split('/');
    if (parts.length >= 2) {
      repos.push({ owner: parts[0], repo: parts[1] });
    }
  }

  return repos;
}

/**
 * Parse a comma-separated repos string (owner/repo,owner/repo,...).
 *
 * @param {string} reposStr
 * @returns {Array<{ owner: string, repo: string }>}
 */
export function parseReposList(reposStr) {
  return reposStr
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const [owner, repo] = s.split('/');
      return { owner, repo };
    })
    .filter((r) => r.owner && r.repo);
}

/**
 * Run a function with limited concurrency.
 *
 * @template T
 * @param {Array<() => Promise<T>>} tasks
 * @param {number} concurrency
 * @param {(completed: number, total: number, result: T) => void} [onProgress]
 * @returns {Promise<T[]>}
 */
async function pool(tasks, concurrency, onProgress) {
  const results = new Array(tasks.length);
  let next = 0;
  let completed = 0;

  async function worker() {
    while (next < tasks.length) {
      const idx = next++;
      results[idx] = await tasks[idx]();
      completed++;
      if (onProgress) onProgress(completed, tasks.length, results[idx]);
    }
  }

  const workers = [];
  for (let i = 0; i < Math.min(concurrency, tasks.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  return results;
}

/**
 * Scan multiple repos and return aggregated results.
 *
 * @param {Array<{ owner: string, repo: string }>} repos
 * @param {{ concurrency?: number, rules?: string[], exclude?: string[], onProgress?: Function }} options
 * @returns {Promise<import('./types.js').MultiRepoResult>}
 */
export async function scanMultipleRepos(repos, { concurrency = 5, rules, exclude, onProgress } = {}) {
  const start = performance.now();

  const tasks = repos.map(({ owner, repo }) => async () => {
    const label = `${owner}/${repo}`;
    const repoStart = performance.now();

    try {
      const fileSource = fetchRepoFiles(owner, repo);
      const { findings } = await audit(`github://${label}`, {
        format: 'json',
        fileSource,
        skipSca: true,
        rules,
        exclude,
      });

      const durationMs = Math.round(performance.now() - repoStart);

      const criticals = findings.filter((f) => f.severity === 'critical').length;
      const warnings = findings.filter((f) => f.severity === 'warning').length;
      const infos = findings.filter((f) => f.severity === 'info').length;
      const grade = criticals > 0 ? 'F' : warnings > 5 ? 'D' : warnings > 0 ? 'C' : infos > 0 ? 'B' : 'A';

      return {
        owner,
        repo,
        fullName: label,
        status: 'success',
        grade,
        findings,
        criticals,
        warnings,
        infos,
        total: findings.length,
        durationMs,
      };
    } catch (err) {
      return {
        owner,
        repo,
        fullName: label,
        status: 'error',
        error: err.message,
        grade: '?',
        findings: [],
        criticals: 0,
        warnings: 0,
        infos: 0,
        total: 0,
        durationMs: Math.round(performance.now() - repoStart),
      };
    }
  });

  // Suppress the per-repo reporter output during multi-repo scan.
  const origLog = console.log;
  console.log = () => {};

  let results;
  try {
    results = await pool(tasks, concurrency, (completed, total, result) => {
      if (onProgress) {
        origLog.call(console, onProgress(completed, total, result));
      }
    });
  } finally {
    console.log = origLog;
  }

  const totalDurationMs = Math.round(performance.now() - start);

  const succeeded = results.filter((r) => r.status === 'success');
  const failed = results.filter((r) => r.status === 'error');

  const allFindings = succeeded.flatMap((r) => r.findings);
  const totalCriticals = succeeded.reduce((s, r) => s + r.criticals, 0);
  const totalWarnings = succeeded.reduce((s, r) => s + r.warnings, 0);
  const totalInfos = succeeded.reduce((s, r) => s + r.infos, 0);

  const orgGrade =
    totalCriticals > 0 ? 'F' :
    totalWarnings > 10 ? 'D' :
    totalWarnings > 0 ? 'C' :
    totalInfos > 0 ? 'B' : 'A';

  return {
    orgGrade,
    repos: results,
    succeeded: succeeded.length,
    failed: failed.length,
    totalRepos: repos.length,
    totalFindings: allFindings.length,
    totalCriticals,
    totalWarnings,
    totalInfos,
    allFindings,
    durationMs: totalDurationMs,
  };
}
