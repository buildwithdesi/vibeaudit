import { audit } from './index.js';
import { fetchRepoFiles } from './github.js';

const DEFAULT_CONCURRENCY = 5;

/**
 * Fetch all non-fork, non-archived repos for a GitHub org or user.
 * Handles pagination (100 per page).
 *
 * @param {string} orgOrUser
 * @param {{ token?: string, includeArchived?: boolean, includeForks?: boolean }} opts
 * @returns {Promise<Array<{ owner: string, repo: string, description: string, language: string, pushedAt: string, defaultBranch: string }>>}
 */
export async function fetchOrgRepos(orgOrUser, opts = {}) {
  const token = opts.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;

  while (true) {
    // Try org endpoint first, fall back to user endpoint.
    let url = `https://api.github.com/orgs/${orgOrUser}/repos?per_page=100&sort=pushed&page=${page}`;
    let res = await fetch(url, { headers });

    if (res.status === 404 && page === 1) {
      url = `https://api.github.com/users/${orgOrUser}/repos?per_page=100&sort=pushed&page=${page}`;
      res = await fetch(url, { headers });
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API error (${res.status}): ${body}`);
    }

    const data = await res.json();
    if (data.length === 0) break;

    for (const r of data) {
      if (!opts.includeArchived && r.archived) continue;
      if (!opts.includeForks && r.fork) continue;

      repos.push({
        owner: r.owner.login,
        repo: r.name,
        description: r.description || '',
        language: r.language || 'Unknown',
        pushedAt: r.pushed_at,
        defaultBranch: r.default_branch || 'main',
      });
    }

    page++;
  }

  return repos;
}

/**
 * Run audit across multiple repos with concurrency control.
 *
 * @param {Array<{ owner: string, repo: string }>} repos
 * @param {{ concurrency?: number, onProgress?: (result: object) => void, rules?: string[], exclude?: string[] }} opts
 * @returns {Promise<Array<{ owner: string, repo: string, findings: object[], filesScanned: number, rulesRun: number, durationMs: number, grade: string, error?: string }>>}
 */
export async function scanMultipleRepos(repos, opts = {}) {
  const concurrency = opts.concurrency || DEFAULT_CONCURRENCY;
  const results = [];
  let completed = 0;

  async function scanOne(repoInfo) {
    const label = `${repoInfo.owner}/${repoInfo.repo}`;
    const start = performance.now();

    try {
      const fileSource = fetchRepoFiles(repoInfo.owner, repoInfo.repo);
      const { findings, exitCode, filesScanned, rulesRun } = await audit(`github://${label}`, {
        format: 'json',
        fileSource,
        skipSca: true,
        quiet: true,
        rules: opts.rules,
        exclude: opts.exclude,
      });

      const durationMs = Math.round(performance.now() - start);
      const criticals = findings.filter((f) => f.severity === 'critical').length;
      const warnings = findings.filter((f) => f.severity === 'warning').length;
      const infos = findings.filter((f) => f.severity === 'info').length;

      const grade =
        criticals > 0 ? 'F' : warnings > 5 ? 'D' : warnings > 0 ? 'C' : infos > 0 ? 'B' : 'A';

      const result = {
        owner: repoInfo.owner,
        repo: repoInfo.repo,
        description: repoInfo.description || '',
        language: repoInfo.language || '',
        findings,
        filesScanned: filesScanned || 0,
        rulesRun: rulesRun || 0,
        durationMs,
        grade,
        exitCode,
        criticals,
        warnings,
        infos,
        total: findings.length,
      };

      completed++;
      if (opts.onProgress) opts.onProgress({ ...result, completed, total: repos.length });
      return result;
    } catch (err) {
      const durationMs = Math.round(performance.now() - start);
      completed++;
      const result = {
        owner: repoInfo.owner,
        repo: repoInfo.repo,
        description: repoInfo.description || '',
        language: repoInfo.language || '',
        findings: [],
        filesScanned: 0,
        rulesRun: 0,
        durationMs,
        grade: '?',
        exitCode: 2,
        criticals: 0,
        warnings: 0,
        infos: 0,
        total: 0,
        error: err.message,
      };
      if (opts.onProgress) opts.onProgress({ ...result, completed, total: repos.length });
      return result;
    }
  }

  // Run with concurrency pool
  const queue = [...repos];
  const running = new Set();

  while (queue.length > 0 || running.size > 0) {
    while (running.size < concurrency && queue.length > 0) {
      const repo = queue.shift();
      const promise = scanOne(repo).then((result) => {
        results.push(result);
        running.delete(promise);
      });
      running.add(promise);
    }
    if (running.size > 0) {
      await Promise.race(running);
    }
  }

  // Sort: worst grade first
  const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
  results.sort((a, b) => (gradeOrder[a.grade] ?? 5) - (gradeOrder[b.grade] ?? 5));

  return results;
}
