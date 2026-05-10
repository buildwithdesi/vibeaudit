import { audit } from './index.js';
import { fetchRepoFiles, parseGitHubTarget } from './github.js';
import { readFile } from 'node:fs/promises';

/**
 * Fetch all non-fork, non-archived repos for a GitHub org or user.
 * Pages through the API (100 per page).
 *
 * @param {string} orgOrUser
 * @returns {Promise<string[]>} Array of "owner/repo" strings
 */
export async function discoverOrgRepos(orgOrUser) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;

  while (true) {
    // Try org endpoint first, fall back to user endpoint.
    let url = `https://api.github.com/orgs/${orgOrUser}/repos?per_page=100&page=${page}&type=sources`;
    let res = await fetch(url, { headers });

    if (res.status === 404 && page === 1) {
      url = `https://api.github.com/users/${orgOrUser}/repos?per_page=100&page=${page}&type=sources`;
      res = await fetch(url, { headers });
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API error fetching repos for ${orgOrUser} (${res.status}): ${body}`);
    }

    const data = await res.json();
    if (data.length === 0) break;

    for (const repo of data) {
      if (repo.archived || repo.fork || repo.disabled) continue;
      repos.push(`${repo.owner.login}/${repo.name}`);
    }

    if (data.length < 100) break;
    page++;
  }

  return repos;
}

/**
 * Load a repo list from a file.
 * Supports JSON array or newline-separated text.
 *
 * @param {string} filePath
 * @returns {Promise<string[]>}
 */
export async function loadRepoList(filePath) {
  const raw = await readFile(filePath, 'utf-8');
  const trimmed = raw.trim();

  if (trimmed.startsWith('[')) {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) throw new Error('repos file must contain a JSON array of "owner/repo" strings');
    return parsed.filter((r) => typeof r === 'string' && r.includes('/'));
  }

  return trimmed
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
}

/**
 * Run a function with limited concurrency.
 *
 * @template T
 * @param {Array<() => Promise<T>>} tasks
 * @param {number} limit
 * @returns {Promise<T[]>}
 */
async function pooled(tasks, limit) {
  const results = new Array(tasks.length);
  let next = 0;

  async function worker() {
    while (next < tasks.length) {
      const idx = next++;
      results[idx] = await tasks[idx]();
    }
  }

  const workers = [];
  for (let i = 0; i < Math.min(limit, tasks.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);
  return results;
}

/**
 * @typedef {Object} RepoResult
 * @property {string} repo - "owner/repo"
 * @property {import('./rules/types.js').Finding[]} findings
 * @property {number} filesScanned
 * @property {number} durationMs
 * @property {string|null} error
 */

/**
 * Scan multiple GitHub repos concurrently.
 *
 * @param {string[]} repos - Array of "owner/repo" strings
 * @param {Object} options
 * @param {number} [options.concurrency=5]
 * @param {string[]} [options.rules]
 * @param {string[]} [options.exclude]
 * @param {boolean} [options.strict]
 * @param {(result: RepoResult, index: number, total: number) => void} [options.onRepoComplete]
 * @returns {Promise<RepoResult[]>}
 */
export async function scanRepos(repos, options = {}) {
  const { concurrency = 5, rules, exclude, strict, onRepoComplete } = options;

  const tasks = repos.map((repoStr, idx) => async () => {
    const start = performance.now();
    const gh = parseGitHubTarget(repoStr);

    if (!gh) {
      const result = { repo: repoStr, findings: [], filesScanned: 0, durationMs: 0, error: `Invalid repo format: ${repoStr}` };
      if (onRepoComplete) onRepoComplete(result, idx, repos.length);
      return result;
    }

    try {
      const fileSource = fetchRepoFiles(gh.owner, gh.repo, {
        onRateLimit: async ({ remaining, reset }) => {
          if (remaining < 100 && reset) {
            const waitMs = Math.max(0, (reset * 1000) - Date.now() + 1000);
            if (waitMs > 0 && waitMs < 900_000) {
              await new Promise((r) => setTimeout(r, waitMs));
            }
          }
        },
      });
      const { findings, filesScanned } = await audit(`github://${gh.owner}/${gh.repo}`, {
        format: 'json',
        rules,
        exclude,
        strict,
        fileSource,
        skipSca: true,
        _silent: true,
      });

      const durationMs = Math.round(performance.now() - start);
      const result = { repo: `${gh.owner}/${gh.repo}`, findings, filesScanned, durationMs, error: null };
      if (onRepoComplete) onRepoComplete(result, idx, repos.length);
      return result;
    } catch (err) {
      const durationMs = Math.round(performance.now() - start);
      const result = { repo: `${gh.owner}/${gh.repo}`, findings: [], filesScanned: 0, durationMs, error: err.message };
      if (onRepoComplete) onRepoComplete(result, idx, repos.length);
      return result;
    }
  });

  return pooled(tasks, concurrency);
}
