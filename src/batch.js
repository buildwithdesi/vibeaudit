import { audit } from './index.js';
import { fetchRepoFiles, parseGitHubTarget } from './github.js';

/**
 * Fetch all non-fork, non-archived repos in a GitHub org (or user account).
 *
 * @param {string} org - GitHub org or username
 * @returns {Promise<Array<{ owner: string, repo: string }>>}
 */
export async function fetchOrgRepos(org) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;

  while (true) {
    const url = `https://api.github.com/orgs/${org}/repos?per_page=100&page=${page}&type=sources`;
    let res = await fetch(url, { headers });

    // Fall back to user endpoint if org endpoint 404s.
    if (res.status === 404 && page === 1) {
      const userUrl = `https://api.github.com/users/${org}/repos?per_page=100&page=${page}&type=owner`;
      res = await fetch(userUrl, { headers });
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API error fetching repos for ${org} (${res.status}): ${body}`);
    }

    const data = await res.json();
    if (data.length === 0) break;

    for (const r of data) {
      if (r.archived || r.fork || r.disabled) continue;
      repos.push({ owner: r.owner.login, repo: r.name });
    }

    if (data.length < 100) break;
    page++;
  }

  return repos;
}

/**
 * Load a repos list from a JSON file.
 * Supports formats:
 *   - Array of "owner/repo" strings
 *   - Array of { owner, repo } objects
 *   - Object with { repos: [...] }
 *
 * @param {string} filePath
 * @returns {Promise<Array<{ owner: string, repo: string }>>}
 */
export async function loadReposList(filePath) {
  const { readFile } = await import('node:fs/promises');
  const raw = await readFile(filePath, 'utf-8');
  const data = JSON.parse(raw);

  const list = Array.isArray(data) ? data : data.repos;
  if (!Array.isArray(list)) {
    throw new Error(`Invalid repos file: expected an array or { repos: [...] }`);
  }

  return list.map((entry) => {
    if (typeof entry === 'string') {
      const parsed = parseGitHubTarget(entry);
      if (!parsed) throw new Error(`Invalid repo reference: ${entry}`);
      return parsed;
    }
    if (entry.owner && entry.repo) return { owner: entry.owner, repo: entry.repo };
    throw new Error(`Invalid repo entry: ${JSON.stringify(entry)}`);
  });
}

/**
 * Scan a single repo and return its results without printing.
 *
 * @param {{ owner: string, repo: string }} repo
 * @param {Object} options
 * @returns {Promise<import('./reporters/batch.js').RepoResult>}
 */
async function scanOne({ owner, repo }, options) {
  const label = `${owner}/${repo}`;
  const start = performance.now();

  try {
    const { findings, exitCode } = await audit(`github://${label}`, {
      format: 'json',
      fileSource: fetchRepoFiles(owner, repo),
      skipSca: true,
      rules: options.rules,
      exclude: options.exclude,
      deep: options.deep,
      // Suppress reporting — we'll aggregate ourselves.
      _silent: true,
    });

    const durationMs = Math.round(performance.now() - start);

    return {
      owner,
      repo,
      label,
      status: 'ok',
      findings,
      exitCode,
      criticals: findings.filter((f) => f.severity === 'critical').length,
      warnings: findings.filter((f) => f.severity === 'warning').length,
      infos: findings.filter((f) => f.severity === 'info').length,
      durationMs,
    };
  } catch (err) {
    return {
      owner,
      repo,
      label,
      status: 'error',
      error: err.message,
      findings: [],
      exitCode: 2,
      criticals: 0,
      warnings: 0,
      infos: 0,
      durationMs: Math.round(performance.now() - start),
    };
  }
}

/**
 * Scan multiple repos with concurrency control.
 *
 * @param {Array<{ owner: string, repo: string }>} repos
 * @param {Object} options
 * @param {number} [options.concurrency=5]
 * @param {string[]} [options.rules]
 * @param {string[]} [options.exclude]
 * @param {boolean} [options.deep]
 * @param {(result: import('./reporters/batch.js').RepoResult, index: number, total: number) => void} [options.onProgress]
 * @returns {Promise<Array<import('./reporters/batch.js').RepoResult>>}
 */
export async function scanRepos(repos, options = {}) {
  const concurrency = options.concurrency || 5;
  const results = [];
  let completed = 0;

  // Process repos in chunks for concurrency control.
  for (let i = 0; i < repos.length; i += concurrency) {
    const chunk = repos.slice(i, i + concurrency);

    const chunkResults = await Promise.all(
      chunk.map((repo) => scanOne(repo, options))
    );

    for (const result of chunkResults) {
      completed++;
      results.push(result);
      if (options.onProgress) {
        options.onProgress(result, completed, repos.length);
      }
    }
  }

  // Sort: repos with criticals first, then by total findings descending.
  results.sort((a, b) => {
    if (a.criticals !== b.criticals) return b.criticals - a.criticals;
    if (a.warnings !== b.warnings) return b.warnings - a.warnings;
    return b.infos - a.infos;
  });

  return results;
}
