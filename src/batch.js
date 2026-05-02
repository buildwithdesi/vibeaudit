import { audit } from './index.js';
import { fetchRepoFiles, parseGitHubTarget } from './github.js';

const GITHUB_API = 'https://api.github.com';

function githubHeaders() {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit-batch',
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function apiFetch(url) {
  const res = await fetch(url, { headers: githubHeaders() });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`GitHub API ${res.status}: ${body}`);
  }
  return res.json();
}

/**
 * Fetch all non-fork, non-archived repos for a GitHub org or user.
 * Paginates automatically (100 per page).
 */
export async function fetchOrgRepos(orgOrUser) {
  const repos = [];
  let page = 1;

  while (true) {
    let data;
    try {
      data = await apiFetch(`${GITHUB_API}/orgs/${orgOrUser}/repos?per_page=100&page=${page}&sort=updated`);
    } catch {
      data = await apiFetch(`${GITHUB_API}/users/${orgOrUser}/repos?per_page=100&page=${page}&sort=updated`);
    }

    if (!data.length) break;

    for (const r of data) {
      if (r.archived || r.fork || r.disabled) continue;
      repos.push({ owner: r.owner.login, repo: r.name, defaultBranch: r.default_branch });
    }

    if (data.length < 100) break;
    page++;
  }

  return repos;
}

/**
 * Parse a repos-file: one repo per line, supports owner/repo or full GitHub URLs.
 * Lines starting with # are comments. Blank lines are skipped.
 */
export function parseReposList(content) {
  const repos = [];
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    const gh = parseGitHubTarget(line);
    if (gh) {
      repos.push({ owner: gh.owner, repo: gh.repo });
    }
  }
  return repos;
}

/**
 * Scan a single repo and return a result summary.
 */
async function scanRepo({ owner, repo }, options = {}) {
  const label = `${owner}/${repo}`;
  const start = performance.now();

  try {
    const fileSource = fetchRepoFiles(owner, repo);
    const { findings } = await audit(`github://${label}`, {
      format: 'json',
      skipSca: true,
      fileSource,
      rules: options.rules,
      exclude: options.exclude,
      deep: options.deep,
      _silent: true,
    });

    const durationMs = Math.round(performance.now() - start);
    const criticals = findings.filter((f) => f.severity === 'critical');
    const warnings = findings.filter((f) => f.severity === 'warning');
    const infos = findings.filter((f) => f.severity === 'info');

    const grade = criticals.length > 0 ? 'F' : warnings.length > 5 ? 'D' : warnings.length > 0 ? 'C' : infos.length > 0 ? 'B' : 'A';

    return {
      repo: label,
      grade,
      critical: criticals.length,
      warning: warnings.length,
      info: infos.length,
      total: findings.length,
      findings,
      durationMs,
      error: null,
    };
  } catch (err) {
    return {
      repo: label,
      grade: '?',
      critical: 0,
      warning: 0,
      info: 0,
      total: 0,
      findings: [],
      durationMs: Math.round(performance.now() - start),
      error: err.message,
    };
  }
}

/**
 * Run batch scan across multiple repos.
 *
 * @param {{ owner: string, repo: string }[]} repos
 * @param {{ concurrency?: number, rules?: string[], exclude?: string[], deep?: boolean, onProgress?: (result, index, total) => void }} options
 * @returns {Promise<import('./reporters/batch-summary.js').BatchResult[]>}
 */
export async function batchScan(repos, options = {}) {
  const concurrency = options.concurrency || 5;
  const results = [];
  let completed = 0;

  const queue = [...repos];
  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    while (queue.length > 0) {
      const repoInfo = queue.shift();
      const result = await scanRepo(repoInfo, options);
      results.push(result);
      completed++;
      if (options.onProgress) {
        options.onProgress(result, completed, repos.length);
      }
    }
  });

  await Promise.all(workers);

  results.sort((a, b) => {
    const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
    return (gradeOrder[a.grade] ?? 5) - (gradeOrder[b.grade] ?? 5);
  });

  return results;
}
