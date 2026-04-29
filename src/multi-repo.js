import { audit } from './index.js';
import { fetchRepoFiles } from './github.js';

/**
 * Fetch all non-archived, non-fork repos for a GitHub org or user.
 * Paginates automatically. Requires GITHUB_TOKEN for private repos.
 *
 * @param {string} orgOrUser
 * @param {{ type?: 'org' | 'user', topic?: string }} options
 * @returns {Promise<{ owner: string, repo: string }[]>}
 */
export async function listOrgRepos(orgOrUser, { type = 'org', topic } = {}) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    const endpoint = type === 'org'
      ? `https://api.github.com/orgs/${orgOrUser}/repos`
      : `https://api.github.com/users/${orgOrUser}/repos`;

    const url = `${endpoint}?per_page=${perPage}&page=${page}&sort=pushed&direction=desc`;
    const res = await fetch(url, { headers });

    if (!res.ok) {
      if (res.status === 404 && type === 'org') {
        return listOrgRepos(orgOrUser, { type: 'user', topic });
      }
      const body = await res.text();
      throw new Error(`GitHub API error listing repos (${res.status}): ${body}`);
    }

    const batch = await res.json();
    if (batch.length === 0) break;

    for (const r of batch) {
      if (r.archived) continue;
      if (r.fork) continue;
      if (topic && !(r.topics || []).includes(topic)) continue;
      repos.push({ owner: r.owner.login, repo: r.name });
    }

    if (batch.length < perPage) break;
    page++;
  }

  return repos;
}

/**
 * Scan a single repo and return structured results.
 *
 * @param {{ owner: string, repo: string }} target
 * @param {object} options
 * @returns {Promise<RepoResult>}
 */
async function scanOneRepo({ owner, repo }, options = {}) {
  const label = `${owner}/${repo}`;
  const start = performance.now();

  try {
    const fileSource = fetchRepoFiles(owner, repo);
    const { findings } = await audit(`github://${label}`, {
      format: 'json',
      skipSca: true,
      quiet: true,
      fileSource,
      ...options,
    });

    const durationMs = Math.round(performance.now() - start);
    const criticals = findings.filter(f => f.severity === 'critical').length;
    const warnings = findings.filter(f => f.severity === 'warning').length;
    const infos = findings.filter(f => f.severity === 'info').length;

    const grade = criticals > 0 ? 'F' : warnings > 5 ? 'D' : warnings > 0 ? 'C' : infos > 0 ? 'B' : 'A';

    return {
      owner,
      repo,
      label,
      grade,
      criticals,
      warnings,
      infos,
      total: findings.length,
      findings,
      durationMs,
      error: null,
    };
  } catch (err) {
    return {
      owner,
      repo,
      label,
      grade: '?',
      criticals: 0,
      warnings: 0,
      infos: 0,
      total: 0,
      findings: [],
      durationMs: Math.round(performance.now() - start),
      error: err.message,
    };
  }
}

/**
 * @typedef {object} RepoResult
 * @property {string} owner
 * @property {string} repo
 * @property {string} label
 * @property {string} grade
 * @property {number} criticals
 * @property {number} warnings
 * @property {number} infos
 * @property {number} total
 * @property {import('./rules/types.js').Finding[]} findings
 * @property {number} durationMs
 * @property {string|null} error
 */

/**
 * @typedef {object} MultiRepoResult
 * @property {RepoResult[]} repos
 * @property {number} totalRepos
 * @property {number} scannedRepos
 * @property {number} failedRepos
 * @property {number} totalFindings
 * @property {number} totalCriticals
 * @property {number} totalWarnings
 * @property {number} durationMs
 */

/**
 * Scan multiple repos with concurrency control.
 *
 * @param {{ owner: string, repo: string }[]} targets
 * @param {{ concurrency?: number, onProgress?: (done: number, total: number, result: RepoResult) => void }} options
 * @returns {Promise<MultiRepoResult>}
 */
export async function scanMultiRepo(targets, { concurrency = 5, onProgress } = {}) {
  const start = performance.now();
  const results = [];
  let done = 0;

  const queue = [...targets];

  async function worker() {
    while (queue.length > 0) {
      const target = queue.shift();
      const result = await scanOneRepo(target);
      results.push(result);
      done++;
      if (onProgress) onProgress(done, targets.length, result);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, targets.length) }, () => worker());
  await Promise.all(workers);

  results.sort((a, b) => {
    if (a.grade === b.grade) return b.total - a.total;
    const order = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
    return (order[a.grade] ?? 6) - (order[b.grade] ?? 6);
  });

  const durationMs = Math.round(performance.now() - start);

  return {
    repos: results,
    totalRepos: targets.length,
    scannedRepos: results.filter(r => !r.error).length,
    failedRepos: results.filter(r => r.error).length,
    totalFindings: results.reduce((s, r) => s + r.total, 0),
    totalCriticals: results.reduce((s, r) => s + r.criticals, 0),
    totalWarnings: results.reduce((s, r) => s + r.warnings, 0),
    durationMs,
  };
}
