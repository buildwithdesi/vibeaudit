import { audit } from './index.js';
import { fetchRepoFiles } from './github.js';

const DEFAULT_CONCURRENCY = 5;
const GITHUB_API = 'https://api.github.com';

/**
 * @typedef {Object} RepoResult
 * @property {string} owner
 * @property {string} repo
 * @property {string} fullName
 * @property {import('./rules/types.js').Finding[]} findings
 * @property {number} filesScanned
 * @property {number} rulesRun
 * @property {number} durationMs
 * @property {string} grade
 * @property {{ critical: number, warning: number, info: number }} counts
 * @property {string|null} error
 */

/**
 * Fetch all non-fork, non-archived repos for a GitHub user or org.
 * Paginates automatically.
 */
async function fetchOrgRepos(owner, token) {
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit-fleet',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;

  while (true) {
    const url = `${GITHUB_API}/users/${owner}/repos?per_page=100&page=${page}&sort=updated`;
    const res = await fetch(url, { headers });

    if (!res.ok) {
      const orgUrl = `${GITHUB_API}/orgs/${owner}/repos?per_page=100&page=${page}&sort=updated`;
      const orgRes = await fetch(orgUrl, { headers });
      if (!orgRes.ok) {
        throw new Error(`GitHub API error fetching repos for "${owner}": ${res.status}`);
      }
      const data = await orgRes.json();
      if (data.length === 0) break;
      repos.push(...data);
      if (data.length < 100) break;
      page++;
      continue;
    }

    const data = await res.json();
    if (data.length === 0) break;
    repos.push(...data);
    if (data.length < 100) break;
    page++;
  }

  return repos
    .filter((r) => !r.fork && !r.archived)
    .map((r) => ({ owner: r.owner.login, repo: r.name, fullName: r.full_name }));
}

function computeGrade(counts) {
  if (counts.critical > 0) return 'F';
  if (counts.warning > 5) return 'D';
  if (counts.warning > 0) return 'C';
  if (counts.info > 0) return 'B';
  return 'A';
}

/**
 * Scan a single repo and return results.
 */
async function scanRepo(owner, repo) {
  const start = performance.now();
  try {
    const fileSource = fetchRepoFiles(owner, repo);
    const { findings, meta } = await audit(`github://${owner}/${repo}`, {
      fileSource,
      skipSca: true,
      quiet: true,
    });

    const durationMs = Math.round(performance.now() - start);
    const counts = {
      critical: findings.filter((f) => f.severity === 'critical').length,
      warning: findings.filter((f) => f.severity === 'warning').length,
      info: findings.filter((f) => f.severity === 'info').length,
    };

    return {
      owner,
      repo,
      fullName: `${owner}/${repo}`,
      findings,
      filesScanned: meta.filesScanned,
      rulesRun: meta.rulesRun,
      durationMs,
      grade: computeGrade(counts),
      counts,
      error: null,
    };
  } catch (err) {
    return {
      owner,
      repo,
      fullName: `${owner}/${repo}`,
      findings: [],
      filesScanned: 0,
      rulesRun: 0,
      durationMs: Math.round(performance.now() - start),
      grade: '?',
      counts: { critical: 0, warning: 0, info: 0 },
      error: err.message,
    };
  }
}

/**
 * Run repos in batches with concurrency limit.
 */
async function runWithConcurrency(items, fn, concurrency) {
  const results = [];
  let index = 0;

  async function worker() {
    while (index < items.length) {
      const i = index++;
      results[i] = await fn(items[i]);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

/**
 * Resolve the repo list from the config.
 *
 * @param {Object} config
 * @param {string[]} [config.repos]   - Explicit "owner/repo" list
 * @param {string[]} [config.orgs]    - GitHub orgs/users to auto-discover
 * @param {string[]} [config.exclude] - Repos to skip (full names)
 * @param {string} [token]
 * @returns {Promise<Array<{ owner: string, repo: string, fullName: string }>>}
 */
async function resolveRepos(config, token) {
  const seen = new Set();
  const repos = [];
  const excludeSet = new Set((config.exclude || []).map((s) => s.toLowerCase()));

  if (config.repos) {
    for (const r of config.repos) {
      const [owner, repo] = r.split('/');
      if (owner && repo) {
        const fullName = `${owner}/${repo}`;
        if (!excludeSet.has(fullName.toLowerCase()) && !seen.has(fullName.toLowerCase())) {
          seen.add(fullName.toLowerCase());
          repos.push({ owner, repo, fullName });
        }
      }
    }
  }

  if (config.orgs) {
    for (const org of config.orgs) {
      const orgRepos = await fetchOrgRepos(org, token);
      for (const r of orgRepos) {
        const key = r.fullName.toLowerCase();
        if (!excludeSet.has(key) && !seen.has(key)) {
          seen.add(key);
          repos.push(r);
        }
      }
    }
  }

  return repos;
}

/**
 * Run a fleet scan across multiple repos.
 *
 * @param {Object} config
 * @param {string[]} [config.repos]       - Explicit "owner/repo" list
 * @param {string[]} [config.orgs]        - GitHub orgs/users to auto-discover
 * @param {string[]} [config.exclude]     - Repos to skip
 * @param {number}   [config.concurrency] - Max parallel scans
 * @param {(status: { repo: string, done: number, total: number }) => void} [onProgress]
 * @returns {Promise<{ results: RepoResult[], summary: Object }>}
 */
export async function fleetScan(config, onProgress) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const concurrency = config.concurrency || DEFAULT_CONCURRENCY;

  const repos = await resolveRepos(config, token);
  if (repos.length === 0) {
    throw new Error('No repos to scan. Add repos or orgs to your fleet config.');
  }

  let done = 0;
  const results = await runWithConcurrency(
    repos,
    async (r) => {
      const result = await scanRepo(r.owner, r.repo);
      done++;
      if (onProgress) onProgress({ repo: r.fullName, done, total: repos.length });
      return result;
    },
    concurrency,
  );

  const totalFindings = results.reduce((s, r) => s + r.findings.length, 0);
  const totalCritical = results.reduce((s, r) => s + r.counts.critical, 0);
  const totalWarning = results.reduce((s, r) => s + r.counts.warning, 0);
  const totalInfo = results.reduce((s, r) => s + r.counts.info, 0);
  const errorCount = results.filter((r) => r.error).length;

  const gradeDistribution = { A: 0, B: 0, C: 0, D: 0, F: 0, '?': 0 };
  for (const r of results) gradeDistribution[r.grade]++;

  results.sort((a, b) => {
    const sevOrder = { F: 0, D: 1, C: 2, '?': 3, B: 4, A: 5 };
    return (sevOrder[a.grade] ?? 3) - (sevOrder[b.grade] ?? 3);
  });

  const summary = {
    reposScanned: repos.length,
    reposFailed: errorCount,
    totalFindings,
    totalCritical,
    totalWarning,
    totalInfo,
    gradeDistribution,
    timestamp: new Date().toISOString(),
  };

  return { results, summary };
}
