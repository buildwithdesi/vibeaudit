import { resolveRules } from './rules/index.js';
import { CWE_MAP } from './data/cwe-map.js';
import { fetchRepoFiles } from './github.js';

const DEFAULT_CONCURRENCY = 5;
const RATE_LIMIT_BACKOFF_MS = 60_000;

/**
 * @typedef {Object} FleetConfig
 * @property {string[]} [repos]       - Explicit list of "owner/repo" strings
 * @property {string}   [org]         - GitHub org to enumerate (overrides repos)
 * @property {string[]} [exclude]     - Repos to skip (matched against "owner/repo" or just "repo")
 * @property {string[]} [rules]       - Only run these rule IDs
 * @property {string[]} [excludeRules] - Exclude these rule IDs
 * @property {number}   [concurrency] - Parallel repo scans (default: 5)
 * @property {boolean}  [skipArchived] - Skip archived repos (default: true)
 * @property {boolean}  [skipForks]    - Skip forked repos (default: true)
 */

/**
 * @typedef {Object} RepoResult
 * @property {string} repo
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
 * @typedef {Object} FleetResult
 * @property {RepoResult[]} repos
 * @property {number} totalRepos
 * @property {number} scannedRepos
 * @property {number} failedRepos
 * @property {number} totalFindings
 * @property {number} totalCritical
 * @property {number} totalWarning
 * @property {number} totalInfo
 * @property {number} durationMs
 */

/**
 * Enumerate all repos for a GitHub org via the API.
 */
async function listOrgRepos(org, token, { skipArchived = true, skipForks = true } = {}) {
  const repos = [];
  let page = 1;

  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit-fleet',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  while (true) {
    const url = `https://api.github.com/orgs/${org}/repos?per_page=100&page=${page}&sort=updated`;
    const res = await fetch(url, { headers });

    if (res.status === 403) {
      const resetHeader = res.headers.get('x-ratelimit-reset');
      if (resetHeader) {
        const waitMs = Math.max(0, (parseInt(resetHeader, 10) * 1000) - Date.now()) + 1000;
        await delay(Math.min(waitMs, RATE_LIMIT_BACKOFF_MS));
        continue;
      }
      throw new Error(`GitHub API 403 while listing org ${org}. Set GITHUB_TOKEN for access.`);
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API error listing org ${org} (${res.status}): ${body}`);
    }

    const data = await res.json();
    if (data.length === 0) break;

    for (const r of data) {
      if (skipArchived && r.archived) continue;
      if (skipForks && r.fork) continue;
      repos.push(`${r.owner.login}/${r.name}`);
    }

    page++;
    if (data.length < 100) break;
  }

  return repos;
}

/**
 * List repos for a GitHub user (for personal accounts that aren't orgs).
 */
async function listUserRepos(user, token, { skipArchived = true, skipForks = true } = {}) {
  const repos = [];
  let page = 1;

  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit-fleet',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  while (true) {
    const url = `https://api.github.com/users/${user}/repos?per_page=100&page=${page}&sort=updated`;
    const res = await fetch(url, { headers });
    if (!res.ok) break;

    const data = await res.json();
    if (data.length === 0) break;

    for (const r of data) {
      if (skipArchived && r.archived) continue;
      if (skipForks && r.fork) continue;
      repos.push(`${r.owner.login}/${r.name}`);
    }

    page++;
    if (data.length < 100) break;
  }

  return repos;
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function computeGrade(critical, warning, info) {
  if (critical > 0) return 'F';
  if (warning > 5) return 'D';
  if (warning > 0) return 'C';
  if (info > 0) return 'B';
  return 'A';
}

/**
 * Scan a single repo and return structured results.
 */
async function scanRepo(owner, repo, rules) {
  const start = performance.now();
  const findings = [];
  let filesScanned = 0;

  const fileSource = fetchRepoFiles(owner, repo);

  for await (const file of fileSource) {
    filesScanned++;
    for (const rule of rules) {
      try {
        const ruleFindings = rule.check(file);
        findings.push(...ruleFindings);
      } catch {
        // Rule failure should not crash the fleet.
      }
    }
  }

  for (const f of findings) {
    const meta = CWE_MAP[f.ruleId];
    if (meta) {
      f.cweId = meta.cweId;
      f.cvssScore = meta.cvssScore;
      f.owaspCategory = meta.owaspCategory;
    }
  }

  const severityOrder = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const durationMs = Math.round(performance.now() - start);
  const critical = findings.filter(f => f.severity === 'critical').length;
  const warning = findings.filter(f => f.severity === 'warning').length;
  const info = findings.filter(f => f.severity === 'info').length;

  return {
    repo: `${owner}/${repo}`,
    grade: computeGrade(critical, warning, info),
    critical,
    warning,
    info,
    total: findings.length,
    filesScanned,
    durationMs,
    findings,
    error: null,
  };
}

/**
 * Run fleet audit across multiple repos.
 *
 * @param {FleetConfig} config
 * @param {{ onRepoStart?: (repo: string, index: number, total: number) => void, onRepoEnd?: (result: RepoResult, index: number, total: number) => void }} callbacks
 * @returns {Promise<FleetResult>}
 */
export async function fleetAudit(config, callbacks = {}) {
  const start = performance.now();
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const concurrency = config.concurrency || DEFAULT_CONCURRENCY;

  let repoList;

  if (config.org) {
    try {
      repoList = await listOrgRepos(config.org, token, {
        skipArchived: config.skipArchived !== false,
        skipForks: config.skipForks !== false,
      });
    } catch {
      repoList = await listUserRepos(config.org, token, {
        skipArchived: config.skipArchived !== false,
        skipForks: config.skipForks !== false,
      });
    }
  } else {
    repoList = config.repos || [];
  }

  const excludeSet = new Set((config.exclude || []).map(r => r.toLowerCase()));
  repoList = repoList.filter(r => {
    const full = r.toLowerCase();
    const name = full.split('/')[1];
    return !excludeSet.has(full) && !excludeSet.has(name);
  });

  const rules = resolveRules(config.rules, config.excludeRules);

  const results = [];
  let idx = 0;

  async function worker() {
    while (idx < repoList.length) {
      const i = idx++;
      const repoStr = repoList[i];
      const [owner, repo] = repoStr.split('/');

      callbacks.onRepoStart?.(repoStr, i, repoList.length);

      let result;
      try {
        result = await scanRepo(owner, repo, rules);
      } catch (err) {
        result = {
          repo: repoStr,
          grade: '?',
          critical: 0,
          warning: 0,
          info: 0,
          total: 0,
          filesScanned: 0,
          durationMs: 0,
          findings: [],
          error: err.message,
        };
      }

      results[i] = result;
      callbacks.onRepoEnd?.(result, i, repoList.length);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, repoList.length) }, () => worker());
  await Promise.all(workers);

  const durationMs = Math.round(performance.now() - start);
  const scanned = results.filter(r => !r.error);
  const failed = results.filter(r => r.error);

  return {
    repos: results,
    totalRepos: repoList.length,
    scannedRepos: scanned.length,
    failedRepos: failed.length,
    totalFindings: results.reduce((s, r) => s + r.total, 0),
    totalCritical: results.reduce((s, r) => s + r.critical, 0),
    totalWarning: results.reduce((s, r) => s + r.warning, 0),
    totalInfo: results.reduce((s, r) => s + r.info, 0),
    durationMs,
  };
}
