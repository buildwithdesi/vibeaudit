import { audit } from './index.js';
import { parseGitHubTarget, fetchRepoFiles } from './github.js';

/**
 * Fetch all non-fork, non-archived repos for a GitHub org or user.
 * Pages through the API automatically.
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
    let url = `https://api.github.com/orgs/${orgOrUser}/repos?per_page=100&page=${page}&sort=pushed`;
    let res = await fetch(url, { headers });

    if (res.status === 404 && page === 1) {
      url = `https://api.github.com/users/${orgOrUser}/repos?per_page=100&page=${page}&sort=pushed`;
      res = await fetch(url, { headers });
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API error fetching repos for "${orgOrUser}" (${res.status}): ${body}`);
    }

    const data = await res.json();
    if (data.length === 0) break;

    for (const r of data) {
      if (!r.archived && !r.fork && !r.disabled) {
        repos.push(`${r.owner.login}/${r.name}`);
      }
    }

    if (data.length < 100) break;
    page++;
  }

  return repos;
}

/**
 * Run a concurrency-limited set of promises.
 * @param {Array<() => Promise<T>>} tasks
 * @param {number} limit
 * @returns {Promise<T[]>}
 * @template T
 */
async function pooled(tasks, limit) {
  const results = new Array(tasks.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < tasks.length) {
      const i = nextIndex++;
      results[i] = await tasks[i]();
    }
  }

  const workers = Array.from({ length: Math.min(limit, tasks.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

/**
 * Scan a single repo and return structured results.
 *
 * @param {string} repoSpec - "owner/repo" or full GitHub URL
 * @param {{ rules?: string[], exclude?: string[], strict?: boolean }} options
 * @returns {Promise<{ repo: string, grade: string, findings: Array, critical: number, warning: number, info: number, filesScanned: number, durationMs: number, error?: string }>}
 */
async function scanOneRepo(repoSpec, options = {}) {
  const start = performance.now();

  const gh = parseGitHubTarget(repoSpec);
  if (!gh) {
    return {
      repo: repoSpec,
      grade: '?',
      findings: [],
      critical: 0,
      warning: 0,
      info: 0,
      filesScanned: 0,
      durationMs: 0,
      error: `Not a valid GitHub repo: ${repoSpec}`,
    };
  }

  const label = `${gh.owner}/${gh.repo}`;

  try {
    const { findings } = await audit(`github://${label}`, {
      format: 'json',
      rules: options.rules,
      exclude: options.exclude,
      strict: options.strict,
      skipSca: true,
      fileSource: fetchRepoFiles(gh.owner, gh.repo),
      silent: true,
    });

    const critical = findings.filter((f) => f.severity === 'critical').length;
    const warning = findings.filter((f) => f.severity === 'warning').length;
    const info = findings.filter((f) => f.severity === 'info').length;
    const grade = critical > 0 ? 'F' : warning > 5 ? 'D' : warning > 0 ? 'C' : info > 0 ? 'B' : 'A';

    return {
      repo: label,
      grade,
      findings,
      critical,
      warning,
      info,
      filesScanned: 0,
      durationMs: Math.round(performance.now() - start),
    };
  } catch (err) {
    return {
      repo: label,
      grade: '?',
      findings: [],
      critical: 0,
      warning: 0,
      info: 0,
      filesScanned: 0,
      durationMs: Math.round(performance.now() - start),
      error: err.message,
    };
  }
}

/**
 * Batch-scan multiple repos with concurrency control.
 *
 * @param {string[]} repos - Array of "owner/repo" or GitHub URLs
 * @param {{ concurrency?: number, rules?: string[], exclude?: string[], strict?: boolean, onProgress?: (done: number, total: number, repo: string, result: object) => void }} options
 * @returns {Promise<{ results: Array, summary: object }>}
 */
export async function batchAudit(repos, options = {}) {
  const concurrency = options.concurrency || 5;
  const totalStart = performance.now();

  const tasks = repos.map((repoSpec, index) => () => {
    return scanOneRepo(repoSpec, options).then((result) => {
      if (options.onProgress) {
        options.onProgress(index + 1, repos.length, result.repo, result);
      }
      return result;
    });
  });

  const results = await pooled(tasks, concurrency);

  const totalDurationMs = Math.round(performance.now() - totalStart);
  const succeeded = results.filter((r) => !r.error);
  const failed = results.filter((r) => r.error);

  const summary = {
    totalRepos: repos.length,
    scanned: succeeded.length,
    failed: failed.length,
    totalFindings: succeeded.reduce((s, r) => s + r.findings.length, 0),
    totalCritical: succeeded.reduce((s, r) => s + r.critical, 0),
    totalWarning: succeeded.reduce((s, r) => s + r.warning, 0),
    totalInfo: succeeded.reduce((s, r) => s + r.info, 0),
    grades: { A: 0, B: 0, C: 0, D: 0, F: 0 },
    durationMs: totalDurationMs,
  };

  for (const r of succeeded) {
    if (summary.grades[r.grade] !== undefined) {
      summary.grades[r.grade]++;
    }
  }

  return { results, summary };
}
