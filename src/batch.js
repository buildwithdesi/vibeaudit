import { audit } from './index.js';
import { fetchRepoFiles, parseGitHubTarget } from './github.js';

/**
 * Scan multiple GitHub repos in parallel with concurrency control.
 *
 * @param {Array<string | { repo: string, rules?: string[], exclude?: string[] }>} repos
 * @param {{ concurrency?: number, strict?: boolean, rules?: string[], exclude?: string[], onResult?: (result: object) => void }} options
 * @returns {Promise<{ results: object[], summary: object }>}
 */
export async function batchAudit(repos, options = {}) {
  const {
    concurrency = 5,
    strict = false,
    rules,
    exclude,
    onResult,
  } = options;

  const results = [];
  const queue = repos.map((entry) => {
    if (typeof entry === 'string') return { repo: entry };
    return entry;
  });

  let idx = 0;

  async function worker() {
    while (idx < queue.length) {
      const i = idx++;
      const entry = queue[i];
      const result = await scanOne(entry, { strict, rules, exclude });
      results[i] = result;
      if (onResult) onResult(result);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, () => worker());
  await Promise.all(workers);

  return { results, summary: buildSummary(results) };
}

async function scanOne(entry, globalOpts) {
  const { repo, rules: repoRules, exclude: repoExclude } = entry;
  const start = performance.now();

  const gh = parseGitHubTarget(repo);
  if (!gh) {
    return {
      repo,
      status: 'error',
      error: `Not a valid GitHub repo: ${repo}`,
      findings: [],
      counts: { critical: 0, warning: 0, info: 0, total: 0 },
      durationMs: 0,
    };
  }

  const label = `${gh.owner}/${gh.repo}`;

  try {
    const cliOptions = {
      format: 'json',
      rules: repoRules || globalOpts.rules,
      exclude: repoExclude || globalOpts.exclude,
      strict: globalOpts.strict,
      fileSource: fetchRepoFiles(gh.owner, gh.repo),
      skipSca: true,
      _silent: true,
    };

    const { findings, exitCode } = await audit(`github://${label}`, cliOptions);
    const durationMs = Math.round(performance.now() - start);

    const critical = findings.filter((f) => f.severity === 'critical').length;
    const warning = findings.filter((f) => f.severity === 'warning').length;
    const info = findings.filter((f) => f.severity === 'info').length;

    return {
      repo: label,
      status: 'scanned',
      grade: gradeFor(critical, warning),
      findings,
      counts: { critical, warning, info, total: findings.length },
      exitCode,
      durationMs,
    };
  } catch (err) {
    return {
      repo: label,
      status: 'error',
      error: err.message,
      findings: [],
      counts: { critical: 0, warning: 0, info: 0, total: 0 },
      durationMs: Math.round(performance.now() - start),
    };
  }
}

function gradeFor(criticals, warnings) {
  if (criticals > 0) return 'F';
  if (warnings > 5) return 'D';
  if (warnings > 0) return 'C';
  return 'A';
}

function buildSummary(results) {
  const scanned = results.filter((r) => r.status === 'scanned');
  const errors = results.filter((r) => r.status === 'error');

  let totalCritical = 0;
  let totalWarning = 0;
  let totalInfo = 0;
  const grades = { A: 0, C: 0, D: 0, F: 0 };

  for (const r of scanned) {
    totalCritical += r.counts.critical;
    totalWarning += r.counts.warning;
    totalInfo += r.counts.info;
    if (r.grade) grades[r.grade] = (grades[r.grade] || 0) + 1;
  }

  const topOffenders = scanned
    .filter((r) => r.counts.total > 0)
    .sort((a, b) => b.counts.critical - a.counts.critical || b.counts.total - a.counts.total)
    .slice(0, 10);

  const ruleHits = new Map();
  for (const r of scanned) {
    for (const f of r.findings) {
      ruleHits.set(f.ruleId, (ruleHits.get(f.ruleId) || 0) + 1);
    }
  }
  const topRules = [...ruleHits.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ruleId, count]) => ({ ruleId, count }));

  return {
    reposScanned: scanned.length,
    reposErrored: errors.length,
    totalFindings: totalCritical + totalWarning + totalInfo,
    totalCritical,
    totalWarning,
    totalInfo,
    grades,
    topOffenders: topOffenders.map((r) => ({
      repo: r.repo,
      grade: r.grade,
      critical: r.counts.critical,
      warning: r.counts.warning,
      total: r.counts.total,
    })),
    topRules,
    errors: errors.map((r) => ({ repo: r.repo, error: r.error })),
  };
}

/**
 * Fetch all repos for a GitHub org/user.
 *
 * @param {string} orgOrUser
 * @param {{ type?: 'org' | 'user', token?: string }} options
 * @returns {Promise<string[]>} repo full names (owner/repo)
 */
export async function fetchOrgRepos(orgOrUser, options = {}) {
  const token = options.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;
  const type = options.type || 'org';
  const base = type === 'org'
    ? `https://api.github.com/orgs/${orgOrUser}/repos`
    : `https://api.github.com/users/${orgOrUser}/repos`;

  while (true) {
    const url = `${base}?per_page=100&page=${page}&sort=pushed&direction=desc`;
    const res = await fetch(url, { headers });
    if (!res.ok) {
      if (page === 1) {
        throw new Error(`Failed to fetch repos for ${orgOrUser}: ${res.status}`);
      }
      break;
    }
    const data = await res.json();
    if (data.length === 0) break;

    for (const r of data) {
      if (!r.archived && !r.disabled && !r.fork) {
        repos.push(r.full_name);
      }
    }
    page++;
  }

  return repos;
}
