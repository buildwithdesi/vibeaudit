import { audit } from './index.js';
import { fetchRepoFiles } from './github.js';

const DEFAULT_CONCURRENCY = 5;
const REPOS_PER_PAGE = 100;

function matchesPattern(name, pattern) {
  if (pattern.startsWith('*') && pattern.endsWith('*')) {
    return name.includes(pattern.slice(1, -1));
  }
  if (pattern.startsWith('*')) {
    return name.endsWith(pattern.slice(1));
  }
  if (pattern.endsWith('*')) {
    return name.startsWith(pattern.slice(0, -1));
  }
  return name === pattern;
}

function matchesAny(name, patterns) {
  if (!patterns || patterns.length === 0) return false;
  return patterns.some((p) => matchesPattern(name, p));
}

function calcGrade(findings) {
  const criticals = findings.filter((f) => f.severity === 'critical').length;
  const warnings = findings.filter((f) => f.severity === 'warning').length;
  const infos = findings.filter((f) => f.severity === 'info').length;
  if (criticals > 0) return 'F';
  if (warnings > 5) return 'D';
  if (warnings > 0) return 'C';
  if (infos > 0) return 'B';
  return 'A';
}

async function apiFetch(url, token) {
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(url, { headers });

  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get('X-RateLimit-Remaining');
    const resetAt = res.headers.get('X-RateLimit-Reset');
    if (remaining === '0' && resetAt) {
      const waitMs = Math.max(0, Number(resetAt) * 1000 - Date.now()) + 1000;
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      return apiFetch(url, token);
    }
  }

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`GitHub API error (${res.status}): ${body}`);
  }

  return res;
}

export async function listRepos(owner, options = {}) {
  const { token, skipForks = false, skipArchived = false, skipEmpty = false, include, exclude } = options;

  const repos = [];
  let page = 1;
  let baseUrl = `https://api.github.com/users/${encodeURIComponent(owner)}/repos`;

  while (true) {
    const url = `${baseUrl}?per_page=${REPOS_PER_PAGE}&page=${page}&sort=updated`;
    let res;
    try {
      res = await apiFetch(url, token);
    } catch (err) {
      if (page === 1) {
        baseUrl = `https://api.github.com/orgs/${encodeURIComponent(owner)}/repos`;
        const orgUrl = `${baseUrl}?per_page=${REPOS_PER_PAGE}&page=${page}&sort=updated`;
        res = await apiFetch(orgUrl, token);
      } else {
        throw err;
      }
    }

    const batch = await res.json();
    if (!Array.isArray(batch) || batch.length === 0) break;
    repos.push(...batch);
    if (batch.length < REPOS_PER_PAGE) break;
    page++;
  }

  return repos.filter((repo) => {
    if (skipForks && repo.fork) return false;
    if (skipArchived && repo.archived) return false;
    if (skipEmpty && repo.size === 0) return false;
    if (include && include.length > 0 && !matchesAny(repo.name, include)) return false;
    if (exclude && exclude.length > 0 && matchesAny(repo.name, exclude)) return false;
    return true;
  });
}

async function runConcurrent(thunks, limit) {
  const results = new Array(thunks.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < thunks.length) {
      const i = nextIndex++;
      results[i] = await thunks[i]();
    }
  }

  const workers = [];
  for (let w = 0; w < Math.min(limit, thunks.length); w++) {
    workers.push(worker());
  }
  await Promise.all(workers);
  return results;
}

export async function scanOrg(owner, options = {}) {
  const {
    token,
    concurrency = DEFAULT_CONCURRENCY,
    skipForks = false,
    skipArchived = false,
    skipEmpty = false,
    include,
    exclude,
    onRepoStart,
    onRepoComplete,
  } = options;

  const overallStart = performance.now();

  if (token) {
    process.env.GITHUB_TOKEN = token;
  }

  const allRepos = await listRepos(owner, { token, skipForks, skipArchived, skipEmpty, include, exclude });

  const results = new Map();

  let scanIndex = 0;
  const thunks = allRepos.map((repo) => async () => {
    scanIndex++;
    if (onRepoStart) onRepoStart(repo, scanIndex, allRepos.length);

    const repoStart = performance.now();
    let result;

    try {
      const fileSource = fetchRepoFiles(owner, repo.name);

      const savedLog = console.log;
      console.log = () => {};
      let auditResult;
      try {
        auditResult = await audit(`github://${owner}/${repo.name}`, {
          fileSource,
          skipSca: true,
          format: 'json',
        });
      } finally {
        console.log = savedLog;
      }

      const findings = auditResult.findings || [];
      const durationMs = Math.round(performance.now() - repoStart);

      result = {
        findings,
        filesScanned: auditResult.filesScanned || 0,
        rulesRun: auditResult.rulesRun || 0,
        durationMs,
        grade: calcGrade(findings),
      };
    } catch (err) {
      const durationMs = Math.round(performance.now() - repoStart);
      result = {
        findings: [],
        filesScanned: 0,
        rulesRun: 0,
        durationMs,
        grade: 'A',
        error: err.message,
      };
    }

    results.set(repo.name, result);
    if (onRepoComplete) onRepoComplete(repo, result);
  });

  await runConcurrent(thunks, concurrency);

  let totalFindings = 0;
  let totalCritical = 0;
  let totalWarning = 0;
  let totalInfo = 0;
  let scannedRepos = 0;
  let skippedRepos = 0;

  for (const [, result] of results) {
    if (result.error) {
      skippedRepos++;
    } else {
      scannedRepos++;
    }
    for (const f of result.findings) {
      totalFindings++;
      if (f.severity === 'critical') totalCritical++;
      else if (f.severity === 'warning') totalWarning++;
      else if (f.severity === 'info') totalInfo++;
    }
  }

  const durationMs = Math.round(performance.now() - overallStart);

  return {
    owner,
    repos: allRepos,
    results,
    summary: {
      totalRepos: allRepos.length,
      scannedRepos,
      skippedRepos,
      totalFindings,
      totalCritical,
      totalWarning,
      totalInfo,
      durationMs,
    },
  };
}
