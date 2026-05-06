import { audit } from './index.js';
import { fetchRepoFiles } from './github.js';

/**
 * Fetch the list of repos for a GitHub org or user.
 *
 * @param {'orgs'|'users'} kind
 * @param {string} name
 * @param {{ skipArchived?: boolean, skipForks?: boolean, minStars?: number }} filters
 * @returns {Promise<Array<{ owner: string, repo: string, stars: number, archived: boolean, fork: boolean, language: string|null, pushedAt: string }>>}
 */
export async function listRepos(kind, name, filters = {}) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (!token) {
    throw new Error('GITHUB_TOKEN is required to list org/user repos.');
  }

  const headers = {
    Accept: 'application/vnd.github.v3+json',
    Authorization: `Bearer ${token}`,
    'User-Agent': 'vibe-audit',
  };

  const repos = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    const url = `https://api.github.com/${kind}/${name}/repos?per_page=${perPage}&page=${page}&sort=pushed&direction=desc`;
    const res = await fetch(url, { headers });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API error listing repos (${res.status}): ${body}`);
    }

    const batch = await res.json();
    if (batch.length === 0) break;

    for (const r of batch) {
      if (filters.skipArchived && r.archived) continue;
      if (filters.skipForks && r.fork) continue;
      if (filters.minStars && (r.stargazers_count || 0) < filters.minStars) continue;

      repos.push({
        owner: r.owner?.login || name,
        repo: r.name,
        stars: r.stargazers_count || 0,
        archived: r.archived,
        fork: r.fork,
        language: r.language,
        pushedAt: r.pushed_at,
      });
    }

    if (batch.length < perPage) break;
    page++;
  }

  return repos;
}

/**
 * Parse a repos file (one "owner/repo" per line, or JSON array).
 *
 * @param {string} content - File content
 * @returns {Array<{ owner: string, repo: string }>}
 */
export function parseReposFile(content) {
  const trimmed = content.trim();

  if (trimmed.startsWith('[')) {
    const arr = JSON.parse(trimmed);
    return arr.map((entry) => {
      if (typeof entry === 'string') {
        const [owner, repo] = entry.split('/');
        return { owner, repo };
      }
      return { owner: entry.owner, repo: entry.repo };
    });
  }

  return trimmed
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => {
      const clean = line.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '');
      const [owner, repo] = clean.split('/');
      return { owner, repo };
    })
    .filter((r) => r.owner && r.repo);
}

/**
 * Scan multiple GitHub repos and return aggregated results.
 *
 * @param {Array<{ owner: string, repo: string }>} repos
 * @param {{ concurrency?: number, format?: string, rules?: string[], exclude?: string[], onProgress?: (info: { repo: string, index: number, total: number, status: string }) => void }} options
 * @returns {Promise<Array<{ owner: string, repo: string, findings: Array, filesScanned: number, rulesRun: number, durationMs: number, grade: string, error?: string }>>}
 */
export async function scanRepos(repos, options = {}) {
  const { concurrency = 5, rules, exclude, onProgress } = options;
  const results = [];
  let completed = 0;

  async function scanOne({ owner, repo }) {
    const label = `${owner}/${repo}`;
    const index = ++completed;

    if (onProgress) {
      onProgress({ repo: label, index, total: repos.length, status: 'scanning' });
    }

    const start = performance.now();

    try {
      const fileSource = fetchRepoFiles(owner, repo);
      const { findings } = await audit(`github://${owner}/${repo}`, {
        fileSource,
        skipSca: true,
        format: 'json-quiet',
        rules,
        exclude,
      });

      const durationMs = Math.round(performance.now() - start);
      const criticals = findings.filter((f) => f.severity === 'critical').length;
      const warnings = findings.filter((f) => f.severity === 'warning').length;
      const infos = findings.filter((f) => f.severity === 'info').length;
      const grade = criticals > 0 ? 'F' : warnings > 5 ? 'D' : warnings > 0 ? 'C' : infos > 0 ? 'B' : 'A';

      const result = { owner, repo, findings, filesScanned: 0, durationMs, grade, criticals, warnings, infos };

      if (onProgress) {
        onProgress({ repo: label, index, total: repos.length, status: 'done', grade });
      }

      return result;
    } catch (err) {
      const durationMs = Math.round(performance.now() - start);

      if (onProgress) {
        onProgress({ repo: label, index, total: repos.length, status: 'error' });
      }

      return { owner, repo, findings: [], filesScanned: 0, durationMs, grade: '?', criticals: 0, warnings: 0, infos: 0, error: err.message };
    }
  }

  // Process in batches for concurrency control.
  for (let i = 0; i < repos.length; i += concurrency) {
    const batch = repos.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(scanOne));
    results.push(...batchResults);
  }

  return results;
}

/**
 * Compute aggregate stats from multi-repo results.
 *
 * @param {Array} results - Output from scanRepos()
 * @returns {{ totalRepos: number, totalFindings: number, totalCriticals: number, totalWarnings: number, totalInfos: number, gradeDistribution: Record<string, number>, topRules: Array<{ ruleId: string, count: number }>, reposByGrade: Record<string, string[]> }}
 */
export function aggregateResults(results) {
  const totalRepos = results.length;
  let totalFindings = 0;
  let totalCriticals = 0;
  let totalWarnings = 0;
  let totalInfos = 0;

  const gradeDistribution = { A: 0, B: 0, C: 0, D: 0, F: 0, '?': 0 };
  const reposByGrade = { F: [], D: [], C: [], B: [], A: [], '?': [] };
  const ruleCounts = new Map();

  for (const r of results) {
    totalFindings += r.findings.length;
    totalCriticals += r.criticals;
    totalWarnings += r.warnings;
    totalInfos += r.infos;
    gradeDistribution[r.grade] = (gradeDistribution[r.grade] || 0) + 1;
    reposByGrade[r.grade]?.push(`${r.owner}/${r.repo}`);

    for (const f of r.findings) {
      ruleCounts.set(f.ruleId, (ruleCounts.get(f.ruleId) || 0) + 1);
    }
  }

  const topRules = [...ruleCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([ruleId, count]) => ({ ruleId, count }));

  return { totalRepos, totalFindings, totalCriticals, totalWarnings, totalInfos, gradeDistribution, topRules, reposByGrade };
}
