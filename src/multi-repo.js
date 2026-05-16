import { parseGitHubTarget, fetchRepoFiles } from './github.js';
import { audit } from './index.js';

const DEFAULT_CONCURRENCY = 5;
const RATE_LIMIT_DELAY_MS = 1000;

/**
 * Fetch all non-fork, non-archived repos for a GitHub org or user.
 * Paginates through all pages automatically.
 *
 * @param {string} org - GitHub org or username
 * @param {{ token?: string, includeForks?: boolean, includeArchived?: boolean }} options
 * @returns {Promise<Array<{ owner: string, repo: string, fullName: string, description: string, stars: number, language: string, updatedAt: string }>>}
 */
export async function fetchOrgRepos(org, options = {}) {
  const token = options.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    const url = `https://api.github.com/users/${org}/repos?per_page=${perPage}&page=${page}&sort=updated&direction=desc`;
    const res = await fetch(url, { headers });

    if (res.status === 404) {
      const orgUrl = `https://api.github.com/orgs/${org}/repos?per_page=${perPage}&page=${page}&sort=updated&direction=desc`;
      const orgRes = await fetch(orgUrl, { headers });
      if (!orgRes.ok) {
        throw new Error(`GitHub API error fetching repos for "${org}": ${orgRes.status}`);
      }
      const data = await orgRes.json();
      if (data.length === 0) break;
      repos.push(...data);
      if (data.length < perPage) break;
      page++;
      continue;
    }

    if (!res.ok) {
      throw new Error(`GitHub API error fetching repos for "${org}": ${res.status}`);
    }

    const data = await res.json();
    if (data.length === 0) break;
    repos.push(...data);
    if (data.length < perPage) break;
    page++;
  }

  return repos
    .filter((r) => {
      if (!options.includeForks && r.fork) return false;
      if (!options.includeArchived && r.archived) return false;
      if (r.size === 0) return false;
      return true;
    })
    .map((r) => ({
      owner: r.owner.login,
      repo: r.name,
      fullName: r.full_name,
      description: r.description || '',
      stars: r.stargazers_count,
      language: r.language || 'Unknown',
      updatedAt: r.updated_at,
    }));
}

/**
 * Load a repo list from a JSON or text file.
 *
 * JSON format: [{ "owner": "x", "repo": "y" }] or ["owner/repo", ...]
 * Text format: one "owner/repo" per line
 *
 * @param {string} content - File content
 * @returns {Array<{ owner: string, repo: string, fullName: string }>}
 */
export function parseRepoList(content) {
  const trimmed = content.trim();

  if (trimmed.startsWith('[')) {
    const parsed = JSON.parse(trimmed);
    return parsed.map((entry) => {
      if (typeof entry === 'string') {
        const gh = parseGitHubTarget(entry);
        if (!gh) throw new Error(`Invalid repo reference: ${entry}`);
        return { owner: gh.owner, repo: gh.repo, fullName: `${gh.owner}/${gh.repo}` };
      }
      return { owner: entry.owner, repo: entry.repo, fullName: `${entry.owner}/${entry.repo}` };
    });
  }

  return trimmed
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => {
      const gh = parseGitHubTarget(line);
      if (!gh) throw new Error(`Invalid repo reference: ${line}`);
      return { owner: gh.owner, repo: gh.repo, fullName: `${gh.owner}/${gh.repo}` };
    });
}

/**
 * Scan multiple repos with concurrency control.
 *
 * @param {Array<{ owner: string, repo: string, fullName?: string }>} repos
 * @param {{ concurrency?: number, rules?: string[], exclude?: string[], onProgress?: (result: RepoResult) => void }} options
 * @returns {Promise<RepoResult[]>}
 *
 * @typedef {{ repo: string, owner: string, fullName: string, grade: string, findings: import('./rules/types.js').Finding[], filesScanned: number, rulesRun: number, durationMs: number, error?: string, criticals: number, warnings: number, infos: number }} RepoResult
 */
export async function scanRepos(repos, options = {}) {
  const concurrency = options.concurrency || DEFAULT_CONCURRENCY;
  const results = [];
  let index = 0;

  async function worker() {
    while (index < repos.length) {
      const current = index++;
      const repo = repos[current];

      const result = await scanSingleRepo(repo, options);
      results.push(result);

      if (options.onProgress) {
        options.onProgress(result);
      }

      if (current < repos.length - 1) {
        await sleep(RATE_LIMIT_DELAY_MS);
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, repos.length) }, () => worker());
  await Promise.all(workers);

  results.sort((a, b) => {
    if (a.criticals !== b.criticals) return b.criticals - a.criticals;
    if (a.warnings !== b.warnings) return b.warnings - a.warnings;
    return b.infos - a.infos;
  });

  return results;
}

async function scanSingleRepo(repo, options) {
  const fullName = repo.fullName || `${repo.owner}/${repo.repo}`;
  const start = performance.now();

  try {
    const fileSource = fetchRepoFiles(repo.owner, repo.repo);
    const { findings, meta } = await audit(`github://${fullName}`, {
      fileSource,
      skipSca: true,
      rules: options.rules,
      exclude: options.exclude,
      silent: true,
    });

    const durationMs = Math.round(performance.now() - start);
    const criticals = findings.filter((f) => f.severity === 'critical').length;
    const warnings = findings.filter((f) => f.severity === 'warning').length;
    const infos = findings.filter((f) => f.severity === 'info').length;

    const grade =
      criticals > 0 ? 'F' : warnings > 5 ? 'D' : warnings > 0 ? 'C' : infos > 0 ? 'B' : 'A';

    return {
      repo: repo.repo,
      owner: repo.owner,
      fullName,
      grade,
      findings,
      filesScanned: meta.filesScanned,
      rulesRun: meta.rulesRun,
      durationMs,
      criticals,
      warnings,
      infos,
      description: repo.description || '',
      language: repo.language || '',
      stars: repo.stars || 0,
    };
  } catch (err) {
    return {
      repo: repo.repo,
      owner: repo.owner,
      fullName,
      grade: '?',
      findings: [],
      filesScanned: 0,
      rulesRun: 0,
      durationMs: Math.round(performance.now() - start),
      error: err.message,
      criticals: 0,
      warnings: 0,
      infos: 0,
      description: repo.description || '',
      language: repo.language || '',
      stars: repo.stars || 0,
    };
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
