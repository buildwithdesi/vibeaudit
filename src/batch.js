import { audit } from './index.js';
import { fetchRepoFiles, parseGitHubTarget } from './github.js';
import { readFile } from 'node:fs/promises';

const DEFAULT_CONCURRENCY = 5;
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

async function fetchJSON(url) {
  const res = await fetch(url, { headers: githubHeaders() });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`GitHub API ${res.status}: ${body}`);
  }
  return { data: await res.json(), headers: res.headers };
}

async function fetchAllPages(baseUrl) {
  const results = [];
  let url = `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}per_page=100`;

  while (url) {
    const { data, headers } = await fetchJSON(url);
    results.push(...data);

    const link = headers.get('link') || '';
    const next = link.match(/<([^>]+)>;\s*rel="next"/);
    url = next ? next[1] : null;
  }
  return results;
}

export async function fetchOrgRepos(org) {
  const repos = await fetchAllPages(`${GITHUB_API}/orgs/${org}/repos`);
  return repos
    .filter((r) => !r.archived && !r.disabled && !r.fork)
    .map((r) => ({ owner: r.owner.login, repo: r.name, defaultBranch: r.default_branch }));
}

export async function fetchUserRepos(username) {
  const repos = await fetchAllPages(`${GITHUB_API}/users/${username}/repos`);
  return repos
    .filter((r) => !r.archived && !r.disabled && !r.fork)
    .map((r) => ({ owner: r.owner.login, repo: r.name, defaultBranch: r.default_branch }));
}

export async function loadRepoList(filePath) {
  const content = await readFile(filePath, 'utf-8');
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => {
      const gh = parseGitHubTarget(line);
      if (!gh) throw new Error(`Invalid repo reference: ${line}`);
      return { owner: gh.owner, repo: gh.repo, defaultBranch: 'HEAD' };
    });
}

async function runPool(items, concurrency, fn) {
  const results = [];
  let index = 0;

  async function worker() {
    while (index < items.length) {
      const i = index++;
      results[i] = await fn(items[i], i);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

export async function batchAudit(repos, options = {}) {
  const concurrency = options.concurrency || DEFAULT_CONCURRENCY;
  const onProgress = options.onProgress || (() => {});

  const results = await runPool(repos, concurrency, async (repo, i) => {
    const label = `${repo.owner}/${repo.repo}`;
    onProgress({ type: 'start', repo: label, index: i, total: repos.length });

    try {
      const fileSource = fetchRepoFiles(repo.owner, repo.repo, { branch: repo.defaultBranch });
      const { findings } = await audit(`github://${label}`, {
        fileSource,
        skipSca: true,
        silent: true,
      });

      const criticals = findings.filter((f) => f.severity === 'critical').length;
      const warnings = findings.filter((f) => f.severity === 'warning').length;
      const infos = findings.filter((f) => f.severity === 'info').length;
      const grade = criticals > 0 ? 'F' : warnings > 5 ? 'D' : warnings > 0 ? 'C' : infos > 0 ? 'B' : 'A';

      const result = { repo: label, grade, criticals, warnings, infos, total: findings.length, findings, error: null };
      onProgress({ type: 'done', repo: label, index: i, total: repos.length, result });
      return result;
    } catch (err) {
      const result = { repo: label, grade: '?', criticals: 0, warnings: 0, infos: 0, total: 0, findings: [], error: err.message };
      onProgress({ type: 'error', repo: label, index: i, total: repos.length, error: err.message });
      return result;
    }
  });

  return results;
}
