import { fetchRepoFiles } from './github.js';
import { audit } from './index.js';

const GITHUB_API = 'https://api.github.com';

function getHeaders() {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function fetchJSON(url) {
  const res = await fetch(url, { headers: getHeaders() });
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

/**
 * List all non-fork, non-archived repos for a GitHub org.
 */
export async function listOrgRepos(org) {
  const repos = await fetchAllPages(`${GITHUB_API}/orgs/${org}/repos`);
  return repos
    .filter((r) => !r.fork && !r.archived)
    .sort((a, b) => new Date(b.pushed_at) - new Date(a.pushed_at));
}

/**
 * List all non-fork, non-archived repos for a GitHub user.
 */
export async function listUserRepos(user) {
  const repos = await fetchAllPages(`${GITHUB_API}/users/${user}/repos`);
  return repos
    .filter((r) => !r.fork && !r.archived)
    .sort((a, b) => new Date(b.pushed_at) - new Date(a.pushed_at));
}

function gradeFromFindings(findings) {
  const criticals = findings.filter((f) => f.severity === 'critical').length;
  const warnings = findings.filter((f) => f.severity === 'warning').length;
  const infos = findings.filter((f) => f.severity === 'info').length;
  if (criticals > 0) return 'F';
  if (warnings > 5) return 'D';
  if (warnings > 0) return 'C';
  if (infos > 0) return 'B';
  return 'A';
}

/**
 * Scan multiple repos with concurrency control.
 *
 * @param {Array<{ owner: string, name: string, default_branch: string }>} repos
 * @param {Object} options
 * @param {number} [options.concurrency=5]
 * @param {string[]} [options.rules]
 * @param {string[]} [options.exclude]
 * @param {(result: object) => void} [options.onRepoComplete] - Progress callback
 * @returns {Promise<Array<{ repo: string, owner: string, grade: string, findings: Array, filesScanned: number, durationMs: number, error?: string }>>}
 */
export async function scanRepos(repos, options = {}) {
  const { concurrency = 5, rules, exclude, onRepoComplete } = options;
  const results = [];
  let idx = 0;

  async function worker() {
    while (idx < repos.length) {
      const i = idx++;
      const r = repos[i];
      const label = `${r.owner}/${r.name}`;
      const start = performance.now();

      try {
        const fileSource = fetchRepoFiles(r.owner, r.name, { branch: r.default_branch || 'HEAD' });
        const { findings } = await audit(`github://${label}`, {
          format: 'json',
          fileSource,
          skipSca: true,
          quiet: true,
          rules,
          exclude,
        });

        const durationMs = Math.round(performance.now() - start);
        const result = {
          repo: r.name,
          owner: r.owner,
          grade: gradeFromFindings(findings),
          findings,
          criticals: findings.filter((f) => f.severity === 'critical').length,
          warnings: findings.filter((f) => f.severity === 'warning').length,
          infos: findings.filter((f) => f.severity === 'info').length,
          filesScanned: 0,
          durationMs,
        };
        results.push(result);
        if (onRepoComplete) onRepoComplete(result, i + 1, repos.length);
      } catch (err) {
        const durationMs = Math.round(performance.now() - start);
        const result = {
          repo: r.name,
          owner: r.owner,
          grade: '?',
          findings: [],
          criticals: 0,
          warnings: 0,
          infos: 0,
          filesScanned: 0,
          durationMs,
          error: err.message,
        };
        results.push(result);
        if (onRepoComplete) onRepoComplete(result, i + 1, repos.length);
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, repos.length) }, () => worker());
  await Promise.all(workers);

  return results;
}
