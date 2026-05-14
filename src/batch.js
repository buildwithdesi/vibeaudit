import { audit } from './index.js';
import { fetchRepoFiles, parseGitHubTarget } from './github.js';

/**
 * Run vibe-audit across multiple repos with concurrency control.
 *
 * @param {string[]} repos - Array of repo targets ("owner/repo" or full GitHub URLs)
 * @param {{ concurrency?: number, rules?: string[], exclude?: string[], strict?: boolean }} options
 * @returns {Promise<{ results: RepoResult[], summary: BatchSummary }>}
 *
 * @typedef {{ repo: string, grade: string, findings: import('./rules/types.js').Finding[], criticals: number, warnings: number, infos: number, filesScanned: number, durationMs: number, error?: string }} RepoResult
 * @typedef {{ totalRepos: number, scanned: number, failed: number, totalFindings: number, totalCriticals: number, totalWarnings: number, totalInfos: number, durationMs: number }} BatchSummary
 */
export async function batchAudit(repos, options = {}) {
  const { concurrency = 5, rules, exclude, strict } = options;
  const start = performance.now();
  const results = [];

  // Process repos in batches to respect concurrency limit.
  for (let i = 0; i < repos.length; i += concurrency) {
    const batch = repos.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(
      batch.map((repo) => scanOneRepo(repo, { rules, exclude, strict }))
    );

    for (let j = 0; j < batchResults.length; j++) {
      const settled = batchResults[j];
      if (settled.status === 'fulfilled') {
        results.push(settled.value);
      } else {
        results.push({
          repo: batch[j],
          grade: '?',
          findings: [],
          criticals: 0,
          warnings: 0,
          infos: 0,
          filesScanned: 0,
          durationMs: 0,
          error: settled.reason?.message || 'Unknown error',
        });
      }
    }
  }

  const durationMs = Math.round(performance.now() - start);

  const summary = {
    totalRepos: repos.length,
    scanned: results.filter((r) => !r.error).length,
    failed: results.filter((r) => r.error).length,
    totalFindings: results.reduce((sum, r) => sum + r.findings.length, 0),
    totalCriticals: results.reduce((sum, r) => sum + r.criticals, 0),
    totalWarnings: results.reduce((sum, r) => sum + r.warnings, 0),
    totalInfos: results.reduce((sum, r) => sum + r.infos, 0),
    durationMs,
  };

  return { results, summary };
}

async function scanOneRepo(repoTarget, { rules, exclude, strict }) {
  const start = performance.now();

  const gh = parseGitHubTarget(repoTarget);
  if (!gh) {
    throw new Error(`Not a valid GitHub repo target: ${repoTarget}`);
  }

  const label = `${gh.owner}/${gh.repo}`;
  const fileSource = fetchRepoFiles(gh.owner, gh.repo);

  const { findings } = await audit(`github://${label}`, {
    format: 'json',
    fileSource,
    skipSca: true,
    rules,
    exclude,
    strict,
    // Suppress console output — we collect results programmatically.
    silent: true,
  });

  const criticals = findings.filter((f) => f.severity === 'critical').length;
  const warnings = findings.filter((f) => f.severity === 'warning').length;
  const infos = findings.filter((f) => f.severity === 'info').length;

  const grade =
    criticals > 0 ? 'F' : warnings > 5 ? 'D' : warnings > 0 ? 'C' : infos > 0 ? 'B' : 'A';

  return {
    repo: label,
    grade,
    findings,
    criticals,
    warnings,
    infos,
    filesScanned: findings.length > 0 ? new Set(findings.map((f) => f.file)).size : 0,
    durationMs: Math.round(performance.now() - start),
  };
}

/**
 * Load a repo list from a JSON config file.
 *
 * Supports two formats:
 *   - Array of strings: ["owner/repo1", "owner/repo2"]
 *   - Object with repos key: { "repos": [...], "concurrency": 5 }
 *
 * @param {string} configPath
 * @returns {Promise<{ repos: string[], concurrency?: number }>}
 */
export async function loadRepoList(configPath) {
  const { readFile } = await import('node:fs/promises');
  const raw = await readFile(configPath, 'utf-8');
  const data = JSON.parse(raw);

  if (Array.isArray(data)) {
    return { repos: data };
  }

  if (data.repos && Array.isArray(data.repos)) {
    return { repos: data.repos, concurrency: data.concurrency };
  }

  throw new Error(`Invalid repo list format in ${configPath}. Expected an array or { "repos": [...] }.`);
}
