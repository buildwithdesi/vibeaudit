import { audit } from './index.js';
import { fetchRepoFiles, parseGitHubTarget, fetchOrgRepos } from './github.js';

const DEFAULT_CONCURRENCY = 5;
const RATE_LIMIT_DELAY_MS = 200;

/**
 * @typedef {Object} RepoResult
 * @property {string} repo - "owner/repo"
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
 * @typedef {Object} BatchConfig
 * @property {string[]} repos - List of "owner/repo" strings
 * @property {number} [concurrency]
 * @property {string[]} [rules]
 * @property {string[]} [exclude]
 * @property {boolean} [strict]
 */

function gradeFromFindings(findings) {
  const criticals = findings.filter(f => f.severity === 'critical').length;
  const warnings = findings.filter(f => f.severity === 'warning').length;
  const infos = findings.filter(f => f.severity === 'info').length;
  if (criticals > 0) return 'F';
  if (warnings > 5) return 'D';
  if (warnings > 0) return 'C';
  if (infos > 0) return 'B';
  return 'A';
}

async function scanOneRepo(repoSpec, options = {}) {
  const start = performance.now();
  const gh = parseGitHubTarget(repoSpec);
  if (!gh) {
    return {
      repo: repoSpec,
      grade: '-',
      critical: 0,
      warning: 0,
      info: 0,
      total: 0,
      filesScanned: 0,
      durationMs: 0,
      findings: [],
      error: `Not a valid GitHub repo: ${repoSpec}`,
    };
  }

  const label = `${gh.owner}/${gh.repo}`;

  try {
    const fileSource = fetchRepoFiles(gh.owner, gh.repo);
    const { findings } = await audit(`github://${label}`, {
      format: 'json',
      fileSource,
      skipSca: true,
      rules: options.rules,
      exclude: options.exclude,
      strict: options.strict,
      _silent: true,
    });

    const critical = findings.filter(f => f.severity === 'critical').length;
    const warning = findings.filter(f => f.severity === 'warning').length;
    const info = findings.filter(f => f.severity === 'info').length;
    const durationMs = Math.round(performance.now() - start);

    return {
      repo: label,
      grade: gradeFromFindings(findings),
      critical,
      warning,
      info,
      total: findings.length,
      filesScanned: 0,
      durationMs,
      findings,
      error: null,
    };
  } catch (err) {
    return {
      repo: label,
      grade: '-',
      critical: 0,
      warning: 0,
      info: 0,
      total: 0,
      filesScanned: 0,
      durationMs: Math.round(performance.now() - start),
      findings: [],
      error: err.message,
    };
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Run batch audit across multiple repos with concurrency control.
 *
 * @param {BatchConfig} config
 * @param {{ onRepoStart?: (repo: string, index: number, total: number) => void,
 *           onRepoEnd?: (result: RepoResult, index: number, total: number) => void }} callbacks
 * @returns {Promise<RepoResult[]>}
 */
export async function batchAudit(config, callbacks = {}) {
  const { repos, concurrency = DEFAULT_CONCURRENCY, rules, exclude, strict } = config;
  const results = [];
  let index = 0;

  async function worker() {
    while (index < repos.length) {
      const i = index++;
      const repo = repos[i];
      callbacks.onRepoStart?.(repo, i, repos.length);

      await sleep(RATE_LIMIT_DELAY_MS);
      const result = await scanOneRepo(repo, { rules, exclude, strict });
      results[i] = result;

      callbacks.onRepoEnd?.(result, i, repos.length);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, repos.length) }, () => worker());
  await Promise.all(workers);

  return results;
}

/**
 * Load a batch config from a JSON file or generate one from a GitHub org.
 *
 * @param {{ file?: string, org?: string }} source
 * @returns {Promise<BatchConfig>}
 */
export async function loadBatchConfig(source) {
  if (source.org) {
    const repos = await fetchOrgRepos(source.org);
    return { repos, concurrency: DEFAULT_CONCURRENCY };
  }

  if (source.file) {
    const { readFile } = await import('node:fs/promises');
    const raw = await readFile(source.file, 'utf-8');
    const parsed = JSON.parse(raw);

    if (Array.isArray(parsed)) {
      return { repos: parsed, concurrency: DEFAULT_CONCURRENCY };
    }

    return {
      repos: parsed.repos || [],
      concurrency: parsed.concurrency || DEFAULT_CONCURRENCY,
      rules: parsed.rules,
      exclude: parsed.exclude,
      strict: parsed.strict,
    };
  }

  throw new Error('Batch config requires --batch <file.json> or --org <name>');
}

export { gradeFromFindings };
