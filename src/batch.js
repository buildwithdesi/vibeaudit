/**
 * Batch scanner — run vibe-audit across multiple GitHub repos in one shot.
 *
 * Designed to replace a DigitalOcean scheduled bot with a single CLI command
 * (or GitHub Actions cron) that scans 70+ repos and produces an aggregated report.
 */

import { fetchRepoFiles, parseGitHubTarget } from './github.js';
import { resolveRules } from './rules/index.js';
import { CWE_MAP } from './data/cwe-map.js';

/**
 * Discover repos for a GitHub org or user via the API.
 * @param {string} owner - GitHub org or username
 * @param {{ token?: string, type?: 'org' | 'user' }} options
 * @returns {Promise<string[]>} Array of "owner/repo" strings
 */
export async function discoverRepos(owner, { token, type } = {}) {
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit-batch',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    // Try org endpoint first, fall back to user endpoint.
    const endpoint = type === 'user'
      ? `https://api.github.com/users/${owner}/repos`
      : `https://api.github.com/orgs/${owner}/repos`;

    let url = `${endpoint}?per_page=${perPage}&page=${page}&sort=updated`;
    let res = await fetch(url, { headers });

    // If org endpoint fails with 404, try user endpoint.
    if (!res.ok && res.status === 404 && type !== 'user') {
      url = `https://api.github.com/users/${owner}/repos?per_page=${perPage}&page=${page}&sort=updated`;
      res = await fetch(url, { headers });
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API error discovering repos for ${owner} (${res.status}): ${body}`);
    }

    const data = await res.json();
    if (data.length === 0) break;

    for (const repo of data) {
      if (!repo.archived && !repo.disabled && !repo.fork) {
        repos.push(`${repo.owner.login}/${repo.name}`);
      }
    }

    if (data.length < perPage) break;
    page++;
  }

  return repos;
}

/**
 * Load repo list from a JSON config file or discover from an org/user.
 * @param {object} config
 * @param {string[]} [config.repos] - Explicit list of "owner/repo" strings
 * @param {string} [config.org] - GitHub org to discover repos from
 * @param {string} [config.user] - GitHub user to discover repos from
 * @param {string[]} [config.exclude] - Repos to exclude (matched against "owner/repo")
 * @param {string[]} [config.include] - If set, only scan these repos (after discovery)
 * @returns {Promise<string[]>}
 */
export async function resolveRepoList(config) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  let repos = [];

  // Explicit repos list.
  if (config.repos?.length) {
    repos.push(...config.repos);
  }

  // Discover from org.
  if (config.org) {
    const discovered = await discoverRepos(config.org, { token, type: 'org' });
    repos.push(...discovered);
  }

  // Discover from user.
  if (config.user) {
    const discovered = await discoverRepos(config.user, { token, type: 'user' });
    repos.push(...discovered);
  }

  // Deduplicate.
  repos = [...new Set(repos)];

  // Filter: include list (if set).
  if (config.include?.length) {
    const includeSet = new Set(config.include);
    repos = repos.filter((r) => includeSet.has(r));
  }

  // Filter: exclude list.
  if (config.exclude?.length) {
    const excludeSet = new Set(config.exclude);
    repos = repos.filter((r) => !excludeSet.has(r));
  }

  return repos;
}

/**
 * Scan a single repo and return structured results.
 * @param {string} repoSlug - "owner/repo"
 * @param {object} options
 * @param {import('./rules/index.js').Rule[]} options.rules
 * @param {boolean} [options.deep]
 * @returns {Promise<{ repo: string, findings: object[], filesScanned: number, durationMs: number, error?: string }>}
 */
async function scanRepo(repoSlug, { rules, deep = false }) {
  const start = performance.now();
  const gh = parseGitHubTarget(repoSlug);
  if (!gh) {
    return { repo: repoSlug, findings: [], filesScanned: 0, durationMs: 0, error: `Invalid repo: ${repoSlug}` };
  }

  try {
    const fileSource = fetchRepoFiles(gh.owner, gh.repo);
    const findings = [];
    let filesScanned = 0;

    for await (const file of fileSource) {
      filesScanned++;
      if (deep) file._deepMode = true;
      for (const rule of rules) {
        try {
          const ruleFindings = rule.check(file);
          findings.push(...ruleFindings);
        } catch {
          // A rule should never crash the batch.
        }
      }
    }

    // Enrich with CWE/CVSS/OWASP.
    for (const f of findings) {
      const meta = CWE_MAP[f.ruleId];
      if (meta) {
        f.cweId = meta.cweId;
        f.cvssScore = meta.cvssScore;
        f.owaspCategory = meta.owaspCategory;
      }
    }

    // Sort: criticals first.
    const severityOrder = { critical: 0, warning: 1, info: 2 };
    findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    const durationMs = Math.round(performance.now() - start);
    return { repo: repoSlug, findings, filesScanned, durationMs };
  } catch (err) {
    const durationMs = Math.round(performance.now() - start);
    return { repo: repoSlug, findings: [], filesScanned: 0, durationMs, error: err.message };
  }
}

/**
 * Run batch audit across multiple repos.
 *
 * @param {string[]} repos - Array of "owner/repo" strings
 * @param {object} [options]
 * @param {string[]} [options.rules] - Rule IDs to run (empty = all)
 * @param {string[]} [options.exclude] - Rule IDs to skip
 * @param {number} [options.concurrency=3] - Max parallel scans
 * @param {boolean} [options.deep]
 * @param {(result: object) => void} [options.onRepoComplete] - Callback after each repo
 * @returns {Promise<{ results: object[], summary: object }>}
 */
export async function batchAudit(repos, options = {}) {
  const {
    rules: ruleIds,
    exclude: excludeIds,
    concurrency = 3,
    deep = false,
    onRepoComplete,
  } = options;

  const rules = resolveRules(
    ruleIds?.length ? ruleIds : [],
    excludeIds?.length ? excludeIds : []
  );

  const results = [];
  const queue = [...repos];

  // Process repos with bounded concurrency.
  async function worker() {
    while (queue.length > 0) {
      const repo = queue.shift();
      const result = await scanRepo(repo, { rules, deep });
      results.push(result);
      if (onRepoComplete) onRepoComplete(result);
    }
  }

  const workers = [];
  for (let i = 0; i < Math.min(concurrency, repos.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  // Sort results by repo name for stable output.
  results.sort((a, b) => a.repo.localeCompare(b.repo));

  // Build summary.
  const summary = buildSummary(results);
  return { results, summary };
}

/**
 * Build aggregated summary stats from batch results.
 */
function buildSummary(results) {
  let totalFindings = 0;
  let totalCritical = 0;
  let totalWarning = 0;
  let totalInfo = 0;
  let totalFiles = 0;
  let totalDuration = 0;
  let reposWithCritical = 0;
  let reposClean = 0;
  let reposFailed = 0;

  for (const r of results) {
    if (r.error) {
      reposFailed++;
      continue;
    }
    const crit = r.findings.filter((f) => f.severity === 'critical').length;
    const warn = r.findings.filter((f) => f.severity === 'warning').length;
    const info = r.findings.filter((f) => f.severity === 'info').length;
    totalFindings += r.findings.length;
    totalCritical += crit;
    totalWarning += warn;
    totalInfo += info;
    totalFiles += r.filesScanned;
    totalDuration += r.durationMs;
    if (crit > 0) reposWithCritical++;
    if (r.findings.length === 0) reposClean++;
  }

  // Grade: based on worst findings across all repos.
  const grade = totalCritical > 0 ? 'F'
    : totalWarning > 10 ? 'D'
      : totalWarning > 0 ? 'C'
        : totalInfo > 0 ? 'B' : 'A';

  return {
    reposScanned: results.length,
    reposClean,
    reposWithCritical,
    reposFailed,
    totalFindings,
    totalCritical,
    totalWarning,
    totalInfo,
    totalFiles,
    totalDurationMs: totalDuration,
    grade,
  };
}

/**
 * Format batch results as a Markdown report.
 * @param {{ results: object[], summary: object }} batchOutput
 * @returns {string}
 */
export function formatBatchMarkdown({ results, summary }) {
  const now = new Date().toISOString().split('T')[0];
  const lines = [];

  // Header.
  lines.push(`# ⚗️ Vibe Audit — Batch Scan Report`);
  lines.push(`> ${now} · ${summary.reposScanned} repos · Grade **${summary.grade}**`);
  lines.push('');

  // Executive summary.
  lines.push('## Summary');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Repos scanned | ${summary.reposScanned} |`);
  lines.push(`| Repos clean | ${summary.reposClean} |`);
  lines.push(`| Repos with criticals | ${summary.reposWithCritical} |`);
  lines.push(`| Repos failed | ${summary.reposFailed} |`);
  lines.push(`| Total findings | ${summary.totalFindings} |`);
  lines.push(`| Critical | ${summary.totalCritical} |`);
  lines.push(`| Warnings | ${summary.totalWarning} |`);
  lines.push(`| Info | ${summary.totalInfo} |`);
  lines.push(`| Files scanned | ${summary.totalFiles} |`);
  lines.push(`| Total duration | ${(summary.totalDurationMs / 1000).toFixed(1)}s |`);
  lines.push('');

  // Repos with critical findings — most important section.
  const criticalRepos = results.filter((r) => !r.error && r.findings.some((f) => f.severity === 'critical'));
  if (criticalRepos.length > 0) {
    lines.push('## 🔴 Repos with Critical Findings');
    lines.push('');
    for (const r of criticalRepos) {
      const crits = r.findings.filter((f) => f.severity === 'critical');
      const warns = r.findings.filter((f) => f.severity === 'warning');
      lines.push(`### [\`${r.repo}\`](https://github.com/${r.repo})`);
      lines.push(`${crits.length} critical · ${warns.length} warnings · ${r.filesScanned} files`);
      lines.push('');
      for (const f of crits) {
        const cweBadge = f.cweId ? ` \`${f.cweId}\`` : '';
        lines.push(`- **${f.severity.toUpperCase()}** \`${f.file}\`${f.line ? `:${f.line}` : ''}${cweBadge} — ${f.message}`);
        if (f.evidence) lines.push(`  - Evidence: \`${f.evidence}\``);
        lines.push(`  - Fix: ${f.fix}`);
      }
      lines.push('');
    }
  }

  // Repos with warnings only.
  const warningOnlyRepos = results.filter(
    (r) => !r.error && !r.findings.some((f) => f.severity === 'critical') && r.findings.some((f) => f.severity === 'warning')
  );
  if (warningOnlyRepos.length > 0) {
    lines.push('## 🟡 Repos with Warnings');
    lines.push('');
    lines.push('| Repo | Warnings | Info | Files |');
    lines.push('|------|----------|------|-------|');
    for (const r of warningOnlyRepos) {
      const warns = r.findings.filter((f) => f.severity === 'warning').length;
      const infos = r.findings.filter((f) => f.severity === 'info').length;
      lines.push(`| [\`${r.repo}\`](https://github.com/${r.repo}) | ${warns} | ${infos} | ${r.filesScanned} |`);
    }
    lines.push('');
  }

  // Clean repos.
  const cleanRepos = results.filter((r) => !r.error && r.findings.length === 0);
  if (cleanRepos.length > 0) {
    lines.push('## ✅ Clean Repos');
    lines.push('');
    lines.push(cleanRepos.map((r) => `\`${r.repo}\``).join(' · '));
    lines.push('');
  }

  // Failed repos.
  const failedRepos = results.filter((r) => r.error);
  if (failedRepos.length > 0) {
    lines.push('## ⚠️ Failed Scans');
    lines.push('');
    for (const r of failedRepos) {
      lines.push(`- \`${r.repo}\` — ${r.error}`);
    }
    lines.push('');
  }

  // Top recurring rules across all repos.
  const ruleCount = new Map();
  for (const r of results) {
    for (const f of r.findings) {
      ruleCount.set(f.ruleId, (ruleCount.get(f.ruleId) || 0) + 1);
    }
  }
  const topRules = [...ruleCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  if (topRules.length > 0) {
    lines.push('## 📊 Top Recurring Issues');
    lines.push('');
    lines.push('| Rule | Count |');
    lines.push('|------|-------|');
    for (const [ruleId, count] of topRules) {
      lines.push(`| \`${ruleId}\` | ${count} |`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('*Generated by [vibe-audit](https://github.com/jackdog668/vibeaudit) batch scanner*');

  return lines.join('\n');
}

/**
 * Format batch results as JSON.
 * @param {{ results: object[], summary: object }} batchOutput
 * @returns {string}
 */
export function formatBatchJSON({ results, summary }) {
  return JSON.stringify({ summary, results }, null, 2);
}
