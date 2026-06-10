import { fetchRepoFiles } from './github.js';
import { resolveRules } from './rules/index.js';
import { CWE_MAP } from './data/cwe-map.js';

const GITHUB_API = 'https://api.github.com';

/**
 * Fetch all repositories for a GitHub user or org (paginated).
 * @param {string} owner
 * @param {{ token?: string, includeArchived?: boolean, includeForks?: boolean }} options
 * @returns {Promise<Array<{ name: string, full_name: string, private: boolean, language: string|null, default_branch: string, archived: boolean, fork: boolean, html_url: string, updated_at: string }>>}
 */
export async function listRepos(owner, { token, includeArchived = false, includeForks = false } = {}) {
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;
  let useAuthEndpoint = false;

  // When authenticated, check if we're scanning our own account.
  if (token) {
    const meRes = await fetch(`${GITHUB_API}/user`, { headers });
    if (meRes.ok) {
      const me = await meRes.json();
      if (me.login?.toLowerCase() === owner.toLowerCase()) {
        useAuthEndpoint = true;
      }
    }
  }

  while (true) {
    let url;
    if (useAuthEndpoint) {
      url = `${GITHUB_API}/user/repos?per_page=100&page=${page}&sort=updated&affiliation=owner`;
    } else {
      url = `${GITHUB_API}/users/${owner}/repos?per_page=100&page=${page}&sort=updated&type=owner`;
    }

    let res = await fetch(url, { headers });

    // Fall back to org endpoint if user endpoint 404s.
    if (res.status === 404 && !useAuthEndpoint) {
      const orgUrl = `${GITHUB_API}/orgs/${owner}/repos?per_page=100&page=${page}&sort=updated&type=all`;
      res = await fetch(orgUrl, { headers });
    }

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`GitHub API error fetching repos for "${owner}" (${res.status}): ${body.slice(0, 200)}`);
    }

    const batch = await res.json();
    if (batch.length === 0) break;
    repos.push(...batch);
    if (batch.length < 100) break;
    page++;
  }

  return repos.filter((r) => {
    if (!includeArchived && r.archived) return false;
    if (!includeForks && r.fork) return false;
    return true;
  });
}

/**
 * Run rules against a file iterator, return raw findings.
 */
async function runRulesOnFiles(fileSource, rules) {
  const findings = [];
  let filesScanned = 0;

  for await (const file of fileSource) {
    filesScanned++;
    for (const rule of rules) {
      try {
        findings.push(...rule.check(file));
      } catch {
        // Rule crash should not abort scan.
      }
    }
  }

  return { findings, filesScanned };
}

/**
 * Scan all repos for a GitHub owner, return a consolidated report.
 *
 * @param {string} owner
 * @param {{ token?: string, format?: string, rules?: string[], exclude?: string[], concurrency?: number, includeArchived?: boolean, includeForks?: boolean, onProgress?: (msg: string) => void }} options
 * @returns {Promise<{ owner: string, scannedAt: string, repos: Array, totals: Object }>}
 */
export async function scanOrg(owner, options = {}) {
  const {
    token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN,
    rules: ruleIds,
    exclude: excludeIds,
    concurrency = 5,
    includeArchived = false,
    includeForks = false,
    onProgress = () => {},
  } = options;

  const allRepos = await listRepos(owner, { token, includeArchived, includeForks });
  onProgress(`Found ${allRepos.length} repos for ${owner}`);

  const rules = resolveRules(ruleIds, excludeIds);
  const results = [];

  // Process repos in batches to respect GitHub API rate limits.
  for (let i = 0; i < allRepos.length; i += concurrency) {
    const batch = allRepos.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(
      batch.map(async (repo) => {
        const start = performance.now();
        try {
          const fileSource = fetchRepoFiles(repo.owner?.login || owner, repo.name, {
            branch: repo.default_branch,
          });
          const { findings, filesScanned } = await runRulesOnFiles(fileSource, rules);

          for (const f of findings) {
            const meta = CWE_MAP[f.ruleId];
            if (meta) {
              f.cweId = meta.cweId;
              f.cvssScore = meta.cvssScore;
              f.owaspCategory = meta.owaspCategory;
            }
          }

          const severityOrder = { critical: 0, warning: 1, info: 2 };
          findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

          const durationMs = Math.round(performance.now() - start);
          const criticals = findings.filter((f) => f.severity === 'critical').length;
          const warnings = findings.filter((f) => f.severity === 'warning').length;
          const infos = findings.filter((f) => f.severity === 'info').length;

          return {
            repo: repo.full_name,
            html_url: repo.html_url,
            language: repo.language,
            private: repo.private,
            filesScanned,
            findings,
            summary: { critical: criticals, warning: warnings, info: infos, total: findings.length },
            durationMs,
            error: null,
          };
        } catch (err) {
          return {
            repo: repo.full_name,
            html_url: repo.html_url,
            language: repo.language,
            private: repo.private,
            filesScanned: 0,
            findings: [],
            summary: { critical: 0, warning: 0, info: 0, total: 0 },
            durationMs: Math.round(performance.now() - start),
            error: err.message,
          };
        }
      })
    );

    for (const result of batchResults) {
      const value = result.status === 'fulfilled' ? result.value : {
        repo: 'unknown',
        error: result.reason?.message || 'Unknown error',
        summary: { critical: 0, warning: 0, info: 0, total: 0 },
        findings: [],
        filesScanned: 0,
        durationMs: 0,
      };
      results.push(value);
      const icon = value.error ? 'x' : value.summary.critical > 0 ? '!' : value.summary.total > 0 ? '~' : '.';
      onProgress(`  [${icon}] ${value.repo} — ${value.summary.total} findings (${value.durationMs}ms)${value.error ? ` ERROR: ${value.error}` : ''}`);
    }
  }

  const totals = {
    repos: results.length,
    reposWithFindings: results.filter((r) => r.summary.total > 0).length,
    reposWithCriticals: results.filter((r) => r.summary.critical > 0).length,
    critical: results.reduce((s, r) => s + r.summary.critical, 0),
    warning: results.reduce((s, r) => s + r.summary.warning, 0),
    info: results.reduce((s, r) => s + r.summary.info, 0),
    total: results.reduce((s, r) => s + r.summary.total, 0),
    errors: results.filter((r) => r.error).length,
  };

  return {
    owner,
    scannedAt: new Date().toISOString(),
    rulesRun: rules.length,
    repos: results,
    totals,
  };
}

/**
 * Format an org scan report as a GitHub-flavored markdown issue body.
 * @param {Awaited<ReturnType<typeof scanOrg>>} report
 * @returns {string}
 */
export function formatOrgReportMarkdown(report) {
  const { owner, scannedAt, rulesRun, repos, totals } = report;
  const date = new Date(scannedAt).toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  const grade = totals.critical > 0 ? 'F' : totals.warning > 10 ? 'D' : totals.warning > 0 ? 'C' : totals.info > 0 ? 'B' : 'A';

  const lines = [];

  lines.push(`## Vibe Audit — Org Scan Report`);
  lines.push(``);
  lines.push(`**${date}** | ${totals.repos} repos | ${rulesRun} rules | Grade: **${grade}**`);
  lines.push(``);

  // Totals table
  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Repos scanned | ${totals.repos} |`);
  lines.push(`| Repos with findings | ${totals.reposWithFindings} |`);
  lines.push(`| Repos with criticals | ${totals.reposWithCriticals} |`);
  lines.push(`| Total critical | ${totals.critical} |`);
  lines.push(`| Total warnings | ${totals.warning} |`);
  lines.push(`| Total info | ${totals.info} |`);
  lines.push(`| Scan errors | ${totals.errors} |`);
  lines.push(``);

  // Criticals section
  const critRepos = repos.filter((r) => r.summary.critical > 0).sort((a, b) => b.summary.critical - a.summary.critical);
  if (critRepos.length > 0) {
    lines.push(`### Critical Findings`);
    lines.push(``);
    for (const r of critRepos) {
      lines.push(`<details><summary><strong>${r.repo}</strong> — ${r.summary.critical} critical, ${r.summary.warning} warnings</summary>`);
      lines.push(``);
      const crits = r.findings.filter((f) => f.severity === 'critical');
      for (const f of crits) {
        const cwe = f.cweId ? ` \`${f.cweId}\`` : '';
        const cvss = f.cvssScore ? ` CVSS:${f.cvssScore}` : '';
        lines.push(`- **${f.message}**${cwe}${cvss}`);
        lines.push(`  - File: \`${f.file}\`${f.line ? `:${f.line}` : ''}`);
        if (f.evidence) lines.push(`  - Evidence: \`${f.evidence}\``);
        lines.push(`  - Fix: ${f.fix}`);
      }
      lines.push(``);
      lines.push(`</details>`);
      lines.push(``);
    }
  }

  // Warnings section (collapsed)
  const warnRepos = repos.filter((r) => r.summary.warning > 0 && r.summary.critical === 0).sort((a, b) => b.summary.warning - a.summary.warning);
  if (warnRepos.length > 0) {
    lines.push(`### Warnings`);
    lines.push(``);
    for (const r of warnRepos) {
      lines.push(`<details><summary>${r.repo} — ${r.summary.warning} warnings</summary>`);
      lines.push(``);
      const warns = r.findings.filter((f) => f.severity === 'warning');
      for (const f of warns) {
        const cwe = f.cweId ? ` \`${f.cweId}\`` : '';
        lines.push(`- ${f.message}${cwe} — \`${f.file}\`${f.line ? `:${f.line}` : ''}`);
      }
      lines.push(``);
      lines.push(`</details>`);
      lines.push(``);
    }
  }

  // Clean repos
  const cleanRepos = repos.filter((r) => r.summary.total === 0 && !r.error);
  if (cleanRepos.length > 0) {
    lines.push(`### Clean Repos (${cleanRepos.length})`);
    lines.push(``);
    lines.push(`<details><summary>All clear</summary>`);
    lines.push(``);
    for (const r of cleanRepos) {
      lines.push(`- ${r.repo} (${r.filesScanned} files)`);
    }
    lines.push(``);
    lines.push(`</details>`);
    lines.push(``);
  }

  // Errors
  const errorRepos = repos.filter((r) => r.error);
  if (errorRepos.length > 0) {
    lines.push(`### Scan Errors (${errorRepos.length})`);
    lines.push(``);
    lines.push(`<details><summary>Failed to scan</summary>`);
    lines.push(``);
    for (const r of errorRepos) {
      lines.push(`- ${r.repo}: ${r.error}`);
    }
    lines.push(``);
    lines.push(`</details>`);
    lines.push(``);
  }

  lines.push(`---`);
  lines.push(`*Generated by [Vibe Audit](https://github.com/jackdog668/vibeaudit) v1.2.0*`);

  return lines.join('\n');
}

/**
 * Format an org scan report as terminal output.
 * @param {Awaited<ReturnType<typeof scanOrg>>} report
 */
export function formatOrgReportTerminal(report) {
  const { owner, totals, repos } = report;

  console.log('');
  console.log(`  \x1b[1m\x1b[36m⚗️  VIBE AUDIT — Org Scan: ${owner}\x1b[0m`);
  console.log(`  \x1b[2m${'─'.repeat(55)}\x1b[0m`);
  console.log('');

  const grade = totals.critical > 0 ? 'F' : totals.warning > 10 ? 'D' : totals.warning > 0 ? 'C' : totals.info > 0 ? 'B' : 'A';
  const gradeColor = { A: '\x1b[32m', B: '\x1b[32m', C: '\x1b[33m', D: '\x1b[33m', F: '\x1b[31m' }[grade];

  console.log(`  ${gradeColor}\x1b[1mGRADE: ${grade}\x1b[0m  \x1b[2m│\x1b[0m  ${totals.repos} repos  \x1b[2m│\x1b[0m  \x1b[31m\x1b[1m${totals.critical}\x1b[0m \x1b[2mcritical\x1b[0m  \x1b[2m│\x1b[0m  \x1b[33m\x1b[1m${totals.warning}\x1b[0m \x1b[2mwarnings\x1b[0m  \x1b[2m│\x1b[0m  \x1b[36m\x1b[1m${totals.info}\x1b[0m \x1b[2minfo\x1b[0m`);
  console.log('');

  // Critical repos first
  const critRepos = repos.filter((r) => r.summary.critical > 0).sort((a, b) => b.summary.critical - a.summary.critical);
  if (critRepos.length > 0) {
    console.log(`  \x1b[31m\x1b[1m  CRITICAL (${critRepos.length} repos)\x1b[0m`);
    for (const r of critRepos) {
      console.log(`    \x1b[31m●\x1b[0m  \x1b[1m${r.repo}\x1b[0m — ${r.summary.critical}C ${r.summary.warning}W \x1b[2m(${r.filesScanned} files, ${r.durationMs}ms)\x1b[0m`);
      for (const f of r.findings.filter((f) => f.severity === 'critical').slice(0, 3)) {
        console.log(`      \x1b[2m└ ${f.message} — ${f.file}${f.line ? `:${f.line}` : ''}\x1b[0m`);
      }
      const remaining = r.summary.critical - 3;
      if (remaining > 0) console.log(`      \x1b[2m└ ...and ${remaining} more criticals\x1b[0m`);
    }
    console.log('');
  }

  // Warning repos
  const warnRepos = repos.filter((r) => r.summary.warning > 0 && r.summary.critical === 0).sort((a, b) => b.summary.warning - a.summary.warning);
  if (warnRepos.length > 0) {
    console.log(`  \x1b[33m\x1b[1m  WARNINGS (${warnRepos.length} repos)\x1b[0m`);
    for (const r of warnRepos) {
      console.log(`    \x1b[33m▲\x1b[0m  ${r.repo} — ${r.summary.warning}W \x1b[2m(${r.filesScanned} files)\x1b[0m`);
    }
    console.log('');
  }

  // Summary
  const cleanCount = repos.filter((r) => r.summary.total === 0 && !r.error).length;
  const errorCount = repos.filter((r) => r.error).length;

  console.log(`  \x1b[2m${'─'.repeat(55)}\x1b[0m`);
  console.log(`  \x1b[32m✓\x1b[0m ${cleanCount} clean  \x1b[2m│\x1b[0m  \x1b[31m✗\x1b[0m ${totals.reposWithFindings} with findings  \x1b[2m│\x1b[0m  \x1b[2m${errorCount} errors\x1b[0m`);
  console.log('');
}
