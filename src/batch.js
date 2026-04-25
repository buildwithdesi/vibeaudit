import { readFile } from 'node:fs/promises';
import { audit } from './index.js';
import { fetchRepoFiles, parseGitHubTarget } from './github.js';
import { bold, red, yellow, cyan, green, dim } from './colors.js';

/**
 * @typedef {Object} ScanConfig
 * @property {string[]} [repos]       - Explicit list: ["owner/repo", ...]
 * @property {string}   [org]         - GitHub org — fetch all its repos
 * @property {number}   [concurrency] - Max parallel scans (default 5)
 * @property {string}   [format]      - Output format
 * @property {boolean}  [strict]      - Fail on warnings
 * @property {string[]} [rules]       - Only run these rules
 * @property {string[]} [exclude]     - Skip these rules
 * @property {string}   [slack]       - Slack webhook URL
 * @property {string}   [branch]      - Default branch to scan
 */

/**
 * @typedef {Object} RepoResult
 * @property {string}  repo
 * @property {string}  grade
 * @property {number}  critical
 * @property {number}  warning
 * @property {number}  info
 * @property {number}  total
 * @property {number}  filesScanned
 * @property {number}  durationMs
 * @property {string}  [error]
 * @property {import('./rules/types.js').Finding[]} findings
 */

/**
 * Load a scan config file.
 * @param {string} configPath
 * @returns {Promise<ScanConfig>}
 */
export async function loadScanConfig(configPath) {
  const raw = await readFile(configPath, 'utf-8');
  return JSON.parse(raw);
}

/**
 * Fetch all non-archived, non-fork repos from a GitHub org.
 * Paginates through all pages.
 * @param {string} org
 * @returns {Promise<string[]>}
 */
export async function fetchOrgRepos(org) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;

  while (true) {
    const url = `https://api.github.com/orgs/${org}/repos?per_page=100&page=${page}&type=sources&sort=updated`;
    const res = await fetch(url, { headers });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API error fetching org repos (${res.status}): ${body}`);
    }

    const data = await res.json();
    if (data.length === 0) break;

    for (const repo of data) {
      if (!repo.archived && !repo.disabled) {
        repos.push(`${org}/${repo.name}`);
      }
    }

    page++;
  }

  return repos;
}

/**
 * Resolve the full list of repos to scan.
 * @param {ScanConfig} config
 * @param {{ org?: string }} cliOverrides
 * @returns {Promise<string[]>}
 */
export async function resolveRepos(config, cliOverrides = {}) {
  const repos = new Set();

  if (config.repos) {
    for (const r of config.repos) {
      const parsed = parseGitHubTarget(r);
      if (parsed) repos.add(`${parsed.owner}/${parsed.repo}`);
    }
  }

  const org = cliOverrides.org || config.org;
  if (org) {
    const orgRepos = await fetchOrgRepos(org);
    for (const r of orgRepos) repos.add(r);
  }

  return [...repos].sort();
}

/**
 * Scan a single repo, returning a result summary.
 * @param {string} repoSlug - "owner/repo"
 * @param {Object} options
 * @returns {Promise<RepoResult>}
 */
async function scanOne(repoSlug, options) {
  const start = performance.now();
  const [owner, repo] = repoSlug.split('/');

  try {
    const fileSource = fetchRepoFiles(owner, repo, { branch: options.branch });
    const { findings } = await audit(`github://${repoSlug}`, {
      format: 'json',
      rules: options.rules,
      exclude: options.exclude,
      strict: options.strict,
      skipSca: true,
      fileSource,
      _silent: true,
    });

    const critical = findings.filter(f => f.severity === 'critical').length;
    const warning = findings.filter(f => f.severity === 'warning').length;
    const info = findings.filter(f => f.severity === 'info').length;
    const grade = critical > 0 ? 'F' : warning > 5 ? 'D' : warning > 0 ? 'C' : info > 0 ? 'B' : 'A';

    return {
      repo: repoSlug,
      grade,
      critical,
      warning,
      info,
      total: findings.length,
      filesScanned: 0,
      durationMs: Math.round(performance.now() - start),
      findings,
    };
  } catch (err) {
    return {
      repo: repoSlug,
      grade: '?',
      critical: 0,
      warning: 0,
      info: 0,
      total: 0,
      filesScanned: 0,
      durationMs: Math.round(performance.now() - start),
      error: err.message,
      findings: [],
    };
  }
}

/**
 * Run batch scanning with concurrency control.
 * @param {string[]} repos
 * @param {Object} options
 * @param {number} [options.concurrency=5]
 * @param {(repo: string, index: number, total: number) => void} [options.onStart]
 * @param {(result: RepoResult, index: number, total: number) => void} [options.onComplete]
 * @returns {Promise<RepoResult[]>}
 */
export async function scanBatch(repos, options = {}) {
  const concurrency = options.concurrency || 5;
  const results = [];
  let completed = 0;

  async function worker(queue) {
    while (queue.length > 0) {
      const { repo, index } = queue.shift();
      options.onStart?.(repo, index, repos.length);

      const result = await scanOne(repo, options);
      results.push(result);
      completed++;

      options.onComplete?.(result, completed, repos.length);
    }
  }

  const queue = repos.map((repo, index) => ({ repo, index }));
  const workers = Array.from({ length: Math.min(concurrency, repos.length) }, () => worker(queue));
  await Promise.all(workers);

  results.sort((a, b) => a.repo.localeCompare(b.repo));
  return results;
}

/**
 * Print the consolidated batch report to terminal.
 * @param {RepoResult[]} results
 */
export function batchReportTerminal(results) {
  const totalRepos = results.length;
  const errors = results.filter(r => r.error);
  const scanned = results.filter(r => !r.error);
  const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
  const totalWarning = scanned.reduce((s, r) => s + r.warning, 0);
  const totalInfo = scanned.reduce((s, r) => s + r.info, 0);
  const totalFindings = totalCritical + totalWarning + totalInfo;

  const gradeDistrib = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of scanned) {
    if (gradeDistrib[r.grade] !== undefined) gradeDistrib[r.grade]++;
  }

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — Multi-Repo Scan'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Overall grade
  const overallGrade = totalCritical > 0 ? 'F'
    : totalWarning > 10 ? 'D'
    : totalWarning > 0 ? 'C'
    : totalInfo > 0 ? 'B' : 'A';
  const gradeColor = { A: green, B: green, C: yellow, D: yellow, F: red }[overallGrade];

  console.log(`  ${gradeColor(bold(`OVERALL: ${overallGrade}`))}  ${dim('│')}  ${bold(String(totalRepos))} repos scanned`);
  console.log(`  ${red(bold(String(totalCritical)))} ${dim('critical')}  ${dim('│')}  ${yellow(bold(String(totalWarning)))} ${dim('warnings')}  ${dim('│')}  ${cyan(bold(String(totalInfo)))} ${dim('info')}`);
  console.log('');

  // Grade distribution bar
  const grades = ['A', 'B', 'C', 'D', 'F'];
  const gradeColors = { A: green, B: green, C: yellow, D: yellow, F: red };
  const bar = grades
    .filter(g => gradeDistrib[g] > 0)
    .map(g => gradeColors[g](`${g}:${gradeDistrib[g]}`))
    .join(dim(' · '));
  if (bar) console.log(`  Grades: ${bar}${errors.length > 0 ? dim(` · ?:${errors.length}`) : ''}`);
  console.log('');

  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Table header
  console.log(`  ${dim('Grade')}  ${dim('Repo'.padEnd(40))} ${dim('Crit')} ${dim('Warn')} ${dim('Info')} ${dim('Time')}`);
  console.log(dim('  ' + '─'.repeat(72)));

  for (const r of results) {
    if (r.error) {
      console.log(`  ${yellow('?')}      ${r.repo.padEnd(40)} ${dim(r.error.slice(0, 30))}`);
      continue;
    }

    const gc = { A: green, B: green, C: yellow, D: yellow, F: red }[r.grade] || dim;
    const critStr = r.critical > 0 ? red(bold(String(r.critical).padStart(4))) : dim('   0');
    const warnStr = r.warning > 0 ? yellow(String(r.warning).padStart(4)) : dim('   0');
    const infoStr = r.info > 0 ? cyan(String(r.info).padStart(4)) : dim('   0');
    const timeStr = dim(`${(r.durationMs / 1000).toFixed(1)}s`.padStart(5));

    console.log(`  ${gc(bold(r.grade))}      ${r.repo.padEnd(40)} ${critStr} ${warnStr} ${infoStr} ${timeStr}`);
  }

  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));

  // Severity bar
  if (totalFindings > 0) {
    const barWidth = 40;
    const critBar = Math.round((totalCritical / totalFindings) * barWidth);
    const warnBar = Math.round((totalWarning / totalFindings) * barWidth);
    const infoBar = barWidth - critBar - warnBar;
    const bar = red('█'.repeat(critBar)) + yellow('█'.repeat(warnBar)) + cyan('█'.repeat(Math.max(0, infoBar)));
    console.log(`  ${bar} ${dim(`${totalFindings} total findings`)}`);
  }

  // Hot spots — repos with most criticals
  const hotspots = scanned.filter(r => r.critical > 0).sort((a, b) => b.critical - a.critical).slice(0, 5);
  if (hotspots.length > 0) {
    console.log('');
    console.log(red(bold('  Hotspots (most critical issues):')));
    for (const r of hotspots) {
      console.log(`    ${red(bold(String(r.critical)))} critical  ${r.repo}`);
    }
  }

  if (errors.length > 0) {
    console.log('');
    console.log(yellow(bold(`  ${errors.length} repo(s) failed to scan:`)));
    for (const r of errors) {
      console.log(`    ${yellow('!')} ${r.repo} — ${dim(r.error)}`);
    }
  }

  console.log('');
  if (totalCritical > 0) {
    console.log(red(bold(`  ⛔ ${totalCritical} critical issues across ${hotspots.length} repos. Fix before deploying.`)));
  } else if (totalWarning > 0) {
    console.log(yellow(bold(`  ⚠️  ${totalWarning} warnings across ${scanned.filter(r => r.warning > 0).length} repos. Review before going live.`)));
  } else {
    console.log(green(bold('  ✅ All repos clean. Ship it.')));
  }
  console.log('');
}

/**
 * Build a JSON report object.
 * @param {RepoResult[]} results
 * @returns {Object}
 */
export function batchReportJSON(results) {
  const scanned = results.filter(r => !r.error);
  const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
  const totalWarning = scanned.reduce((s, r) => s + r.warning, 0);
  const totalInfo = scanned.reduce((s, r) => s + r.info, 0);

  return {
    timestamp: new Date().toISOString(),
    summary: {
      repos: results.length,
      scanned: scanned.length,
      errors: results.filter(r => r.error).length,
      totalFindings: totalCritical + totalWarning + totalInfo,
      critical: totalCritical,
      warning: totalWarning,
      info: totalInfo,
    },
    repos: results.map(r => ({
      repo: r.repo,
      grade: r.grade,
      critical: r.critical,
      warning: r.warning,
      info: r.info,
      total: r.total,
      durationMs: r.durationMs,
      error: r.error || undefined,
      findings: r.findings.map(f => ({
        ruleId: f.ruleId,
        severity: f.severity,
        file: f.file,
        line: f.line,
        message: f.message,
        cweId: f.cweId,
        cvssScore: f.cvssScore,
      })),
    })),
  };
}

/**
 * Build a Markdown summary for Slack/email.
 * @param {RepoResult[]} results
 * @returns {string}
 */
export function batchReportMarkdown(results) {
  const scanned = results.filter(r => !r.error);
  const errors = results.filter(r => r.error);
  const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
  const totalWarning = scanned.reduce((s, r) => s + r.warning, 0);
  const totalInfo = scanned.reduce((s, r) => s + r.info, 0);

  const overallGrade = totalCritical > 0 ? 'F'
    : totalWarning > 10 ? 'D'
    : totalWarning > 0 ? 'C'
    : totalInfo > 0 ? 'B' : 'A';

  const lines = [
    '# ⚗️ Vibe Audit — Multi-Repo Scan',
    '',
    `**Grade: ${overallGrade}** | ${scanned.length} repos scanned | ${new Date().toLocaleDateString()}`,
    '',
    `| Metric | Count |`,
    `|--------|-------|`,
    `| Critical | ${totalCritical} |`,
    `| Warnings | ${totalWarning} |`,
    `| Info | ${totalInfo} |`,
    `| Repos scanned | ${scanned.length} |`,
    `| Errors | ${errors.length} |`,
    '',
    '## Results',
    '',
    '| Grade | Repo | Crit | Warn | Info |',
    '|-------|------|------|------|------|',
  ];

  for (const r of results) {
    if (r.error) {
      lines.push(`| ? | ${r.repo} | — | — | ${r.error.slice(0, 40)} |`);
    } else {
      lines.push(`| ${r.grade} | ${r.repo} | ${r.critical} | ${r.warning} | ${r.info} |`);
    }
  }

  const hotspots = scanned.filter(r => r.critical > 0).sort((a, b) => b.critical - a.critical);
  if (hotspots.length > 0) {
    lines.push('', '## Hotspots', '');
    for (const r of hotspots) {
      lines.push(`- **${r.repo}** — ${r.critical} critical, ${r.warning} warnings`);
    }
  }

  if (errors.length > 0) {
    lines.push('', '## Errors', '');
    for (const r of errors) {
      lines.push(`- **${r.repo}** — ${r.error}`);
    }
  }

  lines.push('', '---', '*Generated by [Vibe Audit](https://github.com/jackdog668/vibeaudit)*');
  return lines.join('\n');
}

/**
 * Send a summary to a Slack webhook.
 * @param {RepoResult[]} results
 * @param {string} webhookUrl
 */
export async function notifySlack(results, webhookUrl) {
  const scanned = results.filter(r => !r.error);
  const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
  const totalWarning = scanned.reduce((s, r) => s + r.warning, 0);
  const errors = results.filter(r => r.error);
  const hotspots = scanned.filter(r => r.critical > 0).sort((a, b) => b.critical - a.critical);

  const totalInfo = scanned.reduce((s, r) => s + r.info, 0);
  const overallGrade = totalCritical > 0 ? 'F'
    : totalWarning > 10 ? 'D'
    : totalWarning > 0 ? 'C'
    : totalInfo > 0 ? 'B' : 'A';

  const emoji = { A: ':white_check_mark:', B: ':large_green_circle:', C: ':warning:', D: ':warning:', F: ':red_circle:' }[overallGrade] || ':question:';

  let text = `${emoji} *Vibe Audit — Morning Scan*\n`;
  text += `*Grade: ${overallGrade}* | ${scanned.length} repos | ${totalCritical} critical | ${totalWarning} warnings\n`;

  if (hotspots.length > 0) {
    text += '\n:fire: *Hotspots:*\n';
    for (const r of hotspots.slice(0, 10)) {
      text += `• \`${r.repo}\` — ${r.critical} critical, ${r.warning} warnings\n`;
    }
  }

  if (errors.length > 0) {
    text += `\n:x: ${errors.length} repo(s) failed to scan\n`;
  }

  const payload = { text };

  const res = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Slack webhook failed (${res.status}): ${body}`);
  }
}
