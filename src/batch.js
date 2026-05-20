import { readFile } from 'node:fs/promises';
import { audit } from './index.js';
import { parseGitHubTarget, fetchRepoFiles } from './github.js';
import { bold, red, yellow, cyan, green, dim } from './colors.js';

const DEFAULT_CONCURRENCY = 5;

/**
 * Load a repos list from a JSON file.
 * Supports two formats:
 *   - Array of strings:  ["owner/repo", "owner/repo2"]
 *   - Array of objects:  [{ "repo": "owner/repo", "rules": [...], "exclude": [...] }]
 *
 * @param {string} filePath
 * @returns {Promise<Array<{ repo: string, rules?: string[], exclude?: string[] }>>}
 */
export async function loadRepoList(filePath) {
  const raw = await readFile(filePath, 'utf8');
  const parsed = JSON.parse(raw);

  if (!Array.isArray(parsed)) {
    throw new Error(`Expected an array in ${filePath}`);
  }

  return parsed.map((entry) => {
    if (typeof entry === 'string') return { repo: entry };
    if (typeof entry === 'object' && entry.repo) return entry;
    throw new Error(`Invalid entry in ${filePath}: ${JSON.stringify(entry)}`);
  });
}

/**
 * Scan a single repo and return results without printing.
 *
 * @param {{ repo: string, rules?: string[], exclude?: string[] }} entry
 * @param {Object} globalOptions
 * @returns {Promise<{ repo: string, findings: Array, filesScanned: number, rulesRun: number, durationMs: number, error?: string }>}
 */
async function scanOne(entry, globalOptions) {
  const start = performance.now();
  const gh = parseGitHubTarget(entry.repo);

  if (!gh) {
    return {
      repo: entry.repo,
      findings: [],
      filesScanned: 0,
      rulesRun: 0,
      durationMs: 0,
      error: `Not a valid GitHub target: ${entry.repo}`,
    };
  }

  const label = `${gh.owner}/${gh.repo}`;

  try {
    const options = {
      format: 'json',
      silent: true,
      rules: entry.rules || globalOptions.rules,
      exclude: entry.exclude || globalOptions.exclude,
      strict: globalOptions.strict,
      skipSca: true,
      fileSource: fetchRepoFiles(gh.owner, gh.repo),
    };

    const result = await audit(`github://${label}`, options);

    return {
      repo: label,
      findings: result.findings,
      filesScanned: result.filesScanned,
      rulesRun: result.rulesRun,
      durationMs: result.durationMs,
    };
  } catch (err) {
    const durationMs = Math.round(performance.now() - start);
    return {
      repo: label,
      findings: [],
      filesScanned: 0,
      rulesRun: 0,
      durationMs,
      error: err.message,
    };
  }
}

/**
 * Run batch audit across multiple repos with concurrency control.
 *
 * @param {Array<{ repo: string, rules?: string[], exclude?: string[] }>} repos
 * @param {Object} options
 * @param {number} [options.concurrency]
 * @param {string[]} [options.rules]
 * @param {string[]} [options.exclude]
 * @param {boolean} [options.strict]
 * @param {'terminal' | 'json' | 'markdown'} [options.format]
 * @returns {Promise<{ results: Array, summary: Object }>}
 */
export async function batchAudit(repos, options = {}) {
  const concurrency = options.concurrency || DEFAULT_CONCURRENCY;
  const format = options.format || 'terminal';
  const results = [];
  const total = repos.length;
  let completed = 0;

  if (format === 'terminal') {
    console.log('');
    console.log(bold('  ⚗️  VIBE AUDIT — Batch Scan'));
    console.log(dim(`  Scanning ${total} repositories (concurrency: ${concurrency})`));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log('');
  }

  const queue = [...repos];

  async function worker() {
    while (queue.length > 0) {
      const entry = queue.shift();
      if (!entry) break;

      if (format === 'terminal') {
        process.stdout.write(dim(`  [${completed + 1}/${total}] Scanning ${entry.repo}...`));
      }

      const result = await scanOne(entry, options);
      results.push(result);
      completed++;

      if (format === 'terminal') {
        const critCount = result.findings.filter((f) => f.severity === 'critical').length;
        const warnCount = result.findings.filter((f) => f.severity === 'warning').length;

        if (result.error) {
          process.stdout.write(`\r  [${completed}/${total}] ${red('✗')} ${result.repo} — ${red(result.error)}\n`);
        } else if (critCount > 0) {
          process.stdout.write(`\r  [${completed}/${total}] ${red('●')} ${result.repo} — ${red(bold(`${critCount} critical`))}${warnCount > 0 ? `, ${yellow(`${warnCount} warnings`)}` : ''} ${dim(`(${result.durationMs}ms)`)}\n`);
        } else if (warnCount > 0) {
          process.stdout.write(`\r  [${completed}/${total}] ${yellow('▲')} ${result.repo} — ${yellow(`${warnCount} warnings`)} ${dim(`(${result.durationMs}ms)`)}\n`);
        } else {
          process.stdout.write(`\r  [${completed}/${total}] ${green('✓')} ${result.repo} — ${green('clean')} ${dim(`(${result.durationMs}ms)`)}\n`);
        }
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, repos.length) }, () => worker());
  await Promise.all(workers);

  const summary = buildSummary(results);

  if (format === 'terminal') {
    printBatchTerminal(results, summary);
  } else if (format === 'json') {
    printBatchJSON(results, summary);
  } else if (format === 'markdown') {
    printBatchMarkdown(results, summary);
  }

  return { results, summary };
}

function buildSummary(results) {
  let totalFindings = 0;
  let totalCritical = 0;
  let totalWarning = 0;
  let totalInfo = 0;
  let totalErrors = 0;
  let totalDuration = 0;

  for (const r of results) {
    if (r.error) {
      totalErrors++;
      continue;
    }
    totalDuration += r.durationMs;
    for (const f of r.findings) {
      totalFindings++;
      if (f.severity === 'critical') totalCritical++;
      else if (f.severity === 'warning') totalWarning++;
      else totalInfo++;
    }
  }

  const reposWithCritical = results.filter((r) => r.findings.some((f) => f.severity === 'critical'));
  const cleanRepos = results.filter((r) => !r.error && r.findings.length === 0);

  return {
    totalRepos: results.length,
    totalFindings,
    totalCritical,
    totalWarning,
    totalInfo,
    totalErrors,
    totalDuration,
    reposWithCritical: reposWithCritical.map((r) => r.repo),
    cleanRepos: cleanRepos.map((r) => r.repo),
  };
}

function printBatchTerminal(results, summary) {
  console.log('');
  console.log(dim('  ═════════════════════════════════════════════════════════════'));
  console.log(bold('  ⚗️  BATCH SUMMARY'));
  console.log(dim('  ═════════════════════════════════════════════════════════════'));
  console.log('');

  console.log(`  ${bold('Repos scanned:')}  ${summary.totalRepos}`);
  console.log(`  ${bold('Total findings:')} ${summary.totalFindings}`);
  console.log(`    ${red(bold(`${summary.totalCritical}`))} ${dim('critical')}  ${yellow(bold(`${summary.totalWarning}`))} ${dim('warnings')}  ${cyan(bold(`${summary.totalInfo}`))} ${dim('info')}`);
  if (summary.totalErrors > 0) {
    console.log(`  ${red(bold(`${summary.totalErrors}`))} ${dim('repos failed')}`);
  }
  console.log(`  ${dim(`Total scan time: ${Math.round(summary.totalDuration / 1000)}s`)}`);
  console.log('');

  if (summary.reposWithCritical.length > 0) {
    console.log(red(bold('  ⛔ Repos with CRITICAL issues:')));
    for (const repo of summary.reposWithCritical) {
      const r = results.find((x) => x.repo === repo);
      const critCount = r.findings.filter((f) => f.severity === 'critical').length;
      console.log(`    ${red('●')} ${bold(repo)} (${critCount} critical)`);
    }
    console.log('');
  }

  if (summary.cleanRepos.length > 0) {
    console.log(green(`  ✅ ${summary.cleanRepos.length} repos clean`));
    console.log('');
  }

  // Top offenders table
  const ranked = [...results]
    .filter((r) => !r.error && r.findings.length > 0)
    .sort((a, b) => {
      const aCrit = a.findings.filter((f) => f.severity === 'critical').length;
      const bCrit = b.findings.filter((f) => f.severity === 'critical').length;
      if (aCrit !== bCrit) return bCrit - aCrit;
      return b.findings.length - a.findings.length;
    })
    .slice(0, 10);

  if (ranked.length > 0) {
    console.log(bold('  Top issues by repo:'));
    console.log(dim('  ───────────────────────────────────────────'));
    for (const r of ranked) {
      const crit = r.findings.filter((f) => f.severity === 'critical').length;
      const warn = r.findings.filter((f) => f.severity === 'warning').length;
      const info = r.findings.filter((f) => f.severity === 'info').length;
      const parts = [];
      if (crit > 0) parts.push(red(bold(`${crit}C`)));
      if (warn > 0) parts.push(yellow(`${warn}W`));
      if (info > 0) parts.push(cyan(`${info}I`));
      console.log(`  ${bold(r.repo.padEnd(40))} ${parts.join(dim(' · '))}`);
    }
    console.log('');
  }
}

function printBatchJSON(results, summary) {
  const output = {
    summary,
    repos: results.map((r) => ({
      repo: r.repo,
      error: r.error || null,
      durationMs: r.durationMs,
      critical: r.findings.filter((f) => f.severity === 'critical').length,
      warning: r.findings.filter((f) => f.severity === 'warning').length,
      info: r.findings.filter((f) => f.severity === 'info').length,
      findings: r.findings,
    })),
  };
  console.log(JSON.stringify(output, null, 2));
}

function printBatchMarkdown(results, summary) {
  const lines = [
    '# ⚗️ Vibe Audit — Batch Scan Report',
    '',
    `> Scanned **${summary.totalRepos}** repositories on ${new Date().toISOString().split('T')[0]}`,
    '',
    '## Summary',
    '',
    '| Metric | Count |',
    '|--------|-------|',
    `| Repos scanned | ${summary.totalRepos} |`,
    `| Critical | ${summary.totalCritical} |`,
    `| Warnings | ${summary.totalWarning} |`,
    `| Info | ${summary.totalInfo} |`,
    `| Errors | ${summary.totalErrors} |`,
    '',
  ];

  if (summary.reposWithCritical.length > 0) {
    lines.push('## Repos with Critical Issues', '');
    for (const repo of summary.reposWithCritical) {
      const r = results.find((x) => x.repo === repo);
      const critCount = r.findings.filter((f) => f.severity === 'critical').length;
      lines.push(`- **${repo}** — ${critCount} critical`);
    }
    lines.push('');
  }

  lines.push('## All Repos', '');
  lines.push('| Repo | Critical | Warnings | Info | Status |');
  lines.push('|------|----------|----------|------|--------|');

  for (const r of results) {
    if (r.error) {
      lines.push(`| ${r.repo} | — | — | — | Error: ${r.error} |`);
      continue;
    }
    const crit = r.findings.filter((f) => f.severity === 'critical').length;
    const warn = r.findings.filter((f) => f.severity === 'warning').length;
    const info = r.findings.filter((f) => f.severity === 'info').length;
    const status = crit > 0 ? 'CRITICAL' : warn > 0 ? 'WARNING' : 'CLEAN';
    lines.push(`| ${r.repo} | ${crit} | ${warn} | ${info} | ${status} |`);
  }
  lines.push('');

  // Detail section for critical findings
  const withCriticals = results.filter((r) => r.findings.some((f) => f.severity === 'critical'));
  if (withCriticals.length > 0) {
    lines.push('## Critical Finding Details', '');
    for (const r of withCriticals) {
      lines.push(`### ${r.repo}`, '');
      const crits = r.findings.filter((f) => f.severity === 'critical');
      for (const f of crits) {
        const cweStr = f.cweId ? ` \`${f.cweId}\`` : '';
        lines.push(`- **${f.message}**${cweStr}`);
        lines.push(`  - File: \`${f.file}\`${f.line ? `:${f.line}` : ''}`);
        if (f.evidence) lines.push(`  - Evidence: \`${f.evidence}\``);
        lines.push(`  - Fix: ${f.fix}`);
      }
      lines.push('');
    }
  }

  console.log(lines.join('\n'));
}
