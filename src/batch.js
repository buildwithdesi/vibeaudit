import { audit } from './index.js';
import { fetchRepoFiles, listRepos } from './github.js';
import { readFile } from 'node:fs/promises';
import { bold, red, yellow, cyan, green, gray, dim } from './colors.js';

/**
 * @typedef {Object} RepoTarget
 * @property {string} owner
 * @property {string} repo
 */

/**
 * @typedef {Object} RepoResult
 * @property {string} fullName
 * @property {import('./rules/types.js').Finding[]} findings
 * @property {number} criticals
 * @property {number} warnings
 * @property {number} infos
 * @property {number} filesScanned
 * @property {number} durationMs
 * @property {string} grade
 * @property {string|null} error
 */

/**
 * Load repo list from a file. One repo per line as owner/repo.
 * Lines starting with # are comments, blank lines are skipped.
 *
 * @param {string} filePath
 * @returns {Promise<RepoTarget[]>}
 */
export async function loadReposFromFile(filePath) {
  const content = await readFile(filePath, 'utf-8');
  return content
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => {
      const [owner, repo] = l.split('/');
      if (!owner || !repo) throw new Error(`Invalid repo format: "${l}" — expected owner/repo`);
      return { owner, repo };
    });
}

/**
 * Load repo list from a GitHub org (fetches all non-archived repos).
 *
 * @param {string} org
 * @returns {Promise<RepoTarget[]>}
 */
export async function loadReposFromOrg(org) {
  const repos = await listRepos(org);
  return repos.map((r) => ({ owner: r.owner, repo: r.repo }));
}

function gradeFromFindings(criticals, warnings, infos) {
  if (criticals > 0) return 'F';
  if (warnings > 5) return 'D';
  if (warnings > 0) return 'C';
  if (infos > 0) return 'B';
  return 'A';
}

/**
 * Scan a single repo and return structured results.
 *
 * @param {RepoTarget} target
 * @param {Object} options
 * @returns {Promise<RepoResult>}
 */
async function scanRepo(target, options = {}) {
  const fullName = `${target.owner}/${target.repo}`;
  try {
    const fileSource = fetchRepoFiles(target.owner, target.repo);
    const { findings, meta } = await audit(`github://${fullName}`, {
      ...options,
      fileSource,
      skipSca: true,
      silent: true,
    });

    const criticals = findings.filter((f) => f.severity === 'critical').length;
    const warnings = findings.filter((f) => f.severity === 'warning').length;
    const infos = findings.filter((f) => f.severity === 'info').length;

    return {
      fullName,
      findings,
      criticals,
      warnings,
      infos,
      filesScanned: meta.filesScanned,
      durationMs: meta.durationMs,
      grade: gradeFromFindings(criticals, warnings, infos),
      error: null,
    };
  } catch (err) {
    return {
      fullName,
      findings: [],
      criticals: 0,
      warnings: 0,
      infos: 0,
      filesScanned: 0,
      durationMs: 0,
      grade: '?',
      error: err.message,
    };
  }
}

/**
 * Run batch audit across multiple repos with concurrency control.
 *
 * @param {RepoTarget[]} repos
 * @param {Object} options
 * @param {number} [options.concurrency=5]
 * @param {string[]} [options.rules]
 * @param {string[]} [options.exclude]
 * @param {'terminal'|'json'|'markdown'} [options.format='terminal']
 * @param {boolean} [options.strict]
 * @returns {Promise<RepoResult[]>}
 */
export async function batchAudit(repos, options = {}) {
  const { concurrency = 5, format = 'terminal', ...auditOpts } = options;
  const results = [];
  const total = repos.length;
  let completed = 0;

  const showProgress = format === 'terminal';

  if (showProgress) {
    console.log('');
    console.log(bold('  ⚗️  VIBE AUDIT — Batch Scan'));
    console.log(dim(`  Scanning ${total} repositories (concurrency: ${concurrency})`));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log('');
  }

  const queue = [...repos];

  async function worker() {
    while (queue.length > 0) {
      const target = queue.shift();
      if (!target) break;

      const fullName = `${target.owner}/${target.repo}`;

      if (showProgress) {
        completed++;
        const pct = Math.round((completed / total) * 100);
        process.stdout.write(`  ${dim(`[${completed}/${total} ${pct}%]`)} Scanning ${cyan(fullName)}...`);
      }

      const result = await scanRepo(target, auditOpts);
      results.push(result);

      if (showProgress) {
        if (result.error) {
          process.stdout.write(` ${red('ERR')}\n`);
        } else if (result.criticals > 0) {
          process.stdout.write(` ${red(bold(`${result.criticals}C`))} ${yellow(`${result.warnings}W`)} ${dim(`(${result.durationMs}ms)`)}\n`);
        } else if (result.warnings > 0) {
          process.stdout.write(` ${yellow(`${result.warnings}W`)} ${dim(`(${result.durationMs}ms)`)}\n`);
        } else {
          process.stdout.write(` ${green('OK')} ${dim(`(${result.durationMs}ms)`)}\n`);
        }
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, total) }, () => worker());
  await Promise.all(workers);

  results.sort((a, b) => b.criticals - a.criticals || b.warnings - a.warnings);

  return results;
}

/**
 * Print the consolidated batch report to stdout.
 *
 * @param {RepoResult[]} results
 * @param {'terminal'|'json'|'markdown'} format
 */
export function batchReport(results, format) {
  switch (format) {
    case 'json':
      return batchReportJSON(results);
    case 'markdown':
      return batchReportMarkdown(results);
    default:
      return batchReportTerminal(results);
  }
}

// ─── Terminal ─────────────────────────────────────────────────────────────────

function batchReportTerminal(results) {
  const totalRepos = results.length;
  const failed = results.filter((r) => r.error);
  const scanned = results.filter((r) => !r.error);
  const totalCrit = scanned.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = scanned.reduce((s, r) => s + r.warnings, 0);
  const totalInfo = scanned.reduce((s, r) => s + r.infos, 0);
  const totalFiles = scanned.reduce((s, r) => s + r.filesScanned, 0);
  const reposWithCrit = scanned.filter((r) => r.criticals > 0);
  const cleanRepos = scanned.filter((r) => r.grade === 'A');

  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log(bold('  ⚗️  BATCH SUMMARY'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Grade distribution
  const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of scanned) grades[r.grade]++;

  console.log(`  ${bold('Repos scanned:')}  ${totalRepos}${failed.length > 0 ? red(` (${failed.length} failed)`) : ''}`);
  console.log(`  ${bold('Files scanned:')}  ${totalFiles}`);
  console.log(`  ${bold('Total findings:')} ${red(bold(String(totalCrit)))} critical · ${yellow(String(totalWarn))} warnings · ${cyan(String(totalInfo))} info`);
  console.log('');

  // Grade bar
  const gradeBar = [
    green(`A:${grades.A}`),
    green(`B:${grades.B}`),
    yellow(`C:${grades.C}`),
    yellow(`D:${grades.D}`),
    red(`F:${grades.F}`),
  ].join(dim(' │ '));
  console.log(`  ${bold('Grades:')} ${gradeBar}`);
  console.log('');

  // Repos with criticals
  if (reposWithCrit.length > 0) {
    console.log(red(bold('  ⛔ Repos with CRITICAL findings:')));
    console.log('');
    for (const r of reposWithCrit) {
      console.log(`    ${red('●')} ${bold(r.fullName)} — ${red(bold(`${r.criticals}`))} critical, ${yellow(`${r.warnings}`)} warnings`);
      const topFindings = r.findings
        .filter((f) => f.severity === 'critical')
        .slice(0, 3);
      for (const f of topFindings) {
        console.log(`      ${dim('└')} ${f.message} ${gray(`(${f.file}${f.line ? ':' + f.line : ''})`)}`);
      }
      if (r.criticals > 3) {
        console.log(`      ${dim(`└ ... and ${r.criticals - 3} more`)}`);
      }
    }
    console.log('');
  }

  // Repos with warnings only
  const warnOnly = scanned.filter((r) => r.criticals === 0 && r.warnings > 0);
  if (warnOnly.length > 0) {
    console.log(yellow(bold('  ⚠️  Repos with warnings:')));
    console.log('');
    for (const r of warnOnly) {
      console.log(`    ${yellow('▲')} ${r.fullName} — ${yellow(`${r.warnings}`)} warnings`);
    }
    console.log('');
  }

  // Clean repos
  if (cleanRepos.length > 0) {
    console.log(green(bold(`  ✅ ${cleanRepos.length} repos are clean (Grade A)`)));
    console.log('');
  }

  // Failed repos
  if (failed.length > 0) {
    console.log(red(bold('  ❌ Failed to scan:')));
    for (const r of failed) {
      console.log(`    ${red('✗')} ${r.fullName} — ${dim(r.error)}`);
    }
    console.log('');
  }

  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log(dim(`  Scan complete. Run ${cyan('vibeaudit <owner/repo>')} for a detailed single-repo report.`));
  console.log('');
}

// ─── JSON ─────────────────────────────────────────────────────────────────────

function batchReportJSON(results) {
  const scanned = results.filter((r) => !r.error);
  const output = {
    summary: {
      totalRepos: results.length,
      scanned: scanned.length,
      failed: results.length - scanned.length,
      totalCritical: scanned.reduce((s, r) => s + r.criticals, 0),
      totalWarnings: scanned.reduce((s, r) => s + r.warnings, 0),
      totalInfo: scanned.reduce((s, r) => s + r.infos, 0),
      totalFiles: scanned.reduce((s, r) => s + r.filesScanned, 0),
      grades: { A: 0, B: 0, C: 0, D: 0, F: 0 },
      timestamp: new Date().toISOString(),
    },
    repos: results.map((r) => ({
      repo: r.fullName,
      grade: r.grade,
      criticals: r.criticals,
      warnings: r.warnings,
      infos: r.infos,
      filesScanned: r.filesScanned,
      durationMs: r.durationMs,
      error: r.error,
      findings: r.findings,
    })),
  };

  for (const r of scanned) output.summary.grades[r.grade]++;

  console.log(JSON.stringify(output, null, 2));
}

// ─── Markdown ─────────────────────────────────────────────────────────────────

function batchReportMarkdown(results) {
  const scanned = results.filter((r) => !r.error);
  const totalCrit = scanned.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = scanned.reduce((s, r) => s + r.warnings, 0);
  const totalInfo = scanned.reduce((s, r) => s + r.infos, 0);
  const totalFiles = scanned.reduce((s, r) => s + r.filesScanned, 0);
  const failed = results.filter((r) => r.error);

  const lines = [
    '# ⚗️ Vibe Audit — Batch Report',
    '',
    `**${new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}**`,
    '',
    '## Summary',
    '',
    '| Metric | Value |',
    '|--------|-------|',
    `| Repos scanned | ${scanned.length} |`,
    `| Files scanned | ${totalFiles} |`,
    `| Critical findings | ${totalCrit} |`,
    `| Warnings | ${totalWarn} |`,
    `| Info | ${totalInfo} |`,
    '',
  ];

  // Grade distribution
  const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of scanned) grades[r.grade]++;
  lines.push('**Grade distribution:** ' + Object.entries(grades).map(([g, c]) => `${g}: ${c}`).join(' | '));
  lines.push('');

  // Scorecard table
  lines.push('## Scorecard');
  lines.push('');
  lines.push('| Repo | Grade | Critical | Warnings | Info | Files |');
  lines.push('|------|-------|----------|----------|------|-------|');

  for (const r of scanned) {
    const gradeEmoji = { A: '🟢', B: '🟢', C: '🟡', D: '🟡', F: '🔴' }[r.grade];
    lines.push(`| ${r.fullName} | ${gradeEmoji} ${r.grade} | ${r.criticals} | ${r.warnings} | ${r.infos} | ${r.filesScanned} |`);
  }
  lines.push('');

  // Critical findings breakdown
  const reposWithCrit = scanned.filter((r) => r.criticals > 0);
  if (reposWithCrit.length > 0) {
    lines.push('## 🔴 Critical Findings');
    lines.push('');
    for (const r of reposWithCrit) {
      lines.push(`### ${r.fullName}`);
      lines.push('');
      const critFindings = r.findings.filter((f) => f.severity === 'critical');
      for (const f of critFindings) {
        lines.push(`- **${f.message}** — \`${f.file}${f.line ? ':' + f.line : ''}\`${f.cweId ? ' `' + f.cweId + '`' : ''}`);
        if (f.evidence) lines.push(`  - Evidence: \`${f.evidence}\``);
        lines.push(`  - Fix: ${f.fix}`);
      }
      lines.push('');
    }
  }

  // Failed repos
  if (failed.length > 0) {
    lines.push('## ❌ Failed');
    lines.push('');
    for (const r of failed) {
      lines.push(`- **${r.fullName}** — ${r.error}`);
    }
    lines.push('');
  }

  console.log(lines.join('\n'));
}
