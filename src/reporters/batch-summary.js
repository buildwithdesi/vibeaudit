import { bold, red, yellow, cyan, green, gray, dim } from '../colors.js';

/**
 * @typedef {Object} BatchResult
 * @property {string} repo
 * @property {string} grade
 * @property {number} critical
 * @property {number} warning
 * @property {number} info
 * @property {number} total
 * @property {import('../rules/types.js').Finding[]} findings
 * @property {number} durationMs
 * @property {string|null} error
 */

const GRADE_EMOJI = { A: '🟢', B: '🟢', C: '🟡', D: '🟠', F: '🔴', '?': '⚪' };

/**
 * Print a terminal summary dashboard for a batch scan.
 * @param {BatchResult[]} results
 * @param {{ durationMs: number }} meta
 */
export function reportBatchTerminal(results, meta) {
  const totalRepos = results.length;
  const errors = results.filter((r) => r.error);
  const scanned = results.filter((r) => !r.error);
  const totalFindings = scanned.reduce((s, r) => s + r.total, 0);
  const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
  const totalWarning = scanned.reduce((s, r) => s + r.warning, 0);
  const totalInfo = scanned.reduce((s, r) => s + r.info, 0);

  const gradeCount = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of scanned) {
    if (gradeCount[r.grade] !== undefined) gradeCount[r.grade]++;
  }

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — BATCH SCAN'));
  console.log(dim('  Multi-repo security dashboard'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Grade distribution
  console.log(`  ${bold('Grade Distribution')}  ${green(`A:${gradeCount.A}`)} ${green(`B:${gradeCount.B}`)} ${yellow(`C:${gradeCount.C}`)} ${yellow(`D:${gradeCount.D}`)} ${red(`F:${gradeCount.F}`)}`);
  console.log(`  ${bold('Totals')}  ${red(bold(`${totalCritical}`))} ${dim('critical')}  ${yellow(bold(`${totalWarning}`))} ${dim('warnings')}  ${cyan(bold(`${totalInfo}`))} ${dim('info')}  ${dim('across')} ${bold(String(scanned.length))} ${dim('repos')}`);
  if (errors.length > 0) {
    console.log(`  ${red(`${errors.length} repo(s) failed to scan`)}`);
  }
  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Repo table — worst grades first
  const repoColWidth = Math.min(40, Math.max(...results.map((r) => r.repo.length)) + 2);

  console.log(`  ${dim('Grade')}  ${dim('Repo'.padEnd(repoColWidth))}  ${dim('Crit'.padStart(5))}  ${dim('Warn'.padStart(5))}  ${dim('Info'.padStart(5))}  ${dim('Time')}`);
  console.log(dim(`  ${'─'.repeat(repoColWidth + 35)}`));

  for (const r of results) {
    if (r.error) {
      console.log(`  ${gray('  ?')}   ${r.repo.padEnd(repoColWidth)}  ${red('ERROR: ' + r.error.slice(0, 40))}`);
      continue;
    }

    const emoji = GRADE_EMOJI[r.grade] || '⚪';
    const gradeStr = r.grade === 'F' ? red(bold(r.grade)) : r.grade === 'D' ? yellow(bold(r.grade)) : r.grade === 'C' ? yellow(r.grade) : green(r.grade);
    const critStr = r.critical > 0 ? red(bold(String(r.critical).padStart(5))) : dim(String(r.critical).padStart(5));
    const warnStr = r.warning > 0 ? yellow(String(r.warning).padStart(5)) : dim(String(r.warning).padStart(5));
    const infoStr = r.info > 0 ? cyan(String(r.info).padStart(5)) : dim(String(r.info).padStart(5));
    const timeStr = dim(`${(r.durationMs / 1000).toFixed(1)}s`);

    console.log(`  ${emoji} ${gradeStr}   ${r.repo.padEnd(repoColWidth)}  ${critStr}  ${warnStr}  ${infoStr}  ${timeStr}`);
  }

  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log(dim(`  ${totalRepos} repos · ${totalFindings} findings · ${(meta.durationMs / 1000).toFixed(1)}s total`));

  // Top critical repos
  const critRepos = scanned.filter((r) => r.critical > 0).sort((a, b) => b.critical - a.critical);
  if (critRepos.length > 0) {
    console.log('');
    console.log(red(bold('  ⛔ Repos with CRITICAL issues:')));
    for (const r of critRepos.slice(0, 10)) {
      console.log(red(`     ${r.repo} — ${r.critical} critical finding${r.critical !== 1 ? 's' : ''}`));
    }
  }

  console.log('');
}

/**
 * Generate JSON output for a batch scan (for CI/webhooks/storage).
 * @param {BatchResult[]} results
 * @param {{ durationMs: number }} meta
 * @returns {object}
 */
export function reportBatchJSON(results, meta) {
  const scanned = results.filter((r) => !r.error);

  return {
    timestamp: new Date().toISOString(),
    summary: {
      repos: results.length,
      scanned: scanned.length,
      errors: results.filter((r) => r.error).length,
      totalFindings: scanned.reduce((s, r) => s + r.total, 0),
      totalCritical: scanned.reduce((s, r) => s + r.critical, 0),
      totalWarning: scanned.reduce((s, r) => s + r.warning, 0),
      totalInfo: scanned.reduce((s, r) => s + r.info, 0),
      gradeDistribution: {
        A: scanned.filter((r) => r.grade === 'A').length,
        B: scanned.filter((r) => r.grade === 'B').length,
        C: scanned.filter((r) => r.grade === 'C').length,
        D: scanned.filter((r) => r.grade === 'D').length,
        F: scanned.filter((r) => r.grade === 'F').length,
      },
      durationMs: meta.durationMs,
    },
    repos: results.map((r) => ({
      repo: r.repo,
      grade: r.grade,
      critical: r.critical,
      warning: r.warning,
      info: r.info,
      total: r.total,
      durationMs: r.durationMs,
      error: r.error,
      findings: r.findings.map((f) => ({
        ruleId: f.ruleId,
        severity: f.severity,
        message: f.message,
        file: f.file,
        line: f.line,
        cweId: f.cweId,
        cvssScore: f.cvssScore,
        owaspCategory: f.owaspCategory,
      })),
    })),
  };
}

/**
 * Generate markdown summary for a batch scan (for GitHub issues/Slack).
 * @param {BatchResult[]} results
 * @param {{ durationMs: number }} meta
 * @returns {string}
 */
export function reportBatchMarkdown(results, meta) {
  const scanned = results.filter((r) => !r.error);
  const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
  const totalWarning = scanned.reduce((s, r) => s + r.warning, 0);
  const totalInfo = scanned.reduce((s, r) => s + r.info, 0);
  const errors = results.filter((r) => r.error);
  const now = new Date().toISOString().split('T')[0];

  const lines = [
    `# ⚗️ Vibe Audit — Batch Scan Report`,
    `**${now}** · ${results.length} repos · ${(meta.durationMs / 1000).toFixed(1)}s`,
    '',
    '## Summary',
    '',
    `| Metric | Count |`,
    `|--------|-------|`,
    `| Repos scanned | ${scanned.length} |`,
    `| Critical | ${totalCritical} |`,
    `| Warnings | ${totalWarning} |`,
    `| Info | ${totalInfo} |`,
    `| Errors | ${errors.length} |`,
    '',
    '## Repo Grades',
    '',
    '| Grade | Repo | Critical | Warnings | Info |',
    '|-------|------|----------|----------|------|',
  ];

  for (const r of results) {
    if (r.error) {
      lines.push(`| ⚪ ? | ${r.repo} | — | — | ERROR: ${r.error.slice(0, 50)} |`);
    } else {
      const emoji = GRADE_EMOJI[r.grade] || '⚪';
      lines.push(`| ${emoji} ${r.grade} | ${r.repo} | ${r.critical} | ${r.warning} | ${r.info} |`);
    }
  }

  const critRepos = scanned.filter((r) => r.critical > 0).sort((a, b) => b.critical - a.critical);
  if (critRepos.length > 0) {
    lines.push('', '## 🔴 Repos with Critical Issues', '');
    for (const r of critRepos) {
      lines.push(`### ${r.repo} (${r.critical} critical)`);
      for (const f of r.findings.filter((f) => f.severity === 'critical')) {
        lines.push(`- **${f.message}** — \`${f.file}${f.line ? ':' + f.line : ''}\`${f.cweId ? ' `' + f.cweId + '`' : ''}`);
      }
      lines.push('');
    }
  }

  lines.push('', `---`, `Generated by [Vibe Audit](https://github.com/jackdog668/vibeaudit)`);

  return lines.join('\n');
}
