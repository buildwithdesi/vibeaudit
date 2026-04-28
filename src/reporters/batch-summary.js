import { bold, red, yellow, cyan, green, dim } from '../colors.js';

const GRADE_COLORS = { A: green, B: green, C: yellow, D: yellow, F: red };

export function reportBatchTerminal(results) {
  const succeeded = results.filter((r) => !r.error);
  const failed = results.filter((r) => r.error);
  const totalCrit = succeeded.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = succeeded.reduce((s, r) => s + r.warnings, 0);
  const totalInfo = succeeded.reduce((s, r) => s + r.infos, 0);
  const totalFindings = totalCrit + totalWarn + totalInfo;

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — BATCH SCAN'));
  console.log(dim('  Multi-repo security dashboard'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  const overallGrade = totalCrit > 0 ? 'F' : totalWarn > 10 ? 'D' : totalWarn > 0 ? 'C' : totalInfo > 0 ? 'B' : 'A';
  const gc = GRADE_COLORS[overallGrade] || dim;
  console.log(`  ${gc(bold(`OVERALL: ${overallGrade}`))}  ${dim('│')}  ${bold(String(results.length))} repos  ${dim('│')}  ${red(bold(String(totalCrit)))} ${dim('critical')}  ${dim('│')}  ${yellow(bold(String(totalWarn)))} ${dim('warnings')}  ${dim('│')}  ${cyan(bold(String(totalInfo)))} ${dim('info')}`);
  console.log('');

  // Table header
  const repoCol = 40;
  const pad = (s, w) => s + ' '.repeat(Math.max(0, w - stripAnsi(s).length));
  console.log(dim(`  ${pad('REPO', repoCol)} GRADE  CRIT  WARN  INFO  TOTAL`));
  console.log(dim('  ' + '─'.repeat(repoCol + 36)));

  // Sort: worst grades first
  const gradeRank = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
  const sorted = [...results].sort((a, b) => (gradeRank[a.grade] ?? 5) - (gradeRank[b.grade] ?? 5) || b.criticals - a.criticals || b.warnings - a.warnings);

  for (const r of sorted) {
    const gc2 = r.error ? dim : (GRADE_COLORS[r.grade] || dim);
    const name = pad(r.repo.length > repoCol - 2 ? r.repo.slice(0, repoCol - 4) + '..' : r.repo, repoCol);
    const grade = gc2(bold(pad(r.grade, 5)));
    const crit = r.criticals > 0 ? red(bold(pad(String(r.criticals), 4))) : dim(pad('0', 4));
    const warn = r.warnings > 0 ? yellow(pad(String(r.warnings), 4)) : dim(pad('0', 4));
    const info = r.infos > 0 ? cyan(pad(String(r.infos), 4)) : dim(pad('0', 4));
    const total = pad(String(r.total), 4);
    const suffix = r.error ? red(` ERR: ${r.error.slice(0, 40)}`) : '';
    console.log(`  ${name} ${grade}  ${crit}  ${warn}  ${info}  ${total}${suffix}`);
  }

  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));

  // Worst offenders
  const worstRepos = sorted.filter((r) => r.grade === 'F').slice(0, 5);
  if (worstRepos.length > 0) {
    console.log('');
    console.log(red(bold('  ⛔ WORST OFFENDERS (Grade F):')));
    for (const r of worstRepos) {
      console.log(`    ${red('●')} ${bold(r.repo)} — ${r.criticals} critical, ${r.warnings} warnings`);
    }
  }

  // Stats
  const gradeBreakdown = {};
  for (const r of succeeded) {
    gradeBreakdown[r.grade] = (gradeBreakdown[r.grade] || 0) + 1;
  }
  console.log('');
  const breakdown = ['A', 'B', 'C', 'D', 'F']
    .filter((g) => gradeBreakdown[g])
    .map((g) => `${(GRADE_COLORS[g] || dim)(bold(g))}:${gradeBreakdown[g]}`)
    .join(dim(' · '));
  console.log(`  ${dim('Grades:')} ${breakdown}`);
  console.log(`  ${dim(`${succeeded.length} scanned · ${failed.length} failed · ${totalFindings} total findings`)}`);

  if (failed.length > 0) {
    console.log('');
    console.log(yellow(`  ⚠ ${failed.length} repo(s) failed to scan:`));
    for (const r of failed) {
      console.log(dim(`    - ${r.repo}: ${r.error}`));
    }
  }

  console.log('');
}

export function reportBatchJSON(results) {
  const succeeded = results.filter((r) => !r.error);
  const output = {
    timestamp: new Date().toISOString(),
    summary: {
      totalRepos: results.length,
      scanned: succeeded.length,
      failed: results.filter((r) => r.error).length,
      totalFindings: succeeded.reduce((s, r) => s + r.total, 0),
      totalCritical: succeeded.reduce((s, r) => s + r.criticals, 0),
      totalWarnings: succeeded.reduce((s, r) => s + r.warnings, 0),
      totalInfo: succeeded.reduce((s, r) => s + r.infos, 0),
      grades: Object.fromEntries(['A', 'B', 'C', 'D', 'F'].map((g) => [g, succeeded.filter((r) => r.grade === g).length])),
    },
    repos: results.map((r) => ({
      repo: r.repo,
      grade: r.grade,
      criticals: r.criticals,
      warnings: r.warnings,
      infos: r.infos,
      total: r.total,
      error: r.error,
      findings: r.findings,
    })),
  };
  console.log(JSON.stringify(output, null, 2));
}

export function reportBatchMarkdown(results) {
  const succeeded = results.filter((r) => !r.error);
  const totalCrit = succeeded.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = succeeded.reduce((s, r) => s + r.warnings, 0);
  const totalInfo = succeeded.reduce((s, r) => s + r.infos, 0);

  const gradeRank = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
  const sorted = [...results].sort((a, b) => (gradeRank[a.grade] ?? 5) - (gradeRank[b.grade] ?? 5));

  const lines = [
    '# ⚗️ Vibe Audit — Batch Scan Report',
    '',
    `**Date:** ${new Date().toISOString().split('T')[0]}`,
    '',
    '## Summary',
    '',
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Repos scanned | ${succeeded.length} |`,
    `| Repos failed | ${results.length - succeeded.length} |`,
    `| Critical findings | ${totalCrit} |`,
    `| Warnings | ${totalWarn} |`,
    `| Info | ${totalInfo} |`,
    '',
    '## Results by Repository',
    '',
    '| Repo | Grade | Critical | Warnings | Info | Total |',
    '|------|-------|----------|----------|------|-------|',
  ];

  for (const r of sorted) {
    const gradeEmoji = { A: '🟢', B: '🟢', C: '🟡', D: '🟡', F: '🔴', '?': '⚪' }[r.grade] || '';
    const err = r.error ? ` ⚠️ ${r.error.slice(0, 30)}` : '';
    lines.push(`| ${r.repo} | ${gradeEmoji} ${r.grade} | ${r.criticals} | ${r.warnings} | ${r.infos} | ${r.total}${err} |`);
  }

  const worstRepos = sorted.filter((r) => r.grade === 'F');
  if (worstRepos.length > 0) {
    lines.push('', '## ⛔ Worst Offenders', '');
    for (const r of worstRepos) {
      lines.push(`- **${r.repo}** — ${r.criticals} critical, ${r.warnings} warnings`);
      const topFindings = r.findings.filter((f) => f.severity === 'critical').slice(0, 3);
      for (const f of topFindings) {
        lines.push(`  - \`${f.file}\`: ${f.message}`);
      }
    }
  }

  lines.push('');
  console.log(lines.join('\n'));
}

function stripAnsi(str) {
  return str.replace(/\x1b\[[0-9;]*m/g, '');
}
