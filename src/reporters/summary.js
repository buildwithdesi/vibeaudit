/**
 * Multi-repo summary reporters — terminal, JSON, and markdown.
 */

import { bold, red, yellow, cyan, green, dim, gray } from '../colors.js';

const GRADE_EMOJI = { A: '🟢', B: '🟢', C: '🟡', D: '🟠', F: '🔴', '?': '⚪' };

/**
 * @param {import('../multi-repo.js').MultiRepoResult} result
 * @param {'terminal' | 'json' | 'markdown'} format
 */
export function reportMultiRepo(result, format) {
  switch (format) {
    case 'json':
      return reportJSON(result);
    case 'markdown':
      return reportMarkdown(result);
    default:
      return reportTerminal(result);
  }
}

function reportTerminal(result) {
  const { repos, totalRepos, scannedRepos, failedRepos, totalFindings, totalCriticals, totalWarnings, durationMs } = result;

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — Multi-Repo Scan'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');
  console.log(`  ${bold('Repos:')}     ${scannedRepos} scanned${failedRepos > 0 ? red(` · ${failedRepos} failed`) : ''} ${dim(`of ${totalRepos} total`)}`);
  console.log(`  ${bold('Findings:')} ${totalCriticals > 0 ? red(bold(`${totalCriticals} critical`)) : green('0 critical')} · ${totalWarnings > 0 ? yellow(`${totalWarnings} warnings`) : green('0 warnings')} · ${dim(`${totalFindings} total`)}`);
  console.log(`  ${bold('Duration:')} ${dim(`${(durationMs / 1000).toFixed(1)}s`)}`);
  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Table header
  console.log(`  ${dim('Grade')}  ${dim('Repo'.padEnd(40))} ${dim('Crit'.padStart(5))} ${dim('Warn'.padStart(5))} ${dim('Info'.padStart(5))} ${dim('Time')}`);
  console.log(dim('  ' + '─'.repeat(72)));

  for (const r of repos) {
    if (r.error) {
      console.log(`  ${gray('?')}      ${r.label.padEnd(40)} ${red('ERROR: ' + r.error.slice(0, 30))}`);
      continue;
    }

    const gradeStr = r.grade === 'F' ? red(bold(r.grade))
      : r.grade === 'D' ? yellow(bold(r.grade))
        : r.grade === 'C' ? yellow(r.grade)
          : green(r.grade);

    const critStr = r.criticals > 0 ? red(bold(String(r.criticals).padStart(5))) : dim('0'.padStart(5));
    const warnStr = r.warnings > 0 ? yellow(String(r.warnings).padStart(5)) : dim('0'.padStart(5));
    const infoStr = r.infos > 0 ? cyan(String(r.infos).padStart(5)) : dim('0'.padStart(5));
    const timeStr = dim(`${(r.durationMs / 1000).toFixed(1)}s`);

    console.log(`  ${gradeStr}      ${r.label.padEnd(40)} ${critStr} ${warnStr} ${infoStr}  ${timeStr}`);
  }

  console.log('');

  // Worst offenders
  const worst = repos.filter(r => r.criticals > 0).sort((a, b) => b.criticals - a.criticals);
  if (worst.length > 0) {
    console.log(red(bold('  ⛔ Repos with critical findings:')));
    for (const r of worst.slice(0, 10)) {
      console.log(`     ${red(bold(String(r.criticals)))} critical — ${bold(r.label)}`);
    }
    console.log('');
  }

  // Grade distribution
  const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of repos) {
    if (r.grade in grades) grades[r.grade]++;
  }
  console.log(dim('  Grade distribution:'));
  console.log(`    ${green('A')} ${green(String(grades.A))}  ${green('B')} ${green(String(grades.B))}  ${yellow('C')} ${yellow(String(grades.C))}  ${yellow('D')} ${yellow(String(grades.D))}  ${red('F')} ${red(String(grades.F))}`);
  console.log('');
}

function reportJSON(result) {
  const output = {
    summary: {
      totalRepos: result.totalRepos,
      scannedRepos: result.scannedRepos,
      failedRepos: result.failedRepos,
      totalFindings: result.totalFindings,
      totalCriticals: result.totalCriticals,
      totalWarnings: result.totalWarnings,
      durationMs: result.durationMs,
      timestamp: new Date().toISOString(),
    },
    repos: result.repos.map(r => ({
      repo: r.label,
      grade: r.grade,
      criticals: r.criticals,
      warnings: r.warnings,
      infos: r.infos,
      total: r.total,
      durationMs: r.durationMs,
      error: r.error,
      findings: r.findings,
    })),
  };
  console.log(JSON.stringify(output, null, 2));
}

function reportMarkdown(result) {
  const { repos, totalRepos, scannedRepos, failedRepos, totalFindings, totalCriticals, totalWarnings, durationMs } = result;
  const now = new Date().toISOString().split('T')[0];

  const lines = [
    `# ⚗️ Vibe Audit — Multi-Repo Report`,
    '',
    `**Date:** ${now}  `,
    `**Repos:** ${scannedRepos} scanned${failedRepos > 0 ? `, ${failedRepos} failed` : ''} (${totalRepos} total)  `,
    `**Findings:** ${totalCriticals} critical, ${totalWarnings} warnings, ${totalFindings} total  `,
    `**Duration:** ${(durationMs / 1000).toFixed(1)}s`,
    '',
    '## Scorecard',
    '',
    '| Grade | Repo | Critical | Warnings | Info | Time |',
    '|:-----:|------|:--------:|:--------:|:----:|-----:|',
  ];

  for (const r of repos) {
    if (r.error) {
      lines.push(`| ❓ | ${r.label} | — | — | — | ERROR |`);
      continue;
    }
    const emoji = GRADE_EMOJI[r.grade] || '⚪';
    const critMark = r.criticals > 0 ? `**${r.criticals}**` : '0';
    const warnMark = r.warnings > 0 ? `**${r.warnings}**` : '0';
    lines.push(`| ${emoji} ${r.grade} | ${r.label} | ${critMark} | ${warnMark} | ${r.infos} | ${(r.durationMs / 1000).toFixed(1)}s |`);
  }

  // Worst offenders
  const worst = repos.filter(r => r.criticals > 0).sort((a, b) => b.criticals - a.criticals);
  if (worst.length > 0) {
    lines.push('', '## 🔴 Repos Needing Immediate Attention', '');
    for (const r of worst.slice(0, 10)) {
      lines.push(`- **${r.label}** — ${r.criticals} critical finding${r.criticals !== 1 ? 's' : ''}`);

      const crits = r.findings.filter(f => f.severity === 'critical');
      for (const f of crits.slice(0, 5)) {
        lines.push(`  - \`${f.ruleId}\` ${f.message} (\`${f.file}${f.line ? ':' + f.line : ''}\`)`);
      }
      if (crits.length > 5) {
        lines.push(`  - …and ${crits.length - 5} more`);
      }
    }
  }

  // Grade distribution
  const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of repos) {
    if (r.grade in grades) grades[r.grade]++;
  }
  lines.push('', '## Grade Distribution', '');
  lines.push(`| A | B | C | D | F |`);
  lines.push(`|:-:|:-:|:-:|:-:|:-:|`);
  lines.push(`| ${grades.A} | ${grades.B} | ${grades.C} | ${grades.D} | ${grades.F} |`);
  lines.push('');

  console.log(lines.join('\n'));
}
