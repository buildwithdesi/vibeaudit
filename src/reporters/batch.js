import { bold, red, yellow, cyan, green, dim, gray } from '../colors.js';

/**
 * Format batch results for terminal output.
 */
export function batchTerminal(results, summary) {
  const lines = [];

  lines.push('');
  lines.push(bold('  ⚗️  VIBE AUDIT — Batch Scan'));
  lines.push(dim('  ─────────────────────────────────────────────────────────────'));
  lines.push('');

  // Summary bar
  const overallGrade = summary.totalCritical > 0 ? 'F'
    : summary.totalWarning > 10 ? 'D'
    : summary.totalWarning > 0 ? 'C'
    : summary.totalInfo > 0 ? 'B'
    : 'A';

  const gradeColor = { A: green, B: green, C: yellow, D: yellow, F: red }[overallGrade];
  lines.push(`  ${gradeColor(bold(`OVERALL: ${overallGrade}`))}  ${dim('│')}  ${bold(String(summary.scanned))} ${dim('repos scanned')}  ${dim('│')}  ${red(bold(String(summary.totalCritical)))} ${dim('critical')}  ${dim('│')}  ${yellow(bold(String(summary.totalWarning)))} ${dim('warnings')}`);
  if (summary.failed > 0) {
    lines.push(`  ${red(bold(`${summary.failed} repos failed`))} ${dim('(auth or API errors)')}`);
  }
  lines.push('');

  // Sort: worst grade first, then by critical count
  const sorted = [...results].sort((a, b) => {
    const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
    const gDiff = (gradeOrder[a.grade] || 5) - (gradeOrder[b.grade] || 5);
    if (gDiff !== 0) return gDiff;
    return b.critical - a.critical;
  });

  // Table header
  const repoWidth = Math.max(30, ...sorted.map(r => r.repo.length)) + 2;
  lines.push(`  ${bold(pad('REPO', repoWidth))} ${bold(pad('GRADE', 7))} ${bold(pad('CRIT', 6))} ${bold(pad('WARN', 6))} ${bold(pad('INFO', 6))} ${bold('TIME')}`);
  lines.push(dim(`  ${'─'.repeat(repoWidth + 35)}`));

  for (const r of sorted) {
    if (r.error) {
      lines.push(`  ${pad(r.repo, repoWidth)} ${red(pad('ERR', 7))} ${dim(truncate(r.error, 40))}`);
      continue;
    }

    const gradeStr = gradeColor2(r.grade, pad(r.grade, 7));
    const critStr = r.critical > 0 ? red(bold(pad(String(r.critical), 6))) : dim(pad('0', 6));
    const warnStr = r.warning > 0 ? yellow(pad(String(r.warning), 6)) : dim(pad('0', 6));
    const infoStr = r.info > 0 ? cyan(pad(String(r.info), 6)) : dim(pad('0', 6));
    const timeStr = dim(`${(r.durationMs / 1000).toFixed(1)}s`);

    lines.push(`  ${pad(r.repo, repoWidth)} ${gradeStr} ${critStr} ${warnStr} ${infoStr} ${timeStr}`);
  }

  lines.push('');
  lines.push(dim(`  ─────────────────────────────────────────────────────────────`));

  // Grade distribution
  const gradeCounts = [];
  for (const [g, count] of Object.entries(summary.grades)) {
    if (count > 0) gradeCounts.push(`${gradeColor2(g, bold(g))}:${count}`);
  }
  if (gradeCounts.length > 0) {
    lines.push(`  ${dim('Grades:')} ${gradeCounts.join(dim('  '))}`);
  }

  lines.push(`  ${dim(`${summary.totalFindings} total findings across ${summary.scanned} repos in ${(summary.durationMs / 1000).toFixed(1)}s`)}`);
  lines.push('');

  if (summary.totalCritical > 0) {
    lines.push(red(bold('  ⛔ Critical issues found. Run per-repo scans with --fix for remediation prompts.')));
  } else if (summary.totalWarning > 0) {
    lines.push(yellow(bold('  ⚠️  Warnings found across your repos. Review before shipping.')));
  } else {
    lines.push(green(bold('  ✅ All repos clean. Ship it.')));
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * Format batch results as JSON.
 */
export function batchJSON(results, summary) {
  const output = {
    summary,
    repos: results.map((r) => ({
      repo: r.repo,
      grade: r.grade,
      critical: r.critical,
      warning: r.warning,
      info: r.info,
      durationMs: r.durationMs,
      error: r.error || undefined,
      findings: r.findings,
    })),
  };
  return JSON.stringify(output, null, 2);
}

/**
 * Format batch results as Markdown (ideal for GitHub Actions summary / Slack).
 */
export function batchMarkdown(results, summary) {
  const lines = [];

  lines.push('# ⚗️ Vibe Audit — Batch Scan Report');
  lines.push('');

  const ts = new Date().toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
  lines.push(`> Scanned **${summary.scanned}** repos on ${ts}`);
  lines.push('');

  // Summary table
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Repos scanned | ${summary.scanned} |`);
  if (summary.failed > 0) lines.push(`| Failed | ${summary.failed} |`);
  lines.push(`| Total findings | ${summary.totalFindings} |`);
  lines.push(`| Critical | ${summary.totalCritical} |`);
  lines.push(`| Warnings | ${summary.totalWarning} |`);
  lines.push(`| Info | ${summary.totalInfo} |`);
  lines.push(`| Duration | ${(summary.durationMs / 1000).toFixed(1)}s |`);
  lines.push('');

  // Grade distribution
  const gradeEmoji = { A: '🟢', B: '🟢', C: '🟡', D: '🟠', F: '🔴' };
  lines.push('### Grade Distribution');
  lines.push('');
  for (const [g, count] of Object.entries(summary.grades)) {
    if (count > 0) lines.push(`${gradeEmoji[g] || '⚪'} **${g}**: ${count} repo${count !== 1 ? 's' : ''}`);
  }
  lines.push('');

  // Per-repo table sorted by severity
  const sorted = [...results].sort((a, b) => {
    const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
    return (gradeOrder[a.grade] || 5) - (gradeOrder[b.grade] || 5);
  });

  lines.push('### Per-Repo Results');
  lines.push('');
  lines.push('| Repo | Grade | Critical | Warnings | Info |');
  lines.push('|------|-------|----------|----------|------|');
  for (const r of sorted) {
    if (r.error) {
      lines.push(`| ${r.repo} | ❌ ERR | — | — | ${r.error} |`);
    } else {
      const emoji = gradeEmoji[r.grade] || '⚪';
      lines.push(`| ${r.repo} | ${emoji} ${r.grade} | ${r.critical} | ${r.warning} | ${r.info} |`);
    }
  }
  lines.push('');

  // Critical findings detail
  const critRepos = sorted.filter((r) => r.critical > 0);
  if (critRepos.length > 0) {
    lines.push('### 🔴 Critical Findings');
    lines.push('');
    for (const r of critRepos) {
      lines.push(`#### ${r.repo}`);
      lines.push('');
      const crits = r.findings.filter((f) => f.severity === 'critical');
      for (const f of crits) {
        const cwe = f.cweId ? ` \`${f.cweId}\`` : '';
        lines.push(`- **${f.message}**${cwe} — \`${f.file}\`${f.line ? `:${f.line}` : ''}`);
        if (f.evidence) lines.push(`  - Evidence: \`${f.evidence}\``);
        lines.push(`  - Fix: ${f.fix}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}


function pad(str, width) {
  return str.length >= width ? str : str + ' '.repeat(width - str.length);
}

function truncate(str, max) {
  return str.length > max ? str.slice(0, max - 3) + '...' : str;
}

function gradeColor2(grade, str) {
  switch (grade) {
    case 'A': case 'B': return green(str);
    case 'C': return yellow(str);
    case 'D': return yellow(bold(str));
    case 'F': return red(bold(str));
    default: return gray(str);
  }
}
