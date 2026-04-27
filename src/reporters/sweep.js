import { bold, red, yellow, cyan, green, gray, dim } from '../colors.js';

/**
 * Print a multi-repo sweep report to stdout.
 *
 * @param {import('../sweep.js').SweepResult} result
 * @param {'terminal' | 'json' | 'markdown'} format
 */
export function reportSweep(result, format) {
  switch (format) {
    case 'json':
      return reportSweepJSON(result);
    case 'markdown':
      return reportSweepMarkdown(result);
    default:
      return reportSweepTerminal(result);
  }
}

// ─── Terminal ────────────────────────────────────────────────────────────────

function reportSweepTerminal({ repos, summary }) {
  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — SWEEP'));
  console.log(dim('  Multi-repo security scan'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  const overallGrade = summary.totalCritical > 0
    ? 'F'
    : summary.totalWarning > 20 ? 'D'
    : summary.totalWarning > 0 ? 'C'
    : summary.totalInfo > 0 ? 'B'
    : 'A';

  const gradeColor = { A: green, B: green, C: yellow, D: yellow, F: red }[overallGrade];

  console.log(`  ${gradeColor(bold(`OVERALL: ${overallGrade}`))}  ${dim('│')}  ${bold(String(summary.scanned))} repos scanned  ${dim('│')}  ${red(bold(String(summary.totalCritical)))} ${dim('critical')}  ${dim('│')}  ${yellow(bold(String(summary.totalWarning)))} ${dim('warnings')}  ${dim('│')}  ${cyan(bold(String(summary.totalInfo)))} ${dim('info')}`);

  if (summary.failed > 0) {
    console.log(`  ${red(`${summary.failed} repos failed to scan`)}`);
  }
  console.log('');

  // Repo table
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log(`  ${dim('Grade')}  ${dim('Repo'.padEnd(40))}  ${dim('Crit'.padStart(4))}  ${dim('Warn'.padStart(4))}  ${dim('Info'.padStart(4))}`);
  console.log(dim('  ─────────────────────────────────────────────────────────────'));

  for (const r of repos) {
    if (r.error) {
      console.log(`  ${gray('  ?  ')}  ${r.name.padEnd(40)}  ${red(r.error)}`);
      continue;
    }

    const gc = { A: green, B: green, C: yellow, D: yellow, F: red }[r.grade] || gray;
    const name = r.name.length > 40 ? r.name.slice(0, 37) + '...' : r.name;

    const critStr = r.critical > 0 ? red(bold(String(r.critical).padStart(4))) : dim('   0');
    const warnStr = r.warning > 0 ? yellow(String(r.warning).padStart(4)) : dim('   0');
    const infoStr = r.info > 0 ? cyan(String(r.info).padStart(4)) : dim('   0');

    console.log(`  ${gc(bold(`  ${r.grade}  `))}  ${name.padEnd(40)}  ${critStr}  ${warnStr}  ${infoStr}`);
  }

  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Top findings across all repos
  const allFindings = repos.flatMap((r) => r.findings.map((f) => ({ ...f, repo: r.name })));
  const byRule = new Map();
  for (const f of allFindings) {
    const key = f.ruleId;
    if (!byRule.has(key)) byRule.set(key, { ruleId: key, message: f.message, severity: f.severity, count: 0, repos: new Set() });
    const entry = byRule.get(key);
    entry.count++;
    entry.repos.add(f.repo);
  }

  const topRules = [...byRule.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  if (topRules.length > 0) {
    console.log(bold('  Top findings across repos:'));
    console.log('');
    for (const rule of topRules) {
      const icon = rule.severity === 'critical' ? red('●') : rule.severity === 'warning' ? yellow('▲') : cyan('ℹ');
      console.log(`  ${icon}  ${bold(rule.ruleId)} — ${rule.count} hits in ${rule.repos.size} repos`);
    }
    console.log('');
  }

  // Repos needing attention (critical findings)
  const critRepos = repos.filter((r) => r.critical > 0);
  if (critRepos.length > 0) {
    console.log(red(bold('  Repos with critical issues:')));
    for (const r of critRepos) {
      console.log(red(`    ${r.name} — ${r.critical} critical`));
    }
    console.log('');
  }

  console.log(dim(`  ${summary.totalFindings} total findings · ${summary.scanned} repos · ${summary.durationMs}ms`));
  console.log('');
}

// ─── JSON ────────────────────────────────────────────────────────────────────

function reportSweepJSON({ repos, summary }) {
  const output = {
    summary,
    repos: repos.map((r) => ({
      name: r.name,
      grade: r.grade,
      critical: r.critical,
      warning: r.warning,
      info: r.info,
      durationMs: r.durationMs,
      error: r.error || undefined,
      findings: r.findings,
    })),
  };
  console.log(JSON.stringify(output, null, 2));
}

// ─── Markdown ────────────────────────────────────────────────────────────────

function reportSweepMarkdown({ repos, summary }) {
  const lines = [
    '# ⚗️ Vibe Audit — Sweep Report',
    '',
    `**${summary.scanned}** repos scanned | **${summary.totalCritical}** critical | **${summary.totalWarning}** warnings | **${summary.totalInfo}** info | ${summary.durationMs}ms`,
    '',
  ];

  if (summary.failed > 0) {
    lines.push(`> ⚠️ ${summary.failed} repos failed to scan`);
    lines.push('');
  }

  lines.push('| Grade | Repo | Critical | Warnings | Info |');
  lines.push('|:-----:|------|:--------:|:--------:|:----:|');

  for (const r of repos) {
    if (r.error) {
      lines.push(`| ? | ${r.name} | — | — | ❌ ${r.error} |`);
      continue;
    }
    const gradeEmoji = { A: '🟢', B: '🟢', C: '🟡', D: '🟡', F: '🔴' }[r.grade] || '⚪';
    lines.push(`| ${gradeEmoji} ${r.grade} | ${r.name} | ${r.critical} | ${r.warning} | ${r.info} |`);
  }

  lines.push('');

  // Top findings
  const allFindings = repos.flatMap((r) => r.findings.map((f) => ({ ...f, repo: r.name })));
  const byRule = new Map();
  for (const f of allFindings) {
    if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, { ruleId: f.ruleId, severity: f.severity, count: 0, repos: new Set() });
    const entry = byRule.get(f.ruleId);
    entry.count++;
    entry.repos.add(f.repo);
  }

  const topRules = [...byRule.values()].sort((a, b) => b.count - a.count).slice(0, 10);

  if (topRules.length > 0) {
    lines.push('## Top Findings');
    lines.push('');
    lines.push('| Rule | Hits | Repos | Severity |');
    lines.push('|------|:----:|:-----:|----------|');
    for (const rule of topRules) {
      const sev = rule.severity === 'critical' ? '🔴' : rule.severity === 'warning' ? '🟡' : 'ℹ️';
      lines.push(`| ${rule.ruleId} | ${rule.count} | ${rule.repos.size} | ${sev} ${rule.severity} |`);
    }
    lines.push('');
  }

  // Critical repos
  const critRepos = repos.filter((r) => r.critical > 0);
  if (critRepos.length > 0) {
    lines.push('## Repos Needing Immediate Attention');
    lines.push('');
    for (const r of critRepos) {
      lines.push(`- **${r.name}** — ${r.critical} critical issues`);
      const crits = r.findings.filter((f) => f.severity === 'critical');
      for (const f of crits.slice(0, 5)) {
        lines.push(`  - \`${f.file}\`${f.line ? `:${f.line}` : ''} — ${f.message}`);
      }
      if (crits.length > 5) lines.push(`  - ...and ${crits.length - 5} more`);
    }
    lines.push('');
  }

  console.log(lines.join('\n'));
}
