import { bold, red, yellow, cyan, green, gray, dim } from '../colors.js';

/**
 * Print a terminal summary of a multi-repo org scan.
 */
export function reportOrgTerminal(results, { orgName, durationMs }) {
  const sorted = [...results].sort((a, b) => {
    const order = { F: 0, D: 1, '?': 2, C: 3, B: 4, A: 5 };
    return (order[a.grade] ?? 2) - (order[b.grade] ?? 2);
  });

  const totalCrit = results.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = results.reduce((s, r) => s + r.warnings, 0);
  const totalInfo = results.reduce((s, r) => s + r.infos, 0);
  const totalFindings = totalCrit + totalWarn + totalInfo;
  const failed = results.filter((r) => r.error).length;

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — ORG SCAN'));
  console.log(dim(`  ${orgName} · ${results.length} repos · ${durationMs}ms`));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Grade distribution
  const grades = { A: 0, B: 0, C: 0, D: 0, F: 0, '?': 0 };
  for (const r of results) grades[r.grade] = (grades[r.grade] || 0) + 1;

  const gradeLine = [
    green(bold(`${grades.A} A`)),
    green(`${grades.B} B`),
    yellow(`${grades.C} C`),
    yellow(`${grades.D} D`),
    red(bold(`${grades.F} F`)),
  ];
  if (grades['?'] > 0) gradeLine.push(gray(`${grades['?']} err`));

  console.log(`  ${bold('Grades:')} ${gradeLine.join(dim(' · '))}`);
  console.log(`  ${bold('Total:')}  ${red(bold(`${totalCrit}`))} ${dim('critical')} · ${yellow(`${totalWarn}`)} ${dim('warnings')} · ${cyan(`${totalInfo}`)} ${dim('info')}`);
  if (failed > 0) console.log(`  ${red(`${failed} repos failed to scan`)}`);
  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Per-repo table
  const nameWidth = Math.min(40, Math.max(20, ...results.map((r) => `${r.owner}/${r.repo}`.length)));

  for (const r of sorted) {
    const name = `${r.owner}/${r.repo}`;
    const padded = name.length > nameWidth ? name.slice(0, nameWidth - 1) + '…' : name.padEnd(nameWidth);

    const gradeStr = gradeColor(r.grade)(bold(r.grade));

    if (r.error) {
      console.log(`  ${gradeStr}  ${dim(padded)}  ${red('error: ' + truncate(r.error, 40))}`);
      continue;
    }

    const parts = [];
    if (r.criticals > 0) parts.push(red(bold(`${r.criticals}C`)));
    if (r.warnings > 0) parts.push(yellow(`${r.warnings}W`));
    if (r.infos > 0) parts.push(cyan(`${r.infos}I`));
    const counts = parts.length > 0 ? parts.join(dim(',')) : green('clean');

    console.log(`  ${gradeStr}  ${padded}  ${counts}  ${dim(`${r.durationMs}ms`)}`);
  }

  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));

  // Visual bar
  if (totalFindings > 0) {
    const barWidth = 40;
    const critBar = Math.round((totalCrit / totalFindings) * barWidth);
    const warnBar = Math.round((totalWarn / totalFindings) * barWidth);
    const infoBar = barWidth - critBar - warnBar;
    const bar = red('█'.repeat(critBar)) + yellow('█'.repeat(warnBar)) + cyan('█'.repeat(Math.max(0, infoBar)));
    console.log(`  ${bar} ${dim(`${totalFindings} total`)}`);
  }

  console.log(`  ${results.length} repos scanned · ${durationMs}ms`);
  console.log('');

  if (totalCrit > 0) {
    const critRepos = sorted.filter((r) => r.criticals > 0);
    console.log(red(bold(`  ⛔ ${critRepos.length} repos have CRITICAL issues:`)));
    for (const r of critRepos) {
      console.log(red(`     ${r.owner}/${r.repo} (${r.criticals} critical)`));
    }
    console.log('');
  }
}

/**
 * Return a JSON summary of a multi-repo org scan.
 */
export function reportOrgJSON(results, { orgName, durationMs }) {
  const totalCrit = results.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = results.reduce((s, r) => s + r.warnings, 0);
  const totalInfo = results.reduce((s, r) => s + r.infos, 0);

  const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of results) {
    if (grades[r.grade] !== undefined) grades[r.grade]++;
  }

  const output = {
    org: orgName,
    scannedAt: new Date().toISOString(),
    summary: {
      repos: results.length,
      totalFindings: totalCrit + totalWarn + totalInfo,
      critical: totalCrit,
      warning: totalWarn,
      info: totalInfo,
      grades,
      durationMs,
    },
    repos: results.map((r) => ({
      repo: `${r.owner}/${r.repo}`,
      grade: r.grade,
      critical: r.criticals,
      warning: r.warnings,
      info: r.infos,
      durationMs: r.durationMs,
      ...(r.error ? { error: r.error } : {}),
      findings: r.findings.map((f) => ({
        ruleId: f.ruleId,
        severity: f.severity,
        file: f.file,
        line: f.line,
        message: f.message,
        ...(f.cweId ? { cweId: f.cweId } : {}),
      })),
    })),
  };

  console.log(JSON.stringify(output, null, 2));
  return output;
}

/**
 * Print a markdown summary of a multi-repo org scan.
 */
export function reportOrgMarkdown(results, { orgName, durationMs }) {
  const totalCrit = results.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = results.reduce((s, r) => s + r.warnings, 0);
  const totalInfo = results.reduce((s, r) => s + r.infos, 0);

  const sorted = [...results].sort((a, b) => {
    const order = { F: 0, D: 1, '?': 2, C: 3, B: 4, A: 5 };
    return (order[a.grade] ?? 2) - (order[b.grade] ?? 2);
  });

  const lines = [
    `# ⚗️ Vibe Audit — Org Scan`,
    '',
    `**${orgName}** · ${results.length} repos · ${new Date().toISOString().split('T')[0]}`,
    '',
    '| Metric | Value |',
    '|--------|-------|',
    `| Repos scanned | ${results.length} |`,
    `| Critical | ${totalCrit} |`,
    `| Warnings | ${totalWarn} |`,
    `| Info | ${totalInfo} |`,
    `| Duration | ${durationMs}ms |`,
    '',
    '## Results by Repo',
    '',
    '| Grade | Repo | Critical | Warnings | Info |',
    '|-------|------|----------|----------|------|',
  ];

  for (const r of sorted) {
    const gradeEmoji = { A: '🟢', B: '🟢', C: '🟡', D: '🟡', F: '🔴', '?': '⚪' }[r.grade] || '⚪';
    lines.push(`| ${gradeEmoji} ${r.grade} | ${r.owner}/${r.repo} | ${r.criticals} | ${r.warnings} | ${r.infos} |`);
  }

  lines.push('');

  const critRepos = sorted.filter((r) => r.criticals > 0);
  if (critRepos.length > 0) {
    lines.push('## 🔴 Repos with Critical Issues');
    lines.push('');
    for (const r of critRepos) {
      lines.push(`### ${r.owner}/${r.repo} (Grade ${r.grade})`);
      lines.push('');
      for (const f of r.findings.filter((f) => f.severity === 'critical')) {
        const cwe = f.cweId ? ` \`${f.cweId}\`` : '';
        lines.push(`- **${f.message}** — \`${f.file}\`${f.line ? `:${f.line}` : ''}${cwe}`);
      }
      lines.push('');
    }
  }

  console.log(lines.join('\n'));
}

function gradeColor(grade) {
  switch (grade) {
    case 'A': case 'B': return green;
    case 'C': case 'D': return yellow;
    case 'F': return red;
    default: return gray;
  }
}

function truncate(str, len) {
  return str.length > len ? str.slice(0, len - 1) + '…' : str;
}
