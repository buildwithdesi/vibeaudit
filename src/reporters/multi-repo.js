import { bold, red, yellow, cyan, green, dim } from '../colors.js';

/**
 * @typedef {import('../multi-repo.js').RepoResult} RepoResult
 */

/**
 * Print a terminal dashboard summarizing multi-repo scan results.
 * @param {RepoResult[]} results
 * @param {number} totalDurationMs
 */
export function reportMultiRepoTerminal(results, totalDurationMs) {
  const successful = results.filter((r) => !r.error);
  const failed = results.filter((r) => r.error);

  const allFindings = successful.flatMap((r) => r.findings);
  const totalCritical = allFindings.filter((f) => f.severity === 'critical').length;
  const totalWarning = allFindings.filter((f) => f.severity === 'warning').length;
  const totalInfo = allFindings.filter((f) => f.severity === 'info').length;
  const totalFiles = successful.reduce((sum, r) => sum + r.filesScanned, 0);

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — MULTI-REPO SCAN'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Overall stats
  const grade = totalCritical > 0 ? 'F' : totalWarning > 10 ? 'D' : totalWarning > 0 ? 'C' : totalInfo > 0 ? 'B' : 'A';
  const gradeColor = { A: green, B: green, C: yellow, D: yellow, F: red }[grade];

  console.log(`  ${gradeColor(bold(`OVERALL GRADE: ${grade}`))}  ${dim('across')} ${bold(String(successful.length))} ${dim('repos')}`);
  console.log(`  ${red(bold(String(totalCritical)))} ${dim('critical')}  ${dim('·')}  ${yellow(bold(String(totalWarning)))} ${dim('warnings')}  ${dim('·')}  ${cyan(bold(String(totalInfo)))} ${dim('info')}`);
  console.log(`  ${dim(`${totalFiles} files scanned · ${(totalDurationMs / 1000).toFixed(1)}s total`)}`);
  if (failed.length > 0) {
    console.log(`  ${red(`${failed.length} repo(s) failed`)}`);
  }
  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Rank repos by severity (criticals first, then warnings)
  const ranked = [...successful].sort((a, b) => {
    const aCrit = a.findings.filter((f) => f.severity === 'critical').length;
    const bCrit = b.findings.filter((f) => f.severity === 'critical').length;
    if (aCrit !== bCrit) return bCrit - aCrit;
    const aWarn = a.findings.filter((f) => f.severity === 'warning').length;
    const bWarn = b.findings.filter((f) => f.severity === 'warning').length;
    return bWarn - aWarn;
  });

  // Table header
  console.log(`  ${bold(pad('REPO', 40))} ${pad('CRIT', 6)} ${pad('WARN', 6)} ${pad('INFO', 6)} ${pad('GRADE', 6)} ${dim('TIME')}`);
  console.log(dim(`  ${'─'.repeat(40)} ${'─'.repeat(6)} ${'─'.repeat(6)} ${'─'.repeat(6)} ${'─'.repeat(6)} ${'─'.repeat(8)}`));

  for (const r of ranked) {
    const crit = r.findings.filter((f) => f.severity === 'critical').length;
    const warn = r.findings.filter((f) => f.severity === 'warning').length;
    const info = r.findings.filter((f) => f.severity === 'info').length;
    const repoGrade = crit > 0 ? 'F' : warn > 5 ? 'D' : warn > 0 ? 'C' : info > 0 ? 'B' : 'A';
    const rGradeColor = { A: green, B: green, C: yellow, D: yellow, F: red }[repoGrade];

    const repoName = r.repo.length > 38 ? '…' + r.repo.slice(-(37)) : r.repo;
    const critStr = crit > 0 ? red(bold(pad(String(crit), 6))) : dim(pad('0', 6));
    const warnStr = warn > 0 ? yellow(pad(String(warn), 6)) : dim(pad('0', 6));
    const infoStr = info > 0 ? cyan(pad(String(info), 6)) : dim(pad('0', 6));
    const timeStr = dim(`${(r.durationMs / 1000).toFixed(1)}s`);

    console.log(`  ${pad(repoName, 40)} ${critStr} ${warnStr} ${infoStr} ${rGradeColor(pad(repoGrade, 6))} ${timeStr}`);
  }

  // Failed repos
  if (failed.length > 0) {
    console.log('');
    console.log(dim(`  ${'─'.repeat(40)} ${'─'.repeat(6)} ${'─'.repeat(6)} ${'─'.repeat(6)} ${'─'.repeat(6)} ${'─'.repeat(8)}`));
    for (const r of failed) {
      console.log(`  ${red(pad(r.repo, 40))} ${dim('ERROR: ' + truncate(r.error, 40))}`);
    }
  }

  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));

  // Repos needing attention
  const needsAttention = ranked.filter((r) => r.findings.some((f) => f.severity === 'critical'));
  if (needsAttention.length > 0) {
    console.log('');
    console.log(red(bold(`  ⛔ ${needsAttention.length} repo(s) have CRITICAL issues:`)));
    for (const r of needsAttention) {
      const critCount = r.findings.filter((f) => f.severity === 'critical').length;
      console.log(`     ${red('●')} ${bold(r.repo)} — ${critCount} critical finding${critCount > 1 ? 's' : ''}`);
    }
    console.log('');
    console.log(dim('  Run individually for full details:'));
    console.log(dim(`    npx vibe-audit ${needsAttention[0].repo} --fix`));
  } else if (totalWarning > 0) {
    console.log('');
    console.log(yellow(bold('  ⚠️  No criticals, but warnings found across repos.')));
  } else {
    console.log('');
    console.log(green(bold('  ✅ All repos clean. Ship it.')));
  }

  console.log('');
}

/**
 * Format multi-repo results as JSON.
 * @param {RepoResult[]} results
 * @param {number} totalDurationMs
 */
export function reportMultiRepoJSON(results, totalDurationMs) {
  const successful = results.filter((r) => !r.error);
  const allFindings = successful.flatMap((r) => r.findings);

  const output = {
    summary: {
      reposScanned: successful.length,
      reposFailed: results.filter((r) => r.error).length,
      totalFindings: allFindings.length,
      critical: allFindings.filter((f) => f.severity === 'critical').length,
      warning: allFindings.filter((f) => f.severity === 'warning').length,
      info: allFindings.filter((f) => f.severity === 'info').length,
      totalFiles: successful.reduce((sum, r) => sum + r.filesScanned, 0),
      durationMs: totalDurationMs,
    },
    repos: results.map((r) => ({
      repo: r.repo,
      error: r.error,
      filesScanned: r.filesScanned,
      durationMs: r.durationMs,
      findings: {
        critical: r.findings.filter((f) => f.severity === 'critical').length,
        warning: r.findings.filter((f) => f.severity === 'warning').length,
        info: r.findings.filter((f) => f.severity === 'info').length,
        details: r.findings,
      },
    })),
  };

  console.log(JSON.stringify(output, null, 2));
}

/**
 * Format multi-repo results as Markdown.
 * @param {RepoResult[]} results
 * @param {number} totalDurationMs
 */
export function reportMultiRepoMarkdown(results, totalDurationMs) {
  const successful = results.filter((r) => !r.error);
  const failed = results.filter((r) => r.error);
  const allFindings = successful.flatMap((r) => r.findings);

  const lines = [
    '# ⚗️ Vibe Audit — Multi-Repo Scan',
    '',
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Repos scanned | ${successful.length} |`,
    `| Repos failed | ${failed.length} |`,
    `| Total findings | ${allFindings.length} |`,
    `| Critical | ${allFindings.filter((f) => f.severity === 'critical').length} |`,
    `| Warnings | ${allFindings.filter((f) => f.severity === 'warning').length} |`,
    `| Info | ${allFindings.filter((f) => f.severity === 'info').length} |`,
    `| Duration | ${(totalDurationMs / 1000).toFixed(1)}s |`,
    '',
    '## Repo Summary',
    '',
    '| Repo | Critical | Warnings | Info | Grade |',
    '|------|----------|----------|------|-------|',
  ];

  const ranked = [...successful].sort((a, b) => {
    const aCrit = a.findings.filter((f) => f.severity === 'critical').length;
    const bCrit = b.findings.filter((f) => f.severity === 'critical').length;
    if (aCrit !== bCrit) return bCrit - aCrit;
    const aWarn = a.findings.filter((f) => f.severity === 'warning').length;
    const bWarn = b.findings.filter((f) => f.severity === 'warning').length;
    return bWarn - aWarn;
  });

  for (const r of ranked) {
    const crit = r.findings.filter((f) => f.severity === 'critical').length;
    const warn = r.findings.filter((f) => f.severity === 'warning').length;
    const info = r.findings.filter((f) => f.severity === 'info').length;
    const grade = crit > 0 ? 'F' : warn > 5 ? 'D' : warn > 0 ? 'C' : info > 0 ? 'B' : 'A';
    lines.push(`| ${r.repo} | ${crit} | ${warn} | ${info} | ${grade} |`);
  }

  if (failed.length > 0) {
    lines.push('', '## Failed Repos', '');
    for (const r of failed) {
      lines.push(`- **${r.repo}**: ${r.error}`);
    }
  }

  const needsAttention = ranked.filter((r) => r.findings.some((f) => f.severity === 'critical'));
  if (needsAttention.length > 0) {
    lines.push('', '## 🔴 Repos With Critical Issues', '');
    for (const r of needsAttention) {
      lines.push(`### ${r.repo}`, '');
      const crits = r.findings.filter((f) => f.severity === 'critical');
      for (const f of crits) {
        lines.push(`- **${f.message}** — \`${f.file}\`${f.line ? `:${f.line}` : ''}${f.cweId ? ` \`${f.cweId}\`` : ''}`);
      }
      lines.push('');
    }
  }

  lines.push('');
  console.log(lines.join('\n'));
}

function pad(str, len) {
  return str.length >= len ? str : str + ' '.repeat(len - str.length);
}

function truncate(str, len) {
  return str.length > len ? str.slice(0, len - 1) + '…' : str;
}
