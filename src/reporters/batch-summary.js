import { bold, red, yellow, cyan, green, dim } from '../colors.js';

/**
 * @typedef {import('../batch.js').RepoResult} RepoResult
 * @typedef {import('../batch.js').BatchSummary} BatchSummary
 */

/**
 * Format batch audit results.
 *
 * @param {RepoResult[]} results
 * @param {BatchSummary} summary
 * @param {'terminal' | 'json' | 'markdown'} format
 * @returns {string} Formatted output (also printed to stdout for terminal format)
 */
export function batchReport(results, summary, format) {
  switch (format) {
    case 'json':
      return batchJSON(results, summary);
    case 'markdown':
      return batchMarkdown(results, summary);
    default:
      return batchTerminal(results, summary);
  }
}

// ─── Terminal ────────────────────────────────────────────────────────────────

function batchTerminal(results, summary) {
  const lines = [];
  lines.push('');
  lines.push(bold('  ⚗️  VIBE AUDIT — Multi-Repo Scan'));
  lines.push(dim('  ─────────────────────────────────────────────────────────────'));
  lines.push('');
  lines.push(
    `  ${bold(String(summary.scanned))} repos scanned` +
    (summary.failed > 0 ? `  ${red(bold(`${summary.failed} failed`))}` : '') +
    `  ${dim('·')}  ${summary.durationMs}ms`
  );
  lines.push('');

  // Overall counts
  const parts = [];
  if (summary.totalCriticals > 0) parts.push(red(bold(`${summary.totalCriticals} critical`)));
  if (summary.totalWarnings > 0) parts.push(yellow(`${summary.totalWarnings} warnings`));
  if (summary.totalInfos > 0) parts.push(cyan(`${summary.totalInfos} info`));
  if (summary.totalFindings === 0) parts.push(green('0 issues across all repos'));
  lines.push(`  ${parts.join(dim(' · '))}`);
  lines.push('');
  lines.push(dim('  ─────────────────────────────────────────────────────────────'));
  lines.push('');

  // Sort: failing repos first, then by criticals desc, then warnings desc
  const sorted = [...results].sort((a, b) => {
    if (a.error && !b.error) return 1;
    if (!a.error && b.error) return -1;
    if (a.criticals !== b.criticals) return b.criticals - a.criticals;
    return b.warnings - a.warnings;
  });

  for (const r of sorted) {
    if (r.error) {
      lines.push(`  ${red('✗')}  ${bold(r.repo)}  ${red(dim(`error: ${r.error}`))}`);
      continue;
    }

    const gradeColor = { A: green, B: green, C: yellow, D: yellow, F: red }[r.grade] || dim;
    const counts = [];
    if (r.criticals > 0) counts.push(red(bold(`${r.criticals}C`)));
    if (r.warnings > 0) counts.push(yellow(`${r.warnings}W`));
    if (r.infos > 0) counts.push(cyan(`${r.infos}I`));
    const countStr = counts.length > 0 ? counts.join(dim(',')) : green('clean');

    lines.push(`  ${gradeColor(bold(r.grade))}  ${bold(r.repo)}  ${countStr}  ${dim(`${r.durationMs}ms`)}`);
  }

  lines.push('');

  if (summary.totalCriticals > 0) {
    lines.push(red(bold('  ⛔ Critical issues found. Review repos graded F immediately.')));
  } else if (summary.totalWarnings > 0) {
    lines.push(yellow(bold('  ⚠️  Warnings found across repos. Review before next deploy.')));
  } else {
    lines.push(green(bold('  ✅ All repos clean. Ship it.')));
  }
  lines.push('');

  const output = lines.join('\n');
  console.log(output);
  return output;
}

// ─── JSON ────────────────────────────────────────────────────────────────────

function batchJSON(results, summary) {
  const output = JSON.stringify({
    summary,
    repos: results.map((r) => ({
      repo: r.repo,
      grade: r.grade,
      criticals: r.criticals,
      warnings: r.warnings,
      infos: r.infos,
      filesScanned: r.filesScanned,
      durationMs: r.durationMs,
      error: r.error || undefined,
      findings: r.findings,
    })),
  }, null, 2);

  console.log(output);
  return output;
}

// ─── Markdown ────────────────────────────────────────────────────────────────

function batchMarkdown(results, summary) {
  const now = new Date().toISOString().split('T')[0];
  const lines = [];

  lines.push('# ⚗️ Vibe Audit — Multi-Repo Security Report');
  lines.push('');
  lines.push(`**Date:** ${now}  `);
  lines.push(`**Repos scanned:** ${summary.scanned}/${summary.totalRepos}  `);
  lines.push(`**Duration:** ${(summary.durationMs / 1000).toFixed(1)}s`);
  lines.push('');

  // Summary table
  lines.push('## Summary');
  lines.push('');
  lines.push('| Metric | Count |');
  lines.push('|--------|-------|');
  lines.push(`| Critical | ${summary.totalCriticals} |`);
  lines.push(`| Warnings | ${summary.totalWarnings} |`);
  lines.push(`| Info | ${summary.totalInfos} |`);
  lines.push(`| Total findings | ${summary.totalFindings} |`);
  if (summary.failed > 0) {
    lines.push(`| Failed repos | ${summary.failed} |`);
  }
  lines.push('');

  // Per-repo table
  lines.push('## Repos');
  lines.push('');
  lines.push('| Grade | Repository | Critical | Warnings | Info | Status |');
  lines.push('|:-----:|------------|:--------:|:--------:|:----:|--------|');

  const sorted = [...results].sort((a, b) => {
    if (a.error && !b.error) return 1;
    if (!a.error && b.error) return -1;
    if (a.criticals !== b.criticals) return b.criticals - a.criticals;
    return b.warnings - a.warnings;
  });

  for (const r of sorted) {
    if (r.error) {
      lines.push(`| ❌ | ${r.repo} | — | — | — | \`${r.error}\` |`);
      continue;
    }

    const gradeEmoji = { A: '🟢', B: '🟢', C: '🟡', D: '🟠', F: '🔴' }[r.grade] || '⚪';
    lines.push(
      `| ${gradeEmoji} **${r.grade}** | ${r.repo} | ${r.criticals} | ${r.warnings} | ${r.infos} | ✅ |`
    );
  }
  lines.push('');

  // Critical findings detail
  const criticalRepos = results.filter((r) => r.criticals > 0);
  if (criticalRepos.length > 0) {
    lines.push('## 🔴 Critical Findings');
    lines.push('');

    for (const r of criticalRepos) {
      lines.push(`### ${r.repo}`);
      lines.push('');
      const crits = r.findings.filter((f) => f.severity === 'critical');
      for (const f of crits) {
        const cweBadge = f.cweId ? ` \`${f.cweId}\`` : '';
        lines.push(`- **${f.message}**${cweBadge}`);
        lines.push(`  - File: \`${f.file}${f.line ? ':' + f.line : ''}\``);
        if (f.evidence) lines.push(`  - Evidence: \`${f.evidence}\``);
        lines.push(`  - Fix: ${f.fix}`);
      }
      lines.push('');
    }
  }

  // Warning findings summary (collapsed)
  const warningRepos = results.filter((r) => r.warnings > 0);
  if (warningRepos.length > 0) {
    lines.push('<details><summary>🟡 Warning Findings (' + summary.totalWarnings + ')</summary>');
    lines.push('');
    for (const r of warningRepos) {
      lines.push(`#### ${r.repo}`);
      lines.push('');
      const warns = r.findings.filter((f) => f.severity === 'warning');
      for (const f of warns) {
        lines.push(`- \`${f.file}${f.line ? ':' + f.line : ''}\` — ${f.message}`);
      }
      lines.push('');
    }
    lines.push('</details>');
    lines.push('');
  }

  lines.push('---');
  lines.push(`*Generated by [Vibe Audit](https://github.com/jackdog668/vibeaudit) on ${now}*`);

  const output = lines.join('\n');
  console.log(output);
  return output;
}
