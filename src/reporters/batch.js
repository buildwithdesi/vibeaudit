import { bold, red, yellow, cyan, green, dim, gray } from '../colors.js';

/**
 * @typedef {Object} RepoResult
 * @property {string} owner
 * @property {string} repo
 * @property {string} label
 * @property {'ok' | 'error'} status
 * @property {string} [error]
 * @property {import('../rules/types.js').Finding[]} findings
 * @property {number} exitCode
 * @property {number} criticals
 * @property {number} warnings
 * @property {number} infos
 * @property {number} durationMs
 */

function grade(r) {
  if (r.status === 'error') return '?';
  if (r.criticals > 0) return 'F';
  if (r.warnings > 5) return 'D';
  if (r.warnings > 0) return 'C';
  if (r.infos > 0) return 'B';
  return 'A';
}

function totals(results) {
  let criticals = 0, warnings = 0, infos = 0, errors = 0, clean = 0;
  for (const r of results) {
    if (r.status === 'error') { errors++; continue; }
    criticals += r.criticals;
    warnings += r.warnings;
    infos += r.infos;
    if (r.criticals === 0 && r.warnings === 0 && r.infos === 0) clean++;
  }
  return { criticals, warnings, infos, errors, clean, total: results.length };
}

/**
 * Print a batch summary to the terminal.
 * @param {RepoResult[]} results
 * @param {{ durationMs: number }} meta
 */
export function reportBatchTerminal(results, meta) {
  const t = totals(results);
  const now = new Date();

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — Batch Scan'));
  console.log(dim(`  ${now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })} at ${now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}`));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Overall stats
  console.log(`  ${bold(`${t.total} repos scanned`)}  ${dim('│')}  ${green(bold(String(t.clean)))} ${dim('clean')}  ${dim('│')}  ${red(bold(String(t.criticals)))} ${dim('critical')}  ${dim('│')}  ${yellow(bold(String(t.warnings)))} ${dim('warnings')}  ${dim('│')}  ${cyan(bold(String(t.infos)))} ${dim('info')}`);
  if (t.errors > 0) {
    console.log(`  ${red(`${t.errors} repo(s) failed to scan`)}`);
  }
  console.log('');

  // Repos with criticals
  const critRepos = results.filter((r) => r.criticals > 0);
  if (critRepos.length > 0) {
    console.log(red(bold('  ⛔ CRITICAL — Fix before deploying')));
    console.log('');
    for (const r of critRepos) {
      console.log(`    ${red('●')} ${bold(r.label)}  ${red(bold(`${r.criticals}C`))} ${yellow(`${r.warnings}W`)} ${cyan(`${r.infos}I`)}`);
      const topFindings = r.findings
        .filter((f) => f.severity === 'critical')
        .slice(0, 3);
      for (const f of topFindings) {
        console.log(`      ${dim('└')} ${f.message} ${gray(`(${f.file}${f.line ? `:${f.line}` : ''})`)}`);
      }
      if (r.criticals > 3) {
        console.log(`      ${dim(`└ ...and ${r.criticals - 3} more criticals`)}`);
      }
    }
    console.log('');
  }

  // Repos with warnings only
  const warnRepos = results.filter((r) => r.criticals === 0 && r.warnings > 0);
  if (warnRepos.length > 0) {
    console.log(yellow(bold('  ⚠️  WARNINGS — Review before going live')));
    console.log('');
    for (const r of warnRepos) {
      console.log(`    ${yellow('▲')} ${bold(r.label)}  ${yellow(`${r.warnings}W`)} ${cyan(`${r.infos}I`)}`);
    }
    console.log('');
  }

  // Clean repos
  const cleanRepos = results.filter((r) => r.status === 'ok' && r.criticals === 0 && r.warnings === 0 && r.infos === 0);
  if (cleanRepos.length > 0) {
    console.log(green(bold(`  ✅ ${cleanRepos.length} repos clean`)));
    console.log(`    ${dim(cleanRepos.map((r) => r.label).join(', '))}`);
    console.log('');
  }

  // Errors
  const errorRepos = results.filter((r) => r.status === 'error');
  if (errorRepos.length > 0) {
    console.log(red(bold('  ❌ Scan errors')));
    for (const r of errorRepos) {
      console.log(`    ${red('✕')} ${r.label}: ${dim(r.error || 'unknown error')}`);
    }
    console.log('');
  }

  // Timing
  const totalSec = (meta.durationMs / 1000).toFixed(1);
  console.log(dim(`  ─────────────────────────────────────────────────────────────`));
  console.log(dim(`  Completed in ${totalSec}s`));
  console.log('');
}

/**
 * Generate a JSON batch report.
 * @param {RepoResult[]} results
 * @param {{ durationMs: number }} meta
 * @returns {string}
 */
export function reportBatchJSON(results, meta) {
  const t = totals(results);

  const output = {
    timestamp: new Date().toISOString(),
    summary: {
      reposScanned: t.total,
      reposClean: t.clean,
      reposWithCriticals: results.filter((r) => r.criticals > 0).length,
      reposWithWarnings: results.filter((r) => r.warnings > 0).length,
      reposFailed: t.errors,
      totalCriticals: t.criticals,
      totalWarnings: t.warnings,
      totalInfos: t.infos,
      durationMs: meta.durationMs,
    },
    repos: results.map((r) => ({
      repo: r.label,
      status: r.status,
      grade: grade(r),
      criticals: r.criticals,
      warnings: r.warnings,
      infos: r.infos,
      durationMs: r.durationMs,
      ...(r.status === 'error' ? { error: r.error } : {}),
      findings: r.findings.map((f) => ({
        ruleId: f.ruleId,
        severity: f.severity,
        message: f.message,
        file: f.file,
        line: f.line,
        cweId: f.cweId,
        cvssScore: f.cvssScore,
      })),
    })),
  };

  return JSON.stringify(output, null, 2);
}

/**
 * Generate a Markdown batch report (suitable for GitHub Issues / Slack).
 * @param {RepoResult[]} results
 * @param {{ durationMs: number }} meta
 * @returns {string}
 */
export function reportBatchMarkdown(results, meta) {
  const t = totals(results);
  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  const lines = [
    `# ⚗️ Vibe Audit — Daily Scan`,
    `> ${dateStr}`,
    '',
    `| Metric | Count |`,
    `|--------|-------|`,
    `| Repos scanned | ${t.total} |`,
    `| Clean repos | ${t.clean} |`,
    `| Critical findings | ${t.criticals} |`,
    `| Warnings | ${t.warnings} |`,
    `| Info | ${t.infos} |`,
    `| Scan errors | ${t.errors} |`,
    `| Duration | ${(meta.durationMs / 1000).toFixed(1)}s |`,
    '',
  ];

  // Criticals
  const critRepos = results.filter((r) => r.criticals > 0);
  if (critRepos.length > 0) {
    lines.push('## 🔴 Repos with Critical Issues', '');
    for (const r of critRepos) {
      lines.push(`### \`${r.label}\` — ${r.criticals} critical, ${r.warnings} warnings`, '');
      const crits = r.findings.filter((f) => f.severity === 'critical');
      for (const f of crits) {
        const cwe = f.cweId ? ` \`${f.cweId}\`` : '';
        lines.push(`- **${f.message}**${cwe} — \`${f.file}${f.line ? `:${f.line}` : ''}\``);
        if (f.fix) lines.push(`  - Fix: ${f.fix}`);
      }
      lines.push('');
    }
  }

  // Warnings
  const warnRepos = results.filter((r) => r.criticals === 0 && r.warnings > 0);
  if (warnRepos.length > 0) {
    lines.push('## 🟡 Repos with Warnings', '');
    lines.push('| Repo | Warnings | Info |');
    lines.push('|------|----------|------|');
    for (const r of warnRepos) {
      lines.push(`| \`${r.label}\` | ${r.warnings} | ${r.infos} |`);
    }
    lines.push('');
  }

  // Clean
  const cleanRepos = results.filter((r) => r.status === 'ok' && r.criticals === 0 && r.warnings === 0 && r.infos === 0);
  if (cleanRepos.length > 0) {
    lines.push(`## ✅ Clean Repos (${cleanRepos.length})`, '');
    lines.push(cleanRepos.map((r) => `\`${r.label}\``).join(', '));
    lines.push('');
  }

  // Errors
  const errorRepos = results.filter((r) => r.status === 'error');
  if (errorRepos.length > 0) {
    lines.push('## ❌ Scan Errors', '');
    for (const r of errorRepos) {
      lines.push(`- \`${r.label}\`: ${r.error || 'unknown error'}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
