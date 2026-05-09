import { bold, dim, red, yellow, cyan, green, gray } from '../colors.js';
import { aggregateResults } from '../batch.js';

/**
 * Print a fleet-wide summary table to the terminal.
 *
 * @param {import('../batch.js').RepoResult[]} results
 */
export function reportBatchTerminal(results) {
  const agg = aggregateResults(results);
  const successful = results.filter(r => !r.error);
  const failed = results.filter(r => r.error);

  console.log('');
  console.log(bold('  VIBE AUDIT — FLEET SCAN'));
  console.log(dim('  ─────────────────────────────────────────────────────────────────────────'));
  console.log('');

  // Summary
  console.log(`  ${bold('Repos:')} ${green(bold(String(agg.reposScanned)))} scanned${agg.reposFailed > 0 ? `, ${red(bold(String(agg.reposFailed)))} failed` : ''}`);
  console.log(`  ${bold('Findings:')} ${red(bold(String(agg.totalCritical)))} critical · ${yellow(String(agg.totalWarning))} warnings · ${cyan(String(agg.totalInfo))} info`);
  console.log(`  ${bold('Grades:')} ${green(`A:${agg.gradeCounts.A}`)} ${green(`B:${agg.gradeCounts.B}`)} ${yellow(`C:${agg.gradeCounts.C}`)} ${yellow(`D:${agg.gradeCounts.D}`)} ${red(`F:${agg.gradeCounts.F}`)}`);
  console.log('');

  // Table header
  const cols = { repo: 40, grade: 7, crit: 6, warn: 6, info: 6, total: 7, time: 8 };
  const header = [
    pad('REPO', cols.repo),
    pad('GRADE', cols.grade),
    pad('CRIT', cols.crit),
    pad('WARN', cols.warn),
    pad('INFO', cols.info),
    pad('TOTAL', cols.total),
    pad('TIME', cols.time),
  ].join('  ');
  console.log(dim(`  ${header}`));
  console.log(dim(`  ${'─'.repeat(header.length)}`));

  // Table rows
  for (const r of successful) {
    const gradeStr = colorGrade(r.grade);
    const critStr = r.critical > 0 ? red(bold(String(r.critical))) : dim('0');
    const warnStr = r.warning > 0 ? yellow(String(r.warning)) : dim('0');
    const infoStr = r.info > 0 ? cyan(String(r.info)) : dim('0');
    const totalStr = r.total > 0 ? bold(String(r.total)) : dim('0');
    const timeStr = r.durationMs > 1000
      ? gray(`${(r.durationMs / 1000).toFixed(1)}s`)
      : gray(`${r.durationMs}ms`);

    const repoName = r.repo.length > cols.repo - 1
      ? r.repo.slice(0, cols.repo - 4) + '...'
      : r.repo;

    console.log(`  ${pad(repoName, cols.repo)}  ${pad(gradeStr, cols.grade, true)}  ${pad(critStr, cols.crit, true)}  ${pad(warnStr, cols.warn, true)}  ${pad(infoStr, cols.info, true)}  ${pad(totalStr, cols.total, true)}  ${timeStr}`);
  }

  // Failed repos
  if (failed.length > 0) {
    console.log('');
    console.log(red(bold('  FAILED:')));
    for (const r of failed) {
      console.log(`    ${red('✗')} ${r.repo} — ${dim(r.error)}`);
    }
  }

  console.log('');
  console.log(dim(`  ─────────────────────────────────────────────────────────────────────────`));

  // Top rules
  if (agg.topRules.length > 0) {
    console.log('');
    console.log(bold('  TOP RECURRING ISSUES:'));
    for (const [ruleId, count] of agg.topRules.slice(0, 5)) {
      const reposWithRule = successful.filter(r => r.findings.some(f => f.ruleId === ruleId)).length;
      console.log(`    ${bold(String(count))} ${dim('hits')} · ${ruleId} ${dim(`(${reposWithRule}/${agg.reposScanned} repos)`)}`);
    }
    console.log('');
  }

  // Bottom line
  if (agg.totalCritical > 0) {
    console.log(red(bold(`  ${agg.totalCritical} critical findings across ${agg.gradeCounts.F} repos need immediate attention.`)));
  } else if (agg.totalWarning > 0) {
    console.log(yellow(bold(`  ${agg.totalWarning} warnings across your fleet. Review before going live.`)));
  } else {
    console.log(green(bold('  Fleet is clean. Ship it.')));
  }
  console.log('');
}

/**
 * Print batch results as JSON to stdout.
 */
export function reportBatchJSON(results) {
  const agg = aggregateResults(results);
  const output = {
    summary: agg,
    repos: results.map(r => ({
      repo: r.repo,
      grade: r.grade,
      critical: r.critical,
      warning: r.warning,
      info: r.info,
      total: r.total,
      durationMs: r.durationMs,
      error: r.error,
      findings: r.findings,
    })),
  };
  console.log(JSON.stringify(output, null, 2));
}

function colorGrade(grade) {
  switch (grade) {
    case 'A': return green(bold(grade));
    case 'B': return green(grade);
    case 'C': return yellow(grade);
    case 'D': return yellow(bold(grade));
    case 'F': return red(bold(grade));
    default: return gray(grade);
  }
}

function pad(str, width, rightAlign = false) {
  // Strip ANSI for length calculation
  const stripped = str.replace(/\x1b\[[0-9;]*m/g, '');
  const diff = width - stripped.length;
  if (diff <= 0) return str;
  const spaces = ' '.repeat(diff);
  return rightAlign ? spaces + str : str + spaces;
}
