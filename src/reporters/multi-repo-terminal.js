import { bold, red, yellow, cyan, green, dim, gray } from '../colors.js';
import { aggregateResults } from '../multi-repo.js';

/**
 * Print a multi-repo summary to the terminal.
 *
 * @param {Array} results - Output from scanRepos()
 */
export function reportMultiRepoTerminal(results) {
  const agg = aggregateResults(results);

  const overallGrade = agg.totalCriticals > 0 ? 'F'
    : agg.totalWarnings > 20 ? 'D'
    : agg.totalWarnings > 0 ? 'C'
    : agg.totalInfos > 0 ? 'B' : 'A';

  const gradeColor = { A: green, B: green, C: yellow, D: yellow, F: red }[overallGrade] || dim;

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — MULTI-REPO SCAN'));
  console.log(dim('  Morning security scan across all repos'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  console.log(`  ${gradeColor(bold(`OVERALL GRADE: ${overallGrade}`))}  ${dim('│')}  ${bold(String(agg.totalRepos))} ${dim('repos')}  ${dim('│')}  ${red(bold(String(agg.totalCriticals)))} ${dim('critical')}  ${dim('│')}  ${yellow(bold(String(agg.totalWarnings)))} ${dim('warnings')}  ${dim('│')}  ${cyan(bold(String(agg.totalInfos)))} ${dim('info')}`);
  console.log('');

  // Grade distribution
  const grades = ['F', 'D', 'C', 'B', 'A'];
  const gradeColors = { A: green, B: green, C: yellow, D: yellow, F: red };
  const gradeParts = grades
    .filter(g => (agg.gradeDistribution[g] || 0) > 0)
    .map(g => {
      const count = agg.gradeDistribution[g];
      const colorFn = gradeColors[g];
      return `${colorFn(bold(g))} ${dim('×')} ${count}`;
    });
  console.log(`  ${dim('Grades:')} ${gradeParts.join(dim('  │  '))}`);
  console.log('');

  // Repos needing attention (grade F and D first)
  const needsAttention = results.filter(r => r.grade === 'F' || r.grade === 'D');
  if (needsAttention.length > 0) {
    console.log(red(bold('  ⛔ REPOS NEEDING ATTENTION')));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    for (const r of needsAttention) {
      const grFn = r.grade === 'F' ? red : yellow;
      const label = `${r.owner}/${r.repo}`;
      const counts = [];
      if (r.criticals > 0) counts.push(red(bold(`${r.criticals}C`)));
      if (r.warnings > 0) counts.push(yellow(`${r.warnings}W`));
      if (r.infos > 0) counts.push(cyan(`${r.infos}I`));
      console.log(`  ${grFn(bold(r.grade))}  ${bold(label.padEnd(40))} ${counts.join(dim(','))}  ${dim(`${r.durationMs}ms`)}`);
    }
    console.log('');
  }

  // Repos with warnings (grade C)
  const hasWarnings = results.filter(r => r.grade === 'C');
  if (hasWarnings.length > 0) {
    console.log(yellow(bold('  ⚠️  REPOS WITH WARNINGS')));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    for (const r of hasWarnings) {
      const label = `${r.owner}/${r.repo}`;
      const counts = [];
      if (r.warnings > 0) counts.push(yellow(`${r.warnings}W`));
      if (r.infos > 0) counts.push(cyan(`${r.infos}I`));
      console.log(`  ${yellow(bold('C'))}  ${label.padEnd(40)} ${counts.join(dim(','))}  ${dim(`${r.durationMs}ms`)}`);
    }
    console.log('');
  }

  // Clean repos
  const clean = results.filter(r => r.grade === 'A' || r.grade === 'B');
  if (clean.length > 0) {
    console.log(green(bold(`  ✅ CLEAN REPOS (${clean.length})`)));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    const names = clean.map(r => `${r.owner}/${r.repo}`);
    for (let i = 0; i < names.length; i += 3) {
      const row = names.slice(i, i + 3).map(n => n.padEnd(35)).join('  ');
      console.log(`  ${green(bold('A'))}  ${dim(row)}`);
    }
    console.log('');
  }

  // Errors
  const errors = results.filter(r => r.error);
  if (errors.length > 0) {
    console.log(red(`  ❌ ERRORS (${errors.length})`));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    for (const r of errors) {
      console.log(`  ${red('?')}  ${r.owner}/${r.repo}  ${dim(r.error.slice(0, 60))}`);
    }
    console.log('');
  }

  // Top issues across repos
  if (agg.topRules.length > 0) {
    console.log(bold('  📊 MOST COMMON ISSUES'));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    for (const r of agg.topRules.slice(0, 10)) {
      const bar = '█'.repeat(Math.min(r.count, 30));
      console.log(`  ${gray(r.ruleId.padEnd(35))} ${yellow(bar)} ${bold(String(r.count))}`);
    }
    console.log('');
  }

  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log(dim(`  ${agg.totalRepos} repos · ${agg.totalFindings} findings · ${new Date().toISOString().replace('T', ' ').slice(0, 16)} UTC`));
  console.log(dim('  Run with --format html to generate an interactive dashboard.'));
  console.log('');
}

/**
 * Output multi-repo results as JSON.
 *
 * @param {Array} results
 */
export function reportMultiRepoJSON(results) {
  const agg = aggregateResults(results);
  const output = {
    timestamp: new Date().toISOString(),
    summary: agg,
    repos: results.map(r => ({
      owner: r.owner,
      repo: r.repo,
      grade: r.grade,
      criticals: r.criticals,
      warnings: r.warnings,
      infos: r.infos,
      totalFindings: r.findings.length,
      durationMs: r.durationMs,
      error: r.error || null,
      findings: r.findings,
    })),
  };
  console.log(JSON.stringify(output, null, 2));
}
