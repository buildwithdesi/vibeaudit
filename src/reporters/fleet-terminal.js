import { bold, dim, red, yellow, cyan, green, gray } from '../colors.js';

const GRADE_COLORS = { A: green, B: green, C: yellow, D: yellow, F: red };

function gradeStr(grade) {
  const color = GRADE_COLORS[grade] || gray;
  return color(bold(grade));
}

function severityBar(crit, warn, info) {
  const parts = [];
  if (crit > 0) parts.push(red(bold(`${crit}C`)));
  if (warn > 0) parts.push(yellow(`${warn}W`));
  if (info > 0) parts.push(cyan(`${info}I`));
  if (parts.length === 0) parts.push(green('clean'));
  return parts.join(dim('/'));
}

/**
 * Print fleet results to terminal.
 * @param {import('../fleet.js').FleetResult} fleet
 */
export function reportFleetTerminal(fleet) {
  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — FLEET SCAN'));
  console.log(dim('  Security audit across your repos'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // Summary cards
  const overallGrade = fleet.totalCritical > 0 ? 'F'
    : fleet.totalWarning > 20 ? 'D'
    : fleet.totalWarning > 0 ? 'C'
    : fleet.totalInfo > 0 ? 'B'
    : 'A';

  console.log(`  ${gradeStr(overallGrade)} ${dim('Overall')}  ${dim('│')}  ${bold(String(fleet.scannedRepos))} repos scanned  ${dim('│')}  ${red(bold(String(fleet.totalCritical)))} ${dim('crit')}  ${yellow(bold(String(fleet.totalWarning)))} ${dim('warn')}  ${cyan(bold(String(fleet.totalInfo)))} ${dim('info')}`);
  console.log('');

  if (fleet.failedRepos > 0) {
    console.log(yellow(`  ⚠  ${fleet.failedRepos} repo(s) failed to scan`));
    console.log('');
  }

  // Sort: worst grade first, then by critical count
  const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
  const sorted = [...fleet.repos].sort((a, b) => {
    const gDiff = (gradeOrder[a.grade] ?? 9) - (gradeOrder[b.grade] ?? 9);
    if (gDiff !== 0) return gDiff;
    return b.critical - a.critical;
  });

  // Table header
  const nameWidth = Math.min(40, Math.max(20, ...sorted.map(r => r.repo.length + 2)));
  console.log(dim(`  ${'REPO'.padEnd(nameWidth)} GRADE  FINDINGS       FILES  TIME`));
  console.log(dim('  ' + '─'.repeat(nameWidth + 45)));

  for (const r of sorted) {
    if (r.error) {
      const name = r.repo.padEnd(nameWidth);
      console.log(`  ${gray(name)} ${gray('ERR')}    ${dim(r.error.slice(0, 40))}`);
      continue;
    }

    const name = (r.total > 0 && r.critical > 0 ? bold(r.repo) : r.repo).padEnd(nameWidth);
    const grade = gradeStr(r.grade).padEnd(14);
    const findings = severityBar(r.critical, r.warning, r.info).padEnd(25);
    const files = String(r.filesScanned).padStart(5);
    const time = dim(`${(r.durationMs / 1000).toFixed(1)}s`);

    console.log(`  ${name} ${grade} ${findings} ${files}  ${time}`);
  }

  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log(dim(`  ${fleet.totalRepos} repos · ${fleet.totalFindings} findings · ${(fleet.durationMs / 1000).toFixed(1)}s total`));
  console.log('');

  // Top offenders
  const critRepos = sorted.filter(r => r.critical > 0);
  if (critRepos.length > 0) {
    console.log(red(bold('  ⛔ REPOS WITH CRITICAL ISSUES:')));
    for (const r of critRepos) {
      const topRules = topRuleIds(r.findings, 'critical', 3);
      console.log(`     ${bold(r.repo)} — ${r.critical} critical ${dim('(' + topRules.join(', ') + ')')}`);
    }
    console.log('');
  }

  // Grade distribution
  const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of fleet.repos) {
    if (r.grade in grades) grades[r.grade]++;
  }
  const distParts = Object.entries(grades)
    .filter(([, n]) => n > 0)
    .map(([g, n]) => `${(GRADE_COLORS[g] || gray)(bold(g))}:${n}`);
  console.log(`  ${dim('Grade distribution:')} ${distParts.join('  ')}`);
  console.log('');
}

function topRuleIds(findings, severity, n) {
  const counts = new Map();
  for (const f of findings) {
    if (f.severity === severity) {
      counts.set(f.ruleId, (counts.get(f.ruleId) || 0) + 1);
    }
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([id]) => id);
}
