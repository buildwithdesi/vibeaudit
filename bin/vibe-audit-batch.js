#!/usr/bin/env node

/**
 * vibe-audit batch scanner
 * Scan 70+ repos in one run — replaces DigitalOcean cron bot.
 *
 * Usage:
 *   npx vibe-audit-batch --org my-org
 *   npx vibe-audit-batch --repos repos.json
 *   npx vibe-audit-batch --repos owner/repo1,owner/repo2
 */

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { batchAudit, fetchOrgRepos } from '../src/batch.js';
import { bold, cyan, dim, red, yellow, green, gray } from '../src/colors.js';

const { values } = parseArgs({
  options: {
    org: { type: 'string' },
    user: { type: 'string' },
    repos: { type: 'string' },
    concurrency: { type: 'string', short: 'c' },
    format: { type: 'string', short: 'f' },
    output: { type: 'string', short: 'o' },
    rules: { type: 'string', short: 'r' },
    exclude: { type: 'string', short: 'e' },
    strict: { type: 'boolean', short: 's' },
    help: { type: 'boolean', short: 'h' },
  },
});

if (values.help) {
  console.log(`
${bold('⚗️  vibe-audit batch')} — Multi-repo security scanner

${bold('USAGE')}
  ${cyan('npx vibe-audit-batch')} ${dim('[options]')}

${bold('REPO SOURCES')} ${dim('(pick one)')}
  ${cyan('--org')} <name>              Scan all repos in a GitHub org
  ${cyan('--user')} <name>             Scan all repos for a GitHub user
  ${cyan('--repos')} <file|list>       JSON file with repo list, or comma-separated repos

${bold('OPTIONS')}
  ${cyan('-c, --concurrency')} <n>     Parallel scans (default: 5)
  ${cyan('-f, --format')} <fmt>        Output: terminal, json, markdown (default: terminal)
  ${cyan('-o, --output')} <file>       Write report to file instead of stdout
  ${cyan('-r, --rules')} <id,id,...>   Only run specific rules
  ${cyan('-e, --exclude')} <id,id,...> Exclude specific rules
  ${cyan('-s, --strict')}              Mark warnings as failures too

${bold('EXAMPLES')}
  ${dim('# Scan all repos in an org')}
  npx vibe-audit-batch --org my-org

  ${dim('# Scan repos from a config file')}
  npx vibe-audit-batch --repos repos.json

  ${dim('# Scan specific repos, JSON output')}
  npx vibe-audit-batch --repos user/app1,user/app2 --format json

  ${dim('# Save markdown report')}
  npx vibe-audit-batch --org my-org --format markdown --output report.md

${bold('REPO CONFIG FILE')} ${dim('(repos.json)')}
  ${dim('Simple list:')}
  ["owner/repo1", "owner/repo2"]

  ${dim('With per-repo overrides:')}
  [
    "owner/repo1",
    { "repo": "owner/repo2", "rules": ["exposed-secrets"] }
  ]

${bold('ENV')}
  ${cyan('GITHUB_TOKEN')}  Required for private repos and to avoid rate limits

${dim('Built by Digital Alchemy Academy — https://digitalalchemy.dev')}
`);
  process.exit(0);
}

// ─── Resolve repo list ──────────────────────────────────────────────────────

async function resolveRepos() {
  if (values.org) {
    console.error(dim(`  Fetching repos for org: ${values.org}...`));
    return fetchOrgRepos(values.org, { type: 'org' });
  }

  if (values.user) {
    console.error(dim(`  Fetching repos for user: ${values.user}...`));
    return fetchOrgRepos(values.user, { type: 'user' });
  }

  if (values.repos) {
    if (values.repos.endsWith('.json')) {
      const raw = await readFile(resolve(values.repos), 'utf8');
      return JSON.parse(raw);
    }
    return values.repos.split(',').filter(Boolean);
  }

  console.error(red('\n  Error: Provide --org, --user, or --repos\n'));
  console.error(dim('  Run with --help for usage.\n'));
  process.exit(2);
}

// ─── Main ────────────────────────────────────────────────────────────────────

try {
  const repos = await resolveRepos();
  const concurrency = parseInt(values.concurrency || '5', 10);
  const format = values.format || 'terminal';
  const rules = values.rules?.split(',').filter(Boolean);
  const exclude = values.exclude?.split(',').filter(Boolean);
  const strict = values.strict ?? false;

  console.error('');
  console.error(bold('  ⚗️  VIBE AUDIT — Batch Scanner'));
  console.error(dim('  ─────────────────────────────────────────────────────────'));
  console.error(dim(`  ${repos.length} repos · concurrency ${concurrency}`));
  console.error('');

  let completed = 0;

  const { results, summary } = await batchAudit(repos, {
    concurrency,
    strict,
    rules,
    exclude,
    onResult(result) {
      completed++;
      const pct = Math.round((completed / repos.length) * 100);
      const icon = result.status === 'error' ? red('✗')
        : result.counts.critical > 0 ? red('●')
          : result.counts.warning > 0 ? yellow('▲')
            : green('✓');
      console.error(
        `  ${dim(`[${String(completed).padStart(3)}/${repos.length}]`)} ${icon} ${result.repo} ${dim(`${result.durationMs}ms`)} ${result.counts.total > 0 ? dim(`(${result.counts.critical}C ${result.counts.warning}W ${result.counts.info}I)`) : ''}`
      );
    },
  });

  console.error('');

  const output = formatOutput(format, results, summary);

  if (values.output) {
    await writeFile(resolve(values.output), output);
    console.error(green(`  Report saved to ${values.output}`));
  } else {
    console.log(output);
  }

  console.error('');

  const exitCode = summary.totalCritical > 0 ? 1 : strict && summary.totalWarning > 0 ? 1 : 0;
  process.exit(exitCode);
} catch (err) {
  console.error(red(`\n  Error: ${err.message}\n`));
  process.exit(2);
}

// ─── Output Formatters ──────────────────────────────────────────────────────

function formatOutput(format, results, summary) {
  switch (format) {
    case 'json':
      return JSON.stringify({ summary, results: results.map(minResult) }, null, 2);
    case 'markdown':
      return formatMarkdown(results, summary);
    default:
      return formatTerminalSummary(results, summary);
  }
}

function minResult(r) {
  return {
    repo: r.repo,
    status: r.status,
    grade: r.grade,
    counts: r.counts,
    durationMs: r.durationMs,
    error: r.error,
    findings: r.findings,
  };
}

function formatTerminalSummary(_results, summary) {
  const lines = [];
  lines.push('');
  lines.push(bold('  ⚗️  BATCH AUDIT SUMMARY'));
  lines.push(dim('  ─────────────────────────────────────────────────────────'));
  lines.push('');
  lines.push(`  ${bold('Repos scanned:')} ${summary.reposScanned}${summary.reposErrored ? `  ${red(`(${summary.reposErrored} errors)`)}` : ''}`);
  lines.push(`  ${bold('Total findings:')} ${summary.totalFindings}`);
  lines.push(`    ${red(bold(`${summary.totalCritical}`))} critical · ${yellow(`${summary.totalWarning}`)} warnings · ${cyan(`${summary.totalInfo}`)} info`);
  lines.push('');

  const gradeBar = [
    green(`${summary.grades.A || 0} A`),
    yellow(`${summary.grades.C || 0} C`),
    yellow(`${summary.grades.D || 0} D`),
    red(`${summary.grades.F || 0} F`),
  ].join(dim(' · '));
  lines.push(`  ${bold('Grades:')} ${gradeBar}`);
  lines.push('');

  if (summary.topOffenders.length > 0) {
    lines.push(bold('  Top Offenders'));
    lines.push(dim('  ─────────────────────────────────────────────────────────'));
    for (const r of summary.topOffenders) {
      const g = r.grade === 'F' ? red(bold(r.grade)) : r.grade === 'D' ? yellow(r.grade) : r.grade === 'C' ? yellow(r.grade) : green(r.grade);
      lines.push(`  ${g}  ${r.repo}  ${dim(`${r.critical}C ${r.warning}W ${r.total} total`)}`);
    }
    lines.push('');
  }

  if (summary.topRules.length > 0) {
    lines.push(bold('  Most Common Issues'));
    lines.push(dim('  ─────────────────────────────────────────────────────────'));
    for (const { ruleId, count } of summary.topRules) {
      lines.push(`  ${dim(String(count).padStart(4))}x  ${ruleId}`);
    }
    lines.push('');
  }

  if (summary.errors.length > 0) {
    lines.push(yellow(bold('  Errors')));
    for (const { repo, error } of summary.errors) {
      lines.push(`  ${red('✗')} ${repo}: ${dim(error)}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function formatMarkdown(_results, summary) {
  const lines = [
    '# ⚗️ Vibe Audit — Batch Report',
    '',
    `> Scanned **${summary.reposScanned}** repos | ${summary.totalCritical} critical · ${summary.totalWarning} warnings · ${summary.totalInfo} info`,
    '',
    '## Dashboard',
    '',
    '| Metric | Count |',
    '|--------|-------|',
    `| Repos scanned | ${summary.reposScanned} |`,
    `| Repos errored | ${summary.reposErrored} |`,
    `| Total findings | ${summary.totalFindings} |`,
    `| Critical | ${summary.totalCritical} |`,
    `| Warnings | ${summary.totalWarning} |`,
    `| Info | ${summary.totalInfo} |`,
    '',
    '### Grade Distribution',
    '',
    `| Grade | Repos |`,
    `|-------|-------|`,
    `| A | ${summary.grades.A || 0} |`,
    `| C | ${summary.grades.C || 0} |`,
    `| D | ${summary.grades.D || 0} |`,
    `| F | ${summary.grades.F || 0} |`,
    '',
  ];

  if (summary.topOffenders.length > 0) {
    lines.push('## Top Offenders', '');
    lines.push('| Repo | Grade | Critical | Warning | Total |');
    lines.push('|------|-------|----------|---------|-------|');
    for (const r of summary.topOffenders) {
      lines.push(`| ${r.repo} | ${r.grade} | ${r.critical} | ${r.warning} | ${r.total} |`);
    }
    lines.push('');
  }

  if (summary.topRules.length > 0) {
    lines.push('## Most Common Issues', '');
    lines.push('| Rule | Hits |');
    lines.push('|------|------|');
    for (const { ruleId, count } of summary.topRules) {
      lines.push(`| \`${ruleId}\` | ${count} |`);
    }
    lines.push('');
  }

  if (summary.errors.length > 0) {
    lines.push('## Errors', '');
    for (const { repo, error } of summary.errors) {
      lines.push(`- **${repo}**: ${error}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
