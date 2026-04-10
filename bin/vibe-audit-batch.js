#!/usr/bin/env node

/**
 * vibe-audit batch CLI
 * Scan multiple GitHub repos in one run — replaces the DigitalOcean cron bot.
 *
 * Usage:
 *   npx vibe-audit-batch --org <github-org>
 *   npx vibe-audit-batch --user <github-user>
 *   npx vibe-audit-batch --repos-file repos.json
 *   npx vibe-audit-batch --repos owner/repo1,owner/repo2
 *
 * Options:
 *   --org <name>             Discover all repos from a GitHub org
 *   --user <name>            Discover all repos from a GitHub user
 *   --repos <list>           Comma-separated list of owner/repo
 *   --repos-file <path>      Path to JSON config file
 *   --format <json|markdown|terminal>  Output format (default: terminal)
 *   --output <path>          Write report to file (instead of stdout)
 *   --concurrency <n>        Max parallel scans (default: 3)
 *   --rules <id,id,...>      Only run specific rules
 *   --exclude <id,id,...>    Skip specific rules
 *   --strict                 Exit 1 on any warnings
 *   --help                   Show help
 */

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { batchAudit, resolveRepoList, formatBatchMarkdown, formatBatchJSON } from '../src/batch.js';
import { bold, cyan, dim, red, yellow, green, gray } from '../src/colors.js';

const { values } = parseArgs({
  options: {
    org: { type: 'string' },
    user: { type: 'string' },
    repos: { type: 'string' },
    'repos-file': { type: 'string' },
    format: { type: 'string', short: 'f', default: 'terminal' },
    output: { type: 'string', short: 'o' },
    concurrency: { type: 'string', short: 'c' },
    rules: { type: 'string', short: 'r' },
    exclude: { type: 'string', short: 'e' },
    strict: { type: 'boolean', short: 's' },
    help: { type: 'boolean', short: 'h' },
  },
});

// ─── Help ────────────────────────────────────────────────────────────────────

if (values.help) {
  console.log(`
${bold('⚗️  vibe-audit batch')} — Scan multiple GitHub repos in one run

${bold('USAGE')}
  ${cyan('npx vibe-audit-batch')} ${dim('[options]')}

${bold('REPO SOURCES')} ${dim('(combine any of these)')}
  ${cyan('--org')} <name>              Discover all repos from a GitHub org
  ${cyan('--user')} <name>             Discover all repos from a GitHub user
  ${cyan('--repos')} <list>            Comma-separated owner/repo list
  ${cyan('--repos-file')} <path>       JSON config file (see repos.example.json)

${bold('OPTIONS')}
  ${cyan('-f, --format')} <terminal|json|markdown>  Output format ${dim('(default: terminal)')}
  ${cyan('-o, --output')} <path>       Write report to file instead of stdout
  ${cyan('-c, --concurrency')} <n>     Max parallel scans ${dim('(default: 3)')}
  ${cyan('-r, --rules')} <id,id,...>   Only run these rules
  ${cyan('-e, --exclude')} <id,id,...> Skip these rules
  ${cyan('-s, --strict')}              Exit 1 on warnings too

${bold('ENVIRONMENT')}
  ${cyan('GITHUB_TOKEN')}              Required for private repos & higher rate limits
  ${cyan('GH_TOKEN')}                  Alternative token variable

${bold('EXAMPLES')}
  ${dim('# Scan all repos in an org')}
  npx vibe-audit-batch --org my-company --format markdown --output report.md

  ${dim('# Scan specific repos')}
  npx vibe-audit-batch --repos user/app1,user/app2,user/api

  ${dim('# Use a config file')}
  npx vibe-audit-batch --repos-file repos.json --format json

  ${dim('# Morning scan (used by GitHub Actions cron)')}
  npx vibe-audit-batch --org my-company --format markdown --output scan-report.md

${bold('CONFIG FILE FORMAT')} ${dim('(repos.json)')}
  {
    "org": "my-company",
    "repos": ["extra/repo1"],
    "exclude": ["my-company/archived-thing"],
    "include": []
  }

${dim('Replaces the old DigitalOcean scheduled bot — runs anywhere Node runs.')}
`);
  process.exit(0);
}

// ─── Resolve repo list ───────────────────────────────────────────────────────

async function main() {
  const repoConfig = {};

  // From --repos-file.
  if (values['repos-file']) {
    try {
      const raw = await readFile(resolve(values['repos-file']), 'utf8');
      const parsed = JSON.parse(raw);
      Object.assign(repoConfig, parsed);
    } catch (err) {
      console.error(red(`\n  Error reading repos file: ${err.message}\n`));
      process.exit(2);
    }
  }

  // CLI flags override / supplement the config file.
  if (values.org) repoConfig.org = values.org;
  if (values.user) repoConfig.user = values.user;
  if (values.repos) {
    repoConfig.repos = [
      ...(repoConfig.repos || []),
      ...values.repos.split(',').map((s) => s.trim()).filter(Boolean),
    ];
  }

  if (!repoConfig.repos?.length && !repoConfig.org && !repoConfig.user) {
    console.error(red('\n  Error: No repos specified.'));
    console.error(dim('  Use --org, --user, --repos, or --repos-file to specify repos.\n'));
    console.error(dim('  Run with --help for usage.\n'));
    process.exit(2);
  }

  // Discover & resolve the full list.
  const format = values.format || 'terminal';
  const isTerminal = format === 'terminal';

  if (isTerminal) {
    console.log('');
    console.log(bold('  ⚗️  VIBE AUDIT — Batch Scanner'));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log('');
  }

  let repos;
  try {
    if (isTerminal) process.stdout.write(dim('  Discovering repos...'));
    repos = await resolveRepoList(repoConfig);
    if (isTerminal) console.log(dim(` found ${repos.length} repos.`));
  } catch (err) {
    console.error(red(`\n  Error discovering repos: ${err.message}\n`));
    process.exit(2);
  }

  if (repos.length === 0) {
    console.error(red('\n  No repos found to scan.\n'));
    process.exit(2);
  }

  if (isTerminal) {
    console.log(dim(`  Scanning ${repos.length} repos (concurrency: ${values.concurrency || 3})...`));
    console.log('');
  }

  // Run the batch scan.
  const concurrency = values.concurrency ? parseInt(values.concurrency, 10) : 3;
  let completed = 0;

  const onRepoComplete = isTerminal ? (result) => {
    completed++;
    const progress = `[${completed}/${repos.length}]`;
    if (result.error) {
      console.log(`  ${gray(progress)} ${red('✗')} ${result.repo} ${dim(`— ${result.error}`)}`);
    } else {
      const crit = result.findings.filter((f) => f.severity === 'critical').length;
      const warn = result.findings.filter((f) => f.severity === 'warning').length;
      const total = result.findings.length;

      if (crit > 0) {
        console.log(`  ${gray(progress)} ${red('●')} ${bold(result.repo)} ${red(bold(`${crit}C`))} ${yellow(`${warn}W`)} ${dim(`${total} total · ${result.filesScanned} files · ${result.durationMs}ms`)}`);
      } else if (warn > 0) {
        console.log(`  ${gray(progress)} ${yellow('▲')} ${result.repo} ${yellow(`${warn}W`)} ${dim(`${total} total · ${result.filesScanned} files · ${result.durationMs}ms`)}`);
      } else if (total > 0) {
        console.log(`  ${gray(progress)} ${cyan('ℹ')} ${result.repo} ${dim(`${total} info · ${result.filesScanned} files · ${result.durationMs}ms`)}`);
      } else {
        console.log(`  ${gray(progress)} ${green('✓')} ${result.repo} ${dim(`clean · ${result.filesScanned} files · ${result.durationMs}ms`)}`);
      }
    }
  } : undefined;

  const batchResult = await batchAudit(repos, {
    rules: values.rules?.split(',').filter(Boolean),
    exclude: values.exclude?.split(',').filter(Boolean),
    concurrency,
    onRepoComplete,
  });

  const { summary } = batchResult;

  // ─── Output ─────────────────────────────────────────────────────────────────

  let output;

  switch (format) {
    case 'json':
      output = formatBatchJSON(batchResult);
      break;
    case 'markdown':
      output = formatBatchMarkdown(batchResult);
      break;
    default:
      // Terminal: print summary dashboard.
      output = null; // Already printed per-repo progress above.
      break;
  }

  if (format === 'terminal') {
    // Print terminal summary.
    console.log('');
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log('');

    const gradeColor = { A: green, B: green, C: yellow, D: yellow, F: red }[summary.grade];
    console.log(`  ${gradeColor(bold(`GRADE: ${summary.grade}`))}  ${dim('│')}  ${bold(String(summary.reposScanned))} ${dim('repos')}  ${dim('│')}  ${red(bold(String(summary.totalCritical)))} ${dim('critical')}  ${dim('│')}  ${yellow(bold(String(summary.totalWarning)))} ${dim('warnings')}`);
    console.log('');

    console.log(`  ${green(bold(String(summary.reposClean)))} ${dim('clean')}  ${dim('·')}  ${red(bold(String(summary.reposWithCritical)))} ${dim('with criticals')}  ${dim('·')}  ${summary.reposFailed > 0 ? yellow(String(summary.reposFailed)) : dim('0')} ${dim('failed')}`);
    console.log(`  ${dim(`${summary.totalFiles} total files · ${(summary.totalDurationMs / 1000).toFixed(1)}s total`)}`);
    console.log('');

    if (summary.totalCritical > 0) {
      console.log(red(bold('  ⛔ Critical issues found across your repos. Review the report.')));
    } else if (summary.totalWarning > 0) {
      console.log(yellow(bold('  ⚠️  Warnings found. Review before shipping.')));
    } else {
      console.log(green(bold('  ✅ All repos clean. Ship it.')));
    }
    console.log('');
  } else if (output) {
    if (values.output) {
      await writeFile(resolve(values.output), output);
      if (process.stderr.isTTY) {
        console.error(dim(`  Report written to ${values.output}`));
      }
    } else {
      console.log(output);
    }
  }

  // Exit code.
  const hasCritical = summary.totalCritical > 0;
  const hasWarning = summary.totalWarning > 0;
  const exitCode = hasCritical ? 1 : values.strict && hasWarning ? 1 : 0;
  process.exit(exitCode);
}

main().catch((err) => {
  console.error(red(`\n  Fatal error: ${err.message}\n`));
  process.exit(2);
});
