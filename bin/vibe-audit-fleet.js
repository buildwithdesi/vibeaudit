#!/usr/bin/env node

/**
 * vibe-audit-fleet CLI
 * Morning security sweep across all repos in a GitHub org or user account.
 *
 * Usage:
 *   npx vibe-audit-fleet --org <name>     Scan all repos in an org
 *   npx vibe-audit-fleet --user <name>    Scan all repos for a user
 *   npx vibe-audit-fleet --repos <file>   Scan repos listed in a file (one owner/repo per line)
 */

import { readFile, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { listRepos, fleetScan, reportFleetTerminal, reportFleetJSON, reportFleetMarkdown } from '../src/fleet.js';
import { bold, cyan, dim, red, yellow } from '../src/colors.js';

const { values } = parseArgs({
  allowPositionals: false,
  options: {
    org: { type: 'string' },
    user: { type: 'string' },
    repos: { type: 'string' },
    format: { type: 'string', short: 'f', default: 'terminal' },
    concurrency: { type: 'string', short: 'c', default: '5' },
    rules: { type: 'string', short: 'r' },
    exclude: { type: 'string', short: 'e' },
    'include-archived': { type: 'boolean', default: false },
    'include-forks': { type: 'boolean', default: false },
    'min-stars': { type: 'string', default: '0' },
    'out-file': { type: 'string', short: 'o' },
    help: { type: 'boolean', short: 'h' },
  },
});

if (values.help) {
  console.log(`
${bold('⚗️  vibe-audit-fleet')} — Morning security sweep for your entire fleet

${bold('USAGE')}
  ${cyan('npx vibe-audit-fleet')} ${dim('--org <name>')}        Scan all repos in a GitHub org
  ${cyan('npx vibe-audit-fleet')} ${dim('--user <name>')}       Scan all repos for a GitHub user
  ${cyan('npx vibe-audit-fleet')} ${dim('--repos <file>')}      Scan repos listed in a file

${bold('OPTIONS')}
  ${cyan('--org <name>')}             GitHub organization to scan
  ${cyan('--user <name>')}            GitHub user to scan
  ${cyan('--repos <file>')}           File with repos (one owner/repo per line)
  ${cyan('-f, --format <fmt>')}       Output: terminal, json, markdown ${dim('(default: terminal)')}
  ${cyan('-c, --concurrency <n>')}    Parallel scans ${dim('(default: 5)')}
  ${cyan('-r, --rules <ids>')}        Only run these rule IDs (comma-separated)
  ${cyan('-e, --exclude <ids>')}      Skip these rule IDs
  ${cyan('--include-archived')}       Include archived repos
  ${cyan('--include-forks')}          Include forked repos
  ${cyan('--min-stars <n>')}          Only scan repos with N+ stars
  ${cyan('-o, --out-file <path>')}    Write report to file
  ${cyan('-h, --help')}               Show this help

${bold('ENVIRONMENT')}
  ${cyan('GITHUB_TOKEN')}             Required for private repos & to avoid rate limits

${bold('EXAMPLES')}
  ${dim('# Morning sweep of your org')}
  GITHUB_TOKEN=ghp_xxx npx vibe-audit-fleet --org my-company

  ${dim('# JSON report for CI, save to file')}
  npx vibe-audit-fleet --org my-company -f json -o fleet-report.json

  ${dim('# Scan specific repos from a list')}
  npx vibe-audit-fleet --repos repos.txt

  ${dim('# GitHub Actions cron (see .github/workflows/morning-scan.yml)')}

${bold('REPO LIST FILE FORMAT')}
  ${dim('# repos.txt — one owner/repo per line, # comments allowed')}
  my-org/frontend
  my-org/backend-api
  my-org/mobile-app

${dim('Replaces your DigitalOcean bot. Runs on GitHub Actions, zero infra.')}
`);
  process.exit(0);
}

if (!values.org && !values.user && !values.repos) {
  console.error(red('\n  Error: Specify --org, --user, or --repos\n'));
  console.error(dim('  Run with --help for usage.\n'));
  process.exit(2);
}

const concurrency = parseInt(values.concurrency, 10) || 5;
const format = values.format || 'terminal';

async function main() {
  const start = performance.now();
  let repos;

  if (values.repos) {
    // Read repo list from file
    const content = await readFile(values.repos, 'utf-8');
    repos = content
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'))
      .map(line => {
        const [owner, repo] = line.split('/');
        return { owner, repo };
      })
      .filter(r => r.owner && r.repo);

    if (repos.length === 0) {
      console.error(red('\n  Error: No repos found in file\n'));
      process.exit(2);
    }
    console.error(cyan(`\n  ⚗️  Fleet scan: ${repos.length} repos from ${values.repos}\n`));
  } else {
    const kind = values.org ? 'org' : 'user';
    const name = values.org || values.user;

    console.error(cyan(`\n  ⚗️  Discovering repos for ${kind}: ${name}...\n`));

    repos = await listRepos(kind, name, {
      includeArchived: values['include-archived'],
      includeForks: values['include-forks'],
      minStars: parseInt(values['min-stars'], 10) || 0,
    });

    if (repos.length === 0) {
      console.error(yellow('  No repos found.\n'));
      process.exit(0);
    }
    console.error(dim(`  Found ${repos.length} repos. Starting scan...\n`));
  }

  const results = await fleetScan(repos, {
    concurrency,
    rules: values.rules?.split(',').filter(Boolean),
    exclude: values.exclude?.split(',').filter(Boolean),
    onProgress: (done, total, repo) => {
      if (format === 'terminal') {
        const pct = Math.round((done / total) * 100);
        const bar = '█'.repeat(Math.round(pct / 5)) + '░'.repeat(20 - Math.round(pct / 5));
        process.stderr.write(`\r  ${dim(`[${bar}]`)} ${pct}% ${dim(`(${done}/${total})`)} ${dim(repo)}${''.padEnd(20)}`);
      }
    },
  });

  if (format === 'terminal') process.stderr.write('\r' + ' '.repeat(100) + '\r');

  const durationMs = Math.round(performance.now() - start);
  const meta = { durationMs };

  let output;
  switch (format) {
    case 'json': {
      output = JSON.stringify(reportFleetJSON(results, meta), null, 2);
      console.log(output);
      break;
    }
    case 'markdown': {
      output = reportFleetMarkdown(results, meta);
      console.log(output);
      break;
    }
    default: {
      reportFleetTerminal(results, meta);
      break;
    }
  }

  if (values['out-file']) {
    let content;
    if (format === 'json') {
      content = output || JSON.stringify(reportFleetJSON(results, meta), null, 2);
    } else if (format === 'markdown') {
      content = output || reportFleetMarkdown(results, meta);
    } else {
      content = JSON.stringify(reportFleetJSON(results, meta), null, 2);
    }
    await writeFile(values['out-file'], content);
    console.error(dim(`\n  Report saved to ${values['out-file']}\n`));
  }

  const hasCritical = results.some(r => r.findings.some(f => f.severity === 'critical'));
  process.exit(hasCritical ? 1 : 0);
}

main().catch((err) => {
  console.error(red(`\n  Error: ${err.message}\n`));
  process.exit(2);
});
