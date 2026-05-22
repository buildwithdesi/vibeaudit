#!/usr/bin/env node

/**
 * vibe-audit-fleet — Morning scan across all your repos.
 *
 * Replaces the DigitalOcean bot. Point it at your GitHub org/user,
 * get a consolidated security dashboard.
 *
 * Usage:
 *   npx vibe-audit-fleet --org myorg
 *   npx vibe-audit-fleet --config fleet.json
 *   npx vibe-audit-fleet --org myorg --format json > results.json
 */

import { parseArgs } from 'node:util';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fleetScan } from '../src/fleet.js';
import { generateFleetHTML } from '../src/reporters/fleet-html.js';
import { bold, cyan, dim, red, yellow, green, gray } from '../src/colors.js';

const { values } = parseArgs({
  allowPositionals: false,
  options: {
    org: { type: 'string', short: 'o', multiple: true },
    repo: { type: 'string', short: 'r', multiple: true },
    exclude: { type: 'string', short: 'e', multiple: true },
    config: { type: 'string', short: 'c' },
    format: { type: 'string', short: 'f' },
    output: { type: 'string' },
    concurrency: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'v' },
  },
});

if (values.help) {
  console.log(`
${bold('⚗️  vibe-audit-fleet')} — Morning security scan across all your repos

${bold('USAGE')}
  ${cyan('npx vibe-audit-fleet')} ${dim('[options]')}

${bold('OPTIONS')}
  ${cyan('-o, --org')} <name>         GitHub org or user to scan (all non-fork, non-archived repos)
  ${cyan('-r, --repo')} <owner/repo>  Add a specific repo (repeatable)
  ${cyan('-e, --exclude')} <o/r>      Exclude a repo (repeatable)
  ${cyan('-c, --config')} <path>      Load config from JSON file
  ${cyan('-f, --format')} <fmt>       Output format: terminal, json, html ${dim('(default: terminal)')}
  ${cyan('--output')} <path>          Write HTML/JSON report to file ${dim('(default: vibe-audit-fleet.html)')}
  ${cyan('--concurrency')} <n>        Max parallel scans ${dim('(default: 5)')}
  ${cyan('-h, --help')}               Show this help
  ${cyan('-v, --version')}            Show version

${bold('EXAMPLES')}
  ${dim('# Scan all repos in your org')}
  npx vibe-audit-fleet --org mycompany

  ${dim('# Scan multiple orgs + specific repos')}
  npx vibe-audit-fleet --org mycompany --org myother-org --repo friend/cool-project

  ${dim('# HTML report for the team')}
  npx vibe-audit-fleet --org mycompany --format html --output morning-report.html

  ${dim('# JSON for CI/automation')}
  npx vibe-audit-fleet --org mycompany --format json > fleet-results.json

  ${dim('# Use a config file')}
  npx vibe-audit-fleet --config fleet.json

${bold('CONFIG FILE')} ${dim('(fleet.json)')}
  {
    "orgs": ["mycompany", "my-other-org"],
    "repos": ["friend/cool-project"],
    "exclude": ["mycompany/deprecated-app"],
    "concurrency": 5
  }

${bold('ENVIRONMENT')}
  ${cyan('GITHUB_TOKEN')} or ${cyan('GH_TOKEN')} — Required for private repos, recommended for rate limits.

${dim('Built by Digital Alchemy Academy — https://digitalalchemy.dev')}
`);
  process.exit(0);
}

if (values.version) {
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const pkg = require('../package.json');
  console.log(pkg.version);
  process.exit(0);
}

const config = {
  orgs: [],
  repos: [],
  exclude: [],
  concurrency: 5,
};

if (values.config) {
  try {
    const raw = await readFile(resolve(values.config), 'utf-8');
    const parsed = JSON.parse(raw);
    config.orgs = parsed.orgs || [];
    config.repos = parsed.repos || [];
    config.exclude = parsed.exclude || [];
    config.concurrency = parsed.concurrency || 5;
  } catch (err) {
    console.error(red(`\n  Error loading config: ${err.message}\n`));
    process.exit(2);
  }
}

if (values.org) config.orgs.push(...values.org);
if (values.repo) config.repos.push(...values.repo);
if (values.exclude) config.exclude.push(...values.exclude);
if (values.concurrency) config.concurrency = parseInt(values.concurrency, 10) || 5;

if (config.orgs.length === 0 && config.repos.length === 0) {
  console.error(red('\n  Error: No repos to scan. Use --org, --repo, or --config.\n'));
  console.error(dim('  Run with --help for usage examples.\n'));
  process.exit(2);
}

const format = values.format || 'terminal';
const outputPath = values.output || (format === 'html' ? 'vibe-audit-fleet.html' : null);

try {
  if (format === 'terminal') {
    console.log('');
    console.log(bold('  ⚗️  VIBE AUDIT FLEET'));
    console.log(dim('  Morning security scan across your repos'));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log('');
  }

  const { results, summary } = await fleetScan(config, ({ repo, done, total }) => {
    if (format === 'terminal') {
      const pct = Math.round((done / total) * 100);
      process.stdout.write(`\r  ${dim(`[${done}/${total}]`)} ${pct}% — scanning ${cyan(repo)}${''.padEnd(40)}`);
    }
  });

  if (format === 'terminal') {
    process.stdout.write('\r' + ' '.repeat(100) + '\r');
    reportTerminal(results, summary);
  } else if (format === 'json') {
    const output = { summary, results: results.map(r => ({
      fullName: r.fullName,
      grade: r.grade,
      counts: r.counts,
      findings: r.findings,
      filesScanned: r.filesScanned,
      durationMs: r.durationMs,
      error: r.error,
    })) };
    const json = JSON.stringify(output, null, 2);
    if (outputPath) {
      await writeFile(resolve(outputPath), json);
      console.error(dim(`  Written to ${outputPath}`));
    } else {
      console.log(json);
    }
  } else if (format === 'html') {
    const html = generateFleetHTML(results, summary);
    const out = resolve(outputPath);
    await writeFile(out, html);
    console.log('');
    console.log(bold('  ⚗️  VIBE AUDIT FLEET — HTML Report Generated'));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log(`  ${bold('Report:')}  ${cyan(out)}`);
    console.log(`  ${bold('Repos:')}   ${summary.reposScanned} scanned (${summary.reposFailed} errors)`);
    console.log(`  ${bold('Issues:')}  ${red(bold(String(summary.totalCritical)))} critical · ${yellow(String(summary.totalWarning))} warnings · ${cyan(String(summary.totalInfo))} info`);
    console.log('');
    console.log(dim('  Open in your browser to view the interactive dashboard.'));
    console.log('');
  }

  const exitCode = summary.totalCritical > 0 ? 1 : 0;
  process.exit(exitCode);
} catch (err) {
  console.error(red(`\n  Error: ${err.message}\n`));
  process.exit(2);
}

function reportTerminal(results, summary) {
  const gradeColor = (g) => ({ A: green, B: green, C: yellow, D: yellow, F: red }[g] || gray);

  console.log(`  ${bold('Repos scanned:')} ${summary.reposScanned}  ${dim('|')}  ${bold('Failed:')} ${summary.reposFailed > 0 ? red(String(summary.reposFailed)) : green('0')}`);
  console.log(`  ${red(bold(`${summary.totalCritical}`))} ${dim('critical')}  ${dim('|')}  ${yellow(bold(`${summary.totalWarning}`))} ${dim('warnings')}  ${dim('|')}  ${cyan(bold(`${summary.totalInfo}`))} ${dim('info')}  ${dim('|')}  ${bold(`${summary.totalFindings}`)} ${dim('total')}`);
  console.log('');

  // Grade distribution
  const gd = summary.gradeDistribution;
  const gradeLine = ['A', 'B', 'C', 'D', 'F']
    .map((g) => `${gradeColor(g)(bold(g))}:${gd[g] || 0}`)
    .join('  ');
  console.log(`  ${dim('Grades:')} ${gradeLine}${gd['?'] > 0 ? `  ${gray('?:' + gd['?'])}` : ''}`);
  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  for (const r of results) {
    const gc = gradeColor(r.grade);
    const badge = gc(bold(`[${r.grade}]`));
    const counts = [];
    if (r.counts.critical > 0) counts.push(red(`${r.counts.critical}C`));
    if (r.counts.warning > 0) counts.push(yellow(`${r.counts.warning}W`));
    if (r.counts.info > 0) counts.push(cyan(`${r.counts.info}I`));
    const countStr = counts.length > 0 ? counts.join(dim(',')) : green('clean');
    const errStr = r.error ? ` ${red(`(error: ${r.error.slice(0, 60)})`)}` : '';
    const timeStr = dim(`${r.durationMs > 1000 ? (r.durationMs / 1000).toFixed(1) + 's' : r.durationMs + 'ms'}`);

    console.log(`  ${badge} ${bold(r.fullName)}  ${countStr}  ${timeStr}${errStr}`);
  }

  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));

  if (summary.totalCritical > 0) {
    console.log(red(bold('  ⛔ Critical issues found across your fleet. Review immediately.')));
    console.log(dim('  Run with --format html for an interactive dashboard.'));
  } else if (summary.totalWarning > 0) {
    console.log(yellow(bold('  ⚠️  Warnings found across your fleet.')));
    console.log(dim('  Run with --format html for details.'));
  } else {
    console.log(green(bold('  ✅ All repos clean. Ship it.')));
  }
  console.log('');
}
