#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { bold, cyan, red, dim } from '../src/colors.js';
import { batchAudit, batchReport, loadReposFromFile, loadReposFromOrg } from '../src/batch.js';
import { parseGitHubTarget } from '../src/github.js';

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    org: { type: 'string' },
    file: { type: 'string' },
    format: { type: 'string', short: 'f' },
    rules: { type: 'string', short: 'r' },
    exclude: { type: 'string', short: 'e' },
    strict: { type: 'boolean', short: 's' },
    concurrency: { type: 'string', short: 'c' },
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'v' },
  },
});

if (values.help) {
  console.log(`
${bold('⚗️  vibe-audit batch')} — Scan multiple GitHub repos at once

${bold('USAGE')}
  ${cyan('vibeaudit-batch')} ${dim('[options]')} ${dim('[owner/repo owner/repo ...]')}

${bold('SOURCES')} ${dim('(pick one or combine)')}
  ${cyan('--org <github-org>')}        Scan all repos in a GitHub org/user
  ${cyan('--file <path>')}             Read repo list from file (one owner/repo per line)
  ${dim('positional args')}            Explicit owner/repo targets

${bold('OPTIONS')}
  ${cyan('-f, --format')} <terminal|json|markdown>  Output format ${dim('(default: terminal)')}
  ${cyan('-c, --concurrency')} <n>                  Parallel scans ${dim('(default: 5)')}
  ${cyan('-r, --rules')}  <id,id,...>               Only run these rules
  ${cyan('-e, --exclude')} <id,id,...>               Skip these rules
  ${cyan('-s, --strict')}                            Exit 1 on warnings too
  ${cyan('-h, --help')}                              Show this help
  ${cyan('-v, --version')}                           Show version

${bold('EXAMPLES')}
  ${dim('# Scan all repos in your org')}
  vibeaudit-batch --org mycompany

  ${dim('# Scan from a file list')}
  vibeaudit-batch --file repos.txt

  ${dim('# Scan specific repos + an entire org')}
  vibeaudit-batch --org mycompany user/extra-repo

  ${dim('# JSON output for CI/dashboards')}
  vibeaudit-batch --org mycompany --format json > report.json

  ${dim('# Markdown report (pipe to a file or PR comment)')}
  vibeaudit-batch --org mycompany --format markdown > batch-report.md

  ${dim('# Increase parallelism for faster scanning')}
  vibeaudit-batch --org mycompany --concurrency 10

${bold('REPO LIST FILE FORMAT')}
  ${dim('# repos.txt — one repo per line')}
  ${dim('# Lines starting with # are comments')}
  mycompany/frontend
  mycompany/backend-api
  mycompany/mobile-app

${bold('ENV VARS')}
  ${cyan('GITHUB_TOKEN')} or ${cyan('GH_TOKEN')} — required for private repos, recommended to avoid rate limits

${bold('SCHEDULING')} ${dim('(replace your DigitalOcean bot)')}
  Use GitHub Actions with a cron schedule:
    schedule:
      - cron: '0 8 * * 1-5'   # weekdays at 8am UTC

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

const repos = [];

try {
  if (values.org) {
    const orgRepos = await loadReposFromOrg(values.org);
    repos.push(...orgRepos);
  }

  if (values.file) {
    const fileRepos = await loadReposFromFile(resolve(values.file));
    repos.push(...fileRepos);
  }

  for (const arg of positionals) {
    const gh = parseGitHubTarget(arg);
    if (gh) {
      repos.push(gh);
    } else {
      console.error(red(`  Invalid repo target: "${arg}" — expected owner/repo or GitHub URL`));
      process.exit(2);
    }
  }

  // Deduplicate
  const seen = new Set();
  const deduped = repos.filter((r) => {
    const key = `${r.owner}/${r.repo}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  if (deduped.length === 0) {
    console.error(red('\n  No repos to scan. Provide --org, --file, or positional owner/repo args.\n'));
    console.error(dim('  Run vibeaudit-batch --help for usage.\n'));
    process.exit(2);
  }

  const format = values.format || 'terminal';
  const concurrency = parseInt(values.concurrency || '5', 10);

  const results = await batchAudit(deduped, {
    concurrency,
    format,
    rules: values.rules?.split(',').filter(Boolean),
    exclude: values.exclude?.split(',').filter(Boolean),
    strict: values.strict,
  });

  batchReport(results, format);

  const totalCrit = results.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = results.reduce((s, r) => s + r.warnings, 0);
  const hasFailures = totalCrit > 0 || (values.strict && totalWarn > 0);
  process.exit(hasFailures ? 1 : 0);
} catch (err) {
  console.error(red(`\n  Error: ${err.message}\n`));
  process.exit(2);
}
