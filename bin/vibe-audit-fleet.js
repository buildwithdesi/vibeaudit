#!/usr/bin/env node

/**
 * vibe-audit fleet — Multi-repo security scanner.
 * Scan 70+ repos in one run. Replaces your DigitalOcean bot.
 *
 * Usage:
 *   npx vibe-audit fleet [config-file] [options]
 *   npx vibe-audit fleet --org myorg
 *   npx vibe-audit fleet --repos owner/repo1,owner/repo2
 */

import { resolve, join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { fleetAudit } from '../src/fleet.js';
import { reportFleetTerminal } from '../src/reporters/fleet-terminal.js';
import { reportFleetJSON } from '../src/reporters/fleet-json.js';
import { reportFleetMarkdown } from '../src/reporters/fleet-markdown.js';
import { reportFleetHTML } from '../src/reporters/fleet-html.js';
import { bold, cyan, dim, red, yellow, green } from '../src/colors.js';

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    org: { type: 'string', short: 'o' },
    repos: { type: 'string', short: 'r' },
    exclude: { type: 'string', short: 'e' },
    format: { type: 'string', short: 'f' },
    concurrency: { type: 'string', short: 'c' },
    rules: { type: 'string' },
    'exclude-rules': { type: 'string' },
    'out-file': { type: 'string' },
    'skip-archived': { type: 'boolean' },
    'skip-forks': { type: 'boolean' },
    strict: { type: 'boolean', short: 's' },
    help: { type: 'boolean', short: 'h' },
  },
});

if (values.help) {
  console.log(`
${bold('⚗️  vibe-audit fleet')} — Multi-repo security scanner

${bold('USAGE')}
  ${cyan('npx vibe-audit fleet')} ${dim('[config-file] [options]')}

${bold('OPTIONS')}
  ${cyan('-o, --org')} <name>              Scan all repos in a GitHub org/user
  ${cyan('-r, --repos')} <owner/repo,...>   Scan specific repos (comma-separated)
  ${cyan('-e, --exclude')} <repo,...>       Skip these repos
  ${cyan('-f, --format')} <format>          Output: terminal, json, markdown, html ${dim('(default: terminal)')}
  ${cyan('-c, --concurrency')} <n>          Parallel scans ${dim('(default: 5)')}
  ${cyan('--rules')} <id,...>               Only run these rules
  ${cyan('--exclude-rules')} <id,...>       Exclude these rules
  ${cyan('--out-file')} <path>             Write HTML report to this path
  ${cyan('--skip-archived')}               Skip archived repos ${dim('(default: true)')}
  ${cyan('--skip-forks')}                  Skip forked repos ${dim('(default: true)')}
  ${cyan('-s, --strict')}                  Exit 1 on any warning
  ${cyan('-h, --help')}                    Show help

${bold('CONFIG FILE')}
  Instead of flags, pass a JSON config:
  ${cyan('npx vibe-audit fleet fleet.json')}

  ${dim(`{
    "org": "my-company",
    "exclude": ["my-company/legacy-app"],
    "concurrency": 3,
    "format": "html"
  }`)}

  Or list repos explicitly:
  ${dim(`{
    "repos": ["owner/repo1", "owner/repo2", "..."],
    "excludeRules": ["high-entropy-strings"]
  }`)}

${bold('EXAMPLES')}
  ${dim('# Scan all repos for a GitHub org')}
  npx vibe-audit fleet --org my-company

  ${dim('# Scan specific repos')}
  npx vibe-audit fleet --repos user/app1,user/app2,user/app3

  ${dim('# Morning cron with HTML dashboard')}
  npx vibe-audit fleet fleet.json --format html

  ${dim('# JSON for CI pipeline')}
  npx vibe-audit fleet --org my-company --format json --strict

${bold('ENVIRONMENT')}
  ${cyan('GITHUB_TOKEN')}  Required for private repos, recommended for rate limits.
                 GitHub Actions provides this automatically.

${dim('Built by Digital Alchemy Academy — https://digitalalchemy.dev')}
`);
  process.exit(0);
}

async function main() {
  let config = {};

  // Load config from file if provided
  const configFile = positionals[0];
  if (configFile) {
    try {
      const raw = await readFile(resolve(configFile), 'utf-8');
      config = JSON.parse(raw);
    } catch (err) {
      console.error(red(`\n  Error loading config: ${err.message}\n`));
      process.exit(2);
    }
  }

  // CLI flags override config
  if (values.org) config.org = values.org;
  if (values.repos) config.repos = values.repos.split(',').map(r => r.trim());
  if (values.exclude) config.exclude = values.exclude.split(',').map(r => r.trim());
  if (values.rules) config.rules = values.rules.split(',').filter(Boolean);
  if (values['exclude-rules']) config.excludeRules = values['exclude-rules'].split(',').filter(Boolean);
  if (values.concurrency) config.concurrency = parseInt(values.concurrency, 10);
  if (values['skip-archived']) config.skipArchived = true;
  if (values['skip-forks']) config.skipForks = true;

  const format = values.format || config.format || 'terminal';

  if (!config.org && !config.repos?.length) {
    console.error(red('\n  Error: Specify --org <name>, --repos <list>, or a config file.\n'));
    console.error(dim('  Run with --help for usage.\n'));
    process.exit(2);
  }

  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (!token) {
    console.error(yellow('\n  ⚠  No GITHUB_TOKEN set. Rate limits will be low and private repos inaccessible.\n'));
  }

  // Progress output (only for terminal format)
  const showProgress = format === 'terminal' || format === 'html';
  let completed = 0;

  if (showProgress) {
    const source = config.org ? `org: ${config.org}` : `${config.repos.length} repos`;
    console.log('');
    console.log(bold('  ⚗️  VIBE AUDIT — Fleet Scanner'));
    console.log(dim(`  Scanning ${source}...`));
    console.log('');
  }

  const result = await fleetAudit(config, {
    onRepoStart(repo, i, total) {
      if (showProgress) {
        completed = i;
        const pct = Math.round(((i) / total) * 100);
        process.stdout.write(`\r  ${dim(`[${pct}%]`)} Scanning ${cyan(repo)} ${dim(`(${i + 1}/${total})`)}`);
      }
    },
    onRepoEnd(repoResult, i, total) {
      if (showProgress) {
        completed = i + 1;
        const icon = repoResult.error ? red('✗')
          : repoResult.critical > 0 ? red('●')
          : repoResult.warning > 0 ? yellow('▲')
          : green('✓');
        const pct = Math.round((completed / total) * 100);
        process.stdout.write(`\r  ${dim(`[${pct}%]`)} ${icon} ${repoResult.repo} ${dim(`— ${repoResult.total} findings`)}${' '.repeat(30)}\n`);
      }
    },
  });

  if (showProgress) {
    console.log('');
  }

  // Report
  switch (format) {
    case 'json':
      reportFleetJSON(result);
      break;
    case 'markdown':
      reportFleetMarkdown(result);
      break;
    case 'html': {
      const outPath = values['out-file'] || join(process.cwd(), 'vibe-audit-fleet.html');
      await reportFleetHTML(result, outPath);
      break;
    }
    default:
      reportFleetTerminal(result);
      break;
  }

  // Exit code
  if (result.totalCritical > 0) process.exit(1);
  if (values.strict && result.totalWarning > 0) process.exit(1);
}

main().catch(err => {
  console.error(red(`\n  Error: ${err.message}\n`));
  process.exit(2);
});
