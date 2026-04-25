#!/usr/bin/env node

/**
 * vibe-audit scan — Multi-repo batch security scanner.
 *
 * Scans 70+ GitHub repos in parallel and produces a consolidated
 * security dashboard. Designed to run as a morning cron job,
 * replacing ad-hoc bots (DigitalOcean, etc.).
 *
 * Usage:
 *   npx vibeaudit-scan [config-file] [options]
 *   npx vibeaudit-scan --org my-org
 *   npx vibeaudit-scan repos.json --slack $SLACK_WEBHOOK
 */

import { resolve } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import {
  loadScanConfig,
  resolveRepos,
  scanBatch,
  batchReportTerminal,
  batchReportJSON,
  batchReportMarkdown,
  notifySlack,
} from '../src/batch.js';
import { bold, cyan, red, yellow, green, dim } from '../src/colors.js';

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    org: { type: 'string' },
    concurrency: { type: 'string', short: 'c' },
    format: { type: 'string', short: 'f' },
    slack: { type: 'string' },
    rules: { type: 'string', short: 'r' },
    exclude: { type: 'string', short: 'e' },
    strict: { type: 'boolean', short: 's' },
    branch: { type: 'string', short: 'b' },
    output: { type: 'string', short: 'o' },
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'v' },
  },
});

// ─── Help ─────────────────────────────────────────────────────────────────────

if (values.help) {
  console.log(`
${bold('⚗️  vibeaudit-scan')} — Multi-repo security scanner

${bold('USAGE')}
  ${cyan('npx vibeaudit-scan')} ${dim('[config-file]')} ${dim('[options]')}

${bold('OPTIONS')}
  ${cyan('--org <org>')}            Scan all repos in a GitHub org
  ${cyan('-c, --concurrency <n>')} Max parallel scans ${dim('(default: 5)')}
  ${cyan('-f, --format <fmt>')}    Output: terminal | json | markdown ${dim('(default: terminal)')}
  ${cyan('-o, --output <file>')}   Write report to file (json/markdown)
  ${cyan('--slack <url>')}          Send summary to Slack webhook
  ${cyan('-b, --branch <name>')}   Default branch to scan ${dim('(default: HEAD)')}
  ${cyan('-r, --rules <ids>')}     Only run these rules
  ${cyan('-e, --exclude <ids>')}   Skip these rules
  ${cyan('-s, --strict')}           Exit 1 on any warnings
  ${cyan('-h, --help')}             Show help
  ${cyan('-v, --version')}          Show version

${bold('CONFIG FILE')}
  JSON file with repo list and defaults:

  ${dim('{')}
  ${dim('  "repos": ["owner/repo1", "owner/repo2", ...],')}
  ${dim('  "org": "my-github-org",')}
  ${dim('  "concurrency": 5,')}
  ${dim('  "slack": "https://hooks.slack.com/services/...",')}
  ${dim('  "rules": [],')}
  ${dim('  "exclude": [],')}
  ${dim('  "strict": false')}
  ${dim('}')}

${bold('EXAMPLES')}
  ${dim('# Scan repos from a config file')}
  npx vibeaudit-scan repos.json

  ${dim('# Scan an entire GitHub org')}
  npx vibeaudit-scan --org my-org

  ${dim('# Morning cron with Slack notification')}
  npx vibeaudit-scan repos.json --slack $SLACK_WEBHOOK

  ${dim('# JSON report for dashboarding')}
  npx vibeaudit-scan repos.json -f json -o scan-results.json

  ${dim('# Fast scan with high concurrency')}
  npx vibeaudit-scan repos.json -c 10

${bold('CRON SETUP')}
  ${dim('# Run every morning at 8am UTC')}
  ${dim('0 8 * * * GITHUB_TOKEN=ghp_xxx npx vibeaudit-scan /path/to/repos.json --slack $SLACK_WEBHOOK')}

${bold('ENVIRONMENT')}
  ${cyan('GITHUB_TOKEN')} or ${cyan('GH_TOKEN')}  Required for private repos / higher rate limits

${dim('Built by Digital Alchemy Academy — https://digitalalchemy.dev')}
`);
  process.exit(0);
}

// ─── Version ──────────────────────────────────────────────────────────────────

if (values.version) {
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const pkg = require('../package.json');
  console.log(pkg.version);
  process.exit(0);
}

// ─── Run Scan ─────────────────────────────────────────────────────────────────

try {
  // Load config from file or build from CLI args.
  let config = {};
  const configFile = positionals[0];

  if (configFile) {
    const configPath = resolve(configFile);
    config = await loadScanConfig(configPath);
  }

  // CLI overrides.
  const org = values.org || config.org;
  const concurrency = parseInt(values.concurrency || config.concurrency || '5', 10);
  const format = values.format || config.format || 'terminal';
  const slackUrl = values.slack || config.slack || process.env.VIBE_AUDIT_SLACK_WEBHOOK;
  const branch = values.branch || config.branch;
  const strict = values.strict ?? config.strict ?? false;
  const rules = values.rules?.split(',').filter(Boolean) || config.rules;
  const exclude = values.exclude?.split(',').filter(Boolean) || config.exclude;

  // Resolve repos.
  if (!config.repos?.length && !org) {
    console.error(red('\n  Error: No repos to scan. Provide a config file with "repos" or use --org.\n'));
    process.exit(2);
  }

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — Multi-Repo Scan'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));

  if (org) {
    console.log(dim(`  Fetching repos from org: ${org}...`));
  }

  const repos = await resolveRepos(config, { org });

  if (repos.length === 0) {
    console.error(red('\n  Error: No repos found to scan.\n'));
    process.exit(2);
  }

  console.log(dim(`  ${repos.length} repos queued · concurrency: ${concurrency}`));
  console.log('');

  // Progress indicator.
  const scanStart = performance.now();
  const results = await scanBatch(repos, {
    concurrency,
    branch,
    rules,
    exclude,
    strict,
    onStart(repo, index, total) {
      if (format === 'terminal') {
        process.stderr.write(dim(`  [${index + 1}/${total}] Scanning ${repo}...\r`));
      }
    },
    onComplete(result, completed, total) {
      if (format === 'terminal') {
        const icon = result.error ? yellow('!') : result.critical > 0 ? red('●') : green('✓');
        const grade = result.error ? '?' : result.grade;
        process.stderr.write(`  ${icon} ${dim(`[${completed}/${total}]`)} ${result.repo} ${dim(`(${grade})`)}\n`);
      }
    },
  });

  const totalDuration = Math.round(performance.now() - scanStart);

  if (format === 'terminal') {
    process.stderr.write('\n');
    console.log(dim(`  Completed in ${(totalDuration / 1000).toFixed(1)}s`));
  }

  // Output report.
  switch (format) {
    case 'json': {
      const report = batchReportJSON(results);
      const output = JSON.stringify(report, null, 2);
      if (values.output) {
        await writeFile(resolve(values.output), output);
        console.error(dim(`  Report saved to ${values.output}`));
      } else {
        console.log(output);
      }
      break;
    }
    case 'markdown': {
      const md = batchReportMarkdown(results);
      if (values.output) {
        await writeFile(resolve(values.output), md);
        console.error(dim(`  Report saved to ${values.output}`));
      } else {
        console.log(md);
      }
      break;
    }
    default:
      batchReportTerminal(results);
  }

  // Slack notification.
  if (slackUrl) {
    try {
      await notifySlack(results, slackUrl);
      if (format === 'terminal') {
        console.log(green(dim('  ✓ Slack notification sent')));
        console.log('');
      }
    } catch (err) {
      console.error(yellow(`  ⚠ Slack notification failed: ${err.message}`));
    }
  }

  // Exit code.
  const hasCritical = results.some(r => r.critical > 0);
  const hasWarning = results.some(r => r.warning > 0);
  const exitCode = hasCritical ? 1 : strict && hasWarning ? 1 : 0;
  process.exit(exitCode);
} catch (err) {
  console.error(red(`\n  Error: ${err.message}\n`));
  process.exit(2);
}
