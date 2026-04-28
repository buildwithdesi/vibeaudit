#!/usr/bin/env node

/**
 * vibe-audit CLI
 * Zero-dependency security scanner for AI-generated codebases.
 *
 * Usage:
 *   npx vibe-audit [directory] [options]
 *
 * Options:
 *   --format <terminal|json|markdown>  Output format (default: terminal)
 *   --rules <id,id,...>                Only run specific rules
 *   --exclude <id,id,...>              Exclude specific rules
 *   --strict                           Exit 1 on warnings too
 *   --list-rules                       Show available rules and exit
 *   --help                             Show help
 *   --version                          Show version
 */

import { resolve } from 'node:path';
import { stat } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { audit } from '../src/index.js';
import { generateFixes } from '../src/fix.js';
import { ALL_RULES } from '../src/rules/index.js';
import { CWE_MAP } from '../src/data/cwe-map.js';
import { bold, cyan, dim, red, yellow, green, gray } from '../src/colors.js';
import { parseGitHubTarget, fetchRepoFiles } from '../src/github.js';
import { batchAudit, fetchOrgRepos, fetchUserRepos, loadRepoList } from '../src/batch.js';
import { reportBatchTerminal, reportBatchJSON, reportBatchMarkdown } from '../src/reporters/batch-summary.js';

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    format: { type: 'string', short: 'f' },
    rules: { type: 'string', short: 'r' },
    exclude: { type: 'string', short: 'e' },
    strict: { type: 'boolean', short: 's' },
    fix: { type: 'boolean' },
    'fix-file': { type: 'boolean' },
    'skip-sca': { type: 'boolean' },
    deep: { type: 'boolean' },
    'list-rules': { type: 'boolean' },
    org: { type: 'string' },
    user: { type: 'string' },
    repos: { type: 'string' },
    concurrency: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'v' },
  },
});

// ─── Help ─────────────────────────────────────────────────────────────────────

if (values.help) {
  console.log(`
${bold('⚗️  vibe-audit')} — Security scanner for AI-generated code

${bold('USAGE')}
  ${cyan('npx vibe-audit')} ${dim('[directory | github-url | owner/repo]')} ${dim('[options]')}

${bold('OPTIONS')}
  ${cyan('-f, --format')} <terminal|json|markdown|html>  Output format ${dim('(default: terminal)')}
  ${cyan('-r, --rules')}  <id,id,...>               Only run these rules
  ${cyan('-e, --exclude')} <id,id,...>               Skip these rules
  ${cyan('-s, --strict')}                            Exit 1 on warnings too
  ${cyan('--fix')}                                   Show copy-paste fix prompts + save VIBE-AUDIT-FIXES.md
  ${cyan('--fix-file')}                              Only save fix file (no terminal prompts)
  ${cyan('--skip-sca')}                              Skip dependency vulnerability scanning
  ${cyan('--deep')}                                  Enable deep scanning (git history secrets)
  ${cyan('--list-rules')}                            Show all available rules
  ${cyan('-h, --help')}                              Show this help
  ${cyan('-v, --version')}                           Show version

${bold('BATCH MODE')} ${dim('(scan multiple repos at once)')}
  ${cyan('--org')} <name>                             Scan all repos in a GitHub org
  ${cyan('--user')} <name>                            Scan all repos for a GitHub user
  ${cyan('--repos')} <file>                           Scan repos listed in a file (one per line)
  ${cyan('--concurrency')} <n>                        Parallel scans ${dim('(default: 5)')}

${bold('EXAMPLES')}
  ${dim('# Audit current directory')}
  npx vibe-audit

  ${dim('# Audit a specific project')}
  npx vibe-audit ./my-app

  ${dim('# Audit a GitHub repo directly')}
  npx vibe-audit https://github.com/user/repo
  npx vibe-audit user/repo

  ${dim('# Scan all repos in an org (morning audit)')}
  npx vibe-audit --org my-company --format json
  npx vibe-audit --user myuser --concurrency 3

  ${dim('# Scan repos from a file')}
  npx vibe-audit --repos repos.txt --format markdown

  ${dim('# Get fix prompts for your AI tool')}
  npx vibe-audit --fix

  ${dim('# JSON output for CI pipelines')}
  npx vibe-audit --format json --strict

  ${dim('# Only check for secrets and auth')}
  npx vibe-audit --rules exposed-secrets,missing-auth

${bold('CONFIG')}
  Add ${cyan('.vibe-audit.json')} to your project root to set defaults.

${bold('RULES')}
  Run ${cyan('npx vibe-audit --list-rules')} to see all available rules.

${dim('Built by Digital Alchemy Academy — https://digitalalchemy.dev')}
`);
  process.exit(0);
}

// ─── Version ──────────────────────────────────────────────────────────────────

if (values.version) {
  // Read version from package.json.
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const pkg = require('../package.json');
  console.log(pkg.version);
  process.exit(0);
}

// ─── List Rules ───────────────────────────────────────────────────────────────

if (values['list-rules']) {
  console.log('');
  console.log(bold('  ⚗️  Available Rules'));
  console.log(dim('  ─────────────────────────────────────'));
  console.log('');

  for (const rule of ALL_RULES) {
    const sev =
      rule.severity === 'critical'
        ? red(bold('CRIT'))
        : rule.severity === 'warning'
          ? yellow('WARN')
          : cyan('INFO');

    const cwe = CWE_MAP[rule.id];
    const cweStr = cwe ? gray(` [${cwe.cweId}]`) : '';
    console.log(`  ${sev}  ${bold(rule.id)}${cweStr}`);
    console.log(`       ${dim(rule.description)}`);
    console.log('');
  }

  process.exit(0);
}

// ─── Batch Mode ──────────────────────────────────────────────────────────────

const isBatch = values.org || values.user || values.repos;

if (isBatch) {
  const format = values.format || 'terminal';
  const concurrency = values.concurrency ? parseInt(values.concurrency, 10) : 5;

  try {
    let repos;
    let label;

    if (values.org) {
      label = `org: ${values.org}`;
      console.log(cyan(`\n  ⚗️  Fetching repos for ${label}...\n`));
      repos = await fetchOrgRepos(values.org);
    } else if (values.user) {
      label = `user: ${values.user}`;
      console.log(cyan(`\n  ⚗️  Fetching repos for ${label}...\n`));
      repos = await fetchUserRepos(values.user);
    } else {
      label = `file: ${values.repos}`;
      repos = await loadRepoList(values.repos);
    }

    console.log(dim(`  Found ${repos.length} repos. Scanning with concurrency ${concurrency}...\n`));

    let completed = 0;
    const results = await batchAudit(repos, {
      concurrency,
      onProgress({ type, repo, total }) {
        if (type === 'done' || type === 'error') {
          completed++;
          if (format === 'terminal') {
            const pct = Math.round((completed / total) * 100);
            const status = type === 'error' ? red('FAIL') : green('done');
            process.stdout.write(`\r  [${pct}%] ${completed}/${total} — ${repo} ${status}   `);
          }
        }
      },
    });

    if (format === 'terminal') process.stdout.write('\r' + ' '.repeat(80) + '\r');

    switch (format) {
      case 'json':
        reportBatchJSON(results);
        break;
      case 'markdown':
        reportBatchMarkdown(results);
        break;
      default:
        reportBatchTerminal(results);
        break;
    }

    const hasCritical = results.some((r) => r.criticals > 0);
    process.exit(hasCritical ? 1 : 0);
  } catch (err) {
    console.error(red(`\n  Error: ${err.message}\n`));
    process.exit(2);
  }
}

// ─── Run Audit ────────────────────────────────────────────────────────────────

const rawTarget = positionals[0] || '.';

const cliOptions = {
  format: values.format,
  rules: values.rules?.split(',').filter(Boolean),
  exclude: values.exclude?.split(',').filter(Boolean),
  strict: values.strict,
  skipSca: values['skip-sca'],
  deep: values.deep,
};

let targetDir;

try {
  // Detect GitHub repo vs local directory.
  const gh = parseGitHubTarget(rawTarget);

  if (gh) {
    // GitHub mode — fetch files directly via API, no clone needed.
    const label = `${gh.owner}/${gh.repo}`;
    console.log(cyan(`\n  ⚗️  Scanning GitHub repo: ${label}\n`));
    targetDir = `github://${label}`;
    cliOptions.fileSource = fetchRepoFiles(gh.owner, gh.repo);
    cliOptions.skipSca = true; // SCA needs local package-lock.json, skip for remote
  } else {
    targetDir = resolve(rawTarget);

    // Verify the local directory exists.
    try {
      const s = await stat(targetDir);
      if (!s.isDirectory()) {
        console.error(red(`\n  Error: ${targetDir} is not a directory\n`));
        process.exit(2);
      }
    } catch {
      console.error(red(`\n  Error: Directory not found — ${targetDir}\n`));
      console.error(dim(`  If this is a GitHub repo, use the full URL or owner/repo shorthand:\n`));
      console.error(dim(`    npx vibe-audit https://github.com/owner/repo`));
      console.error(dim(`    npx vibe-audit owner/repo\n`));
      process.exit(2);
    }
  }

  const { findings, exitCode } = await audit(targetDir, cliOptions);

  // Fix mode: generate prompts after the normal report
  if (values.fix || values['fix-file']) {
    const fixMode = values['fix-file'] ? 'file' : 'all';
    await generateFixes(findings, targetDir, fixMode);
  }

  process.exit(exitCode);
} catch (err) {
  console.error(red(`\n  Error: ${err.message}\n`));
  process.exit(2);
}
