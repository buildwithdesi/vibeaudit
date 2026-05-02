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
import { stat, readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { audit } from '../src/index.js';
import { generateFixes } from '../src/fix.js';
import { ALL_RULES } from '../src/rules/index.js';
import { CWE_MAP } from '../src/data/cwe-map.js';
import { bold, cyan, dim, red, yellow, gray, green } from '../src/colors.js';
import { parseGitHubTarget, fetchRepoFiles } from '../src/github.js';
import { batchScan, fetchOrgRepos, parseReposList } from '../src/batch.js';
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
    'repos-file': { type: 'string' },
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
  ${cyan('--org')} <org-or-user>                      Scan all repos in a GitHub org/user
  ${cyan('--repos-file')} <path>                      Scan repos listed in a file (one per line)
  ${cyan('--concurrency')} <n>                        Parallel repo scans ${dim('(default: 5)')}

${bold('EXAMPLES')}
  ${dim('# Audit current directory')}
  npx vibe-audit

  ${dim('# Audit a specific project')}
  npx vibe-audit ./my-app

  ${dim('# Audit a GitHub repo directly')}
  npx vibe-audit https://github.com/user/repo
  npx vibe-audit user/repo

  ${dim('# Scan all repos in an org')}
  npx vibe-audit --org my-company --format json

  ${dim('# Scan repos from a file')}
  npx vibe-audit --repos-file repos.txt

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

if (values.org || values['repos-file']) {
  const format = values.format || 'terminal';
  const concurrency = parseInt(values.concurrency, 10) || 5;

  let repos;

  if (values.org) {
    console.log(cyan(`\n  ⚗️  Fetching repos for: ${values.org}\n`));
    repos = await fetchOrgRepos(values.org);
    console.log(dim(`  Found ${repos.length} repos\n`));
  } else {
    const content = await readFile(resolve(values['repos-file']), 'utf-8');
    repos = parseReposList(content);
    console.log(cyan(`\n  ⚗️  Batch scan: ${repos.length} repos from ${values['repos-file']}\n`));
  }

  if (repos.length === 0) {
    console.error(red('\n  No repos found to scan.\n'));
    process.exit(2);
  }

  const batchStart = performance.now();
  const results = await batchScan(repos, {
    concurrency,
    rules: values.rules?.split(',').filter(Boolean),
    exclude: values.exclude?.split(',').filter(Boolean),
    deep: values.deep,
    onProgress(result, done, total) {
      const icon = result.error ? red('✗') : result.grade === 'A' || result.grade === 'B' ? green('✓') : result.grade === 'F' ? red('✓') : yellow('✓');
      process.stderr.write(`  ${icon} [${done}/${total}] ${result.repo} — grade ${result.grade} (${result.total} findings, ${(result.durationMs / 1000).toFixed(1)}s)\n`);
    },
  });
  const batchDuration = Math.round(performance.now() - batchStart);

  console.log('');

  const meta = { durationMs: batchDuration };

  switch (format) {
    case 'json':
      console.log(JSON.stringify(reportBatchJSON(results, meta), null, 2));
      break;
    case 'markdown':
      console.log(reportBatchMarkdown(results, meta));
      break;
    default:
      reportBatchTerminal(results, meta);
      break;
  }

  const hasCritical = results.some((r) => r.critical > 0);
  const hasWarning = results.some((r) => r.warning > 0);
  const exitCode = hasCritical ? 1 : values.strict && hasWarning ? 1 : 0;
  process.exit(exitCode);
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
