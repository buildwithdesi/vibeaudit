#!/usr/bin/env node

/**
 * vibe-audit batch scanner
 *
 * Scans multiple GitHub repos from repos.json and produces an aggregated report.
 * Designed to run on a morning cron as a replacement for the DigitalOcean bot.
 *
 * Usage:
 *   node bin/batch-scan.js [options]
 *
 * Options:
 *   --repos <path>          Path to repos manifest (default: repos.json)
 *   --concurrency <n>       Max parallel scans (default: 3)
 *   --delay <ms>            Delay between scan starts (default: 1000)
 *   --format <json|md|both> Output format (default: both)
 *   --out <dir>             Output directory for reports (default: .)
 *   --github-summary        Write to $GITHUB_STEP_SUMMARY (for Actions)
 *   --help
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { batchAudit, batchMarkdownSummary, batchJsonSummary } from '../src/batch.js';
import { bold, cyan, dim, red, yellow, green, gray } from '../src/colors.js';

const { values } = parseArgs({
  options: {
    repos: { type: 'string', default: 'repos.json' },
    concurrency: { type: 'string', default: '3' },
    delay: { type: 'string', default: '1000' },
    format: { type: 'string', default: 'both' },
    out: { type: 'string', default: '.' },
    'github-summary': { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  },
});

if (values.help) {
  console.log(`
${bold('⚗️  vibe-audit batch')} — Scan multiple repos at once

${bold('USAGE')}
  ${cyan('node bin/batch-scan.js')} ${dim('[options]')}

${bold('OPTIONS')}
  ${cyan('--repos <path>')}          Path to repos manifest ${dim('(default: repos.json)')}
  ${cyan('--concurrency <n>')}       Max parallel scans ${dim('(default: 3)')}
  ${cyan('--delay <ms>')}            Delay between scan starts for rate limiting ${dim('(default: 1000)')}
  ${cyan('--format <json|md|both>')} Output format ${dim('(default: both)')}
  ${cyan('--out <dir>')}             Output directory for reports ${dim('(default: .)')}
  ${cyan('--github-summary')}        Write markdown to GITHUB_STEP_SUMMARY
  ${cyan('-h, --help')}              Show this help

${bold('REPOS MANIFEST')}
  Create a ${cyan('repos.json')} file:

  {
    "repos": [
      "owner/repo1",
      "owner/repo2"
    ]
  }

${bold('ENVIRONMENT')}
  ${cyan('GITHUB_TOKEN')} — Required for private repos, recommended for rate limits.
                  The GitHub API allows 60 req/hr unauthenticated vs 5,000 authenticated.

${bold('EXAMPLES')}
  ${dim('# Scan all repos in the manifest')}
  GITHUB_TOKEN=ghp_xxx node bin/batch-scan.js

  ${dim('# Higher concurrency, custom output dir')}
  node bin/batch-scan.js --concurrency 5 --out reports/

  ${dim('# In GitHub Actions with step summary')}
  node bin/batch-scan.js --github-summary
`);
  process.exit(0);
}

// ─── Load manifest ──────────────────────────────────────────────────────────

const manifestPath = resolve(values.repos);
let manifest;

try {
  const raw = await readFile(manifestPath, 'utf-8');
  manifest = JSON.parse(raw);
} catch (err) {
  console.error(red(`\n  Error: Cannot load repos manifest at ${manifestPath}`));
  console.error(dim(`  ${err.message}\n`));
  console.error(dim('  Create a repos.json with: { "repos": ["owner/repo1", "owner/repo2"] }\n'));
  process.exit(2);
}

const repos = manifest.repos;
if (!Array.isArray(repos) || repos.length === 0) {
  console.error(red('\n  Error: repos.json must contain a non-empty "repos" array\n'));
  process.exit(2);
}

// ─── Token check ────────────────────────────────────────────────────────────

const hasToken = !!(process.env.GITHUB_TOKEN || process.env.GH_TOKEN);
if (!hasToken) {
  console.log(yellow('\n  ⚠  No GITHUB_TOKEN set — rate-limited to 60 requests/hour.'));
  console.log(dim('  Set GITHUB_TOKEN for 5,000 req/hr and private repo access.\n'));
}

// ─── Run batch scan ─────────────────────────────────────────────────────────

const concurrency = parseInt(values.concurrency, 10) || 3;
const delayMs = parseInt(values.delay, 10) || 1000;

console.log('');
console.log(bold('  ⚗️  VIBE AUDIT — Batch Scan'));
console.log(dim('  ─────────────────────────────────────'));
console.log(`  ${cyan(String(repos.length))} repos · concurrency ${concurrency} · delay ${delayMs}ms`);
console.log('');

const gradeColor = { A: green, B: green, C: yellow, D: yellow, F: red, '?': gray };
let completed = 0;

const results = await batchAudit(repos, {
  concurrency,
  delayMs,
  strict: manifest.defaults?.strict,
  onResult(result) {
    completed++;
    const color = gradeColor[result.grade] || gray;
    const progress = dim(`[${completed}/${repos.length}]`);

    if (result.status === 'error') {
      console.log(`  ${progress} ${red('✗')} ${result.repo} — ${red(result.error)}`);
    } else {
      const parts = [];
      if (result.critical > 0) parts.push(red(bold(`${result.critical}C`)));
      if (result.warning > 0) parts.push(yellow(`${result.warning}W`));
      if (result.info > 0) parts.push(cyan(`${result.info}I`));
      const counts = parts.length > 0 ? parts.join(dim(',')) : green('clean');
      console.log(`  ${progress} ${color(bold(result.grade))} ${result.repo} ${dim('—')} ${counts} ${dim(`${result.durationMs}ms`)}`);
    }
  },
});

// ─── Summary ────────────────────────────────────────────────────────────────

const scanned = results.filter((r) => r.status === 'scanned');
const errors = results.filter((r) => r.status === 'error');
const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
const totalWarning = scanned.reduce((s, r) => s + r.warning, 0);
const failing = scanned.filter((r) => r.grade === 'F');

console.log('');
console.log(dim('  ─────────────────────────────────────'));
console.log(`  ${bold('Scanned:')} ${scanned.length} repos · ${errors.length > 0 ? red(`${errors.length} errors`) : green('0 errors')}`);
console.log(`  ${bold('Findings:')} ${red(bold(String(totalCritical)))} critical · ${yellow(String(totalWarning))} warnings`);

if (failing.length > 0) {
  console.log(`  ${red(bold(`${failing.length} repos with critical issues:`))} ${failing.map((r) => r.repo).join(', ')}`);
}
console.log('');

// ─── Output ─────────────────────────────────────────────────────────────────

const outDir = resolve(values.out);
const format = values.format;

try {
  await mkdir(outDir, { recursive: true });
} catch { /* exists */ }

if (format === 'json' || format === 'both') {
  const jsonPath = resolve(outDir, 'vibe-audit-batch.json');
  const jsonData = batchJsonSummary(results);
  await writeFile(jsonPath, JSON.stringify(jsonData, null, 2));
  console.log(`  ${dim('JSON report:')} ${cyan(jsonPath)}`);
}

if (format === 'md' || format === 'both') {
  const mdPath = resolve(outDir, 'vibe-audit-batch.md');
  const md = batchMarkdownSummary(results);
  await writeFile(mdPath, md);
  console.log(`  ${dim('Markdown report:')} ${cyan(mdPath)}`);
}

if (values['github-summary'] && process.env.GITHUB_STEP_SUMMARY) {
  const md = batchMarkdownSummary(results);
  await writeFile(process.env.GITHUB_STEP_SUMMARY, md, { flag: 'a' });
  console.log(`  ${dim('GitHub step summary:')} written`);
}

console.log('');

// Exit non-zero if any repo has criticals
process.exit(totalCritical > 0 ? 1 : 0);
