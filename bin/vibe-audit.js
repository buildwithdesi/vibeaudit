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
import { stat, readFile, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { audit } from '../src/index.js';
import { generateFixes } from '../src/fix.js';
import { ALL_RULES } from '../src/rules/index.js';
import { CWE_MAP } from '../src/data/cwe-map.js';
import { bold, cyan, dim, red, yellow, gray } from '../src/colors.js';
import { parseGitHubTarget, fetchRepoFiles } from '../src/github.js';
import { batchScan } from '../src/batch.js';
import { reportBatchTerminal, reportBatchJSON } from '../src/reporters/batch-terminal.js';
import { generateBatchHTML } from '../src/reporters/batch-html.js';

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
    batch: { type: 'boolean' },
    'repos-file': { type: 'string' },
    concurrency: { type: 'string' },
    'out-file': { type: 'string', short: 'o' },
    'list-rules': { type: 'boolean' },
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

${bold('BATCH MODE')} ${dim('— scan 70+ repos in one run')}
  ${cyan('--batch')}                                 Enable multi-repo batch scanning
  ${cyan('--repos-file')} <path>                     JSON file listing repos to scan
  ${cyan('--concurrency')} <n>                       Parallel repo scans ${dim('(default: 4)')}
  ${cyan('-o, --out-file')} <path>                   Write report to file instead of stdout

${bold('EXAMPLES')}
  ${dim('# Audit current directory')}
  npx vibe-audit

  ${dim('# Audit a specific project')}
  npx vibe-audit ./my-app

  ${dim('# Audit a GitHub repo directly')}
  npx vibe-audit https://github.com/user/repo
  npx vibe-audit user/repo

  ${dim('# Get fix prompts for your AI tool')}
  npx vibe-audit --fix

  ${dim('# JSON output for CI pipelines')}
  npx vibe-audit --format json --strict

  ${dim('# Only check for secrets and auth')}
  npx vibe-audit --rules exposed-secrets,missing-auth

  ${dim('# Batch scan all your repos (morning sweep)')}
  npx vibe-audit --batch --repos-file repos.json --format html -o fleet-report.html

  ${dim('# Batch scan repos listed as positional args')}
  npx vibe-audit --batch user/repo1 user/repo2 user/repo3

${bold('BATCH REPOS FILE FORMAT')}
  ${dim('A JSON file with an array of "owner/repo" strings or objects:')}
  ${dim('  ["owner/repo1", "owner/repo2", ...]')}
  ${dim('  [{"repo": "owner/repo1"}, {"repo": "owner/repo2"}]')}

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

if (values.batch) {
  try {
    // Collect repos from --repos-file and/or positional args.
    let repos = [];

    if (values['repos-file']) {
      const filePath = resolve(values['repos-file']);
      const raw = await readFile(filePath, 'utf-8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        for (const entry of parsed) {
          if (typeof entry === 'string') repos.push(entry);
          else if (entry && typeof entry.repo === 'string') repos.push(entry.repo);
        }
      } else {
        console.error(red('\n  Error: repos file must contain a JSON array\n'));
        process.exit(2);
      }
    }

    // Positional args as additional repos
    for (const arg of positionals) {
      if (parseGitHubTarget(arg)) repos.push(arg);
    }

    if (repos.length === 0) {
      console.error(red('\n  Error: No repos specified. Use --repos-file or pass owner/repo args.\n'));
      console.error(dim('  Example: npx vibe-audit --batch --repos-file repos.json'));
      console.error(dim('  Example: npx vibe-audit --batch user/repo1 user/repo2\n'));
      process.exit(2);
    }

    // Deduplicate
    repos = [...new Set(repos)];

    const concurrency = parseInt(values.concurrency, 10) || 4;
    const format = values.format || 'terminal';

    console.log(cyan(`\n  ⚗️  VIBE AUDIT — Batch Scan`));
    console.log(dim(`  ${repos.length} repos · concurrency ${concurrency}\n`));

    const results = await batchScan(repos, {
      concurrency,
      rules: values.rules?.split(',').filter(Boolean),
      exclude: values.exclude?.split(',').filter(Boolean),
      strict: values.strict,
      onProgress({ type, repo, done, total }) {
        if (type === 'start') {
          process.stderr.write(dim(`  [${done + 1}/${total}] Scanning ${repo}...\n`));
        } else if (type === 'done') {
          process.stderr.write(dim(`  [${done}/${total}] ✓ ${repo}\n`));
        } else if (type === 'error') {
          process.stderr.write(red(`  [${done}/${total}] ✗ ${repo}\n`));
        }
      },
    });

    console.log('');

    // Output results
    const outFile = values['out-file'];

    if (format === 'json') {
      if (outFile) {
        const { aggregateResults: agg } = await import('../src/batch.js');
        const output = JSON.stringify({ summary: agg(results), repos: results }, null, 2);
        await writeFile(outFile, output);
        console.log(cyan(`  Report written to ${outFile}\n`));
      } else {
        reportBatchJSON(results);
      }
    } else if (format === 'html') {
      const html = generateBatchHTML(results);
      const dest = outFile || 'vibe-audit-fleet-report.html';
      await writeFile(dest, html);
      console.log(bold('  ⚗️  Fleet report generated'));
      console.log(cyan(`  ${dest}`));
      console.log(dim('  Open in your browser to view the interactive dashboard.\n'));
    } else {
      reportBatchTerminal(results);
      if (outFile) {
        const html = generateBatchHTML(results);
        await writeFile(outFile, html);
        console.log(dim(`  HTML report also saved to ${outFile}\n`));
      }
    }

    // Exit code: 1 if any repo has criticals
    const hasCritical = results.some(r => r.critical > 0);
    const hasWarning = results.some(r => r.warning > 0);
    const exitCode = hasCritical ? 1 : values.strict && hasWarning ? 1 : 0;
    process.exit(exitCode);
  } catch (err) {
    console.error(red(`\n  Error: ${err.message}\n`));
    process.exit(2);
  }
}

// ─── Run Audit (single repo) ────────────────────────────────────────────────

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
