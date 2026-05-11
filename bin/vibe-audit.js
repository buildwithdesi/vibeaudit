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
 *   --batch <file.json>                 Batch scan repos from a config file
 *   --org <name>                        Scan all repos in a GitHub org/user
 *   --concurrency <n>                   Max parallel scans (default: 5)
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
import { bold, cyan, dim, red, yellow, gray } from '../src/colors.js';
import { parseGitHubTarget, fetchRepoFiles } from '../src/github.js';
import { batchAudit, loadBatchConfig } from '../src/batch.js';
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
    batch: { type: 'string', short: 'b' },
    org: { type: 'string' },
    concurrency: { type: 'string', short: 'c' },
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
  ${cyan('-b, --batch')} <repos.json>               Batch scan repos from a config file
  ${cyan('--org')} <name>                            Scan all repos in a GitHub org/user
  ${cyan('-c, --concurrency')} <n>                   Max parallel scans ${dim('(default: 5)')}
  ${cyan('--list-rules')}                            Show all available rules
  ${cyan('-h, --help')}                              Show this help
  ${cyan('-v, --version')}                           Show version

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

  ${dim('# Batch scan all repos in your org (replaces your DO bot)')}
  npx vibe-audit --org mycompany --format html

  ${dim('# Batch scan repos from a config file')}
  npx vibe-audit --batch repos.json --concurrency 3

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

if (values.batch || values.org) {
  const format = values.format || 'terminal';
  const concurrencyOverride = values.concurrency ? parseInt(values.concurrency, 10) : undefined;

  try {
    const config = await loadBatchConfig({
      file: values.batch,
      org: values.org,
    });

    if (concurrencyOverride) config.concurrency = concurrencyOverride;
    if (values.rules) config.rules = values.rules.split(',').filter(Boolean);
    if (values.exclude) config.exclude = values.exclude.split(',').filter(Boolean);
    if (values.strict) config.strict = true;

    const repoCount = config.repos.length;
    console.log('');
    console.log(bold(`  ⚗️  VIBE AUDIT — Batch Scan`));
    console.log(dim(`  ${repoCount} repos · concurrency ${config.concurrency}`));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log('');

    const batchStart = performance.now();

    const results = await batchAudit(config, {
      onRepoStart(repo, i) {
        process.stdout.write(dim(`  [${i + 1}/${repoCount}] Scanning ${repo}...`));
      },
      onRepoEnd(result) {
        const icon = result.error ? red('✗') : result.critical > 0 ? red('●') : result.warning > 0 ? yellow('▲') : green('✓');
        const detail = result.error
          ? red(` error: ${result.error.slice(0, 60)}`)
          : ` ${result.grade} — ${result.total} findings (${result.durationMs}ms)`;
        process.stdout.write(`\r  ${icon} ${result.repo}${detail}\n`);
      },
    });

    const batchDurationMs = Math.round(performance.now() - batchStart);
    const scanned = results.filter(r => !r.error);
    const errored = results.filter(r => r.error);
    const totalFindings = scanned.reduce((s, r) => s + r.total, 0);
    const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
    const totalWarning = scanned.reduce((s, r) => s + r.warning, 0);

    if (format === 'json') {
      console.log(JSON.stringify({
        summary: {
          repos: repoCount,
          scanned: scanned.length,
          errored: errored.length,
          totalFindings,
          totalCritical,
          totalWarning,
          durationMs: batchDurationMs,
        },
        results: results.map(r => ({
          repo: r.repo,
          grade: r.grade,
          critical: r.critical,
          warning: r.warning,
          info: r.info,
          total: r.total,
          durationMs: r.durationMs,
          error: r.error,
          findings: r.findings.map(f => ({
            ruleId: f.ruleId,
            severity: f.severity,
            message: f.message,
            file: f.file,
            line: f.line,
            cweId: f.cweId,
            cvssScore: f.cvssScore,
          })),
        })),
      }, null, 2));
    } else if (format === 'html') {
      const { writeFile } = await import('node:fs/promises');
      const html = generateBatchHTML(results, { durationMs: batchDurationMs });
      const outPath = 'vibe-audit-batch-report.html';
      await writeFile(outPath, html);
      console.log('');
      console.log(dim('  ─────────────────────────────────────────────────────────────'));
      console.log(`  ${bold('Report saved:')} ${cyan(outPath)}`);
      console.log(`  ${bold('Repos:')} ${scanned.length} scanned, ${errored.length} errored`);
      console.log(`  ${bold('Findings:')} ${red(bold(String(totalCritical)))} critical · ${yellow(String(totalWarning))} warnings · ${totalFindings} total`);
      console.log(`  ${bold('Time:')} ${(batchDurationMs / 1000).toFixed(1)}s`);
      console.log('');
      console.log(dim('  Open in your browser to view the interactive fleet dashboard.'));
    } else {
      // Terminal summary
      console.log('');
      console.log(dim('  ─────────────────────────────────────────────────────────────'));
      console.log(bold('  ⚗️  BATCH SUMMARY'));
      console.log('');
      console.log(`  ${bold('Repos:')}     ${scanned.length} scanned, ${errored.length} errored`);
      console.log(`  ${bold('Findings:')} ${red(bold(String(totalCritical)))} critical · ${yellow(String(totalWarning))} warnings · ${totalFindings} total`);
      console.log(`  ${bold('Time:')}     ${(batchDurationMs / 1000).toFixed(1)}s`);
      console.log('');

      // Grade distribution
      const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
      for (const r of scanned) if (grades[r.grade] !== undefined) grades[r.grade]++;
      const gradeLine = Object.entries(grades).map(([g, c]) => {
        const color = { A: green, B: green, C: yellow, D: yellow, F: red }[g];
        return `${color(bold(g))}:${c}`;
      }).join('  ');
      console.log(`  ${bold('Grades:')}   ${gradeLine}`);
      console.log('');

      // Worst repos
      const worst = scanned.filter(r => r.grade === 'F' || r.grade === 'D').sort((a, b) => b.critical - a.critical);
      if (worst.length > 0) {
        console.log(red(bold('  Repos needing attention:')));
        for (const r of worst.slice(0, 10)) {
          console.log(`    ${red('●')} ${bold(r.repo)} — ${r.critical} critical, ${r.warning} warnings`);
        }
        console.log('');
      }

      console.log(dim('  Run with --format html for an interactive fleet dashboard.'));
      console.log(dim('  Run with --format json to pipe into your notification system.'));
    }

    console.log('');
    const hasCritical = totalCritical > 0;
    const hasWarning = totalWarning > 0;
    process.exit(hasCritical ? 1 : values.strict && hasWarning ? 1 : 0);
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
