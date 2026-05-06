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
import { bold, cyan, dim, red, yellow, gray } from '../src/colors.js';
import { parseGitHubTarget, fetchRepoFiles } from '../src/github.js';
import { listRepos, parseReposFile, scanRepos } from '../src/multi-repo.js';
import { reportMultiRepoTerminal, reportMultiRepoJSON } from '../src/reporters/multi-repo-terminal.js';
import { generateMultiRepoHTML } from '../src/reporters/multi-repo-html.js';

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
    'repos-file': { type: 'string' },
    concurrency: { type: 'string' },
    'skip-archived': { type: 'boolean' },
    'skip-forks': { type: 'boolean' },
    'output-file': { type: 'string', short: 'o' },
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

${bold('MULTI-REPO (replace your morning cron / DigitalOcean bot)')}
  ${cyan('--org')} <github-org>                  Scan all repos in a GitHub org
  ${cyan('--user')} <github-user>                Scan all repos for a GitHub user
  ${cyan('--repos-file')} <path>                 Scan repos listed in a file (one owner/repo per line)
  ${cyan('--concurrency')} <n>                   Parallel repo scans ${dim('(default: 5)')}
  ${cyan('--skip-archived')}                     Skip archived repos
  ${cyan('--skip-forks')}                        Skip forked repos
  ${cyan('-o, --output-file')} <path>            Write report to file instead of stdout

${bold('EXAMPLES')}
  ${dim('# Audit current directory')}
  npx vibe-audit

  ${dim('# Audit a specific project')}
  npx vibe-audit ./my-app

  ${dim('# Audit a GitHub repo directly')}
  npx vibe-audit https://github.com/user/repo
  npx vibe-audit user/repo

  ${dim('# Morning scan across an entire org (replaces DigitalOcean bot)')}
  npx vibe-audit --org my-company --format html -o report.html
  npx vibe-audit --org my-company --skip-forks --skip-archived

  ${dim('# Scan repos from a file')}
  npx vibe-audit --repos-file repos.txt --concurrency 10

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

// ─── Multi-Repo Mode ─────────────────────────────────────────────────────────

const isMultiRepo = values.org || values.user || values['repos-file'];

if (isMultiRepo) {
  try {
    let repos;

    if (values['repos-file']) {
      const { readFile: readFileFs } = await import('node:fs/promises');
      const content = await readFileFs(values['repos-file'], 'utf-8');
      repos = parseReposFile(content);
    } else {
      const kind = values.org ? 'orgs' : 'users';
      const name = values.org || values.user;
      console.log(cyan(`\n  ⚗️  Fetching repos for ${kind === 'orgs' ? 'org' : 'user'}: ${name}\n`));
      repos = await listRepos(kind, name, {
        skipArchived: values['skip-archived'],
        skipForks: values['skip-forks'],
      });
    }

    if (repos.length === 0) {
      console.error(red('\n  Error: No repos found.\n'));
      process.exit(2);
    }

    console.log(dim(`  Found ${repos.length} repos. Starting scan...\n`));

    const concurrency = parseInt(values.concurrency, 10) || 5;
    const format = values.format || 'terminal';

    const results = await scanRepos(repos, {
      concurrency,
      rules: values.rules?.split(',').filter(Boolean),
      exclude: values.exclude?.split(',').filter(Boolean),
      onProgress({ repo, index, total, status, grade }) {
        if (format !== 'json') {
          const pct = Math.round((index / total) * 100);
          const statusStr = status === 'done' ? green(`✓ ${grade}`)
            : status === 'error' ? red('✗')
            : cyan('⟳');
          process.stderr.write(`\r  ${dim(`[${index}/${total}]`)} ${statusStr} ${repo.padEnd(45)} ${dim(`${pct}%`)}`);
          if (index === total) process.stderr.write('\n\n');
        }
      },
    });

    const outputFile = values['output-file'];

    if (format === 'html') {
      const html = generateMultiRepoHTML(results);
      if (outputFile) {
        const { writeFile: writeFileFs } = await import('node:fs/promises');
        await writeFileFs(outputFile, html);
        console.log(bold(`\n  ⚗️  Multi-repo HTML report written to: ${cyan(outputFile)}\n`));
      } else {
        const { writeFile: writeFileFs } = await import('node:fs/promises');
        const defaultPath = 'vibe-audit-multi-report.html';
        await writeFileFs(defaultPath, html);
        reportMultiRepoTerminal(results);
        console.log(dim(`  HTML dashboard also saved to ${cyan(defaultPath)}`));
        console.log('');
      }
    } else if (format === 'json') {
      if (outputFile) {
        const { writeFile: writeFileFs } = await import('node:fs/promises');
        const agg = (await import('../src/multi-repo.js')).aggregateResults(results);
        const output = JSON.stringify({
          timestamp: new Date().toISOString(),
          summary: agg,
          repos: results.map(r => ({
            owner: r.owner, repo: r.repo, grade: r.grade,
            criticals: r.criticals, warnings: r.warnings, infos: r.infos,
            totalFindings: r.findings.length, durationMs: r.durationMs,
            error: r.error || null, findings: r.findings,
          })),
        }, null, 2);
        await writeFileFs(outputFile, output);
        console.log(bold(`\n  ⚗️  Multi-repo JSON report written to: ${cyan(outputFile)}\n`));
      } else {
        reportMultiRepoJSON(results);
      }
    } else {
      reportMultiRepoTerminal(results);
    }

    const hasCritical = results.some(r => r.criticals > 0);
    const hasWarning = results.some(r => r.warnings > 0);
    const exitCode = hasCritical ? 1 : values.strict && hasWarning ? 1 : 0;
    process.exit(exitCode);
  } catch (err) {
    console.error(red(`\n  Error: ${err.message}\n`));
    process.exit(2);
  }
}

// ─── Single-Repo Audit ──────────────────────────────────────────────────────

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
