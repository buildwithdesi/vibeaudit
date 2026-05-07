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
import { fetchOrgRepos, scanMultipleRepos } from '../src/multi-repo.js';
import { generateMultiRepoHTML } from '../src/reporters/multi-repo-html.js';
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';

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
    org: { type: 'string' },
    repos: { type: 'string' },
    concurrency: { type: 'string' },
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
  ${cyan('--org')} <name>                            Scan all repos in a GitHub org/user
  ${cyan('--repos')} <file.json>                     Scan repos listed in a JSON file
  ${cyan('--concurrency')} <n>                       Max parallel repo scans ${dim('(default: 5)')}
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

  ${dim('# Scan all repos in a GitHub org (morning audit)')}
  npx vibe-audit --org my-company
  npx vibe-audit --org my-company --format html

  ${dim('# Scan repos from a JSON file')}
  npx vibe-audit --repos repos.json

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

if (values.org || values.repos) {
  try {
    const format = values.format || 'terminal';
    const concurrency = values.concurrency ? parseInt(values.concurrency, 10) : 5;
    const rules = values.rules?.split(',').filter(Boolean);
    const exclude = values.exclude?.split(',').filter(Boolean);

    let repos;
    let orgName;

    if (values.org) {
      orgName = values.org;
      console.log(cyan(`\n  ⚗️  Fetching repos for: ${orgName}\n`));
      repos = await fetchOrgRepos(orgName);
      console.log(dim(`  Found ${repos.length} repos (excluding archived/forks)\n`));
    } else {
      const repoFile = resolve(values.repos);
      const raw = await readFile(repoFile, 'utf-8');
      const parsed = JSON.parse(raw);
      orgName = parsed.name || 'Multi-Repo';
      repos = (parsed.repos || parsed).map((entry) => {
        if (typeof entry === 'string') {
          const [owner, repo] = entry.split('/');
          return { owner, repo, description: '', language: '' };
        }
        return entry;
      });
      console.log(cyan(`\n  ⚗️  Scanning ${repos.length} repos from ${values.repos}\n`));
    }

    if (repos.length === 0) {
      console.error(red('  No repos found.\n'));
      process.exit(2);
    }

    const start = performance.now();

    const results = await scanMultipleRepos(repos, {
      concurrency,
      rules,
      exclude,
      onProgress(result) {
        const icon = result.error ? red('✗') : result.grade === 'A' ? green('✓') : result.grade === 'F' ? red('●') : yellow('▲');
        const label = `${result.owner}/${result.repo}`;
        const pad = ' '.repeat(Math.max(0, 40 - label.length));
        const counts = result.error
          ? red('error')
          : `${red(String(result.criticals) + 'C')} ${yellow(String(result.warnings) + 'W')} ${cyan(String(result.infos) + 'I')}`;
        console.log(`  ${icon} ${dim(`[${result.completed}/${result.total}]`)} ${bold(label)}${pad} ${dim('grade:')} ${bold(result.grade)}  ${counts}  ${dim((result.durationMs / 1000).toFixed(1) + 's')}`);
      },
    });

    const totalDurationMs = Math.round(performance.now() - start);

    // Summary
    const totalCrit = results.reduce((s, r) => s + r.criticals, 0);
    const totalWarn = results.reduce((s, r) => s + r.warnings, 0);
    const totalInfo = results.reduce((s, r) => s + r.infos, 0);
    const totalFindings = results.reduce((s, r) => s + r.total, 0);
    const failed = results.filter((r) => r.error).length;

    console.log('');
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log(bold('  ⚗️  VIBE AUDIT — ORG SUMMARY'));
    console.log(`  ${bold(String(repos.length))} repos scanned${failed > 0 ? ` (${red(failed + ' failed')})` : ''} in ${dim((totalDurationMs / 1000).toFixed(1) + 's')}`);
    console.log(`  ${red(bold(String(totalCrit)))} critical  ${yellow(bold(String(totalWarn)))} warnings  ${cyan(bold(String(totalInfo)))} info  ${dim('(' + totalFindings + ' total)')}`);
    console.log('');

    // Grade distribution
    const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
    for (const r of results) if (grades[r.grade] !== undefined) grades[r.grade]++;
    console.log(`  Grades: ${green(bold('A:' + grades.A))}  ${green('B:' + grades.B)}  ${yellow('C:' + grades.C)}  ${yellow('D:' + grades.D)}  ${red(bold('F:' + grades.F))}`);

    // Worst repos
    const worst = results.filter((r) => r.grade === 'F' || r.grade === 'D').slice(0, 5);
    if (worst.length > 0) {
      console.log('');
      console.log(red(bold('  Repos needing attention:')));
      for (const r of worst) {
        console.log(`    ${red('●')} ${r.owner}/${r.repo} — ${r.criticals}C ${r.warnings}W`);
      }
    }
    console.log('');

    // Output formats
    if (format === 'html') {
      const html = generateMultiRepoHTML(results, { orgName, durationMs: totalDurationMs });
      const outPath = join(process.cwd(), `vibe-audit-org-${orgName}.html`);
      await writeFile(outPath, html);
      console.log(bold(`  HTML report: ${cyan(outPath)}`));
      console.log(dim('  Open in your browser to view the interactive dashboard.\n'));
    } else if (format === 'json') {
      const output = {
        orgName,
        timestamp: new Date().toISOString(),
        summary: {
          totalRepos: repos.length,
          scannedRepos: repos.length - failed,
          failedRepos: failed,
          totalFindings,
          criticals: totalCrit,
          warnings: totalWarn,
          infos: totalInfo,
          durationMs: totalDurationMs,
          grades,
        },
        repos: results.map((r) => ({
          owner: r.owner,
          repo: r.repo,
          grade: r.grade,
          criticals: r.criticals,
          warnings: r.warnings,
          infos: r.infos,
          total: r.total,
          filesScanned: r.filesScanned,
          durationMs: r.durationMs,
          error: r.error || null,
          findings: r.findings,
        })),
      };
      console.log(JSON.stringify(output, null, 2));
    }

    const hasCritical = totalCrit > 0;
    const hasWarning = totalWarn > 0;
    const strict = values.strict;
    const exitCode = hasCritical ? 1 : strict && hasWarning ? 1 : 0;
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
