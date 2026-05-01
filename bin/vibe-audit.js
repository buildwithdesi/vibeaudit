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

import { resolve, join } from 'node:path';
import { stat, writeFile, mkdir } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { audit } from '../src/index.js';
import { generateFixes } from '../src/fix.js';
import { ALL_RULES } from '../src/rules/index.js';
import { CWE_MAP } from '../src/data/cwe-map.js';
import { bold, cyan, dim, red, yellow, gray, green } from '../src/colors.js';
import { parseGitHubTarget, fetchRepoFiles } from '../src/github.js';
import { fetchOrgRepos, loadReposFile, parseReposList, scanMultipleRepos } from '../src/multi-repo.js';
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
    org: { type: 'string' },
    repos: { type: 'string' },
    'repos-file': { type: 'string' },
    concurrency: { type: 'string' },
    'output-dir': { type: 'string', short: 'o' },
    'include-forks': { type: 'boolean' },
    'include-archived': { type: 'boolean' },
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

${bold('MULTI-REPO OPTIONS')}
  ${cyan('--org')} <name>                             Scan all repos in a GitHub org/user
  ${cyan('--repos')} <owner/r1,owner/r2,...>          Scan a comma-separated list of repos
  ${cyan('--repos-file')} <path>                     Scan repos listed in a file (one per line)
  ${cyan('--concurrency')} <n>                       Parallel repo scans ${dim('(default: 5)')}
  ${cyan('-o, --output-dir')} <dir>                  Write reports to this directory ${dim('(default: .)')}
  ${cyan('--include-forks')}                         Include forked repos when using --org
  ${cyan('--include-archived')}                      Include archived repos when using --org

${bold('EXAMPLES')}
  ${dim('# Audit current directory')}
  npx vibe-audit

  ${dim('# Audit a specific project')}
  npx vibe-audit ./my-app

  ${dim('# Audit a GitHub repo directly')}
  npx vibe-audit https://github.com/user/repo
  npx vibe-audit user/repo

  ${dim('# Scan all repos in an org (morning sweep)')}
  npx vibe-audit --org mycompany --concurrency 10

  ${dim('# Scan specific repos from a file')}
  npx vibe-audit --repos-file repos.txt -o ./reports

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

const isMultiRepo = values.org || values.repos || values['repos-file'];

if (isMultiRepo) {
  try {
    const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
    const concurrency = parseInt(values.concurrency) || 5;
    const outputDir = values['output-dir'] || '.';
    const format = values.format || 'html';
    let repos;
    let orgName;

    if (values.org) {
      orgName = values.org;
      console.log(cyan(`\n  ⚗️  Fetching repos for: ${orgName}\n`));
      repos = await fetchOrgRepos(orgName, {
        token,
        includeForks: values['include-forks'],
        includeArchived: values['include-archived'],
      });
      console.log(dim(`  Found ${repos.length} repos\n`));
    } else if (values['repos-file']) {
      repos = await loadReposFile(values['repos-file']);
      orgName = 'Multi-Repo Scan';
      console.log(cyan(`\n  ⚗️  Loaded ${repos.length} repos from ${values['repos-file']}\n`));
    } else {
      repos = parseReposList(values.repos);
      orgName = 'Multi-Repo Scan';
      console.log(cyan(`\n  ⚗️  Scanning ${repos.length} repos\n`));
    }

    if (repos.length === 0) {
      console.error(red('\n  Error: No repos found to scan\n'));
      process.exit(2);
    }

    const ruleIds = values.rules?.split(',').filter(Boolean);
    const excludeIds = values.exclude?.split(',').filter(Boolean);

    const result = await scanMultipleRepos(repos, {
      concurrency,
      rules: ruleIds,
      exclude: excludeIds,
      onProgress: (completed, total, repo) => {
        const icon = repo.status === 'error' ? red('✗') : repo.total === 0 ? green('✓') : yellow('⚠');
        const grade = repo.grade !== '?' ? dim(` [${repo.grade}]`) : '';
        const counts = repo.status === 'success'
          ? dim(` ${repo.criticals}C/${repo.warnings}W/${repo.infos}I`)
          : red(` error`);
        return `  ${icon} ${dim(`[${completed}/${total}]`)} ${repo.fullName}${grade}${counts} ${dim(repo.durationMs + 'ms')}`;
      },
    });

    console.log('');
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log('');

    if (format === 'json') {
      const jsonOut = {
        orgName,
        orgGrade: result.orgGrade,
        scannedAt: new Date().toISOString(),
        summary: {
          totalRepos: result.totalRepos,
          succeeded: result.succeeded,
          failed: result.failed,
          totalFindings: result.totalFindings,
          totalCriticals: result.totalCriticals,
          totalWarnings: result.totalWarnings,
          totalInfos: result.totalInfos,
          durationMs: result.durationMs,
        },
        repos: result.repos.map(r => ({
          fullName: r.fullName,
          status: r.status,
          grade: r.grade,
          criticals: r.criticals,
          warnings: r.warnings,
          infos: r.infos,
          total: r.total,
          durationMs: r.durationMs,
          error: r.error || undefined,
          findings: r.findings,
        })),
      };
      console.log(JSON.stringify(jsonOut, null, 2));
    } else {
      // Terminal summary
      const gradeColor = result.orgGrade === 'A' || result.orgGrade === 'B' ? green
        : result.orgGrade === 'C' || result.orgGrade === 'D' ? yellow : red;

      console.log(bold(`  ⚗️  VIBE AUDIT — Multi-Repo Summary`));
      console.log(dim(`  ${orgName} · ${result.totalRepos} repos · ${result.durationMs}ms`));
      console.log('');
      console.log(`  ${gradeColor(bold(`ORG GRADE: ${result.orgGrade}`))}  ${dim('│')}  ${red(bold(`${result.totalCriticals}`))} ${dim('critical')}  ${dim('│')}  ${yellow(bold(`${result.totalWarnings}`))} ${dim('warnings')}  ${dim('│')}  ${cyan(bold(`${result.totalInfos}`))} ${dim('info')}`);
      console.log('');

      // Worst repos
      const worst = result.repos
        .filter(r => r.status === 'success' && r.total > 0)
        .sort((a, b) => b.criticals - a.criticals || b.warnings - a.warnings)
        .slice(0, 10);

      if (worst.length > 0) {
        console.log(bold(`  Top repos needing attention:`));
        for (const r of worst) {
          const icon = r.criticals > 0 ? red('●') : yellow('▲');
          console.log(`    ${icon}  ${bold(r.fullName)} ${dim('—')} ${red(`${r.criticals}C`)} ${yellow(`${r.warnings}W`)} ${cyan(`${r.infos}I`)}`);
        }
        console.log('');
      }

      if (result.failed > 0) {
        console.log(yellow(`  ⚠  ${result.failed} repo(s) failed to scan:`));
        for (const r of result.repos.filter(r => r.status === 'error')) {
          console.log(`    ${red('✗')}  ${r.fullName}: ${dim(r.error || 'Unknown error')}`);
        }
        console.log('');
      }

      // Generate HTML dashboard
      if (format === 'html' || !values.format) {
        const html = generateMultiRepoHTML(result, { orgName });
        await mkdir(outputDir, { recursive: true });
        const filePath = join(resolve(outputDir), 'vibe-audit-multi-repo.html');
        await writeFile(filePath, html);
        console.log(`  ${bold('Dashboard:')} ${cyan(filePath)}`);
        console.log(dim('  Open in your browser to view the interactive dashboard.'));
        console.log('');
      }

      if (result.totalCriticals > 0) {
        console.log(red(bold('  ⛔ CRITICAL issues found across your repos.')));
      } else if (result.totalWarnings > 0) {
        console.log(yellow(bold('  ⚠️  Warnings found. Review the dashboard.')));
      } else {
        console.log(green(bold('  ✅ All repos clean. Ship it.')));
      }
      console.log('');
    }

    const exitCode = result.totalCriticals > 0 ? 1 : values.strict && result.totalWarnings > 0 ? 1 : 0;
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
