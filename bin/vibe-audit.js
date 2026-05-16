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
import { stat } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { audit } from '../src/index.js';
import { generateFixes } from '../src/fix.js';
import { ALL_RULES } from '../src/rules/index.js';
import { CWE_MAP } from '../src/data/cwe-map.js';
import { bold, cyan, dim, red, yellow, green, gray } from '../src/colors.js';
import { parseGitHubTarget, fetchRepoFiles } from '../src/github.js';
import { fetchOrgRepos, parseRepoList, scanRepos } from '../src/multi-repo.js';
import { generateMultiRepoHTML } from '../src/reporters/multi-repo-html.js';
import { readFile, writeFile, mkdir } from 'node:fs/promises';

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
    'repos-file': { type: 'string' },
    concurrency: { type: 'string' },
    output: { type: 'string', short: 'o' },
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

${bold('MULTI-REPO (Morning Scan)')}
  ${cyan('--org')} <github-org>                       Scan all repos in a GitHub org/user
  ${cyan('--repos-file')} <path>                      Scan repos from a file (JSON or one-per-line)
  ${cyan('--concurrency')} <n>                        Max parallel scans ${dim('(default: 5)')}
  ${cyan('-o, --output')} <dir>                       Output directory for reports ${dim('(default: .)')}
  ${cyan('--include-forks')}                          Include forked repos
  ${cyan('--include-archived')}                       Include archived repos

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

  ${dim('# Morning scan across an entire org')}
  npx vibe-audit --org my-startup
  GITHUB_TOKEN=ghp_xxx npx vibe-audit --org my-startup --concurrency 10

  ${dim('# Scan repos from a file')}
  npx vibe-audit --repos-file repos.txt

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

// ─── Multi-Repo Scan ─────────────────────────────────────────────────────────

if (values.org || values['repos-file']) {
  try {
    const concurrency = values.concurrency ? parseInt(values.concurrency, 10) : 5;
    const outputDir = values.output ? resolve(values.output) : process.cwd();
    const format = values.format || 'html';

    let repos;
    let label;

    if (values.org) {
      label = values.org;
      console.log('');
      console.log(bold(`  ⚗️  VIBE AUDIT — Morning Scan`));
      console.log(dim(`  Fetching repos for ${cyan(values.org)}...`));

      repos = await fetchOrgRepos(values.org, {
        includeForks: values['include-forks'],
        includeArchived: values['include-archived'],
      });

      console.log(dim(`  Found ${bold(String(repos.length))} repos to scan (concurrency: ${concurrency})`));
    } else {
      const content = await readFile(resolve(values['repos-file']), 'utf-8');
      repos = parseRepoList(content);
      label = values['repos-file'];
      console.log('');
      console.log(bold(`  ⚗️  VIBE AUDIT — Multi-Repo Scan`));
      console.log(dim(`  Loaded ${bold(String(repos.length))} repos from ${cyan(values['repos-file'])}`));
    }

    if (repos.length === 0) {
      console.log(yellow('\n  No repos found to scan.\n'));
      process.exit(0);
    }

    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log('');

    const scanStart = performance.now();
    let completed = 0;

    const results = await scanRepos(repos, {
      concurrency,
      rules: values.rules?.split(',').filter(Boolean),
      exclude: values.exclude?.split(',').filter(Boolean),
      onProgress(result) {
        completed++;
        const icon = result.error ? red('✗') : result.criticals > 0 ? red('●') : result.warnings > 0 ? yellow('▲') : green('✓');
        const counts = result.error
          ? dim(`error: ${result.error.slice(0, 60)}`)
          : `${result.criticals}C ${result.warnings}W ${result.infos}I`;
        console.log(`  ${dim(`[${String(completed).padStart(String(repos.length).length)}/${repos.length}]`)} ${icon} ${result.fullName} ${dim('—')} ${counts} ${dim(`(${result.durationMs}ms)`)}`);
      },
    });

    const totalDurationMs = Math.round(performance.now() - scanStart);

    console.log('');
    console.log(dim('  ─────────────────────────────────────────────────────────────'));

    // Aggregated summary
    const totalFindings = results.reduce((s, r) => s + r.findings.length, 0);
    const totalCrits = results.reduce((s, r) => s + r.criticals, 0);
    const totalWarns = results.reduce((s, r) => s + r.warnings, 0);
    const totalInfos = results.reduce((s, r) => s + r.infos, 0);
    const failed = results.filter((r) => r.error).length;
    const passing = results.filter((r) => r.grade === 'A' || r.grade === 'B').length;

    console.log('');
    console.log(bold(`  ⚗️  SCAN COMPLETE`));
    console.log(`  ${bold(String(repos.length))} repos scanned in ${bold(Math.round(totalDurationMs / 1000) + 's')}${failed > 0 ? ` (${red(failed + ' failed')})` : ''}`);
    console.log(`  ${red(bold(String(totalCrits)))} critical  ${yellow(bold(String(totalWarns)))} warnings  ${cyan(bold(String(totalInfos)))} info  ${dim('(' + totalFindings + ' total)')}`);
    console.log(`  ${green(bold(String(passing)))}/${repos.length} repos passing (grade A/B)`);
    console.log('');

    // Worst offenders
    const worst = results.filter((r) => r.criticals > 0).sort((a, b) => b.criticals - a.criticals).slice(0, 5);
    if (worst.length > 0) {
      console.log(red(bold('  Worst offenders:')));
      for (const r of worst) {
        console.log(`    ${red('●')} ${r.fullName} — ${red(bold(String(r.criticals)))} critical, ${yellow(String(r.warnings))} warnings`);
      }
      console.log('');
    }

    // Output
    const now = new Date().toISOString();
    if (format === 'json') {
      const jsonOutput = {
        meta: { org: label, reposScanned: repos.length, durationMs: totalDurationMs, date: now },
        summary: { total: totalFindings, critical: totalCrits, warning: totalWarns, info: totalInfos, failed, passing },
        repos: results.map((r) => ({
          fullName: r.fullName, grade: r.grade, criticals: r.criticals, warnings: r.warnings, infos: r.infos,
          durationMs: r.durationMs, error: r.error || undefined,
          findings: r.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, file: f.file, line: f.line, message: f.message })),
        })),
      };
      const jsonPath = join(outputDir, 'vibe-audit-multi-report.json');
      await writeFile(jsonPath, JSON.stringify(jsonOutput, null, 2));
      console.log(`  ${bold('JSON report:')} ${cyan(jsonPath)}`);
    } else {
      const html = generateMultiRepoHTML(results, { org: label, durationMs: totalDurationMs });
      try { await mkdir(outputDir, { recursive: true }); } catch { /* exists */ }
      const htmlPath = join(outputDir, 'vibe-audit-morning-scan.html');
      await writeFile(htmlPath, html);
      console.log(`  ${bold('HTML dashboard:')} ${cyan(htmlPath)}`);
      console.log(dim('  Open in your browser to view the interactive report.'));
    }

    console.log('');

    const exitCode = totalCrits > 0 ? 1 : values.strict && totalWarns > 0 ? 1 : 0;
    process.exit(exitCode);
  } catch (err) {
    console.error(red(`\n  Error: ${err.message}\n`));
    process.exit(2);
  }
}

// ─── Run Audit (Single Repo) ─────────────────────────────────────────────────

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
