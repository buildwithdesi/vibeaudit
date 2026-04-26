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
import { batchAudit, discoverOrgRepos } from '../src/batch.js';
import { batchTerminal, batchJSON, batchMarkdown } from '../src/reporters/batch.js';

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
    concurrency: { type: 'string' },
    output: { type: 'string', short: 'o' },
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
  ${cyan('-b, --batch')} <file>                      Scan repos listed in a JSON file
  ${cyan('--org')} <name>                            Scan all repos in a GitHub org/user
  ${cyan('--concurrency')} <n>                       Max parallel scans for batch mode ${dim('(default: 5)')}
  ${cyan('-o, --output')} <file>                     Write batch report to file
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

  ${dim('# JSON output for CI pipelines')}
  npx vibe-audit --format json --strict

  ${dim('# Only check for secrets and auth')}
  npx vibe-audit --rules exposed-secrets,missing-auth

  ${dim('# Scan all repos in a GitHub org')}
  npx vibe-audit --org my-company --format markdown

  ${dim('# Batch scan from a repo list')}
  npx vibe-audit --batch repos.json --output report.md

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

// ─── Batch / Org Mode ────────────────────────────────────────────────────────

if (values.batch || values.org) {
  let repos;

  if (values.org) {
    console.log(cyan(`\n  ⚗️  Discovering repos for: ${values.org}\n`));
    repos = await discoverOrgRepos(values.org);
    console.log(dim(`  Found ${repos.length} repos\n`));
  } else {
    const raw = await readFile(resolve(values.batch), 'utf8');
    const parsed = JSON.parse(raw);
    repos = Array.isArray(parsed) ? parsed : parsed.repos;
    if (!Array.isArray(repos)) {
      console.error(red('\n  Error: Batch file must be a JSON array or { "repos": [...] }\n'));
      process.exit(2);
    }
  }

  if (repos.length === 0) {
    console.error(red('\n  Error: No repos to scan\n'));
    process.exit(2);
  }

  const concurrency = values.concurrency ? parseInt(values.concurrency, 10) : 5;
  const format = values.format || 'terminal';

  let scannedCount = 0;
  const onProgress = (_done, total, repo, result) => {
    scannedCount++;
    const icon = result.error ? red('✗') : result.critical > 0 ? red('●') : result.warning > 0 ? yellow('▲') : green('✓');
    if (format === 'terminal') {
      console.log(dim(`  [${scannedCount}/${total}]`) + ` ${icon} ${repo}` + (result.error ? red(` — ${result.error}`) : ''));
    }
  };

  const { results, summary } = await batchAudit(repos, {
    concurrency,
    rules: values.rules?.split(',').filter(Boolean),
    exclude: values.exclude?.split(',').filter(Boolean),
    strict: values.strict,
    onProgress,
  });

  let output;
  switch (format) {
    case 'json':
      output = batchJSON(results, summary);
      break;
    case 'markdown':
      output = batchMarkdown(results, summary);
      break;
    default:
      output = batchTerminal(results, summary);
      break;
  }

  if (values.output) {
    await writeFile(resolve(values.output), output);
    console.log(cyan(`\n  Report written to ${values.output}\n`));
  } else {
    console.log(output);
  }

  const exitCode = summary.totalCritical > 0 ? 1 : values.strict && summary.totalWarning > 0 ? 1 : 0;
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
