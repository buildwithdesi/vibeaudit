#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanOrg } from '../src/org-scan.js';
import { generateOrgHTML } from '../src/reporters/org-html.js';
import { bold, cyan, dim, red, yellow, green } from '../src/colors.js';

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    token: { type: 'string' },
    concurrency: { type: 'string' },
    'skip-forks': { type: 'boolean' },
    'skip-archived': { type: 'boolean' },
    include: { type: 'string' },
    exclude: { type: 'string' },
    format: { type: 'string' },
    output: { type: 'string' },
    'open-issues': { type: 'boolean' },
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'v' },
  },
});

if (values.help) {
  console.log(`
${bold('⚗️  vibeaudit-org')} — Fleet security scanner for GitHub orgs & users

${bold('USAGE')}
  ${cyan('vibeaudit-org')} ${dim('<owner>')} ${dim('[options]')}

${bold('OPTIONS')}
  ${cyan('--token')} <token>          GitHub token (or use GITHUB_TOKEN env var)
  ${cyan('--concurrency')} <n>        Parallel repo scans ${dim('(default: 5)')}
  ${cyan('--skip-forks')}             Skip forked repos
  ${cyan('--skip-archived')}          Skip archived repos
  ${cyan('--include')} <patterns>     Only scan repos matching patterns (comma-separated)
  ${cyan('--exclude')} <patterns>     Skip repos matching patterns (comma-separated)
  ${cyan('--format')} <format>        Output format: terminal, json, html ${dim('(default: terminal)')}
  ${cyan('--output')} <path>          Output file path for html/json ${dim('(default: auto-generated)')}
  ${cyan('--open-issues')}            Create GitHub issues for repos with critical findings
  ${cyan('-h, --help')}               Show this help
  ${cyan('-v, --version')}            Show version

${bold('EXAMPLES')}
  ${dim('# Scan all repos for a user')}
  vibeaudit-org jackdog668

  ${dim('# Scan an org, skip forks, output HTML')}
  vibeaudit-org my-org --skip-forks --format html

  ${dim('# Only scan repos matching a pattern')}
  vibeaudit-org my-org --include "api-*,backend-*"

${dim('Built by Digital Alchemy Academy — https://digitalalchemy.dev')}
`);
  process.exit(0);
}

if (values.version) {
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const pkg = require('../package.json');
  console.log(pkg.version);
  process.exit(0);
}

const owner = positionals[0];

if (!owner) {
  console.error(red('\n  Error: Missing required <owner> argument\n'));
  console.error(dim('  Usage: vibeaudit-org <owner> [options]\n'));
  process.exit(2);
}

const token = values.token || process.env.GITHUB_TOKEN;
const concurrency = values.concurrency ? parseInt(values.concurrency, 10) : 5;
const format = values.format || 'terminal';
const include = values.include ? values.include.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
const exclude = values.exclude ? values.exclude.split(',').map((s) => s.trim()).filter(Boolean) : undefined;

let scannedCount = 0;
let totalCount = 0;

function gradeColor(grade) {
  if (grade === 'A') return green;
  if (grade === 'B') return green;
  if (grade === 'C') return yellow;
  if (grade === 'D') return yellow;
  return red;
}

function calcFleetGrade(results) {
  let totalCrit = 0;
  let totalWarn = 0;
  let reposWithCritical = 0;
  for (const [, result] of results) {
    const crits = result.findings.filter((f) => f.severity === 'critical').length;
    const warns = result.findings.filter((f) => f.severity === 'warning').length;
    if (crits > 0) reposWithCritical++;
    totalCrit += crits;
    totalWarn += warns;
  }
  const repoCount = results.size;
  const critRatio = reposWithCritical / repoCount;
  if (critRatio > 0.3) return 'F';
  if (critRatio > 0.15) return 'D';
  if (totalCrit > 0) return 'C';
  if (totalWarn > 5) return 'B';
  return 'A';
}

try {
  if (format === 'terminal') {
    console.log(cyan(`\n  ⚗️  Scanning all repos for ${bold(owner)}...\n`));
  }

  const orgResult = await scanOrg(owner, {
    token,
    concurrency,
    skipForks: values['skip-forks'],
    skipArchived: values['skip-archived'],
    include,
    exclude,
    onRepoStart(repo) {
      if (format === 'terminal') {
        scannedCount++;
        process.stdout.write(`\r  ${dim(`[${scannedCount}/${totalCount || '?'}]`)} Scanning ${cyan(owner + '/' + repo.name)}...${' '.repeat(20)}`);
      }
    },
    onRepoComplete() {},
  });

  totalCount = orgResult.repos.length;

  if (format === 'json') {
    const plainResults = {};
    for (const [name, result] of orgResult.results) {
      plainResults[name] = result;
    }
    const output = JSON.stringify({ ...orgResult, results: plainResults }, null, 2);
    if (values.output) {
      writeFileSync(resolve(values.output), output, 'utf8');
      console.log(`Written to ${values.output}`);
    } else {
      console.log(output);
    }
  } else if (format === 'html') {
    const html = generateOrgHTML(orgResult);
    const date = new Date().toISOString().slice(0, 10);
    const outputPath = values.output || `vibe-audit-fleet-${owner}-${date}.html`;
    writeFileSync(resolve(outputPath), html, 'utf8');

    const jsonPath = outputPath.replace(/\.html$/, '.json');
    const plainResults = {};
    for (const [name, result] of orgResult.results) {
      plainResults[name] = result;
    }
    writeFileSync(resolve(jsonPath), JSON.stringify({ ...orgResult, results: plainResults }, null, 2), 'utf8');

    console.log(`\n  ${green('✔')} HTML report written to ${cyan(outputPath)}`);
    console.log(`  ${green('✔')} JSON summary written to ${cyan(jsonPath)}\n`);
  } else {
    const { results, summary } = orgResult;

    process.stdout.write('\r' + ' '.repeat(80) + '\r');

    const fleetGrade = calcFleetGrade(results);
    const colorGrade = gradeColor(fleetGrade);

    let reposWithCritical = 0;
    let reposWithWarningsOnly = 0;
    let reposClean = 0;

    const repoEntries = [];

    for (const [name, result] of results) {
      const crits = result.findings.filter((f) => f.severity === 'critical').length;
      const warns = result.findings.filter((f) => f.severity === 'warning').length;
      const infos = result.findings.filter((f) => f.severity === 'info').length;
      const grade = result.grade;

      if (crits > 0) {
        reposWithCritical++;
      } else if (warns > 0) {
        reposWithWarningsOnly++;
      } else {
        reposClean++;
      }

      repoEntries.push({ name, grade, crits, warns, infos });
    }

    const needsAttention = repoEntries
      .filter((r) => r.crits > 0 || r.warns > 0)
      .sort((a, b) => {
        const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4 };
        if (gradeOrder[a.grade] !== gradeOrder[b.grade]) return gradeOrder[a.grade] - gradeOrder[b.grade];
        return b.crits - a.crits;
      });

    const issueCount = {};
    for (const [, result] of results) {
      for (const f of result.findings) {
        issueCount[f.ruleId] = (issueCount[f.ruleId] || 0) + 1;
      }
    }

    const issueRepoCount = {};
    for (const [, result] of results) {
      const seen = new Set();
      for (const f of result.findings) {
        if (!seen.has(f.ruleId)) {
          seen.add(f.ruleId);
          issueRepoCount[f.ruleId] = (issueRepoCount[f.ruleId] || 0) + 1;
        }
      }
    }

    const topIssues = Object.entries(issueRepoCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    const durationSec = (summary.durationMs / 1000).toFixed(1);

    console.log('');
    console.log(`  ${bold('⚗️  VIBE AUDIT — Fleet Scan')}`);
    console.log(`  ${dim('─────────────────────────────────────')}`);
    console.log(`  Owner: ${bold(owner)} (${summary.totalRepos} repos)`);
    console.log('');
    console.log(`  FLEET GRADE: ${colorGrade(bold(fleetGrade))}`);
    console.log('');
    console.log(`  ${red(String(reposWithCritical))} repos with critical issues`);
    console.log(`  ${yellow(String(reposWithWarningsOnly))} repos with warnings only`);
    console.log(`  ${green(String(reposClean))} repos clean (Grade A/B)`);

    if (needsAttention.length > 0) {
      console.log('');
      console.log(`  ${bold('── Repos Needing Attention ──────────')}`);
      console.log('');

      for (const r of needsAttention) {
        const gc = gradeColor(r.grade);
        const padName = r.name.padEnd(22);
        console.log(`  ${gc(bold(r.grade))}  ${padName}${red(r.crits + 'C')}  ${yellow(r.warns + 'W')}  ${cyan(r.infos + 'I')}`);
      }
    }

    if (topIssues.length > 0) {
      console.log('');
      console.log(`  ${bold('── Top Issues Across Fleet ──────────')}`);
      console.log('');

      for (const [ruleId, count] of topIssues) {
        const padRule = ruleId.padEnd(24);
        console.log(`  ${yellow(padRule)}found in ${bold(String(count))} repos`);
      }
    }

    console.log('');
    console.log(dim(`  ${summary.totalRepos} repos scanned · ${summary.totalFindings} findings · ${durationSec}s`));
    console.log('');
  }

  if (values['open-issues']) {
    const ghToken = token;
    if (!ghToken) {
      console.error(red('\n  Error: --open-issues requires a GitHub token (--token or GITHUB_TOKEN)\n'));
      process.exit(2);
    }

    const { results } = orgResult;
    let created = 0;
    let skipped = 0;

    for (const [repoName, result] of results) {
      const criticals = result.findings.filter((f) => f.severity === 'critical');
      if (criticals.length === 0) continue;

      const title = `⚗️ Vibe Audit: ${criticals.length} critical security findings`;

      const existingRes = await fetch(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/issues?state=open&per_page=100`,
        {
          headers: {
            Accept: 'application/vnd.github.v3+json',
            Authorization: `Bearer ${ghToken}`,
            'User-Agent': 'vibe-audit',
          },
        }
      );

      if (existingRes.ok) {
        const existingIssues = await existingRes.json();
        const alreadyExists = existingIssues.some((issue) => issue.title === title);
        if (alreadyExists) {
          skipped++;
          continue;
        }
      }

      let body = `## ⚗️ Vibe Audit — Critical Security Findings\n\n`;
      body += `Found **${criticals.length}** critical issues in this repo.\n\n`;
      body += `| # | Rule | File | Line |\n`;
      body += `|---|------|------|------|\n`;
      criticals.forEach((f, i) => {
        body += `| ${i + 1} | \`${f.ruleId}\` | \`${f.file || 'N/A'}\` | ${f.line || '-'} |\n`;
      });
      body += `\n---\n*Generated by [vibe-audit](https://github.com/jackdog668/vibeaudit)*`;

      const createRes = await fetch(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/issues`,
        {
          method: 'POST',
          headers: {
            Accept: 'application/vnd.github.v3+json',
            Authorization: `Bearer ${ghToken}`,
            'User-Agent': 'vibe-audit',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ title, body }),
        }
      );

      if (createRes.ok) {
        created++;
        if (format === 'terminal') {
          console.log(`  ${green('✔')} Created issue in ${cyan(owner + '/' + repoName)}`);
        }
      } else {
        const errText = await createRes.text();
        if (format === 'terminal') {
          console.log(`  ${red('✗')} Failed to create issue in ${repoName}: ${errText}`);
        }
      }
    }

    if (format === 'terminal') {
      console.log(dim(`\n  Issues: ${created} created, ${skipped} already existed\n`));
    }
  }

  const hasCritical = orgResult.summary.totalCritical > 0;
  process.exit(hasCritical ? 1 : 0);
} catch (err) {
  console.error(red(`\n  Error: ${err.message}\n`));
  process.exit(2);
}
