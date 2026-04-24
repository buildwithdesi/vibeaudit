#!/usr/bin/env node

/**
 * vibe-audit-batch CLI
 * Scan multiple GitHub repos in one run and produce an aggregate report.
 *
 * Usage:
 *   npx vibe-audit-batch [repos.json] [options]
 *
 * Options:
 *   --format <json|markdown>     Output format (default: markdown)
 *   --concurrency <n>            Parallel scans (default: 5)
 *   --output <file>              Write report to file instead of stdout
 *   --github-issue               Post/update a GitHub issue with the report
 *   --github-issue-repo <owner/repo>  Repo to create the issue in
 *   --help                       Show help
 */

import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { loadRepoList, batchScan, batchMarkdownReport, batchJSONReport } from '../src/batch.js';
import { bold, cyan, dim, red, green, yellow, gray } from '../src/colors.js';

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    format: { type: 'string', short: 'f', default: 'markdown' },
    concurrency: { type: 'string', short: 'c', default: '5' },
    output: { type: 'string', short: 'o' },
    'github-issue': { type: 'boolean' },
    'github-issue-repo': { type: 'string' },
    help: { type: 'boolean', short: 'h' },
  },
});

if (values.help) {
  console.log(`
${bold('⚗️  vibe-audit-batch')} — Scan multiple repos in one morning run

${bold('USAGE')}
  ${cyan('npx vibe-audit-batch')} ${dim('[repos.json]')} ${dim('[options]')}

${bold('OPTIONS')}
  ${cyan('-f, --format')} <json|markdown>     Output format ${dim('(default: markdown)')}
  ${cyan('-c, --concurrency')} <n>            Max parallel scans ${dim('(default: 5)')}
  ${cyan('-o, --output')} <file>              Write report to file
  ${cyan('--github-issue')}                   Create/update a GitHub issue with the report
  ${cyan('--github-issue-repo')} <owner/repo> Which repo to file the issue in
  ${cyan('-h, --help')}                       Show this help

${bold('REPO LIST')}
  Create a ${cyan('repos.json')} file:

  {
    "defaults": { "branch": "main" },
    "repos": [
      "owner/repo-1",
      "owner/repo-2",
      { "owner": "org", "repo": "private-app", "branch": "develop" }
    ]
  }

${bold('EXAMPLES')}
  ${dim('# Scan all repos and print markdown report')}
  npx vibe-audit-batch repos.json

  ${dim('# JSON output, 10 parallel scans')}
  npx vibe-audit-batch repos.json -f json -c 10

  ${dim('# Post results as a GitHub issue')}
  npx vibe-audit-batch repos.json --github-issue --github-issue-repo myorg/security

  ${dim('# Save report to file')}
  npx vibe-audit-batch repos.json -o report.md
`);
  process.exit(0);
}

const configPath = positionals[0] || 'repos.json';
const format = values.format || 'markdown';
const concurrency = parseInt(values.concurrency || '5', 10);

async function main() {
  const startTotal = performance.now();

  // Load repo list
  let repoList;
  try {
    repoList = await loadRepoList(configPath);
  } catch (err) {
    console.error(red(`\n  Error loading repo list: ${err.message}`));
    console.error(dim(`  Create a repos.json file or pass a path: npx vibe-audit-batch ./my-repos.json\n`));
    process.exit(2);
  }

  const { repos } = repoList;
  if (repos.length === 0) {
    console.error(red('\n  No repos found in config.\n'));
    process.exit(2);
  }

  console.error('');
  console.error(bold('  ⚗️  VIBE AUDIT — Batch Scanner'));
  console.error(dim('  ─────────────────────────────────────────────────────────'));
  console.error(`  ${cyan(`${repos.length}`)} repos · ${cyan(`${concurrency}`)} parallel · ${dim(format)} format`);
  console.error('');

  // Run the scan
  const results = await batchScan(repos, {
    concurrency,
    onProgress(result, index, total) {
      const pct = Math.round(((index + 1) / total) * 100);
      const status =
        result.status === 'error'
          ? red('ERR')
          : result.criticals > 0
            ? red(bold(`F ${result.criticals}C`))
            : result.warnings > 0
              ? yellow(`${result.grade} ${result.warnings}W`)
              : green(result.grade);
      console.error(`  ${gray(`[${pct}%]`)} ${status} ${dim(result.repo)} ${gray(`${result.durationMs}ms`)}`);
    },
  });

  const elapsed = Math.round(performance.now() - startTotal);
  console.error('');
  console.error(dim(`  Done in ${(elapsed / 1000).toFixed(1)}s`));
  console.error('');

  // Generate report
  let reportContent;
  if (format === 'json') {
    reportContent = JSON.stringify(batchJSONReport(results), null, 2);
  } else {
    reportContent = batchMarkdownReport(results);
  }

  // Output
  if (values.output) {
    const outPath = resolve(values.output);
    await writeFile(outPath, reportContent);
    console.error(`  ${green('✓')} Report saved to ${cyan(outPath)}`);
    console.error('');
  } else if (!values['github-issue']) {
    console.log(reportContent);
  }

  // GitHub issue mode
  if (values['github-issue']) {
    await postGitHubIssue(reportContent, results);
  }

  // Exit with error if any repo has criticals
  const hasCriticals = results.some((r) => r.status === 'ok' && r.criticals > 0);
  process.exit(hasCriticals ? 1 : 0);
}

async function postGitHubIssue(reportContent, results) {
  const issueRepo = values['github-issue-repo'] || process.env.VIBE_AUDIT_ISSUE_REPO;
  if (!issueRepo) {
    console.error(red('  --github-issue-repo is required (or set VIBE_AUDIT_ISSUE_REPO)'));
    process.exit(2);
  }

  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (!token) {
    console.error(red('  GITHUB_TOKEN is required to create GitHub issues'));
    process.exit(2);
  }

  const [owner, repo] = issueRepo.split('/');
  const date = new Date().toISOString().split('T')[0];
  const ok = results.filter((r) => r.status === 'ok');
  const totalCrit = ok.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = ok.reduce((s, r) => s + r.warnings, 0);

  const title = `⚗️ Daily Vibe Audit — ${date} — ${totalCrit}C/${totalWarn}W across ${ok.length} repos`;

  const headers = {
    Accept: 'application/vnd.github.v3+json',
    Authorization: `Bearer ${token}`,
    'User-Agent': 'vibe-audit-batch',
    'Content-Type': 'application/json',
  };

  // Search for an existing open issue to update (avoids issue spam)
  const searchUrl = `https://api.github.com/search/issues?q=${encodeURIComponent(`repo:${owner}/${repo} is:issue is:open label:vibe-audit-daily`)}`;
  const searchRes = await fetch(searchUrl, { headers });
  const searchData = searchRes.ok ? await searchRes.json() : { items: [] };
  const existing = searchData.items?.[0];

  if (existing) {
    // Update existing issue
    const updateUrl = `https://api.github.com/repos/${owner}/${repo}/issues/${existing.number}`;
    const updateRes = await fetch(updateUrl, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ title, body: reportContent }),
    });
    if (updateRes.ok) {
      const data = await updateRes.json();
      console.error(`  ${green('✓')} Updated issue ${cyan(`#${data.number}`)}: ${data.html_url}`);
    } else {
      console.error(red(`  Failed to update issue: ${updateRes.status}`));
    }
  } else {
    // Create new issue
    const createUrl = `https://api.github.com/repos/${owner}/${repo}/issues`;
    const createRes = await fetch(createUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        title,
        body: reportContent,
        labels: ['vibe-audit-daily'],
      }),
    });
    if (createRes.ok) {
      const data = await createRes.json();
      console.error(`  ${green('✓')} Created issue ${cyan(`#${data.number}`)}: ${data.html_url}`);
    } else {
      const body = await createRes.text();
      console.error(red(`  Failed to create issue: ${createRes.status} ${body}`));
    }
  }
}

main().catch((err) => {
  console.error(red(`\n  Fatal: ${err.message}\n`));
  process.exit(2);
});
