#!/usr/bin/env node

/**
 * batch-scan — Run vibe-audit across multiple GitHub repos.
 *
 * Reads repos from repos.json (or a file passed via --config),
 * scans each via the GitHub API, and outputs a consolidated JSON report
 * to stdout. Designed for cron / GitHub Actions morning runs.
 *
 * Usage:
 *   node bin/batch-scan.js [--config repos.json] [--concurrency 4] [--format summary|json|markdown]
 */

import { readFile, writeFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { audit } from '../src/index.js';
import { fetchRepoFiles } from '../src/github.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { values } = parseArgs({
  options: {
    config: { type: 'string', short: 'c', default: resolve(__dirname, '..', 'repos.json') },
    concurrency: { type: 'string', default: '4' },
    format: { type: 'string', short: 'f', default: 'summary' },
    output: { type: 'string', short: 'o' },
    'fail-on-critical': { type: 'boolean', default: false },
  },
});

const concurrency = parseInt(values.concurrency, 10) || 4;

async function loadRepos(configPath) {
  const raw = await readFile(configPath, 'utf8');
  const data = JSON.parse(raw);
  if (!Array.isArray(data.repos) || data.repos.length === 0) {
    throw new Error(`No repos found in ${configPath}`);
  }
  return data.repos;
}

async function scanRepo(repoSlug) {
  const [owner, repo] = repoSlug.split('/');
  if (!owner || !repo) {
    return { repo: repoSlug, error: `Invalid repo format: ${repoSlug}` };
  }

  const start = performance.now();
  try {
    const fileSource = fetchRepoFiles(owner, repo);
    const { findings } = await audit(`github://${owner}/${repo}`, {
      format: 'json',
      fileSource,
      skipSca: true,
      quiet: true,
    });

    const duration = Math.round(performance.now() - start);
    const critical = findings.filter(f => f.severity === 'critical');
    const warnings = findings.filter(f => f.severity === 'warning');
    const info = findings.filter(f => f.severity === 'info');

    return {
      repo: repoSlug,
      duration,
      total: findings.length,
      critical: critical.length,
      warnings: warnings.length,
      info: info.length,
      findings,
      error: null,
    };
  } catch (err) {
    const duration = Math.round(performance.now() - start);
    return { repo: repoSlug, duration, error: err.message, total: 0, critical: 0, warnings: 0, info: 0, findings: [] };
  }
}

async function runBatch(repos) {
  const results = [];
  const queue = [...repos];

  async function worker() {
    while (queue.length > 0) {
      const repo = queue.shift();
      process.stderr.write(`  Scanning ${repo}...\n`);
      const result = await scanRepo(repo);
      results.push(result);
      if (result.error) {
        process.stderr.write(`  ✗ ${repo}: ${result.error}\n`);
      } else {
        process.stderr.write(`  ✓ ${repo}: ${result.critical}C ${result.warnings}W ${result.info}I (${result.duration}ms)\n`);
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, repos.length) }, () => worker());
  await Promise.all(workers);

  return results;
}

function formatSummary(results) {
  const lines = [];
  const timestamp = new Date().toISOString();
  const totalRepos = results.length;
  const failed = results.filter(r => r.error).length;
  const totalCritical = results.reduce((sum, r) => sum + r.critical, 0);
  const totalWarnings = results.reduce((sum, r) => sum + r.warnings, 0);
  const totalInfo = results.reduce((sum, r) => sum + r.info, 0);
  const totalFindings = results.reduce((sum, r) => sum + r.total, 0);

  lines.push('╔══════════════════════════════════════════════════════════════╗');
  lines.push('║          ⚗️  VIBE AUDIT — DAILY SCAN REPORT                 ║');
  lines.push('╚══════════════════════════════════════════════════════════════╝');
  lines.push('');
  lines.push(`  Timestamp:  ${timestamp}`);
  lines.push(`  Repos:      ${totalRepos} scanned${failed > 0 ? `, ${failed} failed` : ''}`);
  lines.push(`  Findings:   ${totalFindings} total`);
  lines.push(`              ${totalCritical} critical · ${totalWarnings} warnings · ${totalInfo} info`);
  lines.push('');

  if (totalCritical > 0) {
    lines.push('  ⛔ REPOS WITH CRITICAL ISSUES:');
    lines.push('  ─────────────────────────────────────');
    for (const r of results.filter(r => r.critical > 0).sort((a, b) => b.critical - a.critical)) {
      lines.push(`    ${r.repo}: ${r.critical} critical, ${r.warnings} warnings`);
      const crits = r.findings.filter(f => f.severity === 'critical').slice(0, 3);
      for (const f of crits) {
        lines.push(`      └─ ${f.file}:${f.line || '?'} — ${f.message}`);
      }
    }
    lines.push('');
  }

  if (totalWarnings > 0) {
    lines.push('  ⚠️  REPOS WITH WARNINGS:');
    lines.push('  ─────────────────────────────────────');
    for (const r of results.filter(r => r.warnings > 0 && r.critical === 0).sort((a, b) => b.warnings - a.warnings)) {
      lines.push(`    ${r.repo}: ${r.warnings} warnings`);
    }
    lines.push('');
  }

  const clean = results.filter(r => r.total === 0 && !r.error);
  if (clean.length > 0) {
    lines.push(`  ✅ CLEAN: ${clean.map(r => r.repo).join(', ')}`);
    lines.push('');
  }

  if (failed > 0) {
    lines.push('  ❌ FAILED TO SCAN:');
    for (const r of results.filter(r => r.error)) {
      lines.push(`    ${r.repo}: ${r.error}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function formatMarkdown(results) {
  const timestamp = new Date().toISOString();
  const totalCritical = results.reduce((sum, r) => sum + r.critical, 0);
  const totalWarnings = results.reduce((sum, r) => sum + r.warnings, 0);
  const totalInfo = results.reduce((sum, r) => sum + r.info, 0);

  const lines = [
    '# ⚗️ Vibe Audit — Daily Scan Report',
    '',
    `**Date:** ${timestamp}  `,
    `**Repos scanned:** ${results.length}  `,
    `**Totals:** ${totalCritical} critical · ${totalWarnings} warnings · ${totalInfo} info`,
    '',
    '## Results',
    '',
    '| Repo | Critical | Warnings | Info | Status |',
    '|------|----------|----------|------|--------|',
  ];

  for (const r of results.sort((a, b) => b.critical - a.critical || b.warnings - a.warnings)) {
    if (r.error) {
      lines.push(`| ${r.repo} | - | - | - | ❌ ${r.error.slice(0, 40)} |`);
    } else {
      const status = r.critical > 0 ? '🔴' : r.warnings > 0 ? '🟡' : '✅';
      lines.push(`| ${r.repo} | ${r.critical} | ${r.warnings} | ${r.info} | ${status} |`);
    }
  }

  lines.push('');

  if (totalCritical > 0) {
    lines.push('## 🔴 Critical Findings');
    lines.push('');
    for (const r of results.filter(r => r.critical > 0)) {
      lines.push(`### ${r.repo}`);
      for (const f of r.findings.filter(f => f.severity === 'critical')) {
        lines.push(`- **${f.message}** — \`${f.file}:${f.line || '?'}\`${f.cweId ? ` [${f.cweId}]` : ''}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

function formatJSON(results) {
  const timestamp = new Date().toISOString();
  return JSON.stringify({
    timestamp,
    summary: {
      repos: results.length,
      failed: results.filter(r => r.error).length,
      critical: results.reduce((s, r) => s + r.critical, 0),
      warnings: results.reduce((s, r) => s + r.warnings, 0),
      info: results.reduce((s, r) => s + r.info, 0),
    },
    results: results.map(r => ({
      repo: r.repo,
      duration: r.duration,
      critical: r.critical,
      warnings: r.warnings,
      info: r.info,
      error: r.error,
      findings: r.findings,
    })),
  }, null, 2);
}

// ─── Main ────────────────────────────────────────────────────────────────────

const configPath = resolve(values.config);
process.stderr.write(`\n  ⚗️  Vibe Audit — Batch Scanner\n`);
process.stderr.write(`  Config: ${configPath}\n`);
process.stderr.write(`  Concurrency: ${concurrency}\n\n`);

const repos = await loadRepos(configPath);
process.stderr.write(`  Found ${repos.length} repos to scan.\n\n`);

const results = await runBatch(repos);

let output;
switch (values.format) {
  case 'json':
    output = formatJSON(results);
    break;
  case 'markdown':
    output = formatMarkdown(results);
    break;
  default:
    output = formatSummary(results);
}

if (values.output) {
  await writeFile(resolve(values.output), output);
  process.stderr.write(`\n  Report written to: ${values.output}\n`);
} else {
  console.log(output);
}

// Exit with code 1 if any criticals found (useful for CI)
if (values['fail-on-critical']) {
  const hasCritical = results.some(r => r.critical > 0);
  if (hasCritical) process.exit(1);
}
