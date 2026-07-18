#!/usr/bin/env node

/**
 * Batch scanner — runs vibe-audit across multiple GitHub repos.
 *
 * Usage:
 *   GITHUB_TOKEN=ghp_xxx node scripts/morning-scan.js [options]
 *
 * Options:
 *   --repos <file>      Repo list JSON (default: scripts/repos.json)
 *   --top <N>           Only scan the first N repos (0 = all)
 *   --discover          Auto-discover repos from GitHub (ignores --repos)
 *   --owner <name>      GitHub owner for --discover (default: jackdog668)
 *   --concurrency <N>   Parallel scans (default: 3)
 *   --format <fmt>      Report format (default: markdown)
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { audit } from '../src/index.js';
import { fetchRepoFiles, parseGitHubTarget } from '../src/github.js';
import { BASELINE_IGNORE } from '../src/baseline-ignore.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const argv = process.argv.slice(2);
function flag(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
}
const hasFlag = (name) => argv.includes(`--${name}`);

const reposFile = flag('repos', join(ROOT, 'scripts', 'repos.json'));
const topN = parseInt(flag('top', '0'), 10);
const discover = hasFlag('discover');
const owner = flag('owner', 'jackdog668');
const concurrency = parseInt(flag('concurrency', '3'), 10);

async function discoverRepos(owner) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = { Accept: 'application/vnd.github.v3+json', 'User-Agent': 'vibe-audit' };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;
  while (true) {
    const url = `https://api.github.com/users/${owner}/repos?per_page=100&page=${page}&sort=updated&direction=desc`;
    const res = await fetch(url, { headers }); // vibe-audit-ignore perf-no-await-parallel  (pagination is inherently sequential — need page N to know if N+1 exists)
    if (!res.ok) throw new Error(`Failed to list repos: ${res.status}`);
    const batch = await res.json(); // vibe-audit-ignore perf-no-await-parallel  (pagination response, inherently sequential)
    if (batch.length === 0) break;
    for (const r of batch) {
      if (!r.archived && !r.fork) repos.push(r.full_name);
    }
    page++;
  }
  return repos;
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function scanRepo(name) {
  const parsed = parseGitHubTarget(name);
  if (!parsed) return { error: { repo: name, error: 'Invalid repo format' } };

  try {
    const fileSource = fetchRepoFiles(parsed.owner, parsed.repo);
    const { findings } = await audit(name, {
      format: 'json',
      skipSca: true,
      fileSource,
      extraIgnore: BASELINE_IGNORE,
    });

    const criticals = findings.filter((f) => f.severity === 'critical').length;
    const warnings = findings.filter((f) => f.severity === 'warning').length;
    const infos = findings.filter((f) => f.severity === 'info').length;
    const grade =
      criticals > 0 ? 'F' : warnings > 3 ? 'D' : warnings > 1 ? 'C' : warnings > 0 ? 'B' : 'A';

    return {
      result: { repo: name, grade, criticals, warnings, infos, total: findings.length, findings },
    };
  } catch (err) {
    // makeApiError tags genuine rate limits (primary/secondary) vs plain 403s
    // (token lacks access) — trust the flag, not string matching, so a forbidden
    // repo doesn't trigger a false portfolio-wide backoff.
    if (err.rateLimited) {
      return { error: { repo: name, error: 'Rate limited' }, rateLimited: true };
    }
    const msg = err.message || String(err);
    const short = msg.includes('404')
      ? 'Not found / empty'
      : msg.includes('403')
        ? 'Forbidden (check token scope)'
        : msg.includes('401')
          ? 'Auth required'
          : msg.includes('409')
            ? 'Empty repo'
            : msg.slice(0, 80);
    return { error: { repo: name, error: short } };
  }
}

async function main() {
  let repos;
  if (discover) {
    console.log(`\n   Discovering repos for ${owner}...`);
    repos = await discoverRepos(owner);
    console.log(`   Found ${repos.length} repos.`);
    // Save discovered list for next time
    await writeFile(join(ROOT, 'scripts', 'repos.json'), JSON.stringify(repos, null, 2));
  } else {
    const raw = await readFile(reposFile, 'utf8');
    repos = JSON.parse(raw);
  }

  if (topN > 0) repos = repos.slice(0, topN);

  const results = [];
  const errors = [];
  const startTime = Date.now();

  const date = new Date().toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
  console.log(`\n  Vibe Audit Morning Scan — ${date}`);
  console.log(`   Scanning ${repos.length} repositories (concurrency: ${concurrency})...\n`);

  // Process repos with controlled concurrency
  let i = 0;
  let rateLimitBackoff = 0;

  while (i < repos.length) {
    if (rateLimitBackoff > 0) {
      console.log(`   Rate limited — waiting ${rateLimitBackoff}s...`);
      await sleep(rateLimitBackoff * 1000); // vibe-audit-ignore perf-no-await-parallel  (intentional rate-limit backoff between batches)
      rateLimitBackoff = 0;
    }

    const batch = repos.slice(i, i + concurrency);
    const promises = batch.map(async (name) => {
      process.stdout.write(`   ${name} ... `);
      const out = await scanRepo(name);
      if (out.result) {
        const r = out.result;
        const icon = r.criticals > 0 ? 'X' : r.warnings > 0 ? '!' : '+';
        console.log(`[${icon}] Grade ${r.grade} (${r.criticals}C/${r.warnings}W/${r.infos}I)`);
        results.push(r);
      } else {
        console.log(`[-] Skipped (${out.error.error})`);
        errors.push(out.error);
        if (out.rateLimited) rateLimitBackoff = Math.min(rateLimitBackoff + 30, 120);
      }
      return out;
    });

    await Promise.all(promises);
    i += concurrency;
  }

  const durationSec = ((Date.now() - startTime) / 1000).toFixed(1);

  // Sort results: worst grade first
  const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4 };
  results.sort((a, b) => gradeOrder[a.grade] - gradeOrder[b.grade]);

  const report = generateReport(results, errors, repos.length, durationSec);
  const outDir = join(ROOT, 'reports');
  await mkdir(outDir, { recursive: true });

  const dateStr = new Date().toISOString().split('T')[0];
  const reportPath = join(outDir, `morning-scan-${dateStr}.md`);
  const jsonPath = join(outDir, `morning-scan-${dateStr}.json`);

  await writeFile(reportPath, report);
  await writeFile(
    jsonPath,
    JSON.stringify(
      { date: dateStr, results, errors, summary: buildSummary(results, errors) },
      null,
      2,
    ),
  );

  console.log(`\n   Report: ${reportPath}`);
  console.log(`   Data:   ${jsonPath}\n`);

  const totalCriticals = results.reduce((sum, r) => sum + r.criticals, 0);
  process.exit(totalCriticals > 0 ? 1 : 0);
}

function buildSummary(results, errors) {
  return {
    total: results.length,
    gradeA: results.filter((r) => r.grade === 'A').length,
    gradeB: results.filter((r) => r.grade === 'B').length,
    gradeC: results.filter((r) => r.grade === 'C').length,
    gradeD: results.filter((r) => r.grade === 'D').length,
    gradeF: results.filter((r) => r.grade === 'F').length,
    totalCriticals: results.reduce((sum, r) => sum + r.criticals, 0),
    totalWarnings: results.reduce((sum, r) => sum + r.warnings, 0),
    skipped: errors.length,
  };
}

function generateReport(results, errors, totalRepos, durationSec) {
  const s = buildSummary(results, errors);
  const date = new Date().toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  let md = `# Vibe Audit Morning Scan\n`;
  md += `**${date}** | ${s.total} repos scanned | ${s.skipped} skipped | ${durationSec}s\n\n`;

  // Health dashboard
  md += `## Portfolio Health\n\n`;
  md += `| Grade | Count | |\n|-------|-------|-|\n`;
  md += `| A | ${s.gradeA} | Clean |\n`;
  md += `| B | ${s.gradeB} | Minor warnings |\n`;
  md += `| C | ${s.gradeC} | Multiple warnings |\n`;
  md += `| D | ${s.gradeD} | Many warnings |\n`;
  md += `| F | ${s.gradeF} | Critical findings |\n\n`;
  md += `**Total: ${s.totalCriticals} criticals, ${s.totalWarnings} warnings across ${s.total} repos**\n\n`;

  // Full results table
  if (results.length > 0) {
    md += `## All Results\n\n`;
    md += `| Repo | Grade | Critical | Warning | Info |\n`;
    md += `|------|-------|----------|---------|------|\n`;
    for (const r of results) {
      md += `| ${r.repo} | ${r.grade} | ${r.criticals} | ${r.warnings} | ${r.infos} |\n`;
    }
    md += `\n`;
  }

  // Critical findings detail
  const criticalRepos = results.filter((r) => r.criticals > 0);
  if (criticalRepos.length > 0) {
    md += `## Critical Findings (action required)\n\n`;
    for (const r of criticalRepos) {
      md += `### ${r.repo} — Grade ${r.grade}\n`;
      const crits = r.findings.filter((f) => f.severity === 'critical');
      for (const f of crits) {
        md += `- **${f.ruleId}**: ${f.message}`;
        if (f.file || f.path) md += ` (${f.file || f.path}:${f.line || '?'})`;
        md += `\n`;
      }
      md += `\n`;
    }
  }

  // Warning findings detail
  const warningRepos = results.filter((r) => r.warnings > 0 && r.criticals === 0);
  if (warningRepos.length > 0) {
    md += `## Warnings\n\n`;
    for (const r of warningRepos) {
      md += `### ${r.repo} — Grade ${r.grade}\n`;
      const warns = r.findings.filter((f) => f.severity === 'warning');
      for (const f of warns) {
        md += `- **${f.ruleId}**: ${f.message}`;
        if (f.file || f.path) md += ` (${f.file || f.path}:${f.line || '?'})`;
        md += `\n`;
      }
      md += `\n`;
    }
  }

  // Clean repos
  const cleanRepos = results.filter((r) => r.grade === 'A');
  if (cleanRepos.length > 0) {
    md += `## Clean Repos (Grade A)\n\n`;
    for (const r of cleanRepos) md += `- ${r.repo}\n`;
    md += `\n`;
  }

  // Skipped repos
  if (errors.length > 0) {
    md += `## Skipped Repos\n\n`;
    for (const e of errors) md += `- ${e.repo}: ${e.error}\n`;
    md += `\n`;
  }

  md += `---\n*Generated by Vibe Audit v1.1.0 — ${new Date().toISOString()}*\n`;
  return md;
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(2);
});
