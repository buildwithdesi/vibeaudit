#!/usr/bin/env node

/**
 * Clone-based morning scan — works in environments where the GitHub API
 * is proxy-scoped to a single repo. Clones each repo locally instead.
 */

import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { audit } from '../src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

const argv = process.argv.slice(2);
function flag(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
}

const reposFile = flag('repos', join(ROOT, 'scripts', 'repos.json'));
const topN = parseInt(flag('top', '0'), 10);
const concurrency = parseInt(flag('concurrency', '3'), 10);

const BASELINE_IGNORE = ['reports', 'tests', 'fixtures', '__tests__', '__fixtures__'];

function cloneRepo(fullName) {
  const url = `https://github.com/${fullName}.git`;
  const tmp = join('/tmp', `va-${fullName.replace('/', '-')}-${Date.now()}`);
  return new Promise((resolve, reject) => {
    execFile('git', ['clone', '--depth', '1', '--single-branch', url, tmp],
      { timeout: 60_000 },
      (err) => {
        if (err) reject(new Error(err.stderr || err.message));
        else resolve(tmp);
      });
  });
}

async function cleanupClone(dir) {
  try { await rm(dir, { recursive: true, force: true }); } catch {}
}

async function scanRepo(name) {
  let clonePath;
  try {
    clonePath = await cloneRepo(name);
    const { findings } = await audit(clonePath, {
      format: 'json',
      skipSca: true,
      extraIgnore: BASELINE_IGNORE,
    });

    const criticals = findings.filter((f) => f.severity === 'critical').length;
    const warnings = findings.filter((f) => f.severity === 'warning').length;
    const infos = findings.filter((f) => f.severity === 'info').length;
    const grade =
      criticals > 0 ? 'F' : warnings > 3 ? 'D' : warnings > 1 ? 'C' : warnings > 0 ? 'B' : 'A';

    // Rewrite paths from temp dir to repo-relative
    for (const f of findings) {
      if (f.file && f.file.startsWith(clonePath)) {
        f.file = f.file.slice(clonePath.length + 1);
      }
      if (f.path && f.path.startsWith(clonePath)) {
        f.path = f.path.slice(clonePath.length + 1);
      }
    }

    return { result: { repo: name, grade, criticals, warnings, infos, total: findings.length, findings } };
  } catch (err) {
    const msg = err.message || String(err);
    const short = msg.includes('not found') || msg.includes('not exist')
      ? 'Not found / empty'
      : msg.includes('Authentication') || msg.includes('could not read Password')
        ? 'Auth required (private)'
        : msg.includes('empty')
          ? 'Empty repo'
          : msg.slice(0, 80);
    return { error: { repo: name, error: short } };
  } finally {
    if (clonePath) await cleanupClone(clonePath);
  }
}

async function main() {
  const raw = await readFile(reposFile, 'utf8');
  let repos = JSON.parse(raw);
  if (topN > 0) repos = repos.slice(0, topN);

  const results = [];
  const errors = [];
  const startTime = Date.now();

  const date = new Date().toLocaleDateString('en-US', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
  });
  console.log(`\n  Vibe Audit Morning Scan — ${date}`);
  console.log(`   Scanning ${repos.length} repositories (clone-based, concurrency: ${concurrency})...\n`);

  let i = 0;
  while (i < repos.length) {
    const batch = repos.slice(i, i + concurrency);
    const promises = batch.map(async (name) => {
      const out = await scanRepo(name);
      if (out.result) {
        const r = out.result;
        const icon = r.criticals > 0 ? 'X' : r.warnings > 0 ? '!' : '+';
        console.log(`   ${name} ... [${icon}] Grade ${r.grade} (${r.criticals}C/${r.warnings}W/${r.infos}I)`);
        results.push(r);
      } else {
        console.log(`   ${name} ... [-] Skipped (${out.error.error})`);
        errors.push(out.error);
      }
    });

    await Promise.all(promises);
    i += concurrency;
  }

  const durationSec = ((Date.now() - startTime) / 1000).toFixed(1);

  const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4 };
  results.sort((a, b) => gradeOrder[a.grade] - gradeOrder[b.grade]);

  const report = generateReport(results, errors, repos.length, durationSec);
  const outDir = join(ROOT, 'reports');
  await mkdir(outDir, { recursive: true });

  const dateStr = new Date().toISOString().split('T')[0];
  const reportPath = join(outDir, `morning-scan-${dateStr}.md`);
  const jsonPath = join(outDir, `morning-scan-${dateStr}.json`);

  await writeFile(reportPath, report);
  await writeFile(jsonPath, JSON.stringify(
    { date: dateStr, results, errors, summary: buildSummary(results, errors) }, null, 2));

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
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
  });

  let md = `# Vibe Audit Morning Scan\n`;
  md += `**${date}** | ${s.total} repos scanned | ${s.skipped} skipped | ${durationSec}s\n\n`;

  md += `## Portfolio Health\n\n`;
  md += `| Grade | Count | |\n|-------|-------|-|\n`;
  md += `| A | ${s.gradeA} | Clean |\n`;
  md += `| B | ${s.gradeB} | Minor warnings |\n`;
  md += `| C | ${s.gradeC} | Multiple warnings |\n`;
  md += `| D | ${s.gradeD} | Many warnings |\n`;
  md += `| F | ${s.gradeF} | Critical findings |\n\n`;
  md += `**Total: ${s.totalCriticals} criticals, ${s.totalWarnings} warnings across ${s.total} repos**\n\n`;

  if (results.length > 0) {
    md += `## All Results\n\n`;
    md += `| Repo | Grade | Critical | Warning | Info |\n`;
    md += `|------|-------|----------|---------|------|\n`;
    for (const r of results) {
      md += `| ${r.repo} | ${r.grade} | ${r.criticals} | ${r.warnings} | ${r.infos} |\n`;
    }
    md += `\n`;
  }

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

  const cleanRepos = results.filter((r) => r.grade === 'A');
  if (cleanRepos.length > 0) {
    md += `## Clean Repos (Grade A)\n\n`;
    for (const r of cleanRepos) md += `- ${r.repo}\n`;
    md += `\n`;
  }

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
