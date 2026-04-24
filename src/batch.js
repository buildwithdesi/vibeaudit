import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { audit } from './index.js';
import { fetchRepoFiles } from './github.js';

/**
 * Load the repo list from a JSON file.
 * Supports both simple array of strings and full config objects.
 *
 * @param {string} configPath
 * @returns {Promise<{ defaults: object, repos: Array<{ owner: string, repo: string, branch?: string }> }>}
 */
export async function loadRepoList(configPath) {
  const raw = JSON.parse(await readFile(resolve(configPath), 'utf8'));

  const defaults = raw.defaults || {};
  const repos = (raw.repos || []).map((entry) => {
    if (typeof entry === 'string') {
      const [owner, repo] = entry.split('/');
      return { owner, repo, ...defaults };
    }
    return { ...defaults, ...entry };
  });

  return { defaults, repos };
}

/**
 * Scan a single GitHub repo and return a result summary.
 *
 * @param {{ owner: string, repo: string, branch?: string, strict?: boolean }} repoConfig
 * @returns {Promise<object>}
 */
async function scanOne(repoConfig) {
  const { owner, repo, branch = 'HEAD', strict = false } = repoConfig;
  const label = `${owner}/${repo}`;
  const start = performance.now();

  try {
    const fileSource = fetchRepoFiles(owner, repo, { branch });
    const targetDir = `github://${label}`;

    const { findings, exitCode } = await audit(targetDir, {
      format: 'json',
      strict,
      skipSca: true,
      fileSource,
    });

    const criticals = findings.filter((f) => f.severity === 'critical').length;
    const warnings = findings.filter((f) => f.severity === 'warning').length;
    const infos = findings.filter((f) => f.severity === 'info').length;
    const durationMs = Math.round(performance.now() - start);

    return {
      repo: label,
      status: 'ok',
      grade: gradeFromCounts(criticals, warnings, infos),
      criticals,
      warnings,
      infos,
      total: findings.length,
      exitCode,
      durationMs,
      topFindings: findings.slice(0, 5).map((f) => ({
        rule: f.ruleId,
        severity: f.severity,
        file: f.file,
        line: f.line,
        message: f.message,
      })),
    };
  } catch (err) {
    return {
      repo: label,
      status: 'error',
      error: err.message,
      durationMs: Math.round(performance.now() - start),
    };
  }
}

function gradeFromCounts(criticals, warnings, infos) {
  if (criticals > 0) return 'F';
  if (warnings > 5) return 'D';
  if (warnings > 0) return 'C';
  if (infos > 0) return 'B';
  return 'A';
}

/**
 * Run a batch scan across multiple repos with concurrency control.
 *
 * @param {Array} repos - Repo configs from loadRepoList
 * @param {{ concurrency?: number, onProgress?: (result: object, index: number, total: number) => void }} options
 * @returns {Promise<object[]>}
 */
export async function batchScan(repos, { concurrency = 5, onProgress } = {}) {
  const results = new Array(repos.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < repos.length) {
      const i = nextIndex++;
      // Suppress stdout from individual audit runs (they print JSON)
      const origLog = console.log;
      console.log = () => {};
      try {
        results[i] = await scanOne(repos[i]);
      } finally {
        console.log = origLog;
      }
      if (onProgress) onProgress(results[i], i, repos.length);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, repos.length) }, () => worker());
  await Promise.all(workers);

  return results;
}

/**
 * Generate a markdown summary from batch results.
 *
 * @param {object[]} results
 * @returns {string}
 */
export function batchMarkdownReport(results) {
  const ok = results.filter((r) => r.status === 'ok');
  const errors = results.filter((r) => r.status === 'error');
  const totalCrit = ok.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = ok.reduce((s, r) => s + r.warnings, 0);
  const totalInfo = ok.reduce((s, r) => s + r.infos, 0);
  const totalFindings = ok.reduce((s, r) => s + r.total, 0);
  const totalDuration = results.reduce((s, r) => s + (r.durationMs || 0), 0);

  const gradeEmoji = { A: '🟢', B: '🟢', C: '🟡', D: '🟠', F: '🔴' };

  const lines = [];
  const date = new Date().toISOString().split('T')[0];

  lines.push(`# ⚗️ Vibe Audit — Daily Scan Report`);
  lines.push('');
  lines.push(`**Date:** ${date}  `);
  lines.push(`**Repos scanned:** ${ok.length}/${results.length}  `);
  lines.push(`**Total findings:** ${totalFindings} (${totalCrit} critical, ${totalWarn} warnings, ${totalInfo} info)  `);
  lines.push(`**Duration:** ${(totalDuration / 1000).toFixed(1)}s  `);
  if (errors.length > 0) {
    lines.push(`**Errors:** ${errors.length} repos failed to scan  `);
  }
  lines.push('');

  // Repos needing attention (criticals first, then by total findings)
  const needsAttention = ok
    .filter((r) => r.criticals > 0 || r.warnings > 0)
    .sort((a, b) => b.criticals - a.criticals || b.warnings - a.warnings);

  if (needsAttention.length > 0) {
    lines.push('## 🚨 Repos Needing Attention');
    lines.push('');
    lines.push('| Repo | Grade | Critical | Warnings | Info | Top Issue |');
    lines.push('|------|-------|----------|----------|------|-----------|');
    for (const r of needsAttention) {
      const top = r.topFindings?.[0];
      const topStr = top ? `${top.rule}: ${top.message}` : '—';
      lines.push(`| \`${r.repo}\` | ${gradeEmoji[r.grade]} ${r.grade} | ${r.criticals} | ${r.warnings} | ${r.infos} | ${topStr} |`);
    }
    lines.push('');
  }

  // Full scoreboard
  lines.push('## 📊 Full Scoreboard');
  lines.push('');
  lines.push('| Repo | Grade | Findings | Time |');
  lines.push('|------|-------|----------|------|');
  for (const r of ok.sort((a, b) => a.repo.localeCompare(b.repo))) {
    const findStr = r.total === 0 ? '✅ clean' : `${r.criticals}C / ${r.warnings}W / ${r.infos}I`;
    lines.push(`| \`${r.repo}\` | ${gradeEmoji[r.grade]} ${r.grade} | ${findStr} | ${(r.durationMs / 1000).toFixed(1)}s |`);
  }
  lines.push('');

  // Errors
  if (errors.length > 0) {
    lines.push('## ❌ Scan Errors');
    lines.push('');
    for (const r of errors) {
      lines.push(`- \`${r.repo}\`: ${r.error}`);
    }
    lines.push('');
  }

  // Grade distribution
  const gradeDist = {};
  for (const r of ok) {
    gradeDist[r.grade] = (gradeDist[r.grade] || 0) + 1;
  }
  lines.push('## 📈 Grade Distribution');
  lines.push('');
  for (const g of ['A', 'B', 'C', 'D', 'F']) {
    const count = gradeDist[g] || 0;
    if (count > 0) {
      const bar = '█'.repeat(count);
      lines.push(`${gradeEmoji[g]} **${g}**: ${bar} ${count}`);
    }
  }
  lines.push('');

  lines.push('---');
  lines.push(`*Generated by [vibe-audit](https://github.com/jackdog668/vibeaudit) batch scanner*`);

  return lines.join('\n');
}

/**
 * Generate a JSON summary from batch results.
 *
 * @param {object[]} results
 * @returns {object}
 */
export function batchJSONReport(results) {
  const ok = results.filter((r) => r.status === 'ok');
  const errors = results.filter((r) => r.status === 'error');

  return {
    date: new Date().toISOString(),
    summary: {
      reposScanned: ok.length,
      reposFailed: errors.length,
      totalFindings: ok.reduce((s, r) => s + r.total, 0),
      totalCritical: ok.reduce((s, r) => s + r.criticals, 0),
      totalWarnings: ok.reduce((s, r) => s + r.warnings, 0),
      totalInfo: ok.reduce((s, r) => s + r.infos, 0),
    },
    results,
  };
}
