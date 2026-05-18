#!/usr/bin/env node

/**
 * Multi-repo scanner — runs Vibe Audit across many GitHub repos.
 *
 * Usage:
 *   GITHUB_TOKEN=ghp_xxx node bin/scan-repos.js [options]
 *
 * Options:
 *   --config <path>     Path to repos.json (default: ./repos.json)
 *   --format <format>   Summary format: terminal, json, markdown (default: markdown)
 *   --concurrency <n>   Parallel scans (default: 5)
 *   --strict            Fail on warnings too
 *   --changed-only      Only scan repos with commits in the last 24h
 *   --post-issue        Create/update a GitHub issue with results
 *   --issue-repo <r>    Repo for the summary issue (default: first repo in list)
 */

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { audit } from '../src/index.js';
import { fetchRepoFiles } from '../src/github.js';

const { values } = parseArgs({
  options: {
    config: { type: 'string', default: './repos.json' },
    format: { type: 'string', short: 'f', default: 'markdown' },
    concurrency: { type: 'string', default: '5' },
    strict: { type: 'boolean', short: 's', default: false },
    'changed-only': { type: 'boolean', default: false },
    'post-issue': { type: 'boolean', default: false },
    'issue-repo': { type: 'string' },
  },
});

const CONCURRENCY = Math.max(1, parseInt(values.concurrency, 10) || 5);

const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
if (!token) {
  console.error('Error: GITHUB_TOKEN or GH_TOKEN env var is required for multi-repo scanning.');
  process.exit(2);
}
const headers = {
  Accept: 'application/vnd.github.v3+json',
  Authorization: `Bearer ${token}`,
  'User-Agent': 'vibe-audit-scanner',
};

// ─── Load config ────────────────────────────────────────────────────────────

async function loadRepoConfig() {
  const configPath = resolve(values.config);
  const raw = await readFile(configPath, 'utf-8');
  return JSON.parse(raw);
}

// ─── Discover repos from orgs ───────────────────────────────────────────────

async function fetchOrgRepos(org) {
  const repos = [];
  let page = 1;
  while (true) {
    const url = `https://api.github.com/orgs/${org}/repos?per_page=100&page=${page}&type=sources&sort=pushed`;
    const res = await fetch(url, { headers });
    if (!res.ok) {
      const url2 = `https://api.github.com/users/${org}/repos?per_page=100&page=${page}&type=sources&sort=pushed`;
      const res2 = await fetch(url2, { headers });
      if (!res2.ok) break;
      const data = await res2.json();
      if (data.length === 0) break;
      repos.push(...data.map((r) => ({ name: r.full_name, default_branch: r.default_branch, pushed_at: r.pushed_at, archived: r.archived, fork: r.fork })));
      if (data.length < 100) break;
      page++;
      continue;
    }
    const data = await res.json();
    if (data.length === 0) break;
    repos.push(...data.map((r) => ({ name: r.full_name, default_branch: r.default_branch, pushed_at: r.pushed_at, archived: r.archived, fork: r.fork })));
    if (data.length < 100) break;
    page++;
  }
  return repos;
}

async function resolveRepos(config) {
  const skipSet = new Set((config.skip || []).map((s) => s.toLowerCase()));
  const explicitMap = new Map();

  for (const entry of config.repos || []) {
    const name = (typeof entry === 'string' ? entry : entry.name).toLowerCase();
    explicitMap.set(name, typeof entry === 'string' ? { name: entry } : entry);
  }

  const discovered = new Map();

  for (const org of config.orgs || []) {
    const orgRepos = await fetchOrgRepos(org);
    for (const r of orgRepos) {
      if (r.archived || r.fork) continue;
      const key = r.name.toLowerCase();
      if (skipSet.has(key)) continue;
      if (!discovered.has(key)) {
        discovered.set(key, {
          name: r.name,
          branch: r.default_branch || config.defaults?.branch || 'main',
          pushed_at: r.pushed_at,
          ...config.defaults,
        });
      }
    }
  }

  // Merge explicit entries (they override discovered).
  for (const [key, entry] of explicitMap) {
    if (skipSet.has(key)) continue;
    const existing = discovered.get(key) || {};
    discovered.set(key, {
      ...config.defaults,
      ...existing,
      ...entry,
      branch: entry.branch || existing.branch || config.defaults?.branch || 'main',
    });
  }

  let repos = Array.from(discovered.values());

  // Filter to recently changed repos if requested.
  if (values['changed-only']) {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    repos = repos.filter((r) => r.pushed_at && new Date(r.pushed_at).getTime() > cutoff);
  }

  return repos;
}

// ─── Scan a single repo ─────────────────────────────────────────────────────

async function scanRepo(repo) {
  const [owner, name] = repo.name.split('/');
  const branch = repo.branch || 'main';
  const label = `${owner}/${name}`;

  const start = performance.now();
  try {
    const fileSource = fetchRepoFiles(owner, name, { branch });
    const { findings } = await audit(`github://${label}`, {
      format: 'json',
      strict: repo.strict || values.strict,
      skipSca: true,
      quiet: true,
      fileSource,
      exclude: repo.exclude,
    });

    const durationMs = Math.round(performance.now() - start);
    const criticals = findings.filter((f) => f.severity === 'critical').length;
    const warnings = findings.filter((f) => f.severity === 'warning').length;
    const infos = findings.filter((f) => f.severity === 'info').length;

    return {
      repo: label,
      status: 'scanned',
      criticals,
      warnings,
      infos,
      total: findings.length,
      grade: criticals > 0 ? 'F' : warnings > 5 ? 'D' : warnings > 0 ? 'C' : infos > 0 ? 'B' : 'A',
      findings,
      durationMs,
    };
  } catch (err) {
    return {
      repo: label,
      status: 'error',
      error: err.message,
      criticals: 0,
      warnings: 0,
      infos: 0,
      total: 0,
      grade: '?',
      findings: [],
      durationMs: Math.round(performance.now() - start),
    };
  }
}

// ─── Run scans with concurrency control ─────────────────────────────────────

async function runScans(repos) {
  const results = [];
  const queue = [...repos];
  const active = new Set();

  return new Promise((done) => {
    function next() {
      while (active.size < CONCURRENCY && queue.length > 0) {
        const repo = queue.shift();
        const p = scanRepo(repo).then((result) => {
          results.push(result);
          active.delete(p);
          const icon = result.status === 'error' ? 'x' : result.criticals > 0 ? '!' : '.';
          process.stderr.write(icon);
          if (queue.length > 0 || active.size > 0) {
            next();
          } else {
            process.stderr.write('\n');
            done(results);
          }
        });
        active.add(p);
      }
    }
    next();
  });
}

// ─── Reporting ──────────────────────────────────────────────────────────────

function gradeEmoji(grade) {
  return { A: ':white_check_mark:', B: ':large_blue_circle:', C: ':warning:', D: ':orange_circle:', F: ':red_circle:', '?': ':grey_question:' }[grade] || '';
}

function formatMarkdown(results) {
  const scanned = results.filter((r) => r.status === 'scanned');
  const errors = results.filter((r) => r.status === 'error');
  const totalCriticals = scanned.reduce((s, r) => s + r.criticals, 0);
  const totalWarnings = scanned.reduce((s, r) => s + r.warnings, 0);
  const totalInfos = scanned.reduce((s, r) => s + r.infos, 0);
  const failing = scanned.filter((r) => r.grade === 'F' || r.grade === 'D');

  const date = new Date().toISOString().split('T')[0];

  const lines = [
    `# Vibe Audit Daily Scan — ${date}`,
    '',
    `| Metric | Count |`,
    `|--------|-------|`,
    `| Repos scanned | ${scanned.length} |`,
    `| Errors | ${errors.length} |`,
    `| Total criticals | ${totalCriticals} |`,
    `| Total warnings | ${totalWarnings} |`,
    `| Total info | ${totalInfos} |`,
    `| Repos failing (D/F) | ${failing.length} |`,
    '',
  ];

  if (failing.length > 0) {
    lines.push('## Repos Needing Attention', '');
    for (const r of failing.sort((a, b) => b.criticals - a.criticals)) {
      lines.push(`### ${gradeEmoji(r.grade)} \`${r.repo}\` — Grade ${r.grade}`);
      lines.push(`${r.criticals} critical, ${r.warnings} warnings, ${r.infos} info`);
      lines.push('');
      const topFindings = r.findings.filter((f) => f.severity === 'critical').slice(0, 5);
      if (topFindings.length > 0) {
        lines.push('| File | Issue | CWE |');
        lines.push('|------|-------|-----|');
        for (const f of topFindings) {
          const cwe = f.cweId || '';
          lines.push(`| \`${f.file}\`${f.line ? `:${f.line}` : ''} | ${f.message} | ${cwe} |`);
        }
        lines.push('');
      }
    }
  }

  lines.push('## All Repos', '');
  lines.push('| Grade | Repo | Critical | Warn | Info | Time |');
  lines.push('|-------|------|----------|------|------|------|');
  for (const r of scanned.sort((a, b) => b.criticals - a.criticals || b.warnings - a.warnings)) {
    lines.push(`| ${r.grade} | \`${r.repo}\` | ${r.criticals} | ${r.warnings} | ${r.infos} | ${r.durationMs}ms |`);
  }
  lines.push('');

  if (errors.length > 0) {
    lines.push('## Scan Errors', '');
    for (const r of errors) {
      lines.push(`- \`${r.repo}\`: ${r.error}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function formatJSON(results) {
  const scanned = results.filter((r) => r.status === 'scanned');
  return JSON.stringify({
    date: new Date().toISOString(),
    summary: {
      repos: scanned.length,
      errors: results.filter((r) => r.status === 'error').length,
      criticals: scanned.reduce((s, r) => s + r.criticals, 0),
      warnings: scanned.reduce((s, r) => s + r.warnings, 0),
      infos: scanned.reduce((s, r) => s + r.infos, 0),
    },
    results: results.map(({ findings, ...rest }) => ({
      ...rest,
      topFindings: findings.filter((f) => f.severity === 'critical').slice(0, 10),
    })),
  }, null, 2);
}

function formatTerminal(results) {
  const scanned = results.filter((r) => r.status === 'scanned');
  const errors = results.filter((r) => r.status === 'error');
  const totalCrit = scanned.reduce((s, r) => s + r.criticals, 0);
  const totalWarn = scanned.reduce((s, r) => s + r.warnings, 0);

  const lines = [
    '',
    '  VIBE AUDIT — Multi-Repo Scan',
    '  ─────────────────────────────────────',
    `  ${scanned.length} repos scanned, ${errors.length} errors`,
    `  ${totalCrit} criticals, ${totalWarn} warnings`,
    '',
  ];

  for (const r of scanned.sort((a, b) => b.criticals - a.criticals || b.warnings - a.warnings)) {
    const icon = r.grade === 'A' ? ' ' : r.grade === 'F' ? '!' : '*';
    lines.push(`  ${icon} [${r.grade}] ${r.repo.padEnd(40)} ${String(r.criticals).padStart(3)}C ${String(r.warnings).padStart(3)}W ${String(r.infos).padStart(3)}I  ${r.durationMs}ms`);
  }

  if (errors.length > 0) {
    lines.push('', '  Errors:');
    for (const r of errors) {
      lines.push(`    ${r.repo}: ${r.error}`);
    }
  }

  lines.push('');
  return lines.join('\n');
}

// ─── GitHub Issue ───────────────────────────────────────────────────────────

async function postOrUpdateIssue(issueRepo, markdown) {
  const [owner, repo] = issueRepo.split('/');
  const date = new Date().toISOString().split('T')[0];
  const title = `Vibe Audit Daily Scan — ${date}`;

  // Check for existing issue with same title.
  const searchUrl = `https://api.github.com/search/issues?q=${encodeURIComponent(`repo:${owner}/${repo} is:issue "${title}"`)}&per_page=1`;
  const searchRes = await fetch(searchUrl, { headers });
  const searchData = searchRes.ok ? await searchRes.json() : { items: [] };

  if (searchData.items?.length > 0) {
    // Update existing issue.
    const issueNumber = searchData.items[0].number;
    const updateUrl = `https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}`;
    await fetch(updateUrl, {
      method: 'PATCH',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: markdown }),
    });
    return `https://github.com/${owner}/${repo}/issues/${issueNumber}`;
  }

  // Create new issue.
  const createUrl = `https://api.github.com/repos/${owner}/${repo}/issues`;
  const res = await fetch(createUrl, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      title,
      body: markdown,
      labels: ['security', 'automated'],
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Failed to create issue: ${res.status} ${body}`);
  }

  const issue = await res.json();
  return issue.html_url;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const config = await loadRepoConfig();
  process.stderr.write(`Resolving repos from ${(config.orgs || []).length} orgs + ${(config.repos || []).length} explicit entries...\n`);

  const repos = await resolveRepos(config);
  process.stderr.write(`Scanning ${repos.length} repos (concurrency: ${CONCURRENCY})...\n`);

  const results = await runScans(repos);

  // Sort: worst grade first.
  results.sort((a, b) => {
    const order = { F: 0, D: 1, '?': 2, C: 3, B: 4, A: 5 };
    return (order[a.grade] ?? 6) - (order[b.grade] ?? 6);
  });

  // Output results.
  let output;
  switch (values.format) {
    case 'json':
      output = formatJSON(results);
      break;
    case 'terminal':
      output = formatTerminal(results);
      break;
    default:
      output = formatMarkdown(results);
  }

  console.log(output);

  // Write to file for GitHub Actions artifact.
  if (process.env.GITHUB_STEP_SUMMARY) {
    await writeFile(process.env.GITHUB_STEP_SUMMARY, output, { flag: 'a' });
  }

  // Post as GitHub issue if requested.
  if (values['post-issue']) {
    const markdown = values.format === 'markdown' ? output : formatMarkdown(results);
    const issueRepo = values['issue-repo'] || repos[0]?.name;
    if (issueRepo) {
      try {
        const url = await postOrUpdateIssue(issueRepo, markdown);
        process.stderr.write(`Issue posted: ${url}\n`);
      } catch (err) {
        process.stderr.write(`Failed to post issue: ${err.message}\n`);
      }
    }
  }

  // Exit code: 1 if any repo has criticals.
  const hasCriticals = results.some((r) => r.criticals > 0);
  process.exit(hasCriticals ? 1 : 0);
}

main().catch((err) => {
  console.error(`Fatal: ${err.message}`);
  process.exit(2);
});
