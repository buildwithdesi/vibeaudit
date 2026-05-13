#!/usr/bin/env node

import { audit } from '../src/index.js';
import { cloneRepo, cleanupClone } from '../src/github.js';
import { writeFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const OWNER = process.env.GITHUB_OWNER || 'jackdog668';
const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
const CONCURRENCY = parseInt(process.env.SCAN_CONCURRENCY || '3', 10);
const CONFIG_PATH = process.env.SCAN_CONFIG || '';

async function listReposViaAPI(owner) {
  const repos = [];
  let page = 1;
  const headers = { Accept: 'application/vnd.github.v3+json', 'User-Agent': 'vibe-audit' };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;

  while (true) {
    const url = `https://api.github.com/users/${owner}/repos?per_page=100&page=${page}&sort=updated&type=owner`;
    const res = await fetch(url, { headers });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API ${res.status}: ${body}`);
    }
    const data = await res.json();
    if (data.length === 0) break;
    repos.push(...data);
    page++;
  }
  return repos;
}

async function loadRepoList() {
  if (CONFIG_PATH) {
    const raw = await readFile(resolve(CONFIG_PATH), 'utf8');
    const config = JSON.parse(raw);
    return (config.repos || []).map((name) => ({
      name,
      full_name: `${OWNER}/${name}`,
      html_url: `https://github.com/${OWNER}/${name}`,
      fork: false,
      archived: false,
      size: 1,
    }));
  }

  const repos = await listReposViaAPI(OWNER);
  return repos.filter((r) => !r.fork && !r.archived && r.size > 0);
}

async function scanRepo(repo) {
  const label = `${OWNER}/${repo.name}`;
  let clonePath;
  try {
    clonePath = await cloneRepo(OWNER, repo.name);
    const { findings } = await audit(clonePath, { quiet: true, skipSca: true });

    const critical = findings.filter((f) => f.severity === 'critical').length;
    const warning = findings.filter((f) => f.severity === 'warning').length;
    const info = findings.filter((f) => f.severity === 'info').length;

    return {
      repo: repo.name,
      fullName: label,
      url: repo.html_url,
      findings,
      critical,
      warning,
      info,
      error: null,
    };
  } catch (err) {
    return {
      repo: repo.name,
      fullName: label,
      url: repo.html_url,
      findings: [],
      critical: 0,
      warning: 0,
      info: 0,
      error: err.message,
    };
  } finally {
    if (clonePath) await cleanupClone(clonePath);
  }
}

async function runBatch(repos, concurrency) {
  const results = [];
  for (let i = 0; i < repos.length; i += concurrency) {
    const batch = repos.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(scanRepo));
    for (const r of batchResults) {
      results.push(r);
      const status = r.error
        ? `ERROR — ${r.error}`
        : `${r.findings.length} findings (${r.critical}C ${r.warning}W ${r.info}I)`;
      console.error(`  [${results.length}/${repos.length}] ${r.fullName}: ${status}`);
    }
  }
  return results;
}

function topRules(findings, n = 3) {
  const counts = new Map();
  for (const f of findings) {
    counts.set(f.ruleId, (counts.get(f.ruleId) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([id]) => id);
}

function buildMarkdownReport(results, durationSec) {
  const date = new Date().toISOString().slice(0, 10);
  const scanned = results.filter((r) => !r.error);
  const errors = results.filter((r) => r.error);
  const totalCritical = results.reduce((s, r) => s + r.critical, 0);
  const totalWarning = results.reduce((s, r) => s + r.warning, 0);
  const totalInfo = results.reduce((s, r) => s + r.info, 0);
  const totalFindings = totalCritical + totalWarning + totalInfo;

  const critRepos = scanned.filter((r) => r.critical > 0).sort((a, b) => b.critical - a.critical);
  const warnRepos = scanned.filter((r) => r.critical === 0 && r.warning > 0).sort((a, b) => b.warning - a.warning);
  const cleanRepos = scanned.filter((r) => r.critical === 0 && r.warning === 0 && r.info === 0);
  const infoOnly = scanned.filter((r) => r.critical === 0 && r.warning === 0 && r.info > 0);

  const grade =
    totalCritical > 0 ? 'F' : totalWarning > 10 ? 'D' : totalWarning > 0 ? 'C' : totalInfo > 0 ? 'B' : 'A';

  const lines = [];
  lines.push(`# Vibe Audit — Morning Scan`);
  lines.push('');
  lines.push(`**Date:** ${date}`);
  lines.push(`**Grade:** ${grade}`);
  lines.push(`**Repos scanned:** ${scanned.length} / ${results.length}`);
  lines.push(`**Total findings:** ${totalFindings} (${totalCritical} critical, ${totalWarning} warnings, ${totalInfo} info)`);
  lines.push(`**Duration:** ${Math.round(durationSec)}s`);
  lines.push('');

  if (critRepos.length > 0) {
    lines.push(`## Repos with Critical Issues (${critRepos.length})`);
    lines.push('');
    lines.push('| Repo | Critical | Warning | Info | Top Issues |');
    lines.push('|------|----------|---------|------|------------|');
    for (const r of critRepos) {
      const top = topRules(r.findings).map((id) => `\`${id}\``).join(', ');
      lines.push(`| [${r.repo}](${r.url}) | ${r.critical} | ${r.warning} | ${r.info} | ${top} |`);
    }
    lines.push('');
  }

  if (warnRepos.length > 0) {
    lines.push(`## Repos with Warnings (${warnRepos.length})`);
    lines.push('');
    lines.push('| Repo | Warning | Info | Top Issues |');
    lines.push('|------|---------|------|------------|');
    for (const r of warnRepos) {
      const top = topRules(r.findings).map((id) => `\`${id}\``).join(', ');
      lines.push(`| [${r.repo}](${r.url}) | ${r.warning} | ${r.info} | ${top} |`);
    }
    lines.push('');
  }

  if (infoOnly.length > 0) {
    lines.push(`<details><summary>Info-only repos (${infoOnly.length})</summary>`);
    lines.push('');
    for (const r of infoOnly) {
      lines.push(`- [${r.repo}](${r.url}) — ${r.info} info`);
    }
    lines.push('');
    lines.push('</details>');
    lines.push('');
  }

  if (cleanRepos.length > 0) {
    lines.push(`<details><summary>Clean repos (${cleanRepos.length})</summary>`);
    lines.push('');
    lines.push(cleanRepos.map((r) => `[${r.repo}](${r.url})`).join(', '));
    lines.push('');
    lines.push('</details>');
    lines.push('');
  }

  if (errors.length > 0) {
    lines.push(`<details><summary>Scan errors (${errors.length})</summary>`);
    lines.push('');
    for (const r of errors) {
      lines.push(`- **${r.repo}**: ${r.error}`);
    }
    lines.push('');
    lines.push('</details>');
    lines.push('');
  }

  const allFindings = results.flatMap((r) => r.findings);
  const globalTop = topRules(allFindings, 5);
  if (globalTop.length > 0) {
    lines.push('## Most Common Issues');
    lines.push('');
    const counts = new Map();
    for (const f of allFindings) counts.set(f.ruleId, (counts.get(f.ruleId) || 0) + 1);
    for (const id of globalTop) {
      lines.push(`- \`${id}\` — ${counts.get(id)} findings`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push(`*Generated by [Vibe Audit](https://github.com/jackdog668/vibeaudit) v1.1.0*`);

  return lines.join('\n');
}

function buildJSONReport(results) {
  const scanned = results.filter((r) => !r.error);
  return {
    date: new Date().toISOString(),
    owner: OWNER,
    summary: {
      reposTotal: results.length,
      reposScanned: scanned.length,
      reposWithErrors: results.length - scanned.length,
      totalFindings: results.reduce((s, r) => s + r.findings.length, 0),
      totalCritical: results.reduce((s, r) => s + r.critical, 0),
      totalWarning: results.reduce((s, r) => s + r.warning, 0),
      totalInfo: results.reduce((s, r) => s + r.info, 0),
    },
    repos: results.map((r) => ({
      repo: r.repo,
      url: r.url,
      critical: r.critical,
      warning: r.warning,
      info: r.info,
      error: r.error,
      findings: r.findings,
    })),
  };
}

async function main() {
  const start = performance.now();
  console.error(`\nVibe Audit — Morning Scan for ${OWNER}`);
  console.error('─'.repeat(50));

  const repos = await loadRepoList();
  console.error(`Found ${repos.length} repos to scan (concurrency: ${CONCURRENCY})\n`);

  const results = await runBatch(repos, CONCURRENCY);

  const durationSec = (performance.now() - start) / 1000;
  console.error(`\n${'─'.repeat(50)}`);
  console.error(`Done in ${Math.round(durationSec)}s`);

  const md = buildMarkdownReport(results, durationSec);
  const json = buildJSONReport(results);

  await writeFile('morning-scan-report.md', md);
  await writeFile('morning-scan-report.json', JSON.stringify(json, null, 2));

  // Print markdown to stdout for GitHub Actions step output capture.
  console.log(md);

  const totalCritical = results.reduce((s, r) => s + r.critical, 0);
  process.exit(totalCritical > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(`Fatal: ${err.message}`);
  process.exit(2);
});
