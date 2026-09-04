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
 *   --owner <name>      GitHub owner for --discover (default: buildwithdesi)
 *   --concurrency <N>   Parallel scans (default: 3)
 *   --format <fmt>      Report format (default: markdown)
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
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
const owner = flag('owner', 'buildwithdesi');
const concurrency = parseInt(flag('concurrency', '3'), 10);

/**
 * Repos that hold this scanner's own output rather than an application.
 *
 * The report archive stores every past scan as JSON, and those files quote the
 * findings they recorded — `NEXT_PUBLIC_...`, service-role keys, `allow read,
 * write: if true`. Scanning it re-flags that quoted evidence as though it were
 * live source, so the archive reports thousands of criticals that describe
 * nothing deployable. On the 2026-08-03 run it produced 2,677 of 3,244 total
 * criticals (82%) — entirely from `scans/morning-scan-*.json` — which buried
 * the ~567 real findings across the rest of the portfolio.
 *
 * Excluded by repo name rather than by ignoring a `scans/` path globally: this
 * repo contains no application code at all, so skipping it cannot hide a real
 * finding, whereas a blanket `scans` ignore could mask one in a normal repo.
 */
export const SCAN_OUTPUT_REPOS = new Set(['vibeaudit-reports']);

/** Drop report-archive repos from a scan list. Matches on the repo name, any owner. */
export function excludeScanOutputRepos(repos) {
  return repos.filter((full) => !SCAN_OUTPUT_REPOS.has(String(full).split('/').pop()));
}

/**
 * Decide whether a discovery result is safe to persist over the saved list.
 * A discovery that lost more than a quarter of the portfolio is treated as a
 * partial result (bad token scope, truncated pagination) rather than a real
 * shrink, because persisting it would silently narrow every future scan.
 */
export function shouldAcceptDiscovery(discoveredCount, savedCount, force = false) {
  if (force) return true;
  if (!savedCount) return true;
  return discoveredCount >= savedCount * 0.75;
}

export async function discoverRepos(owner, { fetchImpl = fetch } = {}) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = { Accept: 'application/vnd.github.v3+json', 'User-Agent': 'vibe-audit' };
  if (token) headers.Authorization = `Bearer ${token}`;

  // /users/{owner}/repos only ever returns PUBLIC repos, even with a token that
  // can see private ones. Scanning your own account through it silently drops
  // every private repo — the exact repos most likely to hold live secrets. When
  // the token belongs to the owner we're discovering, use /user/repos instead,
  // which includes private repos the token can read.
  let listUrl = `https://api.github.com/users/${owner}/repos`;
  let scope = 'public only';
  if (token) {
    const meRes = await fetchImpl('https://api.github.com/user', { headers });
    if (meRes.ok) {
      const me = await meRes.json();
      if (me.login && me.login.toLowerCase() === owner.toLowerCase()) {
        listUrl = 'https://api.github.com/user/repos?affiliation=owner';
        scope = 'public + private';
      }
    }
  }

  const repos = [];
  let page = 1;
  while (true) {
    const sep = listUrl.includes('?') ? '&' : '?';
    const url = `${listUrl}${sep}per_page=100&page=${page}&sort=updated&direction=desc`;
    const res = await fetchImpl(url, { headers }); // vibe-audit-ignore perf-no-await-parallel  (pagination is inherently sequential — need page N to know if N+1 exists)
    if (!res.ok) throw new Error(`Failed to list repos: ${res.status}`);
    const batch = await res.json(); // vibe-audit-ignore perf-no-await-parallel  (pagination response, inherently sequential)
    if (batch.length === 0) break;
    for (const r of batch) {
      if (!r.archived && !r.fork) repos.push(r.full_name);
    }
    page++;
  }
  return { repos, scope };
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Classify a failed repo scan.
 *
 * GitHub answers 403 for two very different situations: a genuine rate limit
 * (retryable — backing off helps) and "this token cannot see this repo"
 * (permanent for this run — backing off just burns wall-clock). Collapsing both
 * into "Rate limited" made a fully blocked scan look like a throttled one, so an
 * access outage rendered as an empty, clean-looking dashboard.
 *
 * @param {Error} err
 * @returns {{ label: string, kind: string, rateLimited: boolean }}
 */
export function classifyScanError(err) {
  const msg = err?.message || String(err);
  // makeApiError tags status and rateLimited structurally on the error object.
  // Trust those when present; parsing the message is only a fallback for errors
  // that did not come from the GitHub client.
  const status = String(
    err?.status || /GitHub API error \((\d+)\)/.exec(msg)?.[1] || /\b(401|403|404|409|429)\b/.exec(msg)?.[1] || ''
  );
  const body = msg.toLowerCase();

  if (status === '403' || status === '429') {
    // Real throttling says so in the body; anything else 403 is an access denial.
    // Distinguishing them matters: a rate limit is worth backing off for, a
    // forbidden repo is not, and treating one as the other either wastes the
    // run or hides a token-scope problem.
    const rateLimited =
      typeof err?.rateLimited === 'boolean'
        ? err.rateLimited
        : body.includes('rate limit') || body.includes('abuse detection');
    if (rateLimited) {
      return { label: 'Rate limited', kind: 'rate-limited', rateLimited: true };
    }
    return { label: 'Access denied (check token scope)', kind: 'access-denied', rateLimited: false };
  }
  if (status === '401') return { label: 'Auth required', kind: 'auth-required', rateLimited: false };
  if (status === '404') return { label: 'Not found / empty', kind: 'not-found', rateLimited: false };
  if (status === '409') return { label: 'Empty repo', kind: 'empty', rateLimited: false };
  return { label: msg.slice(0, 120), kind: 'error', rateLimited: false };
}

/** Repos we could not even look at — these mean missing coverage, not a clean result. */
const BLOCKED_KINDS = new Set(['access-denied', 'auth-required', 'rate-limited']);

async function scanRepo(name) {
  const parsed = parseGitHubTarget(name);
  if (!parsed) return { error: { repo: name, error: 'Invalid repo format', kind: 'error' } };

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
    const { label, kind, rateLimited } = classifyScanError(err);
    return { error: { repo: name, error: label, kind }, rateLimited };
  }
}

async function main() {
  let repos;
  if (discover) {
    console.log(`\n   Discovering repos for ${owner}...`);
    const discovered = await discoverRepos(owner);
    repos = excludeScanOutputRepos(discovered.repos);
    console.log(`   Found ${repos.length} repos (${discovered.scope}).`);

    // Discovery feeds the saved list, so a partial result (bad token scope,
    // truncated pagination) would quietly shrink every future scan. Refuse to
    // shrink the list by more than a quarter without --force-discover.
    const previous = await readFile(reposFile, 'utf8')
      .then((raw) => excludeScanOutputRepos(JSON.parse(raw)))
      .catch(() => []);
    if (!shouldAcceptDiscovery(repos.length, previous.length, hasFlag('force-discover'))) {
      console.error(
        `\n   Refusing to overwrite ${reposFile}: discovery returned ${repos.length} repos ` +
          `but the saved list has ${previous.length}.\n` +
          `   This usually means the token can't see private repos. Scanning the saved list instead.\n` +
          `   Re-run with --force-discover if the shrink is intentional.\n`,
      );
      repos = previous;
    } else {
      await writeFile(reposFile, JSON.stringify(repos, null, 2));
    }
  } else {
    const raw = await readFile(reposFile, 'utf8');
    repos = excludeScanOutputRepos(JSON.parse(raw));
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
  const blocked = errors.filter((e) => BLOCKED_KINDS.has(e.kind));

  // A scan that reached nothing is an outage, not a clean bill of health. Exit
  // distinctly (2) so a scheduler can tell "no findings" from "no coverage".
  if (results.length === 0 && repos.length > 0) {
    console.error(`   SCAN DID NOT RUN — 0 of ${repos.length} repos scanned.`);
    if (blocked.length > 0) {
      console.error(`   ${blocked.length} unreachable (GitHub access / token scope).`);
    }
    console.error(`   This is NOT an all-clear. Fix access and re-run.\n`);
    process.exit(2);
  }

  if (blocked.length > 0) {
    console.error(
      `   WARNING: coverage incomplete — ${blocked.length} of ${repos.length} repos unreachable.\n`,
    );
  }

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
    blocked: errors.filter((e) => BLOCKED_KINDS.has(e.kind)).length,
    attempted: results.length + errors.length,
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

  // An empty dashboard reads as "all clear" at a glance. Say plainly when the
  // grades below are empty because nothing was audited.
  if (s.total === 0 && totalRepos > 0) {
    md += `> ⛔ **SCAN DID NOT RUN — 0 of ${totalRepos} repos scanned. This is not an all-clear.**\n`;
    if (s.blocked > 0) {
      md += `> ${s.blocked} repos were unreachable (GitHub access / token scope).\n`;
    }
    md += `> The grades below are empty because nothing was audited, not because nothing was found.\n\n`;
  } else if (s.blocked > 0) {
    md += `> ⚠️ **Partial coverage — ${s.blocked} of ${totalRepos} repos unreachable (GitHub access).**\n\n`;
  }

  // Health dashboard
  md += `## Portfolio Health\n\n`;
  md += `| Grade | Count | |\n|-------|-------|-|\n`;
  md += `| A | ${s.gradeA} | No checked findings |\n`;
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

  // Repos with no findings from the checks that completed
  const cleanRepos = results.filter((r) => r.grade === 'A');
  if (cleanRepos.length > 0) {
    md += `## Repos With No Checked Findings (Grade A)\n\n`;
    for (const r of cleanRepos) md += `- ${r.repo}\n`;
    md += `\n> Grade A is not proof that a repository is safe. Manual review still applies.\n\n`;
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

// Only scan when invoked as a CLI. Tests import this module for the discovery
// and classification helpers and must not kick off a portfolio-wide scan on
// import. Compare as URLs, not paths, so Windows drive-letter casing does not
// make an invoked script look like an import.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error('Fatal error:', err);
    process.exit(2);
  });
}
