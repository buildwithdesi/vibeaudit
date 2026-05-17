import { readFile } from 'node:fs/promises';
import { audit } from './index.js';
import { fetchOrgRepos, fetchRepoFiles, parseGitHubTarget } from './github.js';
import { bold, cyan, dim, gray, green, red, yellow } from './colors.js';
import { generateBatchHTML } from './reporters/batch-html.js';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * @typedef {Object} BatchConfig
 * @property {string[]} [repos] - List of "owner/repo" or GitHub URLs
 * @property {string} [org] - GitHub org/user to scan all repos for
 * @property {number} [concurrency] - Max parallel scans (default 3)
 * @property {string[]} [rules] - Only run these rules
 * @property {string[]} [exclude] - Exclude these rules
 * @property {boolean} [strict] - Strict mode
 * @property {string} [format] - Output format: terminal, json, html (default: terminal)
 */

/**
 * @typedef {Object} RepoResult
 * @property {string} owner
 * @property {string} repo
 * @property {string} fullName
 * @property {string} grade
 * @property {import('./rules/types.js').Finding[]} findings
 * @property {{ filesScanned: number, rulesRun: number, durationMs: number }} meta
 * @property {number} criticals
 * @property {number} warnings
 * @property {number} infos
 * @property {string|null} error
 */

function computeGrade(criticals, warnings, infos) {
  if (criticals > 0) return 'F';
  if (warnings > 5) return 'D';
  if (warnings > 0) return 'C';
  if (infos > 0) return 'B';
  return 'A';
}

/**
 * Load batch config from a JSON file.
 * @param {string} configPath
 * @returns {Promise<BatchConfig>}
 */
export async function loadBatchConfig(configPath) {
  const raw = await readFile(configPath, 'utf-8');
  return JSON.parse(raw);
}

/**
 * Resolve the full list of repos to scan.
 * @param {BatchConfig} config
 * @returns {Promise<Array<{ owner: string, repo: string }>>}
 */
async function resolveRepos(config) {
  const repos = [];

  if (config.org) {
    const orgRepos = await fetchOrgRepos(config.org);
    repos.push(...orgRepos.map(r => ({ owner: r.owner, repo: r.repo })));
  }

  if (config.repos?.length) {
    for (const entry of config.repos) {
      const parsed = parseGitHubTarget(entry);
      if (parsed) {
        repos.push(parsed);
      }
    }
  }

  const seen = new Set();
  return repos.filter(r => {
    const key = `${r.owner}/${r.repo}`.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Scan a single repo and return results.
 * @param {{ owner: string, repo: string }} repo
 * @param {BatchConfig} config
 * @returns {Promise<RepoResult>}
 */
async function scanRepo({ owner, repo }, config) {
  const fullName = `${owner}/${repo}`;
  const start = performance.now();

  try {
    const fileSource = fetchRepoFiles(owner, repo);
    const { findings, meta } = await audit(`github://${fullName}`, {
      fileSource,
      skipSca: true,
      quiet: true,
      rules: config.rules,
      exclude: config.exclude,
      strict: config.strict,
    });

    const criticals = findings.filter(f => f.severity === 'critical').length;
    const warnings = findings.filter(f => f.severity === 'warning').length;
    const infos = findings.filter(f => f.severity === 'info').length;

    return {
      owner,
      repo,
      fullName,
      grade: computeGrade(criticals, warnings, infos),
      findings,
      meta,
      criticals,
      warnings,
      infos,
      error: null,
    };
  } catch (err) {
    return {
      owner,
      repo,
      fullName,
      grade: '?',
      findings: [],
      meta: { filesScanned: 0, rulesRun: 0, durationMs: Math.round(performance.now() - start) },
      criticals: 0,
      warnings: 0,
      infos: 0,
      error: err.message,
    };
  }
}

/**
 * Run a batch audit across multiple repos.
 *
 * @param {BatchConfig} config
 * @returns {Promise<{ results: RepoResult[], summary: object }>}
 */
export async function batchAudit(config) {
  const concurrency = config.concurrency || 3;
  const repos = await resolveRepos(config);

  if (repos.length === 0) {
    throw new Error('No repositories to scan. Provide --org <name> or a batch config with repos.');
  }

  const format = config.format || 'terminal';
  const totalStart = performance.now();

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — Batch Scan'));
  console.log(dim(`  Scanning ${repos.length} repositories (concurrency: ${concurrency})`));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  const results = [];
  let completed = 0;

  for (let i = 0; i < repos.length; i += concurrency) {
    const chunk = repos.slice(i, i + concurrency);
    const chunkResults = await Promise.allSettled(
      chunk.map(repo => scanRepo(repo, config))
    );

    for (const result of chunkResults) {
      completed++;
      const r = result.status === 'fulfilled' ? result.value : {
        owner: '?', repo: '?', fullName: '?/?', grade: '?',
        findings: [], meta: { filesScanned: 0, rulesRun: 0, durationMs: 0 },
        criticals: 0, warnings: 0, infos: 0, error: result.reason?.message || 'Unknown error',
      };

      results.push(r);

      const gradeColors = { A: green, B: green, C: yellow, D: yellow, F: red };
      const gradeColor = gradeColors[r.grade] || gray;
      const progress = dim(`[${completed}/${repos.length}]`);
      const errorStr = r.error ? red(` ERROR: ${r.error.slice(0, 60)}`) : '';

      const counts = [];
      if (r.criticals > 0) counts.push(red(`${r.criticals}C`));
      if (r.warnings > 0) counts.push(yellow(`${r.warnings}W`));
      if (r.infos > 0) counts.push(cyan(`${r.infos}I`));
      const countStr = counts.length > 0 ? counts.join(dim('/')) : green('clean');

      console.log(`  ${progress} ${gradeColor(bold(r.grade))} ${cyan(r.fullName)} ${dim('—')} ${countStr} ${dim(`(${r.meta.filesScanned} files, ${r.meta.durationMs}ms)`)}${errorStr}`);
    }
  }

  const totalDuration = Math.round(performance.now() - totalStart);

  const summary = buildSummary(results, totalDuration);

  console.log('');
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  reportBatchTerminal(results, summary);

  if (format === 'html' || format === 'all') {
    const html = generateBatchHTML(results, summary);
    const outPath = join(process.cwd(), 'vibe-audit-batch-report.html');
    await writeFile(outPath, html);
    console.log(`  ${bold('HTML Report:')} ${cyan(outPath)}`);
    console.log('');
  }

  if (format === 'json') {
    console.log(JSON.stringify({ summary, results: results.map(r => ({
      repo: r.fullName, grade: r.grade, criticals: r.criticals,
      warnings: r.warnings, infos: r.infos, filesScanned: r.meta.filesScanned,
      durationMs: r.meta.durationMs, error: r.error,
      findings: r.findings,
    })) }, null, 2));
  }

  const exitCode = summary.totalCriticals > 0 ? 1
    : config.strict && summary.totalWarnings > 0 ? 1
    : 0;

  return { results, summary, exitCode };
}

function buildSummary(results, totalDuration) {
  const grades = { A: 0, B: 0, C: 0, D: 0, F: 0, '?': 0 };
  let totalCriticals = 0;
  let totalWarnings = 0;
  let totalInfos = 0;
  let totalFiles = 0;
  let totalFindings = 0;
  let errors = 0;

  const ruleHits = new Map();

  for (const r of results) {
    grades[r.grade] = (grades[r.grade] || 0) + 1;
    totalCriticals += r.criticals;
    totalWarnings += r.warnings;
    totalInfos += r.infos;
    totalFiles += r.meta.filesScanned;
    totalFindings += r.findings.length;
    if (r.error) errors++;

    for (const f of r.findings) {
      ruleHits.set(f.ruleId, (ruleHits.get(f.ruleId) || 0) + 1);
    }
  }

  const topRules = [...ruleHits.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  return {
    reposScanned: results.length,
    totalFiles,
    totalFindings,
    totalCriticals,
    totalWarnings,
    totalInfos,
    errors,
    grades,
    topRules,
    totalDuration,
  };
}

function reportBatchTerminal(results, summary) {
  const { grades, totalCriticals, totalWarnings, totalInfos, totalFindings, totalFiles } = summary;

  console.log('');
  console.log(bold('  SUMMARY'));
  console.log('');

  const gradeBar = [
    grades.A > 0 ? green(`${grades.A}A`) : null,
    grades.B > 0 ? green(`${grades.B}B`) : null,
    grades.C > 0 ? yellow(`${grades.C}C`) : null,
    grades.D > 0 ? yellow(`${grades.D}D`) : null,
    grades.F > 0 ? red(`${grades.F}F`) : null,
    grades['?'] > 0 ? gray(`${grades['?']}?`) : null,
  ].filter(Boolean).join(dim(' · '));

  console.log(`  ${bold('Repos:')}    ${summary.reposScanned} scanned ${dim('—')} ${gradeBar}`);
  console.log(`  ${bold('Findings:')} ${totalFindings} total ${dim('—')} ${red(`${totalCriticals} critical`)} ${dim('·')} ${yellow(`${totalWarnings} warnings`)} ${dim('·')} ${cyan(`${totalInfos} info`)}`);
  console.log(`  ${bold('Files:')}    ${totalFiles} scanned across all repos`);
  console.log(`  ${bold('Duration:')} ${(summary.totalDuration / 1000).toFixed(1)}s total`);

  if (summary.errors > 0) {
    console.log(`  ${bold('Errors:')}   ${red(`${summary.errors} repos failed`)}`);
  }

  if (summary.topRules.length > 0) {
    console.log('');
    console.log(dim('  Top issues across all repos:'));
    for (const [ruleId, count] of summary.topRules.slice(0, 5)) {
      console.log(`    ${yellow(bold(String(count).padStart(3)))} ${dim('×')} ${ruleId}`);
    }
  }

  console.log('');

  if (totalCriticals > 0) {
    const critRepos = results.filter(r => r.criticals > 0).map(r => r.fullName);
    console.log(red(bold('  ⛔ CRITICAL issues in:')));
    for (const name of critRepos) {
      console.log(red(`     ${name}`));
    }
    console.log('');
  }
}
