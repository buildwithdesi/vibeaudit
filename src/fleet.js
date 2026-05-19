import { fetchRepoFiles } from './github.js';
import { resolveRules } from './rules/index.js';
import { CWE_MAP } from './data/cwe-map.js';
import { bold, red, yellow, cyan, green, dim } from './colors.js';

/**
 * Fetch all repositories for a GitHub org or user.
 * @param {'org'|'user'} kind
 * @param {string} name
 * @param {{ token?: string, minStars?: number, includeArchived?: boolean, includeForks?: boolean }} opts
 * @returns {Promise<{ owner: string, repo: string, description: string, language: string, stars: number, archived: boolean, fork: boolean }[]>}
 */
export async function listRepos(kind, name, opts = {}) {
  const token = opts.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit-fleet',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const repos = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    const endpoint = kind === 'org'
      ? `https://api.github.com/orgs/${name}/repos?per_page=${perPage}&page=${page}&sort=updated`
      : `https://api.github.com/users/${name}/repos?per_page=${perPage}&page=${page}&sort=updated`;

    const res = await fetch(endpoint, { headers });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`GitHub API error listing repos (${res.status}): ${body}`);
    }

    const data = await res.json();
    if (data.length === 0) break;

    for (const r of data) {
      if (!opts.includeArchived && r.archived) continue;
      if (!opts.includeForks && r.fork) continue;
      if (opts.minStars && r.stargazers_count < opts.minStars) continue;

      repos.push({
        owner: r.owner.login,
        repo: r.name,
        description: r.description || '',
        language: r.language || 'unknown',
        stars: r.stargazers_count,
        archived: r.archived,
        fork: r.fork,
      });
    }

    if (data.length < perPage) break;
    page++;
  }

  return repos;
}

/**
 * Scan a single repo and return aggregated results (no console output).
 * @param {string} owner
 * @param {string} repo
 * @param {{ rules?: string[], exclude?: string[] }} opts
 * @returns {Promise<{ owner: string, repo: string, findings: object[], filesScanned: number, durationMs: number, error?: string }>}
 */
async function scanRepo(owner, repo, opts = {}) {
  const start = performance.now();

  try {
    const rules = resolveRules(opts.rules || [], opts.exclude || []);
    const fileSource = fetchRepoFiles(owner, repo);

    const findings = [];
    let filesScanned = 0;

    for await (const file of fileSource) {
      filesScanned++;
      for (const rule of rules) {
        try {
          const ruleFindings = rule.check(file);
          findings.push(...ruleFindings);
        } catch {
          // A rule should never crash the entire scan.
        }
      }
    }

    for (const f of findings) {
      const meta = CWE_MAP[f.ruleId];
      if (meta) {
        f.cweId = meta.cweId;
        f.cvssScore = meta.cvssScore;
        f.owaspCategory = meta.owaspCategory;
      }
    }

    const severityOrder = { critical: 0, warning: 1, info: 2 };
    findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    const durationMs = Math.round(performance.now() - start);
    return { owner, repo, findings, filesScanned, durationMs };
  } catch (err) {
    const durationMs = Math.round(performance.now() - start);
    return { owner, repo, findings: [], filesScanned: 0, durationMs, error: err.message };
  }
}

/**
 * Scan multiple repos with concurrency control.
 * @param {{ owner: string, repo: string }[]} repos
 * @param {{ concurrency?: number, rules?: string[], exclude?: string[], onProgress?: (done: number, total: number, repo: string) => void }} opts
 * @returns {Promise<object[]>}
 */
export async function fleetScan(repos, opts = {}) {
  const concurrency = opts.concurrency || 5;
  const results = [];
  let done = 0;

  const queue = [...repos];
  const workers = [];

  for (let i = 0; i < Math.min(concurrency, queue.length); i++) {
    workers.push((async () => {
      while (queue.length > 0) {
        const { owner, repo } = queue.shift();
        const result = await scanRepo(owner, repo, {
          rules: opts.rules,
          exclude: opts.exclude,
        });
        results.push(result);
        done++;
        if (opts.onProgress) opts.onProgress(done, repos.length, `${owner}/${repo}`);
      }
    })());
  }

  await Promise.all(workers);
  return results;
}

/**
 * Generate terminal fleet report.
 * @param {object[]} results
 * @param {{ durationMs: number }} meta
 */
export function reportFleetTerminal(results, meta) {
  const totalCriticals = results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'critical').length, 0);
  const totalWarnings = results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'warning').length, 0);
  const totalInfos = results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'info').length, 0);
  const totalFiles = results.reduce((s, r) => s + r.filesScanned, 0);
  const errors = results.filter(r => r.error);

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT — FLEET SCAN'));
  console.log(dim('  Morning security sweep across all repositories'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  const grade = totalCriticals > 0 ? 'F' : totalWarnings > 10 ? 'D' : totalWarnings > 0 ? 'C' : totalInfos > 0 ? 'B' : 'A';
  const gradeColor = { A: green, B: green, C: yellow, D: yellow, F: red }[grade];

  console.log(`  ${gradeColor(bold(`FLEET GRADE: ${grade}`))}  ${dim('│')}  ${bold(String(results.length))} repos scanned`);
  console.log(`  ${red(bold(`${totalCriticals}`))} ${dim('critical')}  ${dim('│')}  ${yellow(bold(`${totalWarnings}`))} ${dim('warnings')}  ${dim('│')}  ${cyan(bold(`${totalInfos}`))} ${dim('info')}  ${dim('│')}  ${dim(`${totalFiles} files · ${meta.durationMs}ms`)}`);
  if (errors.length > 0) {
    console.log(`  ${red(`${errors.length} repo(s) failed to scan`)}`);
  }
  console.log('');

  // Sort repos: most critical first, then most warnings
  const sorted = [...results].sort((a, b) => {
    const aCrit = a.findings.filter(f => f.severity === 'critical').length;
    const bCrit = b.findings.filter(f => f.severity === 'critical').length;
    if (aCrit !== bCrit) return bCrit - aCrit;
    const aWarn = a.findings.filter(f => f.severity === 'warning').length;
    const bWarn = b.findings.filter(f => f.severity === 'warning').length;
    return bWarn - aWarn;
  });

  // Repos with findings
  const withFindings = sorted.filter(r => r.findings.length > 0 || r.error);
  const clean = sorted.filter(r => r.findings.length === 0 && !r.error);

  if (withFindings.length > 0) {
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log(bold('  REPOS WITH FINDINGS'));
    console.log('');

    for (const r of withFindings) {
      if (r.error) {
        console.log(`  ${red('✗')}  ${bold(`${r.owner}/${r.repo}`)}  ${red(`Error: ${r.error}`)}`);
        continue;
      }

      const crit = r.findings.filter(f => f.severity === 'critical').length;
      const warn = r.findings.filter(f => f.severity === 'warning').length;
      const info = r.findings.filter(f => f.severity === 'info').length;

      const counts = [];
      if (crit > 0) counts.push(red(bold(`${crit}C`)));
      if (warn > 0) counts.push(yellow(`${warn}W`));
      if (info > 0) counts.push(cyan(`${info}I`));

      const icon = crit > 0 ? red('●') : warn > 0 ? yellow('▲') : cyan('ℹ');
      console.log(`  ${icon}  ${bold(`${r.owner}/${r.repo}`)}  ${counts.join(dim(' · '))}  ${dim(`${r.filesScanned} files · ${r.durationMs}ms`)}`);

      // Show top 3 criticals
      const topCriticals = r.findings.filter(f => f.severity === 'critical').slice(0, 3);
      for (const f of topCriticals) {
        const lineStr = f.line ? `:${f.line}` : '';
        console.log(`     ${red('→')} ${f.message} ${dim(`${f.file}${lineStr}`)}`);
      }
      if (crit > 3) console.log(dim(`     … and ${crit - 3} more criticals`));
    }
    console.log('');
  }

  if (clean.length > 0) {
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log(`  ${green(bold(`${clean.length} CLEAN REPOS`))} ${dim('— no findings')}`);
    const names = clean.map(r => `${r.owner}/${r.repo}`);
    // Print in compact columns
    for (let i = 0; i < names.length; i += 3) {
      const row = names.slice(i, i + 3).map(n => dim(`  ${n}`)).join('');
      console.log(row);
    }
    console.log('');
  }

  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  if (totalCriticals > 0) {
    console.log(red(bold('  ⛔ CRITICAL issues found. Run vibe-audit <repo> --fix for fix prompts.')));
  } else if (totalWarnings > 0) {
    console.log(yellow(bold('  ⚠️  Warnings found across the fleet. Review before deploying.')));
  } else {
    console.log(green(bold('  ✅ Fleet is clean. Ship it.')));
  }
  console.log('');
}

/**
 * Generate JSON fleet report.
 * @param {object[]} results
 * @param {{ durationMs: number }} meta
 * @returns {object}
 */
export function reportFleetJSON(results, meta) {
  return {
    summary: {
      reposScanned: results.length,
      totalFindings: results.reduce((s, r) => s + r.findings.length, 0),
      totalCritical: results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'critical').length, 0),
      totalWarning: results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'warning').length, 0),
      totalInfo: results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'info').length, 0),
      totalFiles: results.reduce((s, r) => s + r.filesScanned, 0),
      errors: results.filter(r => r.error).length,
      durationMs: meta.durationMs,
      timestamp: new Date().toISOString(),
    },
    repos: results.map(r => ({
      repo: `${r.owner}/${r.repo}`,
      critical: r.findings.filter(f => f.severity === 'critical').length,
      warning: r.findings.filter(f => f.severity === 'warning').length,
      info: r.findings.filter(f => f.severity === 'info').length,
      filesScanned: r.filesScanned,
      durationMs: r.durationMs,
      error: r.error || null,
      findings: r.findings,
    })),
  };
}

/**
 * Generate markdown fleet report (suitable for GitHub Issue body).
 * @param {object[]} results
 * @param {{ durationMs: number }} meta
 * @returns {string}
 */
export function reportFleetMarkdown(results, meta) {
  const totalCriticals = results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'critical').length, 0);
  const totalWarnings = results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'warning').length, 0);
  const totalInfos = results.reduce((s, r) => s + r.findings.filter(f => f.severity === 'info').length, 0);
  const totalFiles = results.reduce((s, r) => s + r.filesScanned, 0);
  const errors = results.filter(r => r.error);

  const grade = totalCriticals > 0 ? 'F' : totalWarnings > 10 ? 'D' : totalWarnings > 0 ? 'C' : totalInfos > 0 ? 'B' : 'A';
  const gradeEmoji = { A: '🟢', B: '🟢', C: '🟡', D: '🟡', F: '🔴' }[grade];

  const lines = [
    `# ⚗️ Vibe Audit — Fleet Scan`,
    '',
    `${gradeEmoji} **Fleet Grade: ${grade}** | ${new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}`,
    '',
    '| Metric | Value |',
    '|--------|-------|',
    `| Repos scanned | ${results.length} |`,
    `| Files scanned | ${totalFiles} |`,
    `| Critical | ${totalCriticals} |`,
    `| Warnings | ${totalWarnings} |`,
    `| Info | ${totalInfos} |`,
    `| Scan errors | ${errors.length} |`,
    `| Duration | ${(meta.durationMs / 1000).toFixed(1)}s |`,
    '',
  ];

  // Sort: worst repos first
  const sorted = [...results].sort((a, b) => {
    const aCrit = a.findings.filter(f => f.severity === 'critical').length;
    const bCrit = b.findings.filter(f => f.severity === 'critical').length;
    if (aCrit !== bCrit) return bCrit - aCrit;
    const aWarn = a.findings.filter(f => f.severity === 'warning').length;
    const bWarn = b.findings.filter(f => f.severity === 'warning').length;
    return bWarn - aWarn;
  });

  const withCriticals = sorted.filter(r => r.findings.some(f => f.severity === 'critical'));
  const withWarnings = sorted.filter(r => !r.findings.some(f => f.severity === 'critical') && r.findings.some(f => f.severity === 'warning'));
  const clean = sorted.filter(r => r.findings.length === 0 && !r.error);

  if (withCriticals.length > 0) {
    lines.push('## 🔴 Critical — Action Required', '');
    lines.push('| Repo | Critical | Warnings | Top Issue |');
    lines.push('|------|----------|----------|-----------|');
    for (const r of withCriticals) {
      const crit = r.findings.filter(f => f.severity === 'critical').length;
      const warn = r.findings.filter(f => f.severity === 'warning').length;
      const top = r.findings[0];
      const topMsg = top ? top.message : '';
      lines.push(`| \`${r.owner}/${r.repo}\` | ${crit} | ${warn} | ${topMsg} |`);
    }
    lines.push('');

    for (const r of withCriticals) {
      const critFindings = r.findings.filter(f => f.severity === 'critical');
      lines.push(`<details><summary><b>${r.owner}/${r.repo}</b> — ${critFindings.length} critical findings</summary>`, '');
      for (const f of critFindings) {
        const lineStr = f.line ? `:${f.line}` : '';
        const cweStr = f.cweId ? ` \`${f.cweId}\`` : '';
        lines.push(`- **${f.message}**${cweStr} — \`${f.file}${lineStr}\``);
        if (f.evidence) lines.push(`  - Evidence: \`${f.evidence}\``);
        lines.push(`  - Fix: ${f.fix}`);
      }
      lines.push('', '</details>', '');
    }
  }

  if (withWarnings.length > 0) {
    lines.push('## 🟡 Warnings', '');
    lines.push('| Repo | Warnings | Info | Top Issue |');
    lines.push('|------|----------|------|-----------|');
    for (const r of withWarnings) {
      const warn = r.findings.filter(f => f.severity === 'warning').length;
      const info = r.findings.filter(f => f.severity === 'info').length;
      const top = r.findings[0];
      lines.push(`| \`${r.owner}/${r.repo}\` | ${warn} | ${info} | ${top ? top.message : ''} |`);
    }
    lines.push('');
  }

  if (errors.length > 0) {
    lines.push('## ⚠️ Scan Errors', '');
    for (const r of errors) {
      lines.push(`- \`${r.owner}/${r.repo}\`: ${r.error}`);
    }
    lines.push('');
  }

  if (clean.length > 0) {
    lines.push(`## ✅ Clean Repos (${clean.length})`, '');
    lines.push(clean.map(r => `\`${r.owner}/${r.repo}\``).join(', '));
    lines.push('');
  }

  lines.push('---', `*Generated by [Vibe Audit](https://github.com/jackdog668/vibeaudit) fleet scanner*`);

  return lines.join('\n');
}
