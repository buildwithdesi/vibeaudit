import { audit } from './index.js';
import { fetchRepoFiles } from './github.js';

/**
 * Scan a single GitHub repo and return a summary object.
 * @param {string} repoSlug - "owner/repo"
 * @param {object} options - Scan options (strict, skipSca, etc.)
 * @returns {Promise<object>}
 */
async function scanRepo(repoSlug, options = {}) {
  const [owner, repo] = repoSlug.split('/');
  const label = `${owner}/${repo}`;
  const start = performance.now();

  try {
    const fileSource = fetchRepoFiles(owner, repo);

    // Suppress stdout from audit()'s internal report() call.
    const origLog = console.log;
    console.log = () => {};
    let result;
    try {
      result = await audit(`github://${label}`, {
        ...options,
        format: 'json',
        skipSca: true,
        fileSource,
      });
    } finally {
      console.log = origLog;
    }
    const { findings } = result;

    const durationMs = Math.round(performance.now() - start);
    const critical = findings.filter((f) => f.severity === 'critical').length;
    const warning = findings.filter((f) => f.severity === 'warning').length;
    const info = findings.filter((f) => f.severity === 'info').length;
    const grade = critical > 0 ? 'F' : warning > 5 ? 'D' : warning > 0 ? 'C' : info > 0 ? 'B' : 'A';

    return {
      repo: label,
      status: 'scanned',
      grade,
      critical,
      warning,
      info,
      total: findings.length,
      durationMs,
      findings,
    };
  } catch (err) {
    return {
      repo: label,
      status: 'error',
      error: err.message,
      grade: '?',
      critical: 0,
      warning: 0,
      info: 0,
      total: 0,
      durationMs: Math.round(performance.now() - start),
      findings: [],
    };
  }
}

/**
 * Sleep for ms milliseconds.
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Run batch audit across multiple repos with concurrency control.
 *
 * @param {string[]} repos - List of "owner/repo" slugs
 * @param {object} [options]
 * @param {number} [options.concurrency=3] - Max parallel scans
 * @param {number} [options.delayMs=1000] - Delay between scan starts (rate-limit protection)
 * @param {boolean} [options.strict]
 * @param {(result: object) => void} [options.onResult] - Callback per completed repo
 * @returns {Promise<object[]>} Array of per-repo results
 */
export async function batchAudit(repos, options = {}) {
  const { concurrency = 3, delayMs = 1000, onResult, ...scanOptions } = options;
  const results = [];
  let index = 0;

  async function worker() {
    while (index < repos.length) {
      const i = index++;
      const repo = repos[i];

      if (i > 0) await sleep(delayMs);

      const result = await scanRepo(repo, scanOptions);
      results.push(result);

      if (onResult) onResult(result);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, repos.length) }, () => worker());
  await Promise.all(workers);

  results.sort((a, b) => {
    const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
    return (gradeOrder[a.grade] ?? 99) - (gradeOrder[b.grade] ?? 99);
  });

  return results;
}

/**
 * Build a markdown summary from batch results.
 * @param {object[]} results
 * @returns {string}
 */
export function batchMarkdownSummary(results) {
  const scanned = results.filter((r) => r.status === 'scanned');
  const errors = results.filter((r) => r.status === 'error');
  const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
  const totalWarning = scanned.reduce((s, r) => s + r.warning, 0);
  const totalInfo = scanned.reduce((s, r) => s + r.info, 0);
  const totalFindings = scanned.reduce((s, r) => s + r.total, 0);

  const gradeEmoji = { A: '🟢', B: '🟢', C: '🟡', D: '🟠', F: '🔴', '?': '⚪' };

  const lines = [];
  lines.push('# ⚗️ Vibe Audit — Morning Batch Report');
  lines.push('');
  lines.push(`**${scanned.length}** repos scanned · **${totalFindings}** findings · **${totalCritical}** critical · **${totalWarning}** warnings · **${totalInfo}** info`);
  if (errors.length > 0) {
    lines.push(`**${errors.length}** repos failed to scan`);
  }
  lines.push('');

  lines.push('## Scorecard');
  lines.push('');
  lines.push('| Grade | Repo | Critical | Warnings | Info | Total |');
  lines.push('|-------|------|----------|----------|------|-------|');

  for (const r of results) {
    const emoji = gradeEmoji[r.grade] || '⚪';
    if (r.status === 'error') {
      lines.push(`| ${emoji} ? | \`${r.repo}\` | — | — | — | ❌ ${r.error} |`);
    } else {
      lines.push(`| ${emoji} ${r.grade} | \`${r.repo}\` | ${r.critical || '—'} | ${r.warning || '—'} | ${r.info || '—'} | ${r.total} |`);
    }
  }
  lines.push('');

  const failing = scanned.filter((r) => r.grade === 'F');
  if (failing.length > 0) {
    lines.push('## 🔴 Repos with Critical Issues');
    lines.push('');
    for (const r of failing) {
      lines.push(`### \`${r.repo}\` — ${r.critical} critical`);
      lines.push('');
      const critFindings = r.findings.filter((f) => f.severity === 'critical');
      for (const f of critFindings.slice(0, 10)) {
        const cweStr = f.cweId ? ` \`${f.cweId}\`` : '';
        lines.push(`- **${f.message}** — \`${f.file}\`${f.line ? `:${f.line}` : ''}${cweStr}`);
      }
      if (critFindings.length > 10) {
        lines.push(`- _...and ${critFindings.length - 10} more critical findings_`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

/**
 * Build a JSON summary from batch results (without per-finding details).
 * @param {object[]} results
 * @returns {object}
 */
export function batchJsonSummary(results) {
  const scanned = results.filter((r) => r.status === 'scanned');
  return {
    timestamp: new Date().toISOString(),
    reposScanned: scanned.length,
    reposErrored: results.length - scanned.length,
    totalFindings: scanned.reduce((s, r) => s + r.total, 0),
    totalCritical: scanned.reduce((s, r) => s + r.critical, 0),
    totalWarning: scanned.reduce((s, r) => s + r.warning, 0),
    totalInfo: scanned.reduce((s, r) => s + r.info, 0),
    repos: results.map(({ findings: _findings, ...rest }) => rest),
  };
}
