import { writeFile } from 'node:fs/promises';
import { bold, cyan, dim } from '../colors.js';

function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const GRADE_COLORS = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444', '?': '#94a3b8' };

/**
 * Generate fleet HTML dashboard and write to file.
 * @param {import('../fleet.js').FleetResult} fleet
 * @param {string} outPath
 */
export async function reportFleetHTML(fleet, outPath) {
  const now = new Date().toISOString().split('T')[0];

  const overallGrade = fleet.totalCritical > 0 ? 'F'
    : fleet.totalWarning > 20 ? 'D'
    : fleet.totalWarning > 0 ? 'C'
    : fleet.totalInfo > 0 ? 'B'
    : 'A';

  const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of fleet.repos) {
    if (r.grade in grades) grades[r.grade]++;
  }

  const sorted = [...fleet.repos].sort((a, b) => {
    const go = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
    const gDiff = (go[a.grade] ?? 9) - (go[b.grade] ?? 9);
    if (gDiff !== 0) return gDiff;
    return b.critical - a.critical;
  });

  // Top rules across the fleet
  const ruleFreq = new Map();
  for (const r of fleet.repos) {
    for (const f of r.findings) {
      ruleFreq.set(f.ruleId, (ruleFreq.get(f.ruleId) || 0) + 1);
    }
  }
  const topRules = [...ruleFreq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15);

  // OWASP coverage across fleet
  const owaspCounts = new Map();
  for (const r of fleet.repos) {
    for (const f of r.findings) {
      const cat = f.owaspCategory || 'Other';
      owaspCounts.set(cat, (owaspCounts.get(cat) || 0) + 1);
    }
  }

  const owaspLabels = {
    'A01:2021': 'Broken Access Control',
    'A02:2021': 'Cryptographic Failures',
    'A03:2021': 'Injection',
    'A04:2021': 'Insecure Design',
    'A05:2021': 'Security Misconfiguration',
    'A06:2021': 'Vulnerable Components',
    'A07:2021': 'Auth Failures',
    'A08:2021': 'Data Integrity Failures',
    'A09:2021': 'Logging Failures',
    'A10:2021': 'SSRF',
  };

  const html = `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit Fleet Dashboard — ${now}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#ffffff;--bg2:#f8fafc;--bg3:#f1f5f9;--fg:#0f172a;--fg2:#475569;--fg3:#94a3b8;--border:#e2e8f0;--card:#ffffff;--shadow:0 1px 3px rgba(0,0,0,.1);--crit:#ef4444;--crit-bg:#fef2f2;--warn:#eab308;--warn-bg:#fefce8;--info:#06b6d4;--info-bg:#ecfeff;--ok:#22c55e;--ok-bg:#f0fdf4;--accent:#6366f1;--radius:12px}
[data-theme="dark"]{--bg:#0f172a;--bg2:#1e293b;--bg3:#334155;--fg:#f1f5f9;--fg2:#94a3b8;--fg3:#64748b;--border:#334155;--card:#1e293b;--shadow:0 1px 3px rgba(0,0,0,.4);--crit-bg:#450a0a;--warn-bg:#422006;--info-bg:#083344;--ok-bg:#052e16}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6}
a{color:var(--accent);text-decoration:none}
.container{max-width:1400px;margin:0 auto;padding:24px}
.header{display:flex;align-items:center;justify-content:space-between;padding:24px 0;border-bottom:1px solid var(--border);margin-bottom:32px}
.header h1{font-size:28px;display:flex;align-items:center;gap:12px}
.header-meta{display:flex;gap:16px;align-items:center}
.header-meta span{font-size:13px;color:var(--fg2)}
.theme-toggle{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:14px;color:var(--fg)}
.grade-lg{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:36px;font-weight:800;color:#fff;flex-shrink:0}
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:32px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}
.stat-card .label{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--fg3);margin-bottom:4px}
.stat-card .value{font-size:32px;font-weight:700}
.stat-card .sub{font-size:12px;color:var(--fg2);margin-top:4px}
.stat-card.crit .value{color:var(--crit)}
.stat-card.warn .value{color:var(--warn)}
.stat-card.info-c .value{color:var(--info)}
.stat-card.ok .value{color:var(--ok)}
.section{margin-bottom:40px}
.section-title{font-size:20px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px}
/* Grade distribution */
.grade-dist{display:flex;gap:12px;flex-wrap:wrap}
.grade-chip{display:flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:12px 20px;box-shadow:var(--shadow)}
.grade-chip .g{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:800;color:#fff}
.grade-chip .n{font-size:24px;font-weight:700}
.grade-chip .lbl{font-size:12px;color:var(--fg2)}
/* Repo table */
.repo-table{width:100%;border-collapse:separate;border-spacing:0;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
.repo-table th{text-align:left;padding:12px 16px;background:var(--bg2);font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg3);border-bottom:1px solid var(--border)}
.repo-table td{padding:12px 16px;border-bottom:1px solid var(--border);font-size:14px}
.repo-table tr:last-child td{border-bottom:none}
.repo-table tr:hover td{background:var(--bg2)}
.repo-table .repo-name{font-weight:600;font-family:monospace;font-size:13px}
.grade-sm{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:50%;font-size:13px;font-weight:800;color:#fff}
.sev-badge{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.sev-badge.c{background:var(--crit-bg);color:var(--crit)}
.sev-badge.w{background:var(--warn-bg);color:var(--warn)}
.sev-badge.i{background:var(--info-bg);color:var(--info)}
.sev-badge.clean{background:var(--ok-bg);color:var(--ok)}
/* Filter/search */
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:var(--card);cursor:pointer;font-size:13px;color:var(--fg2);transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
/* Top rules */
.rule-bar{display:flex;align-items:center;gap:12px;padding:8px 0}
.rule-bar .rule-name{font-family:monospace;font-size:13px;width:260px;flex-shrink:0}
.rule-bar .bar{flex:1;height:20px;background:var(--bg3);border-radius:4px;overflow:hidden}
.rule-bar .bar-fill{height:100%;border-radius:4px;transition:width .5s}
.rule-bar .count{font-size:13px;font-weight:600;width:40px;text-align:right;flex-shrink:0}
/* OWASP */
.owasp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.owasp-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow)}
.owasp-card .cat-id{font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.5px}
.owasp-card .cat-name{font-size:14px;font-weight:600;margin:4px 0}
.owasp-card .cat-count{font-size:24px;font-weight:700}
.owasp-bar{height:6px;background:var(--bg3);border-radius:3px;margin-top:8px;overflow:hidden}
.owasp-bar-fill{height:100%;border-radius:3px}
/* Expandable findings */
.repo-findings{display:none;padding:0 16px 16px}
.repo-findings.open{display:block}
.finding-row{padding:8px 12px;border-left:3px solid var(--border);margin:4px 0;font-size:13px;background:var(--bg2);border-radius:0 6px 6px 0}
.finding-row.crit{border-left-color:var(--crit)}
.finding-row.warn{border-left-color:var(--warn)}
.finding-row.info-f{border-left-color:var(--info)}
.toggle-link{cursor:pointer;color:var(--accent);font-size:12px;text-decoration:underline}
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{.theme-toggle,.filter-bar,.toggle-link{display:none!important}.repo-findings{display:block!important}body{background:#fff;color:#000}}
@media(max-width:768px){.dashboard{grid-template-columns:repeat(2,1fr)}.header{flex-direction:column;gap:16px;text-align:center}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade-lg" style="background:${GRADE_COLORS[overallGrade]}">${overallGrade}</div>
      <div>
        <h1>⚗️ Fleet Dashboard</h1>
        <div style="color:var(--fg2);font-size:14px">Vibe Audit across ${fleet.scannedRepos} repos &middot; ${now}</div>
      </div>
    </div>
    <div class="header-meta">
      <span>${fleet.scannedRepos} repos</span>
      <span>${fleet.totalFindings} findings</span>
      <span>${(fleet.durationMs / 1000).toFixed(1)}s</span>
      <button class="theme-toggle" onclick="toggleTheme()">🌓</button>
    </div>
  </div>

  <div class="dashboard">
    <div class="stat-card ok">
      <div class="label">Repos</div>
      <div class="value">${fleet.scannedRepos}</div>
      <div class="sub">${fleet.failedRepos > 0 ? fleet.failedRepos + ' failed' : 'all scanned'}</div>
    </div>
    <div class="stat-card crit">
      <div class="label">Critical</div>
      <div class="value">${fleet.totalCritical}</div>
      <div class="sub">across ${fleet.repos.filter(r => r.critical > 0).length} repos</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Warnings</div>
      <div class="value">${fleet.totalWarning}</div>
      <div class="sub">across ${fleet.repos.filter(r => r.warning > 0).length} repos</div>
    </div>
    <div class="stat-card info-c">
      <div class="label">Info</div>
      <div class="value">${fleet.totalInfo}</div>
      <div class="sub">${fleet.totalFindings} total</div>
    </div>
  </div>

  <!-- Grade Distribution -->
  <div class="section">
    <div class="section-title">📊 Grade Distribution</div>
    <div class="grade-dist">
      ${Object.entries(grades).filter(([, n]) => n > 0).map(([g, n]) => `
      <div class="grade-chip">
        <div class="g" style="background:${GRADE_COLORS[g]}">${g}</div>
        <div><div class="n">${n}</div><div class="lbl">repo${n !== 1 ? 's' : ''}</div></div>
      </div>`).join('')}
    </div>
  </div>

  <!-- Top Rules -->
  <div class="section">
    <div class="section-title">🔥 Most Common Issues</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)">
      ${topRules.map(([rule, count]) => {
        const pct = fleet.totalFindings > 0 ? Math.round((count / fleet.totalFindings) * 100) : 0;
        return `<div class="rule-bar">
          <div class="rule-name">${esc(rule)}</div>
          <div class="bar"><div class="bar-fill" style="width:${Math.max(pct, 2)}%;background:var(--accent)"></div></div>
          <div class="count">${count}</div>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>

  <!-- OWASP -->
  <div class="section">
    <div class="section-title">🛡️ OWASP Top 10 Across Fleet</div>
    <div class="owasp-grid">
      ${Object.entries(owaspLabels).map(([cat, label]) => {
        const count = owaspCounts.get(cat) || 0;
        const pct = fleet.totalFindings > 0 ? Math.round((count / fleet.totalFindings) * 100) : 0;
        const barColor = count === 0 ? 'var(--ok)' : count > 10 ? 'var(--crit)' : 'var(--warn)';
        return `<div class="owasp-card">
          <div class="cat-id">${cat}</div>
          <div class="cat-name">${label}</div>
          <div class="cat-count">${count}</div>
          <div class="owasp-bar"><div class="owasp-bar-fill" style="width:${Math.max(pct, 2)}%;background:${barColor}"></div></div>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>

  <!-- Repo Table -->
  <div class="section">
    <div class="section-title">📋 All Repos (${fleet.scannedRepos})</div>
    <div class="filter-bar">
      <input type="text" id="search" placeholder="Search repos..." oninput="filterRepos()">
      <button class="filter-btn active" data-grade="all" onclick="setGradeFilter('all',this)">All</button>
      ${Object.entries(grades).filter(([, n]) => n > 0).map(([g]) =>
        `<button class="filter-btn" data-grade="${g}" onclick="setGradeFilter('${g}',this)">${g} (${grades[g]})</button>`
      ).join('\n      ')}
    </div>
    <table class="repo-table">
      <thead>
        <tr>
          <th>Repo</th>
          <th>Grade</th>
          <th>Critical</th>
          <th>Warnings</th>
          <th>Info</th>
          <th>Files</th>
          <th>Time</th>
          <th></th>
        </tr>
      </thead>
      <tbody id="repo-tbody">
        ${sorted.map((r, i) => {
          if (r.error) {
            return `<tr class="repo-row" data-grade="?" data-search="${esc(r.repo).toLowerCase()}">
              <td class="repo-name">${esc(r.repo)}</td>
              <td><span class="grade-sm" style="background:#94a3b8">?</span></td>
              <td colspan="5" style="color:var(--fg3)">${esc(r.error.slice(0, 60))}</td>
              <td></td>
            </tr>`;
          }
          const hasFindings = r.findings.length > 0;
          return `<tr class="repo-row" data-grade="${r.grade}" data-search="${esc(r.repo).toLowerCase()}">
            <td class="repo-name">${esc(r.repo)}</td>
            <td><span class="grade-sm" style="background:${GRADE_COLORS[r.grade]}">${r.grade}</span></td>
            <td>${r.critical > 0 ? `<span class="sev-badge c">${r.critical}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
            <td>${r.warning > 0 ? `<span class="sev-badge w">${r.warning}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
            <td>${r.info > 0 ? `<span class="sev-badge i">${r.info}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
            <td>${r.filesScanned}</td>
            <td style="color:var(--fg3)">${(r.durationMs / 1000).toFixed(1)}s</td>
            <td>${hasFindings ? `<span class="toggle-link" onclick="toggleFindings(${i})">details</span>` : ''}</td>
          </tr>
          ${hasFindings ? `<tr class="repo-row" data-grade="${r.grade}" data-search="${esc(r.repo).toLowerCase()}"><td colspan="8"><div class="repo-findings" id="findings-${i}">
            ${r.findings.slice(0, 50).map(f => {
              const sevClass = f.severity === 'critical' ? 'crit' : f.severity === 'warning' ? 'warn' : 'info-f';
              return `<div class="finding-row ${sevClass}">
                <strong>${esc(f.message)}</strong>
                <span style="color:var(--fg3);font-family:monospace;font-size:12px"> ${esc(f.file)}${f.line ? ':' + f.line : ''}</span>
                ${f.cweId ? `<span style="color:var(--fg3);font-size:11px"> [${f.cweId}]</span>` : ''}
              </div>`;
            }).join('\n            ')}
            ${r.findings.length > 50 ? `<div style="padding:8px;color:var(--fg3);font-size:12px">...and ${r.findings.length - 50} more findings</div>` : ''}
          </div></td></tr>` : ''}`;
        }).join('\n        ')}
      </tbody>
    </table>
  </div>

  <div class="footer">
    ⚗️ Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a> fleet scanner &middot;
    ${fleet.scannedRepos} repos &middot; ${fleet.totalFindings} findings &middot; ${(fleet.durationMs / 1000).toFixed(1)}s &middot; ${now}
  </div>
</div>

<script>
function toggleTheme(){document.documentElement.dataset.theme=document.documentElement.dataset.theme==='dark'?'light':'dark'}
function toggleFindings(i){document.getElementById('findings-'+i)?.classList.toggle('open')}
let gradeFilter='all';
function setGradeFilter(g,btn){gradeFilter=g;document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');filterRepos()}
function filterRepos(){
  const q=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.repo-row').forEach(row=>{
    const matchG=gradeFilter==='all'||row.dataset.grade===gradeFilter;
    const matchQ=!q||row.dataset.search.includes(q);
    row.style.display=matchG&&matchQ?'':'none';
  });
}
</script>
</body>
</html>`;

  try {
    await writeFile(outPath, html);
    console.log('');
    console.log(bold('  ⚗️  VIBE AUDIT — Fleet HTML Dashboard Generated'));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log(`  ${bold('Report:')} ${cyan(outPath)}`);
    console.log(`  ${bold('Repos:')}  ${fleet.scannedRepos} scanned · ${fleet.totalFindings} findings`);
    console.log(dim('  Open in your browser to view the interactive fleet dashboard.'));
    console.log('');
  } catch {
    console.log(html);
  }
}
