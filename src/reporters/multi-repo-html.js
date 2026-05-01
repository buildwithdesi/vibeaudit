/**
 * Multi-Repo HTML Dashboard — aggregated security overview across an org.
 *
 * Generates a self-contained HTML file with:
 *   - Org-wide grade and severity breakdown
 *   - Repo leaderboard sorted by risk (worst first)
 *   - Per-repo expandable detail cards
 *   - Top recurring vulnerabilities across the org
 *   - OWASP coverage heatmap
 *   - Dark mode, search/filter, print-friendly
 *   - Zero external dependencies
 */

/**
 * @param {import('../types.js').MultiRepoResult} result
 * @param {{ orgName?: string }} options
 * @returns {string} Complete HTML document
 */
export function generateMultiRepoHTML(result, { orgName = 'Organization' } = {}) {
  const now = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const gradeColor = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444', '?': '#94a3b8' }[result.orgGrade] || '#94a3b8';

  // Sort repos: worst grade first, then by critical count
  const gradeOrder = { F: 0, D: 1, C: 2, B: 3, A: 4, '?': 5 };
  const sortedRepos = [...result.repos].sort((a, b) => {
    const gDiff = (gradeOrder[a.grade] ?? 5) - (gradeOrder[b.grade] ?? 5);
    if (gDiff !== 0) return gDiff;
    return b.criticals - a.criticals;
  });

  // Top recurring rules across all repos
  const ruleCount = new Map();
  for (const repo of result.repos) {
    if (repo.status !== 'success') continue;
    for (const f of repo.findings) {
      const key = f.ruleId;
      if (!ruleCount.has(key)) ruleCount.set(key, { ruleId: key, message: f.message, severity: f.severity, cweId: f.cweId, count: 0, repos: new Set() });
      const entry = ruleCount.get(key);
      entry.count++;
      entry.repos.add(repo.fullName);
    }
  }
  const topRules = [...ruleCount.values()]
    .sort((a, b) => b.repos.size - a.repos.size || b.count - a.count)
    .slice(0, 20);

  // OWASP heatmap
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
  const owaspCounts = {};
  for (const f of result.allFindings) {
    const cat = f.owaspCategory || 'Unknown';
    owaspCounts[cat] = (owaspCounts[cat] || 0) + 1;
  }

  // Grade distribution
  const gradeDist = { A: 0, B: 0, C: 0, D: 0, F: 0, '?': 0 };
  for (const r of result.repos) {
    gradeDist[r.grade] = (gradeDist[r.grade] || 0) + 1;
  }

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit — ${esc(orgName)} Multi-Repo Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#ffffff;--bg2:#f8fafc;--bg3:#f1f5f9;--fg:#0f172a;--fg2:#475569;--fg3:#94a3b8;--border:#e2e8f0;--card:#ffffff;--shadow:0 1px 3px rgba(0,0,0,.1);--crit:#ef4444;--crit-bg:#fef2f2;--warn:#eab308;--warn-bg:#fefce8;--info:#06b6d4;--info-bg:#ecfeff;--ok:#22c55e;--ok-bg:#f0fdf4;--accent:#6366f1;--radius:12px}
[data-theme="dark"]{--bg:#0f172a;--bg2:#1e293b;--bg3:#334155;--fg:#f1f5f9;--fg2:#94a3b8;--fg3:#64748b;--border:#334155;--card:#1e293b;--shadow:0 1px 3px rgba(0,0,0,.4);--crit-bg:#450a0a;--warn-bg:#422006;--info-bg:#083344;--ok-bg:#052e16}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.container{max-width:1400px;margin:0 auto;padding:24px}
.header{display:flex;align-items:center;justify-content:space-between;padding:24px 0;border-bottom:1px solid var(--border);margin-bottom:32px}
.header h1{font-size:28px;display:flex;align-items:center;gap:12px}
.header-meta{display:flex;gap:16px;align-items:center}
.header-meta span{font-size:13px;color:var(--fg2)}
.theme-toggle{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:14px;color:var(--fg)}
.grade-lg{width:90px;height:90px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:42px;font-weight:800;color:#fff;flex-shrink:0}
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:32px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}
.stat-card .label{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--fg3);margin-bottom:4px}
.stat-card .value{font-size:32px;font-weight:700}
.stat-card .sub{font-size:12px;color:var(--fg2);margin-top:4px}
.stat-card.crit .value{color:var(--crit)}.stat-card.warn .value{color:var(--warn)}.stat-card.info .value{color:var(--info)}.stat-card.ok .value{color:var(--ok)}
.section{margin-bottom:40px}
.section-title{font-size:20px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px}
/* Grade distribution bar */
.grade-bar{display:flex;height:40px;border-radius:8px;overflow:hidden;margin-bottom:8px}
.grade-bar-seg{display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;color:#fff;min-width:20px;transition:flex .3s}
.grade-legend{display:flex;gap:16px;font-size:13px;color:var(--fg2)}
.grade-legend span{display:flex;align-items:center;gap:4px}
.grade-dot{width:12px;height:12px;border-radius:3px;display:inline-block}
/* Repo table */
.repo-table{width:100%;border-collapse:separate;border-spacing:0;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
.repo-table th{text-align:left;padding:12px 16px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg3);background:var(--bg2);border-bottom:1px solid var(--border);cursor:pointer;user-select:none}
.repo-table th:hover{color:var(--fg)}
.repo-table td{padding:12px 16px;border-bottom:1px solid var(--border);font-size:14px}
.repo-table tr:last-child td{border-bottom:none}
.repo-table tr:hover td{background:var(--bg2)}
.grade-badge{display:inline-flex;width:32px;height:32px;border-radius:50%;align-items:center;justify-content:center;font-weight:800;font-size:14px;color:#fff}
.sev-pill{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}
.sev-pill.c{background:var(--crit-bg);color:var(--crit)}.sev-pill.w{background:var(--warn-bg);color:var(--warn)}.sev-pill.i{background:var(--info-bg);color:var(--info)}
.sev-pill.err{background:var(--bg3);color:var(--fg3)}
/* Top rules */
.rule-row{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border)}
.rule-row:last-child{border-bottom:none}
.rule-rank{width:28px;height:28px;border-radius:50%;background:var(--bg3);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:var(--fg2);flex-shrink:0}
.rule-id{font-family:monospace;font-size:13px;font-weight:600;min-width:200px}
.rule-repos{font-size:12px;color:var(--fg3)}
.rule-count{font-size:18px;font-weight:700;margin-left:auto;flex-shrink:0}
/* OWASP */
.owasp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.owasp-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow)}
.owasp-card .cat-id{font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.5px}
.owasp-card .cat-name{font-size:14px;font-weight:600;margin:4px 0}
.owasp-card .cat-count{font-size:24px;font-weight:700}
.owasp-bar{height:6px;background:var(--bg3);border-radius:3px;margin-top:8px;overflow:hidden}
.owasp-bar-fill{height:100%;border-radius:3px}
/* Expandable repo detail */
.repo-detail{display:none;padding:16px 20px;background:var(--bg2)}
.repo-detail.open{display:block}
.repo-detail-findings{max-height:400px;overflow-y:auto}
.finding-mini{padding:8px 12px;border-bottom:1px solid var(--border);font-size:13px;display:flex;gap:8px;align-items:baseline}
.finding-mini:last-child{border-bottom:none}
.finding-mini .sev-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:5px}
.finding-mini .sev-dot.critical{background:var(--crit)}.finding-mini .sev-dot.warning{background:var(--warn)}.finding-mini .sev-dot.info{background:var(--info)}
.finding-mini .f-file{font-family:monospace;color:var(--fg3);font-size:12px}
/* Search */
.search-bar{margin-bottom:16px}
.search-bar input{width:100%;max-width:400px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{
  .theme-toggle,.search-bar{display:none!important}
  .repo-detail{display:block!important}
  body{background:#fff;color:#000}
}
@media(max-width:768px){
  .dashboard{grid-template-columns:repeat(2,1fr)}
  .header{flex-direction:column;gap:16px;text-align:center}
  .repo-table{font-size:12px}
  .repo-table td,.repo-table th{padding:8px}
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade-lg" style="background:${gradeColor}">${result.orgGrade}</div>
      <div>
        <h1>Vibe Audit — ${esc(orgName)}</h1>
        <div style="color:var(--fg2);font-size:14px">Multi-repo security dashboard &middot; ${esc(now)}</div>
      </div>
    </div>
    <div class="header-meta">
      <span>${result.totalRepos} repos</span>
      <span>${result.totalFindings} findings</span>
      <span>${formatDuration(result.durationMs)}</span>
      <button class="theme-toggle" onclick="toggleTheme()">Theme</button>
    </div>
  </div>

  <div class="dashboard">
    <div class="stat-card">
      <div class="label">Repos Scanned</div>
      <div class="value">${result.succeeded}</div>
      <div class="sub">${result.failed > 0 ? result.failed + ' failed' : 'all successful'}</div>
    </div>
    <div class="stat-card crit">
      <div class="label">Criticals</div>
      <div class="value">${result.totalCriticals}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Warnings</div>
      <div class="value">${result.totalWarnings}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="stat-card info">
      <div class="label">Info</div>
      <div class="value">${result.totalInfos}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="stat-card ok">
      <div class="label">Clean Repos</div>
      <div class="value">${result.repos.filter(r => r.status === 'success' && r.total === 0).length}</div>
      <div class="sub">grade A, zero findings</div>
    </div>
    <div class="stat-card">
      <div class="label">Total Findings</div>
      <div class="value">${result.totalFindings}</div>
      <div class="sub">${formatDuration(result.durationMs)} total scan time</div>
    </div>
  </div>

  <!-- Grade Distribution -->
  <div class="section">
    <div class="section-title">Grade Distribution</div>
    ${renderGradeBar(gradeDist, result.totalRepos)}
  </div>

  <!-- Repo Leaderboard -->
  <div class="section">
    <div class="section-title">Repo Leaderboard</div>
    <div class="search-bar">
      <input type="text" id="repo-search" placeholder="Filter repos..." oninput="filterRepos()">
    </div>
    <table class="repo-table" id="repo-table">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Grade</th>
          <th onclick="sortTable(1)">Repository</th>
          <th onclick="sortTable(2)">Critical</th>
          <th onclick="sortTable(3)">Warning</th>
          <th onclick="sortTable(4)">Info</th>
          <th onclick="sortTable(5)">Total</th>
          <th onclick="sortTable(6)">Time</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        ${sortedRepos.map((r, i) => {
          const gc = gradeColorFor(r.grade);
          return `<tr class="repo-row" data-name="${esc(r.fullName.toLowerCase())}" data-grade="${r.grade}" data-crit="${r.criticals}" data-warn="${r.warnings}" data-info="${r.infos}" data-total="${r.total}">
          <td><span class="grade-badge" style="background:${gc}">${r.grade}</span></td>
          <td><a href="https://github.com/${esc(r.fullName)}" target="_blank">${esc(r.fullName)}</a></td>
          <td>${r.criticals > 0 ? `<span class="sev-pill c">${r.criticals}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
          <td>${r.warnings > 0 ? `<span class="sev-pill w">${r.warnings}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
          <td>${r.infos > 0 ? `<span class="sev-pill i">${r.infos}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
          <td><strong>${r.total}</strong></td>
          <td style="color:var(--fg3);font-size:12px">${formatDuration(r.durationMs)}</td>
          <td>${r.status === 'error' ? `<span class="sev-pill err" title="${esc(r.error || '')}">error</span>` : r.total > 0 ? `<button style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px;color:var(--fg2)" onclick="toggleDetail(${i})">details</button>` : ''}</td>
        </tr>
        <tr><td colspan="8" style="padding:0"><div class="repo-detail" id="detail-${i}">
          ${r.status === 'error' ? `<div style="color:var(--crit);padding:8px">Error: ${esc(r.error || 'Unknown error')}</div>` : renderRepoDetail(r)}
        </div></td></tr>`;
        }).join('\n        ')}
      </tbody>
    </table>
  </div>

  <!-- Top Recurring Vulnerabilities -->
  ${topRules.length > 0 ? `
  <div class="section">
    <div class="section-title">Top Recurring Vulnerabilities</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)">
      ${topRules.map((r, i) => {
        const sevColor = r.severity === 'critical' ? 'var(--crit)' : r.severity === 'warning' ? 'var(--warn)' : 'var(--info)';
        return `<div class="rule-row">
          <div class="rule-rank">${i + 1}</div>
          <div>
            <div class="rule-id" style="color:${sevColor}">${esc(r.ruleId)}</div>
            <div class="rule-repos">${r.repos.size} repo${r.repos.size !== 1 ? 's' : ''} affected${r.cweId ? ` &middot; ${r.cweId}` : ''}</div>
          </div>
          <div class="rule-count" style="color:${sevColor}">${r.count}</div>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>` : ''}

  <!-- OWASP -->
  <div class="section">
    <div class="section-title">OWASP Top 10 (2021) Coverage</div>
    <div class="owasp-grid">
      ${Object.entries(owaspLabels).map(([cat, label]) => {
        const count = owaspCounts[cat] || 0;
        const pct = result.totalFindings > 0 ? Math.round((count / result.totalFindings) * 100) : 0;
        const barColor = count === 0 ? 'var(--ok)' : count > 5 ? 'var(--crit)' : 'var(--warn)';
        return `<div class="owasp-card">
          <div class="cat-id">${cat}</div>
          <div class="cat-name">${label}</div>
          <div class="cat-count">${count} <span style="font-size:13px;font-weight:400;color:var(--fg2)">finding${count !== 1 ? 's' : ''}</span></div>
          <div class="owasp-bar"><div class="owasp-bar-fill" style="width:${Math.max(pct, 2)}%;background:${barColor}"></div></div>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>

  <div class="footer">
    Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a> &middot;
    ${result.totalRepos} repos &middot; ${result.totalFindings} findings &middot; ${formatDuration(result.durationMs)} &middot; ${esc(now)}<br>
    Built by <a href="https://digitalalchemy.dev">Digital Alchemy Academy</a>
  </div>
</div>

<script>
function toggleTheme(){
  const h=document.documentElement;
  h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';
}
function toggleDetail(i){
  document.getElementById('detail-'+i).classList.toggle('open');
}
function filterRepos(){
  const q=document.getElementById('repo-search').value.toLowerCase();
  document.querySelectorAll('.repo-row').forEach(row=>{
    const name=row.dataset.name;
    const show=!q||name.includes(q);
    row.style.display=show?'':'none';
    row.nextElementSibling.style.display=show?'':'none';
  });
}
let sortCol=-1,sortAsc=true;
function sortTable(col){
  if(sortCol===col)sortAsc=!sortAsc;else{sortCol=col;sortAsc=true;}
  const tbody=document.querySelector('#repo-table tbody');
  const pairs=[];
  const rows=tbody.querySelectorAll('.repo-row');
  rows.forEach(row=>{
    pairs.push([row,row.nextElementSibling]);
  });
  pairs.sort((a,b)=>{
    const cellA=a[0].children[col];
    const cellB=b[0].children[col];
    let vA,vB;
    if(col>=2&&col<=6){
      vA=parseInt(cellA.textContent)||0;
      vB=parseInt(cellB.textContent)||0;
    }else{
      vA=cellA.textContent.trim().toLowerCase();
      vB=cellB.textContent.trim().toLowerCase();
    }
    const cmp=typeof vA==='number'?(vA-vB):(vA<vB?-1:vA>vB?1:0);
    return sortAsc?cmp:-cmp;
  });
  pairs.forEach(([row,detail])=>{tbody.appendChild(row);tbody.appendChild(detail);});
}
</script>
</body>
</html>`;
}

function renderGradeBar(gradeDist, total) {
  if (total === 0) return '';
  const colors = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444', '?': '#94a3b8' };
  const segments = ['F', 'D', 'C', 'B', 'A', '?']
    .filter(g => gradeDist[g] > 0)
    .map(g => {
      return `<div class="grade-bar-seg" style="flex:${gradeDist[g]};background:${colors[g]}">${g} (${gradeDist[g]})</div>`;
    })
    .join('');

  const legend = ['A', 'B', 'C', 'D', 'F']
    .map(g => `<span><span class="grade-dot" style="background:${colors[g]}"></span>${g}: ${gradeDist[g]}</span>`)
    .join('');

  return `<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)">
    <div class="grade-bar">${segments}</div>
    <div class="grade-legend">${legend}</div>
  </div>`;
}

function renderRepoDetail(repo) {
  if (!repo.findings || repo.findings.length === 0) return '<div style="padding:8px;color:var(--fg3)">No findings</div>';

  const items = repo.findings.slice(0, 50).map(f => {
    return `<div class="finding-mini">
      <span class="sev-dot ${f.severity}"></span>
      <span>${esc(f.message)}</span>
      <span class="f-file">${esc(f.file)}${f.line ? ':' + f.line : ''}</span>
    </div>`;
  }).join('');

  const overflow = repo.findings.length > 50 ? `<div style="padding:8px 12px;font-size:12px;color:var(--fg3)">...and ${repo.findings.length - 50} more findings</div>` : '';

  return `<div class="repo-detail-findings">${items}${overflow}</div>`;
}

function gradeColorFor(grade) {
  return { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444', '?': '#94a3b8' }[grade] || '#94a3b8';
}

function formatDuration(ms) {
  if (ms < 1000) return ms + 'ms';
  if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
  return (ms / 60000).toFixed(1) + 'min';
}

function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
