/**
 * Multi-Repo HTML Dashboard — consolidated security report across all repos.
 *
 * Generates a single self-contained HTML file with:
 *   - Org-level executive summary (total repos, grades distribution, top risks)
 *   - Sortable repo table with grade, severity counts, language
 *   - Drill-down per-repo findings
 *   - Top 10 most common findings across the org
 *   - Search/filter
 *   - Dark mode, print-friendly
 *   - Zero external dependencies
 */

/**
 * @param {Array<object>} results - Array of per-repo scan results
 * @param {{ orgName: string, durationMs: number }} meta
 * @returns {string} Complete HTML document
 */
export function generateMultiRepoHTML(results, meta) {
  const now = new Date().toISOString().split('T')[0];
  const totalRepos = results.length;
  const scannedRepos = results.filter((r) => !r.error).length;
  const failedRepos = results.filter((r) => r.error).length;

  const totalFindings = results.reduce((s, r) => s + r.total, 0);
  const totalCriticals = results.reduce((s, r) => s + r.criticals, 0);
  const totalWarnings = results.reduce((s, r) => s + r.warnings, 0);
  const totalInfos = results.reduce((s, r) => s + r.infos, 0);

  // Grade distribution
  const gradeDist = { A: 0, B: 0, C: 0, D: 0, F: 0, '?': 0 };
  for (const r of results) gradeDist[r.grade] = (gradeDist[r.grade] || 0) + 1;

  // Top findings by rule across all repos
  const ruleCount = new Map();
  for (const r of results) {
    for (const f of r.findings) {
      const key = f.ruleId || 'unknown';
      if (!ruleCount.has(key)) ruleCount.set(key, { ruleId: key, message: f.message, severity: f.severity, count: 0, repos: new Set() });
      const entry = ruleCount.get(key);
      entry.count++;
      entry.repos.add(`${r.owner}/${r.repo}`);
    }
  }
  const topRules = [...ruleCount.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, 15)
    .map((r) => ({ ...r, repoCount: r.repos.size }));

  const orgGrade = totalCriticals > 0 ? 'F' : totalWarnings > 10 ? 'D' : totalWarnings > 0 ? 'C' : totalInfos > 0 ? 'B' : 'A';
  const gradeColor = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[orgGrade] || '#94a3b8';

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit — ${esc(meta.orgName)} Org Report — ${now}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#ffffff;--bg2:#f8fafc;--bg3:#f1f5f9;--fg:#0f172a;--fg2:#475569;--fg3:#94a3b8;--border:#e2e8f0;--card:#ffffff;--shadow:0 1px 3px rgba(0,0,0,.1);--crit:#ef4444;--crit-bg:#fef2f2;--warn:#eab308;--warn-bg:#fefce8;--info:#06b6d4;--info-bg:#ecfeff;--ok:#22c55e;--ok-bg:#f0fdf4;--accent:#6366f1;--radius:12px}
[data-theme="dark"]{--bg:#0f172a;--bg2:#1e293b;--bg3:#334155;--fg:#f1f5f9;--fg2:#94a3b8;--fg3:#64748b;--border:#334155;--card:#1e293b;--shadow:0 1px 3px rgba(0,0,0,.4);--crit-bg:#450a0a;--warn-bg:#422006;--info-bg:#083344;--ok-bg:#052e16}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1400px;margin:0 auto;padding:24px}
.header{display:flex;align-items:center;justify-content:space-between;padding:24px 0;border-bottom:1px solid var(--border);margin-bottom:32px}
.header h1{font-size:28px;display:flex;align-items:center;gap:12px}
.header-meta{display:flex;gap:16px;align-items:center}
.header-meta span{font-size:13px;color:var(--fg2)}
.theme-toggle{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:14px;color:var(--fg)}
.grade{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:36px;font-weight:800;color:#fff;flex-shrink:0}
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:32px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}
.stat-card .label{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--fg3);margin-bottom:4px}
.stat-card .value{font-size:32px;font-weight:700}
.stat-card .sub{font-size:12px;color:var(--fg2);margin-top:4px}
.stat-card.crit .value{color:var(--crit)}
.stat-card.warn .value{color:var(--warn)}
.stat-card.info .value{color:var(--info)}
.stat-card.ok .value{color:var(--ok)}
.section{margin-bottom:40px}
.section-title{font-size:20px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px}
/* Grade distribution bars */
.grade-dist{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.grade-box{text-align:center;min-width:60px}
.grade-box .g-label{font-size:28px;font-weight:800;display:block}
.grade-box .g-count{font-size:14px;color:var(--fg2)}
.grade-box .g-bar{height:8px;border-radius:4px;margin-top:6px}
/* Repo table */
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:var(--card);cursor:pointer;font-size:13px;color:var(--fg2);transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
th{padding:12px 16px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg3);border-bottom:2px solid var(--border);cursor:pointer;user-select:none;background:var(--bg2)}
th:hover{color:var(--fg)}
td{padding:10px 16px;border-bottom:1px solid var(--border);font-size:14px}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--bg2)}
.grade-cell{font-weight:800;font-size:18px;text-align:center;width:50px}
.grade-A{color:#22c55e}.grade-B{color:#86efac}.grade-C{color:#eab308}.grade-D{color:#f97316}.grade-F{color:#ef4444}.grade-\\?{color:#94a3b8}
.sev-badge{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;display:inline-block}
.sev-badge.critical{background:var(--crit-bg);color:var(--crit)}
.sev-badge.warning{background:var(--warn-bg);color:var(--warn)}
.sev-badge.info{background:var(--info-bg);color:var(--info)}
.lang-badge{padding:2px 8px;border-radius:4px;font-size:11px;background:var(--bg3);color:var(--fg2)}
.error-badge{padding:2px 8px;border-radius:4px;font-size:11px;background:var(--crit-bg);color:var(--crit)}
/* Top rules */
.rule-row{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--card)}
.rule-row:last-child{border-bottom:none}
.rule-rank{font-size:18px;font-weight:700;color:var(--fg3);min-width:30px;text-align:right}
.rule-bar{flex:1;height:24px;background:var(--bg3);border-radius:6px;overflow:hidden;position:relative}
.rule-bar-fill{height:100%;border-radius:6px}
.rule-bar-label{position:absolute;left:8px;top:50%;transform:translateY(-50%);font-size:12px;font-weight:600;color:var(--fg)}
.rule-count{font-size:14px;font-weight:700;min-width:40px;text-align:right}
.rule-repos{font-size:12px;color:var(--fg3);min-width:80px}
/* Expand row for per-repo findings */
.expand-row{display:none}
.expand-row.open{display:table-row}
.expand-cell{padding:16px 20px;background:var(--bg2)}
.finding-mini{padding:6px 0;font-size:13px;border-bottom:1px solid var(--border)}
.finding-mini:last-child{border-bottom:none}
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{.theme-toggle,.filter-bar{display:none!important}body{background:#fff;color:#000}}
@media(max-width:768px){.dashboard{grid-template-columns:repeat(2,1fr)}.header{flex-direction:column;gap:16px;text-align:center}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade" style="background:${gradeColor}">${orgGrade}</div>
      <div>
        <h1>Vibe Audit — Org Report</h1>
        <div style="color:var(--fg2);font-size:14px">${esc(meta.orgName)} &middot; ${totalRepos} repositories &middot; ${now}</div>
      </div>
    </div>
    <div class="header-meta">
      <span>${Math.round(meta.durationMs / 1000)}s total</span>
      <button class="theme-toggle" onclick="toggleTheme()">Theme</button>
    </div>
  </div>

  <div class="dashboard">
    <div class="stat-card">
      <div class="label">Repos Scanned</div>
      <div class="value">${scannedRepos}</div>
      <div class="sub">${failedRepos > 0 ? failedRepos + ' failed' : 'all successful'}</div>
    </div>
    <div class="stat-card crit">
      <div class="label">Critical</div>
      <div class="value">${totalCriticals}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Warnings</div>
      <div class="value">${totalWarnings}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="stat-card info">
      <div class="label">Info</div>
      <div class="value">${totalInfos}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="stat-card">
      <div class="label">Total Findings</div>
      <div class="value">${totalFindings}</div>
      <div class="sub">${topRules.length > 0 ? 'top: ' + topRules[0].ruleId : 'clean'}</div>
    </div>
  </div>

  <!-- Grade Distribution -->
  <div class="section">
    <div class="section-title">Grade Distribution</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow)">
      <div class="grade-dist">
        ${['A', 'B', 'C', 'D', 'F'].map((g) => {
          const count = gradeDist[g] || 0;
          const pct = totalRepos > 0 ? Math.round((count / totalRepos) * 100) : 0;
          const color = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[g];
          return `<div class="grade-box" style="flex:1;max-width:200px">
            <span class="g-label" style="color:${color}">${g}</span>
            <span class="g-count">${count} repo${count !== 1 ? 's' : ''} (${pct}%)</span>
            <div class="g-bar" style="background:${color};width:${Math.max(pct, 2)}%"></div>
          </div>`;
        }).join('\n        ')}
      </div>
      ${failedRepos > 0 ? `<div style="text-align:center;margin-top:12px;font-size:13px;color:var(--fg3)">${failedRepos} repo(s) failed to scan</div>` : ''}
    </div>
  </div>

  <!-- Top Rules -->
  ${topRules.length > 0 ? `
  <div class="section">
    <div class="section-title">Top Findings Across Org</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)">
      ${topRules.map((rule, i) => {
        const maxCount = topRules[0].count;
        const pct = Math.round((rule.count / maxCount) * 100);
        const color = rule.severity === 'critical' ? 'var(--crit)' : rule.severity === 'warning' ? 'var(--warn)' : 'var(--info)';
        return `<div class="rule-row">
          <span class="rule-rank">${i + 1}</span>
          <span class="sev-badge ${rule.severity}">${rule.severity}</span>
          <div class="rule-bar">
            <div class="rule-bar-fill" style="width:${pct}%;background:${color};opacity:0.3"></div>
            <span class="rule-bar-label">${esc(rule.ruleId)}</span>
          </div>
          <span class="rule-count">${rule.count}</span>
          <span class="rule-repos">${rule.repoCount} repo${rule.repoCount !== 1 ? 's' : ''}</span>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>` : ''}

  <!-- Repo Table -->
  <div class="section">
    <div class="section-title">All Repositories (${totalRepos})</div>
    <div class="filter-bar">
      <input type="text" id="repoSearch" placeholder="Search repos..." oninput="filterRepos()">
      <button class="filter-btn active" data-grade="all" onclick="setGradeFilter('all',this)">All</button>
      <button class="filter-btn" data-grade="F" onclick="setGradeFilter('F',this)">F (${gradeDist.F || 0})</button>
      <button class="filter-btn" data-grade="D" onclick="setGradeFilter('D',this)">D (${gradeDist.D || 0})</button>
      <button class="filter-btn" data-grade="C" onclick="setGradeFilter('C',this)">C (${gradeDist.C || 0})</button>
      <button class="filter-btn" data-grade="B" onclick="setGradeFilter('B',this)">B (${gradeDist.B || 0})</button>
      <button class="filter-btn" data-grade="A" onclick="setGradeFilter('A',this)">A (${gradeDist.A || 0})</button>
    </div>
    <table>
      <thead>
        <tr>
          <th onclick="sortTable(0)">Grade</th>
          <th onclick="sortTable(1)">Repository</th>
          <th onclick="sortTable(2)">Language</th>
          <th onclick="sortTable(3)" style="text-align:right">Critical</th>
          <th onclick="sortTable(4)" style="text-align:right">Warnings</th>
          <th onclick="sortTable(5)" style="text-align:right">Info</th>
          <th onclick="sortTable(6)" style="text-align:right">Total</th>
          <th style="text-align:right">Time</th>
        </tr>
      </thead>
      <tbody id="repoTableBody">
        ${results.map((r, idx) => `
        <tr class="repo-row" data-grade="${r.grade}" data-search="${esc(`${r.owner}/${r.repo} ${r.language} ${r.description}`).toLowerCase()}" onclick="toggleExpand(${idx})">
          <td class="grade-cell grade-${r.grade}">${r.grade}</td>
          <td>
            <div><a href="https://github.com/${esc(r.owner)}/${esc(r.repo)}" target="_blank">${esc(r.owner)}/${esc(r.repo)}</a></div>
            ${r.description ? `<div style="font-size:12px;color:var(--fg3)">${esc(r.description.slice(0, 80))}</div>` : ''}
          </td>
          <td><span class="lang-badge">${esc(r.language || '?')}</span></td>
          <td style="text-align:right">${r.criticals > 0 ? `<span class="sev-badge critical">${r.criticals}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
          <td style="text-align:right">${r.warnings > 0 ? `<span class="sev-badge warning">${r.warnings}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
          <td style="text-align:right">${r.infos > 0 ? `<span class="sev-badge info">${r.infos}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
          <td style="text-align:right;font-weight:600">${r.total}</td>
          <td style="text-align:right;color:var(--fg3);font-size:12px">${r.error ? '<span class="error-badge">error</span>' : (r.durationMs / 1000).toFixed(1) + 's'}</td>
        </tr>
        <tr class="expand-row" id="expand-${idx}">
          <td colspan="8" class="expand-cell">
            ${r.error ? `<div style="color:var(--crit)">Error: ${esc(r.error)}</div>` :
              r.findings.length === 0 ? '<div style="color:var(--ok)">No findings — clean!</div>' :
              r.findings.slice(0, 20).map((f) => `<div class="finding-mini">
                <span class="sev-badge ${f.severity}" style="margin-right:8px">${f.severity}</span>
                <span style="font-family:monospace;color:var(--fg3)">${esc(f.file)}${f.line ? ':' + f.line : ''}</span>
                — ${esc(f.message)}
                ${f.cweId ? `<span style="font-size:11px;color:var(--fg3)">[${f.cweId}]</span>` : ''}
              </div>`).join('') +
              (r.findings.length > 20 ? `<div style="padding:8px 0;color:var(--fg3);font-size:12px">...and ${r.findings.length - 20} more findings</div>` : '')}
          </td>
        </tr>`).join('\n        ')}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a> &middot;
    ${totalRepos} repos &middot; ${totalFindings} findings &middot; ${Math.round(meta.durationMs / 1000)}s &middot; ${now}
  </div>
</div>

<script>
function toggleTheme(){
  const h=document.documentElement;
  h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';
}
let gradeFilter='all';
function setGradeFilter(g,btn){
  gradeFilter=g;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  filterRepos();
}
function filterRepos(){
  const q=document.getElementById('repoSearch').value.toLowerCase();
  document.querySelectorAll('.repo-row').forEach(row=>{
    const mg=gradeFilter==='all'||row.dataset.grade===gradeFilter;
    const mq=!q||row.dataset.search.includes(q);
    row.style.display=mg&&mq?'':'none';
    const idx=row.nextElementSibling?.id?.replace('expand-','');
    if(row.nextElementSibling)row.nextElementSibling.classList.remove('open');
  });
}
function toggleExpand(idx){
  const row=document.getElementById('expand-'+idx);
  if(row)row.classList.toggle('open');
}
let sortCol=-1,sortDir=1;
function sortTable(col){
  const body=document.getElementById('repoTableBody');
  const rows=[...body.querySelectorAll('.repo-row')];
  if(sortCol===col)sortDir*=-1;else{sortCol=col;sortDir=1;}
  rows.sort((a,b)=>{
    const ac=a.children[col],bc=b.children[col];
    let av=ac.textContent.trim(),bv=bc.textContent.trim();
    const an=parseFloat(av),bn=parseFloat(bv);
    if(!isNaN(an)&&!isNaN(bn))return(an-bn)*sortDir;
    return av.localeCompare(bv)*sortDir;
  });
  rows.forEach(r=>{
    const expand=r.nextElementSibling;
    body.appendChild(r);
    if(expand&&expand.classList.contains('expand-row'))body.appendChild(expand);
  });
}
</script>
</body>
</html>`;
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
