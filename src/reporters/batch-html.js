/**
 * Multi-repo batch HTML dashboard.
 *
 * Generates a single self-contained HTML file showing:
 *   - Fleet-level summary (total repos, aggregate grade, critical count)
 *   - Per-repo table with grade, severity counts, top issues
 *   - Heatmap grid view
 *   - Drill-down per repo with finding details
 *   - Sortable/filterable table
 *   - Dark mode, print-friendly
 *   - Zero external dependencies
 */

function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const GRADE_COLORS = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444', '-': '#94a3b8' };

/**
 * @param {import('../batch.js').RepoResult[]} results
 * @param {{ durationMs: number }} meta
 * @returns {string}
 */
export function generateBatchHTML(results, _meta) {
  const now = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const totalRepos = results.length;
  const scanned = results.filter(r => !r.error);
  const errored = results.filter(r => r.error);
  const totalFindings = scanned.reduce((s, r) => s + r.total, 0);
  const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
  const totalWarning = scanned.reduce((s, r) => s + r.warning, 0);
  const totalInfo = scanned.reduce((s, r) => s + r.info, 0);

  const gradeDistrib = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of scanned) {
    if (gradeDistrib[r.grade] !== undefined) gradeDistrib[r.grade]++;
  }

  const fleetGrade = totalCritical > 0 ? 'F'
    : totalWarning > 20 ? 'D'
    : totalWarning > 0 ? 'C'
    : totalFindings > 0 ? 'B'
    : 'A';

  const sorted = [...scanned].sort((a, b) => {
    const ord = { F: 0, D: 1, C: 2, B: 3, A: 4 };
    return (ord[a.grade] ?? 5) - (ord[b.grade] ?? 5) || b.total - a.total;
  });

  const topIssuesByRule = new Map();
  for (const r of scanned) {
    for (const f of r.findings) {
      topIssuesByRule.set(f.ruleId, (topIssuesByRule.get(f.ruleId) || 0) + 1);
    }
  }
  const topRules = [...topIssuesByRule.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit — Fleet Dashboard (${totalRepos} repos)</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#ffffff;--bg2:#f8fafc;--bg3:#f1f5f9;--fg:#0f172a;--fg2:#475569;--fg3:#94a3b8;--border:#e2e8f0;--card:#ffffff;--shadow:0 1px 3px rgba(0,0,0,.1);--crit:#ef4444;--crit-bg:#fef2f2;--warn:#eab308;--warn-bg:#fefce8;--info:#06b6d4;--info-bg:#ecfeff;--ok:#22c55e;--ok-bg:#f0fdf4;--accent:#6366f1;--radius:12px}
[data-theme="dark"]{--bg:#0f172a;--bg2:#1e293b;--bg3:#334155;--fg:#f1f5f9;--fg2:#94a3b8;--fg3:#64748b;--border:#334155;--card:#1e293b;--shadow:0 1px 3px rgba(0,0,0,.4);--crit-bg:#450a0a;--warn-bg:#422006;--info-bg:#083344;--ok-bg:#052e16}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6}
.container{max-width:1440px;margin:0 auto;padding:24px}
.header{display:flex;align-items:center;justify-content:space-between;padding:24px 0;border-bottom:1px solid var(--border);margin-bottom:32px}
.header h1{font-size:28px;display:flex;align-items:center;gap:12px}
.grade{width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:32px;font-weight:800;color:#fff;flex-shrink:0}
.theme-toggle{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:14px;color:var(--fg)}
.theme-toggle:hover{background:var(--border)}
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
/* Grade distribution */
.grade-bar{display:flex;height:40px;border-radius:8px;overflow:hidden;margin-bottom:16px}
.grade-bar span{display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;color:#fff;min-width:30px}
/* Heatmap */
.heatmap{display:grid;grid-template-columns:repeat(auto-fill,minmax(48px,1fr));gap:4px;margin-bottom:24px}
.heat-cell{aspect-ratio:1;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;cursor:pointer;position:relative;transition:transform .1s}
.heat-cell:hover{transform:scale(1.15);z-index:1}
.heat-cell .tooltip{display:none;position:absolute;bottom:110%;left:50%;transform:translateX(-50%);background:var(--fg);color:var(--bg);padding:4px 10px;border-radius:6px;white-space:nowrap;font-size:12px;font-weight:400;z-index:10}
.heat-cell:hover .tooltip{display:block}
/* Repo table */
.repo-table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
.repo-table th{background:var(--bg2);text-align:left;padding:12px 16px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg3);cursor:pointer;user-select:none;border-bottom:1px solid var(--border)}
.repo-table th:hover{color:var(--fg)}
.repo-table td{padding:12px 16px;border-bottom:1px solid var(--border);font-size:14px}
.repo-table tr:last-child td{border-bottom:none}
.repo-table tr:hover td{background:var(--bg2)}
.grade-sm{width:32px;height:32px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:800;color:#fff}
.sev-pill{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;display:inline-block;min-width:28px;text-align:center}
.sev-pill.c{background:var(--crit-bg);color:var(--crit)}
.sev-pill.w{background:var(--warn-bg);color:var(--warn)}
.sev-pill.i{background:var(--info-bg);color:var(--info)}
.sev-pill.zero{opacity:.4}
.err-badge{background:var(--crit-bg);color:var(--crit);padding:2px 8px;border-radius:6px;font-size:12px}
/* Top rules */
.rule-bar{display:flex;align-items:center;gap:12px;margin-bottom:8px}
.rule-name{font-family:monospace;font-size:13px;min-width:240px}
.rule-fill{height:20px;border-radius:4px;transition:width .5s}
.rule-count{font-size:13px;font-weight:600;min-width:30px}
/* Drill-down */
.drill{display:none;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);margin:8px 16px 16px;padding:16px}
.drill.open{display:block}
.drill-finding{padding:8px 0;border-bottom:1px solid var(--border);font-size:13px}
.drill-finding:last-child{border-bottom:none}
.drill-sev{display:inline-block;width:60px;font-weight:700;font-size:11px;text-transform:uppercase}
.drill-sev.critical{color:var(--crit)}
.drill-sev.warning{color:var(--warn)}
.drill-sev.info{color:var(--info)}
/* Filter */
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:var(--card);cursor:pointer;font-size:13px;color:var(--fg2);transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{.theme-toggle,.filter-bar,.heat-cell .tooltip{display:none!important}.drill{display:block!important}body{background:#fff;color:#000}}
@media(max-width:768px){.dashboard{grid-template-columns:repeat(2,1fr)}.header{flex-direction:column;gap:16px;text-align:center}.heatmap{grid-template-columns:repeat(auto-fill,minmax(36px,1fr))}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade" style="background:${GRADE_COLORS[fleetGrade]}">${fleetGrade}</div>
      <div>
        <h1>Vibe Audit — Fleet Dashboard</h1>
        <div style="color:var(--fg2);font-size:14px">${totalRepos} repositories &middot; ${now}</div>
      </div>
    </div>
    <div style="display:flex;gap:12px;align-items:center">
      <button class="theme-toggle" onclick="toggleTheme()">Theme</button>
    </div>
  </div>

  <div class="dashboard">
    <div class="stat-card">
      <div class="label">Repos Scanned</div>
      <div class="value">${scanned.length}</div>
      <div class="sub">${errored.length > 0 ? errored.length + ' errored' : 'all successful'}</div>
    </div>
    <div class="stat-card crit">
      <div class="label">Total Critical</div>
      <div class="value">${totalCritical}</div>
      <div class="sub">across ${scanned.filter(r => r.critical > 0).length} repos</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Total Warnings</div>
      <div class="value">${totalWarning}</div>
      <div class="sub">across ${scanned.filter(r => r.warning > 0).length} repos</div>
    </div>
    <div class="stat-card info">
      <div class="label">Total Info</div>
      <div class="value">${totalInfo}</div>
      <div class="sub">${totalFindings} total findings</div>
    </div>
    <div class="stat-card ok">
      <div class="label">Clean Repos</div>
      <div class="value">${gradeDistrib.A}</div>
      <div class="sub">grade A — no issues</div>
    </div>
  </div>

  <!-- Grade Distribution Bar -->
  <div class="section">
    <div class="section-title">Grade Distribution</div>
    <div class="grade-bar">
      ${['F','D','C','B','A'].map(g => {
        const count = gradeDistrib[g];
        const pct = scanned.length > 0 ? (count / scanned.length * 100) : 0;
        if (count === 0) return '';
        return `<span style="width:${Math.max(pct, 5)}%;background:${GRADE_COLORS[g]}" title="${g}: ${count} repos">${g} (${count})</span>`;
      }).join('')}
    </div>
  </div>

  <!-- Heatmap -->
  <div class="section">
    <div class="section-title">Repo Heatmap</div>
    <div class="heatmap">
      ${sorted.map(r => `<div class="heat-cell" style="background:${GRADE_COLORS[r.grade]}" onclick="scrollToRepo('${esc(r.repo)}')">${r.grade}<span class="tooltip">${esc(r.repo)} — ${r.total} findings</span></div>`).join('\n      ')}
    </div>
  </div>

  <!-- Top Rules -->
  ${topRules.length > 0 ? `
  <div class="section">
    <div class="section-title">Top 10 Most Common Issues</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)">
      ${topRules.map(([rule, count]) => {
        const pct = totalFindings > 0 ? Math.round(count / totalFindings * 100) : 0;
        return `<div class="rule-bar">
          <span class="rule-name">${esc(rule)}</span>
          <div style="flex:1;background:var(--bg3);border-radius:4px;overflow:hidden"><div class="rule-fill" style="width:${Math.max(pct, 2)}%;background:var(--accent)"></div></div>
          <span class="rule-count">${count}</span>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>` : ''}

  <!-- Repo Table -->
  <div class="section">
    <div class="section-title">All Repositories (${totalRepos})</div>
    <div class="filter-bar">
      <input type="text" id="repo-search" placeholder="Search repos..." oninput="filterRepos()">
      <button class="filter-btn active" data-grade="all" onclick="setGradeFilter('all',this)">All</button>
      ${['F','D','C','B','A'].map(g => `<button class="filter-btn" data-grade="${g}" onclick="setGradeFilter('${g}',this)">${g} (${gradeDistrib[g]})</button>`).join('\n      ')}
    </div>
    <table class="repo-table" id="repo-table">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Grade</th>
          <th onclick="sortTable(1)">Repository</th>
          <th onclick="sortTable(2)">Critical</th>
          <th onclick="sortTable(3)">Warnings</th>
          <th onclick="sortTable(4)">Info</th>
          <th onclick="sortTable(5)">Total</th>
          <th>Time</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        ${sorted.map(r => `
        <tr data-grade="${r.grade}" data-repo="${esc(r.repo).toLowerCase()}" id="row-${esc(r.repo).replace(/\//g, '-')}">
          <td><span class="grade-sm" style="background:${GRADE_COLORS[r.grade]}">${r.grade}</span></td>
          <td><strong>${esc(r.repo)}</strong></td>
          <td><span class="sev-pill c${r.critical === 0 ? ' zero' : ''}">${r.critical}</span></td>
          <td><span class="sev-pill w${r.warning === 0 ? ' zero' : ''}">${r.warning}</span></td>
          <td><span class="sev-pill i${r.info === 0 ? ' zero' : ''}">${r.info}</span></td>
          <td><strong>${r.total}</strong></td>
          <td style="color:var(--fg3);font-size:12px">${r.durationMs > 1000 ? (r.durationMs / 1000).toFixed(1) + 's' : r.durationMs + 'ms'}</td>
          <td>${r.total > 0 ? `<button class="filter-btn" onclick="toggleDrill(this, '${esc(r.repo).replace(/'/g, "\\'")}')">Details</button>` : ''}</td>
        </tr>
        ${r.total > 0 ? `<tr class="drill-row" style="display:none" data-grade="${r.grade}" data-repo="${esc(r.repo).toLowerCase()}"><td colspan="8">
          <div class="drill open">
            ${r.findings.slice(0, 50).map(f => `<div class="drill-finding">
              <span class="drill-sev ${f.severity}">${f.severity}</span>
              <strong>${esc(f.message)}</strong>
              <span style="color:var(--fg3);font-size:12px;margin-left:8px">${esc(f.file)}${f.line ? ':' + f.line : ''}</span>
              ${f.cweId ? `<span style="background:var(--bg3);padding:1px 6px;border-radius:3px;font-size:11px;margin-left:6px">${f.cweId}</span>` : ''}
            </div>`).join('')}
            ${r.findings.length > 50 ? `<div style="padding:8px 0;color:var(--fg3);font-size:13px">... and ${r.findings.length - 50} more findings</div>` : ''}
          </div>
        </td></tr>` : ''}`).join('\n        ')}
        ${errored.map(r => `
        <tr data-grade="-" data-repo="${esc(r.repo).toLowerCase()}">
          <td><span class="grade-sm" style="background:${GRADE_COLORS['-']}">-</span></td>
          <td><strong>${esc(r.repo)}</strong></td>
          <td colspan="5"><span class="err-badge">Error: ${esc(r.error).slice(0, 80)}</span></td>
          <td></td>
        </tr>`).join('\n        ')}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Vibe Audit Fleet Dashboard &middot; ${totalRepos} repos &middot; ${totalFindings} findings &middot; ${now}<br>
    Generated by <a href="https://github.com/jackdog668/vibeaudit" style="color:var(--accent)">vibe-audit</a>
  </div>
</div>

<script>
function toggleTheme(){document.documentElement.dataset.theme=document.documentElement.dataset.theme==='dark'?'light':'dark'}

let currentGrade='all';
function setGradeFilter(g,btn){
  currentGrade=g;
  document.querySelectorAll('.filter-btn[data-grade]').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  filterRepos();
}

function filterRepos(){
  const q=(document.getElementById('repo-search').value||'').toLowerCase();
  document.querySelectorAll('#repo-table tbody tr').forEach(tr=>{
    const grade=tr.dataset.grade;
    const repo=tr.dataset.repo||'';
    const matchG=currentGrade==='all'||grade===currentGrade;
    const matchQ=!q||repo.includes(q);
    tr.style.display=matchG&&matchQ?'':'none';
  });
}

function toggleDrill(btn,repo){
  const row=btn.closest('tr');
  const next=row.nextElementSibling;
  if(next&&next.classList.contains('drill-row')){
    const isOpen=next.style.display!=='none';
    next.style.display=isOpen?'none':'table-row';
    btn.textContent=isOpen?'Details':'Hide';
  }
}

function scrollToRepo(repo){
  const id='row-'+repo.replace(/\\//g,'-');
  const el=document.getElementById(id);
  if(el){el.scrollIntoView({behavior:'smooth',block:'center'});el.style.outline='2px solid var(--accent)';setTimeout(()=>el.style.outline='',2000)}
}

let sortCol=-1,sortAsc=true;
function sortTable(col){
  if(sortCol===col)sortAsc=!sortAsc; else{sortCol=col;sortAsc=true}
  const tbody=document.querySelector('#repo-table tbody');
  const rows=[...tbody.querySelectorAll('tr:not(.drill-row)')];
  rows.sort((a,b)=>{
    let va=a.children[col]?.textContent.trim()||'';
    let vb=b.children[col]?.textContent.trim()||'';
    const na=parseFloat(va),nb=parseFloat(vb);
    if(!isNaN(na)&&!isNaN(nb))return sortAsc?na-nb:nb-na;
    return sortAsc?va.localeCompare(vb):vb.localeCompare(va);
  });
  for(const row of rows){
    tbody.appendChild(row);
    const next=row.nextElementSibling;
    if(!next||!next.classList.contains('drill-row')){
      const drillId=row.id?.replace('row-','');
      if(drillId){
        const drill=tbody.querySelector('.drill-row[data-repo="'+row.dataset.repo+'"]');
        if(drill)tbody.insertBefore(drill,row.nextSibling);
      }
    }
  }
}
</script>
</body>
</html>`;
}
