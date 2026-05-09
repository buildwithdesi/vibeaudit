/**
 * Multi-repo HTML dashboard for batch scans.
 *
 * Generates a single self-contained HTML file with:
 *   - Fleet-wide executive summary (grades, totals)
 *   - Heatmap grid of all repos by grade
 *   - Top recurring vulnerabilities across repos
 *   - Per-repo expandable detail cards
 *   - Search/filter/sort
 *   - Dark mode, print-friendly
 *   - Zero external dependencies
 */

import { aggregateResults } from '../batch.js';

/**
 * @param {import('../batch.js').RepoResult[]} results
 * @returns {string} Complete HTML document
 */
export function generateBatchHTML(results) {
  const agg = aggregateResults(results);
  const now = new Date().toISOString().replace('T', ' ').slice(0, 16);
  const successful = results.filter(r => !r.error);
  const failed = results.filter(r => r.error);

  const gradeColor = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444', '-': '#94a3b8' };

  const fleetGrade = agg.gradeCounts.F > 0 ? 'F'
    : agg.gradeCounts.D > 0 ? 'D'
    : agg.gradeCounts.C > 0 ? 'C'
    : agg.gradeCounts.B > 0 ? 'B' : 'A';

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit — Fleet Report — ${esc(now)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#ffffff;--bg2:#f8fafc;--bg3:#f1f5f9;--fg:#0f172a;--fg2:#475569;--fg3:#94a3b8;--border:#e2e8f0;--card:#ffffff;--shadow:0 1px 3px rgba(0,0,0,.1);--crit:#ef4444;--crit-bg:#fef2f2;--warn:#eab308;--warn-bg:#fefce8;--info:#06b6d4;--info-bg:#ecfeff;--ok:#22c55e;--ok-bg:#f0fdf4;--accent:#6366f1;--radius:12px}
[data-theme="dark"]{--bg:#0f172a;--bg2:#1e293b;--bg3:#334155;--fg:#f1f5f9;--fg2:#94a3b8;--fg3:#64748b;--border:#334155;--card:#1e293b;--shadow:0 1px 3px rgba(0,0,0,.4);--crit-bg:#450a0a;--warn-bg:#422006;--info-bg:#083344;--ok-bg:#052e16}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}
.container{max-width:1400px;margin:0 auto;padding:24px}
.header{display:flex;align-items:center;justify-content:space-between;padding:24px 0;border-bottom:1px solid var(--border);margin-bottom:32px;flex-wrap:wrap;gap:16px}
.header h1{font-size:28px;display:flex;align-items:center;gap:12px}
.header-meta{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.header-meta span{font-size:13px;color:var(--fg2)}
.theme-toggle{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:14px;color:var(--fg)}
.grade{width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:32px;font-weight:800;color:#fff;flex-shrink:0}
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
/* Grade heatmap */
.heatmap{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px}
.heat-cell{border-radius:8px;padding:10px;text-align:center;cursor:pointer;border:1px solid var(--border);transition:transform .15s,box-shadow .15s}
.heat-cell:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.15)}
.heat-cell .repo-name{font-size:11px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:4px}
.heat-cell .heat-grade{font-size:24px;font-weight:800}
.heat-cell .heat-counts{font-size:10px;color:var(--fg2);margin-top:2px}
/* Top rules table */
.rules-table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
.rules-table th{text-align:left;padding:12px 16px;background:var(--bg2);font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg3);border-bottom:1px solid var(--border)}
.rules-table td{padding:10px 16px;border-bottom:1px solid var(--border);font-size:13px}
.rules-table tr:last-child td{border-bottom:none}
.rules-table .count{font-weight:700;font-size:16px}
/* Repo cards */
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-bar select{padding:8px 12px;border:1px solid var(--border);border-radius:8px;font-size:13px;background:var(--card);color:var(--fg)}
.repo-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden;box-shadow:var(--shadow);transition:box-shadow .2s}
.repo-card:hover{box-shadow:0 4px 12px rgba(0,0,0,.1)}
.repo-header{display:flex;align-items:center;gap:12px;padding:14px 20px;cursor:pointer;user-select:none}
.repo-header:hover{background:var(--bg2)}
.repo-grade-badge{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:800;color:#fff;flex-shrink:0}
.repo-title{flex:1;font-size:14px;font-weight:600;font-family:monospace}
.repo-stats{display:flex;gap:8px;flex-shrink:0;align-items:center}
.repo-stat{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.repo-stat.c{background:var(--crit-bg);color:var(--crit)}
.repo-stat.w{background:var(--warn-bg);color:var(--warn)}
.repo-stat.i{background:var(--info-bg);color:var(--info)}
.repo-stat.ok{background:var(--ok-bg);color:var(--ok)}
.repo-stat.err{background:#fef2f2;color:#991b1b}
.chevron{transition:transform .2s;color:var(--fg3);flex-shrink:0}
.chevron.open{transform:rotate(90deg)}
.repo-body{display:none;padding:0 20px 16px;border-top:1px solid var(--border)}
.repo-body.open{display:block;padding-top:16px}
.repo-body table{width:100%;border-collapse:collapse;font-size:12px}
.repo-body th{text-align:left;padding:6px 8px;background:var(--bg2);font-size:11px;text-transform:uppercase;color:var(--fg3)}
.repo-body td{padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
.sev-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px}
.sev-dot.critical{background:var(--crit)}
.sev-dot.warning{background:var(--warn)}
.sev-dot.info{background:var(--info)}
.duration{font-size:11px;color:var(--fg3);margin-left:8px}
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{
  .theme-toggle,.filter-bar,.chevron{display:none!important}
  .repo-body{display:block!important;padding-top:16px!important}
  .repo-card{break-inside:avoid;box-shadow:none;border:1px solid #ccc}
  body{background:#fff;color:#000}
}
@media(max-width:768px){
  .dashboard{grid-template-columns:repeat(2,1fr)}
  .header{flex-direction:column;text-align:center}
  .heatmap{grid-template-columns:repeat(auto-fill,minmax(80px,1fr))}
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade" style="background:${gradeColor[fleetGrade]}">${fleetGrade}</div>
      <div>
        <h1>Vibe Audit &mdash; Fleet Report</h1>
        <div style="color:var(--fg2);font-size:14px">${agg.reposScanned} repos scanned &middot; ${now}</div>
      </div>
    </div>
    <div class="header-meta">
      <span>${agg.reposScanned} repos</span>
      <span>${agg.totalFindings} findings</span>
      ${agg.reposFailed > 0 ? `<span style="color:var(--crit)">${agg.reposFailed} failed</span>` : ''}
      <button class="theme-toggle" onclick="toggleTheme()">Theme</button>
    </div>
  </div>

  <!-- Dashboard -->
  <div class="dashboard">
    <div class="stat-card ok">
      <div class="label">Repos Scanned</div>
      <div class="value">${agg.reposScanned}</div>
      <div class="sub">${agg.reposFailed > 0 ? agg.reposFailed + ' failed' : 'all successful'}</div>
    </div>
    <div class="stat-card crit">
      <div class="label">Critical</div>
      <div class="value">${agg.totalCritical}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Warnings</div>
      <div class="value">${agg.totalWarning}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="stat-card info">
      <div class="label">Info</div>
      <div class="value">${agg.totalInfo}</div>
      <div class="sub">best practices</div>
    </div>
    <div class="stat-card">
      <div class="label">Grade A</div>
      <div class="value" style="color:var(--ok)">${agg.gradeCounts.A}</div>
      <div class="sub">${agg.reposScanned > 0 ? Math.round(agg.gradeCounts.A / agg.reposScanned * 100) : 0}% of fleet</div>
    </div>
    <div class="stat-card">
      <div class="label">Grade F</div>
      <div class="value" style="color:var(--crit)">${agg.gradeCounts.F}</div>
      <div class="sub">${agg.reposScanned > 0 ? Math.round(agg.gradeCounts.F / agg.reposScanned * 100) : 0}% of fleet</div>
    </div>
  </div>

  <!-- Heatmap -->
  <div class="section">
    <div class="section-title">Repo Heatmap</div>
    <div class="heatmap">
      ${successful.map(r => `<div class="heat-cell" style="background:${gradeColor[r.grade]}22" onclick="scrollToRepo('${esc(r.repo)}')">
        <div class="repo-name" title="${esc(r.repo)}">${esc(r.repo.split('/')[1] || r.repo)}</div>
        <div class="heat-grade" style="color:${gradeColor[r.grade]}">${r.grade}</div>
        <div class="heat-counts">${r.critical}C ${r.warning}W ${r.info}I</div>
      </div>`).join('\n      ')}
    </div>
  </div>

  <!-- Top Recurring Rules -->
  ${agg.topRules.length > 0 ? `
  <div class="section">
    <div class="section-title">Top Recurring Vulnerabilities</div>
    <table class="rules-table">
      <thead><tr><th>#</th><th>Rule</th><th>Occurrences</th><th>% of Repos</th></tr></thead>
      <tbody>
        ${agg.topRules.map(([ruleId, count], i) => {
          const reposWithRule = successful.filter(r => r.findings.some(f => f.ruleId === ruleId)).length;
          return `<tr>
            <td>${i + 1}</td>
            <td><code>${esc(ruleId)}</code></td>
            <td class="count">${count}</td>
            <td>${Math.round(reposWithRule / agg.reposScanned * 100)}% (${reposWithRule}/${agg.reposScanned})</td>
          </tr>`;
        }).join('\n        ')}
      </tbody>
    </table>
  </div>
  ` : ''}

  <!-- Per-repo details -->
  <div class="section">
    <div class="section-title">All Repos (${results.length})</div>
    <div class="filter-bar">
      <input type="text" id="repoSearch" placeholder="Search repos..." oninput="filterRepos()">
      <select id="gradeFilter" onchange="filterRepos()">
        <option value="all">All grades</option>
        <option value="F">Grade F</option>
        <option value="D">Grade D</option>
        <option value="C">Grade C</option>
        <option value="B">Grade B</option>
        <option value="A">Grade A</option>
      </select>
      <select id="sortBy" onchange="sortRepos()">
        <option value="grade">Sort: Worst first</option>
        <option value="critical">Sort: Most criticals</option>
        <option value="total">Sort: Most findings</option>
        <option value="name">Sort: Name</option>
      </select>
    </div>
    <div id="repo-list">
      ${results.map(r => `
      <div class="repo-card" data-repo="${esc(r.repo)}" data-grade="${r.grade}" data-critical="${r.critical}" data-total="${r.total}">
        <div class="repo-header" onclick="toggleRepo(this)">
          <div class="repo-grade-badge" style="background:${gradeColor[r.grade]}">${r.grade}</div>
          <span class="repo-title">${esc(r.repo)}</span>
          <div class="repo-stats">
            ${r.error ? `<span class="repo-stat err">ERROR</span>` : ''}
            ${r.critical > 0 ? `<span class="repo-stat c">${r.critical} crit</span>` : ''}
            ${r.warning > 0 ? `<span class="repo-stat w">${r.warning} warn</span>` : ''}
            ${r.info > 0 ? `<span class="repo-stat i">${r.info} info</span>` : ''}
            ${!r.error && r.total === 0 ? `<span class="repo-stat ok">clean</span>` : ''}
            <span class="duration">${r.durationMs > 1000 ? (r.durationMs / 1000).toFixed(1) + 's' : r.durationMs + 'ms'}</span>
          </div>
          <span class="chevron">▶</span>
        </div>
        <div class="repo-body">
          ${r.error ? `<div style="color:var(--crit);padding:8px 0">${esc(r.error)}</div>` : ''}
          ${r.findings.length > 0 ? `
          <table>
            <thead><tr><th>Sev</th><th>File</th><th>Issue</th><th>Fix</th></tr></thead>
            <tbody>
              ${r.findings.map(f => `<tr>
                <td><span class="sev-dot ${f.severity}"></span>${f.severity}</td>
                <td style="font-family:monospace;font-size:11px">${esc(f.file.replace(/^github:\/\/[^/]+\/[^/]+\//, ''))}${f.line ? ':' + f.line : ''}</td>
                <td>${esc(f.message)}${f.cweId ? ` <code style="font-size:10px">${f.cweId}</code>` : ''}</td>
                <td style="font-size:11px;color:var(--fg2)">${esc(f.fix)}</td>
              </tr>`).join('\n              ')}
            </tbody>
          </table>` : r.error ? '' : '<div style="color:var(--ok);padding:8px 0">No issues found.</div>'}
        </div>
      </div>
      `).join('')}
    </div>
  </div>

  ${failed.length > 0 ? `
  <div class="section">
    <div class="section-title" style="color:var(--crit)">Failed Repos (${failed.length})</div>
    ${failed.map(r => `<div style="padding:8px 0;font-size:13px"><code>${esc(r.repo)}</code> &mdash; ${esc(r.error)}</div>`).join('\n    ')}
  </div>` : ''}

  <div class="footer">
    Vibe Audit Fleet Report &middot; ${agg.reposScanned} repos &middot; ${agg.totalFindings} findings &middot; ${now}<br>
    Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a>
  </div>
</div>

<script>
function toggleTheme(){
  const h=document.documentElement;
  h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';
}
function toggleRepo(el){
  el.nextElementSibling.classList.toggle('open');
  el.querySelector('.chevron').classList.toggle('open');
}
function scrollToRepo(name){
  const card=document.querySelector('.repo-card[data-repo="'+name+'"]');
  if(card){card.scrollIntoView({behavior:'smooth',block:'center'});toggleRepo(card.querySelector('.repo-header'));}
}
function filterRepos(){
  const q=document.getElementById('repoSearch').value.toLowerCase();
  const g=document.getElementById('gradeFilter').value;
  document.querySelectorAll('.repo-card').forEach(c=>{
    const matchQ=!q||c.dataset.repo.toLowerCase().includes(q);
    const matchG=g==='all'||c.dataset.grade===g;
    c.style.display=matchQ&&matchG?'':'none';
  });
}
function sortRepos(){
  const by=document.getElementById('sortBy').value;
  const list=document.getElementById('repo-list');
  const cards=[...list.querySelectorAll('.repo-card')];
  const go={'F':0,'D':1,'C':2,'B':3,'A':4,'-':5};
  cards.sort((a,b)=>{
    if(by==='name') return a.dataset.repo.localeCompare(b.dataset.repo);
    if(by==='critical') return parseInt(b.dataset.critical)-parseInt(a.dataset.critical);
    if(by==='total') return parseInt(b.dataset.total)-parseInt(a.dataset.total);
    return (go[a.dataset.grade]||5)-(go[b.dataset.grade]||5);
  });
  cards.forEach(c=>list.appendChild(c));
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
