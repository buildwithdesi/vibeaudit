/**
 * Multi-Repo HTML Dashboard — Morning security scan report.
 *
 * Generates a single self-contained HTML file with:
 *   - Org-level executive summary (grade distribution, total findings)
 *   - Per-repo cards with grade, severity counts, top issues
 *   - Heatmap of most common rules across all repos
 *   - Sortable/filterable repo table
 *   - Drill-down into per-repo findings
 *   - Dark mode, print-friendly
 *   - Zero external dependencies
 */

import { aggregateResults } from '../multi-repo.js';

/**
 * @param {Array} results - Output from scanRepos()
 * @returns {string} Complete HTML document
 */
export function generateMultiRepoHTML(results) {
  const agg = aggregateResults(results);
  const now = new Date().toISOString().replace('T', ' ').slice(0, 16);
  const date = new Date().toISOString().split('T')[0];

  const overallGrade = agg.totalCriticals > 0 ? 'F'
    : agg.totalWarnings > 20 ? 'D'
    : agg.totalWarnings > 0 ? 'C'
    : agg.totalInfos > 0 ? 'B' : 'A';
  const gradeColor = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[overallGrade] || '#94a3b8';

  const sorted = [...results].sort((a, b) => {
    const order = { F: 0, D: 1, C: 2, '?': 3, B: 4, A: 5 };
    return (order[a.grade] ?? 3) - (order[b.grade] ?? 3);
  });

  const repoGradeColor = (g) => ({ A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[g] || '#94a3b8');

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit — Multi-Repo Report — ${date}</title>
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
/* Grade distribution bar */
.grade-bar{display:flex;height:40px;border-radius:8px;overflow:hidden;margin-bottom:24px;box-shadow:var(--shadow)}
.grade-bar-seg{display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;color:#fff;min-width:30px;transition:flex .3s}
/* Repo cards */
.repo-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}
.repo-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow);cursor:pointer;transition:box-shadow .2s,transform .1s}
.repo-card:hover{box-shadow:0 4px 12px rgba(0,0,0,.15);transform:translateY(-1px)}
.repo-card-header{display:flex;align-items:center;gap:12px;margin-bottom:12px}
.repo-grade{width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:800;color:#fff;flex-shrink:0}
.repo-name{font-size:16px;font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.repo-counts{display:flex;gap:8px;margin-bottom:8px}
.repo-count{padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}
.repo-count.c{background:var(--crit-bg);color:var(--crit)}
.repo-count.w{background:var(--warn-bg);color:var(--warn)}
.repo-count.i{background:var(--info-bg);color:var(--info)}
.repo-time{font-size:11px;color:var(--fg3)}
.repo-error{font-size:12px;color:var(--crit);margin-top:4px}
/* Top rules table */
.rules-table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
.rules-table th{background:var(--bg2);padding:12px 16px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--fg3);border-bottom:1px solid var(--border)}
.rules-table td{padding:12px 16px;border-bottom:1px solid var(--border);font-size:14px}
.rules-table tr:last-child td{border-bottom:none}
.rules-table .rule-bar{height:8px;border-radius:4px;background:var(--bg3);overflow:hidden}
.rules-table .rule-bar-fill{height:100%;border-radius:4px}
/* Filter */
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:var(--card);cursor:pointer;font-size:13px;color:var(--fg2);transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
/* Findings modal */
.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);z-index:1000;justify-content:center;align-items:flex-start;padding:40px 20px;overflow-y:auto}
.modal-overlay.open{display:flex}
.modal{background:var(--card);border-radius:var(--radius);max-width:900px;width:100%;max-height:calc(100vh - 80px);overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.modal-header{display:flex;align-items:center;justify-content:space-between;padding:20px 24px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--card);z-index:1}
.modal-header h2{font-size:18px}
.modal-close{background:none;border:none;font-size:24px;cursor:pointer;color:var(--fg2);padding:4px 8px}
.modal-body{padding:24px}
.finding-item{padding:12px 16px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px}
.finding-item .sev{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;text-transform:uppercase;margin-right:8px}
.finding-item .sev.critical{background:var(--crit-bg);color:var(--crit)}
.finding-item .sev.warning{background:var(--warn-bg);color:var(--warn)}
.finding-item .sev.info{background:var(--info-bg);color:var(--info)}
.finding-item .msg{font-size:14px}
.finding-item .file{font-size:12px;color:var(--fg3);font-family:monospace;margin-top:4px}
.finding-item .evidence{font-size:12px;color:var(--fg2);font-family:monospace;background:var(--bg2);padding:6px 10px;border-radius:4px;margin-top:6px;white-space:pre-wrap;word-break:break-all}
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{.theme-toggle,.filter-bar,.modal-overlay{display:none!important}.repo-card{break-inside:avoid}}
@media(max-width:768px){.dashboard{grid-template-columns:repeat(2,1fr)}.repo-grid{grid-template-columns:1fr}.header{flex-direction:column;gap:16px}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade" style="background:${gradeColor}">${overallGrade}</div>
      <div>
        <h1>Vibe Audit — Morning Scan</h1>
        <div style="color:var(--fg2);font-size:14px">${agg.totalRepos} repos scanned &middot; ${now} UTC</div>
      </div>
    </div>
    <div class="header-meta">
      <span>${agg.totalFindings} findings</span>
      <button class="theme-toggle" onclick="toggleTheme()">Theme</button>
    </div>
  </div>

  <div class="dashboard">
    <div class="stat-card">
      <div class="label">Repos Scanned</div>
      <div class="value">${agg.totalRepos}</div>
      <div class="sub">${results.filter(r => r.error).length} errors</div>
    </div>
    <div class="stat-card crit">
      <div class="label">Critical</div>
      <div class="value">${agg.totalCriticals}</div>
      <div class="sub">across ${results.filter(r => r.criticals > 0).length} repos</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Warnings</div>
      <div class="value">${agg.totalWarnings}</div>
      <div class="sub">across ${results.filter(r => r.warnings > 0).length} repos</div>
    </div>
    <div class="stat-card info">
      <div class="label">Info</div>
      <div class="value">${agg.totalInfos}</div>
    </div>
    <div class="stat-card ok">
      <div class="label">Clean Repos</div>
      <div class="value" style="color:var(--ok)">${agg.gradeDistribution['A'] || 0}</div>
      <div class="sub">grade A (no issues)</div>
    </div>
  </div>

  <!-- Grade Distribution -->
  <div class="section">
    <div class="section-title">Grade Distribution</div>
    <div class="grade-bar">
      ${['F', 'D', 'C', 'B', 'A'].map(g => {
        const count = agg.gradeDistribution[g] || 0;
        if (count === 0) return '';
        const pct = Math.max(((count / agg.totalRepos) * 100), 3);
        const color = repoGradeColor(g);
        return `<div class="grade-bar-seg" style="flex:${pct};background:${color}" title="${g}: ${count} repos">${g} (${count})</div>`;
      }).join('')}
    </div>
  </div>

  <!-- Top Rules Across All Repos -->
  ${agg.topRules.length > 0 ? `
  <div class="section">
    <div class="section-title">Most Common Issues</div>
    <table class="rules-table">
      <thead><tr><th>Rule</th><th>Occurrences</th><th style="width:40%">Distribution</th></tr></thead>
      <tbody>
        ${agg.topRules.slice(0, 15).map(r => {
          const pct = Math.round((r.count / agg.totalFindings) * 100);
          const color = r.count > 10 ? 'var(--crit)' : r.count > 3 ? 'var(--warn)' : 'var(--info)';
          return `<tr>
            <td style="font-family:monospace;font-size:13px">${esc(r.ruleId)}</td>
            <td><strong>${r.count}</strong></td>
            <td><div class="rule-bar"><div class="rule-bar-fill" style="width:${Math.max(pct, 2)}%;background:${color}"></div></div></td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>
  </div>` : ''}

  <!-- Repo Cards -->
  <div class="section">
    <div class="section-title">All Repos (${agg.totalRepos})</div>
    <div class="filter-bar">
      <input type="text" id="repo-search" placeholder="Search repos..." oninput="filterRepos()">
      <button class="filter-btn active" data-grade="all" onclick="setGradeFilter('all',this)">All</button>
      <button class="filter-btn" data-grade="F" onclick="setGradeFilter('F',this)">F (${agg.gradeDistribution['F'] || 0})</button>
      <button class="filter-btn" data-grade="D" onclick="setGradeFilter('D',this)">D (${agg.gradeDistribution['D'] || 0})</button>
      <button class="filter-btn" data-grade="C" onclick="setGradeFilter('C',this)">C (${agg.gradeDistribution['C'] || 0})</button>
      <button class="filter-btn" data-grade="B" onclick="setGradeFilter('B',this)">B (${agg.gradeDistribution['B'] || 0})</button>
      <button class="filter-btn" data-grade="A" onclick="setGradeFilter('A',this)">A (${agg.gradeDistribution['A'] || 0})</button>
    </div>
    <div class="repo-grid" id="repo-grid">
      ${sorted.map((r, idx) => `
      <div class="repo-card" data-grade="${r.grade}" data-name="${esc(`${r.owner}/${r.repo}`).toLowerCase()}" onclick="showFindings(${idx})">
        <div class="repo-card-header">
          <div class="repo-grade" style="background:${repoGradeColor(r.grade)}">${r.grade}</div>
          <div class="repo-name">${esc(r.owner)}/<strong>${esc(r.repo)}</strong></div>
        </div>
        <div class="repo-counts">
          ${r.criticals > 0 ? `<span class="repo-count c">${r.criticals} critical</span>` : ''}
          ${r.warnings > 0 ? `<span class="repo-count w">${r.warnings} warning</span>` : ''}
          ${r.infos > 0 ? `<span class="repo-count i">${r.infos} info</span>` : ''}
          ${r.findings.length === 0 && !r.error ? '<span style="color:var(--ok);font-size:12px;font-weight:600">Clean</span>' : ''}
        </div>
        <div class="repo-time">${r.durationMs}ms${r.error ? '' : ` &middot; ${r.findings.length} findings`}</div>
        ${r.error ? `<div class="repo-error">Error: ${esc(r.error.slice(0, 80))}</div>` : ''}
      </div>
      `).join('')}
    </div>
  </div>

  <div class="footer">
    Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a> &middot;
    ${agg.totalRepos} repos &middot; ${agg.totalFindings} findings &middot; ${now} UTC
  </div>
</div>

<!-- Findings Modal -->
<div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-header">
      <h2 id="modal-title">Findings</h2>
      <button class="modal-close" onclick="closeModal()">&times;</button>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<script>
const RESULTS=${JSON.stringify(sorted.map(r => ({
  owner: r.owner,
  repo: r.repo,
  grade: r.grade,
  findings: r.findings.map(f => ({
    severity: f.severity,
    message: f.message,
    file: f.file,
    line: f.line,
    evidence: f.evidence,
    fix: f.fix,
    ruleId: f.ruleId,
    cweId: f.cweId,
    cvssScore: f.cvssScore,
  })),
  error: r.error,
})))};

function toggleTheme(){
  const h=document.documentElement;
  h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';
}

let currentGrade='all';
function setGradeFilter(g,btn){
  currentGrade=g;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  filterRepos();
}
function filterRepos(){
  const q=document.getElementById('repo-search').value.toLowerCase();
  document.querySelectorAll('.repo-card').forEach(card=>{
    const matchG=currentGrade==='all'||card.dataset.grade===currentGrade;
    const matchQ=!q||card.dataset.name.includes(q);
    card.style.display=matchG&&matchQ?'':'none';
  });
}

function showFindings(idx){
  const r=RESULTS[idx];
  document.getElementById('modal-title').textContent=r.owner+'/'+r.repo+' — Grade '+r.grade;
  const body=document.getElementById('modal-body');

  if(r.error){
    body.innerHTML='<div style="color:var(--crit)">Error: '+esc(r.error)+'</div>';
  } else if(r.findings.length===0){
    body.innerHTML='<div style="color:var(--ok);font-weight:600">No issues found.</div>';
  } else {
    body.innerHTML=r.findings.map(f=>{
      let html='<div class="finding-item">';
      html+='<span class="sev '+f.severity+'">'+f.severity+'</span>';
      html+='<span class="msg">'+esc(f.message)+'</span>';
      html+='<div class="file">'+esc(f.file)+(f.line?':'+f.line:'')+'</div>';
      if(f.evidence) html+='<div class="evidence">'+esc(f.evidence)+'</div>';
      html+='<div style="font-size:12px;color:var(--fg2);margin-top:6px">Fix: '+esc(f.fix)+'</div>';
      html+='</div>';
      return html;
    }).join('');
  }

  document.getElementById('modal').classList.add('open');
}
function closeModal(){document.getElementById('modal').classList.remove('open')}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal()});

function esc(s){
  if(!s)return '';
  const d=document.createElement('div');
  d.textContent=String(s);
  return d.innerHTML;
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
