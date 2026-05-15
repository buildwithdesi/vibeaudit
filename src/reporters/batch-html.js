/**
 * Batch HTML Report — Multi-repo security dashboard.
 *
 * Generates a single self-contained HTML file with:
 *   - Fleet overview: grades, totals, trend-ready data
 *   - Repo-by-repo breakdown with expandable findings
 *   - Heatmap of findings by repo × severity
 *   - Top rules fired across the fleet
 *   - Filterable, sortable, searchable
 *   - Dark mode, print-friendly
 *   - Zero external dependencies
 */

function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * @param {import('../batch.js').RepoResult[]} results
 * @param {number} totalDurationMs
 * @returns {string}
 */
export function generateBatchHTML(results, totalDurationMs) {
  const now = new Date().toISOString().split('T')[0];
  const totalRepos = results.length;
  const scanned = results.filter((r) => !r.error).length;
  const failed = results.filter((r) => r.error).length;
  const totalFindings = results.reduce((s, r) => s + r.total, 0);
  const totalCritical = results.reduce((s, r) => s + r.critical, 0);
  const totalWarning = results.reduce((s, r) => s + r.warning, 0);
  const totalInfo = results.reduce((s, r) => s + r.info, 0);

  // Grade distribution
  const gradeCounts = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of results) {
    if (r.grade in gradeCounts) gradeCounts[r.grade]++;
  }

  // Top rules across fleet
  const ruleCounts = new Map();
  for (const r of results) {
    for (const f of r.findings) {
      ruleCounts.set(f.ruleId, (ruleCounts.get(f.ruleId) || 0) + 1);
    }
  }
  const topRules = [...ruleCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15);

  // Fleet grade
  const fleetGrade = totalCritical > 0 ? 'F' : totalWarning > 10 ? 'D' : totalWarning > 0 ? 'C' : totalInfo > 0 ? 'B' : 'A';
  const gradeColor = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[fleetGrade];

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit — Fleet Report ${now}</title>
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
.grade-dist{display:flex;gap:2px;height:40px;border-radius:8px;overflow:hidden;margin-bottom:8px}
.grade-dist div{display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:14px;min-width:30px;transition:flex .3s}
.grade-labels{display:flex;gap:16px;font-size:13px;color:var(--fg2)}
.grade-labels span{display:flex;align-items:center;gap:4px}
.grade-dot{width:12px;height:12px;border-radius:50%;display:inline-block}
/* Top rules */
.rule-bar-row{display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--border)}
.rule-bar-row:last-child{border-bottom:none}
.rule-bar-label{width:260px;font-family:monospace;font-size:13px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rule-bar{flex:1;height:24px;background:var(--bg3);border-radius:4px;overflow:hidden}
.rule-bar-fill{height:100%;border-radius:4px;transition:width .5s}
.rule-bar-count{width:40px;text-align:right;font-size:13px;font-weight:600;flex-shrink:0}
/* Repo table */
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:var(--card);cursor:pointer;font-size:13px;color:var(--fg2);transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.repo-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden;box-shadow:var(--shadow)}
.repo-header{display:flex;align-items:center;gap:12px;padding:16px 20px;cursor:pointer;user-select:none}
.repo-header:hover{background:var(--bg2)}
.repo-grade{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:800;color:#fff;flex-shrink:0}
.repo-name{flex:1;font-size:15px;font-weight:600;font-family:monospace}
.repo-counts{display:flex;gap:8px;flex-shrink:0}
.count-badge{padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}
.count-badge.c{background:var(--crit-bg);color:var(--crit)}
.count-badge.w{background:var(--warn-bg);color:var(--warn)}
.count-badge.i{background:var(--info-bg);color:var(--info)}
.repo-time{font-size:12px;color:var(--fg3);width:50px;text-align:right;flex-shrink:0}
.chevron{transition:transform .2s;color:var(--fg3);flex-shrink:0}
.chevron.open{transform:rotate(90deg)}
.repo-body{display:none;border-top:1px solid var(--border);padding:16px 20px}
.repo-body.open{display:block}
.finding-row{display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);font-size:13px}
.finding-row:last-child{border-bottom:none}
.sev-badge{padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;text-transform:uppercase;flex-shrink:0}
.sev-badge.critical{background:var(--crit-bg);color:var(--crit)}
.sev-badge.warning{background:var(--warn-bg);color:var(--warn)}
.sev-badge.info{background:var(--info-bg);color:var(--info)}
.finding-msg{flex:1}
.finding-file{font-family:monospace;font-size:12px;color:var(--fg3);flex-shrink:0}
.meta-badge{padding:1px 6px;border-radius:4px;font-size:10px;background:var(--bg3);color:var(--fg2);font-family:monospace;margin-left:4px}
.error-banner{background:var(--crit-bg);color:var(--crit);padding:12px 16px;border-radius:8px;font-size:13px}
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{.theme-toggle,.filter-bar,.chevron{display:none!important}.repo-body{display:block!important}.repo-card{break-inside:avoid;box-shadow:none}}
@media(max-width:768px){.dashboard{grid-template-columns:repeat(2,1fr)}.header{flex-direction:column;gap:16px;text-align:center}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade" style="background:${gradeColor}">${fleetGrade}</div>
      <div>
        <h1>Vibe Audit — Fleet Report</h1>
        <div style="color:var(--fg2);font-size:14px">Morning security scan across ${totalRepos} repos &middot; ${now}</div>
      </div>
    </div>
    <div class="header-meta">
      <span>${scanned} scanned</span>
      ${failed > 0 ? `<span style="color:var(--crit)">${failed} failed</span>` : ''}
      <span>${(totalDurationMs / 1000).toFixed(1)}s</span>
      <button class="theme-toggle" onclick="toggleTheme()">Theme</button>
    </div>
  </div>

  <div class="dashboard">
    <div class="stat-card">
      <div class="label">Repos Scanned</div>
      <div class="value">${scanned}</div>
      <div class="sub">${failed > 0 ? `${failed} failed` : 'all successful'}</div>
    </div>
    <div class="stat-card crit">
      <div class="label">Critical</div>
      <div class="value">${totalCritical}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Warnings</div>
      <div class="value">${totalWarning}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="stat-card info">
      <div class="label">Info</div>
      <div class="value">${totalInfo}</div>
      <div class="sub">best practices</div>
    </div>
    <div class="stat-card">
      <div class="label">Total Findings</div>
      <div class="value">${totalFindings}</div>
      <div class="sub">${(totalFindings / Math.max(scanned, 1)).toFixed(1)} avg/repo</div>
    </div>
  </div>

  <!-- Grade Distribution -->
  <div class="section">
    <div class="section-title">Grade Distribution</div>
    <div class="grade-dist">
      ${gradeCounts.A > 0 ? `<div style="flex:${gradeCounts.A};background:#22c55e">${gradeCounts.A} A</div>` : ''}
      ${gradeCounts.B > 0 ? `<div style="flex:${gradeCounts.B};background:#86efac;color:#0f172a">${gradeCounts.B} B</div>` : ''}
      ${gradeCounts.C > 0 ? `<div style="flex:${gradeCounts.C};background:#eab308;color:#0f172a">${gradeCounts.C} C</div>` : ''}
      ${gradeCounts.D > 0 ? `<div style="flex:${gradeCounts.D};background:#f97316">${gradeCounts.D} D</div>` : ''}
      ${gradeCounts.F > 0 ? `<div style="flex:${gradeCounts.F};background:#ef4444">${gradeCounts.F} F</div>` : ''}
    </div>
    <div class="grade-labels">
      <span><span class="grade-dot" style="background:#22c55e"></span> A: ${gradeCounts.A}</span>
      <span><span class="grade-dot" style="background:#86efac"></span> B: ${gradeCounts.B}</span>
      <span><span class="grade-dot" style="background:#eab308"></span> C: ${gradeCounts.C}</span>
      <span><span class="grade-dot" style="background:#f97316"></span> D: ${gradeCounts.D}</span>
      <span><span class="grade-dot" style="background:#ef4444"></span> F: ${gradeCounts.F}</span>
    </div>
  </div>

  <!-- Top Rules -->
  ${topRules.length > 0 ? `
  <div class="section">
    <div class="section-title">Top Rules Fired</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;box-shadow:var(--shadow)">
      ${topRules.map(([ruleId, count]) => {
        const pct = Math.round((count / totalFindings) * 100);
        const color = count > 10 ? 'var(--crit)' : count > 5 ? 'var(--warn)' : 'var(--info)';
        return `<div class="rule-bar-row">
          <div class="rule-bar-label">${esc(ruleId)}</div>
          <div class="rule-bar"><div class="rule-bar-fill" style="width:${Math.max(pct, 2)}%;background:${color}"></div></div>
          <div class="rule-bar-count">${count}</div>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>
  ` : ''}

  <!-- Repos -->
  <div class="section">
    <div class="section-title">Repos (${totalRepos})</div>
    <div class="filter-bar">
      <input type="text" id="search" placeholder="Search repos..." oninput="filterRepos()">
      <button class="filter-btn active" data-grade="all" onclick="setGradeFilter('all',this)">All</button>
      <button class="filter-btn" data-grade="F" onclick="setGradeFilter('F',this)">F (${gradeCounts.F})</button>
      <button class="filter-btn" data-grade="D" onclick="setGradeFilter('D',this)">D (${gradeCounts.D})</button>
      <button class="filter-btn" data-grade="C" onclick="setGradeFilter('C',this)">C (${gradeCounts.C})</button>
      <button class="filter-btn" data-grade="B" onclick="setGradeFilter('B',this)">B (${gradeCounts.B})</button>
      <button class="filter-btn" data-grade="A" onclick="setGradeFilter('A',this)">A (${gradeCounts.A})</button>
    </div>
    <div id="repo-list">
      ${results.map((r) => {
        const gc = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444', '-': '#94a3b8' }[r.grade] || '#94a3b8';
        return `
      <div class="repo-card" data-grade="${r.grade}" data-search="${esc(r.repo).toLowerCase()}">
        <div class="repo-header" onclick="toggleRepo(this)">
          <div class="repo-grade" style="background:${gc}">${r.grade}</div>
          <div class="repo-name">${esc(r.repo)}</div>
          <div class="repo-counts">
            ${r.critical > 0 ? `<span class="count-badge c">${r.critical} crit</span>` : ''}
            ${r.warning > 0 ? `<span class="count-badge w">${r.warning} warn</span>` : ''}
            ${r.info > 0 ? `<span class="count-badge i">${r.info} info</span>` : ''}
            ${r.error ? `<span class="count-badge c">ERROR</span>` : ''}
            ${r.total === 0 && !r.error ? '<span class="count-badge" style="background:var(--ok-bg);color:var(--ok)">clean</span>' : ''}
          </div>
          <div class="repo-time">${(r.durationMs / 1000).toFixed(1)}s</div>
          <span class="chevron">&#9654;</span>
        </div>
        <div class="repo-body">
          ${r.error ? `<div class="error-banner">${esc(r.error)}</div>` : ''}
          ${r.findings.length === 0 && !r.error ? '<div style="color:var(--ok);font-weight:600">No issues found.</div>' : ''}
          ${r.findings.map((f) => `
          <div class="finding-row">
            <span class="sev-badge ${f.severity}">${f.severity}</span>
            <span class="finding-msg">${esc(f.message)}${f.cweId ? `<span class="meta-badge">${f.cweId}</span>` : ''}${f.cvssScore ? `<span class="meta-badge">CVSS ${f.cvssScore}</span>` : ''}</span>
            <span class="finding-file">${esc(f.file)}${f.line ? ':' + f.line : ''}</span>
          </div>
          `).join('')}
        </div>
      </div>`;
      }).join('\n')}
    </div>
  </div>

  <div class="footer">
    Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a> &middot;
    ${totalRepos} repos &middot; ${totalFindings} findings &middot; ${(totalDurationMs / 1000).toFixed(1)}s &middot; ${now}
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
let currentGrade='all';
function setGradeFilter(g,btn){
  currentGrade=g;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  filterRepos();
}
function filterRepos(){
  const q=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.repo-card').forEach(card=>{
    const matchG=currentGrade==='all'||card.dataset.grade===currentGrade;
    const matchQ=!q||card.dataset.search.includes(q);
    card.style.display=matchG&&matchQ?'':'none';
  });
}
</script>
</body>
</html>`;
}
