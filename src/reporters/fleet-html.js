/**
 * Fleet HTML Report — Morning dashboard across all repos.
 *
 * Single self-contained HTML file with:
 *   - Org-wide health summary (grade distribution, total findings)
 *   - Repo cards sorted worst-first with severity breakdown
 *   - Drill-down: expand any repo to see its findings
 *   - Trend-ready JSON blob embedded for future charting
 *   - Dark mode, search/filter, print-friendly
 *   - Zero external dependencies
 */

/**
 * @param {import('../fleet.js').RepoResult[]} results
 * @param {Object} summary
 * @returns {string} Complete HTML document
 */
export function generateFleetHTML(results, summary) {
  const now = new Date().toISOString().split('T')[0];

  const gradeColors = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444', '?': '#94a3b8' };

  const topFindings = new Map();
  for (const r of results) {
    for (const f of r.findings) {
      topFindings.set(f.ruleId, (topFindings.get(f.ruleId) || 0) + 1);
    }
  }
  const topRules = [...topFindings.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit Fleet Report — ${now}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#ffffff;--bg2:#f8fafc;--bg3:#f1f5f9;--fg:#0f172a;--fg2:#475569;--fg3:#94a3b8;--border:#e2e8f0;--card:#ffffff;--shadow:0 1px 3px rgba(0,0,0,.1);--crit:#ef4444;--crit-bg:#fef2f2;--warn:#eab308;--warn-bg:#fefce8;--info:#06b6d4;--info-bg:#ecfeff;--ok:#22c55e;--ok-bg:#f0fdf4;--accent:#6366f1;--radius:12px;--err:#f97316;--err-bg:#fff7ed}
[data-theme="dark"]{--bg:#0f172a;--bg2:#1e293b;--bg3:#334155;--fg:#f1f5f9;--fg2:#94a3b8;--fg3:#64748b;--border:#334155;--card:#1e293b;--shadow:0 1px 3px rgba(0,0,0,.4);--crit-bg:#450a0a;--warn-bg:#422006;--info-bg:#083344;--ok-bg:#052e16;--err-bg:#431407}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}
.container{max-width:1400px;margin:0 auto;padding:24px}
.header{display:flex;align-items:center;justify-content:space-between;padding:24px 0;border-bottom:1px solid var(--border);margin-bottom:32px}
.header h1{font-size:28px;display:flex;align-items:center;gap:12px}
.header-right{display:flex;gap:12px;align-items:center}
.header-right span{font-size:13px;color:var(--fg2)}
.theme-toggle{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:14px;color:var(--fg)}
.theme-toggle:hover{background:var(--border)}
/* KPIs */
.kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:32px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow);text-align:center}
.kpi .label{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--fg3)}
.kpi .value{font-size:36px;font-weight:800;margin:4px 0}
.kpi .sub{font-size:12px;color:var(--fg2)}
.kpi.crit .value{color:var(--crit)} .kpi.warn .value{color:var(--warn)} .kpi.info .value{color:var(--info)} .kpi.ok .value{color:var(--ok)} .kpi.err .value{color:var(--err)}
/* Grade distribution */
.grade-row{display:flex;gap:12px;justify-content:center;margin-bottom:32px;flex-wrap:wrap}
.grade-pill{display:flex;flex-direction:column;align-items:center;gap:4px;padding:12px 20px;border-radius:var(--radius);background:var(--card);border:2px solid var(--border);box-shadow:var(--shadow);min-width:70px}
.grade-pill .g{font-size:28px;font-weight:800}
.grade-pill .c{font-size:13px;color:var(--fg2)}
/* Top rules */
.top-rules{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow);margin-bottom:32px}
.top-rules h3{font-size:16px;margin-bottom:12px}
.rule-bar{display:flex;align-items:center;gap:12px;padding:6px 0}
.rule-bar .name{font-family:monospace;font-size:13px;width:260px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rule-bar .bar{flex:1;height:20px;background:var(--bg3);border-radius:4px;overflow:hidden}
.rule-bar .bar-fill{height:100%;border-radius:4px;background:var(--accent);transition:width .5s}
.rule-bar .count{font-size:13px;font-weight:600;width:40px;text-align:right}
/* Filter */
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:var(--card);cursor:pointer;font-size:13px;color:var(--fg2);transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
/* Repo cards */
.repo-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden;box-shadow:var(--shadow)}
.repo-header{display:flex;align-items:center;gap:12px;padding:16px 20px;cursor:pointer;user-select:none}
.repo-header:hover{background:var(--bg2)}
.repo-grade{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:#fff;flex-shrink:0}
.repo-name{flex:1;font-size:15px;font-weight:600}
.repo-name a{color:var(--fg)}
.repo-name a:hover{color:var(--accent)}
.repo-counts{display:flex;gap:8px;flex-shrink:0}
.repo-count{padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}
.repo-count.c{background:var(--crit-bg);color:var(--crit)}
.repo-count.w{background:var(--warn-bg);color:var(--warn)}
.repo-count.i{background:var(--info-bg);color:var(--info)}
.repo-count.e{background:var(--err-bg);color:var(--err)}
.repo-time{font-size:12px;color:var(--fg3);width:60px;text-align:right;flex-shrink:0}
.chevron{transition:transform .2s;color:var(--fg3);flex-shrink:0}
.chevron.open{transform:rotate(90deg)}
.repo-body{display:none;border-top:1px solid var(--border);padding:16px 20px}
.repo-body.open{display:block}
.repo-body table{width:100%;border-collapse:collapse;font-size:13px}
.repo-body th{text-align:left;padding:6px 8px;border-bottom:2px solid var(--border);font-weight:600;color:var(--fg2);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.repo-body td{padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
.sev-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.sev-dot.critical{background:var(--crit)} .sev-dot.warning{background:var(--warn)} .sev-dot.info{background:var(--info)}
.evidence{font-family:monospace;font-size:11px;color:var(--fg2);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* Footer */
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{.theme-toggle,.filter-bar,.chevron{display:none!important}.repo-body{display:block!important}.repo-card{break-inside:avoid;box-shadow:none;border:1px solid #ccc}body{background:#fff;color:#000}}
@media(max-width:768px){.kpi-row{grid-template-columns:repeat(2,1fr)}.header{flex-direction:column;gap:16px;text-align:center}.header-right{flex-wrap:wrap;justify-content:center}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>&#9878;&#65039; Vibe Audit Fleet Report</h1>
      <div style="color:var(--fg2);font-size:14px">Morning security scan across ${summary.reposScanned} repositories &middot; ${now}</div>
    </div>
    <div class="header-right">
      <span>${summary.reposScanned} repos</span>
      <span>${summary.totalFindings} findings</span>
      <button class="theme-toggle" onclick="toggleTheme()">&#127763; Theme</button>
    </div>
  </div>

  <!-- KPIs -->
  <div class="kpi-row">
    <div class="kpi ok">
      <div class="label">Repos Scanned</div>
      <div class="value">${summary.reposScanned}</div>
      <div class="sub">${summary.reposFailed} failed</div>
    </div>
    <div class="kpi crit">
      <div class="label">Critical</div>
      <div class="value">${summary.totalCritical}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="kpi warn">
      <div class="label">Warnings</div>
      <div class="value">${summary.totalWarning}</div>
      <div class="sub">across all repos</div>
    </div>
    <div class="kpi info">
      <div class="label">Info</div>
      <div class="value">${summary.totalInfo}</div>
      <div class="sub">best practices</div>
    </div>
    <div class="kpi">
      <div class="label">Total Findings</div>
      <div class="value" style="color:var(--fg)">${summary.totalFindings}</div>
      <div class="sub">${results.filter(r => r.findings.length > 0).length} repos affected</div>
    </div>
  </div>

  <!-- Grade Distribution -->
  <div style="text-align:center;margin-bottom:8px;font-size:16px;font-weight:700">Grade Distribution</div>
  <div class="grade-row">
    ${['A', 'B', 'C', 'D', 'F'].map(g =>
      `<div class="grade-pill"><div class="g" style="color:${gradeColors[g]}">${g}</div><div class="c">${summary.gradeDistribution[g] || 0} repos</div></div>`
    ).join('\n    ')}
    ${summary.gradeDistribution['?'] > 0 ? `<div class="grade-pill"><div class="g" style="color:${gradeColors['?']}">?</div><div class="c">${summary.gradeDistribution['?']} errors</div></div>` : ''}
  </div>

  <!-- Top Rules -->
  ${topRules.length > 0 ? `
  <div class="top-rules">
    <h3>Top 10 Most Common Issues</h3>
    ${topRules.map(([ruleId, count]) => {
      const maxCount = topRules[0][1];
      const pct = Math.round((count / maxCount) * 100);
      return `<div class="rule-bar">
        <div class="name">${esc(ruleId)}</div>
        <div class="bar"><div class="bar-fill" style="width:${pct}%"></div></div>
        <div class="count">${count}</div>
      </div>`;
    }).join('\n    ')}
  </div>
  ` : ''}

  <!-- Repo list -->
  <div style="font-size:20px;font-weight:700;margin-bottom:16px">All Repositories</div>
  <div class="filter-bar">
    <input type="text" id="search" placeholder="Search repos..." oninput="filterRepos()">
    <button class="filter-btn active" data-grade="all" onclick="setGradeFilter('all',this)">All (${results.length})</button>
    <button class="filter-btn" data-grade="F" onclick="setGradeFilter('F',this)">F (${summary.gradeDistribution.F || 0})</button>
    <button class="filter-btn" data-grade="D" onclick="setGradeFilter('D',this)">D (${summary.gradeDistribution.D || 0})</button>
    <button class="filter-btn" data-grade="C" onclick="setGradeFilter('C',this)">C (${summary.gradeDistribution.C || 0})</button>
    <button class="filter-btn" data-grade="B" onclick="setGradeFilter('B',this)">B (${summary.gradeDistribution.B || 0})</button>
    <button class="filter-btn" data-grade="A" onclick="setGradeFilter('A',this)">A (${summary.gradeDistribution.A || 0})</button>
  </div>

  <div id="repo-list">
    ${results.map((r) => `
    <div class="repo-card" data-grade="${r.grade}" data-search="${esc(r.fullName).toLowerCase()}">
      <div class="repo-header" onclick="toggleRepo(this)">
        <div class="repo-grade" style="background:${gradeColors[r.grade] || gradeColors['?']}">${r.grade}</div>
        <div class="repo-name"><a href="https://github.com/${esc(r.fullName)}" target="_blank">${esc(r.fullName)}</a></div>
        <div class="repo-counts">
          ${r.error ? `<span class="repo-count e">error</span>` : ''}
          ${r.counts.critical > 0 ? `<span class="repo-count c">${r.counts.critical} crit</span>` : ''}
          ${r.counts.warning > 0 ? `<span class="repo-count w">${r.counts.warning} warn</span>` : ''}
          ${r.counts.info > 0 ? `<span class="repo-count i">${r.counts.info} info</span>` : ''}
          ${!r.error && r.findings.length === 0 ? `<span style="color:var(--ok);font-size:12px;font-weight:600">&#10003; clean</span>` : ''}
        </div>
        <div class="repo-time">${r.durationMs > 1000 ? (r.durationMs / 1000).toFixed(1) + 's' : r.durationMs + 'ms'}</div>
        <span class="chevron">&#9654;</span>
      </div>
      <div class="repo-body">
        ${r.error ? `<div style="color:var(--err);padding:8px 0">${esc(r.error)}</div>` : ''}
        ${r.findings.length > 0 ? `
        <table>
          <thead><tr><th>Sev</th><th>Rule</th><th>File</th><th>Message</th><th>CWE</th></tr></thead>
          <tbody>
            ${r.findings.map(f => `<tr>
              <td><span class="sev-dot ${f.severity}"></span>${f.severity}</td>
              <td style="font-family:monospace;font-size:12px">${esc(f.ruleId)}</td>
              <td style="font-family:monospace;font-size:12px">${esc(f.file)}${f.line ? ':' + f.line : ''}</td>
              <td>${esc(f.message)}</td>
              <td style="font-size:12px;color:var(--fg2)">${f.cweId || ''}</td>
            </tr>`).join('\n            ')}
          </tbody>
        </table>
        ` : (!r.error ? '<div style="color:var(--ok)">No issues found.</div>' : '')}
      </div>
    </div>
    `).join('')}
  </div>

  <div class="footer">
    &#9878;&#65039; Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a> Fleet Scanner &middot;
    ${summary.reposScanned} repos &middot; ${summary.totalFindings} findings &middot; ${now}<br>
    Built by <a href="https://digitalalchemy.dev">Digital Alchemy Academy</a>
  </div>
</div>

<!-- Embedded JSON for programmatic consumption / future trend tracking -->
<script id="fleet-data" type="application/json">${JSON.stringify({ summary, repos: results.map(r => ({ fullName: r.fullName, grade: r.grade, counts: r.counts, error: r.error })) })}</script>

<script>
function toggleTheme(){
  const h=document.documentElement;
  h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';
}
function toggleRepo(el){
  const body=el.nextElementSibling;
  const chev=el.querySelector('.chevron');
  body.classList.toggle('open');
  chev.classList.toggle('open');
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
    const matchGrade=currentGrade==='all'||card.dataset.grade===currentGrade;
    const matchQ=!q||card.dataset.search.includes(q);
    card.style.display=matchGrade&&matchQ?'':'none';
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
