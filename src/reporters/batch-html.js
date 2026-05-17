/**
 * Batch HTML Report — Org-wide security dashboard.
 *
 * Generates a single self-contained HTML file with:
 *   - Org-level executive summary (grades, finding counts)
 *   - Per-repo grade heatmap / sortable table
 *   - Top offending rules across all repos
 *   - OWASP Top 10 breakdown across the entire org
 *   - Drill-down per repo with findings
 *   - Dark mode, search/filter, print-friendly
 *   - Zero external dependencies
 */

/**
 * @param {import('../batch.js').RepoResult[]} results
 * @param {object} summary
 * @returns {string} Complete HTML document
 */
export function generateBatchHTML(results, summary) {
  const now = new Date().toISOString().split('T')[0];
  const { grades, totalCriticals, totalWarnings, totalInfos, totalFindings, totalFiles, topRules } = summary;

  const orgGrade = totalCriticals > 0 ? 'F'
    : totalWarnings > (results.length * 3) ? 'D'
    : totalWarnings > 0 ? 'C'
    : totalInfos > 0 ? 'B' : 'A';
  const gradeColor = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[orgGrade] || '#94a3b8';

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

  const allFindings = results.flatMap(r => r.findings.map(f => ({ ...f, _repo: r.fullName })));
  const byOwasp = new Map();
  for (const f of allFindings) {
    const cat = f.owaspCategory || 'Unknown';
    byOwasp.set(cat, (byOwasp.get(cat) || 0) + 1);
  }

  const sortedResults = [...results].sort((a, b) => {
    const order = { F: 0, D: 1, C: 2, '?': 3, B: 4, A: 5 };
    return (order[a.grade] ?? 3) - (order[b.grade] ?? 3);
  });

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit — Batch Report ${now}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#ffffff;--bg2:#f8fafc;--bg3:#f1f5f9;--fg:#0f172a;--fg2:#475569;--fg3:#94a3b8;--border:#e2e8f0;--card:#ffffff;--shadow:0 1px 3px rgba(0,0,0,.1);--crit:#ef4444;--crit-bg:#fef2f2;--warn:#eab308;--warn-bg:#fefce8;--info:#06b6d4;--info-bg:#ecfeff;--ok:#22c55e;--ok-bg:#f0fdf4;--accent:#6366f1;--radius:12px}
[data-theme="dark"]{--bg:#0f172a;--bg2:#1e293b;--bg3:#334155;--fg:#f1f5f9;--fg2:#94a3b8;--fg3:#64748b;--border:#334155;--card:#1e293b;--shadow:0 1px 3px rgba(0,0,0,.4);--crit-bg:#450a0a;--warn-bg:#422006;--info-bg:#083344;--ok-bg:#052e16}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}
.container{max-width:1400px;margin:0 auto;padding:24px}
.header{display:flex;align-items:center;justify-content:space-between;padding:24px 0;border-bottom:1px solid var(--border);margin-bottom:32px}
.header h1{font-size:28px;display:flex;align-items:center;gap:12px}
.header-meta{display:flex;gap:16px;align-items:center}
.header-meta span{font-size:13px;color:var(--fg2)}
.theme-toggle{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:14px;color:var(--fg)}
.theme-toggle:hover{background:var(--border)}
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
/* Grade distribution */
.grade-dist{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.grade-pill{display:flex;align-items:center;gap:8px;padding:10px 20px;border-radius:var(--radius);background:var(--card);border:1px solid var(--border);box-shadow:var(--shadow)}
.grade-pill .g{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:#fff}
.grade-pill .count{font-size:24px;font-weight:700}
.grade-pill .pct{font-size:12px;color:var(--fg3)}
/* Repo table */
.repo-table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
.repo-table th{text-align:left;padding:12px 16px;background:var(--bg2);font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg3);cursor:pointer;user-select:none;border-bottom:1px solid var(--border)}
.repo-table th:hover{color:var(--fg)}
.repo-table td{padding:12px 16px;border-bottom:1px solid var(--border);font-size:14px}
.repo-table tr:last-child td{border-bottom:none}
.repo-table tr:hover td{background:var(--bg2)}
.mini-grade{width:28px;height:28px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff}
.sev-badge{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;display:inline-block}
.sev-badge.c{background:var(--crit-bg);color:var(--crit)}
.sev-badge.w{background:var(--warn-bg);color:var(--warn)}
.sev-badge.i{background:var(--info-bg);color:var(--info)}
.sev-badge.ok{background:var(--ok-bg);color:var(--ok)}
.sev-badge.err{background:var(--bg3);color:var(--fg3)}
/* Top rules */
.rule-bar{display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border)}
.rule-bar:last-child{border-bottom:none}
.rule-bar .bar{flex:1;height:8px;background:var(--bg3);border-radius:4px;overflow:hidden}
.rule-bar .bar-fill{height:100%;border-radius:4px}
.rule-bar .count{font-weight:700;min-width:32px;text-align:right}
.rule-bar .name{min-width:250px;font-family:monospace;font-size:13px}
/* OWASP grid */
.owasp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.owasp-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow)}
.owasp-card .cat-id{font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase}
.owasp-card .cat-name{font-size:14px;font-weight:600;margin:4px 0}
.owasp-card .cat-count{font-size:24px;font-weight:700}
.owasp-bar{height:6px;background:var(--bg3);border-radius:3px;margin-top:8px;overflow:hidden}
.owasp-bar-fill{height:100%;border-radius:3px}
/* Drill-down */
.drill{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden;box-shadow:var(--shadow)}
.drill-header{display:flex;align-items:center;gap:12px;padding:16px 20px;cursor:pointer;user-select:none}
.drill-header:hover{background:var(--bg2)}
.drill-body{display:none;border-top:1px solid var(--border);padding:16px 20px}
.drill-body.open{display:block}
.finding-row{padding:8px 0;border-bottom:1px solid var(--border);font-size:13px}
.finding-row:last-child{border-bottom:none}
.chevron{transition:transform .2s;color:var(--fg3);flex-shrink:0}
.chevron.open{transform:rotate(90deg)}
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:var(--card);cursor:pointer;font-size:13px;color:var(--fg2);transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{.theme-toggle,.filter-bar,.chevron{display:none!important}.drill-body{display:block!important}}
@media(max-width:768px){.dashboard{grid-template-columns:repeat(2,1fr)}.header{flex-direction:column;gap:16px;text-align:center}.repo-table{font-size:12px}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade" style="background:${gradeColor}">${orgGrade}</div>
      <div>
        <h1>Vibe Audit — Batch Report</h1>
        <div style="color:var(--fg2);font-size:14px">${summary.reposScanned} repositories scanned &middot; ${now}</div>
      </div>
    </div>
    <div class="header-meta">
      <span>${totalFiles} files</span>
      <span>${totalFindings} findings</span>
      <span>${(summary.totalDuration / 1000).toFixed(1)}s</span>
      <button class="theme-toggle" onclick="toggleTheme()">Theme</button>
    </div>
  </div>

  <div class="dashboard">
    <div class="stat-card">
      <div class="label">Repos Scanned</div>
      <div class="value">${summary.reposScanned}</div>
      <div class="sub">${summary.errors > 0 ? summary.errors + ' failed' : 'All successful'}</div>
    </div>
    <div class="stat-card crit">
      <div class="label">Critical</div>
      <div class="value">${totalCriticals}</div>
      <div class="sub">across ${results.filter(r => r.criticals > 0).length} repos</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Warnings</div>
      <div class="value">${totalWarnings}</div>
      <div class="sub">across ${results.filter(r => r.warnings > 0).length} repos</div>
    </div>
    <div class="stat-card info">
      <div class="label">Info</div>
      <div class="value">${totalInfos}</div>
    </div>
    <div class="stat-card ok">
      <div class="label">Clean Repos</div>
      <div class="value">${grades.A || 0}</div>
      <div class="sub">Grade A</div>
    </div>
    <div class="stat-card">
      <div class="label">Total Files</div>
      <div class="value">${totalFiles}</div>
      <div class="sub">${(summary.totalDuration / 1000).toFixed(1)}s total</div>
    </div>
  </div>

  <!-- Grade Distribution -->
  <div class="section">
    <div class="section-title">Grade Distribution</div>
    <div class="grade-dist">
      ${renderGradePill('A', grades.A || 0, '#22c55e', results.length)}
      ${renderGradePill('B', grades.B || 0, '#86efac', results.length)}
      ${renderGradePill('C', grades.C || 0, '#eab308', results.length)}
      ${renderGradePill('D', grades.D || 0, '#f97316', results.length)}
      ${renderGradePill('F', grades.F || 0, '#ef4444', results.length)}
    </div>
  </div>

  <!-- Repository Table -->
  <div class="section">
    <div class="section-title">All Repositories</div>
    <div class="filter-bar">
      <input type="text" id="repoSearch" placeholder="Search repos..." oninput="filterRepos()">
      <button class="filter-btn active" data-grade="all" onclick="setGradeFilter('all',this)">All</button>
      <button class="filter-btn" data-grade="F" onclick="setGradeFilter('F',this)">F (${grades.F || 0})</button>
      <button class="filter-btn" data-grade="D" onclick="setGradeFilter('D',this)">D (${grades.D || 0})</button>
      <button class="filter-btn" data-grade="C" onclick="setGradeFilter('C',this)">C (${grades.C || 0})</button>
      <button class="filter-btn" data-grade="B" onclick="setGradeFilter('B',this)">B (${grades.B || 0})</button>
      <button class="filter-btn" data-grade="A" onclick="setGradeFilter('A',this)">A (${grades.A || 0})</button>
    </div>
    <table class="repo-table">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Grade</th>
          <th onclick="sortTable(1)">Repository</th>
          <th onclick="sortTable(2)">Critical</th>
          <th onclick="sortTable(3)">Warnings</th>
          <th onclick="sortTable(4)">Info</th>
          <th onclick="sortTable(5)">Files</th>
          <th onclick="sortTable(6)">Time</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="repoTableBody">
        ${sortedResults.map(r => {
          const gc = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[r.grade] || '#94a3b8';
          return `<tr data-grade="${esc(r.grade)}" data-repo="${esc(r.fullName.toLowerCase())}">
            <td><span class="mini-grade" style="background:${gc}">${esc(r.grade)}</span></td>
            <td><strong>${esc(r.fullName)}</strong></td>
            <td>${r.criticals > 0 ? `<span class="sev-badge c">${r.criticals}</span>` : '<span class="sev-badge ok">0</span>'}</td>
            <td>${r.warnings > 0 ? `<span class="sev-badge w">${r.warnings}</span>` : '<span class="sev-badge ok">0</span>'}</td>
            <td>${r.infos > 0 ? `<span class="sev-badge i">${r.infos}</span>` : '<span class="sev-badge ok">0</span>'}</td>
            <td>${r.meta.filesScanned}</td>
            <td>${r.meta.durationMs}ms</td>
            <td>${r.error ? `<span class="sev-badge err" title="${esc(r.error)}">error</span>` : '<span class="sev-badge ok">ok</span>'}</td>
          </tr>`;
        }).join('\n        ')}
      </tbody>
    </table>
  </div>

  <!-- Top Rules -->
  ${topRules.length > 0 ? `
  <div class="section">
    <div class="section-title">Top Offending Rules</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)">
      ${topRules.map(([ruleId, count]) => {
        const pct = Math.round((count / totalFindings) * 100);
        const barColor = pct > 20 ? 'var(--crit)' : pct > 10 ? 'var(--warn)' : 'var(--info)';
        return `<div class="rule-bar">
          <span class="count">${count}</span>
          <span class="name">${esc(ruleId)}</span>
          <div class="bar"><div class="bar-fill" style="width:${Math.max(pct, 2)}%;background:${barColor}"></div></div>
          <span style="font-size:12px;color:var(--fg3);min-width:40px">${pct}%</span>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>` : ''}

  <!-- OWASP Breakdown -->
  <div class="section">
    <div class="section-title">OWASP Top 10 (2021) — Org-Wide</div>
    <div class="owasp-grid">
      ${Object.entries(owaspLabels).map(([cat, label]) => {
        const count = byOwasp.get(cat) || 0;
        const pct = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0;
        const barColor = count === 0 ? 'var(--ok)' : count > 10 ? 'var(--crit)' : 'var(--warn)';
        return `<div class="owasp-card">
          <div class="cat-id">${cat}</div>
          <div class="cat-name">${label}</div>
          <div class="cat-count">${count} <span style="font-size:13px;font-weight:400;color:var(--fg2)">finding${count !== 1 ? 's' : ''}</span></div>
          <div class="owasp-bar"><div class="owasp-bar-fill" style="width:${Math.max(pct, 2)}%;background:${barColor}"></div></div>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>

  <!-- Per-repo drill-down -->
  <div class="section">
    <div class="section-title">Per-Repository Details</div>
    ${sortedResults.filter(r => r.findings.length > 0).map(r => {
      const gc = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[r.grade] || '#94a3b8';
      return `<div class="drill">
        <div class="drill-header" onclick="toggleDrill(this)">
          <span class="mini-grade" style="background:${gc}">${esc(r.grade)}</span>
          <strong style="flex:1">${esc(r.fullName)}</strong>
          ${r.criticals > 0 ? `<span class="sev-badge c">${r.criticals} critical</span>` : ''}
          ${r.warnings > 0 ? `<span class="sev-badge w">${r.warnings} warnings</span>` : ''}
          ${r.infos > 0 ? `<span class="sev-badge i">${r.infos} info</span>` : ''}
          <span style="font-size:12px;color:var(--fg3)">${r.meta.filesScanned} files</span>
          <span class="chevron">&#9654;</span>
        </div>
        <div class="drill-body">
          ${r.findings.map(f => {
            const sevClass = f.severity === 'critical' ? 'c' : f.severity === 'warning' ? 'w' : 'i';
            return `<div class="finding-row">
              <span class="sev-badge ${sevClass}">${esc(f.severity)}</span>
              <strong>${esc(f.message)}</strong>
              <span style="color:var(--fg3);font-family:monospace;font-size:12px;margin-left:8px">${esc(f.file)}${f.line ? ':' + f.line : ''}</span>
              ${f.cweId ? `<span style="font-size:11px;color:var(--fg3);margin-left:8px">[${esc(f.cweId)}]</span>` : ''}
              <div style="font-size:12px;color:var(--fg2);margin-top:4px">${esc(f.fix)}</div>
            </div>`;
          }).join('\n          ')}
        </div>
      </div>`;
    }).join('\n    ')}
  </div>

  <div class="footer">
    Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a> &middot;
    ${summary.reposScanned} repos &middot; ${totalFiles} files &middot; ${totalFindings} findings &middot; ${(summary.totalDuration / 1000).toFixed(1)}s &middot; ${now}<br>
    Built by <a href="https://digitalalchemy.dev">Digital Alchemy Academy</a>
  </div>
</div>

<script>
function toggleTheme(){
  const h=document.documentElement;
  h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';
}
function toggleDrill(el){
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
  const q=document.getElementById('repoSearch').value.toLowerCase();
  document.querySelectorAll('#repoTableBody tr').forEach(row=>{
    const matchGrade=currentGrade==='all'||row.dataset.grade===currentGrade;
    const matchQ=!q||row.dataset.repo.includes(q);
    row.style.display=matchGrade&&matchQ?'':'none';
  });
}
let sortCol=-1,sortAsc=true;
function sortTable(col){
  if(sortCol===col)sortAsc=!sortAsc;else{sortCol=col;sortAsc=true}
  const tbody=document.getElementById('repoTableBody');
  const rows=[...tbody.querySelectorAll('tr')];
  rows.sort((a,b)=>{
    let av=a.children[col].textContent.trim();
    let bv=b.children[col].textContent.trim();
    const an=parseFloat(av),bn=parseFloat(bv);
    if(!isNaN(an)&&!isNaN(bn))return sortAsc?an-bn:bn-an;
    return sortAsc?av.localeCompare(bv):bv.localeCompare(av);
  });
  for(const r of rows)tbody.appendChild(r);
}
</script>
</body>
</html>`;
}

function renderGradePill(letter, count, color, total) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return `<div class="grade-pill">
    <div class="g" style="background:${color}">${letter}</div>
    <div>
      <div class="count">${count}</div>
      <div class="pct">${pct}%</div>
    </div>
  </div>`;
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
