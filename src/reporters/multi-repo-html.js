/**
 * Multi-Repo HTML Dashboard — Aggregated security report across all repos.
 *
 * Generates a single self-contained HTML file with:
 *   - Executive summary with total repos, aggregate grades, worst offenders
 *   - Grade distribution chart
 *   - Per-repo cards with drill-down findings
 *   - Top recurring issues across the org
 *   - Heatmap of rule violations by repo
 *   - Sortable/filterable repo table
 *   - Zero external dependencies (all CSS/JS inlined)
 */

/**
 * @param {import('../multi-repo.js').RepoResult[]} results
 * @param {{ org?: string, durationMs: number }} meta
 * @returns {string} Complete HTML document
 */
export function generateMultiRepoHTML(results, meta) {
  const now = new Date().toISOString().split('T')[0];
  const timeStr = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  const org = meta.org || 'Multi-Repo';

  const totalRepos = results.length;
  const successfulScans = results.filter((r) => !r.error);
  const failedScans = results.filter((r) => r.error);

  const totalFindings = successfulScans.reduce((s, r) => s + r.findings.length, 0);
  const totalCriticals = successfulScans.reduce((s, r) => s + r.criticals, 0);
  const totalWarnings = successfulScans.reduce((s, r) => s + r.warnings, 0);
  const totalInfos = successfulScans.reduce((s, r) => s + r.infos, 0);

  const gradeDistribution = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of successfulScans) {
    if (gradeDistribution[r.grade] !== undefined) gradeDistribution[r.grade]++;
  }

  const overallGrade =
    totalCriticals > 0
      ? 'F'
      : totalWarnings > totalRepos * 2
        ? 'D'
        : totalWarnings > 0
          ? 'C'
          : totalInfos > 0
            ? 'B'
            : 'A';

  const gradeColor = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[
    overallGrade
  ];

  // Top recurring rules across all repos
  const ruleHits = new Map();
  for (const r of successfulScans) {
    for (const f of r.findings) {
      if (!ruleHits.has(f.ruleId)) {
        ruleHits.set(f.ruleId, { ruleId: f.ruleId, ruleName: f.ruleName, severity: f.severity, count: 0, repos: new Set() });
      }
      const entry = ruleHits.get(f.ruleId);
      entry.count++;
      entry.repos.add(r.fullName);
    }
  }
  const topRules = [...ruleHits.values()]
    .sort((a, b) => b.repos.size - a.repos.size)
    .slice(0, 15);

  // OWASP category aggregation
  const owaspAgg = new Map();
  for (const r of successfulScans) {
    for (const f of r.findings) {
      const cat = f.owaspCategory || 'Other';
      owaspAgg.set(cat, (owaspAgg.get(cat) || 0) + 1);
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

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit — ${esc(org)} Morning Scan — ${now}</title>
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
/* Grade distribution */
.grade-bar{display:flex;gap:12px;justify-content:center;padding:24px}
.grade-col{display:flex;flex-direction:column;align-items:center;gap:6px}
.grade-circle{width:56px;height:56px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:800;color:#fff}
.grade-count{font-size:18px;font-weight:700}
.grade-label{font-size:12px;color:var(--fg3)}
/* Repo table */
.repo-table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
.repo-table th{background:var(--bg2);padding:12px 16px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg3);cursor:pointer;user-select:none;border-bottom:2px solid var(--border)}
.repo-table th:hover{background:var(--bg3)}
.repo-table td{padding:12px 16px;border-bottom:1px solid var(--border);font-size:14px}
.repo-table tr:last-child td{border-bottom:none}
.repo-table tr:hover td{background:var(--bg2)}
.repo-grade{width:36px;height:36px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;color:#fff}
.sev-pill{padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600}
.sev-pill.c{background:var(--crit-bg);color:var(--crit)}
.sev-pill.w{background:var(--warn-bg);color:var(--warn)}
.sev-pill.i{background:var(--info-bg);color:var(--info)}
.sev-pill.ok{background:var(--ok-bg);color:var(--ok)}
.sev-pill.err{background:var(--bg3);color:var(--fg3)}
/* Top rules */
.rule-row{display:flex;align-items:center;gap:16px;padding:12px 16px;border-bottom:1px solid var(--border)}
.rule-row:last-child{border-bottom:none}
.rule-bar{flex:1;height:8px;background:var(--bg3);border-radius:4px;overflow:hidden}
.rule-bar-fill{height:100%;border-radius:4px}
.rule-count{font-size:14px;font-weight:600;min-width:40px;text-align:right}
.rule-repos{font-size:12px;color:var(--fg3);min-width:60px;text-align:right}
.rule-name{font-size:14px;font-weight:500;min-width:200px}
.rule-sev{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;text-transform:uppercase}
/* Repo detail */
.repo-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:16px;overflow:hidden;box-shadow:var(--shadow)}
.repo-card-header{display:flex;align-items:center;gap:16px;padding:16px 20px;cursor:pointer;user-select:none}
.repo-card-header:hover{background:var(--bg2)}
.repo-card-body{display:none;padding:0 20px 20px;border-top:1px solid var(--border)}
.repo-card-body.open{display:block;padding-top:16px}
.chevron{transition:transform .2s;color:var(--fg3);flex-shrink:0}
.chevron.open{transform:rotate(90deg)}
.finding-mini{padding:8px 12px;border-left:3px solid var(--border);margin:6px 0;font-size:13px}
.finding-mini.critical{border-color:var(--crit);background:var(--crit-bg)}
.finding-mini.warning{border-color:var(--warn);background:var(--warn-bg)}
.finding-mini.info{border-color:var(--info);background:var(--info-bg)}
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:var(--card);cursor:pointer;font-size:13px;color:var(--fg2);transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{.theme-toggle,.filter-bar,.chevron{display:none!important}.repo-card-body{display:block!important;padding-top:16px!important}.repo-card{break-inside:avoid;box-shadow:none;border:1px solid #ccc}body{background:#fff;color:#000}}
@media(max-width:768px){.dashboard{grid-template-columns:repeat(2,1fr)}.header{flex-direction:column;gap:16px;text-align:center}.repo-table{font-size:12px}.repo-table th,.repo-table td{padding:8px}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade" style="background:${gradeColor}">${overallGrade}</div>
      <div>
        <h1>Morning Scan — ${esc(org)}</h1>
        <div style="color:var(--fg2);font-size:14px">${totalRepos} repos scanned &middot; ${now} ${timeStr}</div>
      </div>
    </div>
    <div class="header-meta">
      <span>${Math.round(meta.durationMs / 1000)}s total</span>
      <span>${totalFindings} findings</span>
      <button class="theme-toggle" onclick="toggleTheme()">Theme</button>
    </div>
  </div>

  <div class="dashboard">
    <div class="stat-card ok">
      <div class="label">Repos Scanned</div>
      <div class="value">${totalRepos}</div>
      <div class="sub">${failedScans.length > 0 ? failedScans.length + ' failed' : 'all successful'}</div>
    </div>
    <div class="stat-card crit">
      <div class="label">Critical</div>
      <div class="value">${totalCriticals}</div>
      <div class="sub">across ${successfulScans.filter((r) => r.criticals > 0).length} repos</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Warnings</div>
      <div class="value">${totalWarnings}</div>
      <div class="sub">across ${successfulScans.filter((r) => r.warnings > 0).length} repos</div>
    </div>
    <div class="stat-card info">
      <div class="label">Info</div>
      <div class="value">${totalInfos}</div>
      <div class="sub">${totalFindings} total findings</div>
    </div>
    <div class="stat-card" style="border-left:4px solid ${gradeColor}">
      <div class="label">Passing (A/B)</div>
      <div class="value" style="color:var(--ok)">${gradeDistribution.A + gradeDistribution.B}</div>
      <div class="sub">${totalRepos > 0 ? Math.round(((gradeDistribution.A + gradeDistribution.B) / totalRepos) * 100) : 0}% of repos</div>
    </div>
  </div>

  <!-- Grade Distribution -->
  <div class="section">
    <div class="section-title">Grade Distribution</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)">
      <div class="grade-bar">
        ${['A', 'B', 'C', 'D', 'F']
          .map((g) => {
            const colors = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' };
            return `<div class="grade-col">
            <div class="grade-circle" style="background:${colors[g]}">${g}</div>
            <div class="grade-count">${gradeDistribution[g]}</div>
            <div class="grade-label">repo${gradeDistribution[g] !== 1 ? 's' : ''}</div>
          </div>`;
          })
          .join('\n        ')}
      </div>
    </div>
  </div>

  <!-- OWASP Coverage -->
  <div class="section">
    <div class="section-title">OWASP Top 10 Across All Repos</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px">
      ${Object.entries(owaspLabels)
        .map(([cat, label]) => {
          const count = owaspAgg.get(cat) || 0;
          const pct = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0;
          const barColor = count === 0 ? 'var(--ok)' : count > 10 ? 'var(--crit)' : 'var(--warn)';
          return `<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow)">
          <div style="font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.5px">${cat}</div>
          <div style="font-size:14px;font-weight:600;margin:4px 0">${label}</div>
          <div style="font-size:24px;font-weight:700">${count}</div>
          <div style="height:6px;background:var(--bg3);border-radius:3px;margin-top:8px;overflow:hidden"><div style="height:100%;width:${Math.max(pct, 2)}%;background:${barColor};border-radius:3px"></div></div>
        </div>`;
        })
        .join('\n      ')}
    </div>
  </div>

  <!-- Top Recurring Issues -->
  ${
    topRules.length > 0
      ? `<div class="section">
    <div class="section-title">Top Recurring Issues</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)">
      ${topRules
        .map((rule) => {
          const sevColor = rule.severity === 'critical' ? 'var(--crit)' : rule.severity === 'warning' ? 'var(--warn)' : 'var(--info)';
          const sevBg = rule.severity === 'critical' ? 'var(--crit-bg)' : rule.severity === 'warning' ? 'var(--warn-bg)' : 'var(--info-bg)';
          const pct = totalRepos > 0 ? Math.round((rule.repos.size / totalRepos) * 100) : 0;
          return `<div class="rule-row">
          <span class="rule-sev" style="background:${sevBg};color:${sevColor}">${rule.severity}</span>
          <span class="rule-name">${esc(rule.ruleName || rule.ruleId)}</span>
          <div class="rule-bar"><div class="rule-bar-fill" style="width:${Math.max(pct, 3)}%;background:${sevColor}"></div></div>
          <span class="rule-repos">${rule.repos.size} repos</span>
          <span class="rule-count">${rule.count}x</span>
        </div>`;
        })
        .join('\n      ')}
    </div>
  </div>`
      : ''
  }

  <!-- Repo Table -->
  <div class="section">
    <div class="section-title">All Repos (${totalRepos})</div>
    <div class="filter-bar">
      <input type="text" id="repo-search" placeholder="Search repos..." oninput="filterRepos()">
      <button class="filter-btn active" data-grade="all" onclick="setGradeFilter('all',this)">All</button>
      <button class="filter-btn" data-grade="F" onclick="setGradeFilter('F',this)">F (${gradeDistribution.F})</button>
      <button class="filter-btn" data-grade="D" onclick="setGradeFilter('D',this)">D (${gradeDistribution.D})</button>
      <button class="filter-btn" data-grade="C" onclick="setGradeFilter('C',this)">C (${gradeDistribution.C})</button>
      <button class="filter-btn" data-grade="B" onclick="setGradeFilter('B',this)">B (${gradeDistribution.B})</button>
      <button class="filter-btn" data-grade="A" onclick="setGradeFilter('A',this)">A (${gradeDistribution.A})</button>
    </div>
    <table class="repo-table">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Grade</th>
          <th onclick="sortTable(1)">Repository</th>
          <th onclick="sortTable(2)">Language</th>
          <th onclick="sortTable(3)">Critical</th>
          <th onclick="sortTable(4)">Warnings</th>
          <th onclick="sortTable(5)">Info</th>
          <th onclick="sortTable(6)">Total</th>
          <th onclick="sortTable(7)">Time</th>
        </tr>
      </thead>
      <tbody id="repo-tbody">
        ${results
          .map((r) => {
            const gc = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444', '?': '#94a3b8' }[r.grade] || '#94a3b8';
            const total = r.criticals + r.warnings + r.infos;
            return `<tr data-grade="${r.grade}" data-search="${esc(r.fullName + ' ' + r.language + ' ' + (r.description || '')).toLowerCase()}">
          <td><span class="repo-grade" style="background:${gc}">${r.grade}</span></td>
          <td><a href="https://github.com/${esc(r.fullName)}" target="_blank">${esc(r.fullName)}</a>${r.error ? ` <span class="sev-pill err">error</span>` : ''}</td>
          <td>${esc(r.language || '')}</td>
          <td>${r.criticals > 0 ? `<span class="sev-pill c">${r.criticals}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
          <td>${r.warnings > 0 ? `<span class="sev-pill w">${r.warnings}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
          <td>${r.infos > 0 ? `<span class="sev-pill i">${r.infos}</span>` : '<span style="color:var(--fg3)">0</span>'}</td>
          <td>${total}</td>
          <td style="color:var(--fg3)">${r.durationMs < 1000 ? r.durationMs + 'ms' : Math.round(r.durationMs / 1000) + 's'}</td>
        </tr>`;
          })
          .join('\n        ')}
      </tbody>
    </table>
  </div>

  <!-- Per-Repo Details -->
  <div class="section">
    <div class="section-title">Repo Details</div>
    ${results
      .filter((r) => r.findings.length > 0)
      .map((r) => {
        const gc = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[r.grade] || '#94a3b8';
        return `<div class="repo-card" data-repo-grade="${r.grade}">
        <div class="repo-card-header" onclick="toggleRepo(this)">
          <span class="repo-grade" style="background:${gc}">${r.grade}</span>
          <div style="flex:1">
            <div style="font-weight:600">${esc(r.fullName)}</div>
            <div style="font-size:12px;color:var(--fg3)">${r.criticals}C ${r.warnings}W ${r.infos}I &middot; ${r.findings.length} findings</div>
          </div>
          <span class="chevron">&#9654;</span>
        </div>
        <div class="repo-card-body">
          ${r.findings
            .slice(0, 25)
            .map(
              (f) =>
                `<div class="finding-mini ${f.severity}">
              <strong>${esc(f.message)}</strong> <span style="color:var(--fg3)">${esc(f.file)}${f.line ? ':' + f.line : ''}</span>
              ${f.cweId ? `<span style="font-size:11px;color:var(--fg3)">[${f.cweId}]</span>` : ''}
            </div>`
            )
            .join('\n          ')}
          ${r.findings.length > 25 ? `<div style="padding:8px 12px;font-size:13px;color:var(--fg3)">... and ${r.findings.length - 25} more findings</div>` : ''}
        </div>
      </div>`;
      })
      .join('\n    ')}
  </div>

  ${
    failedScans.length > 0
      ? `<div class="section">
    <div class="section-title">Failed Scans (${failedScans.length})</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)">
      ${failedScans
        .map(
          (r) => `<div style="padding:12px 16px;border-bottom:1px solid var(--border);font-size:14px">
        <strong>${esc(r.fullName)}</strong> <span style="color:var(--crit)">${esc(r.error)}</span>
      </div>`
        )
        .join('\n      ')}
    </div>
  </div>`
      : ''
  }

  <div class="footer">
    Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a> &middot;
    ${totalRepos} repos &middot; ${totalFindings} findings &middot; ${Math.round(meta.durationMs / 1000)}s &middot; ${now}<br>
    Built by <a href="https://digitalalchemy.dev">Digital Alchemy Academy</a>
  </div>
</div>

<script>
function toggleTheme(){document.documentElement.dataset.theme=document.documentElement.dataset.theme==='dark'?'light':'dark'}
function toggleRepo(el){const body=el.nextElementSibling;const chev=el.querySelector('.chevron');body.classList.toggle('open');chev.classList.toggle('open')}
let currentGrade='all';
function setGradeFilter(g,btn){currentGrade=g;document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');filterRepos()}
function filterRepos(){const q=document.getElementById('repo-search').value.toLowerCase();document.querySelectorAll('#repo-tbody tr').forEach(row=>{const mg=currentGrade==='all'||row.dataset.grade===currentGrade;const mq=!q||row.dataset.search.includes(q);row.style.display=mg&&mq?'':'none'})}
let sortCol=-1,sortDir=1;
function sortTable(col){if(sortCol===col)sortDir*=-1;else{sortCol=col;sortDir=1}const tbody=document.getElementById('repo-tbody');const rows=[...tbody.querySelectorAll('tr')];rows.sort((a,b)=>{let av=a.children[col].textContent.trim();let bv=b.children[col].textContent.trim();const an=parseFloat(av),bn=parseFloat(bv);if(!isNaN(an)&&!isNaN(bn))return(an-bn)*sortDir;return av.localeCompare(bv)*sortDir});for(const r of rows)tbody.appendChild(r)}
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
