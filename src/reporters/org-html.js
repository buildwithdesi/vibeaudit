export function generateOrgHTML(orgResult) {
  const { owner, results, summary } = orgResult;
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const nowDate = new Date().toISOString().split('T')[0];

  const gradeOrder = { A: 0, B: 1, C: 2, D: 3, F: 4 };
  const gradeColors = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' };

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

  const repos = [];
  for (const [repoName, data] of results) {
    const critCount = data.findings ? data.findings.filter(f => f.severity === 'critical').length : 0;
    const warnCount = data.findings ? data.findings.filter(f => f.severity === 'warning').length : 0;
    const infoCount = data.findings ? data.findings.filter(f => f.severity === 'info').length : 0;
    const topFinding = data.findings && data.findings.length > 0
      ? data.findings.reduce((worst, f) => {
          const sevOrder = { critical: 0, warning: 1, info: 2 };
          return (sevOrder[f.severity] || 2) < (sevOrder[worst.severity] || 2) ? f : worst;
        }, data.findings[0])
      : null;
    repos.push({
      name: repoName,
      grade: data.grade || 'A',
      critCount,
      warnCount,
      infoCount,
      totalFindings: (data.findings || []).length,
      findings: data.findings || [],
      filesScanned: data.filesScanned || 0,
      rulesRun: data.rulesRun || 0,
      durationMs: data.durationMs || 0,
      error: data.error || null,
      topFinding,
    });
  }

  repos.sort((a, b) => {
    const gA = gradeOrder[a.grade] ?? 4;
    const gB = gradeOrder[b.grade] ?? 4;
    if (gB !== gA) return gB - gA;
    if (b.critCount !== a.critCount) return b.critCount - a.critCount;
    if (b.warnCount !== a.warnCount) return b.warnCount - a.warnCount;
    return b.totalFindings - a.totalFindings;
  });

  const gradeCounts = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const r of repos) {
    gradeCounts[r.grade] = (gradeCounts[r.grade] || 0) + 1;
  }

  const orgGrade = summary.totalCritical > 0 ? 'F'
    : summary.totalWarning > 10 ? 'D'
    : summary.totalWarning > 0 ? 'C'
    : summary.totalInfo > 5 ? 'B'
    : 'A';

  const byOwasp = new Map();
  for (const r of repos) {
    for (const f of r.findings) {
      const cat = f.owaspCategory || 'Unknown';
      if (!byOwasp.has(cat)) byOwasp.set(cat, []);
      byOwasp.get(cat).push({ ...f, _repo: r.name });
    }
  }

  const ruleAgg = new Map();
  for (const r of repos) {
    for (const f of r.findings) {
      if (!ruleAgg.has(f.ruleId)) ruleAgg.set(f.ruleId, { ruleId: f.ruleId, message: f.message, severity: f.severity, count: 0, repos: new Set() });
      const entry = ruleAgg.get(f.ruleId);
      entry.count++;
      entry.repos.add(r.name);
    }
  }
  const topRules = [...ruleAgg.values()].sort((a, b) => b.count - a.count).slice(0, 20);

  const cleanRepos = repos.filter(r => r.totalFindings === 0 && !r.error);

  const durationSec = (summary.durationMs / 1000).toFixed(1);

  const repoRows = repos.map((r) => {
    const topMsg = r.topFinding ? esc(r.topFinding.message) : (r.error ? `<span style="color:var(--crit)">${esc(r.error)}</span>` : '<span style="color:var(--ok)">Clean</span>');
    const topSev = r.topFinding ? r.topFinding.severity : '';
    return `<tr class="repo-row" data-repo="${esc(r.name)}" data-grade="${r.grade}" data-search="${esc(r.name).toLowerCase()}">
      <td><a href="https://github.com/${esc(owner)}/${esc(r.name)}" target="_blank">${esc(r.name)}</a></td>
      <td><span class="grade-sm" style="background:${gradeColors[r.grade] || '#64748b'}">${r.grade}</span></td>
      <td class="num">${r.critCount > 0 ? `<span style="color:var(--crit);font-weight:700">${r.critCount}</span>` : '0'}</td>
      <td class="num">${r.warnCount > 0 ? `<span style="color:var(--warn);font-weight:700">${r.warnCount}</span>` : '0'}</td>
      <td class="num">${r.infoCount > 0 ? `<span style="color:var(--info);font-weight:700">${r.infoCount}</span>` : '0'}</td>
      <td class="top-finding">${topSev ? `<span class="sev-badge ${topSev}" style="margin-right:6px">${topSev}</span>` : ''}${topMsg}</td>
      <td class="ts">${r.durationMs}ms</td>
    </tr>`;
  }).join('\n');

  const heatCells = repos.map(r => {
    return `<div class="heat-cell" title="${esc(r.name)}: ${r.critCount}C / ${r.warnCount}W / ${r.infoCount}I (Grade ${r.grade})" style="background:${gradeColors[r.grade] || '#64748b'}"></div>`;
  }).join('\n');

  const owaspCards = Object.entries(owaspLabels).map(([cat, label]) => {
    const items = byOwasp.get(cat) || [];
    const count = items.length;
    const repoSet = new Set(items.map(i => i._repo));
    const total = summary.totalFindings || 1;
    const pct = Math.round((count / total) * 100);
    const barColor = count === 0 ? 'var(--ok)' : count > 5 ? 'var(--crit)' : 'var(--warn)';
    return `<div class="owasp-card">
      <div class="cat-id">${cat}</div>
      <div class="cat-name">${label}</div>
      <div class="cat-count">${count} <span style="font-size:13px;font-weight:400;color:var(--fg2)">finding${count !== 1 ? 's' : ''} in ${repoSet.size} repo${repoSet.size !== 1 ? 's' : ''}</span></div>
      <div class="owasp-bar"><div class="owasp-bar-fill" style="width:${Math.max(pct, 2)}%;background:${barColor}"></div></div>
    </div>`;
  }).join('\n');

  const topRulesRows = topRules.map(r => {
    return `<tr>
      <td><span class="sev-badge ${r.severity}">${r.severity}</span></td>
      <td><code>${esc(r.ruleId)}</code></td>
      <td>${esc(r.message)}</td>
      <td class="num" style="font-weight:700">${r.count}</td>
      <td class="num">${r.repos.size}</td>
    </tr>`;
  }).join('\n');

  const cleanList = cleanRepos.map(r => {
    return `<span class="clean-badge"><a href="https://github.com/${esc(owner)}/${esc(r.name)}" target="_blank">${esc(r.name)}</a></span>`;
  }).join('\n');

  const repoDetails = repos.filter(r => r.totalFindings > 0).map((r, idx) => {
    const findingCards = r.findings.map((f) => {
      return `<div class="finding-card" data-sev="${f.severity}">
        <div class="finding-header" onclick="toggleFinding(this)">
          <span class="sev-badge ${f.severity}">${f.severity}</span>
          <span class="finding-title">${esc(f.message)}</span>
          <span class="finding-file">${esc(f.file)}${f.line ? ':' + f.line : ''}</span>
          <span class="finding-meta">
            ${f.cweId ? `<span class="meta-badge">${f.cweId}</span>` : ''}
            ${f.cvssScore ? `<span class="meta-badge">CVSS ${f.cvssScore}</span>` : ''}
            ${f.owaspCategory ? `<span class="meta-badge">${f.owaspCategory}</span>` : ''}
          </span>
          <span class="chevron">&#9654;</span>
        </div>
        <div class="finding-body">
          ${f.evidence ? `<div><strong>Evidence:</strong></div><div class="evidence-box">${esc(f.evidence)}</div>` : ''}
          <div><strong>Fix:</strong></div>
          <div class="fix-box">${esc(f.fix)}</div>
        </div>
      </div>`;
    }).join('\n');

    return `<div class="repo-detail" id="repo-${idx}" data-repo="${esc(r.name)}">
      <div class="repo-detail-header" onclick="toggleRepoDetail(this)">
        <span class="chevron">&#9654;</span>
        <span class="grade-sm" style="background:${gradeColors[r.grade] || '#64748b'}">${r.grade}</span>
        <span class="repo-detail-name">${esc(r.name)}</span>
        <span class="repo-detail-counts">
          ${r.critCount > 0 ? `<span class="file-count c">${r.critCount} critical</span>` : ''}
          ${r.warnCount > 0 ? `<span class="file-count w">${r.warnCount} warning</span>` : ''}
          ${r.infoCount > 0 ? `<span class="file-count i">${r.infoCount} info</span>` : ''}
        </span>
      </div>
      <div class="repo-detail-body">
        ${findingCards}
      </div>
    </div>`;
  }).join('\n');

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Audit Fleet Dashboard — ${esc(owner)} — ${nowDate}</title>
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
.theme-toggle:hover{background:var(--border)}
.grade{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:36px;font-weight:800;color:#fff;flex-shrink:0}
.grade-sm{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:50%;font-size:13px;font-weight:800;color:#fff;flex-shrink:0}
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:32px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}
.stat-card .label{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--fg3);margin-bottom:4px}
.stat-card .value{font-size:32px;font-weight:700}
.stat-card .sub{font-size:12px;color:var(--fg2);margin-top:4px}
.stat-card.crit .value{color:var(--crit)}
.stat-card.warn .value{color:var(--warn)}
.stat-card.info .value{color:var(--info)}
.stat-card.ok .value{color:var(--ok)}
.stat-card.repos .value{color:var(--accent)}
.section{margin-bottom:40px}
.section-title{font-size:20px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:var(--card);cursor:pointer;font-size:13px;color:var(--fg2);transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
table.fleet-table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
table.fleet-table thead{background:var(--bg2)}
table.fleet-table th{padding:12px 16px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg3);border-bottom:2px solid var(--border)}
table.fleet-table td{padding:10px 16px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:middle}
table.fleet-table tr:last-child td{border-bottom:none}
table.fleet-table tr:hover{background:var(--bg2)}
table.fleet-table .num{text-align:center;font-variant-numeric:tabular-nums}
table.fleet-table .ts{font-size:12px;color:var(--fg3);white-space:nowrap}
table.fleet-table .top-finding{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sev-badge{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;flex-shrink:0;display:inline-block}
.sev-badge.critical{background:var(--crit-bg);color:var(--crit)}
.sev-badge.warning{background:var(--warn-bg);color:var(--warn)}
.sev-badge.info{background:var(--info-bg);color:var(--info)}
.heat-grid{display:flex;flex-wrap:wrap;gap:4px;padding:20px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}
.heat-cell{width:28px;height:28px;border-radius:4px;cursor:default;transition:transform .15s}
.heat-cell:hover{transform:scale(1.4);z-index:1}
.owasp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.owasp-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow)}
.owasp-card .cat-id{font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.5px}
.owasp-card .cat-name{font-size:14px;font-weight:600;margin:4px 0}
.owasp-card .cat-count{font-size:24px;font-weight:700}
.owasp-bar{height:6px;background:var(--bg3);border-radius:3px;margin-top:8px;overflow:hidden}
.owasp-bar-fill{height:100%;border-radius:3px;transition:width .5s}
table.rules-table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
table.rules-table thead{background:var(--bg2)}
table.rules-table th{padding:12px 16px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--fg3);border-bottom:2px solid var(--border)}
table.rules-table td{padding:10px 16px;border-bottom:1px solid var(--border);font-size:14px}
table.rules-table tr:last-child td{border-bottom:none}
table.rules-table tr:hover{background:var(--bg2)}
table.rules-table .num{text-align:center;font-weight:700;font-variant-numeric:tabular-nums}
table.rules-table code{background:var(--bg3);padding:2px 6px;border-radius:4px;font-size:12px}
.clean-section{display:flex;flex-wrap:wrap;gap:8px}
.clean-badge{background:var(--ok-bg);border:1px solid var(--ok);border-radius:8px;padding:6px 14px;font-size:13px;font-weight:600}
.clean-badge a{color:var(--ok)}
.repo-detail{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden;box-shadow:var(--shadow)}
.repo-detail-header{display:flex;align-items:center;gap:12px;padding:16px 20px;cursor:pointer;user-select:none}
.repo-detail-header:hover{background:var(--bg2)}
.repo-detail-name{font-size:16px;font-weight:600;flex:1}
.repo-detail-counts{display:flex;gap:6px}
.repo-detail-body{display:none;padding:0 20px 20px;border-top:1px solid var(--border)}
.repo-detail-body.open{display:block;padding-top:16px}
.finding-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:10px;overflow:hidden}
.finding-header{display:flex;align-items:center;gap:12px;padding:12px 16px;cursor:pointer;user-select:none}
.finding-header:hover{background:var(--bg3)}
.finding-title{flex:1;font-size:13px;font-weight:500}
.finding-file{font-size:12px;color:var(--fg3);font-family:monospace}
.finding-meta{display:flex;gap:8px;flex-shrink:0}
.meta-badge{padding:2px 8px;border-radius:4px;font-size:11px;background:var(--bg3);color:var(--fg2);font-family:monospace}
.finding-body{padding:0 16px 16px;display:none;border-top:1px solid var(--border)}
.finding-body.open{display:block;padding-top:12px}
.evidence-box{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px 16px;font-family:'Fira Code',monospace;font-size:13px;margin:12px 0;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.fix-box{background:var(--ok-bg);border:1px solid var(--ok);border-radius:8px;padding:12px 16px;font-size:13px;margin:12px 0}
.chevron{transition:transform .2s;color:var(--fg3);flex-shrink:0;font-size:12px}
.chevron.open{transform:rotate(90deg)}
.file-count{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.file-count.c{background:var(--crit-bg);color:var(--crit)}
.file-count.w{background:var(--warn-bg);color:var(--warn)}
.file-count.i{background:var(--info-bg);color:var(--info)}
.grade-dist{display:flex;gap:12px;margin-top:8px}
.grade-dist-item{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--fg2)}
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
@media print{
  .theme-toggle,.filter-bar,.chevron{display:none!important}
  .repo-detail-body{display:block!important;padding-top:16px!important}
  .finding-body{display:block!important;padding-top:12px!important}
  .finding-card,.repo-detail{break-inside:avoid;box-shadow:none;border:1px solid #ccc}
  body{background:#fff;color:#000}
  .heat-cell{print-color-adjust:exact;-webkit-print-color-adjust:exact}
}
@media(max-width:768px){
  .dashboard{grid-template-columns:repeat(2,1fr)}
  .header{flex-direction:column;gap:16px;text-align:center}
  .header-meta{flex-wrap:wrap;justify-content:center}
  table.fleet-table .top-finding{max-width:160px}
  .heat-cell{width:20px;height:20px}
}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade" style="background:${gradeColors[orgGrade]}">${orgGrade}</div>
      <div>
        <h1>Vibe Audit Fleet Dashboard</h1>
        <div style="color:var(--fg2);font-size:14px">${esc(owner)} &middot; ${summary.scannedRepos} repos scanned &middot; ${now}</div>
      </div>
    </div>
    <div class="header-meta">
      <span>${summary.totalFindings} findings</span>
      <span>${durationSec}s</span>
      <button class="theme-toggle" onclick="toggleTheme()">Theme</button>
    </div>
  </div>

  <div class="dashboard">
    <div class="stat-card repos">
      <div class="label">Repos Scanned</div>
      <div class="value">${summary.scannedRepos}</div>
      <div class="sub">${summary.skippedRepos} skipped of ${summary.totalRepos} total</div>
    </div>
    <div class="stat-card crit">
      <div class="label">Critical</div>
      <div class="value">${summary.totalCritical}</div>
      <div class="sub">Across all repos</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Warnings</div>
      <div class="value">${summary.totalWarning}</div>
      <div class="sub">Across all repos</div>
    </div>
    <div class="stat-card info">
      <div class="label">Info</div>
      <div class="value">${summary.totalInfo}</div>
      <div class="sub">Best practices</div>
    </div>
    <div class="stat-card ok">
      <div class="label">Clean Repos</div>
      <div class="value">${cleanRepos.length}</div>
      <div class="sub">${summary.scannedRepos > 0 ? Math.round((cleanRepos.length / summary.scannedRepos) * 100) : 0}% of fleet</div>
    </div>
    <div class="stat-card">
      <div class="label">Fleet Grade</div>
      <div class="value" style="color:${gradeColors[orgGrade]}">${orgGrade}</div>
      <div class="grade-dist">
        ${Object.entries(gradeCounts).map(([g, c]) => `<span class="grade-dist-item"><span class="grade-sm" style="background:${gradeColors[g]};width:20px;height:20px;font-size:10px">${g}</span>${c}</span>`).join('')}
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Repos At Risk</div>
    <div class="filter-bar">
      <input type="text" id="repo-search" placeholder="Search repos..." oninput="filterRepos()">
      <button class="filter-btn active" data-grade="all" onclick="setGradeFilter('all',this)">All</button>
      <button class="filter-btn" data-grade="F" onclick="setGradeFilter('F',this)">F (${gradeCounts.F})</button>
      <button class="filter-btn" data-grade="D" onclick="setGradeFilter('D',this)">D (${gradeCounts.D})</button>
      <button class="filter-btn" data-grade="C" onclick="setGradeFilter('C',this)">C (${gradeCounts.C})</button>
      <button class="filter-btn" data-grade="B" onclick="setGradeFilter('B',this)">B (${gradeCounts.B})</button>
      <button class="filter-btn" data-grade="A" onclick="setGradeFilter('A',this)">A (${gradeCounts.A})</button>
    </div>
    <div style="overflow-x:auto">
      <table class="fleet-table">
        <thead>
          <tr>
            <th>Repository</th>
            <th>Grade</th>
            <th>Critical</th>
            <th>Warning</th>
            <th>Info</th>
            <th>Top Finding</th>
            <th>Duration</th>
          </tr>
        </thead>
        <tbody id="repo-table-body">
          ${repoRows}
        </tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Fleet Heat Map</div>
    <div style="color:var(--fg2);font-size:13px;margin-bottom:8px">Each square is one repo. Color = grade (green=A, yellow=C, red=F). Hover for details.</div>
    <div class="heat-grid">
      ${heatCells}
    </div>
  </div>

  <div class="section">
    <div class="section-title">OWASP Top 10 (2021) Coverage</div>
    <div class="owasp-grid">
      ${owaspCards}
    </div>
  </div>

  <div class="section">
    <div class="section-title">Top Recurring Issues</div>
    ${topRules.length > 0 ? `<div style="overflow-x:auto">
      <table class="rules-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule</th>
            <th>Message</th>
            <th>Hits</th>
            <th>Repos</th>
          </tr>
        </thead>
        <tbody>
          ${topRulesRows}
        </tbody>
      </table>
    </div>` : '<div style="color:var(--fg2)">No recurring issues found.</div>'}
  </div>

  ${cleanRepos.length > 0 ? `<div class="section">
    <div class="section-title">Repos with Zero Issues</div>
    <div class="clean-section">
      ${cleanList}
    </div>
  </div>` : ''}

  <div class="section">
    <div class="section-title">Per-Repo Details</div>
    <div style="color:var(--fg2);font-size:13px;margin-bottom:12px">Click a repo to expand its findings.</div>
    ${repoDetails}
  </div>

  <div class="footer">
    Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a> &middot;
    ${summary.scannedRepos} repos &middot; ${summary.totalFindings} findings &middot; ${durationSec}s &middot; ${nowDate}<br>
    Built by <a href="https://digitalalchemy.dev">Digital Alchemy Academy</a>
  </div>
</div>

<script>
function toggleTheme(){
  var html=document.documentElement;
  html.dataset.theme=html.dataset.theme==='dark'?'light':'dark';
}
function toggleFinding(el){
  var body=el.nextElementSibling;
  var chev=el.querySelector('.chevron');
  body.classList.toggle('open');
  chev.classList.toggle('open');
}
function toggleRepoDetail(el){
  var body=el.nextElementSibling;
  var chev=el.querySelector('.chevron');
  body.classList.toggle('open');
  chev.classList.toggle('open');
}
var currentGrade='all';
function setGradeFilter(grade,btn){
  currentGrade=grade;
  document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active')});
  btn.classList.add('active');
  filterRepos();
}
function filterRepos(){
  var q=document.getElementById('repo-search').value.toLowerCase();
  document.querySelectorAll('.repo-row').forEach(function(row){
    var matchGrade=currentGrade==='all'||row.dataset.grade===currentGrade;
    var matchQ=!q||row.dataset.search.indexOf(q)!==-1;
    row.style.display=matchGrade&&matchQ?'':'none';
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
