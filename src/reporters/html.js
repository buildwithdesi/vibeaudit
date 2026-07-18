/**
 * HTML Report Generator — Audit-grade security report.
 *
 * Generates a single self-contained HTML file with:
 *   - Executive dashboard with severity gauges and OWASP coverage
 *   - Interactive findings table with search/filter/sort
 *   - File-by-file breakdown with code evidence
 *   - CWE/CVSS/OWASP metadata for every finding
 *   - CVSS score distribution chart
 *   - Copy-paste fix prompts per finding
 *   - Print-friendly / PDF-exportable layout
 *   - Dark mode toggle
 *   - Zero external dependencies (all CSS/JS inlined)
 */

import { getFixPrompt } from '../data/prompts.js';
import { PREFLIGHT_AUDIT_URL, PREFLIGHT_AUDIT_MESSAGE } from '../constants.js';

/**
 * @param {import('../rules/types.js').Finding[]} findings
 * @param {{ filesScanned: number, rulesRun: number, durationMs: number }} meta
 * @returns {string} Complete HTML document
 */
export function generateHTML(findings, meta) {
  const criticals = findings.filter((f) => f.severity === 'critical');
  const warnings = findings.filter((f) => f.severity === 'warning');
  const infos = findings.filter((f) => f.severity === 'info');
  const total = findings.length;

  // Group by file
  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }

  // Group by OWASP category
  const byOwasp = new Map();
  for (const f of findings) {
    const cat = f.owaspCategory || 'Unknown';
    if (!byOwasp.has(cat)) byOwasp.set(cat, []);
    byOwasp.get(cat).push(f);
  }

  // Group by rule
  const byRule = new Map();
  for (const f of findings) {
    if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, []);
    byRule.get(f.ruleId).push(f);
  }

  // CVSS distribution
  const cvssRanges = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const score = f.cvssScore || 0;
    if (score >= 9.0) cvssRanges.critical++;
    else if (score >= 7.0) cvssRanges.high++;
    else if (score >= 4.0) cvssRanges.medium++;
    else if (score > 0) cvssRanges.low++;
    else cvssRanges.info++;
  }

  const now = new Date().toISOString().split('T')[0];
  const grade = criticals.length > 0 ? 'F' : warnings.length > 5 ? 'D' : warnings.length > 0 ? 'C' : infos.length > 0 ? 'B' : 'A';
  const gradeColor = { A: '#22c55e', B: '#86efac', C: '#eab308', D: '#f97316', F: '#ef4444' }[grade];

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

  // Enrich findings with prompts
  const enriched = findings.map((f, i) => {
    const prompt = getFixPrompt(f.ruleId);
    return { ...f, _idx: i, _prompt: prompt?.prompt || '', _platformNotes: prompt?.platformNotes || '' };
  });

  return `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:;">
<title>Vibe Audit Report — ${now}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#ffffff;--bg2:#f8fafc;--bg3:#f1f5f9;--fg:#0f172a;--fg2:#475569;--fg3:#94a3b8;--border:#e2e8f0;--card:#ffffff;--shadow:0 1px 3px rgba(0,0,0,.1);--crit:#ef4444;--crit-bg:#fef2f2;--warn:#eab308;--warn-bg:#fefce8;--info:#06b6d4;--info-bg:#ecfeff;--ok:#22c55e;--ok-bg:#f0fdf4;--accent:#6366f1;--radius:12px}
[data-theme="dark"]{--bg:#0f172a;--bg2:#1e293b;--bg3:#334155;--fg:#f1f5f9;--fg2:#94a3b8;--fg3:#64748b;--border:#334155;--card:#1e293b;--shadow:0 1px 3px rgba(0,0,0,.4);--crit-bg:#450a0a;--warn-bg:#422006;--info-bg:#083344;--ok-bg:#052e16}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}
.container{max-width:1280px;margin:0 auto;padding:24px}
/* Header */
.header{display:flex;align-items:center;justify-content:space-between;padding:24px 0;border-bottom:1px solid var(--border);margin-bottom:32px}
.header h1{font-size:28px;display:flex;align-items:center;gap:12px}
.header-meta{display:flex;gap:16px;align-items:center}
.header-meta span{font-size:13px;color:var(--fg2)}
.theme-toggle{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:14px;color:var(--fg)}
.theme-toggle:hover{background:var(--border)}
/* Grade badge */
.grade{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:36px;font-weight:800;color:#fff;flex-shrink:0}
/* Dashboard cards */
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:32px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}
.stat-card .label{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--fg3);margin-bottom:4px}
.stat-card .value{font-size:32px;font-weight:700}
.stat-card .sub{font-size:12px;color:var(--fg2);margin-top:4px}
.stat-card.crit .value{color:var(--crit)}
.stat-card.warn .value{color:var(--warn)}
.stat-card.info .value{color:var(--info)}
.stat-card.ok .value{color:var(--ok)}
/* Sections */
.section{margin-bottom:40px}
.section-title{font-size:20px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px}
/* OWASP chart */
.owasp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.owasp-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow)}
.owasp-card .cat-id{font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.5px}
.owasp-card .cat-name{font-size:14px;font-weight:600;margin:4px 0}
.owasp-card .cat-count{font-size:24px;font-weight:700}
.owasp-bar{height:6px;background:var(--bg3);border-radius:3px;margin-top:8px;overflow:hidden}
.owasp-bar-fill{height:100%;border-radius:3px;transition:width .5s}
/* CVSS distribution */
.cvss-bars{display:flex;gap:8px;align-items:end;height:120px;padding:0 20px}
.cvss-col{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}
.cvss-bar{width:100%;border-radius:4px 4px 0 0;min-height:4px;transition:height .5s}
.cvss-label{font-size:11px;color:var(--fg3)}
.cvss-count{font-size:13px;font-weight:600}
/* Findings */
.filter-bar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-bar input{flex:1;min-width:200px;padding:10px 16px;border:1px solid var(--border);border-radius:8px;font-size:14px;background:var(--card);color:var(--fg)}
.filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:var(--card);cursor:pointer;font-size:13px;color:var(--fg2);transition:all .2s}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.finding-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden;box-shadow:var(--shadow);transition:box-shadow .2s}
.finding-card:hover{box-shadow:0 4px 12px rgba(0,0,0,.1)}
.finding-header{display:flex;align-items:center;gap:12px;padding:16px 20px;cursor:pointer;user-select:none}
.finding-header:hover{background:var(--bg2)}
.sev-badge{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;flex-shrink:0}
.sev-badge.critical{background:var(--crit-bg);color:var(--crit)}
.sev-badge.warning{background:var(--warn-bg);color:var(--warn)}
.sev-badge.info{background:var(--info-bg);color:var(--info)}
.finding-title{flex:1;font-size:14px;font-weight:500}
.finding-file{font-size:12px;color:var(--fg3);font-family:monospace}
.finding-meta{display:flex;gap:8px;flex-shrink:0}
.meta-badge{padding:2px 8px;border-radius:4px;font-size:11px;background:var(--bg3);color:var(--fg2);font-family:monospace}
.finding-body{padding:0 20px 20px;display:none;border-top:1px solid var(--border)}
.finding-body.open{display:block;padding-top:16px}
.evidence-box{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px 16px;font-family:'Fira Code',monospace;font-size:13px;margin:12px 0;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.fix-box{background:var(--ok-bg);border:1px solid var(--ok);border-radius:8px;padding:12px 16px;font-size:13px;margin:12px 0}
.prompt-box{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;margin:12px 0;position:relative}
.prompt-box pre{white-space:pre-wrap;font-size:12px;line-height:1.5;font-family:monospace}
.copy-btn{position:absolute;top:8px;right:8px;padding:4px 12px;border:1px solid var(--border);border-radius:6px;background:var(--card);cursor:pointer;font-size:12px;color:var(--fg2)}
.copy-btn:hover{background:var(--accent);color:#fff}
.chevron{transition:transform .2s;color:var(--fg3);flex-shrink:0}
.chevron.open{transform:rotate(90deg)}
/* Files breakdown */
.file-row{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border)}
.file-row:last-child{border-bottom:none}
.file-name{font-family:monospace;font-size:13px;flex:1}
.file-counts{display:flex;gap:6px}
.file-count{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.file-count.c{background:var(--crit-bg);color:var(--crit)}
.file-count.w{background:var(--warn-bg);color:var(--warn)}
.file-count.i{background:var(--info-bg);color:var(--info)}
/* Footer */
.footer{text-align:center;padding:32px 0;color:var(--fg3);font-size:13px;border-top:1px solid var(--border);margin-top:40px}
/* Print */
@media print{
  .theme-toggle,.filter-bar,.copy-btn,.chevron{display:none!important}
  .finding-body{display:block!important;padding-top:16px!important}
  .finding-card{break-inside:avoid;box-shadow:none;border:1px solid #ccc}
  body{background:#fff;color:#000}
}
/* Responsive */
@media(max-width:768px){
  .dashboard{grid-template-columns:repeat(2,1fr)}
  .header{flex-direction:column;gap:16px;text-align:center}
  .header-meta{flex-wrap:wrap;justify-content:center}
}
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <div style="display:flex;align-items:center;gap:20px">
      <div class="grade" style="background:${gradeColor}">${grade}</div>
      <div>
        <h1>⚗️ Vibe Audit Report</h1>
        <div style="color:var(--fg2);font-size:14px">Security audit for AI-generated code &middot; ${now}</div>
      </div>
    </div>
    <div class="header-meta">
      <span>${meta.filesScanned} files</span>
      <span>${meta.rulesRun} rules</span>
      <span>${meta.durationMs}ms</span>
      <button class="theme-toggle" onclick="toggleTheme()">🌓 Theme</button>
    </div>
  </div>

  <!-- Dashboard -->
  <div class="dashboard">
    <div class="stat-card crit">
      <div class="label">Critical</div>
      <div class="value">${criticals.length}</div>
      <div class="sub">Must fix before deploy</div>
    </div>
    <div class="stat-card warn">
      <div class="label">Warnings</div>
      <div class="value">${warnings.length}</div>
      <div class="sub">Fix before going live</div>
    </div>
    <div class="stat-card info">
      <div class="label">Info</div>
      <div class="value">${infos.length}</div>
      <div class="sub">Best practices</div>
    </div>
    <div class="stat-card ok">
      <div class="label">Total Findings</div>
      <div class="value">${total}</div>
      <div class="sub">${byFile.size} files affected</div>
    </div>
  </div>

  <!-- CVSS Distribution -->
  <div class="section">
    <div class="section-title">📊 CVSS Score Distribution</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow)">
      <div class="cvss-bars">
        ${renderCvssBar('Critical', '9.0-10.0', cvssRanges.critical, total, 'var(--crit)')}
        ${renderCvssBar('High', '7.0-8.9', cvssRanges.high, total, '#f97316')}
        ${renderCvssBar('Medium', '4.0-6.9', cvssRanges.medium, total, 'var(--warn)')}
        ${renderCvssBar('Low', '0.1-3.9', cvssRanges.low, total, 'var(--ok)')}
        ${renderCvssBar('Info', '0', cvssRanges.info, total, 'var(--info)')}
      </div>
    </div>
  </div>

  <!-- OWASP Top 10 Coverage -->
  <div class="section">
    <div class="section-title">🛡️ OWASP Top 10 (2021) Coverage</div>
    <div class="owasp-grid">
      ${Object.entries(owaspLabels).map(([cat, label]) => {
        const count = byOwasp.get(cat)?.length || 0;
        const pct = total > 0 ? Math.round((count / total) * 100) : 0;
        const barColor = count === 0 ? 'var(--ok)' : count > 3 ? 'var(--crit)' : 'var(--warn)';
        return `<div class="owasp-card">
          <div class="cat-id">${cat}</div>
          <div class="cat-name">${label}</div>
          <div class="cat-count">${count} <span style="font-size:13px;font-weight:400;color:var(--fg2)">finding${count !== 1 ? 's' : ''}</span></div>
          <div class="owasp-bar"><div class="owasp-bar-fill" style="width:${Math.max(pct, 2)}%;background:${barColor}"></div></div>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>

  <!-- Files Breakdown -->
  <div class="section">
    <div class="section-title">📁 Files Breakdown</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)">
      ${[...byFile.entries()].map(([file, ff]) => {
        const c = ff.filter(f => f.severity === 'critical').length;
        const w = ff.filter(f => f.severity === 'warning').length;
        const i = ff.filter(f => f.severity === 'info').length;
        return `<div class="file-row">
          <div class="file-name">${esc(file)}</div>
          <div class="file-counts">
            ${c > 0 ? `<span class="file-count c">${c} critical</span>` : ''}
            ${w > 0 ? `<span class="file-count w">${w} warning</span>` : ''}
            ${i > 0 ? `<span class="file-count i">${i} info</span>` : ''}
          </div>
        </div>`;
      }).join('\n      ')}
    </div>
  </div>

  <!-- Findings -->
  <div class="section">
    <div class="section-title">🔍 All Findings (${total})</div>
    <div class="filter-bar">
      <input type="text" id="search" placeholder="Search findings..." oninput="filterFindings()">
      <button class="filter-btn active" data-sev="all" onclick="setSevFilter('all',this)">All</button>
      <button class="filter-btn" data-sev="critical" onclick="setSevFilter('critical',this)">Critical (${criticals.length})</button>
      <button class="filter-btn" data-sev="warning" onclick="setSevFilter('warning',this)">Warning (${warnings.length})</button>
      <button class="filter-btn" data-sev="info" onclick="setSevFilter('info',this)">Info (${infos.length})</button>
    </div>
    <div id="findings-list">
      ${enriched.map((f) => `
      <div class="finding-card" data-sev="${f.severity}" data-search="${esc(f.message + ' ' + f.file + ' ' + f.ruleId + ' ' + (f.cweId || '') + ' ' + (f.owaspCategory || '')).toLowerCase()}">
        <div class="finding-header" onclick="toggleFinding(this)">
          <span class="sev-badge ${f.severity}">${f.severity}</span>
          <span class="finding-title">${esc(f.message)}</span>
          <span class="finding-file">${esc(f.file)}${f.line ? ':' + f.line : ''}</span>
          <span class="finding-meta">
            ${f.cweId ? `<span class="meta-badge">${f.cweId}</span>` : ''}
            ${f.cvssScore ? `<span class="meta-badge">CVSS ${f.cvssScore}</span>` : ''}
            ${f.owaspCategory ? `<span class="meta-badge">${f.owaspCategory}</span>` : ''}
            ${f.wcag ? `<span class="meta-badge">${esc(f.wcag)}</span>` : ''}
          </span>
          <span class="chevron">▶</span>
        </div>
        <div class="finding-body">
          ${f.evidence ? `<div><strong>Evidence:</strong></div><div class="evidence-box">${esc(f.evidence)}</div>` : ''}
          <div><strong>Fix:</strong></div>
          <div class="fix-box">${esc(f.fix)}</div>
          ${f._prompt ? `
          <div><strong>Copy-paste fix prompt:</strong></div>
          <div class="prompt-box">
            <button class="copy-btn" onclick="copyPrompt(this, event)">📋 Copy</button>
            <pre>${esc(f._prompt)}</pre>
          </div>
          ${f._platformNotes ? `<div style="font-size:12px;color:var(--fg2);margin-top:8px"><strong>Platform notes:</strong> ${esc(f._platformNotes)}</div>` : ''}
          ` : ''}
        </div>
      </div>
      `).join('')}
    </div>
  </div>

  <!-- Footer -->
  <div class="footer">
    ⚗️ Generated by <a href="https://github.com/jackdog668/vibeaudit">Vibe Audit</a> &middot;
    ${meta.rulesRun} rules &middot; ${meta.filesScanned} files &middot; ${meta.durationMs}ms &middot; ${now}<br>
    Built by <a href="https://digitalalchemy.dev">Digital Alchemy Academy</a><br>
    <span style="opacity:.85">${esc(PREFLIGHT_AUDIT_MESSAGE)} <a href="${PREFLIGHT_AUDIT_URL}">${esc(PREFLIGHT_AUDIT_URL)}</a></span>
  </div>
</div>

<script>
function toggleTheme(){
  const html=document.documentElement;
  html.dataset.theme=html.dataset.theme==='dark'?'light':'dark';
}
function toggleFinding(el){
  const body=el.nextElementSibling;
  const chev=el.querySelector('.chevron');
  body.classList.toggle('open');
  chev.classList.toggle('open');
}
let currentSev='all';
function setSevFilter(sev,btn){
  currentSev=sev;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  filterFindings();
}
function filterFindings(){
  const q=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.finding-card').forEach(card=>{
    const matchSev=currentSev==='all'||card.dataset.sev===currentSev;
    const matchQ=!q||card.dataset.search.includes(q);
    card.style.display=matchSev&&matchQ?'':'none';
  });
}
function copyPrompt(btn,e){
  e.stopPropagation();
  const pre=btn.parentElement.querySelector('pre');
  navigator.clipboard.writeText(pre.textContent).then(()=>{
    btn.textContent='✅ Copied!';
    setTimeout(()=>btn.textContent='📋 Copy',2000);
  });
}
</script>
</body>
</html>`;
}

function renderCvssBar(label, range, count, total, color) {
  const maxH = 100;
  const h = total > 0 ? Math.max(4, Math.round((count / total) * maxH)) : 4;
  return `<div class="cvss-col">
    <div class="cvss-count">${count}</div>
    <div class="cvss-bar" style="height:${h}px;background:${color}"></div>
    <div class="cvss-label">${label}</div>
    <div class="cvss-label" style="font-size:10px">${range}</div>
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
