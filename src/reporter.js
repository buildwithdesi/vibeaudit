import { bold, red, yellow, cyan, green, gray, dim } from './colors.js';
import { getFixPrompt } from './data/prompts.js';
import { generateHTML } from './reporters/html.js';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * @typedef {import('./rules/types.js').Finding} Finding
 */

/**
 * Format and print findings to stdout.
 *
 * @param {Finding[]} findings
 * @param {'terminal' | 'json' | 'markdown' | 'html'} format
 * @param {{ filesScanned: number, rulesRun: number, durationMs: number, targetDir?: string }} meta
 */
export function report(findings, format, meta) {
  switch (format) {
    case 'json':
      return reportJSON(findings, meta);
    case 'markdown':
      return reportMarkdown(findings, meta);
    case 'html':
      return reportHTMLFile(findings, meta);
    case 'silent':
      return;
    default:
      return reportTerminal(findings, meta);
  }
}

// ─── Terminal ─────────────────────────────────────────────────────────────────

function reportTerminal(findings, meta) {
  const criticals = findings.filter((f) => f.severity === 'critical');
  const warnings = findings.filter((f) => f.severity === 'warning');
  const infos = findings.filter((f) => f.severity === 'info');

  console.log('');
  console.log(bold('  ⚗️  VIBE AUDIT'));
  console.log(dim('  Security audit for AI-generated code'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // ── Dashboard summary ──
  const grade = criticals.length > 0 ? 'F' : warnings.length > 5 ? 'D' : warnings.length > 0 ? 'C' : infos.length > 0 ? 'B' : 'A';
  const gradeColor = { A: green, B: green, C: yellow, D: yellow, F: red }[grade];

  const total = findings.length;
  if (total === 0) {
    console.log(green(bold('  ┌─────────────────────────────────────────────────────────┐')));
    console.log(green(bold('  │                  ✅  ALL CLEAR — GRADE A                │')));
    console.log(green(bold('  │             No security issues found. Ship it.           │')));
    console.log(green(bold('  └─────────────────────────────────────────────────────────┘')));
    console.log('');
    printSummaryBar(0, 0, 0, meta);
    return;
  }

  // Grade + severity counts
  console.log(`  ${gradeColor(bold(`GRADE: ${grade}`))}  ${dim('│')}  ${red(bold(`${criticals.length}`))} ${dim('critical')}  ${dim('│')}  ${yellow(bold(`${warnings.length}`))} ${dim('warning' + (warnings.length !== 1 ? 's' : ''))}  ${dim('│')}  ${cyan(bold(`${infos.length}`))} ${dim('info')}`);
  console.log('');

  // ── OWASP coverage (compact) ──
  const byOwasp = new Map();
  for (const f of findings) {
    const cat = f.owaspCategory || 'Other';
    byOwasp.set(cat, (byOwasp.get(cat) || 0) + 1);
  }
  const owaspLabels = {
    'A01:2021': 'Access Ctrl',
    'A02:2021': 'Crypto',
    'A03:2021': 'Injection',
    'A04:2021': 'Design',
    'A05:2021': 'Misconfig',
    'A06:2021': 'Components',
    'A07:2021': 'Auth',
    'A08:2021': 'Integrity',
    'A09:2021': 'Logging',
    'A10:2021': 'SSRF',
  };
  const owaspHits = [];
  for (const [cat, label] of Object.entries(owaspLabels)) {
    const count = byOwasp.get(cat) || 0;
    if (count > 0) {
      owaspHits.push(`${dim(cat)} ${label} ${red(bold(String(count)))}`);
    }
  }
  if (owaspHits.length > 0) {
    console.log(dim('  OWASP Top 10 hits:'));
    for (const hit of owaspHits) {
      console.log(`    ${hit}`);
    }
    console.log('');
  }

  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');

  // ── Group findings by file ──
  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }

  for (const [file, fileFindings] of byFile) {
    const fileCrit = fileFindings.filter(f => f.severity === 'critical').length;
    const fileWarn = fileFindings.filter(f => f.severity === 'warning').length;
    const fileInfo = fileFindings.filter(f => f.severity === 'info').length;
    const counts = [];
    if (fileCrit > 0) counts.push(red(bold(`${fileCrit}C`)));
    if (fileWarn > 0) counts.push(yellow(`${fileWarn}W`));
    if (fileInfo > 0) counts.push(cyan(`${fileInfo}I`));

    console.log(`  ${bold(cyan(file))} ${dim('(')}${counts.join(dim(','))}${dim(')')}`);

    for (const f of fileFindings) {
      const icon = severityIcon(f.severity);
      const lineStr = f.line ? gray(`:${f.line}`) : '';
      const cweStr = f.cweId ? dim(` [${f.cweId}]`) : '';
      const cvssStr = f.cvssScore ? dim(` CVSS:${f.cvssScore}`) : '';
      console.log(`    ${icon}  ${f.message}${lineStr}${cweStr}${cvssStr}`);
      if (f.evidence) {
        console.log(`        ${dim(f.evidence)}`);
      }
      console.log(`        ${dim('Fix:')} ${gray(f.fix)}`);
      console.log('');
    }
  }

  printSummaryBar(criticals.length, warnings.length, infos.length, meta);
}

function severityIcon(severity) {
  switch (severity) {
    case 'critical':
      return red('●');
    case 'warning':
      return yellow('▲');
    case 'info':
      return cyan('ℹ');
    default:
      return ' ';
  }
}

function printSummaryBar(critCount, warnCount, infoCount, meta) {
  const total = critCount + warnCount + infoCount;
  console.log(dim('  ─────────────────────────────────────────────────────────────'));

  // Visual severity bar
  if (total > 0) {
    const barWidth = 40;
    const critBar = Math.round((critCount / total) * barWidth);
    const warnBar = Math.round((warnCount / total) * barWidth);
    const infoBar = barWidth - critBar - warnBar;
    const bar = red('█'.repeat(critBar)) + yellow('█'.repeat(warnBar)) + cyan('█'.repeat(Math.max(0, infoBar)));
    console.log(`  ${bar} ${dim(`${total} total`)}`);
  }

  const parts = [];
  if (critCount > 0) parts.push(red(bold(`${critCount} critical`)));
  if (warnCount > 0) parts.push(yellow(`${warnCount} warning${warnCount !== 1 ? 's' : ''}`));
  if (infoCount > 0) parts.push(cyan(`${infoCount} info`));
  if (total === 0) parts.push(green('0 issues'));

  console.log(`  ${parts.join(dim(' · '))}`);
  console.log(
    dim(
      `  ${meta.filesScanned} files scanned · ${meta.rulesRun} rules · ${meta.durationMs}ms`
    )
  );
  console.log('');

  if (critCount > 0) {
    console.log(red(bold('  ⛔ CRITICAL issues found. Fix these before deploying.')));
    console.log(dim('  Run with --fix to get copy-paste prompts for your AI tool.'));
    console.log(dim('  Run with --format html to generate an interactive report.'));
  } else if (warnCount > 0) {
    console.log(yellow(bold('  ⚠️  Warnings found. Review before going live.')));
    console.log(dim('  Run with --fix to get fix prompts.'));
  } else {
    console.log(green(bold('  ✅ Looking clean. Ship it.')));
  }
  console.log('');
}

// ─── JSON ─────────────────────────────────────────────────────────────────────

function reportJSON(findings, meta) {
  // Enrich findings with fix prompts.
  const enriched = findings.map((f) => {
    const promptData = getFixPrompt(f.ruleId);
    const entry = { ...f };
    if (promptData) {
      entry.prompt = promptData.prompt;
      entry.platformNotes = promptData.platformNotes;
    }
    return entry;
  });

  const output = {
    summary: {
      total: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      warning: findings.filter((f) => f.severity === 'warning').length,
      info: findings.filter((f) => f.severity === 'info').length,
      filesScanned: meta.filesScanned,
      rulesRun: meta.rulesRun,
      durationMs: meta.durationMs,
    },
    findings: enriched,
  };

  console.log(JSON.stringify(output, null, 2));
}

// ─── Markdown ─────────────────────────────────────────────────────────────────

function reportMarkdown(findings, meta) {
  const criticals = findings.filter((f) => f.severity === 'critical');
  const warnings = findings.filter((f) => f.severity === 'warning');
  const infos = findings.filter((f) => f.severity === 'info');

  const lines = [
    '# ⚗️ Vibe Audit Report',
    '',
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Files scanned | ${meta.filesScanned} |`,
    `| Rules run | ${meta.rulesRun} |`,
    `| Critical | ${criticals.length} |`,
    `| Warnings | ${warnings.length} |`,
    `| Info | ${infos.length} |`,
    `| Duration | ${meta.durationMs}ms |`,
    '',
  ];

  if (findings.length === 0) {
    lines.push('**✅ No issues found.**');
  } else {
    const renderFinding = (f) => {
      const cweBadge = f.cweId ? ` \`${f.cweId}\`` : '';
      lines.push(`### \`${f.file}\`${f.line ? `:${f.line}` : ''}${cweBadge}`);
      lines.push(`- **${f.message}**`);
      if (f.evidence) lines.push(`- Evidence: \`${f.evidence}\``);
      lines.push(`- Fix: ${f.fix}`);
      const promptData = getFixPrompt(f.ruleId);
      if (promptData) {
        lines.push('');
        lines.push('<details><summary>📋 Copy-paste fix prompt (works in any AI coding tool)</summary>');
        lines.push('');
        lines.push('```');
        lines.push(promptData.prompt);
        lines.push('```');
        if (promptData.platformNotes) {
          lines.push('');
          lines.push(`**Platform notes:** ${promptData.platformNotes}`);
        }
        lines.push('');
        lines.push('</details>');
      }
      lines.push('');
    };

    if (criticals.length > 0) {
      lines.push('## 🔴 Critical', '');
      for (const f of criticals) renderFinding(f);
    }

    if (warnings.length > 0) {
      lines.push('## 🟡 Warnings', '');
      for (const f of warnings) renderFinding(f);
    }

    if (infos.length > 0) {
      lines.push('## ℹ️ Info', '');
      for (const f of infos) {
        lines.push(`- \`${f.file}\`${f.line ? `:${f.line}` : ''} — ${f.message}`);
      }
      lines.push('');
    }
  }

  console.log(lines.join('\n'));
}

// ─── HTML ─────────────────────────────────────────────────────────────────────

async function reportHTMLFile(findings, meta) {
  const html = generateHTML(findings, meta);
  const targetDir = meta.targetDir || process.cwd();
  const filePath = join(targetDir, 'vibe-audit-report.html');

  try {
    await writeFile(filePath, html);
    console.log('');
    console.log(bold('  ⚗️  VIBE AUDIT — HTML Report Generated'));
    console.log(dim('  ─────────────────────────────────────────────────────────────'));
    console.log('');

    const criticals = findings.filter((f) => f.severity === 'critical').length;
    const warns = findings.filter((f) => f.severity === 'warning').length;
    const total = findings.length;

    console.log(`  ${bold('Report:')}  ${cyan(filePath)}`);
    console.log(`  ${bold('Findings:')} ${total > 0 ? red(bold(String(criticals))) + ' critical · ' + yellow(String(warns)) + ' warnings' : green('0 issues')}`);
    console.log(`  ${bold('Files:')}    ${meta.filesScanned} scanned · ${meta.rulesRun} rules · ${meta.durationMs}ms`);
    console.log('');
    console.log(dim('  Open in your browser to view the interactive dashboard.'));
    console.log('');
  } catch {
    // Fall back to stdout if we can't write the file
    console.log(html);
  }
}
