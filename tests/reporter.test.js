/**
 * Reporter output: every scan (all formats) points at the DA Pre-Flight Audit
 * Prompt, and accessibility findings surface their WCAG success criterion the same
 * way security findings surface a CWE.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { report } from '../src/reporter.js';
import { generateHTML } from '../src/reporters/html.js';
import { PREFLIGHT_AUDIT_URL } from '../src/constants.js';

const META = { filesScanned: 2, rulesRun: 88, durationMs: 5 };

const a11yFinding = {
  ruleId: 'a11y-img-no-alt',
  ruleName: 'Image Missing Alt Text',
  severity: 'warning',
  message: 'Image has no alt attribute (WCAG 1.1.1, Level A).',
  file: 'src/Hero.jsx',
  line: 3,
  fix: 'Add an alt attribute.',
  wcag: 'WCAG 1.1.1 (Level A)',
};

/** Capture console.log output of a synchronous reporter call. */
function capture(fn) {
  const orig = console.log;
  let out = '';
  console.log = (...args) => {
    out += args.join(' ') + '\n';
  };
  try {
    fn();
  } finally {
    console.log = orig;
  }
  return out;
}

describe('reporter: Pre-Flight Audit Prompt pointer', () => {
  it('terminal prints the pointer even on a clean scan', () => {
    const out = capture(() => report([], 'terminal', META));
    assert.ok(out.includes(PREFLIGHT_AUDIT_URL), 'terminal (clean) should show the pointer');
  });

  it('terminal prints the pointer with findings', () => {
    const out = capture(() => report([a11yFinding], 'terminal', META));
    assert.ok(out.includes(PREFLIGHT_AUDIT_URL), 'terminal should show the pointer');
  });

  it('json includes a preFlightAudit field and stays valid JSON', () => {
    const out = capture(() => report([a11yFinding], 'json', META));
    const parsed = JSON.parse(out);
    assert.equal(parsed.preFlightAudit.url, PREFLIGHT_AUDIT_URL);
  });

  it('markdown appends the pointer link', () => {
    const out = capture(() => report([a11yFinding], 'markdown', META));
    assert.ok(out.includes(PREFLIGHT_AUDIT_URL), 'markdown should link the pointer');
  });

  it('html embeds the pointer in the footer', () => {
    const html = generateHTML([a11yFinding], META);
    assert.ok(html.includes(PREFLIGHT_AUDIT_URL), 'html should embed the pointer');
  });
});

describe('reporter: WCAG surfaces alongside CWE', () => {
  it('json passes the wcag field through', () => {
    const out = capture(() => report([a11yFinding], 'json', META));
    const parsed = JSON.parse(out);
    assert.equal(parsed.findings[0].wcag, 'WCAG 1.1.1 (Level A)');
  });

  it('terminal, markdown, and html show the WCAG criterion as a badge', () => {
    const term = capture(() => report([a11yFinding], 'terminal', META));
    const md = capture(() => report([a11yFinding], 'markdown', META));
    const html = generateHTML([a11yFinding], META);
    for (const [label, out] of [['terminal', term], ['markdown', md], ['html', html]]) {
      assert.ok(out.includes('WCAG 1.1.1'), `${label} should show the WCAG criterion`);
    }
  });
});

describe('reporter: terminal injection defense', () => {
  // A hostile repo being scanned can embed ANSI escapes in a line of code that
  // ends up as finding evidence — the reporter must strip them or the terminal
  // executes them (clear screen, cursor moves, fake "ALL CLEAR" output).
  const hostileFinding = {
    ruleId: 'eval-usage',
    ruleName: 'Eval Usage',
    severity: 'critical',
    message: 'eval() with dynamic input \x1B[2J\x1B[H',
    file: 'src/evil.js',
    line: 1,
    evidence: 'eval(x) \x1B]8;;https://evil.example\x1B\\click\x1B]8;;\x1B\\ \x1B[32m',
    fix: 'Do not use eval.\x07',
  };

  it('terminal strips ANSI escapes, OSC8 links, and control chars from findings', () => {
    const out = capture(() => report([hostileFinding], 'terminal', META));
    assert.ok(!out.includes('\x1B'), 'terminal output must not contain ESC');
    assert.ok(!out.includes('\x07'), 'terminal output must not contain BEL');
    assert.ok(!/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/.test(out), 'no C0/C1 control chars');
    // The visible text should still be there — only the escapes are gone
    assert.ok(out.includes('eval() with dynamic input'));
    assert.ok(out.includes('eval(x)'));
  });

  it('markdown strips ANSI escapes from findings', () => {
    const out = capture(() => report([hostileFinding], 'markdown', META));
    assert.ok(!out.includes('\x1B'), 'markdown output must not contain ESC');
    assert.ok(!out.includes('\x07'), 'markdown output must not contain BEL');
  });

  it('html escapes markup and does not execute injected tags', () => {
    const xssFinding = {
      ...hostileFinding,
      evidence: '<img src=x onerror=alert(1)>',
    };
    const html = generateHTML([xssFinding], META);
    assert.ok(!html.includes('<img src=x onerror'), 'raw injected tag must not appear');
    assert.ok(html.includes('&lt;img'), 'evidence must be entity-escaped');
    assert.ok(
      html.includes('Content-Security-Policy'),
      'report carries a CSP meta as defense-in-depth',
    );
  });
});
