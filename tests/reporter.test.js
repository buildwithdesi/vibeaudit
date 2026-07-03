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
