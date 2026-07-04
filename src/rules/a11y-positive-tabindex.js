/**
 * Rule: a11y-positive-tabindex
 * Detects tabindex / tabIndex values greater than 0.
 *
 * A positive tabindex yanks an element to the front of the tab order and breaks
 * keyboard navigation for everything after it. Use 0 (natural order) or -1
 * (script-focusable only). WCAG 2.4.3.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { A11Y_SKIP, MARKUP_FILES, lineAt } from './a11y-utils.js';

// tabindex="2" | tabIndex={2} | tabindex='2' | tabindex=2 — capture the integer.
const TABINDEX = /\btab[Ii]ndex\s*=\s*["'{]?\s*(\d+)/g;

/** @type {Rule} */
export const a11yPositiveTabindex = {
  id: 'a11y-positive-tabindex',
  name: 'Positive tabindex',
  severity: 'warning',
  description: 'Detects tabindex values greater than 0, which break the natural keyboard tab order (WCAG 2.4.3).',

  check(file) {
    if (A11Y_SKIP.test(file.relativePath)) return [];
    if (!MARKUP_FILES.test(file.relativePath)) return [];

    const findings = [];
    TABINDEX.lastIndex = 0;
    let match;
    while ((match = TABINDEX.exec(file.content)) !== null) {
      const value = parseInt(match[1], 10);
      if (!(value > 0)) continue; // 0 and -1 are fine

      const line = lineAt(file.content, match.index);
      findings.push({
        ruleId: 'a11y-positive-tabindex',
        ruleName: 'Positive tabindex',
        severity: 'warning',
        message: `Positive tabindex (${value}) forces this element to the front of the tab order and breaks keyboard navigation for everything after it (WCAG 2.4.3, Level A).`,
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Use tabindex="0" to include an element in the natural DOM tab order, or tabindex="-1" to make it focusable only via script. Never use a positive value — reorder the DOM instead.',
        wcag: 'WCAG 2.4.3 (Level A)',
      });
    }
    return findings;
  },
};
