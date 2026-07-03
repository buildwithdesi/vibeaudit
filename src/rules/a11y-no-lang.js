/**
 * Rule: a11y-no-lang
 * Detects an <html> root element with no lang attribute.
 *
 * Without lang, screen readers guess the document language and often mispronounce
 * the entire page. One attribute, whole-document impact. WCAG 3.1.1.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { A11Y_SKIP, openingTag, lineAt, hasSpread } from './a11y-utils.js';

// <html> appears in raw HTML docs and framework root layouts (Next.js app/layout.tsx).
const LANG_FILES = /\.(?:html?|jsx|tsx|vue|svelte|astro)$/i;
const HTML_START = /<html\b/i;

/** @type {Rule} */
export const a11yNoLang = {
  id: 'a11y-no-lang',
  name: 'Document Missing lang',
  severity: 'warning',
  description: "Detects an <html> element with no lang attribute (WCAG 3.1.1) — screen readers can't pick the right pronunciation.",

  check(file) {
    if (A11Y_SKIP.test(file.relativePath)) return [];
    if (!LANG_FILES.test(file.relativePath)) return [];

    const match = HTML_START.exec(file.content);
    if (!match) return [];

    const tag = openingTag(file.content, match.index);
    if (/\blang\s*=/i.test(tag)) return [];
    if (hasSpread(tag)) return []; // <html {...props}> may inject lang

    const line = lineAt(file.content, match.index);
    return [
      {
        ruleId: 'a11y-no-lang',
        ruleName: 'Document Missing lang',
        severity: 'warning',
        message:
          'The <html> element has no lang attribute — screen readers can\'t determine the language and may mispronounce the whole page (WCAG 3.1.1, Level A).',
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Add a lang attribute to the root element: <html lang="en"> (or the correct BCP-47 code). In Next.js App Router this lives in app/layout.tsx.',
        wcag: 'WCAG 3.1.1 (Level A)',
      },
    ];
  },
};
