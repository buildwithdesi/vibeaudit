/**
 * Rule: a11y-button-no-name
 * Detects <button> elements with no accessible name — no visible text and no
 * aria-label / aria-labelledby / title. Icon-only buttons are the usual culprit:
 * a screen reader just announces "button". WCAG 4.1.2.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { A11Y_SKIP, MARKUP_FILES, openingTag, lineAt, hasSpread } from './a11y-utils.js';

const BUTTON_START = /<button\b/gi;

/** @type {Rule} */
export const a11yButtonNoName = {
  id: 'a11y-button-no-name',
  name: 'Button Has No Accessible Name',
  severity: 'warning',
  description: 'Detects <button> elements with no text and no aria-label — a screen reader just announces "button" (WCAG 4.1.2).',

  check(file) {
    if (A11Y_SKIP.test(file.relativePath)) return [];
    if (!MARKUP_FILES.test(file.relativePath)) return [];

    const findings = [];
    BUTTON_START.lastIndex = 0;
    let match;
    while ((match = BUTTON_START.exec(file.content)) !== null) {
      const openTag = openingTag(file.content, match.index);
      if (hasSpread(openTag)) continue; // {...props} may supply a name
      if (/\b(?:aria-label|aria-labelledby|title)\s*=/i.test(openTag)) continue;
      if (/\/>\s*$/.test(openTag)) continue; // self-closing <button /> — no children to inspect, unusual

      const innerStart = match.index + openTag.length;
      const closeIdx = file.content.indexOf('</button>', innerStart);
      if (closeIdx === -1) continue;
      const inner = file.content.slice(innerStart, closeIdx);

      // Dynamic children ({label}, {children}, {t('save')}) provide the name at runtime.
      if (inner.includes('{')) continue;
      // Strip nested tags/comments; any remaining visible text is the accessible name.
      const text = inner.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
      if (text.length > 0) continue;

      const line = lineAt(file.content, match.index);
      findings.push({
        ruleId: 'a11y-button-no-name',
        ruleName: 'Button Has No Accessible Name',
        severity: 'warning',
        message:
          'Button has no accessible name — no text content and no aria-label, so a screen reader just announces "button" (WCAG 4.1.2, Level A).',
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Give the button a name: add visible text, or for an icon-only button add aria-label="Close" (or aria-labelledby pointing at a label element).',
        wcag: 'WCAG 4.1.2 (Level A)',
      });
    }
    return findings;
  },
};
