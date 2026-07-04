/**
 * Rule: a11y-form-no-label
 * Detects form controls (<input>, <select>, <textarea>) with no programmatic label:
 * no id (to pair with <label for>), no aria-label / aria-labelledby, no title, and
 * no nearby <label>. Placeholder text is NOT a label. WCAG 1.3.1 / 4.1.2.
 *
 * Deliberately conservative: fires only when there is no plausible labelling signal,
 * to hold the project's zero-false-positive bar.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { A11Y_SKIP, MARKUP_FILES, openingTag, lineAt, hasSpread } from './a11y-utils.js';

const CONTROL_START = /<(?:input|select|textarea)\b/gi;
// Control types that carry their own name or need no text label.
const NO_LABEL_TYPE = /\btype\s*=\s*["']?(?:hidden|submit|button|reset|image)\b/i;

/** @type {Rule} */
export const a11yFormNoLabel = {
  id: 'a11y-form-no-label',
  name: 'Form Control Missing Label',
  severity: 'warning',
  description: 'Detects inputs/selects/textareas with no associated label or aria-label (WCAG 1.3.1) — placeholder text does not count.',

  check(file) {
    if (A11Y_SKIP.test(file.relativePath)) return [];
    if (!MARKUP_FILES.test(file.relativePath)) return [];

    const findings = [];
    CONTROL_START.lastIndex = 0;
    let match;
    while ((match = CONTROL_START.exec(file.content)) !== null) {
      const tag = openingTag(file.content, match.index);
      if (hasSpread(tag)) continue; // {...register('email')} / {...props} may add labelling
      if (NO_LABEL_TYPE.test(tag)) continue; // submit/hidden/etc. need no text label
      if (/\b(?:aria-label|aria-labelledby|title)\s*=/i.test(tag)) continue;
      if (/\bid\s*=/i.test(tag)) continue; // id is likely paired with a <label for>

      // A <label> just before the control (wrapping or adjacent) is a labelling signal.
      const before = file.content.slice(Math.max(0, match.index - 160), match.index);
      if (/<label\b/i.test(before)) continue;

      const line = lineAt(file.content, match.index);
      findings.push({
        ruleId: 'a11y-form-no-label',
        ruleName: 'Form Control Missing Label',
        severity: 'warning',
        message:
          'Form control has no associated label — no id/<label>, no aria-label, no title. Screen-reader users hear an unlabeled field, and placeholder text does not count (WCAG 1.3.1, Level A).',
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Associate a label: <label for="email">Email</label><input id="email">, wrap the input in a <label>, or add aria-label="Email" for a control with no visible label.',
        wcag: 'WCAG 1.3.1 (Level A)',
      });
    }
    return findings;
  },
};
