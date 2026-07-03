/**
 * Rule: a11y-click-no-keyboard
 * Detects onClick on a non-interactive element (div/span/li/…) with no keyboard
 * handler and no role. Keyboard and screen-reader users can't activate it — the
 * classic "clickable div". WCAG 2.1.1.
 *
 * React (.jsx/.tsx) only: keys off the camelCase onClick / onKeyDown props.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { A11Y_SKIP, REACT_FILES, openingTag, lineAt, hasSpread } from './a11y-utils.js';

// Non-interactive host elements that get click handlers slapped on them.
const NON_INTERACTIVE_START =
  /<(div|span|li|p|td|tr|section|article|header|footer|main|aside|nav|ul|ol|figure)\b/gi;

/** @type {Rule} */
export const a11yClickNoKeyboard = {
  id: 'a11y-click-no-keyboard',
  name: 'Click Handler Without Keyboard Support',
  severity: 'warning',
  description: "Detects onClick on a non-interactive element with no keyboard handler or role (WCAG 2.1.1) — keyboard users can't trigger it.",

  check(file) {
    if (A11Y_SKIP.test(file.relativePath)) return [];
    if (!REACT_FILES.test(file.relativePath)) return [];

    const findings = [];
    NON_INTERACTIVE_START.lastIndex = 0;
    let match;
    while ((match = NON_INTERACTIVE_START.exec(file.content)) !== null) {
      const tag = openingTag(file.content, match.index);
      if (!/\bonClick\s*=/.test(tag)) continue; // only clickable ones
      if (hasSpread(tag)) continue; // {...props} / {...handlers} may add keyboard support or role
      if (/\bon(?:KeyDown|KeyUp|KeyPress)\s*=/.test(tag)) continue; // keyboard handled
      if (/\brole\s*=/i.test(tag)) continue; // author gave it an interactive role

      const line = lineAt(file.content, match.index);
      findings.push({
        ruleId: 'a11y-click-no-keyboard',
        ruleName: 'Click Handler Without Keyboard Support',
        severity: 'warning',
        message: `<${match[1]}> has onClick but no keyboard handler and no role — keyboard and screen-reader users can't activate it (WCAG 2.1.1, Level A).`,
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Use a real <button> for click actions. If you must keep this element, add role="button", tabIndex={0}, and an onKeyDown handler that fires on Enter/Space.',
        wcag: 'WCAG 2.1.1 (Level A)',
      });
    }
    return findings;
  },
};
