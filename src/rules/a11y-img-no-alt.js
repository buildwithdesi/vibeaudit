/**
 * Rule: a11y-img-no-alt
 * Detects <img> and next/image <Image> elements with no `alt` attribute.
 *
 * Missing alt text is the most common WCAG failure and the first thing automated
 * legal scanners (PowerMapper, axe, WAVE) flag. This catches the Level A miss; it
 * does not judge whether present alt text is meaningful — pair with a manual pass.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { A11Y_SKIP, MARKUP_FILES, openingTag, lineAt, hasSpread } from './a11y-utils.js';

// <img> (native) or <Image> (next/image). Case-sensitive so SVG's <image> isn't caught.
const IMG_START = /<(?:img|Image)\b/g;

/** @type {Rule} */
export const a11yImgNoAlt = {
  id: 'a11y-img-no-alt',
  name: 'Image Missing Alt Text',
  severity: 'warning',
  description: 'Detects <img> / next/image elements with no alt attribute (WCAG 1.1.1) — the first thing automated accessibility scanners flag.',

  check(file) {
    if (A11Y_SKIP.test(file.relativePath)) return [];
    if (!MARKUP_FILES.test(file.relativePath)) return [];

    const findings = [];
    IMG_START.lastIndex = 0;
    let match;
    while ((match = IMG_START.exec(file.content)) !== null) {
      const tag = openingTag(file.content, match.index);
      if (hasSpread(tag)) continue; // {...props} may supply alt
      if (/\balt\s*=/i.test(tag)) continue; // has alt (even alt="") — valid
      // Decorative images intentionally hidden from assistive tech don't need alt text.
      if (/\baria-hidden\s*=\s*["'{]?\s*true/i.test(tag)) continue;
      if (/\brole\s*=\s*["']presentation["']/i.test(tag)) continue;

      const line = lineAt(file.content, match.index);
      findings.push({
        ruleId: 'a11y-img-no-alt',
        ruleName: 'Image Missing Alt Text',
        severity: 'warning',
        message:
          "Image has no alt attribute — screen readers can't describe it, and automated WCAG scanners flag it (WCAG 1.1.1, Level A).",
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Add an alt attribute: describe the image\'s meaning for content images (alt="Team at the 2026 summit"), or use an empty alt="" for purely decorative images so screen readers skip them.',
        wcag: 'WCAG 1.1.1 (Level A)',
      });
    }
    return findings;
  },
};
