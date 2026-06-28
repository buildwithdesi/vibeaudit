/**
 * Rule: dangerously-set-inner-html
 * Detects React dangerouslySetInnerHTML with potentially user-controlled,
 * unsanitized content.
 *
 * Context-aware: skips when an escaper/sanitizer is used near the call (in
 * either direction) or when the __html value is a static string literal.
 * Custom escaper names can be added via `.vibe-audit.json` `customEscapers`.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { escapersFor, escaperRegex } from '../context.js';

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const REACT_FILES = /\.(jsx|tsx)$/i;

/** @type {Rule} */
export const dangerouslySetInnerHtml = {
  id: 'dangerously-set-inner-html',
  name: 'dangerouslySetInnerHTML Usage',
  severity: 'critical',
  description: 'Detects React dangerouslySetInnerHTML with potentially user-controlled content.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!REACT_FILES.test(file.relativePath)) return [];

    const escRe = escaperRegex(escapersFor(file));
    const findings = [];
    const pattern = /dangerouslySetInnerHTML/g;
    pattern.lastIndex = 0;

    let match;
    while ((match = pattern.exec(file.content)) !== null) {
      const lineNum = file.content.slice(0, match.index).split('\n').length;
      const line = file.lines[lineNum - 1]?.trim();

      // Look both directions — sanitizers are often defined just before the JSX.
      const ctx = file.content.slice(Math.max(0, match.index - 140), match.index + 260);
      if (escRe.test(ctx)) continue;

      // Static string/template literal passed to __html is not user-controlled.
      const after = file.content.slice(match.index, match.index + 220);
      const htmlVal = after.match(/__html\s*:\s*([^,}\n]+)/);
      if (htmlVal) {
        const v = htmlVal[1].trim();
        if (/^['"]/.test(v) || (v.startsWith('`') && !v.includes('${'))) continue;
      }

      findings.push({
        ruleId: 'dangerously-set-inner-html',
        ruleName: 'dangerouslySetInnerHTML Usage',
        severity: 'critical',
        message: 'dangerouslySetInnerHTML used without sanitization — XSS vulnerability.',
        file: file.relativePath,
        line: lineNum,
        evidence: line?.slice(0, 120),
        fix: 'Sanitize the HTML before rendering (e.g. DOMPurify.sanitize(content)) and pass the result to __html. If you use a custom escaper, add its name to .vibe-audit.json "customEscapers". Better yet, avoid dangerouslySetInnerHTML and rely on React\'s built-in escaping.',
      });
    }

    return findings;
  },
};
