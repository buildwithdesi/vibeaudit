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

// Manual escaping, for when the value passes through a local helper rather
// than a named sanitizer library. Two dialects, both legitimate:
//   - HTML entity escaping, for markup context
//   - closing-tag / line-separator escaping, the correct hardening for JSON-LD
//     inside a <script> tag, where entities would corrupt the JSON
const ESCAPES_HTML =
  /&amp;|&lt;|&gt;|replace\s*\(\s*\/&\/|replaceAll\s*\(\s*['"]&['"]|<\\{1,2}\/|\\{2}u003c|\/\s*<\\?\/\(?script/i;

/**
 * Resolve what `__html` is actually being handed, by looking at the whole file
 * rather than a fixed byte window around the JSX.
 *
 * The window approach missed real sanitization constantly: in one live app the
 * escaping helper was declared at line 240 and used at line 820, so a correct
 * escape-then-decorate function read as an unsanitized XSS sink.
 *
 * Tri-state on purpose:
 *   true  — provably safe, skip
 *   false — provably unsafe, report even if a sanitizer appears nearby
 *   null  — cannot tell, fall back to the proximity heuristic
 *
 * The `false` case matters. `let x = sanitize(a); x = raw;` puts a sanitizer
 * within a few characters of the JSX, so a proximity check alone clears it.
 * Resolution has to be able to override that.
 *
 * @param {string} expr the raw `__html:` expression
 * @param {string} content whole file
 * @param {RegExp} escRe matches known escaper/sanitizer names
 * @returns {boolean|null}
 */
function resolvesSafe(expr, content, escRe, depth = 0) {
  const v = expr.trim();
  if (!v) return null;
  // One hop only: `const safe = escapeForScriptTag(x)` needs the identifier
  // resolved to its RHS and then that call evaluated. Deeper chains are rare
  // and not worth the cycle risk.
  if (depth > 1) return null;

  // Inline literal with no interpolation.
  if (/^['"]/.test(v)) return true;
  if (v.startsWith('`')) return v.includes('${') ? null : true;

  // A call to a sanitizer, or to a locally-defined helper that escapes.
  const call = /^([A-Za-z_$][\w$]*)\s*\(/.exec(v);
  if (call) {
    if (escRe.test(v)) return true;
    return localFunctionEscapes(call[1], content, escRe) ? true : null;
  }

  // A bare identifier: safe only if it has exactly ONE assignment in the file
  // and that assignment is a static literal or an escaper result.
  const ident = /^[A-Za-z_$][\w$]*$/.exec(v);
  if (!ident) return null;

  // Count EVERY assignment, not just declarations. A bare `clean = raw;`
  // after `let clean = sanitize(raw)` carries no declarator keyword, and
  // missing it would let the dangerous reassignment hide behind the safe one.
  const assignments = [
    ...content.matchAll(
      new RegExp(`(?:^|[^\\w$.])(?:(?:const|let|var)\\s+)?${v}\\s*(?::[^=\\n]+)?=(?![=>])\\s*([^\\n]+)`, 'gm'),
    ),
  ];
  // No assignment found — a prop or parameter. Cannot resolve.
  if (assignments.length === 0) return null;
  // More than one assignment: the safe one cannot vouch for the others.
  if (assignments.length > 1) return false;

  const rhs = assignments[0][1].trim().replace(/;+$/, '');
  if (escRe.test(rhs)) return true;
  // Evaluate the right-hand side with the same rules — it is usually a call to
  // a local escaping helper.
  return resolvesSafe(rhs, content, escRe, depth + 1);
}

/**
 * Is `fn` declared in this file, with a body that escapes HTML or calls a
 * sanitizer? Scans a bounded window after the declaration so a huge file
 * cannot make this quadratic.
 */
function localFunctionEscapes(fn, content, escRe) {
  const decl = new RegExp(
    `(?:function\\s+${fn}\\s*\\(|(?:const|let|var)\\s+${fn}\\s*(?::[^=\\n]+)?=\\s*(?:async\\s*)?(?:function|\\())`,
  ).exec(content);
  if (!decl) return false;

  const body = content.slice(decl.index, decl.index + 800);
  return ESCAPES_HTML.test(body) || escRe.test(body);
}

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

      // The identifier appearing in a comment is not a usage. This rule scans
      // raw content, so a JSDoc or an eslint-disable line counted as a finding
      // — including comments that said the file deliberately AVOIDS this API.
      if (!line || line.startsWith('//') || line.startsWith('*') || line.startsWith('/*')) continue;

      // Resolve what __html actually receives, file-wide. This runs BEFORE the
      // proximity check so a definitive "unsafe" verdict cannot be overridden
      // by a sanitizer that merely happens to sit nearby.
      const after = file.content.slice(match.index, match.index + 220);
      const htmlVal = after.match(/__html\s*:\s*([^,}\n]+)/);
      const verdict = htmlVal ? resolvesSafe(htmlVal[1], file.content, escRe) : null;
      if (verdict === true) continue;

      // Only when the value could not be resolved: fall back to looking both
      // directions, since sanitizers are often applied just before the JSX.
      if (verdict === null) {
        const ctx = file.content.slice(Math.max(0, match.index - 140), match.index + 260);
        if (escRe.test(ctx)) continue;
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
