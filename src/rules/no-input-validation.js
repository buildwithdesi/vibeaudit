/**
 * Rule: no-input-validation
 * Detects patterns where user input is used without validation or sanitization.
 *
 * Context-aware: `innerHTML` and `document.write` are only flagged when the
 * value is dynamic AND not run through an escaper/sanitizer. Static template
 * strings (`el.innerHTML = `<button>…`) and escaped values (`esc(x)`) are safe
 * and no longer reported.
 *
 * Two categories are deliberately NOT handled here, to avoid double-counting:
 * `dangerouslySetInnerHTML` is owned by its dedicated rule, and SQL injection
 * is owned by `sql-injection`. Both used to be duplicated here, which meant one
 * defect produced two criticals and inflated every report.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { escapersFor, escaperRegex } from '../context.js';

// Paths where a "dangerous" pattern is noise: tests, type stubs, generated or
// vendored bundles. Mirrors sql-injection.js and dangerously-set-inner-html.js,
// both of which have always had one.
const SKIP_PATH =
  /(?:\.test\.|\.spec\.|__tests__|\.d\.ts$|node_modules|(?:^|\/)(?:dist|build|vendor|coverage)\/|\.min\.js$|src\/rules\/)/i;

// The JS-only patterns below are meaningless in a stylesheet, a Python script,
// or a YAML file, all of which the scanner happily feeds this rule.
const JS_LIKE = /\.(?:[cm]?[jt]sx?|html?|vue|svelte|astro)$/i;

/** Patterns that indicate dangerous direct use of user input (excluding innerHTML/dSIH). */
const DANGEROUS_PATTERNS = [
  {
    regex: /\beval\s*\(\s*[^)'"\s]/g,
    label: 'eval() with dynamic input — code injection risk',
    severity: 'critical',
  },
  {
    regex: /new\s+Function\s*\(\s*[^)'"\s]/g,
    label: 'new Function() with dynamic input — code injection risk',
    severity: 'critical',
  },
  {
    regex: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:[`'"].*\$\{|.*\+\s*(?:req\.|request\.|params\.))/gi,
    label: 'Shell command with user input — command injection risk',
    severity: 'critical',
  },
  {
    regex: /(?:res\.redirect|window\.location|location\.href)\s*[=(]\s*(?:req\.|request\.|params\.|query\.|searchParams)/gi,
    label: 'Redirect using unvalidated user input — open redirect risk',
    severity: 'warning',
  },
];

// Capture to end of line. NOT `[^;]*` — HTML entities like &#10024; contain
// semicolons and would truncate a static string into a fake "dynamic" value.
// NOT `(.+)$` either — `.` excludes `\r` and `$` won't anchor before a lone
// CRLF `\r`, so that silently captures nothing on Windows-checked-out files.
const INNERHTML = /\.innerHTML\s*=\s*([^\r\n]*)/;

// Same treatment for document.write. It used to fire unconditionally, so
// `document.write('<p>hi</p>')` — a static literal with no user input anywhere
// near it — was reported as critical.
const DOC_WRITE = /\bdocument\.write(?:ln)?\s*\(([^\r\n]*)/;

/**
 * Is an innerHTML right-hand side actually dangerous (dynamic + unescaped)?
 * @param {string} rhs - text after `innerHTML =` up to the statement end
 * @param {RegExp} escRe - matches escaper/sanitizer calls
 */
/**
 * Does `v` BEGIN with a complete, interpolation-free string/template literal
 * that is not concatenated onto? If so it's static even when trailing code
 * follows on the same line (e.g. `` `<div>…</div>`; return; } ``). A literal
 * followed by `+` (concatenation) is NOT static.
 */
function leadingStaticLiteral(v) {
  const m =
    /^'(?:[^'\\]|\\.)*'/.exec(v) ||
    /^"(?:[^"\\]|\\.)*"/.exec(v) ||
    /^`(?:[^`\\$]|\\.|\$(?!\{))*`/.exec(v); // template with no ${…} interpolation
  if (!m) return false;
  const rest = v.slice(m[0].length).trim();
  return rest === '' || /^[;,)}\]]/.test(rest) || rest.startsWith('return');
}

function isDynamicUnescaped(rhs, escRe) {
  const v = rhs.trim();
  if (!v) return false; // `el.innerHTML =` with nothing meaningful on the line
  if (escRe.test(v)) return false; // escaped / sanitized
  if (leadingStaticLiteral(v)) return false; // static literal (incl. trailing code)

  // An unterminated template fragment (multi-line static HTML) with no
  // interpolation and no concatenation on this line is also static.
  if (v.startsWith('`') && !v.includes('${') && !v.includes('`', 1) && !v.includes('+')) return false;

  return true;
}

/** @type {Rule} */
export const noInputValidation = {
  id: 'no-input-validation',
  name: 'No Input Validation',
  severity: 'critical',
  description: 'Detects patterns where user input is used unsafely without validation or sanitization.',

  check(file) {
    if (SKIP_PATH.test(file.relativePath)) return [];
    if (!JS_LIKE.test(file.relativePath)) return [];

    const findings = [];
    const escRe = escaperRegex(escapersFor(file));

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;

      // document.write — same context test as innerHTML. Static markup is safe;
      // an interpolated or variable argument is the XSS vector.
      const dw = line.match(DOC_WRITE);
      if (dw) {
        const arg = dw[1].trim().replace(/\)\s*;?\s*$/, '');
        if (isDynamicUnescaped(arg, escRe)) {
          findings.push({
            ruleId: 'no-input-validation',
            ruleName: 'No Input Validation',
            severity: 'critical',
            message: 'document.write() with a dynamic, unescaped value — XSS vector',
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: 'Avoid document.write entirely. Build nodes with createElement/textContent, or sanitize the value first (e.g. DOMPurify).',
          });
        }
      }

      // innerHTML — context-aware (only dynamic, unescaped assignments).
      const inner = line.match(INNERHTML);
      if (inner) {
        const rhs = inner[1].trim().replace(/;+\s*$/, '');
        if (isDynamicUnescaped(rhs, escRe)) {
          // Multi-line builders (open template / .map() / `=>` / `{`) escape inside
          // the block the single line can't see — clear them if an escaper appears.
          const continues = /[`{(,]$|=>$/.test(rhs);
          const escapedBlock = continues && escRe.test(file.lines.slice(i, i + 15).join('\n'));
          if (!escapedBlock) {
            findings.push({
              ruleId: 'no-input-validation',
              ruleName: 'No Input Validation',
              severity: 'critical',
              message: 'Direct innerHTML assignment with dynamic, unescaped value — potential XSS vector',
              file: file.relativePath,
              line: i + 1,
              evidence: trimmed.slice(0, 120),
              fix: 'Escape/sanitize the value before assigning to innerHTML (e.g. an esc()/DOMPurify wrapper), or use textContent for plain text.',
            });
          }
        }
      }

      for (const { regex, label, severity } of DANGEROUS_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'no-input-validation',
            ruleName: 'No Input Validation',
            severity,
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Sanitize all user input before use. For HTML: use a sanitization library or textContent instead of innerHTML. For SQL: use parameterized queries. For shell: use allowlists, never interpolate user input into commands.`,
          });
        }
      }
    }

    return findings;
  },
};
