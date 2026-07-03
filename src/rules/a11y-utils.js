/**
 * Shared helpers for the accessibility (WCAG) rule pack.
 *
 * The key primitive is openingTag(): it extracts an element's opening tag from a
 * '<' position while respecting quotes and JSX expression braces, so a handler like
 * onClick={() => f(a > b)} does NOT truncate the attribute scan at the '>' inside it.
 * Naive /<tag[^>]*>/ regexes break on that and produce false positives — which would
 * fail this project's zero-false-positive bar.
 *
 * These rules are static/regex checks (the scanner's acorn build does not parse JSX
 * into element nodes). They catch the low-hanging Level A misses that automated legal
 * scanners flag; they do not fully verify screen-reader UX — pair with axe-core for that.
 */

/** Skip test files, stories, and vendored code — same convention as the other rules. */
export const A11Y_SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|\.stories\.)/i;

/** Files whose markup a11y rules apply to. */
export const MARKUP_FILES = /\.(?:jsx|tsx|html?|vue|svelte|astro)$/i;

/** React component files (for JSX-only checks like onClick handlers). */
export const REACT_FILES = /\.(?:jsx|tsx)$/i;

/**
 * Extract an element's opening tag starting at `start` (which must point at '<'),
 * ending at the tag's own closing '>' — ignoring any '>' inside quotes or {JSX braces}.
 *
 * @param {string} content
 * @param {number} start - index of the '<'
 * @returns {string} the opening tag, e.g. '<img src="x" alt="y">'
 */
export function openingTag(content, start) {
  let depth = 0;
  let quote = null;
  const max = Math.min(content.length, start + 4000);
  for (let i = start; i < max; i++) {
    const c = content[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') quote = c;
    else if (c === '{') depth++;
    else if (c === '}') { if (depth > 0) depth--; }
    else if (c === '>' && depth === 0) return content.slice(start, i + 1);
  }
  return content.slice(start, max);
}

/** 1-indexed line number of a character offset. */
export function lineAt(content, index) {
  return content.slice(0, index).split('\n').length;
}

/** A spread expression ({...props}) may supply attributes we can't see — don't guess. */
export function hasSpread(tag) {
  return /\{\s*\.\.\./.test(tag);
}
