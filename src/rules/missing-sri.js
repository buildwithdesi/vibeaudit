/**
 * Rule: missing-sri
 * Detects an external (CDN) <script> or stylesheet <link> loaded with no Subresource
 * Integrity (`integrity=`) hash. If that CDN is compromised or the URL is hijacked, it
 * runs arbitrary code in your users' browsers and you have no way to notice.
 *
 * Only flags absolute/protocol-relative (external) URLs — same-origin/relative assets
 * you build yourself don't need SRI, so they're not flagged.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const MARKUP = /\.(?:html?|jsx|tsx|vue|svelte|astro|ejs|hbs)$/i;

// <script ...> or <link ...> opening tags.
const TAG = /<(script|link)\b([^>]*)>/gi;
// An external resource URL: https://, http://, or protocol-relative //.
const EXTERNAL = /\b(?:src|href)\s*=\s*["'](?:https?:)?\/\/[^"']+["']/i;

/** @type {Rule} */
export const missingSri = {
  id: 'missing-sri',
  name: 'Missing Subresource Integrity',
  severity: 'warning',
  description: 'Detects external CDN <script>/<link> tags loaded with no integrity hash — a compromised CDN then runs arbitrary code in your users\' browsers.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!MARKUP.test(file.relativePath)) return [];

    const findings = [];
    TAG.lastIndex = 0;
    let match;
    while ((match = TAG.exec(file.content)) !== null) {
      const kind = match[1].toLowerCase();
      const attrs = match[2] || '';
      if (!EXTERNAL.test(attrs)) continue; // relative / same-origin — SRI not needed
      if (kind === 'link' && !/\brel\s*=\s*["']?stylesheet/i.test(attrs)) continue; // only stylesheet links
      if (/\bintegrity\s*=/i.test(attrs)) continue; // already has SRI

      const line = file.content.slice(0, match.index).split('\n').length;
      findings.push({
        ruleId: 'missing-sri',
        ruleName: 'Missing Subresource Integrity',
        severity: 'warning',
        message: `External ${kind === 'script' ? 'script' : 'stylesheet'} loaded from a CDN with no integrity hash — if that CDN is compromised, it runs arbitrary code in your users' browsers and you can't tell.`,
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Add a Subresource Integrity hash and crossorigin: `<script src="https://cdn…/lib.js" integrity="sha384-…" crossorigin="anonymous">`. Better yet, install the package with npm and bundle it so there\'s no third-party CDN in the loop at all.',
      });
    }
    return findings;
  },
};
