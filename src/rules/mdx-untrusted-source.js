/**
 * Rule: mdx-untrusted-source
 * Detects an MDX compile/render call in a file that also reads from a
 * database, a request body, or a network fetch.
 *
 * MDX is not a document format — it compiles to a JavaScript module. Anyone
 * who can write to whatever feeds the compile call (a posts table, a form
 * submission, an API response) can run code inside your build or your
 * visitors' browsers. Plain Markdown has no such risk; it just renders to
 * HTML. This is the MDX-specific sibling of template-injection.js — same
 * weakness class (CWE-1336, a template engine executing attacker-reachable
 * input), different engine family (next-mdx-remote / @mdx-js/mdx instead of
 * Handlebars/EJS/Pug).
 *
 * Regex, not AST, on purpose: this codebase's parser (acorn) does not handle
 * JSX, and the highest-signal real-world case — `<MDXRemote source={...} />`
 * — is JSX. See dangerously-set-inner-html.js for the same tradeoff on a
 * neighboring rule.
 *
 * Tight by design: fires only when an MDX-compile API appears in a file that
 * ALSO shows a database/request/fetch origin. A static local MDX pipeline
 * (fs.readFileSync of a repo-owned .mdx file, no DB/network signal) does not
 * trip this — only compile.md/serialize.md targets that could realistically
 * be sourced from outside the repo do.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

// next-mdx-remote's three real entry points (serialize/compileMDX/<MDXRemote>),
// plus @mdx-js/mdx's own compile/evaluate — every mainstream "compile MDX at
// runtime from a variable" API.
const MDX_API = /(?:compileMDX|serialize|evaluate(?:Sync)?)\s*\(|<MDXRemote\b/;

// Signals that whatever feeds the MDX call could have come from outside the
// repo: a database read, a raw request body, or a network fetch. A file that
// only reads local .mdx files off disk will not match any of these.
const UNTRUSTED_ORIGIN =
  /(?:supabase|prisma\.|\.from\s*\(\s*['"`]|db\.query|req\.body|formData\.get|searchParams\.get|await\s+fetch\s*\()/i;

/** @type {Rule} */
export const mdxUntrustedSource = {
  id: 'mdx-untrusted-source',
  name: 'MDX Compiled From Untrusted Source',
  severity: 'critical',
  description:
    'Detects an MDX compile/render call (next-mdx-remote, @mdx-js/mdx) in a file that also reads from a database, request body, or fetch — MDX compiles to executable JS, so untrusted content here is remote code execution, not a rendering bug.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!/mdx/i.test(file.content)) return []; // cheap pre-filter before the heavier regexes
    if (!UNTRUSTED_ORIGIN.test(file.content)) return []; // no dynamic-origin signal in this file at all

    const findings = [];
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;
      const match = MDX_API.exec(line);
      MDX_API.lastIndex = 0; // MDX_API has no /g flag, but stay defensive
      if (!match) continue;

      const apiName = match[0].replace(/[\s(<]/g, '');
      findings.push({
        ruleId: 'mdx-untrusted-source',
        ruleName: 'MDX Compiled From Untrusted Source',
        severity: 'critical',
        message: `${apiName} compiles MDX in a file that also reads from a database/request/fetch — MDX compiles to a JS module, so this is remote code execution if that content is ever attacker-reachable.`,
        file: file.relativePath,
        line: i + 1,
        evidence: line.trim().slice(0, 120),
        fix: 'Never compile MDX from anything a non-owner can write (a DB row, a form submission, an API response). Keep MDX authored only by trusted maintainers in the repo. For guest or user-submitted content, use plain Markdown through a sanitizer (e.g. remark + rehype-sanitize) — never MDX.',
      });
    }
    return findings;
  },
};
