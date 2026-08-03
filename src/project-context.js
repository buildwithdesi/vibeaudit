/**
 * Project-level facts gathered while the file stream is consumed.
 *
 * Rules are strictly per-file: `rule.check(file)` sees one file and nothing
 * else. That is fine for most checks, but it makes `missing-auth` structurally
 * wrong on any app that authenticates in middleware — the route handler has no
 * visible guard, so every route in the app reports as unauthenticated.
 *
 * The file stream is one-shot (remote scans come from the GitHub API), so a
 * real second pass would mean buffering every file. Instead we collect one
 * small summary object during the existing loop and post-filter the findings
 * after it. Order does not matter because filtering happens at the end.
 */

import { parseSource, isParseable, walk, callsAuthGuard, collectImportedNames } from './ast.js';

const MIDDLEWARE_FILE = /(?:^|\/)(?:src\/)?middleware\.[mc]?[jt]sx?$/i;

/** Middleware helpers that ARE the auth mechanism when called. */
const MIDDLEWARE_AUTH = /^(?:clerkMiddleware|authMiddleware|withClerkMiddleware|withAuth|NextAuth|updateSession|createMiddlewareClient|createServerClient)$/;

/** @returns {{ authMiddleware: null | { guarded: boolean, prefixes: string[] } }} */
export function createProjectContext() {
  return { authMiddleware: null };
}

/**
 * Record anything project-wide this file tells us. Called once per file.
 *
 * @param {{ relativePath: string, content: string }} file
 * @param {ReturnType<typeof createProjectContext>} ctx
 */
export function collectProjectFact(file, ctx) {
  if (!MIDDLEWARE_FILE.test(file.relativePath)) return;
  if (!isParseable(file.relativePath)) return;

  const ast = parseSource(file.content);
  if (!ast) return;

  const imported = collectImportedNames(ast);
  let guarded = callsAuthGuard(ast, imported);

  // A bare `clerkMiddleware()` export is the guard, but it is a call to an
  // imported name that the generic hint regex does not always reach.
  if (!guarded) {
    walk(ast, (node) => {
      if (guarded) return;
      if (node.type !== 'CallExpression') return;
      const callee = node.callee;
      const name =
        callee.type === 'Identifier'
          ? callee.name
          : callee.type === 'MemberExpression' && callee.property?.type === 'Identifier'
            ? callee.property.name
            : null;
      // Require a CALL, not merely an import — a file that imports Clerk and
      // never invokes it is not protecting anything.
      if (name && MIDDLEWARE_AUTH.test(name)) guarded = true;
    });
  }

  ctx.authMiddleware = { guarded, prefixes: matcherPrefixes(ast) };
}

/**
 * Read `export const config = { matcher: [...] }` and reduce each entry to the
 * plain path prefix it covers.
 *
 * @param {import('acorn').Node} ast
 * @returns {string[]}
 */
function matcherPrefixes(ast) {
  const prefixes = [];
  walk(ast, (node) => {
    if (node.type !== 'Property') return;
    const key = node.key?.name || node.key?.value;
    if (key !== 'matcher') return;

    const entries =
      node.value?.type === 'ArrayExpression'
        ? node.value.elements
        : node.value?.type === 'Literal'
          ? [node.value]
          : [];

    for (const el of entries) {
      if (!el || el.type !== 'Literal' || typeof el.value !== 'string') continue;
      const p = normalizeMatcher(el.value);
      if (p !== null) prefixes.push(p);
    }
  });
  return prefixes;
}

/**
 * `/api/:path*` → `/api`, `/api/(.*)` → `/api`, a negative-lookahead catch-all
 * → `/`. Returns null when the entry is too exotic to reduce safely, which is
 * the conservative answer: no prefix means no downgrade.
 *
 * @param {string} raw
 * @returns {string | null}
 */
export function normalizeMatcher(raw) {
  let p = String(raw).trim();
  if (!p.startsWith('/')) return null;

  // A negative-lookahead group is Next's "everything except these" catch-all.
  if (p.includes('(?!')) return '/';

  p = p.replace(/\/:\w+\*?\??.*$/, '');
  p = p.replace(/\/?\(\.\*\)\$?$/, '');
  p = p.replace(/\/?\.\*\$?$/, '');
  p = p.replace(/\$$/, '');
  p = p.replace(/\/+$/, '');

  if (p === '') return '/';
  // Anything still carrying regex metacharacters is not a plain prefix.
  if (/[()[\]{}*+?|\\^$]/.test(p)) return null;
  return p;
}

/**
 * Map a route file to the URL path it serves.
 * `src/app/api/x/route.ts` → `/api/x`; `pages/api/x.ts` → `/api/x`.
 *
 * @param {string} relativePath
 * @returns {string | null}
 */
export function routeUrlFor(relativePath) {
  const p = String(relativePath).replace(/\\/g, '/');

  const app = /(?:^|\/)app\/(.+)\/route\.[mc]?[jt]sx?$/i.exec(p);
  if (app) {
    const segments = app[1]
      .split('/')
      // Route groups `(marketing)` and parallel slots `@modal` are not in the URL.
      .filter((s) => !/^\(.*\)$/.test(s) && !s.startsWith('@'));
    return '/' + segments.join('/');
  }

  const pages = /(?:^|\/)pages\/(api\/.+)\.[mc]?[jt]sx?$/i.exec(p);
  if (pages) return '/' + pages[1].replace(/\/index$/, '');

  return null;
}

/** Does `prefix` cover `url`? */
function covers(prefix, url) {
  if (prefix === '/') return true;
  return url === prefix || url.startsWith(prefix + '/');
}

/**
 * Downgrade `missing-auth` findings on routes that middleware already covers.
 *
 * Deliberately a downgrade, not a deletion: a matcher can cover `/api` while
 * the middleware only sets headers, and a rewrite can expose a route the
 * matcher never sees. Reclassifying takes them out of the critical count that
 * drives the F grade while keeping them visible and `--strict`-failable.
 *
 * @param {Array} findings
 * @param {ReturnType<typeof createProjectContext>} ctx
 * @returns {Array}
 */
export function applyProjectContext(findings, ctx) {
  const mw = ctx?.authMiddleware;
  if (!mw || !mw.guarded || !mw.prefixes.length) return findings;

  return findings.map((f) => {
    if (f.ruleId !== 'missing-auth' || f.severity !== 'critical') return f;

    const url = routeUrlFor(f.file);
    if (!url) return f;

    const prefix = mw.prefixes.find((p) => covers(p, url));
    if (!prefix) return f;

    return {
      ...f,
      severity: 'warning',
      message: `${f.message} Auth appears to be enforced by middleware (matcher "${prefix}") — verify that matcher really covers this route.`,
    };
  });
}
