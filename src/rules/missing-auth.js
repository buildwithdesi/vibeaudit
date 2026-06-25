/**
 * Rule: missing-auth (AST-enhanced, context-aware)
 * Detects API routes / server endpoints whose exported handlers lack an
 * authentication check.
 *
 * Upgrade: auth detection now recognizes developer-defined guards (e.g. a
 * custom `requireAuthedApiFromReq` imported from a local lib) and wrapped
 * exports (`export const POST = withAuth(handler)`), not just a hardcoded list
 * of framework function names. This kills the dominant false positive where a
 * route is fully guarded by an imported helper the scanner couldn't see.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, isParseable, walk, callsAuthGuard, collectImportedNames } from '../ast.js';

const HTTP_METHOD = /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/;

/** Find exported route handlers: function declarations, const arrows, and wrapped exports. */
function findExportedHandlers(ast) {
  const handlers = [];

  walk(ast, (node) => {
    if (node.type !== 'ExportNamedDeclaration' || !node.declaration) return;
    const decl = node.declaration;

    if (decl.type === 'FunctionDeclaration' && decl.id && HTTP_METHOD.test(decl.id.name)) {
      handlers.push({ name: decl.id.name, body: decl.body, loc: decl.loc });
      return;
    }

    if (decl.type === 'VariableDeclaration') {
      for (const d of decl.declarations || []) {
        if (!d.id?.name || !HTTP_METHOD.test(d.id.name) || !d.init) continue;
        const init = d.init;
        if (init.type === 'ArrowFunctionExpression' || init.type === 'FunctionExpression') {
          handlers.push({ name: d.id.name, body: init.body, loc: d.id.loc || node.loc });
        } else if (init.type === 'CallExpression') {
          // Wrapped export: export const POST = withAuth(handler) — pass the call
          // so a wrapper guard (withAuth/requireAuth/...) is detected.
          handlers.push({ name: d.id.name, body: init, loc: d.id.loc || node.loc });
        }
      }
    }
  });

  return handlers;
}

// Regex fallback for Express-style routers.
const ROUTE_REGEX = [
  { regex: /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\(/g, framework: 'Next.js' },
  { regex: /export\s+default\s+(?:async\s+)?function\s*(?:\w+)?\s*\(\s*req\s*,\s*res\s*\)/g, framework: 'Next.js' },
  { regex: /(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]/g, framework: 'Express' },
];
const AUTH_REGEX = [
  /(?:getServerSession|getSession|auth\(\)|getAuth|verifyIdToken|requireAuth|isAuthenticated|authenticate|withAuth|authMiddleware|getToken|verifyToken|clerkClient|currentUser|getUser)/i,
  /require\w*auth\w*/i,
  /\.use\(\s*[^)]*(?:auth|protect|guard|session)/i,
  /(?:protect|guard|ensureAuth|checkAuth|authorize)\w*\s*\(/i,
  /request\.auth/i, /req\.user/i, /session\.\s*user/i,
  /(?:Authorization|Bearer)\s*.*header/i, /middleware.*auth/i,
  /(?:jwt|token)\.verify/i, /admin\.auth\(\)/i,
];

const API_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/)/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/)/i;

/** @type {Rule} */
export const missingAuth = {
  id: 'missing-auth',
  name: 'Missing Authentication',
  severity: 'critical',
  description: 'Detects API routes and server endpoints that lack authentication checks.',

  check(file) {
    if (!API_FILES.test(file.relativePath)) return [];
    if (SKIP.test(file.relativePath)) return [];

    if (isParseable(file.relativePath)) {
      const ast = parseSource(file.content);
      if (ast) {
        const imported = collectImportedNames(ast);
        const handlers = findExportedHandlers(ast);

        if (handlers.length > 0) {
          const findings = [];
          for (const handler of handlers) {
            if (callsAuthGuard(handler.body, imported, file._config?.customAuthGuards)) continue;

            const line = handler.loc?.start?.line || 1;
            findings.push({
              ruleId: 'missing-auth',
              ruleName: 'Missing Authentication',
              severity: 'critical',
              message: `Exported ${handler.name} handler has no authentication check.`,
              file: file.relativePath,
              line,
              evidence: file.lines[line - 1]?.trim().slice(0, 120),
              fix: `Add an auth check at the top of the handler (e.g. "const session = await getServerSession(); if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 })") or wrap it with your auth guard. If this route is intentionally public, add "// vibe-audit-ignore-next-line missing-auth".`,
            });
          }
          return findings;
        }
      }
    }

    // Regex fallback (Express-style or unparseable files).
    if (AUTH_REGEX.some((p) => p.test(file.content))) return [];

    const findings = [];
    for (const { regex, framework } of ROUTE_REGEX) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'missing-auth',
          ruleName: 'Missing Authentication',
          severity: 'critical',
          message: `${framework} route handler found with no authentication check in file.`,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim(),
          fix: `Verify the user's session/token at the top of every handler. If the route is intentionally public, add "// vibe-audit-ignore-next-line missing-auth".`,
        });
      }
    }
    return findings;
  },
};
