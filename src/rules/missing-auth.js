/**
 * Rule: missing-auth (AST-enhanced)
 * Detects API routes and server endpoints that lack authentication checks.
 *
 * AST upgrade: Checks each exported handler function individually.
 * Old version: "does the file have auth anywhere?" (one auth check
 * covered all routes). New version: "does EACH handler have auth?"
 */

/** @typedef {import('./types.js').Rule} Rule */

import {
  parseSource, findFunctions, containsNode, containsCall,
  getLine, isParseable, walk
} from '../ast.js';

/** Auth check indicators in AST */
function hasAuthCheckAST(funcBody) {
  // Look for common auth function calls
  if (containsCall(funcBody, /^(?:getServerSession|getSession|auth|getAuth|verifyIdToken|requireAuth|isAuthenticated|authenticate|withAuth|getToken|verifyToken|currentUser|getUser)$/i)) return true;

  // Look for req.user / request.auth access
  if (containsNode(funcBody, (node) => {
    if (node.type !== 'MemberExpression') return false;
    const prop = node.property;
    if (prop.type !== 'Identifier') return false;
    if (/^(?:user|auth)$/.test(prop.name)) {
      const obj = node.object;
      if (obj.type === 'Identifier' && /^(?:req|request|session)$/.test(obj.name)) return true;
    }
    return false;
  })) return true;

  // Look for jwt.verify, admin.auth()
  if (containsCall(funcBody, /^(?:verify|verifyIdToken)$/i)) return true;

  return false;
}

/** Find exported handler functions (Next.js App Router style) */
function findExportedHandlers(ast) {
  const handlers = [];

  walk(ast, (node) => {
    // export async function GET/POST/PUT/PATCH/DELETE
    if (node.type === 'ExportNamedDeclaration' && node.declaration) {
      const decl = node.declaration;
      if (decl.type === 'FunctionDeclaration' && decl.id) {
        if (/^(?:GET|POST|PUT|PATCH|DELETE)$/.test(decl.id.name)) {
          handlers.push({ name: decl.id.name, body: decl.body, loc: decl.loc });
        }
      }
    }
  });

  return handlers;
}

// Regex fallback
const ROUTE_REGEX = [
  { regex: /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\(/g, framework: 'Next.js' },
  { regex: /export\s+default\s+(?:async\s+)?function\s*(?:\w+)?\s*\(\s*req\s*,\s*res\s*\)/g, framework: 'Next.js' },
  { regex: /(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]/g, framework: 'Express' },
];
const AUTH_REGEX = [
  /(?:getServerSession|getSession|auth\(\)|getAuth|verifyIdToken|requireAuth|isAuthenticated|authenticate|withAuth|authMiddleware|getToken|verifyToken|clerkClient|currentUser|getUser)/i,
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

    const isDemoRoute = /(?:demo|test|debug|sandbox)/i.test(file.relativePath);

    if (isParseable(file.relativePath)) {
      const ast = parseSource(file.content);
      if (ast) {
        const findings = [];

        // Check each exported handler individually
        const handlers = findExportedHandlers(ast);
        for (const handler of handlers) {
          if (hasAuthCheckAST(handler.body)) continue;

          const line = handler.loc?.start?.line || 1;
          const message = isDemoRoute
            ? `Unauthenticated test/demo/debug endpoint found: Exported ${handler.name} handler has no authentication check. Leaving unauthenticated test routes in production is a major vulnerability.`
            : `Exported ${handler.name} handler has no authentication check.`;

          findings.push({
            ruleId: 'missing-auth',
            ruleName: 'Missing Authentication',
            severity: 'critical',
            message,
            file: file.relativePath,
            line,
            evidence: file.lines[line - 1]?.trim().slice(0, 120),
            fix: isDemoRoute
              ? `Remove this test/demo endpoint before deploying, or secure it with proper authentication checks at the top: "const session = await getServerSession(); if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 })".`
              : `Add auth at the top: "const session = await getServerSession(); if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 })".`,
          });
        }

        // If no exported handlers found, fall through to regex for Express-style
        if (handlers.length > 0) return findings;
      }
    }

    // Regex fallback
    let hasRouteHandler = false;
    const hasAuthCheck = AUTH_REGEX.some((p) => p.test(file.content));
    if (hasAuthCheck) return [];

    const findings = [];
    for (const { regex, framework } of ROUTE_REGEX) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(file.content)) !== null) {
        hasRouteHandler = true;
        const upTo = file.content.slice(0, match.index);
        const lineNum = upTo.split('\n').length;
        const message = isDemoRoute
          ? `Unauthenticated test/demo/debug endpoint found: ${framework} route handler found with no authentication check in file. Leaving unauthenticated test routes in production is a major vulnerability.`
          : `${framework} route handler found with no authentication check in file.`;

        findings.push({
          ruleId: 'missing-auth',
          ruleName: 'Missing Authentication',
          severity: 'critical',
          message,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim(),
          fix: isDemoRoute
            ? `Add authentication before processing, or delete this file. Ensure test/demo endpoints are either fully secured or deleted before production deployment.`
            : `Add authentication before processing. Verify the user's session/token at the top of every handler.`,
        });
      }
    }
    return findings;
  },
};
