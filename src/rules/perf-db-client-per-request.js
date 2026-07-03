/**
 * Rule: perf-db-client-per-request
 * Detects a pooled DB client (PrismaClient, pg Pool, Sequelize) instantiated INSIDE a
 * function instead of once at module scope. On serverless every request runs the
 * handler fresh, so a per-request `new PrismaClient()` opens a new connection each time
 * and exhausts the pool ("too many connections", then the app falls over). The #1
 * Prisma-on-Vercel footgun.
 *
 * Scope-aware, like the rest of the perf pack: a module-scope singleton is correct and
 * left alone; the globalThis singleton (the documented fix) is left alone; only a client
 * created per-request-scoped function is flagged.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, walk, isParseable, containsNode } from '../ast.js';

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

// Pooled clients where a fresh instance per request exhausts the connection pool.
const POOLED_CLIENTS = /^(?:PrismaClient|Pool|Sequelize)$/;

const FUNCTION_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);

function insideFunction(ancestors) {
  return ancestors.some((a) => FUNCTION_TYPES.has(a.type));
}

/**
 * The Next.js singleton caches the instance on globalThis/global (const prisma =
 * globalThis.prisma ?? new PrismaClient(), or globalThis.x ??= new PrismaClient()).
 * That's the fix — never flag it.
 */
function isGlobalSingleton(ancestors) {
  for (const a of ancestors) {
    if (a.type !== 'AssignmentExpression' && a.type !== 'LogicalExpression') continue;
    if (a.left && containsNode(a.left, (n) => n.type === 'Identifier' && /global/i.test(n.name))) {
      return true;
    }
  }
  return false;
}

/** @type {Rule} */
export const perfDbClientPerRequest = {
  id: 'perf-db-client-per-request',
  name: 'DB Client Created Per Request',
  severity: 'warning',
  description: 'Detects a pooled DB client (PrismaClient, pg Pool, Sequelize) created inside a function instead of a module-scope singleton — on serverless, every request opens a new connection and exhausts the pool.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!isParseable(file.relativePath)) return [];
    const ast = parseSource(file.content);
    if (!ast) return [];

    const findings = [];
    const seen = new Set();
    walk(ast, (node, ancestors) => {
      if (node.type !== 'NewExpression') return;
      const callee = node.callee;
      if (!callee || callee.type !== 'Identifier' || !POOLED_CLIENTS.test(callee.name)) return;
      if (!insideFunction(ancestors)) return; // module-scope singleton is correct
      if (isGlobalSingleton(ancestors)) return; // globalThis.x ?? new ... is the fix

      const line = node.loc?.start?.line || 0;
      if (seen.has(line)) return;
      seen.add(line);

      findings.push({
        ruleId: 'perf-db-client-per-request',
        ruleName: 'DB Client Created Per Request',
        severity: 'warning',
        message: `new ${callee.name}() runs inside a function — on serverless, every request opens a new connection and exhausts the pool ("too many connections", then the app falls over).`,
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Instantiate the client ONCE at module scope and reuse it. In Next.js / serverless, cache it on globalThis to survive hot reloads: `const prisma = globalThis.prisma ?? new PrismaClient(); if (process.env.NODE_ENV !== "production") globalThis.prisma = prisma;`',
      });
    });
    return findings;
  },
};
