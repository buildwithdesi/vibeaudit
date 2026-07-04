/**
 * Rule: perf-n-plus-one
 * Detects a database/network query inside a loop or array iteration — the N+1
 * pattern where one request quietly becomes one-per-row. This is the real culprit
 * behind the "$50k server bill", not the vague "the AI made it sequential".
 *
 * AST-based so it can tell N+1 apart from the correct batched/parallel patterns:
 * a query in a plain helper function (called once) is NOT flagged; only a query a
 * loop or iteration actually runs per-element is.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, walk, isParseable } from '../ast.js';
import { enclosingLoop, inIterationCallback } from './perf-utils.js';

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

// Method names that are unambiguous DB queries (not shared with Array.prototype).
const STRONG_QUERY =
  /^(?:findUnique|findFirst|findMany|findOne|createMany|updateMany|deleteMany|upsert|aggregate|groupBy|execute|query)$/;

// Identifiers that root a DB client — any method call on them is a query.
const DB_ROOT = /^(?:prisma|db|database|supabase|knex|mongoose|pool|sql|conn|connection|repo|repository)$/i;

/** Walk an object/callee chain down to the root identifier name (through .x and .from()). */
function rootIdentifier(node) {
  let cur = node;
  while (cur) {
    if (cur.type === 'MemberExpression') cur = cur.object;
    else if (cur.type === 'CallExpression') cur = cur.callee;
    else break;
  }
  return cur && cur.type === 'Identifier' ? cur.name : null;
}

function isQueryCall(node) {
  if (node.type !== 'CallExpression') return false;
  const callee = node.callee;
  // DB queries only — they're batchable (WHERE ... IN). A network fetch in a loop is
  // real, but "batch with WHERE IN" doesn't apply to it, so that case belongs to
  // perf-no-await-parallel (run them together with Promise.all), not here.
  if (callee.type !== 'MemberExpression') return false;
  const prop = callee.property;
  if (prop && prop.type === 'Identifier' && STRONG_QUERY.test(prop.name)) return true;
  const root = rootIdentifier(callee.object);
  return Boolean(root && DB_ROOT.test(root));
}

/** @type {Rule} */
export const perfNPlusOne = {
  id: 'perf-n-plus-one',
  name: 'N+1 Query in Loop',
  severity: 'warning',
  description: 'Detects a database or network query inside a loop or array iteration — the N+1 pattern that turns one request into hundreds.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!isParseable(file.relativePath)) return [];
    const ast = parseSource(file.content);
    if (!ast) return [];

    const findings = [];
    const seen = new Set();
    walk(ast, (node, ancestors) => {
      if (!isQueryCall(node)) return;
      const loop = enclosingLoop(ancestors);
      const iter = inIterationCallback(ancestors);
      if (!loop && !iter) return;

      const line = node.loc?.start?.line || 0;
      if (seen.has(line)) return;
      seen.add(line);

      const where = loop ? 'a loop' : 'an array iteration (.map/.forEach/…)';
      findings.push({
        ruleId: 'perf-n-plus-one',
        ruleName: 'N+1 Query in Loop',
        severity: 'warning',
        message: `Query runs inside ${where} — the N+1 pattern: one request becomes one-per-row, and at scale that's the "$50k server bill".`,
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Batch it into a single query instead of one per iteration: fetch all rows with WHERE id IN (...) (Prisma: findMany({ where: { id: { in: ids } } })), or a JOIN / include. If the calls are genuinely independent network I/O, at minimum run them together with Promise.all.',
      });
    });
    return findings;
  },
};
