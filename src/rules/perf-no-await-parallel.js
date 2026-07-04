/**
 * Rule: perf-no-await-parallel
 * Detects `await` inside a loop, where independent async work runs one-at-a-time
 * instead of together with Promise.all. Ten 200ms calls take 2s sequentially and
 * 200ms in parallel.
 *
 * AST-based and scope-aware: an await inside a .map/.forEach callback is NOT flagged
 * (that's the parallel pattern), and `for await…of` is left alone (intentional
 * sequential async iteration). Kept a warning, not critical — a truly dependent
 * sequence is a legitimate reason to await in a loop.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, walk, isParseable } from '../ast.js';
import { enclosingLoop } from './perf-utils.js';

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

/**
 * `await Promise.all/allSettled/race/any(...)` IS the parallel/batched pattern —
 * awaiting combined promises (often once per concurrency chunk) is correct, not the
 * antipattern. Never flag it.
 */
function isParallelCombinator(arg) {
  return Boolean(
    arg &&
      arg.type === 'CallExpression' &&
      arg.callee &&
      arg.callee.type === 'MemberExpression' &&
      arg.callee.object &&
      arg.callee.object.type === 'Identifier' &&
      arg.callee.object.name === 'Promise' &&
      arg.callee.property &&
      arg.callee.property.type === 'Identifier' &&
      /^(?:all|allSettled|race|any)$/.test(arg.callee.property.name),
  );
}

/** @type {Rule} */
export const perfNoAwaitParallel = {
  id: 'perf-no-await-parallel',
  name: 'Sequential Await in Loop',
  severity: 'warning',
  description: 'Detects await inside a loop — independent async work that runs one-at-a-time instead of in parallel with Promise.all.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!isParseable(file.relativePath)) return [];
    const ast = parseSource(file.content);
    if (!ast) return [];

    const findings = [];
    const seen = new Set();
    walk(ast, (node, ancestors) => {
      if (node.type !== 'AwaitExpression') return;
      if (isParallelCombinator(node.argument)) return; // await Promise.all(...) is the fix, not the bug
      if (!enclosingLoop(ancestors)) return;

      const line = node.loc?.start?.line || 0;
      if (seen.has(line)) return;
      seen.add(line);

      findings.push({
        ruleId: 'perf-no-await-parallel',
        ruleName: 'Sequential Await in Loop',
        severity: 'warning',
        message:
          'await inside a loop runs each iteration one-at-a-time. If the iterations are independent, they should run in parallel.',
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'If each iteration is independent, collect the promises and await them together: const results = await Promise.all(items.map(async (i) => { ... })). Keep the sequential await only when an iteration truly depends on the previous one.',
      });
    });
    return findings;
  },
};
