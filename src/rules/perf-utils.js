/**
 * Shared scope analysis for the scale / performance rule pack.
 *
 * The point of these helpers is precision: a query "inside a loop" is N+1, but a query
 * inside an array-iteration callback that gets Promise.all'd is fine. Both look similar
 * textually — the difference is whether a loop actually runs the node repeatedly WITHIN
 * its nearest function scope. These helpers answer that from an ancestors chain (the
 * root→parent path acorn's walk() provides).
 */

const LOOP_TYPES = new Set([
  'ForStatement',
  'ForInStatement',
  'ForOfStatement',
  'WhileStatement',
  'DoWhileStatement',
]);

const FUNCTION_TYPES = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
]);

// Array iteration methods that take a per-element callback.
const ITER_METHODS = /^(?:map|forEach|reduce|reduceRight|filter|flatMap|some|every|find|findIndex)$/;

/** Index of the nearest enclosing function in an ancestors chain, or -1 (module scope). */
function nearestFunctionIndex(ancestors) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    if (FUNCTION_TYPES.has(ancestors[i].type)) return i;
  }
  return -1;
}

/**
 * Type of a loop that encloses the node WITHIN its nearest function scope — i.e. the
 * loop actually runs the node repeatedly — or null. Skips `for await…of`, which is
 * legitimate sequential async iteration, not an antipattern.
 *
 * @param {import('acorn').Node[]} ancestors
 * @returns {string | null}
 */
export function enclosingLoop(ancestors) {
  const fIdx = nearestFunctionIndex(ancestors);
  for (let i = ancestors.length - 1; i > fIdx; i--) {
    const node = ancestors[i];
    if (LOOP_TYPES.has(node.type)) {
      if (node.type === 'ForOfStatement' && node.await) continue; // `for await…of` is intentional
      return node.type;
    }
  }
  return null;
}

/**
 * True if the node lives directly inside an array-iteration callback
 * (arr.map(fn), items.forEach(fn), …) — where running N items in parallel via
 * Promise.all is expected, not an antipattern.
 *
 * @param {import('acorn').Node[]} ancestors
 * @returns {boolean}
 */
export function inIterationCallback(ancestors) {
  const fIdx = nearestFunctionIndex(ancestors);
  if (fIdx <= 0) return false;
  const parent = ancestors[fIdx - 1];
  return Boolean(
    parent &&
      parent.type === 'CallExpression' &&
      parent.callee &&
      parent.callee.type === 'MemberExpression' &&
      parent.callee.property &&
      parent.callee.property.type === 'Identifier' &&
      ITER_METHODS.test(parent.callee.property.name),
  );
}
