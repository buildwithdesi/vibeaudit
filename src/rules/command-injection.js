/**
 * Rule: command-injection
 * Detects a child_process shell call (exec/execSync/spawn/execFile) whose command is
 * BUILT from dynamic input — a template literal with interpolation or string
 * concatenation. If any of that input is user-controlled, it's remote code execution:
 * one `; rm -rf /` away.
 *
 * AST-based and tight to hold zero false positives: a static command string
 * (`exec('ls -la')`) or an argument array (`execFile('git', [arg])`) is safe and NOT
 * flagged — only a command assembled from `${...}` or `'...' + x` trips it.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, walk, isParseable } from '../ast.js';

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const CMD_FUNCS = /^(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/;

function calleeName(node) {
  const c = node.callee;
  if (c.type === 'Identifier') return c.name;
  if (c.type === 'MemberExpression' && c.property.type === 'Identifier') return c.property.name;
  return null;
}

/** A command string assembled from interpolation or concatenation — attacker-influenceable. */
function isInjectable(arg) {
  if (!arg) return false;
  if (arg.type === 'TemplateLiteral') return arg.expressions.length > 0; // `cmd ${x}`
  if (arg.type === 'BinaryExpression' && arg.operator === '+') return true; // 'cmd ' + x
  return false; // a plain string literal (or a bare variable) is not flagged
}

/** @type {Rule} */
export const commandInjection = {
  id: 'command-injection',
  name: 'OS Command Injection',
  severity: 'critical',
  description: 'Detects child_process exec/spawn calls whose command is built from interpolated or concatenated input — user input flowing into a shell is remote code execution.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!isParseable(file.relativePath)) return [];
    const ast = parseSource(file.content);
    if (!ast) return [];

    const findings = [];
    const seen = new Set();
    walk(ast, (node) => {
      if (node.type !== 'CallExpression') return;
      const name = calleeName(node);
      if (!name || !CMD_FUNCS.test(name)) return;
      if (!isInjectable(node.arguments[0])) return;

      const line = node.loc?.start?.line || 0;
      if (seen.has(line)) return;
      seen.add(line);

      findings.push({
        ruleId: 'command-injection',
        ruleName: 'OS Command Injection',
        severity: 'critical',
        message: `${name}() runs a shell command built from interpolated input — if any of it is user-controlled, that's remote code execution (a "; rm -rf" away).`,
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Never build a shell command from input. Use execFile()/spawn() with the program and an ARGUMENT ARRAY (no `shell: true`) so args can\'t break out: `execFile("convert", [userFile, out])`. If a value must reach a shell, strictly allowlist it.',
      });
    });
    return findings;
  },
};
