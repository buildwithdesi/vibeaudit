/**
 * Rule: template-injection
 * Detects server-side template injection (SSTI): a template engine compiling/rendering a
 * template string built from dynamic input. Handlebars/EJS/Pug/Nunjucks/lodash all
 * execute logic inside templates, so a user-controlled template is remote code execution.
 *
 * AST-based and tight: compiling a STATIC template string is safe and NOT flagged — only
 * a template assembled from `${...}` interpolation or `+` concatenation trips it.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, walk, isParseable } from '../ast.js';

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

// Template engines whose compile/render executes the template.
const ENGINE = /^(?:Handlebars|handlebars|ejs|pug|jade|nunjucks|_|dot|eta|Twig)$/;
const TEMPLATE_METHOD = /^(?:compile|render|renderString|template|compileFile)$/;

/** A template string assembled from interpolation or concatenation — attacker-influenceable. */
function isInjectable(arg) {
  if (!arg) return false;
  if (arg.type === 'TemplateLiteral') return arg.expressions.length > 0;
  if (arg.type === 'BinaryExpression' && arg.operator === '+') return true;
  return false;
}

/** @type {Rule} */
export const templateInjection = {
  id: 'template-injection',
  name: 'Server-Side Template Injection',
  severity: 'critical',
  description: 'Detects a template engine (Handlebars/EJS/Pug/Nunjucks) compiling a template built from dynamic input — a user-controlled template is remote code execution.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!isParseable(file.relativePath)) return [];
    const ast = parseSource(file.content);
    if (!ast) return [];

    const findings = [];
    const seen = new Set();
    walk(ast, (node) => {
      if (node.type !== 'CallExpression') return;
      const callee = node.callee;
      if (
        callee.type !== 'MemberExpression' ||
        callee.object.type !== 'Identifier' ||
        callee.property.type !== 'Identifier' ||
        !ENGINE.test(callee.object.name) ||
        !TEMPLATE_METHOD.test(callee.property.name)
      ) {
        return;
      }
      if (!isInjectable(node.arguments[0])) return;

      const line = node.loc?.start?.line || 0;
      if (seen.has(line)) return;
      seen.add(line);

      findings.push({
        ruleId: 'template-injection',
        ruleName: 'Server-Side Template Injection',
        severity: 'critical',
        message: `${callee.object.name}.${callee.property.name}() compiles a template built from dynamic input — if any of it is user-controlled, the template engine runs it as code (SSTI → RCE).`,
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Never build a template from user input. Keep templates static and pass user data as DATA (the render context), not as the template string: `template = Handlebars.compile(STATIC_SOURCE); template({ userName })`.',
      });
    });
    return findings;
  },
};
