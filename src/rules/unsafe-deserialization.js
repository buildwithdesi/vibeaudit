/**
 * Rule: unsafe-deserialization
 * Detects deserialization / dynamic-code primitives that execute attacker-controlled
 * input: node-serialize's unserialize() (a documented RCE) and vm.runInNewContext /
 * runInContext / compileFunction (arbitrary code execution). JSON.parse is safe and is
 * NOT flagged.
 *
 * Regex over parseable files, tight to the unambiguous RCE sinks — these rarely appear
 * in legit web app code, so false positives stay near zero.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const PARSEABLE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;

const PATTERNS = [
  {
    regex: /\bunserialize\s*\(/,
    label: 'node-serialize unserialize() deserializes untrusted data — a documented remote code execution sink.',
  },
  {
    regex: /\bvm\.(?:runInNewContext|runInContext|compileFunction)\s*\(/,
    label: 'vm.runInNewContext/runInContext/compileFunction executes code from a string — RCE if the source is user-influenced.',
  },
];

/** @type {Rule} */
export const unsafeDeserialization = {
  id: 'unsafe-deserialization',
  name: 'Unsafe Deserialization',
  severity: 'critical',
  description: 'Detects node-serialize unserialize() and vm.runIn* — deserialization / dynamic-code sinks that run attacker-controlled input.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!PARSEABLE.test(file.relativePath)) return [];

    const findings = [];
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      for (const { regex, label } of PATTERNS) {
        if (regex.test(line)) {
          findings.push({
            ruleId: 'unsafe-deserialization',
            ruleName: 'Unsafe Deserialization',
            severity: 'critical',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: 'Never deserialize or execute untrusted input. Use JSON.parse() for data (never node-serialize). If you must run sandboxed logic, use a real sandbox (isolated-vm) with strict limits — plain vm is not a security boundary.',
          });
          break;
        }
      }
    }
    return findings;
  },
};
