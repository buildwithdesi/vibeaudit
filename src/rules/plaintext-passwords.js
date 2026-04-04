/**
 * Rule: plaintext-passwords (AST-enhanced)
 * Detects code that stores or compares passwords without hashing.
 *
 * AST upgrade: Traces per-function — checks if the function that writes
 * a password to the DB also calls bcrypt.hash/argon2.hash in its scope.
 * Old regex version passed if bcrypt was imported ANYWHERE in the file.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, findFunctions, containsNode, containsCall, getLine, isParseable } from '../ast.js';

/** Does this function write a password to a DB without hashing first? */
function hasPlaintextPasswordWrite(funcBody) {
  // Check if function hashes passwords
  const hasHashing = containsCall(funcBody, /^(?:hash|hashSync|genSalt|genSaltSync|scrypt|pbkdf2)$/i) ||
    containsNode(funcBody, (n) => {
      if (n.type !== 'MemberExpression') return false;
      const obj = n.object;
      const prop = n.property;
      return obj?.type === 'Identifier' && /^(?:bcrypt|argon2|scrypt)$/i.test(obj.name) &&
             prop?.type === 'Identifier' && /^(?:hash|hashSync)$/i.test(prop.name);
    });

  if (hasHashing) return [];

  const findings = [];

  // Look for DB create/update calls that include a "password" property
  containsNode(funcBody, (node) => {
    if (node.type !== 'CallExpression') return false;
    const callee = node.callee;
    if (callee?.type !== 'MemberExpression') return false;
    const method = callee.property;
    if (method?.type !== 'Identifier') return false;
    if (!/^(?:create|update|set|add|insert|save)$/.test(method.name)) return false;

    // Check if arguments contain a password property
    for (const arg of node.arguments) {
      const hasPasswordProp = containsNode(arg, (n) => {
        return n.type === 'Property' && n.key?.type === 'Identifier' &&
               /^(?:password|passwd|hash)$/.test(n.key.name);
      });
      if (hasPasswordProp) { findings.push(node); return false; }
    }
    return false;
  });

  return findings;
}

/** Does this function hash passwords with a weak algorithm (MD5/SHA1)? */
function hasWeakHashForPassword(funcBody) {
  // Only flag if the function deals with passwords
  const hasPasswordRef = containsNode(funcBody, (n) =>
    n.type === 'Identifier' && /^(?:password|passwd|hashedPassword|passwordHash)$/i.test(n.name)
  );
  if (!hasPasswordRef) return [];

  const findings = [];

  // Detect crypto.createHash('md5'|'sha1')
  containsNode(funcBody, (node) => {
    if (node.type !== 'CallExpression') return false;
    const callee = node.callee;
    // crypto.createHash(...)
    if (callee?.type === 'MemberExpression' &&
        callee.property?.type === 'Identifier' && callee.property.name === 'createHash') {
      const arg = node.arguments[0];
      if (arg?.type === 'Literal' && /^(?:md5|sha1|sha-1)$/i.test(arg.value)) {
        findings.push(node);
      }
    }
    // bare createHash(...)
    if (callee?.type === 'Identifier' && callee.name === 'createHash') {
      const arg = node.arguments[0];
      if (arg?.type === 'Literal' && /^(?:md5|sha1|sha-1)$/i.test(arg.value)) {
        findings.push(node);
      }
    }
    return false;
  });

  // Detect md5(password) or sha1(password) — from require('md5') / require('sha1')
  containsNode(funcBody, (node) => {
    if (node.type !== 'CallExpression') return false;
    const callee = node.callee;
    if (callee?.type === 'Identifier' && /^(?:md5|sha1)$/i.test(callee.name)) {
      // Check if any argument references a password
      for (const arg of node.arguments) {
        if (containsNode(arg, (n) =>
          n.type === 'Identifier' && /^(?:password|passwd)$/i.test(n.name)
        )) {
          findings.push(node);
          break;
        }
      }
    }
    return false;
  });

  return findings;
}

/** Does this function compare passwords with === ? */
function hasPlaintextPasswordCompare(funcBody) {
  const findings = [];
  containsNode(funcBody, (node) => {
    if (node.type !== 'BinaryExpression' || !/^[!=]==?$/.test(node.operator)) return false;
    const hasPasswordRef = (n) => containsNode(n, (inner) =>
      inner.type === 'Identifier' && /^(?:password|passwd)$/i.test(inner.name)
    );
    const hasDbRef = (n) => containsNode(n, (inner) =>
      inner.type === 'MemberExpression' && inner.property?.type === 'Identifier' &&
      /^(?:password|passwd|hash)$/i.test(inner.property.name)
    );
    if ((hasPasswordRef(node.left) && hasDbRef(node.right)) ||
        (hasPasswordRef(node.right) && hasDbRef(node.left))) {
      findings.push(node);
    }
    return false;
  });

  // Skip if bcrypt.compare is also in scope
  if (containsCall(funcBody, /^(?:compare|compareSync|verify)$/i)) return [];
  return findings;
}

// Regex fallback
const PLAINTEXT_REGEX = [
  { regex: /\.create\s*\(\s*\{[^}]*password\s*:\s*(?:req\.body|body|request\.body|data)\.password/gi, label: 'Password stored without hashing' },
  { regex: /\.create\s*\(\s*\{[^}]*password\s*:\s*password\b/gi, label: 'Password variable stored directly' },
  { regex: /(?:password|passwd)\s*===?\s*(?:req\.body|body|user|stored|db|record)\.\w*(?:password|passwd)/gi, label: 'Password compared with === instead of bcrypt.compare' },
  { regex: /createHash\s*\(\s*['"](?:md5|sha1|sha-1)['"]\s*\).*(?:password|passwd)/gi, label: 'Password hashed with weak algorithm (MD5/SHA1)' },
  { regex: /(?:password|passwd).*createHash\s*\(\s*['"](?:md5|sha1|sha-1)['"]\s*\)/gi, label: 'Password hashed with weak algorithm (MD5/SHA1)' },
  { regex: /(?:require\s*\(\s*['"](?:md5|sha1)['"]\s*\)|import\s+(?:md5|sha1)\b).*(?:password|passwd)/gi, label: 'Weak hash package used for passwords' },
];
const HASH_REGEX = [/bcrypt/i, /argon2/i, /scrypt/i, /pbkdf2/i, /hashPassword/i, /saltRounds/i];

const AUTH_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/|controllers\/|auth|user|account|register|signup|login)/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|src\/rules\/)/i;

/** @type {Rule} */
export const plaintextPasswords = {
  id: 'plaintext-passwords',
  name: 'Plaintext Passwords',
  severity: 'critical',
  description: 'Detects code that stores or compares passwords without hashing, or uses weak algorithms (MD5/SHA1).',

  check(file) {
    if (!AUTH_FILES.test(file.relativePath)) return [];
    if (SKIP.test(file.relativePath)) return [];
    if (!/password|passwd/i.test(file.content)) return [];

    if (isParseable(file.relativePath)) {
      const ast = parseSource(file.content);
      if (ast) {
        const findings = [];
        for (const func of findFunctions(ast)) {
          for (const node of hasPlaintextPasswordWrite(func.body)) {
            const line = getLine(node);
            findings.push({ ruleId: 'plaintext-passwords', ruleName: 'Plaintext Passwords', severity: 'critical',
              message: `Function "${func.name}" writes a password to the database without hashing it first.`,
              file: file.relativePath, line, evidence: file.lines[line - 1]?.trim().slice(0, 120),
              fix: 'Hash before storing: "const hash = await bcrypt.hash(password, 12)". To verify: "await bcrypt.compare(input, storedHash)".' });
          }
          for (const node of hasPlaintextPasswordCompare(func.body)) {
            const line = getLine(node);
            findings.push({ ruleId: 'plaintext-passwords', ruleName: 'Plaintext Passwords', severity: 'critical',
              message: `Function "${func.name}" compares passwords with === instead of bcrypt.compare — implies plaintext storage.`,
              file: file.relativePath, line, evidence: file.lines[line - 1]?.trim().slice(0, 120),
              fix: 'Use bcrypt.compare(inputPassword, storedHash) instead of ===.' });
          }
          for (const node of hasWeakHashForPassword(func.body)) {
            const line = getLine(node);
            findings.push({ ruleId: 'plaintext-passwords', ruleName: 'Plaintext Passwords', severity: 'critical',
              message: `Function "${func.name}" hashes a password with a weak algorithm (MD5/SHA1). Use bcrypt or argon2 instead.`,
              file: file.relativePath, line, evidence: file.lines[line - 1]?.trim().slice(0, 120),
              fix: 'Replace crypto.createHash("md5") with bcrypt.hash(password, 12). MD5 and SHA1 are not suitable for password hashing — they are fast hashes designed for integrity checks.' });
          }
        }
        return findings;
      }
    }

    // Regex fallback
    if (HASH_REGEX.some((p) => p.test(file.content))) return [];
    const findings = [];
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (line.trim().startsWith('//')) continue;
      for (const { regex, label } of PLAINTEXT_REGEX) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({ ruleId: 'plaintext-passwords', ruleName: 'Plaintext Passwords', severity: 'critical',
            message: label, file: file.relativePath, line: i + 1,
            evidence: line.trim().slice(0, 120), fix: 'Use bcrypt.hash() for storage and bcrypt.compare() for verification.' });
        }
      }
    }
    return findings;
  },
};
