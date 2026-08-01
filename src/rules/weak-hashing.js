/**
 * Rule: weak-hashing
 * Detects use of broken/weak hash algorithms (MD5, SHA-1, MD4, MD2).
 *
 * These algorithms are cryptographically broken — collisions are cheap to
 * generate — so they must not be used for passwords, signatures, integrity
 * checks, or anything security-relevant. Modern code uses SHA-256+ (for
 * integrity) or a dedicated password hash like bcrypt/scrypt/argon2.
 *
 * Note: `crypto.createHmac('sha1', ...)` is intentionally NOT flagged here —
 * HMAC-SHA1 is still considered safe. This rule only targets bare hashing.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|\.d\.ts$)/i;
const SKIP_RULES = /src\/rules\//i;

// createHash('md5') / createHash("sha1") / createHash(`md4`) — weak algorithms only.
const CREATE_HASH_WEAK = /createHash\s*\(\s*['"`](?:md5|md4|md2|sha1|sha-1)['"`]/i;

/** @type {Rule} */
export const weakHashing = {
  id: 'weak-hashing',
  name: 'Weak Hash Algorithm',
  severity: 'warning',
  description:
    'Detects use of broken hash algorithms (MD5, SHA-1, MD4, MD2) for hashing — collision-vulnerable and unfit for security.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];
    if (SKIP_RULES.test(file.relativePath)) return [];
    if (!file.content.includes('createHash')) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;

      CREATE_HASH_WEAK.lastIndex = 0;
      if (!CREATE_HASH_WEAK.test(line)) continue;

      findings.push({
        ruleId: 'weak-hashing',
        ruleName: 'Weak Hash Algorithm',
        severity: 'warning',
        message: 'Broken hash algorithm (MD5/SHA-1) used — collisions are trivial to forge.',
        file: file.relativePath,
        line: i + 1,
        evidence: trimmed.slice(0, 120),
        fix: "For data integrity, use SHA-256 or stronger: crypto.createHash('sha256'). For passwords, never use a plain hash — use bcrypt, scrypt, or argon2. MD5 and SHA-1 are collision-broken and must not be used for anything security-relevant.",
      });
    }

    return findings;
  },
};
