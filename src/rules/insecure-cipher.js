/**
 * Rule: insecure-cipher
 * Detects insecure symmetric encryption:
 *   1. crypto.createCipher / createDecipher — deprecated, derives the key with
 *      no salt/IV, so identical plaintext always encrypts identically.
 *   2. Broken ciphers/modes — DES, 3DES, RC4, RC2, Blowfish, or ECB mode.
 *
 * Safe code uses createCipheriv/createDecipheriv with an authenticated AES
 * mode (aes-256-gcm) and a random IV.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|\.d\.ts$)/i;
const SKIP_RULES = /src\/rules\//i;

// Deprecated key-derivation API: createCipher( but NOT createCipheriv(.
const LEGACY_CIPHER = /\bcreate(?:De)?cipher\s*\(/i;

// Weak algorithm or ECB mode passed to createCipheriv / createDecipheriv.
const WEAK_ALGO = /create(?:De)?cipheriv\s*\(\s*['"`][^'"`]*(?:des|3des|des-ede|rc4|rc2|bf|blowfish|-ecb)[^'"`]*['"`]/i;

/** @type {Rule} */
export const insecureCipher = {
  id: 'insecure-cipher',
  name: 'Insecure Cipher',
  severity: 'warning',
  description:
    'Detects deprecated crypto.createCipher and broken ciphers/modes (DES, RC4, ECB) — weak or unauthenticated encryption.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];
    if (SKIP_RULES.test(file.relativePath)) return [];
    if (!/createCipher|createDecipher/i.test(file.content)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;

      LEGACY_CIPHER.lastIndex = 0;
      WEAK_ALGO.lastIndex = 0;

      const isWeakAlgo = WEAK_ALGO.test(line);
      // Legacy API check must exclude the *iv variant, which WEAK_ALGO handles.
      const isLegacy = !isWeakAlgo && LEGACY_CIPHER.test(line) && !/create(?:De)?cipheriv/i.test(line);
      if (!isWeakAlgo && !isLegacy) continue;

      findings.push({
        ruleId: 'insecure-cipher',
        ruleName: 'Insecure Cipher',
        severity: 'warning',
        message: isLegacy
          ? 'Deprecated crypto.createCipher — derives the key with no IV, leaking plaintext patterns.'
          : 'Broken cipher or ECB mode (DES/RC4/ECB) — encryption is easily reversible.',
        file: file.relativePath,
        line: i + 1,
        evidence: trimmed.slice(0, 120),
        fix: "Use crypto.createCipheriv('aes-256-gcm', key, iv) with a cryptographically random IV (crypto.randomBytes(12)) and store/transmit the IV alongside the ciphertext. Never use createCipher (no IV), DES/3DES/RC4, or ECB mode.",
      });
    }

    return findings;
  },
};
