/**
 * Last-line redaction for reports and the free-credit checklist.
 * Findings may quote a line of target code. That line is untrusted and may
 * hold a live key. The report names the variable, never the value.
 */

const SECRET_PATTERNS = [
  /sk_live_[0-9a-zA-Z]{8,}/g,
  /sk_test_[0-9a-zA-Z]{8,}/g,
  /sk-[A-Za-z0-9]{20,}/g,
  /AIza[0-9A-Za-z_-]{30,}/g,
  /ghp_[A-Za-z0-9]{20,}/g,
  /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];

/** @param {string} text */
export function redactSecretValues(text) {
  let out = String(text ?? '');
  for (const pattern of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    out = out.replace(pattern, '[redacted]');
  }
  return out;
}

/**
 * Redact key-shaped text, and refuse to continue if a known secret value
 * (an env token the caller still holds) survived into the output.
 *
 * @param {string} text
 * @param {string[]} [secrets]
 */
export function assertNoSecretValues(text, secrets = []) {
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 8 && text.includes(secret)) {
      throw new Error('Refusing to write output that contains a secret value');
    }
  }
  return redactSecretValues(text);
}
