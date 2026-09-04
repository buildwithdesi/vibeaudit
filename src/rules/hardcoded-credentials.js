/**
 * Rule: hardcoded-credentials
 * Detects hardcoded passwords, connection strings, and credential patterns.
 */

/** @typedef {import('./types.js').Rule} Rule */

const CREDENTIAL_PATTERNS = [
  // password = "something" or password: "something"
  {
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"`](?![\s'"`${}])[^'"`\n]{4,}['"`]/gi,
    label: 'Hardcoded password',
  },
  // Database connection strings with embedded credentials
  {
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^/\s]+:[^@/\s]+@[^/\s]+/gi,
    label: 'Database connection string with credentials',
  },
  // Bearer tokens hardcoded
  {
    regex: /['"`]Bearer\s+[A-Za-z0-9_-]{20,}['"`]/g,
    label: 'Hardcoded bearer token',
  },
  // Basic auth headers
  {
    regex: /['"`]Basic\s+[A-Za-z0-9+/=]{10,}['"`]/g,
    label: 'Hardcoded basic auth header',
    validate: looksLikeBasicAuth,
  },
];

/**
 * Confirm a `"Basic ..."` string really is an Authorization header value.
 *
 * The regex above only checks the charset, and `[A-Za-z0-9+/=]` happily accepts
 * ordinary English. On the 2026-08-13 portfolio scan that turned the string
 * `'Basic electrical'` — an entry in a job-training skills array in the PUBLIC
 * trade-match repo — into a critical "hardcoded credential", three times over.
 *
 * A real basic-auth value is base64 of `user:pass`, so decode it and require
 * what that actually implies: a valid base64 payload whose plaintext holds the
 * `:` separator and is printable. `electrical` decodes to binary noise with no
 * colon and fails, while `ZGVtbzpkZW1v` ("demo:demo") passes.
 *
 * @param {string} matchedText The full regex match, quotes included.
 * @returns {boolean}
 */
function looksLikeBasicAuth(matchedText) {
  const value = matchedText.slice(1, -1).replace(/^Basic\s+/, '');
  // Base64 encodes 3 bytes to 4 chars, so a length remainder of 1 is impossible.
  if (value.length % 4 === 1) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;

  let decoded;
  try {
    decoded = Buffer.from(value, 'base64').toString('utf8');
  } catch {
    return false;
  }
  // "user:pass" — the colon is what makes it credentials rather than a word that
  // happens to be base64-shaped, and real credentials are printable text.
  return decoded.includes(':') && !/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F�]/.test(decoded);
}

/** Ignore test files and fixtures — hardcoded creds there are expected. */
const TEST_FILE_PATTERN = /(?:__tests__|__mocks__|\.test\.|\.spec\.|\.mock\.|test\/fixtures|tests\/fixtures)/i;

/** Ignore lines that are clearly template/placeholder values. */
const PLACEHOLDER_VALUES = /(?:your[_-]?password|changeme|placeholder|example|xxx+|todo|fixme|replace[_-]?me)/i;

function isCommentOrDoc(line) {
  const trimmed = line.trim();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('#') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('<!--')
  );
}

function redactConnection(str) {
  // Redact the password portion of connection strings.
  return str.replace(/:([^@:]+)@/, ':***@');
}

/** @type {Rule} */
export const hardcodedCredentials = {
  id: 'hardcoded-credentials',
  name: 'Hardcoded Credentials',
  severity: 'critical',
  description: 'Detects passwords, connection strings, and auth tokens hardcoded in source files.',

  check(file) {
    if (TEST_FILE_PATTERN.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (isCommentOrDoc(line)) continue;

      for (const { regex, label, validate } of CREDENTIAL_PATTERNS) {
        regex.lastIndex = 0;
        let match;
        while ((match = regex.exec(line)) !== null) {
          const matchedText = match[0];

          // Skip placeholder values.
          if (PLACEHOLDER_VALUES.test(matchedText)) continue;
          // Patterns whose charset alone is too permissive confirm the match
          // against the credential format they claim to have found.
          if (validate && !validate(matchedText)) continue;

          findings.push({
            ruleId: 'hardcoded-credentials',
            ruleName: 'Hardcoded Credentials',
            severity: 'critical',
            message: `${label} detected.`,
            file: file.relativePath,
            line: i + 1,
            evidence: label.includes('connection')
              ? redactConnection(matchedText)
              : '***REDACTED***',
            fix: `Move credentials to environment variables. Use process.env or a secrets manager. Never store passwords or connection strings in source code.`,
          });
        }
      }
    }

    return findings;
  },
};
