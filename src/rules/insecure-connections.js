/**
 * Rule: insecure-connections
 * Detects insecure HTTP URLs, disabled TLS verification, and CORS wildcards.
 */

/** @typedef {import('./types.js').Rule} Rule */

const INSECURE_PATTERNS = [
  // HTTP URLs (not localhost, not example.com, not W3C namespace identifiers)
  {
    regex: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|www\.w3\.org\/)[^'"`\s]+['"`]/gi,
    label: 'Non-localhost HTTP URL — data sent unencrypted',
    severity: 'warning',
    ignore: isNonNetworkUrl,
  },
  // TLS verification disabled
  {
    regex: /rejectUnauthorized\s*:\s*false/gi,
    label: 'TLS certificate verification disabled',
    severity: 'critical',
  },
  {
    regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"`]?0['"`]?/gi,
    label: 'TLS verification globally disabled via env var',
    severity: 'critical',
  },
  // CORS wildcard
  {
    regex: /(?:Access-Control-Allow-Origin|origin)\s*[:=,]\s*['"`]\*['"`]/gi,
    label: 'CORS allows all origins — any website can call your API',
    severity: 'warning',
  },
  // setHeader("Access-Control-Allow-Origin", "*")
  {
    regex: /Access-Control-Allow-Origin['"`]\s*,\s*['"`]\*/gi,
    label: 'CORS allows all origins — any website can call your API',
    severity: 'warning',
  },
  {
    regex: /cors\s*\(\s*\)/g,
    label: 'CORS middleware with no configuration (defaults to allow all)',
    severity: 'warning',
  },
];

/**
 * True when an http:// match is an identifier, not a request: an xmlns
 * namespace attribute, or text inside an inline data: URI (inline SVG/CSS).
 */
function isNonNetworkUrl(line, index) {
  const before = line.slice(0, index);
  if (/xmlns(?::[\w-]+)?\s*=\s*$/i.test(before)) return true;
  return /data:[\w.+-]+\/[\w.+-]+[;,]/i.test(before);
}

/** Skip test and config example files. */
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|\.example|\.sample)/i;

/** @type {Rule} */
export const insecureConnections = {
  id: 'insecure-connections',
  name: 'Insecure Connections',
  severity: 'warning',
  description: 'Detects insecure HTTP URLs, disabled TLS verification, and overly permissive CORS.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;

      for (const { regex, label, severity, ignore } of INSECURE_PATTERNS) {
        regex.lastIndex = 0;
        let hit = false;
        let m;
        while ((m = regex.exec(line)) !== null) {
          if (!ignore || !ignore(line, m.index)) { hit = true; break; }
          if (!regex.global) break;
        }
        if (hit) {
          findings.push({
            ruleId: 'insecure-connections',
            ruleName: 'Insecure Connections',
            severity,
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: label.includes('CORS')
              ? `Configure CORS with specific allowed origins instead of "*". List only the domains that need access to your API.`
              : label.includes('TLS')
                ? `Never disable TLS verification. Fix the underlying certificate issue instead. In production this allows man-in-the-middle attacks.`
                : `Use HTTPS for all external connections. HTTP transmits data in plaintext — anyone on the network can read it.`,
          });
        }
      }
    }

    return findings;
  },
};
