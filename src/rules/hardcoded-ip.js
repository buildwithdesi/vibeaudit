/**
 * Rule: hardcoded-ip
 * Detects hardcoded IP addresses that should be in environment variables.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|\.d\.ts$|\.lock$)/i;
const SKIP_RULES = /src\/rules\//i;

// Match IPv4 addresses in strings (not localhost or common test IPs)
const IP_IN_STRING = /['"`](?:https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?['"`]/g;

// IPs to ignore (localhost, test ranges)
const IGNORE_IPS = /^(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)$/;

// X.509 attribute types (2.5.4.x) and certificate extensions (2.5.29.x) are
// four-part ASN.1 OIDs, not addresses.
const X509_OID = /^2\.5\.(?:4|29)\.\d+$/;

// A quoted dotted-number string that cannot be IPv4 (3 parts, or 5+ parts)
// is a strong sign the file deals in OIDs or version strings.
const NON_IPV4_DOTTED = /['"`]\d+(?:\.\d+){2}['"`]|['"`]\d+(?:\.\d+){4,}['"`]/;
const OID_WORDS = /\boids?\b|objectIdentifier|OBJECT IDENTIFIER|asn\.?1|x\.?509/i;

function validOctets(ip) {
  return ip.split('.').every((part) => Number(part) <= 255);
}

/**
 * True when a four-part match sits in OID-mapping context: an object key that
 * maps to a name, in a file that also holds non-IPv4 dotted strings or names OIDs.
 */
function inOidMap(file, match) {
  const after = file.content.slice(match.index + match[0].length, match.index + match[0].length + 40);
  const isKeyToName = /^\s*:\s*['"`][A-Za-z]/.test(after);
  if (!isKeyToName) return false;
  return NON_IPV4_DOTTED.test(file.content) || OID_WORDS.test(file.content);
}

/** @type {Rule} */
export const hardcodedIp = {
  id: 'hardcoded-ip',
  name: 'Hardcoded IP Address',
  severity: 'info',
  description: 'Detects hardcoded IP addresses that should be in environment variables.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (SKIP_RULES.test(file.relativePath)) return [];

    const findings = [];

    IP_IN_STRING.lastIndex = 0;
    let match;
    while ((match = IP_IN_STRING.exec(file.content)) !== null) {
      const ip = match[1];
      if (IGNORE_IPS.test(ip)) continue;
      if (!validOctets(ip)) continue;
      if (X509_OID.test(ip)) continue;
      if (inOidMap(file, match)) continue;

      const lineNum = file.content.slice(0, match.index).split('\n').length;
      const line = file.lines[lineNum - 1]?.trim();
      if (line?.startsWith('//') || line?.startsWith('*') || line?.startsWith('#')) continue;

      findings.push({
        ruleId: 'hardcoded-ip',
        ruleName: 'Hardcoded IP Address',
        severity: 'info',
        message: `Hardcoded IP address ${ip} — should be in an environment variable.`,
        file: file.relativePath,
        line: lineNum,
        evidence: line?.slice(0, 120),
        fix: 'Move the IP address to an environment variable: process.env.SERVICE_HOST. Hardcoded IPs make deployment inflexible and may expose infrastructure details.',
      });
    }

    return findings;
  },
};
