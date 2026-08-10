/**
 * Rule: license-contamination
 *
 * Flags dependencies whose license would force you to open-source your own
 * product, or whose license status is unknown, before you find out the hard
 * way at a funding round, an acquisition, or a cease-and-desist.
 *
 * Two license families create real obligations for a closed-source or hosted
 * product:
 *   - Strong copyleft (GPL). Shipping GPL code inside your product means your
 *     source has to go out under the same terms.
 *   - Network copyleft (AGPL, SSPL). Closes the "but it's SaaS, I never
 *     distribute a binary" loophole — serving it over a network counts as
 *     distribution.
 * Weak copyleft (LGPL, MPL) is fine to use unmodified as a dependency; it
 * only bites if you modify and redistribute the library's own source. A
 * dual-licensed package ("X OR GPL-3.0") is fine too — elect the permissive
 * branch and you're clear of the GPL terms entirely.
 *
 * AI can silently launder a copyleft package into a project — a model
 * suggests a library it saw work well in training without surfacing what it's
 * licensed under, or a transitive dependency update pulls one in with nobody
 * running `npm install` at all. This rule reads what npm already recorded:
 * lockfile v2/v3 stores a `license` field (an SPDX expression) for every
 * resolved package, sourced from that package's own package.json at install
 * time. No network call, no shelling out to a license-lookup tool — the zero
 * dependency scanner reads the license the same way it already reads
 * `hasInstallScript`.
 *
 * KNOWN LIMITATIONS — read before trusting a silent result.
 *   - Only sees `package-lock.json` v2+, same limitation as
 *     install-script-dependency. `bun.lock`, `pnpm-lock.yaml`, and
 *     `yarn.lock` don't record an equivalent field, so those get no
 *     findings, which is NOT the same as a clean bill of health.
 *   - This checks DEPENDENCIES, not code. It does not catch an AI regenerating
 *     GPL-licensed source it saw during training with no package install
 *     involved at all — that is a code-provenance problem, not a dependency
 *     one, and needs a different tool.
 *   - The SPDX expression parsing here is a practical heuristic (split on
 *     top-level AND/OR), not a full SPDX license-expression parser. It
 *     handles every real-world case in this project's own tree and the vast
 *     majority of npm packages, but a deeply nested expression like
 *     "(MIT AND (GPL-2.0 OR BSD-3-Clause))" is read as "has an OR with a
 *     permissive branch" rather than resolved precisely. Good enough to flag
 *     for a human to actually read the LICENSE file; not a legal opinion.
 */

/** @typedef {import('./types.js').Rule} Rule */

const LOCKFILE = /(?:^|\/)package-lock\.json$/i;

const AGPL = /^AGPL-/i;
const SSPL = /^SSPL/i;
const GPL_STRICT = /^GPL-/i; // matches "GPL-3.0-or-later" but not "LGPL-..." or "AGPL-..." — anchored at string start
const LGPL = /^LGPL-/i;
const MPL = /^MPL-/i;
const EPL = /^EPL-/i;
const CDDL = /^CDDL-/i;

/**
 * SPDX identifiers with no meaningful obligation beyond keeping attribution
 * notices intact. Not exhaustive — anything not recognized falls through to
 * "unrecognized" rather than being silently assumed safe.
 */
const PERMISSIVE = new Set([
  'MIT', '0BSD', 'ISC', 'UNLICENSE', 'CC0-1.0', 'WTFPL', 'ZLIB', 'ZLIB-ACKNOWLEDGEMENT',
  'PYTHON-2.0', 'ARTISTIC-2.0', 'BLUEOAK-1.0.0', 'POSTGRESQL', 'X11', 'NCSA', 'VIM',
  'CC-BY-4.0', 'CC-BY-3.0',
]);
const PERMISSIVE_PREFIX = /^(APACHE|BSD|OFL)-/i;

/**
 * @param {string} token - a single trimmed SPDX identifier, no AND/OR/parens
 * @returns {boolean}
 */
function isPermissive(token) {
  const upper = token.toUpperCase();
  return PERMISSIVE.has(upper) || PERMISSIVE_PREFIX.test(token);
}

/** @param {string} token */
function isStrongCopyleft(token) {
  return AGPL.test(token) || SSPL.test(token) || GPL_STRICT.test(token);
}

/** @param {string} token */
function isWeakCopyleft(token) {
  return LGPL.test(token) || MPL.test(token) || EPL.test(token) || CDDL.test(token);
}

/**
 * @typedef {Object} LicenseVerdict
 * @property {'block' | 'warn' | 'flag' | 'pass'} tier
 * @property {string} reason - human-readable explanation for the message/fix text
 */

/**
 * Classify a raw SPDX license expression from package-lock.json.
 * @param {unknown} raw
 * @returns {LicenseVerdict}
 */
export function classifyLicense(raw) {
  if (typeof raw !== 'string' || raw.trim() === '') {
    return { tier: 'flag', reason: 'no license declared' };
  }

  const normalized = raw.trim();
  if (/^(UNLICENSED|CUSTOM|SEE LICENSE IN|UNKNOWN)/i.test(normalized)) {
    return { tier: 'flag', reason: `marked "${normalized}"` };
  }

  const hasOr = /\bOR\b/i.test(normalized);
  const tokens = normalized
    .replace(/[()]/g, '')
    .split(/\s+(?:AND|OR)\s+/i)
    .map((t) => t.trim())
    .filter(Boolean);

  if (tokens.length === 0) {
    return { tier: 'flag', reason: `unrecognized license expression "${normalized}"` };
  }

  const strong = tokens.filter(isStrongCopyleft);
  const weak = tokens.filter(isWeakCopyleft);
  const permissive = tokens.filter(isPermissive);
  const recognized = strong.length + weak.length + permissive.length;

  if (strong.length > 0) {
    if (hasOr && permissive.length > 0) {
      return {
        tier: 'warn',
        reason: `dual-licensed "${normalized}" — elect the permissive branch (${permissive[0]}) and you're clear of the copyleft terms`,
      };
    }
    return { tier: 'block', reason: `"${normalized}" is strong or network copyleft with no permissive option` };
  }

  if (weak.length > 0) {
    return { tier: 'warn', reason: `"${normalized}" is weak copyleft — fine unmodified, review before forking or redistributing it` };
  }

  if (recognized === tokens.length) {
    return { tier: 'pass', reason: normalized };
  }

  return { tier: 'flag', reason: `unrecognized license expression "${normalized}"` };
}

/**
 * `node_modules/@scope/name` and `node_modules/a/node_modules/b` both resolve
 * to the final package name. Same helper as install-script-dependency.js;
 * duplicated rather than imported so each rule file stays self-contained.
 * @param {string} lockPath
 * @returns {string}
 */
export function packageNameFromLockPath(lockPath) {
  const marker = 'node_modules/';
  const i = lockPath.lastIndexOf(marker);
  if (i === -1) return lockPath;
  return lockPath.slice(i + marker.length);
}

/** @type {Rule} */
export const licenseContamination = {
  id: 'license-contamination',
  name: 'License Contamination',
  severity: 'critical',
  description:
    'Flags GPL/AGPL/SSPL dependencies that would force source disclosure, and undeclared licenses, before they block commercialization.',

  check(file) {
    if (!LOCKFILE.test(file.relativePath)) return [];

    let lock;
    try {
      lock = JSON.parse(file.content);
    } catch {
      return [];
    }

    const packages = lock.packages;
    if (!packages || typeof packages !== 'object') return [];

    const allowExtra = file._config?.allowedLicenses;
    const allowed = new Set(Array.isArray(allowExtra) ? allowExtra : []);

    const findings = [];
    const seen = new Set();

    for (const [lockPath, meta] of Object.entries(packages)) {
      if (lockPath === '' || !meta) continue; // root project entry, not a dependency

      const name = packageNameFromLockPath(lockPath);
      const version = meta.version || 'unknown';
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const verdict = classifyLicense(meta.license);
      if (verdict.tier === 'pass') continue;

      let severity = verdict.tier === 'block' ? 'critical' : verdict.tier === 'warn' ? 'warning' : 'warning';

      // A dev-only dependency never ships in the built product — real
      // copyleft obligations attach to distribution, so drop it a tier
      // rather than treating it the same as a runtime dependency.
      const devOnly = meta.dev === true;
      if (devOnly) severity = severity === 'critical' ? 'warning' : 'info';

      if (allowed.has(name)) severity = 'info';

      const idx = file.lines.findIndex((l) => l.includes(`"${lockPath}"`));

      const scopeNote = devOnly ? ' (development-only — does not ship in the built product)' : '';

      findings.push({
        ruleId: 'license-contamination',
        ruleName: 'License Contamination',
        severity,
        message:
          verdict.tier === 'block'
            ? `${key} is ${verdict.reason}${scopeNote}. Shipping this means your own source has to go out under the same terms, or the network-use equivalent for AGPL/SSPL.`
            : verdict.tier === 'warn'
              ? `${key}: ${verdict.reason}${scopeNote}.`
              : `${key} has ${verdict.reason}${scopeNote}. No declared license defaults to all rights reserved, not permissive.`,
        file: file.relativePath,
        line: idx >= 0 ? idx + 1 : 1,
        evidence: `${lockPath} — license: ${JSON.stringify(meta.license ?? null)}`,
        fix:
          verdict.tier === 'block'
            ? `Check node_modules/${name}/LICENSE directly, npm's field can be wrong. Then either replace ${name} with a permissively-licensed alternative, isolate it to a build-time step that never ships, or if it's dual-licensed confirm you can elect the permissive branch and add "${name}" to .vibe-audit.json "allowedLicenses" to document that decision.`
            : verdict.tier === 'warn'
              ? `No action needed if you're using ${name} unmodified as a dependency. If you fork or redistribute ${name}'s own source, its copyleft terms apply to that. Add "${name}" to .vibe-audit.json "allowedLicenses" once reviewed to silence this.`
              : `Check node_modules/${name}/LICENSE and its repository before shipping. If it's actually permissive, add "${name}" to .vibe-audit.json "allowedLicenses".`,
      });
    }

    return findings;
  },
};
