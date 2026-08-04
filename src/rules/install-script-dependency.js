/**
 * Rule: install-script-dependency
 *
 * Flags dependencies that execute code during `npm install`.
 *
 * Why this exists: every scanner that checks dependencies against a CVE feed
 * (including this project's own SCA, which shells out to `npm audit`) is blind
 * on day zero. A maintainer account gets compromised, a malicious version is
 * published, and there is no advisory for hours or days — but the code runs on
 * every machine that installs it in the meantime.
 *
 * The delivery mechanism, though, is constant. The Shai-Hulud family, and most
 * npm supply-chain malware before it, arrives through a lifecycle hook:
 * `preinstall` / `install` / `postinstall` fire automatically, before any of
 * your code imports anything. So instead of asking "is this package known-bad",
 * this rule asks "which packages can run code on my machine at install time" —
 * a question that has a correct answer today, with no feed to be behind on.
 *
 * npm already records the answer. Lockfile v2/v3 marks every such package with
 * `"hasInstallScript": true`, so this needs no network call and no walk of
 * node_modules.
 *
 * KNOWN LIMITATION — read before trusting a silent result. This rule only sees
 * `package-lock.json` v2+. `bun.lock`, `pnpm-lock.yaml`, and `yarn.lock` do not
 * record an equivalent flag, so a project using them gets no findings, which is
 * NOT the same as having no install scripts. For those, the check is
 * `npm config set ignore-scripts true` (bun and pnpm both honor it) rather than
 * anything this rule can tell you.
 *
 * Severity is split deliberately. A short list of packages genuinely need a
 * hook to compile or fetch a platform binary; those are reported as `info` so
 * the inventory stays visible without crying wolf. Everything else is a
 * `warning`: not an accusation, a prompt to look, because a package that has no
 * reason to build anything and still runs code at install time is the exact
 * shape of this attack.
 */

/** @typedef {import('./types.js').Rule} Rule */

const LOCKFILE = /(?:^|\/)package-lock\.json$/i;

/**
 * Packages whose install hook is expected: native compilation, or downloading
 * a platform-specific binary. Being on this list lowers severity to `info`; it
 * never suppresses the finding, because a compromised version of one of these
 * would still run code.
 */
const EXPECTED_INSTALL_SCRIPTS = new Set([
  'esbuild',
  'fsevents',
  'sharp',
  'core-js',
  'core-js-pure',
  'protobufjs',
  'playwright',
  'playwright-core',
  'puppeteer',
  'puppeteer-core',
  'better-sqlite3',
  'sqlite3',
  'bcrypt',
  'argon2',
  'canvas',
  'node-pty',
  'keytar',
  'bufferutil',
  'utf-8-validate',
  'cpu-features',
  'ssh2',
  're2',
  'deasync',
  'lmdb',
  'msgpackr-extract',
  'nx',
  'turbo',
  'swc',
  '@swc/core',
  '@parcel/watcher',
  '@biomejs/biome',
  '@tailwindcss/oxide',
  'unrs-resolver',
  'workerd',
  'sass-embedded',
  'node-sass',
]);

/**
 * `node_modules/@scope/name` and `node_modules/a/node_modules/b` both resolve
 * to the final package name.
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
export const installScriptDependency = {
  id: 'install-script-dependency',
  name: 'Dependency Runs Code at Install Time',
  severity: 'warning',
  description:
    'Flags dependencies that execute lifecycle scripts during npm install — the delivery mechanism for npm supply-chain malware.',

  check(file) {
    if (!LOCKFILE.test(file.relativePath)) return [];

    let lock;
    try {
      lock = JSON.parse(file.content);
    } catch {
      return [];
    }

    // hasInstallScript is only recorded in lockfile v2+. On v1 this rule has
    // nothing to read, and saying nothing is better than a false all-clear.
    const packages = lock.packages;
    if (!packages || typeof packages !== 'object') return [];

    const allowExtra = file._config?.allowedInstallScripts;
    const allowed = new Set([
      ...EXPECTED_INSTALL_SCRIPTS,
      ...(Array.isArray(allowExtra) ? allowExtra : []),
    ]);

    const findings = [];
    const seen = new Set();

    for (const [lockPath, meta] of Object.entries(packages)) {
      if (!meta || meta.hasInstallScript !== true) continue;

      const name = packageNameFromLockPath(lockPath);
      const version = meta.version || 'unknown';
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const expected = allowed.has(name);

      findings.push({
        ruleId: 'install-script-dependency',
        ruleName: 'Dependency Runs Code at Install Time',
        severity: expected ? 'info' : 'warning',
        message: expected
          ? `${key} runs an install script (expected for this package — native build or platform binary).`
          : `${key} runs code during npm install. Confirm it needs to — an install hook is how npm supply-chain malware executes.`,
        file: file.relativePath,
        line: 1,
        evidence: `${lockPath} — hasInstallScript: true`,
        fix: expected
          ? 'No action needed if this dependency is intentional. To stop ALL install scripts by default: npm config set ignore-scripts true, then rebuild the ones you need with `npm rebuild <pkg>`.'
          : `Check why ${name} needs an install hook: npm view ${name} scripts. If it is expected, add it to .vibe-audit.json "allowedInstallScripts". To stop install scripts running automatically: npm config set ignore-scripts true (then \`npm install --foreground-scripts\` deliberately when a package genuinely needs them).`,
      });
    }

    return findings;
  },
};
