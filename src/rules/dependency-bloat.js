/**
 * Rule: dependency-bloat
 * Reports the size of the dependency tree a lockfile resolves to, and flags
 * known one-function micro-packages that duplicate a platform built-in.
 *
 * Every installed package is code that runs at install time and at runtime,
 * under a maintainer account that can be stolen. The doctrine target is to cut
 * package count hard (on the order of 80%): inline trivial helpers, prefer
 * platform built-ins, and keep vetted libraries for the things that are
 * dangerous to hand-roll (crypto, auth, parsers for hostile input).
 *
 * Counts come from the lockfile alone: package-lock.json (v1 tree or v2/v3
 * `packages` map), pnpm-lock.yaml (snapshots/packages sections), yarn.lock (v1
 * block format). Bun's lockfile is JSONC/binary and is not parsed in v1.
 */

/** @typedef {import('./types.js').Rule} Rule */
/** @typedef {import('./types.js').Finding} Finding */

const PKG_LOCK = /(?:^|\/)package-lock\.json$/;
const PNPM_LOCK = /(?:^|\/)pnpm-lock\.yaml$/;
const YARN_LOCK = /(?:^|\/)yarn\.lock$/;

/** Tree sizes worth mentioning, and worth warning about. */
const TOTAL_INFO = 250;
const TOTAL_WARNING = 1000;

/** One-function packages whose job the platform already does. */
const MICRO_PACKAGES = {
  'is-odd': 'an inline `n % 2 !== 0` check',
  'is-even': 'an inline `n % 2 === 0` check',
  'is-number': '`typeof n === "number"` or `Number.isFinite(n)`',
  isarray: 'the built-in `Array.isArray()`',
  'left-pad': 'the built-in `String.prototype.padStart()`',
  'is-buffer': 'the built-in `Buffer.isBuffer()`',
};

function lineOf(file, needle) {
  const idx = file.lines.findIndex((l) => l.includes(needle));
  return { line: idx >= 0 ? idx + 1 : 1, evidence: idx >= 0 ? file.lines[idx].trim().slice(0, 120) : undefined };
}

function finding(file, needle, severity, message, fix) {
  const at = lineOf(file, needle);
  return {
    ruleId: 'dependency-bloat',
    ruleName: 'Dependency Bloat',
    severity,
    message,
    file: file.relativePath,
    line: at.line,
    evidence: at.evidence,
    fix,
    cweId: 'CWE-1104',
    owaspCategory: 'A06:2021',
  };
}

/** Package name from a pnpm lock key: `'@scope/pkg@1.0.0'` / `pkg@1.0.0(peer)` -> name. */
function pnpmKeyName(rawKey) {
  const key = rawKey.replace(/^['"]|['"]$/g, '');
  const scoped = /^(@[^/]+\/[^@]+)@/.exec(key);
  if (scoped) return scoped[1];
  const plain = /^([^@(\s]+)@/.exec(key);
  return plain ? plain[1] : key;
}

/** Package name from a yarn.lock v1 entry key: `"@scope/pkg@^1"` / `pkg@^1` -> name. */
function yarnKeyName(rawKey) {
  const key = rawKey.split(',')[0].trim().replace(/^["']|["']$/g, '');
  const scoped = /^(@[^/]+\/[^@]+)@/.exec(key);
  if (scoped) return scoped[1];
  const plain = /^([^@]+)@/.exec(key);
  return plain ? plain[1] : key;
}

/** @returns {null | { total: number, direct: number | null, names: Set<string> }} */
function countNpmLock(content) {
  let lock;
  try { lock = JSON.parse(content); } catch { return null; }

  if (lock?.packages && typeof lock.packages === 'object') {
    const names = new Set();
    let total = 0;
    for (const key of Object.keys(lock.packages)) {
      if (key === '') continue;
      total++;
      const idx = key.lastIndexOf('node_modules/');
      if (idx >= 0) names.add(key.slice(idx + 'node_modules/'.length));
    }
    const root = lock.packages[''] || {};
    const direct = new Set([
      ...Object.keys(root.dependencies || {}),
      ...Object.keys(root.devDependencies || {}),
      ...Object.keys(root.peerDependencies || {}),
      ...Object.keys(root.optionalDependencies || {}),
    ]);
    return { total, direct: direct.size, names };
  }

  if (lock?.dependencies && typeof lock.dependencies === 'object') {
    const names = new Set();
    let total = 0;
    const walkTree = (deps) => {
      for (const [name, node] of Object.entries(deps)) {
        total++;
        names.add(name);
        if (node?.dependencies && typeof node.dependencies === 'object') walkTree(node.dependencies);
      }
    };
    walkTree(lock.dependencies);
    return { total, direct: null, names };
  }

  return null;
}

/** @returns {null | { total: number, direct: number | null, names: Set<string> }} */
function countPnpmLock(content) {
  const lines = content.split('\n');
  for (const section of ['snapshots', 'packages']) {
    const start = lines.findIndex((l) => l.trimEnd() === `${section}:`);
    if (start < 0) continue;

    const names = new Set();
    let total = 0;
    for (let i = start + 1; i < lines.length; i++) {
      const l = lines[i];
      if (/^\S/.test(l)) break;
      const m = /^ {2}(\S.*?):\s*$/.exec(l);
      if (m) {
        total++;
        names.add(pnpmKeyName(m[1]));
      }
    }
    if (total > 0) return { total, direct: null, names };
  }
  return null;
}

/** @returns {null | { total: number, direct: number | null, names: Set<string> }} */
function countYarnLock(content) {
  const names = new Set();
  let total = 0;
  for (const line of content.split('\n')) {
    if (!line || line.startsWith('#') || /^\s/.test(line)) continue;
    if (!line.trimEnd().endsWith(':')) continue;
    total++;
    names.add(yarnKeyName(line.trimEnd().slice(0, -1)));
  }
  return total > 0 ? { total, direct: null, names } : null;
}

/** @type {Rule} */
export const dependencyBloat = {
  id: 'dependency-bloat',
  name: 'Dependency Bloat',
  severity: 'info',
  description: 'Reports direct and total dependency counts from lockfiles, flags very large trees, and flags known one-function micro-packages that duplicate a platform built-in.',

  check(file) {
    const p = file.relativePath;

    let counts = null;
    if (PKG_LOCK.test(p)) counts = countNpmLock(file.content);
    else if (PNPM_LOCK.test(p)) counts = countPnpmLock(file.content);
    else if (YARN_LOCK.test(p)) counts = countYarnLock(file.content);
    else return [];
    if (!counts) return [];

    const out = [];

    if (counts.total >= TOTAL_INFO) {
      const sev = counts.total >= TOTAL_WARNING ? 'warning' : 'info';
      const directNote = counts.direct !== null ? ` (${counts.direct} direct, the rest transitive)` : '';
      out.push(finding(file, '', sev,
        `This lockfile installs ${counts.total} packages${directNote}. Every one is install-time and runtime code under a maintainer account that can be stolen, and the transitive majority is code nobody on the project chose directly.`,
        'Treat the tree as attack surface: remove packages that duplicate platform built-ins or trivially inlined helpers, consolidate overlapping libraries, and re-check the count after. Keep vetted libraries for crypto, auth, and parsing hostile input — those are more dangerous hand-rolled than depended on.'));
    }

    for (const name of Object.keys(MICRO_PACKAGES)) {
      if (!counts.names.has(name)) continue;
      out.push(finding(file, name, 'info',
        `"${name}" is installed. It is a one-function package that duplicates ${MICRO_PACKAGES[name]} — a dependency, a maintainer account, and an install script for something the platform already ships.`,
        `Remove "${name}" from package.json, replace its call sites with ${MICRO_PACKAGES[name]}, and reinstall with scripts disabled (\`--ignore-scripts\`) to regenerate the lockfile.`));
    }

    return out;
  },
};
