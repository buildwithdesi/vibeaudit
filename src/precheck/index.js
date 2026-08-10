/**
 * Pre-install gate.
 *
 * Every other check in this project looks at code you already have. This one
 * runs BEFORE `npm install`, on a package you do not have yet, because that is
 * the only moment a supply-chain decision is still reversible.
 *
 * It exists because of a specific failure mode. `npm audit` and osv-scanner
 * answer "does this have a known CVE", and a freshly compromised package has no
 * CVE for hours or days — the entire window in which the damage happens. So
 * this asks three questions that have answers immediately:
 *
 *   1. Was this exact version published very recently?
 *      Account-takeover attacks work by publishing a new version of a package
 *      you already trust. The malicious release is always new.
 *   2. Does it run code at install time?
 *      preinstall/install/postinstall fire before you import anything. That is
 *      the execution vector for this whole malware family.
 *   3. Is it on the known-bad list?
 *      Cheap, and catches the named incident once it is public.
 *
 * Critically it checks the WHOLE resolved tree, not the package you typed.
 * In the Mini Shai-Hulud incident the poisoned packages (keyv, file-entry-cache,
 * cacheable-request) were transitive dependencies — nobody installed them on
 * purpose. Checking only the named package would have missed it entirely.
 *
 * A fourth question rides along for free, because the same packument fetch
 * already carries the answer: what is this package licensed under? A GPL or
 * AGPL dependency is not a malware risk, but it is the one supply-chain
 * decision that is cheapest to reverse before install and most expensive
 * after — once it is woven into a build, ripping it back out is a real
 * engineering project. See rules/license-contamination.js for the
 * classification logic this reuses; this is the pre-install mirror of that
 * post-install lockfile check.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { classifyLicense } from '../rules/license-contamination.js';

/** Severity ladder for combining independent checks without ever downgrading a finding. */
const LEVEL_RANK = { ok: 0, warn: 1, block: 2 };

/** Versions confirmed malicious. Checked by exact name@version. */
export const KNOWN_MALICIOUS = new Set([
  // Mini Shai-Hulud, 2026-08 (Microsoft Threat Intelligence)
  'keyv@6.0.0',
  'file-entry-cache@11.1.6',
  'cache-manager@7.2.10',
  'cacheable-request@13.0.20',
  '@qlik/api@2.14.2',
]);

/** A version published inside this window is "fresh" — the shape of a hijack release. */
export const FRESH_HOURS = 72;

/**
 * npm has to be launched through a shell on Windows (it is a .cmd shim), and a
 * shell means the spec string is concatenated rather than passed as an argv
 * element. Since the spec comes from whatever the user typed, that would be a
 * command-injection hole in a security tool. So the spec is validated against
 * the shape npm actually accepts, which contains no shell metacharacters.
 *
 * @param {string} spec
 */
export function assertSafeSpec(spec) {
  const SPEC = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*(?:@[a-zA-Z0-9-._~^>=<|* ]+)?$/;
  if (typeof spec !== 'string' || !SPEC.test(spec)) {
    throw new Error(
      `Refusing to run: "${spec}" is not a valid npm package spec. Expected e.g. "lodash", "lodash@4.17.21", "@scope/pkg".`,
    );
  }
}

/**
 * Locate npm's own CLI entry point so it can be run with the current node
 * binary instead of through a shell.
 *
 * @returns {string|null}
 */
export function findNpmCli() {
  const candidates = [
    // Standard layout next to the node binary that is running us.
    join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    // nvm / Volta / Linux prefix layouts.
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

/**
 * Ask npm what installing `spec` would actually add, without adding it.
 *
 * `--dry-run` resolves the full tree and reports every package, transitive
 * included, then changes nothing on disk. `--ignore-scripts` is belt-and-braces:
 * dry-run should not execute hooks, and we do not rely on that.
 *
 * @param {string} spec e.g. "cacheable-request" or "left-pad@1.3.0"
 * @returns {{name: string, version: string}[]}
 */
export function resolveTree(spec) {
  assertSafeSpec(spec);
  const dir = mkdtempSync(join(tmpdir(), 'vibeaudit-precheck-'));
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'precheck', version: '1.0.0' }));
    const args = ['install', spec, '--dry-run', '--ignore-scripts', '--no-audit', '--no-fund'];
    const cli = findNpmCli();
    // Prefer running npm's own JS with the current node binary: no shell, so
    // the spec is a real argv element and cannot be reinterpreted as a command.
    // The shell path is a fallback for layouts where npm-cli.js is not where
    // we expect, and is only reachable after assertSafeSpec above.
    const out = cli
      ? execFileSync(process.execPath, [cli, ...args], {
          cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000,
        })
      : execFileSync('npm', args, {
          cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000,
          shell: process.platform === 'win32',
        });
    const pkgs = [];
    for (const line of out.split('\n')) {
      // npm prints "add <name> <version>" per resolved package.
      const m = /^\s*add\s+(\S+)\s+(\S+)\s*$/.exec(line);
      if (m) pkgs.push({ name: m[1], version: m[2] });
    }
    return pkgs;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * One registry read per package. The full packument carries both the publish
 * timestamp for every version and that version's package.json (so, its scripts).
 *
 * @param {string} name
 * @param {typeof fetch} [fetchImpl]
 */
export async function fetchPackument(name, fetchImpl = fetch) {
  const res = await fetchImpl(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, {
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`registry ${res.status} for ${name}`);
  return res.json();
}

/**
 * Judge one resolved package.
 *
 * @param {{name: string, version: string}} pkg
 * @param {any} packument
 * @param {number} nowMs
 * @returns {{name:string, version:string, level:'block'|'warn'|'ok', reasons:string[], ageHours:number|null, installScripts:string[]}}
 *   `reasons` may include a `"license: ..."` entry from classifyLicense — see rules/license-contamination.js
 */
export function assessPackage(pkg, packument, nowMs) {
  const reasons = [];
  let level = 'ok';

  if (KNOWN_MALICIOUS.has(`${pkg.name}@${pkg.version}`)) {
    return {
      ...pkg,
      level: 'block',
      reasons: ['CONFIRMED MALICIOUS — this exact version is on the known-bad list'],
      ageHours: null,
      installScripts: [],
    };
  }

  const published = packument?.time?.[pkg.version];
  const ageHours = published ? (nowMs - Date.parse(published)) / 36e5 : null;

  const scripts = packument?.versions?.[pkg.version]?.scripts || {};
  const installScripts = ['preinstall', 'install', 'postinstall'].filter((h) => scripts[h]);

  if (installScripts.length) {
    reasons.push(`runs code at install time (${installScripts.join(', ')})`);
    level = 'warn';
  }

  if (ageHours !== null && ageHours < FRESH_HOURS) {
    reasons.push(`version published ${Math.round(ageHours)}h ago`);
    // Fresh AND executes on install is the exact hijack signature — that pair
    // is worth stopping for, either alone is only worth mentioning.
    level = installScripts.length ? 'block' : 'warn';
  }

  // License check rides the same packument, no extra registry call. Unlike
  // the malware checks above, a license verdict is a legal fact, not a
  // heuristic — so a strong-copyleft package with no permissive escape
  // blocks outright, same tier as a confirmed-malicious version.
  const license = packument?.versions?.[pkg.version]?.license;
  const verdict = classifyLicense(license);
  const licenseLevel = verdict.tier === 'block' ? 'block' : verdict.tier === 'pass' ? 'ok' : 'warn';
  if (verdict.tier !== 'pass') reasons.push(`license: ${verdict.reason}`);
  if (LEVEL_RANK[licenseLevel] > LEVEL_RANK[level]) level = licenseLevel;

  return { ...pkg, level, reasons, ageHours, installScripts };
}

/**
 * Run the gate for an install spec.
 *
 * @param {string} spec
 * @param {{fetchImpl?: typeof fetch, nowMs?: number, resolve?: typeof resolveTree}} [opts]
 */
export async function precheck(spec, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const nowMs = opts.nowMs ?? Date.now();
  const resolve = opts.resolve || resolveTree;

  const tree = resolve(spec);

  // One registry read per package, run in parallel with a small pool. A real
  // tree is often 300+ packages; sequential reads would make the gate slow
  // enough that it gets skipped, and a gate people skip protects nobody. The
  // pool keeps us from opening 300 sockets at the registry at once.
  const CONCURRENCY = 8;
  const results = new Array(tree.length);
  let next = 0;

  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= tree.length) return;
      const pkg = tree[i];
      try {
        // Parallelism here is the CONCURRENCY workers above; each must drain its queue serially.
        const packument = await fetchPackument(pkg.name, fetchImpl); // vibe-audit-ignore perf-no-await-parallel
        results[i] = assessPackage(pkg, packument, nowMs);
      } catch {
        // A registry read that fails is not an all-clear. Say so.
        results[i] = {
          ...pkg,
          level: 'warn',
          reasons: ['could not reach the registry to check this package'],
          ageHours: null,
          installScripts: [],
        };
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, tree.length) }, worker));

  const blocked = results.filter((r) => r.level === 'block');
  const warned = results.filter((r) => r.level === 'warn');

  return {
    spec,
    total: results.length,
    blocked,
    warned,
    results,
    // 2 = block, 1 = warnings only, 0 = clean. Mirrors morning-scan's convention.
    exitCode: blocked.length ? 2 : warned.length ? 1 : 0,
  };
}
