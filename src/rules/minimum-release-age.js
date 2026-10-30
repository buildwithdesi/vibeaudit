/**
 * Rule: minimum-release-age
 * Flags JavaScript projects with no dependency release-age cooldown, and projects
 * whose cooldown is shorter than the standing doctrine minimum of 3 days.
 *
 * The attack: a maintainer's npm credentials are stolen and a poisoned version is
 * published. Anyone who installs in the first hours gets it, before the registry,
 * OSV, or the community notices. A cooldown (pnpm `minimumReleaseAge`, npm `--before`,
 * Bun `minimumReleaseAge`) makes installs wait until a release is a few days old,
 * which is exactly the window in which poisoned releases get caught and yanked.
 *
 * Rules in this scanner are per-file and offline: a rule cannot ask the registry
 * when each locked version was published. So this rule checks the gate itself:
 * a too-short gate is flagged where it is written, and the "no gate anywhere"
 * case is emitted as an info candidate on the root manifest/lockfile, which the
 * project-context pass then suppresses when any recognized config file in the
 * project does set a gate (see src/project-context.js).
 */

/** @typedef {import('./types.js').Rule} Rule */
/** @typedef {import('./types.js').Finding} Finding */

/** Doctrine floor: 3 days, in minutes. The doctrine range is 3-7 days (4320-10080). */
export const MIN_RELEASE_AGE_MINUTES = 4320;
const MIN_RELEASE_AGE_DAYS = 3;

const PNPM_WORKSPACE = /(?:^|\/)pnpm-workspace\.yaml$/;
const NPMRC = /(?:^|\/)\.npmrc$/;
const BUNFIG = /(?:^|\/)bunfig\.toml$/;
const ROOT_MANIFEST = /^package\.json$/;
const ROOT_LOCK = /^(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock)$/;

function fmtMinutes(minutes) {
  if (minutes === 0) return '0 minutes (disabled)';
  if (minutes % 1440 === 0) return `${minutes} minutes (${minutes / 1440} day${minutes === 1440 ? '' : 's'})`;
  if (minutes % 60 === 0) return `${minutes} minutes (${minutes / 60} hours)`;
  return `${minutes} minutes`;
}

/**
 * Read the release-age gate from a recognized package-manager config file.
 * Returns null for files that cannot hold the setting. For a recognized file,
 * `hasGate` says whether the setting is written at all; `minutes` is the gate
 * length in minutes (Bun stores seconds and is converted), and `staticBeforeDays`
 * is set instead when npm's static `before=<date>` gate is used: how many days
 * before today that date sits.
 *
 * Shared with src/project-context.js, which uses it to decide whether a project
 * has any gate at all. Keep the two callers on this one parser.
 *
 * @param {{ relativePath: string, content: string }} file
 * @returns {null | { hasGate: boolean, minutes: number | null, staticBeforeDays?: number }}
 */
export function readCooldown(file) {
  const p = file.relativePath;

  if (PNPM_WORKSPACE.test(p)) {
    const m = /^\s*minimumReleaseAge\s*:\s*(\d+)\s*$/m.exec(file.content);
    return { hasGate: Boolean(m), minutes: m ? Number(m[1]) : null };
  }

  if (NPMRC.test(p)) {
    const age = /^\s*minimum-release-age\s*=\s*(\d+)\s*$/m.exec(file.content);
    if (age) return { hasGate: true, minutes: Number(age[1]) };
    const before = /^\s*before\s*=\s*["']?([0-9TZ:.\-+]+)["']?\s*$/m.exec(file.content);
    if (before) {
      const t = Date.parse(before[1]);
      if (!Number.isNaN(t)) {
        return { hasGate: true, minutes: null, staticBeforeDays: Math.floor((Date.now() - t) / 86400000) };
      }
      return { hasGate: true, minutes: null };
    }
    return { hasGate: false, minutes: null };
  }

  if (BUNFIG.test(p)) {
    const m = /^\s*minimumReleaseAge\s*=\s*(\d+)\s*$/m.exec(file.content);
    return { hasGate: Boolean(m), minutes: m ? Math.floor(Number(m[1]) / 60) : null };
  }

  return null;
}

function lineOf(file, needle) {
  const idx = file.lines.findIndex((l) => l.includes(needle));
  return { line: idx >= 0 ? idx + 1 : 1, evidence: idx >= 0 ? file.lines[idx].trim().slice(0, 120) : undefined };
}

function finding(file, needle, severity, message, fix) {
  const at = lineOf(file, needle);
  return {
    ruleId: 'minimum-release-age',
    ruleName: 'Minimum Release Age',
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

const GATE_FIX = 'Set a 3-7 day cooldown and keep versions pinned exactly: pnpm — "minimumReleaseAge: 4320" in pnpm-workspace.yaml (minutes; 10080 = 7 days). npm — "minimum-release-age=4320" in .npmrc for pnpm-managed installs, or pass --before=<date> at install time. Bun — "minimumReleaseAge = 259200" under [install] in bunfig.toml (seconds; 604800 = 7 days).';

/** @type {Rule} */
export const minimumReleaseAge = {
  id: 'minimum-release-age',
  name: 'Minimum Release Age',
  severity: 'warning',
  description: 'Flags JS projects with no dependency release-age cooldown (minimumReleaseAge) configured, or a cooldown shorter than 3 days — the window in which poisoned releases published with stolen maintainer credentials get caught.',

  check(file) {
    const p = file.relativePath;

    const gate = readCooldown(file);
    if (gate) {
      if (!gate.hasGate) return [];
      if (gate.minutes !== null && gate.minutes < MIN_RELEASE_AGE_MINUTES) {
        return [finding(file, NPMRC.test(p) ? 'minimum-release-age' : 'minimumReleaseAge', 'warning',
          `This release-age cooldown is ${fmtMinutes(gate.minutes)}, shorter than the 3-day minimum. A poisoned release published with stolen maintainer credentials is usually caught within days; a shorter gate lets it through.`,
          GATE_FIX)];
      }
      if (gate.minutes === null && gate.staticBeforeDays !== undefined && gate.staticBeforeDays < MIN_RELEASE_AGE_DAYS) {
        return [finding(file, 'before', 'warning',
          `This npm "before" gate is only ${gate.staticBeforeDays} day${gate.staticBeforeDays === 1 ? '' : 's'} in the past, shorter than the 3-day minimum release age.`,
          'Move the "before" date in .npmrc to at least 3-7 days before today, and refresh it on a schedule — a static date only protects while it stays old. ' + GATE_FIX)];
      }
      return [];
    }

    if (ROOT_MANIFEST.test(p) || ROOT_LOCK.test(p)) {
      return [finding(file, '', 'info',
        'No dependency release-age cooldown (minimumReleaseAge) is configured for this project. A version published minutes ago — including one pushed with stolen maintainer credentials — installs as easily as one that has been public for years.',
        GATE_FIX)];
    }

    return [];
  },
};
