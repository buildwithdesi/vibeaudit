/**
 * Rule: serverless-fs-write
 * Detects filesystem writes / embedded SQLite in serverless runtime code (API routes,
 * route handlers, server actions, .server files). On Vercel / Netlify / Lambda the disk
 * is ephemeral — wiped between invocations, usually read-only outside /tmp — so anything
 * written there silently vanishes. The "it worked on my machine, then data disappeared
 * in prod" bug.
 *
 * Scoped to server-runtime files and skips /tmp (the one writable, disposable path) to
 * hold the zero-false-positive bar — build scripts and CLIs that legitimately write files
 * are never in these paths.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

// Serverless runtime code: API routes, route handlers, server actions, .server modules.
const SERVER_RUNTIME = /(?:\/api\/|(?:^|\/)route\.[jt]sx?$|(?:^|\/)actions?\.[jt]sx?$|\.server\.[jt]sx?$)/i;

// A filesystem write or an embedded SQLite database opened for writing.
const FS_WRITE = /\bfs\.(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|mkdir|mkdirSync)\s*\(|\bnew\s+Database\s*\(/;

// /tmp (or os.tmpdir()) is the one writable, ephemeral path serverless allows — don't flag it.
const TMP = /tmp|tmpdir/i;

/** @type {Rule} */
export const serverlessFsWrite = {
  id: 'serverless-fs-write',
  name: 'Filesystem Write in Serverless Code',
  severity: 'warning',
  description: 'Detects filesystem writes / embedded SQLite in serverless runtime code (API routes, server actions) — the disk is ephemeral, so the data silently vanishes.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!SERVER_RUNTIME.test(file.relativePath)) return [];

    const findings = [];
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
      if (!FS_WRITE.test(line)) continue;
      if (TMP.test(line)) continue; // /tmp is the allowed, disposable scratch path

      findings.push({
        ruleId: 'serverless-fs-write',
        ruleName: 'Filesystem Write in Serverless Code',
        severity: 'warning',
        message: 'Writing to the local filesystem in serverless code — the disk is ephemeral (wiped between invocations) and usually read-only, so this data silently disappears in production.',
        file: file.relativePath,
        line: i + 1,
        evidence: trimmed.slice(0, 120),
        fix: 'Persist to a real store, not local disk: Postgres/Supabase for data, S3 / Vercel Blob / Supabase Storage for files, a KV store for cache. If you genuinely need scratch space, write to os.tmpdir() and treat it as disposable.',
      });
    }
    return findings;
  },
};
