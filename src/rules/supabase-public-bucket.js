/**
 * Rule: supabase-public-bucket
 * Detects a Supabase Storage bucket created (or updated) with `public: true`. A public
 * bucket means every file in it is readable by anyone with the URL — fine for logos,
 * a data leak for user uploads, IDs, invoices, or anything private.
 *
 * None of the other supabase-* rules cover Storage — this closes the "misconfigured
 * bucket" gap for the stack this scanner's audience actually ships on.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const PARSEABLE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;

// createBucket('name', { public: true }) / updateBucket(id, { public: true })
const BUCKET_CALL = /\b(?:create|update)Bucket\s*\(/g;
const PUBLIC_TRUE = /['"]?public['"]?\s*:\s*true/;

/** @type {Rule} */
export const supabasePublicBucket = {
  id: 'supabase-public-bucket',
  name: 'Supabase Public Storage Bucket',
  severity: 'warning',
  description: 'Detects a Supabase Storage bucket created with public: true — every file in it is readable by anyone with the URL.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!PARSEABLE.test(file.relativePath)) return [];

    const findings = [];
    const seen = new Set();
    BUCKET_CALL.lastIndex = 0;
    let match;
    while ((match = BUCKET_CALL.exec(file.content)) !== null) {
      // Look at the options object that follows the call (same statement).
      const window = file.content.slice(match.index, match.index + 200);
      if (!PUBLIC_TRUE.test(window)) continue;

      const line = file.content.slice(0, match.index).split('\n').length;
      if (seen.has(line)) continue;
      seen.add(line);

      findings.push({
        ruleId: 'supabase-public-bucket',
        ruleName: 'Supabase Public Storage Bucket',
        severity: 'warning',
        message: 'Supabase Storage bucket created with public: true — every file in it is readable by anyone with the URL. Fine for public assets, a leak for user uploads / private files.',
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Make the bucket private (public: false) and serve files with short-lived signed URLs: `supabase.storage.from(bucket).createSignedUrl(path, 60)`. Only keep a bucket public if everything in it is genuinely public.',
      });
    }
    return findings;
  },
};
