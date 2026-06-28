/**
 * Rule: supabase-service-key-client
 * Detects the Supabase service_role key (which bypasses all RLS) referenced in
 * code that actually ships to the browser.
 *
 * Context-aware: a file is only treated as client code when it has a
 * `'use client'` directive or lives in a plainly-client location — importing
 * React no longer counts, because App Router components are server by default.
 * A `NEXT_PUBLIC_*SERVICE_ROLE` reference is always flagged regardless of file,
 * since NEXT_PUBLIC vars are bundled to the browser.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { isClient } from '../context.js';

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|\.server\.|server\/|api\/|src\/rules\/)/i;

const SERVICE_KEY_PATTERNS = [
  /service_role/i,
  /SUPABASE_SERVICE_ROLE/i,
  /serviceRole/i,
  /supabaseAdmin/i,
];

/** A NEXT_PUBLIC_* service-role/key env var — bundled to the client, always wrong. */
const NEXT_PUBLIC_LEAK = /NEXT_PUBLIC_[A-Z0-9_]*(?:SERVICE_ROLE|SERVICEROLE|SERVICE_KEY)/i;

/** @type {Rule} */
export const supabaseServiceKeyClient = {
  id: 'supabase-service-key-client',
  name: 'Supabase Service Key in Client',
  severity: 'critical',
  description: 'Detects Supabase service_role key used in client-side code.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];

    const client = isClient(file);
    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
      // Type-only imports never reach runtime.
      if (/^import\s+type\b/.test(trimmed)) continue;

      const nextPublicLeak = NEXT_PUBLIC_LEAK.test(line);
      // On server files, only the NEXT_PUBLIC footgun is actually exploitable.
      if (!client && !nextPublicLeak) continue;

      for (const pattern of SERVICE_KEY_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            ruleId: 'supabase-service-key-client',
            ruleName: 'Supabase Service Key in Client',
            severity: 'critical',
            message: nextPublicLeak
              ? 'Supabase service_role key exposed via a NEXT_PUBLIC_ env var — bundled to the browser.'
              : 'Supabase service_role key referenced in client-side code — bypasses all RLS.',
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: 'Never expose the service_role key to the client. Use the anon key for browser Supabase calls, and keep service_role usage in server-only code (route handlers, server actions, or files importing "server-only").',
          });
          break;
        }
      }
    }

    return findings;
  },
};
