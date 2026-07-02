/**
 * Rule: client-side-db-access
 * Detects direct database access (Supabase, Firebase, or query builders like
 * Drizzle/Prisma) inside code that actually runs on the client.
 *
 * Context-aware: uses the shared client/server detection so server components
 * (the App Router default) and files importing "server-only" or marked
 * 'use server' are not flagged for querying the database directly.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { isClient } from '../context.js';

// Patterns representing direct DB query/client initializations or queries.
const DB_PATTERNS = [
  {
    regex: /\.from\s*\(\s*['"`][a-zA-Z0-9_-]+['"`]\s*\)\s*\.(?:select|insert|update|delete|upsert)/gi,
    label: 'Direct Supabase query builder called client-side (e.g. supabase.from().select())',
  },
  {
    regex: /db\s*\.\s*(?:select|insert|update|delete|execute)\s*\(/gi,
    label: 'Direct Drizzle/SQL query builder called client-side (e.g. db.select())',
  },
  {
    regex: /\.collection\s*\(\s*['"`][a-zA-Z0-9_-]+['"`]\s*\)\s*\.(?:doc|get|add|set|update)/gi,
    label: 'Direct Firebase Firestore query called client-side (e.g. db.collection().get())',
  },
];

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

/** @type {Rule} */
export const clientSideDbAccess = {
  id: 'client-side-db-access',
  name: 'Client-Side Database Access',
  severity: 'critical',
  description: 'Detects direct database queries (Supabase, Firebase, or query builders) in client-side code.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];
    // Only client code is at risk — server components / 'use server' / server-only are fine.
    if (!isClient(file)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('{/*')) continue;

      for (const { regex, label } of DB_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({
            ruleId: 'client-side-db-access',
            ruleName: 'Client-Side Database Access',
            severity: 'critical',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
            fix: `Move database query logic to the server (Server Actions, API routes, or server-only modules) and call that endpoint from the client. Direct client-side queries expose your schema and bypass server-side security controls.`,
          });
        }
      }
    }

    return findings;
  },
};
