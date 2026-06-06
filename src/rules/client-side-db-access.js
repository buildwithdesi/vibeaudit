/**
 * Rule: client-side-db-access
 * Detects direct database access (Supabase, Firebase, or query builders like Drizzle/Prisma)
 * inside client-side files.
 */

/** @typedef {import('./types.js').Rule} Rule */

// Patterns representing direct DB query/client initializations or queries
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

// Skip files that are meant to be server-only
const SERVER_ONLY_FILES = /(?:^src\/app\/api\/|^src\/pages\/api\/|^src\/server\/|^api\/|route\.ts$|action\.ts$|\.server\.ts$)/i;
const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const CLIENT_FILES = /\.(?:jsx|tsx|vue|svelte|html)$|(?:^src\/(?:components|pages|app|views))/i;

/** @type {Rule} */
export const clientSideDbAccess = {
  id: 'client-side-db-access',
  name: 'Client-Side Database Access',
  severity: 'critical',
  description: 'Detects direct database queries (Supabase, Firebase, or query builders) in client-side code.',

  check(file) {
    // Only scan files that run on client
    if (!CLIENT_FILES.test(file.relativePath)) return [];
    if (SERVER_ONLY_FILES.test(file.relativePath)) return [];
    if (SKIP_PATTERN.test(file.relativePath)) return [];

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
            fix: `Move all database query logic to the server side (e.g. Server Actions, API routes, or server-only controller functions). Call this server endpoint from your client component. Direct client-side queries expose your database structure and bypass strict server security controls.`,
          });
        }
      }
    }

    return findings;
  },
};
