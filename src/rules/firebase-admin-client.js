/**
 * Rule: firebase-admin-client
 * Detects Firebase Admin SDK imported or initialized in client-side code.
 * The Admin SDK has full access and must only run server-side.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { hasUseClient, isServerOnly } from '../context.js';

/**
 * Credentials the browser can never hold: a non-public `process.env` secret of
 * the kind the Admin SDK initializes from. A module sourcing its credentials
 * this way is server code even when it sits under `src/` — bundling it would
 * fail at runtime rather than leak, because the value is not in the bundle.
 *
 * `CLIENT_FILE` below counts any `src/` path as client, which on the 2026-08-13
 * scan made chibi-forge's `src/lib/firebaseAdmin.js` a critical finding: a
 * textbook server module reading `process.env.FIREBASE_PRIVATE_KEY`, guarded by
 * an early return when the key is absent.
 *
 * NEXT_PUBLIC_/VITE_/REACT_APP_ are excluded from the escape hatch on purpose —
 * those prefixes DO ship to the browser, so they stay flagged.
 */
const SERVER_SECRET_ENV =
  /process\.env\.(?!NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:PRIVATE_KEY|CLIENT_EMAIL|SERVICE_ACCOUNT|CREDENTIALS?)/;

const CLIENT_FILE = /(?:src\/|app\/(?!api)|pages\/(?!api)|components\/|hooks\/|lib\/client|utils\/client).*\.(js|ts|jsx|tsx)$/i;
const CLIENT_INDICATOR = /['"]use client['"]|import\s+.*from\s+['"]react['"]|useState|useEffect|onClick/;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|\.server\.|server\/|api\/|functions\/)/i;

const ADMIN_PATTERNS = [
  /import\s+.*from\s+['"]firebase-admin/g,
  /require\s*\(\s*['"]firebase-admin/g,
  /admin\.initializeApp/g,
  /admin\.firestore\(\)/g,
  /admin\.auth\(\)/g,
  /getFirestore\s*\(\s*adminApp/g,
];

/** @type {Rule} */
export const firebaseAdminClient = {
  id: 'firebase-admin-client',
  name: 'Firebase Admin in Client',
  severity: 'critical',
  description: 'Detects Firebase Admin SDK imported in client-side code.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];

    // 'use client' is decisive — Admin SDK there is a real leak whatever else the
    // file does. Absent it, a server marker or server-only credentials mean this
    // module never reaches the browser, so the path heuristics below don't apply.
    if (!hasUseClient(file) && (isServerOnly(file) || SERVER_SECRET_ENV.test(file.content))) {
      return [];
    }

    const isClient = CLIENT_FILE.test(file.relativePath) || CLIENT_INDICATOR.test(file.content);
    if (!isClient) return [];

    const findings = [];

    for (const pattern of ADMIN_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        const line = file.lines[lineNum - 1]?.trim();
        if (line?.startsWith('//') || line?.startsWith('*')) continue;

        findings.push({
          ruleId: 'firebase-admin-client',
          ruleName: 'Firebase Admin in Client',
          severity: 'critical',
          message: 'Firebase Admin SDK used in client-side code — grants full database/auth access.',
          file: file.relativePath,
          line: lineNum,
          evidence: line?.slice(0, 120),
          fix: 'Move Firebase Admin SDK usage to server-side API routes or Cloud Functions. Use the regular Firebase client SDK for client-side code.',
        });
      }
    }

    return findings;
  },
};
