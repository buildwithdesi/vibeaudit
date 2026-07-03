/**
 * Rule: nextjs-server-action-exposure
 * Detects Next.js server actions that lack authentication checks. Server
 * actions are callable from the client and must validate the caller.
 *
 * Context-aware: only EXPORTED functions are flagged (non-exported helpers
 * aren't client-callable), and auth detection recognizes custom/imported
 * guards and wrapper functions.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { parseSource, isParseable, findExportedFunctions, collectImportedNames, callsAuthGuard } from '../ast.js';
import { hasUseServer } from '../context.js';

// Used only to locate a display line once hasUseServer() has already confirmed
// a real directive exists — never to decide whether one exists. A naive
// content-wide regex would also match "use server" mentioned inside comments
// or string literals (e.g. context.js's own JSDoc and its hasDirective() helper).
const USE_SERVER_LINE = /['"]use server['"]/;
const SERVER_ACTION_FILE = /(?:actions|server-actions?)\.(js|ts|jsx|tsx)$/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|fixtures\/|src\/rules\/)/i;
const FILE_LEVEL_AUTH = /(?:getServerSession|getSession|auth\(\)|require\w*auth\w*|currentUser|getUser|session\.user|clerkClient|verify\w*token)/i;

/** @type {Rule} */
export const nextjsServerActionExposure = {
  id: 'nextjs-server-action-exposure',
  name: 'Next.js Server Action Exposure',
  severity: 'critical',
  description: 'Detects Next.js server actions without authentication checks.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    const hasDirective = hasUseServer(file);
    const isActionFile = SERVER_ACTION_FILE.test(file.relativePath);
    if (!hasDirective && !isActionFile) return [];
    if (!isParseable(file.relativePath)) return [];

    const ast = parseSource(file.content);
    if (!ast) return [];

    const imported = collectImportedNames(ast);
    const exported = findExportedFunctions(ast);

    const findings = [];
    for (const fn of exported) {
      if (callsAuthGuard(fn.body, imported, file._config?.customAuthGuards)) continue;

      const line = fn.loc?.start?.line || 1;
      findings.push({
        ruleId: 'nextjs-server-action-exposure',
        ruleName: 'Next.js Server Action Exposure',
        severity: 'critical',
        message: `Server action "${fn.name}" has no authentication check. Anyone can call it.`,
        file: file.relativePath,
        line,
        evidence: file.lines[line - 1]?.trim().slice(0, 120),
        fix: 'Add auth at the top of every exported server action (e.g. "const session = await getServerSession(); if (!session) throw new Error(\'Unauthorized\');") or wrap it with your auth guard. If it is intentionally public, add "// vibe-audit-ignore-next-line nextjs-server-action-exposure".',
      });
    }

    // If we found exported functions, trust that result (precise per-function check).
    if (exported.length > 0) return findings;

    // Fallback: a "use server" file we couldn't resolve into exports, with no auth anywhere.
    if (hasDirective && !FILE_LEVEL_AUTH.test(file.content)) {
      const lineIdx = file.lines.findIndex((l) => USE_SERVER_LINE.test(l));
      findings.push({
        ruleId: 'nextjs-server-action-exposure',
        ruleName: 'Next.js Server Action Exposure',
        severity: 'critical',
        message: 'File uses "use server" directive but contains no authentication checks.',
        file: file.relativePath,
        line: lineIdx + 1,
        fix: 'Add authentication checks to every exported function in this server action file.',
      });
    }

    return findings;
  },
};
