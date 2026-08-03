/**
 * Rule: nextjs-middleware-bypass
 * Detects Next.js middleware that doesn't cover all routes or has
 * a matcher config that leaves API routes unprotected.
 */

/** @typedef {import('./types.js').Rule} Rule */

const MIDDLEWARE_FILE = /middleware\.(js|ts|jsx|tsx)$/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

/** @type {Rule} */
export const nextjsMiddlewareBypass = {
  id: 'nextjs-middleware-bypass',
  name: 'Next.js Middleware Bypass',
  severity: 'critical',
  description: 'Detects Next.js middleware with matcher config that may leave routes unprotected.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!MIDDLEWARE_FILE.test(file.relativePath)) return [];

    const findings = [];

    // Check for matcher that excludes API routes
    const matcherMatch = file.content.match(/export\s+const\s+config\s*=\s*\{[^}]*matcher\s*:\s*(\[[\s\S]*?\]|['"][^'"]*['"])/);
    if (matcherMatch) {
      const matcher = matcherMatch[1];
      // If matcher only covers specific paths and doesn't include /api
      if (!matcher.includes('/api') && !matcher.includes('/:path*') && !matcher.includes('/((?!') ) {
        const lineIdx = file.lines.findIndex((l) => /matcher/.test(l));
        findings.push({
          ruleId: 'nextjs-middleware-bypass',
          ruleName: 'Next.js Middleware Bypass',
          severity: 'critical',
          message: 'Middleware matcher does not cover /api routes — API endpoints may be unprotected.',
          file: file.relativePath,
          line: lineIdx >= 0 ? lineIdx + 1 : 1,
          evidence: file.lines[lineIdx]?.trim().slice(0, 120),
          fix: 'Expand the matcher to include API routes, or ensure API routes have their own auth checks. Example: matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"].',
        });
      }
    }

    // Check for conditional logic that might skip auth.
    //
    // The original list predated the current generation of middleware helpers,
    // so a Clerk app — where `clerkMiddleware()` IS the entire auth layer —
    // reported "contains no authentication logic" as a critical. Requires a
    // CALL, not just an import: a file that imports Clerk and never invokes it
    // is genuinely protecting nothing.
    const hasAuth =
      /(?:getToken|getSession|auth\(\)|NextResponse\.redirect.*login|NextResponse\.redirect.*sign-in)/i.test(
        file.content,
      ) ||
      /\b(?:clerkMiddleware|authMiddleware|withClerkMiddleware|withAuth|NextAuth|updateSession|createMiddlewareClient|createServerClient)\s*\(/.test(
        file.content,
      );
    if (!hasAuth) {
      findings.push({
        ruleId: 'nextjs-middleware-bypass',
        ruleName: 'Next.js Middleware Bypass',
        severity: 'critical',
        message: 'Middleware file contains no authentication or redirect logic.',
        file: file.relativePath,
        line: 1,
        fix: 'Add auth checking in middleware: verify session/token and redirect unauthenticated users to login.',
      });
    }

    return findings;
  },
};
