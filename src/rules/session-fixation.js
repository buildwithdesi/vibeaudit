/**
 * Rule: session-fixation
 * Detects login handlers that don't regenerate the session after authentication,
 * and logout handlers that don't destroy the server-side session.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const AUTH_FILES = /(?:auth|login|signin|sign-in|logout|signout|sign-out|session|passport)/i;

/** @type {Rule} */
export const sessionFixation = {
  id: 'session-fixation',
  name: 'Session Fixation',
  severity: 'critical',
  description: 'Detects login handlers that do not regenerate the session ID after authentication, and logout handlers that do not destroy the server-side session.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!AUTH_FILES.test(file.relativePath) && !AUTH_FILES.test(file.content)) return [];

    const findings = [];

    // ── Login check ──────────────────────────────────────────────────────────
    const hasLogin = /(?:login|signIn|sign_in|authenticate)\s*(?:=|:|\()/i.test(file.content);
    const hasSessionAssign = /(?:req\.session\.\w+\s*=|session\.\w+\s*=)/i.test(file.content);

    if (hasLogin && hasSessionAssign) {
      const hasRegenerate = /(?:regenerate|rotateSession|req\.session\.regenerate|session\.regenerate)/i.test(file.content);
      if (!hasRegenerate) {
        const lineIdx = file.lines.findIndex((l) => /(?:req\.session\.\w+\s*=|session\.\w+\s*=)/.test(l));
        findings.push({
          ruleId: 'session-fixation',
          ruleName: 'Session Fixation',
          severity: 'critical',
          message: 'Session data set after login without regenerating the session ID.',
          file: file.relativePath,
          line: lineIdx >= 0 ? lineIdx + 1 : 1,
          evidence: file.lines[lineIdx]?.trim().slice(0, 120),
          fix: 'Regenerate the session after login: req.session.regenerate((err) => { req.session.userId = user.id; req.session.save(); }). This prevents session fixation attacks.',
        });
      }
    }

    // ── Logout check ─────────────────────────────────────────────────────────
    const hasLogout = /(?:logout|signOut|sign_out|logOut|log_out)\s*(?:=|:|\()/i.test(file.content);
    if (hasLogout) {
      const hasServerInvalidation = /(?:session\.destroy|req\.session\.destroy|req\.logout|token.*(?:blacklist|revoke|delete|invalidate)|(?:blacklist|revoke|delete|invalidate).*token|\.delete\s*\(.*session|removeSession)/i.test(file.content);
      if (!hasServerInvalidation) {
        const logoutLineIdx = file.lines.findIndex((l) => /(?:logout|signOut|sign_out|logOut|log_out)\s*(?:=|:|\()/i.test(l));
        findings.push({
          ruleId: 'session-fixation',
          ruleName: 'Session Fixation',
          severity: 'critical',
          message: 'Logout handler does not destroy the server-side session — old session tokens remain valid.',
          file: file.relativePath,
          line: logoutLineIdx >= 0 ? logoutLineIdx + 1 : 1,
          evidence: file.lines[logoutLineIdx]?.trim().slice(0, 120),
          fix: 'Add session.destroy() or req.logout() in the logout handler. Clearing cookies alone does not invalidate the session server-side. For JWT auth, add the token to a server-side revocation list on logout.',
        });
      }
    }

    return findings;
  },
};
