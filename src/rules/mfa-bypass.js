/**
 * Rule: mfa-bypass
 * Detects MFA implementations that can be bypassed by skipping the
 * verification step and hitting a different endpoint.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|src\/rules\/)/i;

/** @type {Rule} */
export const mfaBypass = {
  id: 'mfa-bypass',
  name: 'MFA Bypass',
  severity: 'warning',
  description: 'Detects MFA implementations that may be skippable.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];

    const hasMFA = /(?:\bmfa|Mfa|MFA|\b2fa|2FA|\btwo[-_ ]?factor|\btotp|Totp|TOTP|\botp|Otp|OTP|\bauthenticator|Authenticator)/.test(file.content);
    if (!hasMFA) return [];

    const findings = [];

    // Pattern: MFA check gated by a boolean flag that could be bypassed
    const mfaOptional = /(?:if\s*\(\s*(?:user\.)?(?:mfaEnabled|twoFactorEnabled|has2FA|hasMFA|requires2FA))/gi;
    mfaOptional.lastIndex = 0;
    let match;
    while ((match = mfaOptional.exec(file.content)) !== null) {
      // Check if there's an else branch that allows login without MFA
      const after = file.content.slice(match.index, match.index + 500);
      if (/else\s*\{[\s\S]{0,200}(?:redirect|navigate|return|token|session|login)/i.test(after)) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'mfa-bypass',
          ruleName: 'MFA Bypass',
          severity: 'warning',
          message: 'MFA check has an else branch that grants access without verification.',
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Ensure the MFA check cannot be bypassed. The session/token should not be fully issued until MFA is verified. Use a "pending MFA" state between password and MFA steps.',
        });
      }
    }

    // Pattern: MFA verified on a separate endpoint with no session link
    if (/[Vv]erify.*(?:\botp|Otp|OTP|\btotp|Totp|TOTP|\bmfa|Mfa|MFA|\b2fa|2FA)/.test(file.content)) {
      const checksMfaSession = /(?:mfaSession|pendingMfa|mfaPending|awaitingMfa|mfaToken)/i.test(file.content);
      if (!checksMfaSession) {
        const lineIdx = file.lines.findIndex((l) => /[Vv]erify.*(?:\botp|Otp|OTP|\btotp|Totp|TOTP|\bmfa|Mfa|MFA|\b2fa|2FA)/.test(l));
        findings.push({
          ruleId: 'mfa-bypass',
          ruleName: 'MFA Bypass',
          severity: 'warning',
          message: 'MFA verification endpoint may not be linked to the login session — could be called independently.',
          file: file.relativePath,
          line: lineIdx >= 0 ? lineIdx + 1 : 1,
          fix: 'Link MFA verification to the login session. Issue a temporary "pending MFA" token after password auth, require it for the MFA verify endpoint, and only issue a full session after both steps pass.',
        });
      }
    }

    return findings;
  },
};
