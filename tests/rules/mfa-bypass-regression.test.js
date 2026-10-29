import assert from 'node:assert/strict';
import test from 'node:test';

import { mfaBypass } from '../../src/rules/mfa-bypass.js';

function source(content) {
  return { relativePath: 'src/control-plane.js', content, lines: content.split('\n') };
}

test('mfa-bypass does not mistake rootPath or options for OTP code', () => {
  const content = 'export function verifyAgentIntegrityBaseline(rootPath, baselinePath, options) { return rootPath; }';
  assert.deepEqual(mfaBypass.check(source(content)), []);
});

test('mfa-bypass still catches a real OTP verifier without pending-session binding', () => {
  const content = 'export async function verifyOtp(code) { return authenticator.verify(code); }';
  assert.equal(mfaBypass.check(source(content)).length, 1);
});
