import test from 'node:test';
import assert from 'node:assert/strict';
import { denyHook } from '../src/guard/hook.js';

test('ConfigChange denial uses the event-specific blocking response', () => {
  assert.deepEqual(denyHook('Fixture configuration change was not reviewed.', 'ConfigChange'), {
    decision: 'block',
    reason: 'Fixture configuration change was not reviewed.',
  });
});

test('PreToolUse denial preserves the tool permission response', () => {
  assert.deepEqual(denyHook('Fixture tool call is not allowed.', 'PreToolUse'), {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: 'Fixture tool call is not allowed.',
    },
  });
});

test('Unspecified event keeps the PreToolUse default', () => {
  assert.deepEqual(denyHook('Fixture failure.'), denyHook('Fixture failure.', 'PreToolUse'));
});
