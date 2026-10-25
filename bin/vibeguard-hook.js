#!/usr/bin/env node

import { denyHook, evaluateHook, readHookInput } from '../src/guard/hook.js';

let eventName = 'PreToolUse';
try {
  const payload = await readHookInput();
  eventName = payload?.hook_event_name || payload?.hookEventName || eventName;
  const verdict = evaluateHook(payload);
  if (!verdict.allow) console.log(JSON.stringify(verdict.output));
} catch (error) {
  // A guard that cannot finish its check must not wave the action through.
  // A missing baseline is handled inside evaluateHook, so only real failures land here.
  console.log(JSON.stringify(denyHook(`VibeGuard failed closed: ${error.message}`, eventName)));
}
