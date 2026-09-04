#!/usr/bin/env node

import { denyHook, evaluateHook, readHookInput } from '../src/guard/hook.js';

try {
  const payload = await readHookInput();
  const verdict = evaluateHook(payload);
  if (!verdict.allow) console.log(JSON.stringify(verdict.output));
} catch (error) {
  console.log(JSON.stringify(denyHook(`VibeGuard failed closed: ${error.message}`)));
}
