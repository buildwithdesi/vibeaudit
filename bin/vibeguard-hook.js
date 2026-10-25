#!/usr/bin/env node

import { evaluateHook, readHookInput } from '../src/guard/hook.js';

try {
  const payload = await readHookInput();
  const verdict = evaluateHook(payload);
  if (!verdict.allow) console.log(JSON.stringify(verdict.output));
} catch (error) {
  process.stderr.write(`VibeGuard could not complete its check and allowed this action to continue: ${error.message}\n`);
}
