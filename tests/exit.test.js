import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { ALL_RULES } from '../src/rules/index.js';

const cli = resolve('bin/vibe-audit.js');
const exitModule = pathToFileURL(resolve('src/exit.js')).href;

// stdio "pipe" is a socket pair, where writes are asynchronous. That is how
// another program reads this CLI, and where process.exit() used to cut output.
function runPiped(args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    child.stdout.on('data', (chunk) => out.push(chunk));
    child.stderr.on('data', (chunk) => err.push(chunk));
    child.on('error', reject);
    child.on('close', (status) => resolvePromise({
      status,
      stdout: Buffer.concat(out).toString('utf8'),
      stderr: Buffer.concat(err).toString('utf8'),
    }));
  });
}

test('exitAfterFlush delivers every byte written before it and keeps the exit code', async () => {
  const size = 4 * 1024 * 1024;
  const script = [
    `import { exitAfterFlush } from ${JSON.stringify(exitModule)};`,
    `process.stdout.write('x'.repeat(${size}));`,
    `process.stderr.write('done');`,
    'await exitAfterFlush(3);',
    `process.stdout.write('never');`,
  ].join('\n');
  const result = await runPiped(['--input-type=module', '-e', script]);
  assert.equal(result.status, 3);
  assert.equal(result.stdout.length, size);
  assert.equal(result.stderr, 'done');
});

test('--list-rules prints every rule when read through a pipe by several callers at once', async () => {
  const runs = await Promise.all(Array.from({ length: 8 }, () => runPiped([cli, '--list-rules'])));
  for (const result of runs) {
    assert.equal(result.status, 0, result.stderr);
    // CI=true turns colors on, which puts escape codes in front of each id.
    const plain = result.stdout.replace(/\x1b\[\d+m/g, '');
    const missing = ALL_RULES.map((rule) => rule.id).filter((id) => !plain.includes(` ${id}`));
    assert.deepEqual(missing, []);
  }
});
