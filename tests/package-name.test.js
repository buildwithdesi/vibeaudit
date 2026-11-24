import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';

// WHY THIS TEST EXISTS
// This package is published under a scope: @jackdog668/vibeaudit. The short
// names are NOT ours. `vibe-audit` and `vibe-guard` on npm belong to other
// authors, so `npx vibe-audit` downloads and runs somebody else's program.
// Until 2026-11-23 our own --help screen printed that short command 13 times.
// A security scanner must never send its users to a stranger's code, so any
// `npx <short name>` in text we ship or publish fails the build here.

const pkg = JSON.parse(readFileSync(resolve('package.json'), 'utf8'));

// Commands that look like ours but are not this package.
const BARE_NPX = /npx\s+(?:--yes\s+|-y\s+)?(?:vibe-audit|vibeaudit|vibe-guard|vibeguard)\b/;

// Everything a user can read: the code that prints help and errors, the README
// npm shows, and the docs folder (parts of it ship, the rest is public on GitHub).
const ROOTS = ['bin', 'src', 'docs', 'README.md'];
const TEXT_FILE = /\.(?:js|mjs|cjs|md|txt|json|ps1|html)$/;

function walk(path, found = []) {
  const stat = statSync(path);
  if (stat.isDirectory()) {
    for (const entry of readdirSync(path)) {
      if (entry === 'node_modules') continue;
      walk(join(path, entry), found);
    }
  } else if (TEXT_FILE.test(path)) {
    found.push(path);
  }
  return found;
}

test('the package is published under its scope', () => {
  assert.equal(pkg.name, '@jackdog668/vibeaudit');
});

test('nothing we ship tells a user to npx a short name that is not ours', () => {
  const offenders = [];
  for (const root of ROOTS) {
    for (const file of walk(resolve(root))) {
      const lines = readFileSync(file, 'utf8').split(/\r?\n/);
      lines.forEach((line, index) => {
        if (BARE_NPX.test(line)) offenders.push(`${file}:${index + 1}: ${line.trim().slice(0, 100)}`);
      });
    }
  }
  assert.deepEqual(offenders, [], `use "npx ${pkg.name}" instead:\n${offenders.join('\n')}`);
});

test('--help shows the full scoped command and never the short one', () => {
  const run = spawnSync(process.execPath, [resolve('bin/vibe-audit.js'), '--help'], { encoding: 'utf8' });
  const output = `${run.stdout}${run.stderr}`;
  assert.equal(run.status, 0);
  assert.ok(output.includes(`npx ${pkg.name}`), 'help does not show the scoped command');
  assert.doesNotMatch(output, BARE_NPX);
});
