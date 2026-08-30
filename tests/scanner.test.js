import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

import { discoverFiles } from '../src/scanner.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = resolve(__dirname, 'fixtures');

describe('scanner', () => {
  it('discovers files in fixtures directory', async () => {
    const files = [];
    for await (const file of discoverFiles(FIXTURES_DIR)) {
      files.push(file);
    }

    assert.ok(files.length >= 3, `Should find at least 3 fixture files, found ${files.length}`);

    // Check that all files have required properties.
    for (const file of files) {
      assert.ok(file.path, 'File should have path');
      assert.ok(file.relativePath, 'File should have relativePath');
      assert.ok(typeof file.content === 'string', 'File should have content');
      assert.ok(Array.isArray(file.lines), 'File should have lines');
    }
  });

  it('respects ignore patterns', async () => {
    const files = [];
    for await (const file of discoverFiles(FIXTURES_DIR, ['api'])) {
      files.push(file);
    }

    const apiFiles = files.filter((f) => f.relativePath.includes('api/'));
    assert.equal(apiFiles.length, 0, 'Should skip ignored directories');
  });

  it('respects ignore patterns with a trailing slash (e.g. "api/" from .vibe-audit.json)', async () => {
    const files = [];
    for await (const file of discoverFiles(FIXTURES_DIR, ['api/'])) {
      files.push(file);
    }

    const apiFiles = files.filter((f) => f.relativePath.includes('api/'));
    assert.equal(apiFiles.length, 0, 'A trailing slash on a config ignore entry should still match the directory');
  });

  it('scans agent controls and installer scripts while excluding only Claude worktrees', async () => {
    const root = mkdtempSync(resolve(tmpdir(), 'vibeaudit-scanner-agent-test-'));
    mkdirSync(resolve(root, '.claude', 'skills', 'demo'), { recursive: true });
    mkdirSync(resolve(root, '.claude', 'worktrees', 'copy'), { recursive: true });
    writeFileSync(resolve(root, '.claude', 'skills', 'demo', 'SKILL.md'), 'Use clear instructions.');
    writeFileSync(resolve(root, '.claude', 'worktrees', 'copy', 'SKILL.md'), 'Duplicate.');
    writeFileSync(resolve(root, 'install.ps1'), 'Write-Host "install"');
    writeFileSync(resolve(root, '.npmrc'), 'registry=https://registry.npmjs.org/');
    try {
      const files = [];
      for await (const file of discoverFiles(root, ['.claude/worktrees'])) files.push(file);
      const paths = files.map((file) => file.relativePath);
      assert.ok(paths.includes('.claude/skills/demo/SKILL.md'));
      assert.ok(paths.includes('install.ps1'));
      assert.ok(paths.includes('.npmrc'));
      assert.ok(!paths.includes('.claude/worktrees/copy/SKILL.md'));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
