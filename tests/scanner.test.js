import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

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
});
