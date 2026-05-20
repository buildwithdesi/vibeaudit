import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { loadRepoList } from '../src/batch.js';
import { writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

describe('batch', () => {
  describe('loadRepoList', () => {
    it('loads an array of strings', async () => {
      const tmpFile = join(tmpdir(), `vibe-audit-test-${Date.now()}.json`);
      await writeFile(tmpFile, JSON.stringify(['owner/repo1', 'owner/repo2']));
      try {
        const repos = await loadRepoList(tmpFile);
        assert.equal(repos.length, 2);
        assert.deepEqual(repos[0], { repo: 'owner/repo1' });
        assert.deepEqual(repos[1], { repo: 'owner/repo2' });
      } finally {
        await unlink(tmpFile).catch(() => {});
      }
    });

    it('loads an array of objects', async () => {
      const tmpFile = join(tmpdir(), `vibe-audit-test-${Date.now()}.json`);
      const data = [
        { repo: 'owner/repo1', rules: ['exposed-secrets'] },
        { repo: 'owner/repo2', exclude: ['devtools-enabled'] },
      ];
      await writeFile(tmpFile, JSON.stringify(data));
      try {
        const repos = await loadRepoList(tmpFile);
        assert.equal(repos.length, 2);
        assert.deepEqual(repos[0], { repo: 'owner/repo1', rules: ['exposed-secrets'] });
        assert.deepEqual(repos[1], { repo: 'owner/repo2', exclude: ['devtools-enabled'] });
      } finally {
        await unlink(tmpFile).catch(() => {});
      }
    });

    it('loads a mixed array', async () => {
      const tmpFile = join(tmpdir(), `vibe-audit-test-${Date.now()}.json`);
      const data = ['owner/repo1', { repo: 'owner/repo2', rules: ['missing-auth'] }];
      await writeFile(tmpFile, JSON.stringify(data));
      try {
        const repos = await loadRepoList(tmpFile);
        assert.equal(repos.length, 2);
        assert.deepEqual(repos[0], { repo: 'owner/repo1' });
        assert.deepEqual(repos[1], { repo: 'owner/repo2', rules: ['missing-auth'] });
      } finally {
        await unlink(tmpFile).catch(() => {});
      }
    });

    it('rejects non-array input', async () => {
      const tmpFile = join(tmpdir(), `vibe-audit-test-${Date.now()}.json`);
      await writeFile(tmpFile, JSON.stringify({ repos: ['a/b'] }));
      try {
        await assert.rejects(() => loadRepoList(tmpFile), /Expected an array/);
      } finally {
        await unlink(tmpFile).catch(() => {});
      }
    });

    it('rejects invalid entries', async () => {
      const tmpFile = join(tmpdir(), `vibe-audit-test-${Date.now()}.json`);
      await writeFile(tmpFile, JSON.stringify([42]));
      try {
        await assert.rejects(() => loadRepoList(tmpFile), /Invalid entry/);
      } finally {
        await unlink(tmpFile).catch(() => {});
      }
    });
  });
});
