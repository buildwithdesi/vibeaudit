import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fetchRepoFiles } from '../src/github.js';

const SHA = 'a'.repeat(40);
const BLOB_SHA = 'b'.repeat(40);

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

async function collect(source) {
  const files = [];
  for await (const file of source) files.push(file);
  return files;
}

describe('GitHub snapshot scanning', () => {
  it('binds every file to one commit and fetches authenticated blobs only from api.github.com', async () => {
    const originalFetch = globalThis.fetch;
    const urls = [];
    globalThis.fetch = async (url) => {
      urls.push(String(url));
      if (String(url).includes('/commits/HEAD')) return jsonResponse({ sha: SHA });
      if (String(url).includes(`/git/trees/${SHA}`)) {
        return jsonResponse({
          truncated: false,
          tree: [{ type: 'blob', path: '.claude/skills/transcriber/SKILL.md', sha: BLOB_SHA, size: 28 }],
        });
      }
      if (String(url).includes(`/git/blobs/${BLOB_SHA}`)) {
        return jsonResponse({ encoding: 'base64', content: Buffer.from('Use short, clear sentences.').toString('base64') });
      }
      throw new Error(`Unexpected URL: ${url}`);
    };
    try {
      const files = await collect(fetchRepoFiles('owner', 'repo'));
      assert.equal(files.length, 1);
      assert.equal(files[0]._snapshot, SHA);
      assert.equal(files[0]._agentControl, true);
      assert.match(files[0].path, new RegExp(`@${SHA}/`));
      assert.ok(urls.every((url) => url.startsWith('https://api.github.com/')));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('fails instead of reporting a truncated tree as clean', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      if (String(url).includes('/commits/HEAD')) return jsonResponse({ sha: SHA });
      return jsonResponse({ truncated: true, tree: [] });
    };
    try {
      await assert.rejects(() => collect(fetchRepoFiles('owner', 'repo')), /truncated/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('fails when one selected blob cannot be fetched', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      if (String(url).includes('/commits/HEAD')) return jsonResponse({ sha: SHA });
      if (String(url).includes('/git/trees/')) {
        return jsonResponse({ truncated: false, tree: [{ type: 'blob', path: 'src/app.js', sha: BLOB_SHA, size: 12 }] });
      }
      return jsonResponse({ message: 'failed' }, 500);
    };
    try {
      await assert.rejects(() => collect(fetchRepoFiles('owner', 'repo')), /GitHub API error \(500\)/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('fails when a selected source file exceeds the scan limit', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      if (String(url).includes('/commits/HEAD')) return jsonResponse({ sha: SHA });
      return jsonResponse({
        truncated: false,
        tree: [{ type: 'blob', path: 'src/app.js', sha: BLOB_SHA, size: 3 * 1024 * 1024 }],
      });
    };
    try {
      await assert.rejects(() => collect(fetchRepoFiles('owner', 'repo')), /exceeds the 2 MB safety limit/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
