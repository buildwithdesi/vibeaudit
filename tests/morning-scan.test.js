import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { discoverRepos, shouldAcceptDiscovery } from '../scripts/morning-scan.js';

/**
 * Builds a fake fetch that records requested URLs and replies from a route map.
 * Any URL not in the map returns an empty page, which terminates pagination.
 */
function fakeFetch(routes) {
  const calls = [];
  const impl = async (url) => {
    calls.push(url);
    for (const [pattern, body] of Object.entries(routes)) {
      if (url.includes(pattern)) {
        return { ok: true, status: 200, json: async () => body(url) };
      }
    }
    return { ok: true, status: 200, json: async () => [] };
  };
  impl.calls = calls;
  return impl;
}

const repo = (name, extra = {}) => ({ full_name: name, archived: false, fork: false, ...extra });

describe('discoverRepos endpoint selection', () => {
  const original = { GITHUB_TOKEN: process.env.GITHUB_TOKEN, GH_TOKEN: process.env.GH_TOKEN };

  beforeEach(() => {
    process.env.GITHUB_TOKEN = 'test-token';
    delete process.env.GH_TOKEN;
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(original)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  test('uses /user/repos so private repos are included when scanning your own account', async () => {
    const fetchImpl = fakeFetch({
      'api.github.com/user/repos': (url) =>
        url.includes('&page=1&') ? [repo('buildwithdesi/private-one', { private: true })] : [],
      'api.github.com/user': () => ({ login: 'buildwithdesi' }),
    });

    const { repos, scope } = await discoverRepos('buildwithdesi', { fetchImpl });

    assert.equal(scope, 'public + private');
    assert.deepEqual(repos, ['buildwithdesi/private-one']);
    assert.ok(
      fetchImpl.calls.some((u) => u.includes('/user/repos?affiliation=owner')),
      `expected /user/repos, got: ${fetchImpl.calls.join(', ')}`,
    );
    assert.ok(
      !fetchImpl.calls.some((u) => u.includes('/users/buildwithdesi/repos')),
      '/users/{owner}/repos returns public repos only — must not be used for your own account',
    );
  });

  test('falls back to /users/{owner}/repos for an account the token does not own', async () => {
    const fetchImpl = fakeFetch({
      'api.github.com/users/someoneelse/repos': (url) =>
        url.includes('&page=1&') ? [repo('someoneelse/public-one')] : [],
      'api.github.com/user': () => ({ login: 'buildwithdesi' }),
    });

    const { repos, scope } = await discoverRepos('someoneelse', { fetchImpl });

    assert.equal(scope, 'public only');
    assert.deepEqual(repos, ['someoneelse/public-one']);
  });

  test('skips archived repos and forks', async () => {
    const fetchImpl = async (url) => {
      if (url === 'https://api.github.com/user') {
        return { ok: true, status: 200, json: async () => ({ login: 'buildwithdesi' }) };
      }
      const body = url.includes('&page=1&')
        ? [
            repo('buildwithdesi/live'),
            repo('buildwithdesi/old', { archived: true }),
            repo('buildwithdesi/copied', { fork: true }),
          ]
        : [];
      return { ok: true, status: 200, json: async () => body };
    };

    const { repos } = await discoverRepos('buildwithdesi', { fetchImpl });
    assert.deepEqual(repos, ['buildwithdesi/live']);
  });

  test('paginates until an empty page', async () => {
    const pages = {
      '&page=1&': [repo('o/a'), repo('o/b')],
      '&page=2&': [repo('o/c')],
      '&page=3&': [],
    };
    const fetchImpl = async (url) => {
      if (url === 'https://api.github.com/user') {
        return { ok: true, status: 200, json: async () => ({ login: 'o' }) };
      }
      const key = Object.keys(pages).find((p) => url.includes(p));
      return { ok: true, status: 200, json: async () => pages[key] ?? [] };
    };

    const { repos } = await discoverRepos('o', { fetchImpl });
    assert.deepEqual(repos, ['o/a', 'o/b', 'o/c']);
  });

  test('throws instead of silently returning a partial list on API error', async () => {
    const fetchImpl = async (url) => {
      if (url === 'https://api.github.com/user') {
        return { ok: true, status: 200, json: async () => ({ login: 'o' }) };
      }
      return { ok: false, status: 401, json: async () => ({}) };
    };

    await assert.rejects(() => discoverRepos('o', { fetchImpl }), /Failed to list repos: 401/);
  });
});

describe('shouldAcceptDiscovery shrink guard', () => {
  test('rejects a discovery that lost most of the portfolio', () => {
    // The real regression: /users/{owner}/repos returned 15 of 172 repos.
    assert.equal(shouldAcceptDiscovery(15, 172), false);
  });

  test('accepts growth and small churn', () => {
    assert.equal(shouldAcceptDiscovery(172, 158), true);
    assert.equal(shouldAcceptDiscovery(158, 158), true);
    assert.equal(shouldAcceptDiscovery(150, 172), true);
  });

  test('rejects at the boundary, accepts exactly at the threshold', () => {
    assert.equal(shouldAcceptDiscovery(75, 100), true);
    assert.equal(shouldAcceptDiscovery(74, 100), false);
  });

  test('accepts anything when there is no saved list to protect', () => {
    assert.equal(shouldAcceptDiscovery(0, 0), true);
    assert.equal(shouldAcceptDiscovery(5, 0), true);
  });

  test('force overrides the guard', () => {
    assert.equal(shouldAcceptDiscovery(15, 172, true), true);
  });
});
