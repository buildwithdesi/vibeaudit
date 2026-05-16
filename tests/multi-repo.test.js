import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseRepoList } from '../src/multi-repo.js';

describe('parseRepoList', () => {
  it('parses one-per-line text format', () => {
    const content = `
      owner1/repo1
      owner2/repo2
      # this is a comment
      owner3/repo3
    `;
    const repos = parseRepoList(content);
    assert.equal(repos.length, 3);
    assert.equal(repos[0].owner, 'owner1');
    assert.equal(repos[0].repo, 'repo1');
    assert.equal(repos[0].fullName, 'owner1/repo1');
    assert.equal(repos[2].owner, 'owner3');
  });

  it('parses JSON array of strings', () => {
    const content = '["alice/app1", "bob/app2"]';
    const repos = parseRepoList(content);
    assert.equal(repos.length, 2);
    assert.equal(repos[0].owner, 'alice');
    assert.equal(repos[1].repo, 'app2');
  });

  it('parses JSON array of objects', () => {
    const content = JSON.stringify([
      { owner: 'org1', repo: 'service-a' },
      { owner: 'org1', repo: 'service-b' },
    ]);
    const repos = parseRepoList(content);
    assert.equal(repos.length, 2);
    assert.equal(repos[0].fullName, 'org1/service-a');
  });

  it('parses GitHub URLs in text format', () => {
    const content = `
      https://github.com/user/repo1
      https://github.com/user/repo2
    `;
    const repos = parseRepoList(content);
    assert.equal(repos.length, 2);
    assert.equal(repos[0].owner, 'user');
    assert.equal(repos[0].repo, 'repo1');
  });

  it('skips empty lines and comments', () => {
    const content = `
      # Header comment
      owner/repo1

      # Another comment
      owner/repo2

    `;
    const repos = parseRepoList(content);
    assert.equal(repos.length, 2);
  });

  it('throws on invalid repo references', () => {
    assert.throws(() => parseRepoList('not-valid'), /Invalid repo reference/);
  });
});
