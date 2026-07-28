import { test } from 'node:test';
import assert from 'node:assert/strict';

import { classifyScanError } from '../scripts/morning-scan.js';

const err = (msg) => new Error(msg);

test('a 403 that says "rate limit" is retryable', () => {
  const c = classifyScanError(
    err('GitHub API error (403): {"message":"API rate limit exceeded for user ID 1."}'),
  );
  assert.equal(c.kind, 'rate-limited');
  assert.equal(c.rateLimited, true);
});

test('a 403 secondary-rate-limit / abuse response is retryable', () => {
  const c = classifyScanError(
    err('GitHub API error (403): {"message":"You have exceeded a secondary rate limit."}'),
  );
  assert.equal(c.kind, 'rate-limited');
  assert.equal(c.rateLimited, true);
});

test('a 403 access denial is NOT reported as a rate limit', () => {
  const c = classifyScanError(
    err(
      'GitHub API error (403): {"message":"GitHub access to this repository is not enabled for this session."}',
    ),
  );
  assert.equal(c.kind, 'access-denied');
  assert.equal(c.label, 'Access denied');
  // Backing off cannot fix a permission problem — it only burns wall-clock.
  assert.equal(c.rateLimited, false);
});

test('429 without a rate-limit body still counts as denial, not throttling', () => {
  const c = classifyScanError(err('GitHub API error (429): {"message":"Forbidden by policy"}'));
  assert.equal(c.kind, 'access-denied');
  assert.equal(c.rateLimited, false);
});

test('401 / 404 / 409 keep their own labels', () => {
  assert.equal(classifyScanError(err('GitHub API error (401): bad creds')).kind, 'auth-required');
  assert.equal(classifyScanError(err('GitHub API error (404): Not Found')).kind, 'not-found');
  assert.equal(classifyScanError(err('GitHub API error (409): Git Repository is empty.')).kind, 'empty');
});

test('unrecognized failures fall through to a truncated message', () => {
  const c = classifyScanError(err('socket hang up'));
  assert.equal(c.kind, 'error');
  assert.equal(c.label, 'socket hang up');
  assert.equal(c.rateLimited, false);
});

test('a repo named like a status code does not hijack classification', () => {
  const c = classifyScanError(err('GitHub API error (404): {"message":"Not Found","repo":"403"}'));
  assert.equal(c.kind, 'not-found');
});
