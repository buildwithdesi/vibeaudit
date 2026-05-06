import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseReposFile, aggregateResults } from '../src/multi-repo.js';

describe('parseReposFile', () => {
  it('parses newline-separated owner/repo entries', () => {
    const input = `
acme/frontend
acme/backend
acme/api-gateway
    `;
    const result = parseReposFile(input);
    assert.deepStrictEqual(result, [
      { owner: 'acme', repo: 'frontend' },
      { owner: 'acme', repo: 'backend' },
      { owner: 'acme', repo: 'api-gateway' },
    ]);
  });

  it('skips comment lines and blank lines', () => {
    const input = `
# These are our production repos
acme/app

# Staging
acme/staging
    `;
    const result = parseReposFile(input);
    assert.equal(result.length, 2);
    assert.equal(result[0].repo, 'app');
    assert.equal(result[1].repo, 'staging');
  });

  it('strips GitHub URLs to owner/repo', () => {
    const input = `
https://github.com/acme/frontend
https://github.com/acme/backend.git
    `;
    const result = parseReposFile(input);
    assert.deepStrictEqual(result, [
      { owner: 'acme', repo: 'frontend' },
      { owner: 'acme', repo: 'backend' },
    ]);
  });

  it('parses JSON array of strings', () => {
    const input = JSON.stringify(['acme/frontend', 'acme/backend']);
    const result = parseReposFile(input);
    assert.deepStrictEqual(result, [
      { owner: 'acme', repo: 'frontend' },
      { owner: 'acme', repo: 'backend' },
    ]);
  });

  it('parses JSON array of objects', () => {
    const input = JSON.stringify([
      { owner: 'acme', repo: 'frontend' },
      { owner: 'acme', repo: 'backend' },
    ]);
    const result = parseReposFile(input);
    assert.deepStrictEqual(result, [
      { owner: 'acme', repo: 'frontend' },
      { owner: 'acme', repo: 'backend' },
    ]);
  });
});

describe('aggregateResults', () => {
  const mockResults = [
    {
      owner: 'acme', repo: 'frontend', grade: 'F', criticals: 3, warnings: 2, infos: 1,
      findings: [
        { ruleId: 'exposed-secrets', severity: 'critical' },
        { ruleId: 'exposed-secrets', severity: 'critical' },
        { ruleId: 'missing-auth', severity: 'critical' },
        { ruleId: 'missing-rate-limiting', severity: 'warning' },
        { ruleId: 'missing-rate-limiting', severity: 'warning' },
        { ruleId: 'no-pagination', severity: 'info' },
      ],
      durationMs: 1200,
    },
    {
      owner: 'acme', repo: 'backend', grade: 'C', criticals: 0, warnings: 2, infos: 0,
      findings: [
        { ruleId: 'missing-rate-limiting', severity: 'warning' },
        { ruleId: 'insecure-jwt', severity: 'warning' },
      ],
      durationMs: 800,
    },
    {
      owner: 'acme', repo: 'docs', grade: 'A', criticals: 0, warnings: 0, infos: 0,
      findings: [],
      durationMs: 200,
    },
  ];

  it('computes correct totals', () => {
    const agg = aggregateResults(mockResults);
    assert.equal(agg.totalRepos, 3);
    assert.equal(agg.totalFindings, 8);
    assert.equal(agg.totalCriticals, 3);
    assert.equal(agg.totalWarnings, 4);
    assert.equal(agg.totalInfos, 1);
  });

  it('computes grade distribution', () => {
    const agg = aggregateResults(mockResults);
    assert.equal(agg.gradeDistribution['F'], 1);
    assert.equal(agg.gradeDistribution['C'], 1);
    assert.equal(agg.gradeDistribution['A'], 1);
    assert.equal(agg.gradeDistribution['B'], 0);
    assert.equal(agg.gradeDistribution['D'], 0);
  });

  it('groups repos by grade', () => {
    const agg = aggregateResults(mockResults);
    assert.deepStrictEqual(agg.reposByGrade['F'], ['acme/frontend']);
    assert.deepStrictEqual(agg.reposByGrade['C'], ['acme/backend']);
    assert.deepStrictEqual(agg.reposByGrade['A'], ['acme/docs']);
  });

  it('ranks top rules by occurrence count', () => {
    const agg = aggregateResults(mockResults);
    assert.equal(agg.topRules[0].ruleId, 'missing-rate-limiting');
    assert.equal(agg.topRules[0].count, 3);
    assert.equal(agg.topRules[1].ruleId, 'exposed-secrets');
    assert.equal(agg.topRules[1].count, 2);
  });

  it('handles empty results', () => {
    const agg = aggregateResults([]);
    assert.equal(agg.totalRepos, 0);
    assert.equal(agg.totalFindings, 0);
    assert.equal(agg.topRules.length, 0);
  });
});
