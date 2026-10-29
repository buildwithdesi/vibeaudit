#!/usr/bin/env node

/**
 * Run the safe, checked-in Agent Shield benchmark corpus.
 *
 * The corpus contains inert fixtures. This runner calls the production
 * control-plane scanner and never executes a fixture, hook, or MCP command.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanAgentControlPlane } from '../src/guard/control-plane.js';

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const DEFAULT_MANIFEST = resolve(REPO_ROOT, 'tests/fixtures/agent-benchmark/manifest.json');

function readManifest(manifestPath = DEFAULT_MANIFEST) {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.cases)) {
    throw new Error('Agent benchmark manifest must use schemaVersion 1 and contain cases.');
  }
  return { manifest, manifestPath: resolve(manifestPath) };
}

function expectedDecisionFor(caseDefinition) {
  const allowed = new Set(['pass', 'review', 'block']);
  if (!allowed.has(caseDefinition.expectedDecision)) {
    throw new Error(`${caseDefinition.id}: expectedDecision must be pass, review, or block.`);
  }
  return caseDefinition.expectedDecision;
}

function classifyResult(caseDefinition, report) {
  const expectedDecision = expectedDecisionFor(caseDefinition);
  const exact = report.decision === expectedDecision;
  const isBenign = caseDefinition.classification === 'benign';
  const isMalicious = caseDefinition.classification === 'malicious';
  const isIncomplete = caseDefinition.classification === 'incomplete';
  return {
    id: caseDefinition.id,
    classification: caseDefinition.classification,
    evaluation: caseDefinition.evaluation || 'required',
    expectedDecision,
    actualDecision: report.decision,
    exact,
    coverageComplete: report.coverage.complete,
    scanned: report.coverage.scanned,
    findings: report.findings.map((finding) => finding.id),
    errors: report.coverage.errors,
    benignPass: isBenign && report.decision === 'pass' && report.coverage.complete,
    maliciousBlocked: isMalicious && report.decision === 'block' && report.coverage.complete,
    falsePositive: isBenign && report.decision === 'block',
    falseNegative: isMalicious && report.decision !== 'block',
    incompleteBlocked: isIncomplete && report.decision === 'block' && !report.coverage.complete,
    knownGap: isMalicious && caseDefinition.evaluation === 'known-gap' && report.decision !== 'block',
    sourceRefs: caseDefinition.sourceRefs || [],
  };
}

/**
 * @param {{manifestPath?:string}} [options]
 */
export function runBenchmark(options = {}) {
  const { manifest, manifestPath } = readManifest(options.manifestPath);
  const corpusRoot = resolve(manifestPath, '..');
  const results = manifest.cases.map((caseDefinition) => {
    if (!caseDefinition.id || !caseDefinition.path || !caseDefinition.classification) {
      throw new Error('Every benchmark case needs id, path, and classification.');
    }
    const target = resolve(corpusRoot, caseDefinition.path);
    const report = scanAgentControlPlane(target);
    return classifyResult(caseDefinition, report);
  });
  const required = results.filter((result) => result.evaluation === 'required');
  return {
    schemaVersion: 1,
    mode: 'safe-agent-shield-benchmark',
    manifestPath,
    corpusRoot,
    cases: results,
    summary: {
      total: results.length,
      exact: results.filter((result) => result.exact).length,
      required: required.length,
      requiredExact: required.filter((result) => result.exact).length,
      requiredFailures: required.filter((result) => !result.exact).length,
      benign: results.filter((result) => result.classification === 'benign').length,
      benignPass: results.filter((result) => result.benignPass).length,
      falsePositives: results.filter((result) => result.falsePositive).length,
      malicious: results.filter((result) => result.classification === 'malicious').length,
      maliciousBlocked: results.filter((result) => result.maliciousBlocked).length,
      falseNegatives: results.filter((result) => result.falseNegative).length,
      knownGaps: results.filter((result) => result.knownGap).length,
      incomplete: results.filter((result) => result.classification === 'incomplete').length,
      incompleteBlocked: results.filter((result) => result.incompleteBlocked).length,
    },
  };
}

export function formatBenchmark(report) {
  const lines = [
    'Agent Shield benchmark (safe inert fixtures)',
    `Cases: ${report.summary.total}`,
    `Required exact matches: ${report.summary.requiredExact}/${report.summary.required}`,
    `Benign pass: ${report.summary.benignPass}/${report.summary.benign}, false positives: ${report.summary.falsePositives}`,
    `Malicious blocked: ${report.summary.maliciousBlocked}/${report.summary.malicious}, false negatives: ${report.summary.falseNegatives}`,
    `Incomplete blocked: ${report.summary.incompleteBlocked}/${report.summary.incomplete}`,
    '',
  ];
  for (const result of report.cases) {
    const marker = result.exact ? 'PASS' : result.knownGap ? 'GAP ' : 'FAIL';
    lines.push(`${marker} ${result.id}: expected ${result.expectedDecision}, got ${result.actualDecision}; coverage ${result.coverageComplete ? 'complete' : 'incomplete'}; findings ${result.findings.join(', ') || 'none'}`);
    for (const error of result.errors) lines.push(`     coverage error: ${error}`);
  }
  lines.push('', 'This is a small fixture benchmark, not a malware verdict or detection certification.');
  return lines.join('\n');
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  try {
    const report = runBenchmark();
    if (process.argv.includes('--json')) console.log(JSON.stringify(report, null, 2));
    else console.log(formatBenchmark(report));
    process.exitCode = process.argv.includes('--strict') && report.summary.requiredFailures > 0 ? 1 : 0;
  } catch (error) {
    console.error(`Agent benchmark: ${error.message}`);
    process.exitCode = 2;
  }
}
