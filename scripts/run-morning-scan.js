#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Findings are allowed; a crashed scan or missing report is never success. */
export function verifyMorningScan(result, outputDir) {
  if (result.error || result.signal || ![0, 1].includes(result.status)) {
    throw new Error(`Morning scan failed (exit ${result.status}, signal ${result.signal || 'none'}).`);
  }
  const files = readdirSync(outputDir);
  const jsonFiles = files.filter((file) => /^morning-scan-\d{4}-\d{2}-\d{2}\.json$/.test(file));
  if (jsonFiles.length !== 1) throw new Error('Expected one JSON report from this run.');
  const jsonFile = jsonFiles[0];
  const markdown = readFileSync(join(outputDir, jsonFile.replace(/\.json$/, '.md')), 'utf8');
  if (!markdown.trim()) throw new Error('Morning scan Markdown report is empty.');
  const report = JSON.parse(readFileSync(join(outputDir, jsonFile), 'utf8'));
  if (!Array.isArray(report.results) || !Array.isArray(report.errors)
      || report.results.length === 0 || report.summary?.total !== report.results.length
      || report.summary?.attempted !== report.results.length + report.errors.length) {
    throw new Error('Morning scan report has missing or inconsistent coverage.');
  }
  return report.summary;
}

export function runMorningScan(args = [], { reportsDir = join(root, 'reports'), run = spawnSync } = {}) {
  mkdirSync(reportsDir, { recursive: true });
  // Each invocation has an empty directory, so yesterday's report cannot pass.
  const outputDir = mkdtempSync(join(reportsDir, 'morning-run-'));
  const result = run(process.execPath, [
    join(root, 'scripts', 'morning-scan.js'), '--output-dir', outputDir, ...args,
  ], { stdio: 'inherit', shell: false });
  const summary = verifyMorningScan(result, outputDir);
  console.log(`Verified ${summary.total} scanned repositories. Reports: ${outputDir}`);
  return summary;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    runMorningScan(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
  }
}
