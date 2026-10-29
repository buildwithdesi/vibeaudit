import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { runMorningScan, verifyMorningScan } from '../scripts/run-morning-scan.js';

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'morning-runner-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function reports(dir, { results = [{ repo: 'example/app' }], errors = [], markdown = '# Scan\n' } = {}) {
  const report = { results, errors, summary: { total: results.length, attempted: results.length + errors.length } };
  writeFileSync(join(dir, 'morning-scan-2026-09-05.json'), JSON.stringify(report));
  writeFileSync(join(dir, 'morning-scan-2026-09-05.md'), markdown);
}

test('verified reports accept clean scans and findings, while preserving partial coverage', (t) => {
  const dir = fixture(t);
  reports(dir, { errors: [{ repo: 'example/private', kind: 'access-denied' }] });
  for (const status of [0, 1]) {
    assert.deepEqual(verifyMorningScan({ status }, dir), { total: 1, attempted: 2 });
  }
});

test('startup failures, signals, and launch errors fail even with valid reports', (t) => {
  const dir = fixture(t);
  reports(dir);
  for (const result of [{ status: 2 }, { status: 9 }, { status: null },
    { status: 0, signal: 'SIGTERM' }, { status: 0, error: new Error('spawn failed') }]) {
    assert.throws(() => verifyMorningScan(result, dir), /Morning scan failed/);
  }
});

test('exit 0 or 1 without reports cannot look successful', (t) => {
  const dir = fixture(t);
  for (const status of [0, 1]) {
    assert.throws(() => verifyMorningScan({ status }, dir), /Expected one JSON report/);
  }
});

test('empty, malformed, missing, and zero-coverage reports fail', (t) => {
  const dir = fixture(t);
  reports(dir, { markdown: '  \n' });
  assert.throws(() => verifyMorningScan({ status: 0 }, dir), /Markdown report is empty/);
  reports(dir);
  writeFileSync(join(dir, 'morning-scan-2026-09-05.json'), '{broken');
  assert.throws(() => verifyMorningScan({ status: 0 }, dir), SyntaxError);
  reports(dir, { results: [] });
  assert.throws(() => verifyMorningScan({ status: 0 }, dir), /coverage/);
  reports(dir);
  writeFileSync(join(dir, 'morning-scan-2026-09-05.json'), JSON.stringify({ results: [{}], errors: [], summary: { total: 2 } }));
  assert.throws(() => verifyMorningScan({ status: 0 }, dir), /coverage/);
  reports(dir);
  rmSync(join(dir, 'morning-scan-2026-09-05.md'));
  assert.throws(() => verifyMorningScan({ status: 0 }, dir), /ENOENT/);
});

test('runner uses a fresh directory and cannot reuse an older successful scan', (t) => {
  const dir = fixture(t);
  const old = join(dir, 'morning-run-old');
  mkdirSync(old);
  reports(old);
  assert.throws(() => runMorningScan([], {
    reportsDir: dir,
    run(_node, args, options) {
      const outputDir = args[args.indexOf('--output-dir') + 1];
      assert.notEqual(outputDir, old);
      assert.deepEqual(readdirSync(outputDir), []);
      assert.equal(options.shell, false);
      return { status: 1 };
    },
  }), /Expected one JSON report/);
});

test('runner verifies reports produced by its scanner invocation', (t) => {
  const dir = fixture(t);
  assert.deepEqual(runMorningScan(['--top', '1'], {
    reportsDir: dir,
    run(_node, args) {
      assert.deepEqual(args.slice(-2), ['--top', '1']);
      reports(args[args.indexOf('--output-dir') + 1]);
      return { status: 1 };
    },
  }), { total: 1, attempted: 1 });
});

test('real scanner empty portfolio writes reports but the runner rejects zero coverage offline', (t) => {
  const dir = fixture(t);
  const repos = join(dir, 'repos.json');
  writeFileSync(repos, '[]');
  assert.throws(() => runMorningScan(['--repos', repos], {
    reportsDir: dir,
    run(node, args) {
      const result = spawnSync(node, args, { encoding: 'utf8', timeout: 120_000 });
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /Report:/);
      return result;
    },
  }), /coverage/);
});

test('real scanner missing repo list exits 2 before contacting GitHub', (t) => {
  const dir = fixture(t);
  const result = spawnSync(process.execPath, [resolve('scripts/morning-scan.js'),
    '--repos', join(dir, 'missing.json'), '--output-dir', dir], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(result.status, 2, result.stderr);
  assert.throws(() => verifyMorningScan(result, dir), /Morning scan failed/);
});

test('real scan reads a GitHub snapshot, detects a finding, and persists verified reports offline', (t) => {
  const dir = fixture(t);
  const repos = join(dir, 'repos.json');
  const preload = join(dir, 'github-fixture.mjs');
  writeFileSync(repos, JSON.stringify(['example/app']));
  // Replace only the network boundary. The downloaded source stays inert data.
  writeFileSync(preload, `
    const base = 'https://api.github.com/repos/example/app';
    const sha = 'a'.repeat(40);
    globalThis.fetch = async (url) => {
      let data;
      if (url === base + '/commits/HEAD') data = { sha };
      else if (url === base + '/tarball/' + sha) {
        const { gzipSync } = await import('node:zlib');
        const entry = (name, body) => {
          const h = Buffer.alloc(512);
          h.write(name, 0); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
          h.write(body.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136);
          h.write('        ', 148); h.write('0', 156); h.write('ustar\0' + '00', 257);
          h.write(h.reduce((a, b) => a + b, 0).toString(8).padStart(6, '0') + '\0 ', 148);
          return Buffer.concat([h, body, Buffer.alloc((512 - (body.length % 512)) % 512)]);
        };
        const tar = Buffer.concat([entry('example-app-' + sha.slice(0, 7) + '/app.js', Buffer.from('eval(req.body.code);')), Buffer.alloc(1024)]);
        return new Response(gzipSync(tar), { status: 200 });
      } else throw new Error('Unexpected network request: ' + url);
      return new Response(JSON.stringify(data), { status: 200 });
    };
  `);
  let outputDir;
  const summary = runMorningScan(['--repos', repos], {
    reportsDir: dir,
    run(node, args) {
      outputDir = args[args.indexOf('--output-dir') + 1];
      const result = spawnSync(node, ['--import', pathToFileURL(preload).href, ...args], {
        encoding: 'utf8', timeout: 120_000,
      });
      assert.equal(result.status, 1, result.stderr);
      return result;
    },
  });
  assert.equal(summary.total, 1);
  assert.ok(summary.totalCriticals > 0);
  const jsonFile = readdirSync(outputDir).find((file) => file.endsWith('.json'));
  const report = JSON.parse(readFileSync(join(outputDir, jsonFile), 'utf8'));
  assert.equal(report.results[0].repo, 'example/app');
  assert.ok(report.results[0].findings.some((finding) => finding.ruleId === 'eval-usage'));
  assert.match(readFileSync(join(outputDir, jsonFile.replace(/\.json$/, '.md')), 'utf8'), /eval-usage/);
});
