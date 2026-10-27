import assert from 'node:assert/strict';
import { Agent, request } from 'node:http';
import { connect } from 'node:net';
import { test } from 'node:test';
import { startRegistryBroker } from '../src/precheck/npm-registry-broker.js';

function packument(name = 'fixture', versions = {}) {
  return {
    name, 'dist-tags': { latest: '2.0.0' },
    versions: Object.fromEntries(['1.0.0', '2.0.0'].map((version) => [version, {
      name, version, dist: { tarball: `https://registry.npmjs.org/${name}/-/fixture-${version}.tgz` },
      ...versions[version],
    }])),
  };
}

function get(broker, { path = 'fixture', rawPath, method = 'GET', headers, agent } = {}) {
  const url = new URL(broker.url);
  return new Promise((resolve, reject) => {
    const req = request({ hostname: url.hostname, port: url.port, path: rawPath ?? `${url.pathname}${path}`, method, headers, agent }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
}

async function fixture(t, respond = (name) => packument(name)) {
  const calls = [];
  const broker = await startRegistryBroker({ fetchImpl: async (url, options) => {
    calls.push({ url, options });
    const name = decodeURIComponent(new URL(url).pathname.slice(1));
    const value = await respond(name, options);
    return value instanceof Response ? value : new Response(JSON.stringify(value));
  } });
  t.after(() => broker.close());
  return { broker, calls };
}

test('broker uses a random loopback capability and preserves registry artifacts and every safe version', async (t) => {
  const document = packument('fixture', { '1.0.0': { devDependencies: { local: 'file:../private-development-only' } },
    '2.0.0': { dependencies: { alpha: '^2.0.0' }, optionalDependencies: { renamed: 'npm:@scope/real@~1.0.0' }, peerDependencies: { peer: '>=1.0.0 <3' } } });
  const { broker, calls } = await fixture(t, () => document);
  assert.match(broker.url, /^http:\/\/127\.0\.0\.1:\d+\/[a-f0-9]{64}\/$/);
  const response = await get(broker);
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.body), document);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://registry.npmjs.org/fixture');
  assert.equal(calls[0].options.redirect, 'error');
  assert.deepEqual(Object.keys(calls[0].options.headers), ['Accept']);
  assert.ok(calls[0].options.signal instanceof AbortSignal);
  assert.doesNotThrow(() => broker.assertHealthy());
});

test('scoped names with an encoded slash use the fixed npm registry endpoint', async (t) => {
  const { broker, calls } = await fixture(t);
  const response = await get(broker, { path: '@scope%2ffixture' });
  assert.equal(response.status, 200);
  assert.equal(JSON.parse(response.body).name, '@scope/fixture');
  assert.equal(calls[0].url, 'https://registry.npmjs.org/%40scope%2Ffixture');
});

test('repeated and concurrent package lookups share one upstream response', async (t) => {
  const { broker, calls } = await fixture(t);
  const responses = await Promise.all(Array.from({ length: 8 }, () => get(broker)));
  assert.ok(responses.every((result) => result.status === 200));
  assert.equal((await get(broker)).status, 200);
  assert.equal(calls.length, 1);
});

for (const [field, source] of [
  ['dependencies', 'https://outside.invalid/DO_NOT_ECHO.tgz'], ['dependencies', 'http://127.0.0.1/private'],
  ['optionalDependencies', 'file:/private/DO_NOT_ECHO'], ['peerDependencies', 'git+https://outside.invalid/repo'],
  ['dependencies', 'github:private/repo'], ['optionalDependencies', 'npm:nested@file:../DO_NOT_ECHO'],
  ['dependencies', 'archive.tgz'],
]) {
  test(`refuses ${field} with an unsupported source before releasing any metadata`, async (t) => {
    const { broker, calls } = await fixture(t, () => packument('fixture', { '2.0.0': { [field]: { payload: source } } }));
    const result = await get(broker);
    assert.equal(result.status, 502);
    assert.match(result.body, /Every published candidate must be compatible/);
    assert.ok(!result.body.includes(source) && !result.body.includes('DO_NOT_ECHO'));
    assert.throws(() => broker.assertHealthy(), /refused or incomplete/);
    assert.deepEqual(calls.map(({ url }) => url), ['https://registry.npmjs.org/fixture'], 'no transitive URL is contacted');
  });
}

test('an unsafe old candidate is refused rather than filtered or replaced with another version', async (t) => {
  const { broker, calls } = await fixture(t, () => packument('fixture', { '1.0.0': { dependencies: { payload: 'file:../private' } } }));
  const result = await get(broker);
  assert.equal(result.status, 502);
  assert.match(result.body, /does not filter versions or select an older release/);
  assert.ok(!result.body.includes('"versions"'));
  assert.equal(calls.length, 1);
});

for (const extra of [{ workspaces: [] }, { bundleDependencies: ['nested'] }, { bundledDependencies: [] }]) {
  test('refuses unsupported workspace or bundled candidate metadata', async (t) => {
    const { broker } = await fixture(t, () => packument('fixture', { '2.0.0': extra }));
    assert.equal((await get(broker)).status, 502);
    assert.throws(() => broker.assertHealthy(), /unsupported/);
  });
}

for (const tarball of ['http://registry.npmjs.org/package.tgz', 'https://outside.invalid/private.tgz',
  'https://credential:DO_NOT_ECHO@registry.npmjs.org/package.tgz', 'https://registry.npmjs.org:443/package.tgz',
  'https://registry.npmjs.org/package.tgz?token=DO_NOT_ECHO', 'https://registry.npmjs.org/package.tgz#private',
  'https://registry.npmjs.org/a/../package.tgz']) {
  test('rejects noncanonical or non-registry artifact URLs without fetching artifacts', async (t) => {
    const { broker, calls } = await fixture(t, () => packument('fixture', { '2.0.0': { dist: { tarball } } }));
    const result = await get(broker);
    assert.equal(result.status, 502);
    assert.ok(!result.body.includes(tarball) && !result.body.includes('DO_NOT_ECHO'));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://registry.npmjs.org/fixture');
  });
}

for (const options of [{ rawPath: '/fixture' }, { rawPath: '/wrong-capability/fixture' },
  { path: 'fixture?token=DO_NOT_ECHO' }, { path: '-/npm/v1/security/audits' }, { path: 'fixture/-/fixture.tgz' },
  { path: 'fixture.tgz' }, { path: 'https%3A%2F%2Foutside.invalid%2Fprivate' }, { path: '%2e%2e%2fprivate' },
  { path: 'fixture%00' }, { path: '%ZZ' }, { path: '' }, { method: 'POST' }, { method: 'DELETE' }, { method: 'HEAD' },
  { headers: { Authorization: 'Bearer DO_NOT_ECHO' } }, { headers: { 'Proxy-Authorization': 'DO_NOT_ECHO' } }]) {
  test(`rejects unauthorized methods, paths, or credentials ${JSON.stringify(options)}`, async (t) => {
    const { broker, calls } = await fixture(t);
    const result = await get(broker, options);
    assert.ok(result.status >= 400);
    assert.equal(calls.length, 0);
    assert.ok(!result.body.includes('DO_NOT_ECHO'));
    if (options.rawPath) assert.doesNotThrow(() => broker.assertHealthy());
    else assert.throws(() => broker.assertHealthy(), /refused or incomplete/);
  });
}

test('unauthenticated and malformed port probes cannot poison a legitimate review', async (t) => {
  const { broker, calls } = await fixture(t);
  const url = new URL(broker.url);
  await new Promise((resolve, reject) => {
    const socket = connect({ host: url.hostname, port: Number(url.port) }, () => socket.end('INVALID HTTP PROBE\r\n\r\n'));
    socket.on('close', resolve);
    socket.on('error', (error) => error.code === 'ECONNRESET' ? resolve() : reject(error));
  });
  assert.equal((await get(broker, { rawPath: '/outside', method: 'POST', headers: { Authorization: 'DO_NOT_ECHO' } })).status, 404);
  assert.equal(calls.length, 0);
  assert.doesNotThrow(() => broker.assertHealthy());
  assert.equal((await get(broker)).status, 200);
  assert.equal(calls.length, 1);
  assert.doesNotThrow(() => broker.assertHealthy());
});

for (const document of [null, [], {}, { name: 'fixture', versions: [], 'dist-tags': {} },
  { name: 'fixture', versions: {}, 'dist-tags': {} }, { ...packument(), name: 'wrong-name' },
  { ...packument(), 'dist-tags': { latest: 'file:../DO_NOT_ECHO' } },
  packument('fixture', { '2.0.0': { name: 'wrong-name' } }), packument('fixture', { '2.0.0': { dist: null } })]) {
  test('invalid registry documents fail closed', async (t) => {
    const { broker } = await fixture(t, () => document);
    const result = await get(broker);
    assert.equal(result.status, 502);
    assert.ok(!result.body.includes('DO_NOT_ECHO'));
    assert.throws(() => broker.assertHealthy(), /refused or incomplete/);
  });
}

test('upstream transport, HTTP, malformed JSON, and UTF-8 failures are redacted and retained', async (t) => {
  for (const respond of [() => { throw new Error('https://credential:DO_NOT_ECHO@private.invalid'); },
    () => new Response('DO_NOT_ECHO', { status: 503 }), () => new Response('{DO_NOT_ECHO'),
    () => new Response(Buffer.from([0xff, 0xfe]))]) {
    const { broker, calls } = await fixture(t, respond);
    const first = await get(broker);
    assert.equal(first.status, 502);
    assert.ok(!first.body.includes('DO_NOT_ECHO'));
    assert.throws(() => broker.assertHealthy());
    assert.equal((await get(broker)).status, 502);
    assert.equal(calls.length, 1, 'a refused package is not retried invisibly');
  }
});

test('responses beyond the per-document limit cannot be released as metadata', async (t) => {
  const { broker } = await fixture(t, () => new Response(Buffer.alloc(20 * 1024 * 1024 + 1, 32)));
  const result = await get(broker);
  assert.equal(result.status, 502);
  assert.match(result.body, /20 MiB limit/);
  assert.throws(() => broker.assertHealthy(), /20 MiB limit/);
});

test('the 501st distinct package lookup is refused before contacting the registry', async (t) => {
  const { broker, calls } = await fixture(t);
  for (let offset = 0; offset < 500; offset += 25) {
    const results = await Promise.all(Array.from({ length: 25 }, (_, index) => get(broker, { path: `package-${offset + index}` })));
    assert.ok(results.every((value) => value.status === 200));
  }
  const extra = await get(broker, { path: 'package-500' });
  assert.equal(extra.status, 502);
  assert.match(extra.body, /500 package lookup limit/);
  assert.equal(calls.length, 500);
  assert.throws(() => broker.assertHealthy());
});

test('a failed optional lookup cannot be hidden by later successful requests', async (t) => {
  const { broker } = await fixture(t, (name) => name === 'optional' ? new Response('', { status: 404 }) : packument(name));
  assert.equal((await get(broker, { path: 'optional' })).status, 502);
  assert.equal((await get(broker)).status, 200);
  assert.throws(() => broker.assertHealthy(), /unavailable/);
});

test('close aborts pending upstream requests and does not hang on keep-alive sockets', async (t) => {
  let started;
  const ready = new Promise((resolve) => { started = resolve; });
  let aborted = false;
  const { broker } = await fixture(t, async (name, options) => {
    if (name !== 'pending') return packument(name);
    started();
    await new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => { aborted = true; reject(new Error('aborted')); }, { once: true }));
  });
  const agent = new Agent({ keepAlive: true });
  t.after(() => agent.destroy());
  assert.equal((await get(broker, { agent })).status, 200);
  const pending = get(broker, { path: 'pending' }).catch(() => null);
  await ready;
  await broker.close();
  await broker.close();
  await pending;
  assert.equal(aborted, true);
  assert.throws(() => broker.assertHealthy(), /closed before all metadata/);
  await assert.rejects(get(broker));
});
