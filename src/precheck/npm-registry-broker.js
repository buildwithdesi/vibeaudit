/** Short-lived metadata gate: npm never sees unsupported transitive sources. */
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { TextDecoder } from 'node:util';
import { readBounded } from './fresh-review.js';
import { validateManifest } from './npm-project.js';

const MAX_DOCUMENT = 20 * 1024 * 1024;
const MAX_CACHE = 100 * 1024 * 1024;
const MAX_LOOKUPS = 500;
const TIMEOUT = 20000;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const UNSUPPORTED = 'Registry metadata has an unsupported dependency source, workspace, or bundle. Every published candidate must be compatible; this pilot does not filter versions or select an older release.';

function validateTarball(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Registry artifact URL is invalid.'); }
  if (typeof value !== 'string' || !value.startsWith('https://registry.npmjs.org/') || url.href !== value ||
      url.hostname !== 'registry.npmjs.org' || url.protocol !== 'https:' || url.port || url.username || url.password ||
      url.search || url.hash || url.pathname === '/') throw new Error('Registry artifacts must use canonical public npm HTTPS URLs.');
}

function validatePackument(document, name) {
  if (!object(document) || document.name !== name || !object(document.versions) || !Object.keys(document.versions).length ||
      !object(document['dist-tags'])) throw new Error('Registry metadata is incomplete or invalid.');
  if (own(document, 'workspaces')) throw new Error(UNSUPPORTED);
  for (const [version, metadata] of Object.entries(document.versions)) {
    if (!object(metadata) || metadata.name !== name || metadata.version !== version || !object(metadata.dist)) {
      throw new Error('Registry candidate metadata is incomplete or invalid.');
    }
    const input = {};
    // Registry package devDependencies and overrides are not used to install
    // that package. Production, optional, and peer specs can cause fetches.
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'workspaces', 'bundledDependencies', 'bundleDependencies']) {
      if (own(metadata, field)) input[field] = metadata[field];
    }
    try { validateManifest(input); } catch { throw new Error(UNSUPPORTED); }
    validateTarball(metadata.dist.tarball);
  }
  for (const version of Object.values(document['dist-tags'])) {
    if (typeof version !== 'string' || !own(document.versions, version)) throw new Error('Registry distribution tags are incomplete or invalid.');
  }
}

/**
 * Bind an unguessable loopback URL for one resolution. Only package metadata
 * can pass; upstream credentials, caller URLs, and redirects are never used.
 * A failed optional lookup remains a failure even if npm omits that dependency.
 */
export async function startRegistryBroker({ fetchImpl = fetch } = {}) {
  const prefix = `/${randomBytes(32).toString('hex')}/`;
  const cache = new Map();
  const controllers = new Set();
  const sockets = new Set();
  let failure;
  let cacheBytes = 0;
  let closed = false;
  let closePromise;
  const fail = (reason) => { failure ||= reason; return reason; };

  async function lookup(name) {
    if (cache.has(name)) return cache.get(name);
    if (cache.size >= MAX_LOOKUPS) throw new Error('Registry resolution exceeds the 500 package lookup limit.');
    const pending = (async () => {
      const controller = new AbortController();
      controllers.add(controller);
      const timeout = setTimeout(() => controller.abort(), TIMEOUT);
      timeout.unref?.();
      try {
        let response;
        try {
          response = await fetchImpl(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
            headers: { Accept: 'application/vnd.npm.install-v1+json' }, redirect: 'error', signal: controller.signal,
          });
        } catch { throw new Error('Public npm registry lookup failed or timed out.'); }
        if (!response?.ok || !response.body) throw new Error('Public npm registry lookup was unavailable.');
        let bytes;
        try { bytes = await readBounded(response, MAX_DOCUMENT); }
        catch { throw new Error('Registry response was incomplete or exceeded the 20 MiB limit.'); }
        let document;
        try { document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
        catch { throw new Error('Registry metadata is not valid JSON.'); }
        validatePackument(document, name);
        const result = Buffer.from(JSON.stringify(document));
        if ((cacheBytes += result.length) > MAX_CACHE) throw new Error('Registry metadata exceeds the 100 MiB session limit.');
        return result;
      } finally {
        clearTimeout(timeout);
        controllers.delete(controller);
      }
    })();
    cache.set(name, pending);
    return pending;
  }

  const server = createServer(async (request, response) => {
    response.setHeader('Content-Type', 'application/json');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    let status = 502;
    let authorized = false;
    try {
      if (closed) throw new Error('Registry broker is closed.');
      if (typeof request.url !== 'string' || !request.url.startsWith(prefix)) {
        status = 404; throw new Error('Registry broker rejected an unauthorized metadata path.');
      }
      authorized = true;
      if (request.method !== 'GET') { status = 405; throw new Error('Registry broker supports metadata GET requests only.'); }
      if (request.url.length > 4096 || /[?#]/.test(request.url)) {
        status = 404; throw new Error('Registry broker rejected an unsupported metadata path.');
      }
      if (request.headers.authorization || request.headers['proxy-authorization']) {
        status = 403; throw new Error('Registry broker does not accept credentials.');
      }
      let name;
      try {
        name = decodeURIComponent(request.url.slice(prefix.length));
        if (/\.(?:tgz|tar\.gz|tar)$/i.test(name)) throw new Error('Archive path');
        validateManifest({ dependencies: { [name]: '*' } });
      } catch { status = 404; throw new Error('Registry broker accepts npm package names only.'); }
      const bytes = await lookup(name);
      if (closed) throw new Error('Registry broker closed during resolution.');
      response.writeHead(200, { 'Content-Length': bytes.length });
      response.end(bytes);
    } catch (error) {
      const reason = authorized ? fail(error.message) : error.message;
      if (!response.destroyed) {
        response.writeHead(status);
        response.end(JSON.stringify({ error: reason }));
      }
    }
  });
  server.headersTimeout = 10000;
  server.requestTimeout = TIMEOUT;
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.setTimeout(TIMEOUT + 1000, () => socket.destroy());
    socket.on('close', () => sockets.delete(socket));
  });
  server.on('clientError', (_error, socket) => {
    // Port probes and malformed unauthenticated traffic cannot invalidate a
    // session. Only requests with the capability can contribute review evidence.
    socket.destroy();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  server.on('error', () => fail('Registry broker could not serve a request.'));

  return {
    url: `http://127.0.0.1:${server.address().port}${prefix}`,
    assertHealthy() { if (failure) throw new Error(`Registry resolution was refused or incomplete: ${failure}`); },
    close() {
      if (closePromise) return closePromise;
      closed = true;
      if (controllers.size) fail('Registry broker closed before all metadata was verified.');
      for (const controller of controllers) controller.abort();
      closePromise = new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
        // Explicitly close idle keep-alive sockets on Node 18 as well as newer
        // versions, and bound shutdown when a request is still in flight.
        for (const socket of sockets) socket.destroy();
      });
      return closePromise;
    },
  };
}
