import { createHash, timingSafeEqual, createPublicKey, verify } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

const MAX_DOWNLOAD = 20 * 1024 * 1024;
const MAX_EXPANDED = 64 * 1024 * 1024;

export async function readBounded(response, limit) {
  if (!response.ok || !response.body) throw new Error('review download unavailable');
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > limit) throw new Error('review size limit exceeded');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/** Read regular files in memory. Never extract or execute package contents. */
export function inspectArchive(archive, pkg) {
  const tar = gunzipSync(archive, { maxOutputLength: MAX_EXPANDED });
  const findings = [];
  let manifest;
  let files = 0;
  let ended = false;
  let root;
  const paths = new Set();
  const pathSpellings = new Map();
  const directories = new Set();
  const regularFiles = new Set();
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (offset + 1024 > tar.length || !tar.subarray(offset).every((byte) => byte === 0)) throw new Error('invalid archive termination or trailing entries');
      ended = true;
      break;
    }
    const field = (start, length) => header.subarray(start, start + length).toString('utf8').replace(/\0.*$/s, '');
    const sizeText = field(124, 12).trim();
    if (!/^[0-7]+$/.test(sizeText)) throw new Error('unsupported archive size');
    const size = Number.parseInt(sizeText, 8);
    const checksum = Number.parseInt(field(148, 8).trim(), 8);
    const actual = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    if (checksum !== actual) throw new Error('invalid archive checksum');
    const type = field(156, 1);
    if (!['', '0', '5'].includes(type)) throw new Error('unsupported archive entry type');
    const rawName = [field(345, 155), field(0, 100)].filter(Boolean).join('/');
    if (rawName.includes('//') || /[\\<>:"|?*\x00-\x1f\x7f]/.test(rawName)) throw new Error('unsafe archive path');
    const parts = (type === '5' ? rawName.replace(/\/$/, '') : rawName).split('/');
    if (parts.some((part) => !part || part === '.' || part === '..' || /[. ]$/.test(part) || /^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:[ .]|$)/i.test(part))) throw new Error('unsafe archive path');
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(parts[0]) || (parts.length === 1 && type !== '5')) throw new Error('unsafe archive root');
    if (parts.some((part) => part.toLowerCase() === 'node_modules')) throw new Error('bundled node_modules are not supported in reviewed archives');
    if (root !== undefined && parts[0] !== root) throw new Error('mixed archive roots');
    root = parts[0];
    // npm strips one top-level component. Normalize that component for checks,
    // while requiring every entry to share the same unambiguous directory.
    parts[0] = 'package';
    const name = parts.join('/');
    for (let index = 1; index <= parts.length; index++) {
      const prefix = parts.slice(0, index).join('/');
      const previous = pathSpellings.get(prefix.toLowerCase());
      if (previous !== undefined && previous !== prefix) throw new Error('case-colliding archive paths');
      pathSpellings.set(prefix.toLowerCase(), prefix);
      if (index < parts.length) {
        if (regularFiles.has(prefix)) throw new Error('file and directory archive path collision');
        directories.add(prefix);
      }
    }
    if (paths.has(name)) throw new Error('duplicate or ambiguous archive path');
    if (type !== '5' && directories.has(name)) throw new Error('file and directory archive path collision');
    paths.add(name);
    (type === '5' ? directories : regularFiles).add(name);
    const end = offset + 512 + size;
    if (end > tar.length) throw new Error('truncated archive');
    if (++files > 10000) throw new Error('archive file limit exceeded');
    if (type !== '5') {
      const content = tar.subarray(offset + 512, end).toString('utf8');
      if (name === 'package/package.json') {
        if (manifest) throw new Error('duplicate package manifest');
        manifest = JSON.parse(content);
      }
      if (/\.(?:[cm]?js|json|sh|ps1|cmd|bat)$/i.test(name)) {
        if (/\b(?:curl|wget)\b[^\n]{0,300}\|\s*(?:sh|bash)|Invoke-Expression|\bIEX\s*\(/i.test(content)) findings.push(`download-and-execute pattern in ${name}`);
        if (/eval\s*\(\s*(?:atob|Buffer\.from)|child_process[^\n]{0,200}base64/i.test(content)) findings.push(`encoded execution pattern in ${name}`);
      }
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  if (!ended || !manifest || manifest.name !== pkg.name || manifest.version !== pkg.version) throw new Error('archive manifest or termination mismatch');
  if (Object.hasOwn(manifest, 'bundledDependencies') || Object.hasOwn(manifest, 'bundleDependencies')) throw new Error('bundled dependencies are not supported in reviewed archives');
  const installScripts = ['preinstall', 'install', 'postinstall'].filter((name) => manifest.scripts?.[name]);
  if (paths.has('package/binding.gyp') && !manifest.scripts?.install && !manifest.scripts?.preinstall) {
    findings.push('binding.gyp triggers implicit native installation (node-gyp rebuild)');
  }
  return { files, findings, installScripts, lifecycleCommands: Object.fromEntries(installScripts.map((name) => [name, manifest.scripts[name]])) };
}

/**
 * Evidence only: a clean static review cannot establish that a package is safe.
 * The callback receives authenticated archive bytes after all service responses
 * and archive structure have been checked. Findings can still block the package;
 * authenticated bytes are not permission to install or execute them.
 * Archive bytes are never included in the returned report.
 *
 * @param {{name: string, version: string}} pkg
 * @param {object} metadata
 * @param {typeof fetch} [fetchImpl]
 * @param {{publishedAt?: string, onVerifiedArchive?: (artifact: {name: string, version: string, integrity: string, archive: Buffer}) => unknown}} [options]
 */
export async function reviewRegistryPackage(pkg, metadata, fetchImpl = fetch, options = {}) {
  try {
    const url = new URL(metadata?.dist?.tarball);
    if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.username || url.password || url.port) throw new Error('untrusted archive URL');
    const integrity = metadata?.dist?.integrity;
    if (typeof integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(integrity)) throw new Error('SHA-512 integrity is required');
    const response = await fetchImpl(url.href, { redirect: 'error', signal: AbortSignal.timeout(20000) });
    const archive = await readBounded(response, MAX_DOWNLOAD);
    const digest = createHash('sha512').update(archive).digest();
    const expected = Buffer.from(integrity.slice(7), 'base64');
    if (expected.length !== digest.length || !timingSafeEqual(expected, digest)) throw new Error('archive integrity mismatch');
    const signatures = metadata.dist.signatures;
    if (!Array.isArray(signatures) || !signatures.length) throw new Error('registry signature is missing');
    const keysResponse = await fetchImpl('https://registry.npmjs.org/-/npm/v1/keys', { redirect: 'error', signal: AbortSignal.timeout(15000) });
    const keyDocument = JSON.parse((await readBounded(keysResponse, 256 * 1024)).toString('utf8'));
    if (!Array.isArray(keyDocument.keys)) throw new Error('registry signing keys unavailable');
    const signedMessage = Buffer.from(`${pkg.name}@${pkg.version}:${integrity}`);
    const signatureVerified = signatures.some((signature) => {
      const key = keyDocument.keys.find((candidate) => candidate.keyid === signature.keyid);
      if (!key || typeof key.key !== 'string' || typeof signature.sig !== 'string') return false;
      if (key.expires !== null && key.expires !== undefined) {
        const expiry = typeof key.expires === 'string' ? Date.parse(key.expires) : NaN;
        const published = typeof options.publishedAt === 'string' ? Date.parse(options.publishedAt) : NaN;
        // Match npm/pacote's publication-time key validity check. An expired
        // key can authenticate an older release; missing time is never guessed.
        if (!Number.isFinite(expiry) || !Number.isFinite(published) || published >= expiry) return false;
      }
      try {
        return verify('sha256', signedMessage, createPublicKey({ key: Buffer.from(key.key, 'base64'), format: 'der', type: 'spki' }), Buffer.from(signature.sig, 'base64'));
      } catch { return false; }
    });
    if (!signatureVerified) throw new Error('registry signature verification failed');
    const inspection = inspectArchive(archive, pkg);
    for (const hook of ['preinstall', 'install', 'postinstall']) {
      if ((inspection.lifecycleCommands[hook] || null) !== (metadata.scripts?.[hook] || null)) inspection.findings.push(`archive and registry disagree on ${hook}`);
    }
    const osvResponse = await fetchImpl('https://api.osv.dev/v1/query', {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version }),
    });
    const osv = JSON.parse((await readBounded(osvResponse, 2 * 1024 * 1024)).toString('utf8'));
    if (!osv || typeof osv !== 'object' || Array.isArray(osv) || (osv.vulns !== undefined && !Array.isArray(osv.vulns)) || osv.error) throw new Error('invalid vulnerability response');
    const advisories = (osv.vulns || []).map((entry) => {
      if (typeof entry.id !== 'string') throw new Error('invalid vulnerability record');
      return entry.id;
    });
    if (options.onVerifiedArchive !== undefined) {
      try {
        await options.onVerifiedArchive({ name: pkg.name, version: pkg.version, integrity, archive });
      } catch (error) {
        throw new Error(`verified archive callback failed: ${error?.message || 'archive could not be retained'}`);
      }
    }
    return { status: inspection.findings.length || advisories.length ? 'flagged' : 'reviewed', integrity, signatureVerified, ...inspection, advisories };
  } catch (error) {
    return { status: 'incomplete', reason: error.message };
  }
}

// Preserve the existing public name for callers that review only fresh releases.
export const reviewFreshPackage = reviewRegistryPackage;
