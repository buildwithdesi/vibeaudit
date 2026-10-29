/** Strict project inputs for the public-registry npm installation pilot. */
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const MANIFEST_LIMIT = 2 * 1024 * 1024;
const LOCK_LIMIT = 10 * 1024 * 1024;
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i;
const PACKAGE_LOCATION = /^(?:node_modules\/(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*)(?:\/node_modules\/(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*)*$/i;
const DEPENDENCY_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

function exactVersion(version) {
  if (typeof version !== 'string' || version.length > 256) return false;
  const [release, build, extra] = version.split('+');
  const identifiers = (text) => text.split('.').every((part) => /^[0-9A-Za-z-]+$/.test(part));
  if (extra !== undefined || (build !== undefined && !identifiers(build))) return false;
  const dash = release.indexOf('-');
  const core = (dash < 0 ? release : release.slice(0, dash)).split('.');
  if (core.length !== 3 || !core.every((part) => /^(?:0|[1-9][0-9]*)$/.test(part) && Number.isSafeInteger(Number(part)))) return false;
  if (dash < 0) return true;
  const prerelease = release.slice(dash + 1);
  return identifiers(prerelease) && prerelease.split('.').every((part) => !/^[0-9]+$/.test(part) || part === '0' || !part.startsWith('0'));
}

function requireRecord(value, label) {
  if (!record(value)) throw new Error(`${label} must be an object.`);
}

function validateName(name) {
  if (typeof name !== 'string' || name.length > 214 || !PACKAGE_NAME.test(name)) {
    throw new Error('Unsupported npm package name; only registry package names are supported.');
  }
  // These filesystem names are ambiguous on Windows, even with an extension.
  if (name.split('/').some((part) => part.endsWith('.') || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) {
    throw new Error('Unsupported npm package name on Windows.');
  }
}

function validateRegistrySpec(spec) {
  if (typeof spec !== 'string' || !spec.trim() || spec.length > 2048) {
    throw new Error('Dependency specs must be nonempty public npm registry versions, ranges, or tags.');
  }
  if (spec.startsWith('npm:')) {
    const alias = spec.slice(4).match(/^((?:@[^/]+\/)?[^@]+)(?:@(.+))?$/);
    if (!alias) throw new Error('Invalid npm registry alias.');
    validateName(alias[1]);
    if (alias[2]) validateRegistryRange(alias[2]);
    return;
  }
  validateRegistryRange(spec);
}

function validateRegistryRange(spec) {
  // Deliberately exclude URL/path/protocol syntax before invoking npm. npm itself
  // subsequently validates range/tag semantics; no rejected spec reaches it.
  if (!/^[a-zA-Z0-9*~^<>=|.+ -]+$/.test(spec) || !/[a-zA-Z0-9*]/.test(spec) ||
      /^[-.]/.test(spec.trim()) || /\.(?:tgz|tar\.gz|tar)$/i.test(spec.trim())) {
    throw new Error('Unsupported dependency source; this pilot supports public npm registry specs only.');
  }
}

function validateDependencyFields(metadata) {
  for (const field of DEPENDENCY_FIELDS) {
    if (!own(metadata, field)) continue;
    requireRecord(metadata[field], field);
    for (const [name, spec] of Object.entries(metadata[field])) {
      validateName(name);
      validateRegistrySpec(spec);
    }
  }
}

function validateOverrides(overrides, references, depth = 0) {
  requireRecord(overrides, 'overrides');
  if (depth > 32) throw new Error('npm overrides exceed the supported nesting depth.');
  for (const [selector, value] of Object.entries(overrides)) {
    if (selector !== '.') {
      const match = selector.match(/^((?:@[^/]+\/)?[^@]+)(?:@(.+))?$/);
      if (!match) throw new Error('Unsupported npm override selector.');
      validateName(match[1]);
      if (match[2]) validateRegistryRange(match[2]);
    } else if (depth === 0) {
      throw new Error('A root npm override cannot use the dot selector.');
    }
    if (typeof value === 'string') {
      if (value.startsWith('$')) {
        const name = value.slice(1);
        validateName(name);
        if (!references.has(name)) throw new Error('npm override references a missing direct dependency.');
      } else validateRegistrySpec(value);
    } else {
      if (selector === '.') throw new Error('The npm override dot selector must contain a registry spec.');
      validateOverrides(value, references, depth + 1);
    }
  }
}

/** Validate fields that can send npm to another source or introduce workspace links. */
export function validateManifest(manifest) {
  requireRecord(manifest, 'package.json');
  if (own(manifest, 'workspaces')) throw new Error('npm workspaces are not supported by this protection pilot.');
  if (own(manifest, 'bundledDependencies') || own(manifest, 'bundleDependencies')) {
    throw new Error('Bundled npm dependencies are not supported by this protection pilot.');
  }
  validateDependencyFields(manifest);
  if (own(manifest, 'overrides')) {
    const references = new Set(DEPENDENCY_FIELDS.flatMap((field) => Object.keys(manifest[field] ?? {})));
    validateOverrides(manifest.overrides, references);
  }
}

function validateIntegrity(integrity) {
  const match = typeof integrity === 'string' && integrity.match(/^sha512-([A-Za-z0-9+/]{86}==)$/);
  if (!match || Buffer.from(match[1], 'base64').toString('base64') !== match[1]) {
    throw new Error('Every locked package must have one canonical SHA512 integrity digest.');
  }
}

function validateResolved(resolved) {
  let url;
  try { url = new URL(resolved); } catch { throw new Error('Locked package artifact URL is invalid.'); }
  if (typeof resolved !== 'string' || !resolved.startsWith('https://registry.npmjs.org/') ||
      url.href !== resolved || url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' ||
      url.username || url.password || url.port || url.search || url.hash || url.pathname === '/') {
    throw new Error('Locked package artifacts must use canonical public npm registry HTTPS URLs without credentials, ports, queries, or fragments.');
  }
}

function validateLegacyDependencies(dependencies, depth = 0) {
  requireRecord(dependencies, 'Legacy lock dependencies');
  if (depth > 64) throw new Error('Legacy lock dependencies exceed the supported nesting depth.');
  for (const [name, metadata] of Object.entries(dependencies)) {
    validateName(name);
    requireRecord(metadata, 'Legacy locked package');
    if (metadata.link || metadata.inBundle || metadata.bundled) throw new Error('Linked or bundled locked packages are not supported.');
    validateRegistrySpec(metadata.version);
    if (own(metadata, 'resolved')) validateResolved(metadata.resolved);
    if (own(metadata, 'integrity')) validateIntegrity(metadata.integrity);
    if (own(metadata, 'requires')) validateDependencyFields({ dependencies: metadata.requires });
    if (own(metadata, 'dependencies')) validateLegacyDependencies(metadata.dependencies, depth + 1);
  }
}

/** Return every installation location, preserving an alias's actual registry identity. */
export function validateLock(lock, { allowEmpty = false } = {}) {
  requireRecord(lock, 'package-lock.json');
  if (![2, 3].includes(lock.lockfileVersion)) throw new Error('This pilot requires npm package-lock format 2 or 3.');
  requireRecord(lock.packages, 'Locked packages');
  if (!own(lock.packages, '')) throw new Error('The package lock must contain root project metadata.');
  validateManifest(lock.packages['']);
  if (own(lock, 'dependencies')) validateLegacyDependencies(lock.dependencies);
  const locations = new Map();
  const packages = [];
  for (const [location, metadata] of Object.entries(lock.packages)) {
    if (location === '') continue;
    if (!PACKAGE_LOCATION.test(location)) {
      throw new Error('The package lock contains a noncanonical or colliding node_modules location.');
    }
    const prefixes = location.split('/node_modules/');
    for (let index = 1; index <= prefixes.length; index++) {
      const prefix = prefixes.slice(0, index).join('/node_modules/');
      const previous = locations.get(prefix.toLowerCase());
      if (previous && previous !== prefix) throw new Error('The package lock contains a colliding node_modules location.');
      locations.set(prefix.toLowerCase(), prefix);
    }
    // Validate every nested path component, including aliases and parent packages.
    for (const name of location.split(/(?:^|\/)node_modules\//).filter(Boolean)) validateName(name.replace(/\/$/, ''));
    requireRecord(metadata, 'Locked package');
    if (metadata.link || metadata.inBundle) throw new Error('Linked or bundled locked packages are not supported.');
    validateManifest(metadata);
    const name = own(metadata, 'name') ? metadata.name : location.slice(location.lastIndexOf('node_modules/') + 'node_modules/'.length);
    validateName(name);
    if (!exactVersion(metadata.version)) {
      throw new Error('Every locked package must have an exact semantic version.');
    }
    validateIntegrity(metadata.integrity);
    validateResolved(metadata.resolved);
    packages.push({ name, version: metadata.version, integrity: metadata.integrity, resolved: metadata.resolved, location });
  }
  if (!allowEmpty && packages.length === 0) throw new Error('npm resolved no packages; the installation review is incomplete.');
  return packages;
}

function statIfPresent(path) {
  try { return lstatSync(path); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function readRegularFile(path, label, limit, required = false) {
  const before = statIfPresent(path);
  if (!before) {
    if (required) throw new Error(`${label} is required for the protected npm installation.`);
    return null;
  }
  const check = (stat) => {
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error(`${label} must be a regular file with no symlink or hard links.`);
    if (stat.size > limit) throw new Error(`${label} exceeds the supported size limit.`);
  };
  check(before);
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(descriptor);
    check(opened);
    if (!sameFile(before, opened)) throw new Error('Project changed while reading inputs; review again.');
    const buffer = Buffer.alloc(Math.min(opened.size + 1, limit + 1));
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(descriptor, buffer, length, buffer.length - length, null);
      if (count === 0) break;
      length += count;
    }
    const bytes = buffer.subarray(0, length);
    const after = fstatSync(descriptor);
    const current = statIfPresent(path);
    if (!current || current.isSymbolicLink() || !sameFile(opened, after) || !sameFile(after, current)) {
      throw new Error('Project changed while reading inputs; review again.');
    }
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes)) throw new Error(`${label} must contain valid UTF-8 text.`);
    return text;
  } finally { closeSync(descriptor); }
}

function parseJson(text, label) {
  try { return JSON.parse(text.replace(/^\uFEFF/, '')); } catch { throw new Error(`${label} contains invalid JSON.`); }
}

/** Snapshot only the supported npm inputs; never expose project npmrc values. */
export function readProject(projectPath) {
  if (typeof projectPath !== 'string' || !projectPath.trim()) throw new Error('An npm project directory is required.');
  const absolute = resolve(projectPath);
  const directories = [];
  for (let current = absolute;; current = dirname(current)) {
    directories.push(current);
    if (dirname(current) === current) break;
  }
  for (const directory of [...directories].reverse()) {
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('The npm project and its ancestors must be real directories without symlinks or junctions.');
  }
  const project = realpathSync(absolute);
  for (const ancestor of directories.slice(1)) {
    const text = readRegularFile(join(ancestor, 'package.json'), 'Ancestor package.json', MANIFEST_LIMIT);
    if (text !== null) {
      const manifest = parseJson(text, 'Ancestor package.json');
      if (record(manifest) && own(manifest, 'workspaces')) throw new Error('This project belongs to an unsupported npm workspace.');
    }
  }
  if (statIfPresent(join(project, 'npm-shrinkwrap.json'))) throw new Error('npm-shrinkwrap.json is not supported by this protection pilot.');
  const files = {
    'package.json': readRegularFile(join(project, 'package.json'), 'package.json', MANIFEST_LIMIT, true),
    'package-lock.json': readRegularFile(join(project, 'package-lock.json'), 'package-lock.json', LOCK_LIMIT),
    '.npmrc': readRegularFile(join(project, '.npmrc'), 'Project .npmrc', MANIFEST_LIMIT),
    'npm-shrinkwrap.json': null,
  };
  if (files['.npmrc']?.split(/[\r\n]+/).some((line) => line.trim() && !/^[;#]/.test(line.trim()))) {
    throw new Error('Project .npmrc configuration is not supported by this public-registry pilot. Remove or review that configuration separately.');
  }
  validateManifest(parseJson(files['package.json'], 'package.json'));
  if (files['package-lock.json'] !== null) validateLock(parseJson(files['package-lock.json'], 'package-lock.json'), { allowEmpty: true });
  return { project, files, fingerprint: createHash('sha256').update(JSON.stringify(files)).digest('hex') };
}

export function assertProjectUnchanged(snapshot) {
  let current;
  try { current = readProject(snapshot.project); } catch { throw new Error('Project changed since approval; review again.'); }
  if (current.project !== snapshot.project || current.fingerprint !== snapshot.fingerprint) {
    throw new Error('Project changed since approval; review again.');
  }
}
