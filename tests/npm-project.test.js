import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { assertProjectUnchanged, readProject, validateLock, validateManifest } from '../src/precheck/npm-project.js';

const integrity = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;
const artifact = (name = 'alpha', extra = {}) => ({
  version: '1.2.3',
  resolved: `https://registry.npmjs.org/${name}/-/package-1.2.3.tgz`,
  integrity,
  ...extra,
});
const lock = (packages = { 'node_modules/alpha': artifact() }, extra = {}) => ({
  lockfileVersion: 3,
  packages: { '': { name: 'pilot', dependencies: { alpha: '^1.2.0' } }, ...packages },
  ...extra,
});

function fixture(t, manifest = { name: 'pilot' }) {
  const directory = mkdtempSync(join(tmpdir(), 'vibeguard-project-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const project = join(directory, 'project');
  mkdirSync(project);
  writeFileSync(join(project, 'package.json'), JSON.stringify(manifest));
  return { directory, project };
}

function makeSymlink(t, target, path, type = 'file') {
  try { symlinkSync(target, path, type); return true; } catch (error) {
    if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) { t.skip('Creating symlinks is unavailable on this platform.'); return false; }
    throw error;
  }
}

describe('protected npm manifest sources', () => {
  it('supports public versions, ranges, tags, aliases, and nested override references', () => {
    assert.doesNotThrow(() => validateManifest({
      private: true,
      dependencies: { alpha: '^1.0.0', renamed: 'npm:@scope/original@~2.1.0' },
      devDependencies: { beta: 'latest' },
      optionalDependencies: { gamma: '>=1.0.0 <2.0.0 || ^3.0.0' },
      peerDependencies: { delta: '1.0.0 - 2.0.0' },
      overrides: { alpha: '$alpha', '@scope/original@^2.0.0': { '.': '2.1.0', beta: 'npm:replacement@3.0.0' } },
    }));
  });

  for (const source of ['file:../secret', 'link:../secret', 'workspace:*', 'git+https://github.com/a/b', 'github:a/b', 'a/b',
    'https://example.com/archive.tgz', 'http://registry.npmjs.org/pkg', '../other', '/tmp/project', 'C:\\project', '\\\\server\\share',
    'npm:pkg@file:../other', 'npm:pkg@git+ssh://host/project', 'archive.tgz', 'archive.tar.gz', 'archive.tar',
    'npm:pkg@archive.tgz', '1.0.0\n', '', null, {}, ['1.0.0']]) {
    it(`rejects unsupported dependency source ${JSON.stringify(source)}`, () => {
      for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        assert.throws(() => validateManifest({ [field]: { alpha: source } }));
      }
      assert.throws(() => validateManifest({ overrides: { alpha: { beta: { '.': source } } } }));
    });
  }

  it('rejects workspace, bundled, and malformed dependency declarations', () => {
    for (const manifest of [null, [], { workspaces: [] }, { workspaces: {} }, { bundledDependencies: [] }, { bundleDependencies: false },
      { dependencies: [] }, { dependencies: null }, { dependencies: { '../bad': '1.0.0' } },
      { overrides: { 'alpha@file:../bad': '1.0.0' } }, { overrides: { alpha: '$missing' } },
      { overrides: { '.': '1.0.0' } }, { overrides: { alpha: { '.': {} } } }]) {
      assert.throws(() => validateManifest(manifest));
    }
  });
});

describe('protected npm locked installation tree', () => {
  it('bounds untrusted version strings and rejects unsafe numeric components', () => {
    for (const version of [`1.2.3-${'a.'.repeat(10000)}`, '9007199254740992.0.0', '1.2.3+build+extra', '1.2.3-01']) {
      assert.throws(() => validateLock(lock({ 'node_modules/alpha': artifact('alpha', { version }) })), /exact semantic version/);
    }
  });
  it('returns every location and preserves alias identities, scoped packages, and exact prereleases', () => {
    const source = lock({
      'node_modules/alpha': artifact(),
      'node_modules/renamed': artifact('@scope/original', { name: '@scope/original' }),
      'node_modules/alpha/node_modules/@scope/nested': artifact('@scope/nested', { version: '2.0.0-rc.1+build.123' }),
      'node_modules/alpha/node_modules/alpha': artifact(),
    });
    const result = validateLock(source);
    assert.equal(result.length, 4, 'identical versions at distinct locations must not disappear');
    assert.deepEqual(result[1], {
      name: '@scope/original', version: '1.2.3', integrity,
      resolved: source.packages['node_modules/renamed'].resolved, location: 'node_modules/renamed',
    });
    assert.equal(result[2].name, '@scope/nested');
    assert.equal(result[2].version, '2.0.0-rc.1+build.123');
  });

  it('accepts the repository lock as a representative complete public npm tree', () => {
    const source = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
    assert.equal(validateLock(source).length, Object.keys(source.packages).length - 1);
  });

  it('supports v2 with registry-only legacy metadata', () => {
    assert.equal(validateLock(lock(undefined, { lockfileVersion: 2, dependencies: {
      alpha: { ...artifact(), requires: { beta: '^2.0.0' }, dependencies: { beta: artifact('beta') } },
    } })).length, 1);
  });

  it('accepts a root-only input lock only when explicitly allowed', () => {
    assert.deepEqual(validateLock(lock({}), { allowEmpty: true }), []);
    assert.throws(() => validateLock(lock({})), /incomplete/);
    for (const source of [null, [], {}, { lockfileVersion: 1, packages: {} }, { lockfileVersion: '3', packages: {} },
      { lockfileVersion: 3, packages: [] }, { lockfileVersion: 3, packages: { 'node_modules/alpha': artifact() } }]) {
      assert.throws(() => validateLock(source, { allowEmpty: true }));
    }
  });

  for (const location of ['../node_modules/alpha', 'node_modules/../alpha', 'node_modules/alpha/../../outside',
    'node_modules/alpha/extra', 'node_modules/alpha//node_modules/beta', 'node_modules\\alpha', 'node_modules/alpha/',
    '/node_modules/alpha', 'node_modules/alpha\u0000', 'node_modules/alpha\n', 'node_modules/@scope', 'node_modules/@scope/../alpha',
    'node_modules/alpha.', 'node_modules/con', 'node_modules/nul.json', 'node_modules/@scope./alpha']) {
    it(`rejects noncanonical package location ${JSON.stringify(location)}`, () => {
      assert.throws(() => validateLock(lock({ [location]: artifact() })));
    });
  }

  it('rejects case collisions including inconsistent casing of nested parent paths', () => {
    assert.throws(() => validateLock(lock({ 'node_modules/Alpha': artifact(), 'node_modules/alpha': artifact() })), /colliding/);
    assert.throws(() => validateLock(lock({ 'node_modules/Alpha/node_modules/beta': artifact(), 'node_modules/alpha': artifact() })), /colliding/);
  });

  for (const extra of [{ link: true }, { inBundle: true }, { bundledDependencies: [] }, { name: '../evil' }, { name: null },
    { dependencies: { evil: 'git+ssh://host/repo' } }, { optionalDependencies: { evil: 'file:../external' } },
    { peerDependencies: { evil: 'https://example.com/evil.tgz' } }, { overrides: { alpha: 'file:../evil' } },
    { version: '1.2' }, { version: '^1.2.3' }, { version: '01.2.3' }, { version: '1.2.3-01' }, { version: '1.2.3\n' },
    { integrity: undefined }, { integrity: 'sha1-dGVzdA==' }, { integrity: `sha512-${Buffer.alloc(63).toString('base64')}` },
    { integrity: integrity.replace(/==$/, 'AB') }, { integrity: `${integrity} ${integrity}` }]) {
    it(`rejects incomplete or unsafe locked metadata ${JSON.stringify(extra)}`, () => {
      assert.throws(() => validateLock(lock({ 'node_modules/alpha': artifact('alpha', extra) })));
    });
  }

  for (const resolved of [undefined, '', 'file:../archive.tgz', 'http://registry.npmjs.org/pkg.tgz', 'https://registry.npmjs.org.evil.test/pkg.tgz',
    'https://registry.npmjs.org@evil.test/pkg.tgz', 'https://user@registry.npmjs.org/pkg.tgz',
    'https://registry.npmjs.org:443/pkg.tgz', 'https://registry.npmjs.org:8443/pkg.tgz',
    'https://registry.npmjs.org/pkg.tgz?token=private', 'https://registry.npmjs.org/pkg.tgz#fragment',
    'https://registry.npmjs.org/a/../pkg.tgz', ' https://registry.npmjs.org/pkg.tgz', 'https://registry.npmjs.org/pkg.tgz\n']) {
    it(`rejects unsupported artifact URL ${JSON.stringify(resolved)}`, () => {
      assert.throws(() => validateLock(lock({ 'node_modules/alpha': artifact('alpha', { resolved }) })));
    });
  }

  it('rejects executor sources hidden in legacy v2 dependency metadata', () => {
    for (const metadata of [{ version: 'git+https://host/repo' }, { ...artifact(), requires: { beta: 'file:../external' } },
      { ...artifact(), dependencies: { beta: { version: '1.0.0', resolved: 'https://evil.test/pkg.tgz' } } }]) {
      assert.throws(() => validateLock(lock(undefined, { lockfileVersion: 2, dependencies: { alpha: metadata } })));
    }
  });
});

describe('protected npm project snapshot', () => {
  it('preserves exact text and fingerprints absent files and comment-only npmrc', (t) => {
    const { project } = fixture(t);
    const npmrc = '# Local notes\n  ; No registry settings\n\n';
    writeFileSync(join(project, '.npmrc'), npmrc);
    const result = readProject(project);
    assert.equal(result.project, realpathSync(project));
    assert.deepEqual(result.files, {
      'package.json': '{"name":"pilot"}', 'package-lock.json': null, '.npmrc': npmrc, 'npm-shrinkwrap.json': null,
    });
    assert.equal(result.fingerprint, createHash('sha256').update(JSON.stringify(result.files)).digest('hex'));
    assert.doesNotThrow(() => assertProjectUnchanged(result));
  });

  it('validates existing lock contents before returning a project snapshot', (t) => {
    const { project } = fixture(t);
    writeFileSync(join(project, 'package-lock.json'), JSON.stringify(lock()));
    assert.equal(readProject(project).files['package-lock.json'], JSON.stringify(lock()));
    writeFileSync(join(project, 'package-lock.json'), JSON.stringify(lock({ 'node_modules/alpha': artifact('alpha', { link: true }) })));
    assert.throws(() => readProject(project), /Linked/);
  });

  for (const content of ['registry=https://private.example\n', '//registry.npmjs.org/:_authToken=DO_NOT_ECHO_THIS',
    '# comment\rregistry=https://private.example', 'ignore-scripts=false']) {
    it('rejects meaningful npmrc configuration without echoing its values', (t) => {
      const { project } = fixture(t);
      writeFileSync(join(project, '.npmrc'), content);
      assert.throws(() => readProject(project), (error) => {
        assert.match(error.message, /\.npmrc configuration is not supported/);
        assert.ok(!error.message.includes('DO_NOT_ECHO_THIS') && !error.message.includes('private.example'));
        return true;
      });
    });
  }

  it('rejects ancestor workspace membership and shrinkwrap before resolution', (t) => {
    const { directory, project } = fixture(t);
    writeFileSync(join(directory, 'package.json'), JSON.stringify({ workspaces: ['project'] }));
    assert.throws(() => readProject(project), /workspace/);
    rmSync(join(directory, 'package.json'));
    writeFileSync(join(project, 'npm-shrinkwrap.json'), '{}');
    assert.throws(() => readProject(project), /shrinkwrap/);
  });

  it('rejects missing, malformed, nonregular, and invalid UTF-8 manifests', (t) => {
    const { project } = fixture(t);
    const path = join(project, 'package.json');
    for (const contents of ['{', Buffer.from([0xff, 0xfe])]) {
      writeFileSync(path, contents);
      assert.throws(() => readProject(project));
    }
    rmSync(path);
    assert.throws(() => readProject(project), /required/);
    mkdirSync(path);
    assert.throws(() => readProject(project), /regular file/);
  });

  for (const [name, size] of [['package.json', 2 * 1024 * 1024 + 1], ['package-lock.json', 10 * 1024 * 1024 + 1]]) {
    it(`rejects oversized ${name} before reading its contents`, (t) => {
      const { project } = fixture(t);
      writeFileSync(join(project, name), '{}');
      truncateSync(join(project, name), size);
      assert.throws(() => readProject(project), /size limit/);
    });
  }

  it('rejects hard-linked input files', (t) => {
    const { directory, project } = fixture(t);
    linkSync(join(project, 'package.json'), join(directory, 'linked-manifest.json'));
    assert.throws(() => readProject(project), /hard links/);
  });

  it('rejects file symlinks', (t) => {
    const { directory, project } = fixture(t);
    const target = join(directory, 'manifest.json');
    writeFileSync(target, '{"name":"other"}');
    rmSync(join(project, 'package.json'));
    if (!makeSymlink(t, target, join(project, 'package.json'))) return;
    assert.throws(() => readProject(project), /symlink/);
  });

  it('rejects junction or symlink ancestors', (t) => {
    const { directory, project } = fixture(t);
    const linked = join(directory, 'linked');
    if (!makeSymlink(t, project, linked, process.platform === 'win32' ? 'junction' : 'dir')) return;
    const child = join(project, 'child');
    mkdirSync(child);
    writeFileSync(join(child, 'package.json'), '{}');
    assert.throws(() => readProject(join(linked, 'child')), /symlinks or junctions/);
  });

  for (const file of ['package.json', 'package-lock.json', '.npmrc', 'npm-shrinkwrap.json']) {
    it(`invalidates approval when ${file} changes or appears`, (t) => {
      const { project } = fixture(t);
      const snapshot = readProject(project);
      writeFileSync(join(project, file), file === 'package-lock.json' ? JSON.stringify(lock()) : file === '.npmrc' ? '# added comment' : '{}');
      assert.throws(() => assertProjectUnchanged(snapshot), /Project changed.*review again/);
    });
  }

  it('invalidates approval when an ancestor becomes a workspace or an input disappears', (t) => {
    const { directory, project } = fixture(t);
    const snapshot = readProject(project);
    writeFileSync(join(directory, 'package.json'), '{"workspaces":["project"]}');
    assert.throws(() => assertProjectUnchanged(snapshot), /Project changed.*review again/);
    rmSync(join(directory, 'package.json'));
    rmSync(join(project, 'package.json'));
    assert.throws(() => assertProjectUnchanged(snapshot), /Project changed.*review again/);
  });
});
