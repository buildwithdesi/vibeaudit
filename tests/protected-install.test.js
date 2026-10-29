import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { installReviewed, installStatus, isolatedInstallEnv, reviewInstall, rollbackInstall } from '../src/precheck/protected-install.js';

const NOW = Date.parse('2026-09-06T12:00:00Z');
const IDENTITY = { node: 'v22.0.0', npm: '10.0.0', cliSha256: 'fixture-npm', platform: process.platform, arch: process.arch };
const encode = (value) => `${JSON.stringify(value, null, 2)}\n`;
const json = (path) => JSON.parse(readFileSync(path, 'utf8'));
const artifact = (name, version) => {
  // These are inert stand-ins for the bytes authenticated by the real reviewer.
  // This suite tests the transaction; fresh-review.test.js covers signed archives.
  const archive = Buffer.from(`inert ${name}@${version} fixture archive`);
  return { name, version, archive, integrity: `sha512-${createHash('sha512').update(archive).digest('base64')}` };
};

function fixture(t, { withLock = true, withModules = true } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'vibeguard-install-test-'));
  t.after(() => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert.ok(basename(directory).startsWith('vibeguard-install-test-'));
    rmSync(directory, { recursive: true, force: true });
  });
  const project = join(directory, 'project');
  const store = join(directory, 'reviews');
  mkdirSync(project);
  const packages = new Map([artifact('existing', '1.0.0'), artifact('new-package', '2.0.0')].map((value) => [`${value.name}@${value.version}`, value]));
  const originalManifest = {
    name: 'real-project', version: '1.0.0', private: true,
    dependencies: { existing: '^1.0.0' }, overrides: { existing: '$existing' },
    scripts: { postinstall: 'node must-not-execute.js' },
  };
  function makeLock(manifest) {
    return {
      name: manifest.name, version: manifest.version, lockfileVersion: 3,
      packages: {
        '': { ...manifest },
        ...Object.fromEntries(Object.entries({ ...manifest.dependencies, ...manifest.devDependencies }).map(([name]) => {
          const value = [...packages.values()].find((entry) => entry.name === name);
          return [`node_modules/${name}`, {
            version: value.version, integrity: value.integrity,
            resolved: `https://registry.npmjs.org/${name}/-/${name}-${value.version}.tgz`,
          }];
        })),
      },
    };
  }
  writeFileSync(join(project, 'package.json'), encode(originalManifest));
  if (withLock) writeFileSync(join(project, 'package-lock.json'), encode(makeLock(originalManifest)));
  writeFileSync(join(project, '.npmrc'), '# This project has no custom npm configuration.\n');
  writeFileSync(join(project, 'user-work.txt'), 'unrelated work before install\n');
  if (withModules) {
    mkdirSync(join(project, 'node_modules', 'existing'), { recursive: true });
    writeFileSync(join(project, 'node_modules', 'existing', 'package.json'), encode({ name: 'existing', version: '1.0.0' }));
    writeFileSync(join(project, 'node_modules', 'preserve-me.txt'), 'original installed output\n');
  }
  const originalFiles = Object.fromEntries(['package.json', 'package-lock.json', '.npmrc', 'user-work.txt'].map((name) => [name,
    existsSync(join(project, name)) ? readFileSync(join(project, name), 'utf8') : null]));
  const calls = [];
  const behavior = {};
  const clock = { now: NOW };
  const dependencies = {
    identity: () => ({ ...IDENTITY }), now: () => clock.now,
    runNpm: async (args, options) => {
      calls.push({ args: [...args], options: { ...options } });
      if (behavior.failNpm === args[0]) throw new Error(`fixture npm ${args[0]} failure`);
      if (args[0] === 'install') {
        behavior.inspectResolve?.(args, options);
        const manifest = json(join(options.cwd, 'package.json'));
        const field = args.includes('--save-dev') ? 'devDependencies' : 'dependencies';
        manifest[field] = { ...manifest[field], 'new-package': '2.0.0' };
        writeFileSync(join(options.cwd, 'package.json'), encode(manifest));
        writeFileSync(join(options.cwd, 'package-lock.json'), encode(makeLock(manifest)));
      } else if (args[0] === 'cache') {
        assert.equal(args[1], 'add');
        assert.ok(args.includes('--offline'));
        for (const path of args.slice(2).filter((value) => value !== '--offline')) {
          assert.ok([...packages.values()].some((value) => value.archive.equals(readFileSync(path))));
        }
      } else if (args[0] === 'ci') {
        assert.ok(args.includes('--offline'));
        const lock = json(join(options.cwd, 'package-lock.json'));
        for (const [location, metadata] of Object.entries(lock.packages)) {
          if (!location) continue;
          const name = metadata.name || location.slice(location.lastIndexOf('node_modules/') + 'node_modules/'.length);
          const packagePath = join(options.cwd, location);
          mkdirSync(packagePath, { recursive: true });
          writeFileSync(join(packagePath, 'package.json'), encode({ name, version: metadata.version }));
          writeFileSync(join(packagePath, 'index.js'), '// inert fixture; never executed\n');
        }
        behavior.afterCi?.(options);
      } else assert.fail(`Unexpected fake npm command ${args[0]}`);
    },
    precheck: async (spec, options) => {
      assert.equal(spec, 'new-package@2.0.0');
      assert.equal(options.reviewAll, true);
      const tree = options.resolve(spec);
      behavior.inspectTree?.(tree, options);
      const results = [];
      for (const value of tree) {
        const bundle = packages.get(`${value.name}@${value.version}`);
        assert.ok(bundle, 'the exact resolved package must have a fixture artifact');
        await options.onVerifiedArchive(bundle);
        const blocked = behavior.block && value.name === 'new-package';
        results.push({ ...value, level: blocked ? 'block' : 'ok', reasons: blocked ? ['fixture policy block'] : [],
          ageHours: 5000, installScripts: [], review: { status: blocked ? 'flagged' : 'reviewed', integrity: bundle.integrity } });
      }
      behavior.afterReview?.();
      const blocked = results.filter((value) => value.level === 'block');
      return { spec, total: results.length, results, blocked, warned: [], exitCode: blocked.length ? 2 : 0 };
    },
  };
  const review = (extra = {}) => reviewInstall({ project, spec: 'new-package@2.0.0', store, ...extra }, dependencies);
  const install = (id, extra = {}) => installReviewed(id, { accept: id, store, ...extra }, dependencies);
  const assertOriginalFiles = () => {
    for (const [name, content] of Object.entries(originalFiles)) {
      if (content === null) assert.equal(existsSync(join(project, name)), false, name);
      else assert.equal(readFileSync(join(project, name), 'utf8'), content, name);
    }
    if (withModules) assert.equal(readFileSync(join(project, 'node_modules', 'preserve-me.txt'), 'utf8'), 'original installed output\n');
    else assert.equal(existsSync(join(project, 'node_modules')), false);
  };
  return { directory, project, store, originalFiles, originalManifest, packages, calls, behavior, clock, dependencies,
    review, install, assertOriginalFiles };
}

test('review resolves from the exact project context while leaving the target untouched', async (t) => {
  const f = fixture(t);
  let inspected = false;
  f.behavior.inspectResolve = (args, options) => {
    assert.deepEqual(json(join(options.cwd, 'package.json')), f.originalManifest);
    assert.equal(readFileSync(join(options.cwd, 'package-lock.json'), 'utf8'), f.originalFiles['package-lock.json']);
    assert.equal(readFileSync(join(options.cwd, '.npmrc'), 'utf8'), '');
    assert.notEqual(options.cwd, f.project);
    assert.ok(args.includes('--package-lock-only'));
    assert.ok(args.includes('--save-exact'));
    assert.ok(args.includes('--save-prod'));
    inspected = true;
  };
  f.behavior.inspectTree = (tree) => assert.deepEqual(tree, [{ name: 'existing', version: '1.0.0' }, { name: 'new-package', version: '2.0.0' }]);
  const reviewed = await f.review();
  assert.equal(inspected, true);
  assert.equal(reviewed.status, 'ready');
  assert.equal(reviewed.total, 2);
  assert.equal(reviewed.scripts, 'disabled');
  assert.match(reviewed.id, /^[a-f0-9]{64}$/);
  f.assertOriginalFiles();
  assert.equal(f.calls.length, 1);
  const saved = json(reviewed.reviewPath);
  assert.equal(JSON.parse(saved.manifest).dependencies.existing, '^1.0.0');
  assert.deepEqual(JSON.parse(saved.manifest).overrides, { existing: '$existing' });
  assert.equal(JSON.parse(saved.manifest).dependencies['new-package'], '2.0.0');
  assert.equal(saved.artifacts.length, 2);
  assert.equal(readFileSync(reviewed.reviewPath, 'utf8').includes('"type": "Buffer"'), false);
  assert.equal(installStatus(reviewed.id, { store: f.store }).attempt, null);
});

test('development dependency review preserves production dependencies and overrides', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review({ dev: true });
  const manifest = JSON.parse(json(reviewed.reviewPath).manifest);
  assert.deepEqual(manifest.dependencies, f.originalManifest.dependencies);
  assert.deepEqual(manifest.overrides, f.originalManifest.overrides);
  assert.deepEqual(manifest.devDependencies, { 'new-package': '2.0.0' });
  assert.ok(f.calls[0].args.includes('--save-dev'));
  f.assertOriginalFiles();
});

test('a blocked review cannot install or create an attempt', async (t) => {
  const f = fixture(t);
  f.behavior.block = true;
  const reviewed = await f.review();
  assert.equal(reviewed.status, 'blocked');
  await assert.rejects(f.install(reviewed.id), /blocked/);
  assert.equal(f.calls.length, 1);
  assert.equal(installStatus(reviewed.id, { store: f.store }).attempt, null);
  f.assertOriginalFiles();
});

test('installation requires the complete matching review approval', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review();
  for (const accept of [undefined, reviewed.id.slice(0, 12), '0'.repeat(64)]) {
    await assert.rejects(installReviewed(reviewed.id, { accept, store: f.store }, f.dependencies), /exact review ID/);
  }
  assert.equal(f.calls.length, 1);
  f.assertOriginalFiles();
});

test('expired reviews and changed npm identities cannot install', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review();
  f.clock.now = reviewed.expiresAt + 1;
  await assert.rejects(f.install(reviewed.id), /expired/);
  f.clock.now = NOW;
  await assert.rejects(installReviewed(reviewed.id, { accept: reviewed.id, store: f.store }, {
    ...f.dependencies, identity: () => ({ ...IDENTITY, cliSha256: 'changed-npm' }),
  }), /Node or npm changed/);
  assert.equal(f.calls.length, 1);
  f.assertOriginalFiles();
});

for (const name of ['package.json', 'package-lock.json', '.npmrc']) {
  test(`changed ${name} invalidates approval without overwriting the edit`, async (t) => {
    const f = fixture(t);
    const reviewed = await f.review();
    const changed = `${f.originalFiles[name]}\n`;
    writeFileSync(join(f.project, name), changed);
    await assert.rejects(f.install(reviewed.id), /Project changed/);
    assert.equal(readFileSync(join(f.project, name), 'utf8'), changed);
    assert.equal(f.calls.length, 1);
    assert.equal(installStatus(reviewed.id, { store: f.store }).attempt, null);
  });
}

test('project changes during review prevent saving an approval', async (t) => {
  const f = fixture(t);
  const changed = encode({ ...f.originalManifest, description: 'concurrent human edit' });
  f.behavior.afterReview = () => writeFileSync(join(f.project, 'package.json'), changed);
  await assert.rejects(f.review(), /Project changed/);
  assert.equal(readFileSync(join(f.project, 'package.json'), 'utf8'), changed);
  assert.equal(readdirSync(f.store).some((name) => /^[a-f0-9]{64}$/.test(name)), false);
});

test('tampered retained archives fail before npm cache or installation runs', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review();
  const saved = json(reviewed.reviewPath);
  writeFileSync(join(dirname(reviewed.reviewPath), 'artifacts', saved.artifacts[0].file), 'tampered archive');
  const attempt = await f.install(reviewed.id);
  assert.equal(attempt.status, 'failed');
  assert.match(attempt.error, /archive changed/i);
  assert.equal(f.calls.length, 1);
  f.assertOriginalFiles();
  assert.equal(installStatus(reviewed.id, { store: f.store }).attempt.status, 'failed');
});

test('changed review content cannot be installed under its original ID', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review();
  const saved = json(reviewed.reviewPath);
  saved.manifest = encode({ name: 'tampered-manifest' });
  writeFileSync(reviewed.reviewPath, encode(saved));
  await assert.rejects(f.install(reviewed.id), /Review changed/);
  assert.equal(f.calls.length, 1);
  f.assertOriginalFiles();
});

test('npm failure preserves the project, records evidence, and consumes the single attempt', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review();
  f.behavior.failNpm = 'ci';
  const attempt = await f.install(reviewed.id);
  assert.equal(attempt.status, 'failed');
  assert.match(attempt.error, /fixture npm ci failure/);
  f.assertOriginalFiles();
  assert.equal(json(attempt.receiptPath).status, 'failed');
  const before = f.calls.length;
  delete f.behavior.failNpm;
  await assert.rejects(f.install(reviewed.id), /already had an installation attempt/);
  assert.equal(f.calls.length, before);
  assert.equal(f.calls.filter(({ args }) => args[0] === 'ci').length, 1);
});

test('npm changes to approved manifests prevent publication', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review();
  f.behavior.afterCi = ({ cwd }) => writeFileSync(join(cwd, 'package-lock.json'), '{}');
  const attempt = await f.install(reviewed.id);
  assert.equal(attempt.status, 'failed');
  assert.match(attempt.error, /changed the approved manifests/);
  f.assertOriginalFiles();
});

test('concurrent project edits during offline preparation prevent publication and are preserved', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review();
  const changed = encode({ ...f.originalManifest, description: 'human edit while npm was preparing output' });
  f.behavior.afterCi = () => writeFileSync(join(f.project, 'package.json'), changed);
  const attempt = await f.install(reviewed.id);
  assert.equal(attempt.status, 'failed');
  assert.match(attempt.error, /Project changed/);
  assert.equal(readFileSync(join(f.project, 'package.json'), 'utf8'), changed);
  assert.equal(readFileSync(join(f.project, 'package-lock.json'), 'utf8'), f.originalFiles['package-lock.json']);
  assert.equal(readFileSync(join(f.project, 'node_modules', 'preserve-me.txt'), 'utf8'), 'original installed output\n');
});

for (const mode of ['missing', 'wrong-version']) {
  test(`a ${mode} required package in npm output prevents publication`, async (t) => {
    const f = fixture(t);
    const reviewed = await f.review();
    f.behavior.afterCi = ({ cwd }) => {
      const path = join(cwd, 'node_modules', 'new-package', 'package.json');
      if (mode === 'missing') rmSync(path);
      else writeFileSync(path, encode({ name: 'new-package', version: '9.9.9' }));
    };
    const attempt = await f.install(reviewed.id);
    assert.equal(attempt.status, 'failed');
    assert.match(attempt.error, /omitted a required reviewed package|identity differs from review/);
    f.assertOriginalFiles();
  });
}

test('successful installation replaces only prepared paths and rollback restores previous output', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review();
  const attempt = await f.install(reviewed.id);
  assert.equal(attempt.status, 'installed');
  assert.equal(attempt.scripts, 'disabled');
  assert.deepEqual(attempt.installed, ['node_modules/existing', 'node_modules/new-package']);
  assert.equal(json(join(f.project, 'package.json')).dependencies['new-package'], '2.0.0');
  assert.equal(json(join(f.project, 'node_modules', 'new-package', 'package.json')).version, '2.0.0');
  assert.equal(existsSync(join(f.project, 'node_modules', 'preserve-me.txt')), false);
  assert.equal(readFileSync(join(attempt.backupPath, 'node_modules', 'preserve-me.txt'), 'utf8'), 'original installed output\n');
  assert.equal(readFileSync(join(attempt.backupPath, 'package.json'), 'utf8'), f.originalFiles['package.json']);
  assert.equal(readFileSync(join(f.project, 'user-work.txt'), 'utf8'), f.originalFiles['user-work.txt']);
  assert.equal(readFileSync(join(f.project, '.npmrc'), 'utf8'), f.originalFiles['.npmrc']);
  assert.equal(installStatus(reviewed.id, { store: f.store }).attempt.status, 'installed');
  assert.equal(json(attempt.receiptPath).status, 'installed');
  assert.ok(f.calls.every(({ options }) => options.cwd !== f.project));
  const restored = rollbackInstall(reviewed.id, { store: f.store });
  assert.equal(restored.status, 'rolled-back');
  assert.deepEqual(restored.conflicts, []);
  f.assertOriginalFiles();
  assert.equal(installStatus(reviewed.id, { store: f.store }).attempt.status, 'rolled-back');
  await assert.rejects(f.install(reviewed.id), /already had an installation attempt/);
});

test('rollback removes newly installed paths when the project started without lockfile or modules', async (t) => {
  const f = fixture(t, { withLock: false, withModules: false });
  const reviewed = await f.review();
  assert.equal((await f.install(reviewed.id)).status, 'installed');
  assert.equal(rollbackInstall(reviewed.id, { store: f.store }).status, 'rolled-back');
  f.assertOriginalFiles();
});

for (const name of ['package.json', 'package-lock.json', 'node_modules/new-package/index.js']) {
  test(`rollback preserves a later edit to ${name} and reports recovery required`, async (t) => {
    const f = fixture(t);
    const reviewed = await f.review();
    const attempt = await f.install(reviewed.id);
    assert.equal(attempt.status, 'installed');
    const changed = 'human edit after protected installation\n';
    writeFileSync(join(f.project, name), changed);
    const recovery = rollbackInstall(reviewed.id, { store: f.store });
    assert.equal(recovery.status, 'recovery-required');
    assert.ok(recovery.conflicts.includes(name.startsWith('node_modules/') ? 'node_modules' : name));
    assert.equal(readFileSync(join(f.project, name), 'utf8'), changed);
    assert.equal(readFileSync(join(f.project, 'user-work.txt'), 'utf8'), f.originalFiles['user-work.txt']);
    assert.equal(installStatus(reviewed.id, { store: f.store }).attempt.status, 'recovery-required');
  });
}

test('isolated npm environment strips secrets, Node preload options and inherited npm settings', (t) => {
  const f = fixture(t);
  const values = {
    NODE_OPTIONS: '--require=untrusted-loader', NODE_PATH: '/untrusted/modules', NODE_AUTH_TOKEN: 'fixture-token',
    NPM_TOKEN: 'fixture-token', AWS_SECRET_ACCESS_KEY: 'fixture-secret', OPENAI_API_KEY: 'fixture-secret',
    HTTPS_PROXY: 'https://fixture-credential@example.invalid', NPM_CONFIG_REGISTRY: 'https://untrusted.invalid',
    npm_config_ignore_scripts: 'false', NPM_CONFIG_USERCONFIG: '/untrusted/npmrc',
  };
  const original = Object.fromEntries(Object.keys(values).map((key) => [key, process.env[key]]));
  try {
    Object.assign(process.env, values);
    const env = isolatedInstallEnv(f.directory);
    for (const key of ['NODE_OPTIONS', 'NODE_PATH', 'NODE_AUTH_TOKEN', 'NPM_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'HTTPS_PROXY']) {
      assert.equal(env[key], undefined, key);
    }
    assert.equal(env.NPM_CONFIG_REGISTRY, 'https://registry.npmjs.org/');
    assert.equal(env.NPM_CONFIG_USERCONFIG, join(f.directory, 'user.npmrc'));
    assert.equal(env.NPM_CONFIG_GLOBALCONFIG, join(f.directory, 'global.npmrc'));
    assert.equal(env.NPM_CONFIG_IGNORE_SCRIPTS, 'true');
    assert.equal(env.HOME, f.directory);
    assert.equal(env.USERPROFILE, f.directory);
    assert.equal(JSON.stringify(env).includes('fixture-secret'), false);
    assert.equal(JSON.stringify(env).includes('fixture-token'), false);
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('different review stores cannot install into the same project concurrently', async (t) => {
  const f = fixture(t);
  const first = await f.review();
  const secondStore = join(f.directory, 'other-reviews');
  const second = await f.review({ store: secondStore });
  const originalRunner = f.dependencies.runNpm;
  let entered;
  let release;
  const ready = new Promise((done) => { entered = done; });
  const paused = new Promise((done) => { release = done; });
  f.dependencies.runNpm = async (args, options) => {
    await originalRunner(args, options);
    if (args[0] === 'ci') { entered(); await paused; }
  };
  const firstInstall = f.install(first.id);
  await ready;
  try { await assert.rejects(f.install(second.id, { store: secondStore }), /Another installation/); }
  finally { release(); }
  assert.equal((await firstInstall).status, 'installed');
});

test('a human save during final publication is captured and restored', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review();
  const originalRename = fs.renameSync;
  const manifest = join(f.project, 'package.json');
  const saved = encode({ ...f.originalManifest, description: 'human save during publication' });
  let injected = false;
  fs.renameSync = (source, target) => {
    if (source === manifest && !injected) { injected = true; writeFileSync(manifest, saved); }
    return originalRename(source, target);
  };
  syncBuiltinESMExports();
  let result;
  try { result = await f.install(reviewed.id); }
  finally { fs.renameSync = originalRename; syncBuiltinESMExports(); }
  assert.equal(injected, true);
  assert.equal(result.status, 'failed', JSON.stringify(result));
  assert.match(result.error, /Project changed during installation/);
  assert.equal(readFileSync(manifest, 'utf8'), saved);
  assert.equal(readFileSync(join(f.project, 'package-lock.json'), 'utf8'), f.originalFiles['package-lock.json']);
  assert.equal(readFileSync(join(f.project, 'node_modules/preserve-me.txt'), 'utf8'), 'original installed output\n');
});

test('rollback recovers a crash after an original was moved but before replacement', async (t) => {
  const f = fixture(t);
  const reviewed = await f.review();
  const result = await f.install(reviewed.id);
  assert.equal(result.status, 'installed');
  // Recreate that interrupted filesystem state using retained real backups.
  for (const name of ['package.json', 'package-lock.json', 'node_modules']) {
    fs.renameSync(join(f.project, name), join(result.stage, 'output', name));
    if (name !== 'node_modules') fs.renameSync(join(result.stage, 'backup', name), join(f.project, name));
  }
  const attemptPath = join(dirname(reviewed.reviewPath), 'attempt.json');
  writeFileSync(attemptPath, encode({ ...json(attemptPath), status: 'publishing' }));
  assert.equal(rollbackInstall(reviewed.id, { store: f.store }).status, 'rolled-back');
  f.assertOriginalFiles();
});
