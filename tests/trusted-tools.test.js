import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { createIsolatedNpmEnv, findTrustedExecutable } from '../src/trusted-tools.js';

describe('trusted process execution', () => {
  it('never resolves a target-controlled executable', () => {
    const root = mkdtempSync(join(tmpdir(), 'vibeaudit-tools-test-'));
    const target = join(root, 'target');
    const trusted = join(root, 'trusted');
    mkdirSync(target);
    mkdirSync(trusted);
    const executable = process.platform === 'win32' ? 'git.exe' : 'git';
    writeFileSync(join(target, executable), 'fake');
    writeFileSync(join(trusted, executable), 'trusted');
    try {
      assert.equal(findTrustedExecutable('git', target, { PATH: target }), null);
      assert.equal(findTrustedExecutable('git', target, { PATH: `${target}${delimiter}${trusted}` }), join(trusted, executable));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('strips package-manager credentials and inherited npm configuration', () => {
    const env = createIsolatedNpmEnv({
      PATH: 'safe-path',
      NODE_AUTH_TOKEN: 'secret',
      NPM_TOKEN: 'secret',
      npm_config_registry: 'https://evil.example',
    }, { userConfig: 'user.npmrc', globalConfig: 'global.npmrc' });
    assert.equal(env.PATH, 'safe-path');
    assert.equal(env.NODE_AUTH_TOKEN, undefined);
    assert.equal(env.NPM_TOKEN, undefined);
    assert.equal(env.NPM_CONFIG_REGISTRY, 'https://registry.npmjs.org/');
    assert.equal(env.NPM_CONFIG_USERCONFIG, 'user.npmrc');
  });
});
