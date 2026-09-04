import { existsSync, realpathSync, statSync } from 'node:fs';
import { delimiter, dirname, isAbsolute, join, relative, resolve } from 'node:path';

export const NPM_REGISTRY = 'https://registry.npmjs.org/';

function isInside(candidate, targetDir) {
  if (!targetDir) return false;
  const rel = relative(resolve(targetDir), resolve(candidate));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/**
 * Locate npm's JavaScript entry point without invoking a PATH-resolved shim.
 * @returns {string|null}
 */
export function findTrustedNpmCli() {
  const candidates = [
    join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ].filter((candidate) => isAbsolute(candidate));
  for (const candidate of candidates) {
    try {
      if (existsSync(candidate) && statSync(candidate).isFile()) return resolve(candidate);
    } catch {
      // Try the next trusted installation layout.
    }
  }
  return null;
}

/**
 * Resolve an executable only from absolute PATH directories outside the target.
 * This prevents a scanned Windows repo from supplying npm.cmd or git.exe.
 *
 * @param {string} name
 * @param {string} [targetDir]
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string|null}
 */
export function findTrustedExecutable(name, targetDir, env = process.env) {
  const names = process.platform === 'win32'
    ? [`${name}.exe`, `${name}.com`]
    : [name];
  const pathValue = env.PATH || env.Path || env.path || '';
  for (const rawEntry of pathValue.split(delimiter)) {
    const entry = rawEntry.trim().replace(/^"|"$/g, '');
    if (!entry || !isAbsolute(entry) || isInside(entry, targetDir)) continue;
    for (const executable of names) {
      const candidate = join(entry, executable);
      try {
        if (existsSync(candidate) && statSync(candidate).isFile() && !isInside(candidate, targetDir)) {
          const real = realpathSync(candidate);
          if (statSync(real).isFile() && !isInside(real, targetDir)) return resolve(real);
        }
      } catch {
        // Keep searching trusted PATH entries.
      }
    }
  }
  return null;
}

/**
 * Remove package-manager credentials and inherited configuration.
 * @param {NodeJS.ProcessEnv} [source]
 * @param {{userConfig:string,globalConfig:string,registry?:string}} config
 */
export function createIsolatedNpmEnv(source = process.env, config) {
  const env = {};
  for (const [key, value] of Object.entries(source)) {
    if (/^(?:npm_config_|NPM_CONFIG_)/i.test(key)) continue;
    if (/(?:npm|node|yarn|pnpm).*(?:token|auth)|NODE_AUTH_TOKEN/i.test(key)) continue;
    env[key] = value;
  }
  return {
    ...env,
    NPM_CONFIG_USERCONFIG: config.userConfig,
    NPM_CONFIG_GLOBALCONFIG: config.globalConfig,
    NPM_CONFIG_REGISTRY: config.registry || NPM_REGISTRY,
    NPM_CONFIG_IGNORE_SCRIPTS: 'true',
    NPM_CONFIG_AUDIT: 'false',
    NPM_CONFIG_FUND: 'false',
  };
}
