import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * @typedef {Object} VibeAuditConfig
 * @property {string[]} [ignore] - Additional directories/files to ignore
 * @property {string[]} [rules] - Only run these rule IDs
 * @property {string[]} [exclude] - Exclude these rule IDs
 * @property {'terminal' | 'json' | 'markdown'} [format] - Output format
 * @property {boolean} [strict] - Fail on warnings too (not just criticals)
 */

/** @type {VibeAuditConfig} */
const DEFAULTS = {
  ignore: [],
  rules: [],
  exclude: [],
  format: 'terminal',
  strict: false,
  customEscapers: [],
  customAuthGuards: [],
  disableForPaths: {},
};

/**
 * Validate a raw parsed config object and merge it with defaults.
 * Shared by local config loading (readFile) and remote config fetching (GitHub API),
 * so both paths apply a project's .vibe-audit.json the same way.
 *
 * @param {object} parsed
 * @returns {VibeAuditConfig}
 */
export function normalizeConfig(parsed) {
  return {
    ignore: Array.isArray(parsed.ignore) ? parsed.ignore : DEFAULTS.ignore,
    rules: Array.isArray(parsed.rules) ? parsed.rules : DEFAULTS.rules,
    exclude: Array.isArray(parsed.exclude) ? parsed.exclude : DEFAULTS.exclude,
    format: ['terminal', 'json', 'markdown'].includes(parsed.format)
      ? parsed.format
      : DEFAULTS.format,
    strict: typeof parsed.strict === 'boolean' ? parsed.strict : DEFAULTS.strict,
    customEscapers: Array.isArray(parsed.customEscapers) ? parsed.customEscapers : DEFAULTS.customEscapers,
    customAuthGuards: Array.isArray(parsed.customAuthGuards) ? parsed.customAuthGuards : DEFAULTS.customAuthGuards,
    disableForPaths: parsed.disableForPaths && typeof parsed.disableForPaths === 'object' ? parsed.disableForPaths : DEFAULTS.disableForPaths,
  };
}

/** @returns {VibeAuditConfig} A fresh copy of the default config. */
export function getDefaultConfig() {
  return { ...DEFAULTS };
}

/**
 * Load config from .vibe-audit.json in the project root.
 * Falls back to defaults if no config file exists.
 *
 * @param {string} projectRoot
 * @returns {Promise<VibeAuditConfig>}
 */
export async function loadConfig(projectRoot) {
  const configPath = join(projectRoot, '.vibe-audit.json');

  try {
    const raw = await readFile(configPath, 'utf-8');
    return normalizeConfig(JSON.parse(raw));
  } catch {
    // No config file or invalid JSON — use defaults.
    return getDefaultConfig();
  }
}
