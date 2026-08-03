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
 * Keep only string entries from a config array. A hostile repo can ship a
 * .vibe-audit.json with non-string entries (e.g. "ignore": [123]) — downstream
 * code calls .replace()/.includes() on these and crashes the whole scan.
 * @param {unknown} value
 * @returns {string[]}
 */
function stringArray(value) {
  return Array.isArray(value) ? value.filter((v) => typeof v === 'string') : [];
}

/**
 * Validate a raw parsed config object and merge it with defaults.
 * Shared by local config loading (readFile) and remote config fetching (GitHub API),
 * so both paths apply a project's .vibe-audit.json the same way.
 *
 * @param {object} parsed
 * @returns {VibeAuditConfig}
 */
export function normalizeConfig(parsed) {
  const disableForPaths = {};
  if (parsed.disableForPaths && typeof parsed.disableForPaths === 'object' && !Array.isArray(parsed.disableForPaths)) {
    for (const [ruleId, patterns] of Object.entries(parsed.disableForPaths)) {
      const strs = stringArray(patterns);
      if (strs.length > 0) disableForPaths[ruleId] = strs;
    }
  }

  return {
    ignore: stringArray(parsed.ignore),
    rules: stringArray(parsed.rules),
    exclude: stringArray(parsed.exclude),
    format: ['terminal', 'json', 'markdown'].includes(parsed.format)
      ? parsed.format
      : DEFAULTS.format,
    strict: typeof parsed.strict === 'boolean' ? parsed.strict : DEFAULTS.strict,
    customEscapers: stringArray(parsed.customEscapers),
    customAuthGuards: stringArray(parsed.customAuthGuards),
    disableForPaths,
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
