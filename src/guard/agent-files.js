import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, extname, isAbsolute, join, parse, relative, resolve } from 'node:path';

const AGENT_CODE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.rb', '.go', '.rs',
  '.ps1', '.psm1', '.sh', '.bash', '.zsh', '.fish', '.bat', '.cmd',
  '.vbs', '.wsf',
]);

const AGENT_INSTRUCTION_NAMES = new Set([
  'skill.md',
  'agents.md',
  'agents.override.md',
  'claude.md',
  'claude.local.md',
  'gemini.md',
]);

const DIRECT_AGENT_FILES = [
  'SKILL.md',
  'AGENTS.md',
  'AGENTS.override.md',
  'CLAUDE.md',
  'CLAUDE.local.md',
  'GEMINI.md',
  '.mcp.json',
  'mcp.json',
  '.claude.json',
];

const AGENT_CONFIG_NAMES = new Set([
  '.claude.json',
  '.mcp.json',
  'hooks.json',
  'settings.json',
  'settings.local.json',
  'managed-settings.json',
  'config.toml',
  'managed_config.toml',
  'plugin.json',
  'plugin.lock.json',
  'installed_plugins.json',
  'agent-baseline.json',
  'command-approvals.json',
]);

const NETWORK_RE = /(?:https?:\/\/|\bcurl\b|\bwget\b|invoke-webrequest|invoke-restmethod|downloadstring|\bfetch\s*\(|requests?\.(?:get|post)|webclient)/i;
const EXECUTION_RE = /(?:\biex\b|invoke-expression|\bexec(?:file|sync)?\s*\(|\bspawn(?:sync)?\s*\(|child_process|start-process|\bpowershell\b|\bpwsh\b|\bpython(?:3)?\b|\bnode\b|\bruby\b|\bperl\b|\bbash\b|\bsh\s+-c\b|chmod\s+\+x|mshta|rundll32|regsvr32)/i;
const CREDENTIAL_RE = /(?:credential|password|secret|token|api[_ -]?key|\.ssh|\.aws|\.azure|\.npmrc|\.pypirc|\.env\b|login data|local state|cookies|keychain|process\.env|\$env:|appdata)/i;
const CREDENTIAL_ACCESS_RE = /(?:collect|copy|dump|extract|find|grab|harvest|read|search|steal|upload|send|exfiltrat)[^\r\n]{0,100}(?:credential|password|secret|token|api[_ -]?key|\.ssh|\.aws|\.azure|\.npmrc|\.pypirc|\.env\b|login data|local state|cookies|keychain|process\.env|\$env:|appdata)|(?:credential|password|secret|token|api[_ -]?key|\.ssh|\.aws|\.azure|\.npmrc|\.pypirc|\.env\b|login data|local state|cookies|keychain|process\.env|\$env:|appdata)[^\r\n]{0,100}(?:collect|copy|dump|extract|grab|harvest|read|steal|upload|send|exfiltrat)/i;
const STEALTH_RE = /(?:silently\s+(?:download|curl|fetch|run|execute|collect|upload|send|install|persist|modify|steal|copy|exfiltrate)|without (?:telling|asking|notifying)|no (?:permission|approval) (?:asked|required)|do not (?:tell|mention|show|warn)|hide (?:this|the)|background process|ignore (?:the )?user|bypass(?:ing)?\s+(?:security|guard|review|hooks?|verification|approval|the user)|disable (?:security|antivirus|defender|hooks?|vibeguard)|never reveal)/i;
const AUTONOMY_RE = /(?:never\s+ask\s+(?:for\s+)?(?:the\s+)?(?:user\s+)?permission|without\s+asking\s+(?:for\s+)?(?:a\s+)?(?:separate\s+)?(?:user\s+)?(?:approval|permission)|override(?:s|ing)?\s+approval(?:\s+pauses?)?|standing\s+authorization|(?:do\s+not|don't|never)\s+(?:request|seek|require|wait\s+for)\s+(?:the\s+)?(?:user(?:'s)?\s+)?(?:approval|permission))/i;
const SPEND_AUTOMATION_RE = /(?:\b(?:pay|spend|fund|charge|wallet)\b[^\r\n]{0,100}\b(?:autonomously|automatically)\b|\b(?:autonomously|automatically)\b[^\r\n]{0,100}\b(?:pay|spend|fund|charge|wallet)\b|auto[- ]create[^\r\n]{0,40}\bwallet\b)/i;
const DANGEROUS_MODE_RE = /\b(?:claude|codex)\b[^\r\n]{0,160}--dangerously-skip-permissions\b/i;
const PERSISTENCE_RE = /(?:hooks?\.json|settings(?:\.local)?\.json|managed-settings|powershell profile|startup folder|scheduled task|schtasks|registry run|currentversion\\run|crontab|launchagent|every time (?:the )?(?:ai|agent|claude|codex)|on (?:every )?startup)/i;
const APPROVAL_BYPASS_RE = /(?:\bvibeguard\b[\s\S]{0,80}\b(?:trust-(?:file|current)|approve-command|baseline)\b|\bmodify\b[\s\S]{0,80}\b(?:hooks?\.json|settings\.json)\b|\b(?:remove|disable)\b[\s\S]{0,80}\bvibeguard\b)/i;

/** Return capability evidence so linked files can be evaluated as one chain. */
export function identifyAgentCapabilities(content) {
  const lines = String(content || '').split(/\r?\n/);
  const groups = {
    network: matchingLines(lines, NETWORK_RE),
    execution: matchingLines(lines, EXECUTION_RE),
    credential: matchingLines(lines, CREDENTIAL_RE),
    credentialAccess: matchingLines(lines, CREDENTIAL_ACCESS_RE),
    stealth: matchingLines(lines, STEALTH_RE),
    persistence: matchingLines(lines, PERSISTENCE_RE),
  };
  return Object.fromEntries(Object.entries(groups).map(([name, matches]) => [name, { present: matches.length > 0, lines: matches }]));
}

function matchingLines(lines, pattern) {
  const matches = [];
  for (let index = 0; index < lines.length; index++) {
    if (pattern === EXECUTION_RE && /^\s*```/.test(lines[index])) continue;
    if (pattern.test(lines[index])) matches.push(index + 1);
  }
  return matches;
}

function nearbyCluster(anchorLines, otherGroups, distance = 12) {
  for (const anchor of anchorLines) {
    const neighbors = otherGroups.map((group) => group.find((line) => Math.abs(line - anchor) <= distance));
    if (neighbors.every(Boolean)) return anchor;
  }
  return 0;
}

/** @param {string} value */
export function normalizeAgentPath(value) {
  return String(value || '').replace(/\\/g, '/').toLowerCase();
}

/** @param {string} filePath */
export function isAgentControlPath(filePath) {
  const normalized = normalizeAgentPath(filePath);
  const name = basename(normalized);
  if (AGENT_INSTRUCTION_NAMES.has(name)) return true;
  if (['agent-baseline.json', 'command-approvals.json'].includes(name) &&
      /(?:^|\/)\.vibeaudit\//.test(normalized)) return true;
  if (['.claude.json', '.mcp.json'].includes(name)) return true;
  if (['hooks.json', 'settings.json', 'settings.local.json', 'managed-settings.json'].includes(name) &&
      /(?:^|\/)(?:\.claude|\.codex|\.cursor)(?:\/|$)/.test(normalized)) return true;
  if (name === 'mcp.json' && /(?:^|\/)\.cursor(?:\/|$)/.test(normalized)) return true;
  if (['config.toml', 'managed_config.toml'].includes(name) &&
      /(?:^|\/)\.codex(?:\/|$)/.test(normalized)) return true;
  const extension = extname(name);
  const isAgentCode = AGENT_CODE_EXTENSIONS.has(extension);
  const inSkills = /(?:^|\/)(?:\.claude|\.codex|\.agents|\.cursor)\/(?:[^/]+\/)*skills\//.test(normalized);
  if (inSkills) return name === 'skill.md' || isAgentCode;
  const inHooks = /(?:^|\/)(?:\.claude|\.codex|\.cursor)\/(?:[^/]+\/)*hooks\//.test(normalized);
  if (inHooks) return isAgentCode;
  const inPlugins = /(?:^|\/)(?:\.claude|\.codex|\.cursor)\/(?:[^/]+\/)*plugins\//.test(normalized);
  if (inPlugins && ['plugin.json', 'plugin.lock.json', 'installed_plugins.json', '.mcp.json'].includes(name)) return true;
  const inCommandsOrAgents = /(?:^|\/)\.claude\/(?:commands|agents)\//.test(normalized);
  if (inCommandsOrAgents) return extension === '.md' || isAgentCode;
  const inCodexRules = /(?:^|\/)\.codex\/rules\//.test(normalized);
  if (inCodexRules && (extension === '.md' || extension === '.rules' || isAgentCode)) return true;
  const inCursorRules = /(?:^|\/)\.cursor\/rules\//.test(normalized);
  return inCursorRules && (extension === '.md' || extension === '.mdc' || isAgentCode);
}

/** @param {string} filePath */
export function isHighAuthorityAgentPath(filePath) {
  const normalized = normalizeAgentPath(filePath);
  const name = basename(normalized);
  if (AGENT_INSTRUCTION_NAMES.has(name)) return true;
  if (AGENT_CONFIG_NAMES.has(name) && isAgentControlPath(normalized)) return true;
  return /(?:^|\/)(?:\.claude|\.codex|\.cursor)\/(?:[^/]+\/)*hooks\//.test(normalized) && isAgentControlPath(normalized);
}

/**
 * @param {string} content
 * @param {string} [filePath]
 * @returns {Array<{id:string,severity:'critical'|'warning',message:string,line:number,file:string}>}
 */
export function analyzeAgentControlContent(content, filePath = 'agent control file') {
  const text = String(content || '');
  const lines = text.split(/\r?\n/);
  const networkLines = matchingLines(lines, NETWORK_RE);
  const executionLines = matchingLines(lines, EXECUTION_RE);
  const credentialLines = matchingLines(lines, CREDENTIAL_RE);
  const credentialAccessLines = matchingLines(lines, CREDENTIAL_ACCESS_RE);
  const stealthLines = matchingLines(lines, STEALTH_RE);
  const autonomyLines = matchingLines(lines, AUTONOMY_RE);
  const spendAutomationLines = matchingLines(lines, SPEND_AUTOMATION_RE);
  const dangerousModeLines = matchingLines(lines, DANGEROUS_MODE_RE);
  const persistenceLines = matchingLines(lines, PERSISTENCE_RE);
  const bypassLines = matchingLines(lines, APPROVAL_BYPASS_RE);
  const findings = [];

  const downloadExecutionLine = nearbyCluster(
    networkLines,
    [executionLines, stealthLines],
  );
  if (downloadExecutionLine) {
    findings.push({
      id: 'agent-download-execution',
      severity: 'critical',
      message: 'Agent instructions combine a network download, code execution, and a credential, stealth, or persistence signal.',
      line: downloadExecutionLine,
      file: filePath,
    });
  }

  const persistentDownloadLine = nearbyCluster(networkLines, [executionLines, persistenceLines]);
  if (persistentDownloadLine && !downloadExecutionLine) {
    findings.push({
      id: 'agent-persistent-download-execution',
      severity: 'warning',
      message: 'Agent instructions combine a network download, code execution, and persistence. Confirm the source and purpose manually.',
      line: persistentDownloadLine,
      file: filePath,
    });
  }

  const credentialExfiltrationLine = nearbyCluster(credentialAccessLines, [credentialLines, networkLines, stealthLines]);
  if (credentialExfiltrationLine) {
    findings.push({
      id: 'agent-credential-exfiltration',
      severity: 'critical',
      message: 'Agent instructions combine credential access, outbound networking, and concealment.',
      line: credentialExfiltrationLine,
      file: filePath,
    });
  }

  const persistenceLine = nearbyCluster(persistenceLines, [stealthLines, [...executionLines, ...networkLines]]);
  if (persistenceLine) {
    findings.push({
      id: 'agent-persistence',
      severity: 'critical',
      message: 'Agent instructions describe concealed persistence that can run code again later.',
      line: persistenceLine,
      file: filePath,
    });
  }

  if (autonomyLines.length > 0) {
    findings.push({
      id: 'agent-approval-bypass',
      severity: 'warning',
      message: 'Agent instructions remove a user approval checkpoint. Review the skill before allowing it to run.',
      line: autonomyLines[0],
      file: filePath,
    });
  }

  if (spendAutomationLines.length > 0) {
    findings.push({
      id: 'agent-autonomous-spend',
      severity: 'warning',
      message: 'Agent instructions automate wallet creation or spending. Require explicit approval before any paid action or external data transfer.',
      line: spendAutomationLines[0],
      file: filePath,
    });
  }

  if (dangerousModeLines.length > 0) {
    findings.push({
      id: 'agent-dangerous-mode',
      severity: 'warning',
      message: 'Agent instructions enable an assistant permission-bypass mode. Require normal permissions and human review before use.',
      line: dangerousModeLines[0],
      file: filePath,
    });
  }

  if (bypassLines.length > 0) {
    findings.push({
      id: 'agent-guard-bypass',
      severity: 'critical',
      message: 'Agent instructions attempt to trust, remove, or bypass the security guard.',
      line: bypassLines[0],
      file: filePath,
    });
  }

  return findings;
}

/** @param {string|Buffer} content */
export function sha256(content) {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Locate files that can instruct an AI agent or change its hooks.
 * The walk is bounded so a hostile tree cannot stall every tool call.
 *
 * @param {string[]} roots
 * @param {{maxFiles?:number,maxBytes?:number,knownFiles?:Record<string,{sha256:string,size:number,mtimeMs?:number,ctimeMs?:number}>,authorityOnly?:boolean,includeStaging?:boolean}} [options]
 */
export function collectAgentControlFiles(roots, options = {}) {
  const maxFiles = options.maxFiles ?? 10000;
  const maxBytes = options.maxBytes ?? 2 * 1024 * 1024;
  const knownFiles = options.knownFiles || {};
  const authorityOnly = options.authorityOnly === true;
  const includeStaging = options.includeStaging === true;
  const files = [];
  const errors = [];
  const seen = new Set();
  let limitReached = false;

  function add(filePath, forceAgentCode = false) {
    const absolute = resolve(filePath);
    const key = normalizeAgentPath(absolute);
    if (seen.has(key)) return;
    seen.add(key);
    let stats;
    try {
      if (lstatSync(absolute).isSymbolicLink()) {
        errors.push(`${absolute}: symbolic links are not trusted agent files`);
        return;
      }
      stats = statSync(absolute);
    } catch (error) {
      errors.push(`${absolute}: ${error.code || error.message}`);
      return;
    }
    if (!stats.isFile() || (!forceAgentCode && !isAgentControlPath(absolute))) return;
    if (forceAgentCode && !AGENT_CODE_EXTENSIONS.has(extname(absolute).toLowerCase())) return;
    if (authorityOnly && !forceAgentCode && !isHighAuthorityAgentPath(absolute)) return;
    if (stats.size > maxBytes) {
      errors.push(`${absolute}: exceeds ${maxBytes} byte safety limit`);
      return;
    }
    if (files.length >= maxFiles) {
      if (!limitReached) errors.push(`agent file limit exceeded (${maxFiles})`);
      limitReached = true;
      return;
    }
    const prior = knownFiles[key];
    const alwaysHash = AGENT_CONFIG_NAMES.has(basename(key)) ||
      /(?:^|\/)(?:\.claude|\.codex|\.cursor)\/(?:[^/]+\/)*hooks\//.test(key);
    if (!alwaysHash && prior && prior.size === stats.size &&
        prior.mtimeMs === stats.mtimeMs && prior.ctimeMs === stats.ctimeMs) {
      files.push({
        path: absolute,
        size: stats.size,
        mtimeMs: stats.mtimeMs,
        ctimeMs: stats.ctimeMs,
        hash: prior.sha256,
        content: null,
      });
      return;
    }
    try {
      const content = readFileSync(absolute);
      files.push({
        path: absolute,
        size: stats.size,
        mtimeMs: stats.mtimeMs,
        ctimeMs: stats.ctimeMs,
        hash: sha256(content),
        content: content.toString('utf8'),
      });
    } catch (error) {
      errors.push(`${absolute}: ${error.code || error.message}`);
    }
  }

  function hookCommands(value, commands = []) {
    if (Array.isArray(value)) {
      for (const item of value) hookCommands(item, commands);
      return commands;
    }
    if (!value || typeof value !== 'object') return commands;
    for (const [key, child] of Object.entries(value)) {
      if (key === 'command' && typeof child === 'string') commands.push(child);
      else hookCommands(child, commands);
    }
    return commands;
  }

  function referencedHookScripts(configFile) {
    const name = basename(configFile.path).toLowerCase();
    if (!['hooks.json', 'settings.json', 'settings.local.json', 'managed-settings.json'].includes(name)) return;
    let parsed;
    try {
      parsed = JSON.parse(configFile.content || readFileSync(configFile.path, 'utf8'));
    } catch (error) {
      errors.push(`${configFile.path}: invalid agent hook JSON (${error.message})`);
      return;
    }
    const userRoot = homedir();
    for (const command of hookCommands(parsed.hooks || {})) {
      const tokens = command.match(/"[^"]+"|'[^']+'|[^\s;|&]+/g) || [];
      for (const raw of tokens) {
        const token = raw.replace(/^["']|["']$/g, '')
          .replace(/^~(?=[\\/])/, userRoot)
          .replace(/^%USERPROFILE%(?=[\\/])/i, userRoot)
          .replace(/^\$env:USERPROFILE(?=[\\/])/i, userRoot);
        if (!AGENT_CODE_EXTENSIONS.has(extname(token).toLowerCase())) continue;
        if (/[$%{}]/.test(token)) continue;
        const candidates = isAbsolute(token)
          ? [resolve(token)]
          : [resolve(process.cwd(), token), resolve(dirname(configFile.path), token)];
        const existing = candidates.find((candidate) => {
          try {
            return statSync(candidate).isFile();
          } catch {
            return false;
          }
        });
        if (existing) add(existing, true);
        else errors.push(`${configFile.path}: referenced hook script was not found (${token})`);
      }
    }
  }

  function walk(entryPath) {
    let stats;
    try {
      stats = statSync(entryPath);
    } catch {
      return;
    }
    if (stats.isFile()) {
      add(entryPath);
      return;
    }
    if (!stats.isDirectory()) return;

    let entries;
    try {
      entries = readdirSync(entryPath, { withFileTypes: true });
    } catch (error) {
      errors.push(`${entryPath}: ${error.code || error.message}`);
      return;
    }
    for (const entry of entries) {
      if (limitReached) break;
      const child = join(entryPath, entry.name);
      if (entry.isSymbolicLink()) {
        if (isAgentControlPath(child) || ['.claude', '.codex', '.agents'].includes(entry.name.toLowerCase())) {
          errors.push(`${child}: symbolic links are not trusted agent files`);
        }
        continue;
      }
      if (entry.isDirectory()) {
        const directoryName = entry.name.toLowerCase();
        const inAgentTree = /(?:^|\/)(?:\.claude|\.codex|\.agents|\.cursor)(?:\/|$)/.test(normalizeAgentPath(child));
        if (['node_modules', '.git', '.next', 'coverage'].includes(directoryName)) continue;
        if (!inAgentTree && ['dist', 'build'].includes(directoryName)) continue;
        if (!includeStaging && (directoryName.includes('plugin-source-staging') || directoryName.includes('plugin-install-staging'))) continue;
        if (authorityOnly && ['scripts', 'assets', 'references', 'templates', 'examples', 'archive', 'tests', 'test', 'fixtures', 'scratch'].includes(entry.name.toLowerCase())) continue;
        walk(child);
      } else if (entry.isFile() && isAgentControlPath(child)) {
        add(child);
      }
    }
  }

  for (const root of roots) walk(root);
  for (const file of [...files]) referencedHookScripts(file);
  return { files, errors };
}

/**
 * @param {string} [cwd]
 * @returns {string[]}
 */
export function defaultAgentRoots(cwd = process.cwd()) {
  const userRoot = homedir();
  const claudePluginRegistry = join(userRoot, '.claude', 'plugins', 'installed_plugins.json');
  const roots = [
    join(userRoot, '.claude', 'skills'),
    claudePluginRegistry,
    join(userRoot, '.claude', 'commands'),
    join(userRoot, '.claude', 'agents'),
    join(userRoot, '.claude', 'hooks'),
    join(userRoot, '.claude', 'CLAUDE.md'),
    join(userRoot, '.claude', 'CLAUDE.local.md'),
    join(userRoot, '.claude', 'settings.json'),
    join(userRoot, '.claude', 'settings.local.json'),
    join(userRoot, '.claude', 'managed-settings.json'),
    join(userRoot, '.claude.json'),
    join(userRoot, '.codex', 'skills'),
    join(userRoot, '.codex', 'plugins'),
    join(userRoot, '.codex', 'rules'),
    join(userRoot, '.codex', 'memories', 'skills'),
    join(userRoot, '.codex', 'AGENTS.md'),
    join(userRoot, '.codex', 'AGENTS.override.md'),
    join(userRoot, '.codex', 'hooks.json'),
    join(userRoot, '.codex', 'config.toml'),
    join(userRoot, '.codex', 'managed_config.toml'),
    join(userRoot, '.agents', 'skills'),
    join(userRoot, '.agents', 'AGENTS.md'),
    join(userRoot, '.cursor', 'skills'),
    join(userRoot, '.cursor', 'rules'),
    join(userRoot, '.cursor', 'hooks.json'),
    join(userRoot, '.cursor', 'mcp.json'),
  ];

  try {
    const registry = JSON.parse(readFileSync(claudePluginRegistry, 'utf8'));
    const cacheRoot = resolve(userRoot, '.claude', 'plugins', 'cache');
    for (const records of Object.values(registry.plugins || {})) {
      for (const record of Array.isArray(records) ? records : []) {
        if (typeof record.installPath !== 'string' || !isAbsolute(record.installPath)) continue;
        const candidate = resolve(record.installPath);
        const rel = relative(cacheRoot, candidate);
        if (rel !== '' && !rel.startsWith('..') && !isAbsolute(rel)) roots.push(candidate);
      }
    }
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw new Error(`Could not read the Claude plugin registry: ${error.message}`);
    }
  }

  const directNames = DIRECT_AGENT_FILES;
  let ancestor = resolve(cwd);
  const volumeRoot = parse(ancestor).root;
  const normalizedUserRoot = normalizeAgentPath(resolve(userRoot));
  for (;;) {
    for (const name of directNames) roots.push(join(ancestor, name));
    if (normalizeAgentPath(ancestor) !== normalizedUserRoot) {
      for (const folder of ['.claude', '.codex', '.agents', '.cursor']) roots.push(join(ancestor, folder));
    }
    if (normalizeAgentPath(ancestor) === normalizedUserRoot) break;
    if (ancestor === volumeRoot) break;
    const parent = dirname(ancestor);
    if (parent === ancestor) break;
    ancestor = parent;
  }

  if (process.platform === 'win32' && process.env.ProgramData) {
    roots.push(join(process.env.ProgramData, 'ClaudeCode', 'managed-settings.json'));
  }
  return [...new Set(roots.map((entry) => resolve(entry)))];
}

/**
 * Render a stable, reviewable path relative to a root when possible.
 * @param {string} root
 * @param {string} filePath
 */
export function displayAgentPath(root, filePath) {
  const rel = relative(root, filePath);
  return rel && !rel.startsWith('..') ? rel.replace(/\\/g, '/') : filePath;
}
