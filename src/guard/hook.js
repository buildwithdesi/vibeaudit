import { isAgentControlPath } from './agent-files.js';
import { inspectReferencedAgentFiles, readBaseline } from './baseline.js';
import { analyzeCommand } from './command.js';

const MAX_HOOK_INPUT = 1024 * 1024;
const APPROVAL_COMMAND_RE = /\bvibeguard(?:\.cmd|\.exe)?\b[\s\S]{0,120}\b(?:trust-file|trust-current|baseline|approve)\b/i;
const MCP_TOOL_RE = /^mcp(?:__|_)/i;
const MCP_MUTATION_RE = /(?:^|[_-])(?:create|update|delete|remove|write|send|post|upload|publish|install|execute|exec|run|shell|push|deploy|pay|charge|fund|auth|token|credential|secret|share|move|rename|set|grant|revoke)(?:[_-]|$)/i;
const READ_ONLY_WEB_MCP_RE = /^mcp(?:__|_)web(?:__|_)(?:run|search|open|click|find|screenshot|finance|weather|sports|time)$/i;
// Read-only file tools across Claude Code, Codex, and Cursor. Anything else touching an agent control file is treated as a write.
const READ_ONLY_TOOL_RE = /^(?:read|glob|grep|ls|notebookread|view|view_file|read_file|list_dir|list_directory|file_search|grep_search|codebase_search)$/i;
const SAFE_ENV_BASENAME_RE =/^\.env\.(?:example|sample|template)$/i;
const SENSITIVE_BROWSER_BASENAME_RE = /^(?:login data|local state|cookies)$/i;
const SENSITIVE_GENERIC_BASENAME_RE = /^(?:credentials?|secrets?|tokens?)\.(?:json|jsonl|txt|db|sqlite|yaml|yml|ini|toml)$/i;

function firstString(...values) {
  return values.find((value) => typeof value === 'string' && value.length > 0) || '';
}

/**
 * Every string anywhere in the tool input, so a patch hidden in a second field, an edits
 * array, or a Codex-style command array is still read.
 * @param {unknown} value
 * @param {string[]} [out]
 */
function collectStrings(value, out = [], depth = 0) {
  if (typeof value === 'string') out.push(value);
  else if (value && typeof value === 'object' && depth < 8) {
    for (const item of Object.values(value)) collectStrings(item, out, depth + 1);
  }
  return out;
}

const GIT_ESCAPES = { a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v' };

/**
 * Turn a patch header path into the file paths it could name. A tab starts a timestamp in
 * a unified diff, but is part of the file name in a Codex patch, so both readings are kept
 * and the caller blocks if either one is sensitive.
 * @param {string} raw
 * @returns {string[]}
 */
function cleanPatchPaths(raw) {
  const whole = raw.trim();
  const cut = whole.split('\t')[0].trim();
  return whole === cut ? [cleanPatchPath(whole)] : [cleanPatchPath(whole), cleanPatchPath(cut)];
}

/**
 * Undo git's "quoted\303\251" form and strip a/ or b/.
 * @param {string} raw
 */
function cleanPatchPath(raw) {
  let path = raw;
  if (path.length >= 2 && path.startsWith('"') && path.endsWith('"')) {
    const latin1 = path.slice(1, -1).replace(/\\([0-7]{3}|.)/g, (_, code) => (
      code.length === 3 ? String.fromCharCode(parseInt(code, 8)) : (GIT_ESCAPES[code] ?? code)
    ));
    // Git writes non-ASCII names as octal UTF-8 bytes, so decode them back to text.
    path = /[^\x00-\xff]/.test(latin1) ? latin1 : Buffer.from(latin1, 'latin1').toString('utf8');
  }
  return path.replace(/^[ab]\//, '');
}

const GIT_PATH = String.raw`("(?:[^"\\]|\\.)*"|\S+)`;
const PATCH_HEADER_RES = [
  /^\*\*\*[ \t]+(?:Update|Add|Delete|Move) File:[ \t]*(.+?)[ \t]*$/gim,
  /^\*\*\*[ \t]+Move to:[ \t]*(.+?)[ \t]*$/gim,
  // Spaces or tabs only after ---, so a YAML front matter line is not read as a header.
  /^(?:\+\+\+|---)[ \t]+(.+?)[ \t]*$/gm,
  /^(?:rename|copy) (?:from|to) (.+?)[ \t]*$/gm,
  // A new empty file or a mode change has a diff --git line and no ---/+++ lines.
  new RegExp(String.raw`^diff --git ${GIT_PATH} ${GIT_PATH}[ \t]*$`, 'gm'),
];

/** @param {string[]} texts */
function findPatchPaths(texts) {
  const paths = [];
  for (const text of texts) {
    for (const re of PATCH_HEADER_RES) {
      for (const match of text.matchAll(re)) paths.push(...match.slice(1).filter(Boolean));
    }
  }
  return paths.flatMap(cleanPatchPaths).filter((path) => path && path !== '/dev/null');
}

function getToolInput(payload) {
  return payload.tool_input || payload.toolInput || payload.input || {};
}

function getEventName(payload) {
  return firstString(payload.hook_event_name, payload.hookEventName, payload.event_name, 'PreToolUse');
}

/**
 * Return true for local files that commonly contain credentials or session data.
 * Safe documentation fixtures such as .env.example remain readable.
 * @param {string} filePath
 */
function isSensitiveFilePath(filePath) {
  const segments = filePath
    .replace(/\\/g, '/')
    .split('/')
    .filter(Boolean)
    .map((segment) => segment.toLowerCase());
  if (segments.length === 0) return false;

  const basename = segments.at(-1);
  if (basename === '.env' || (basename.startsWith('.env.') && !SAFE_ENV_BASENAME_RE.test(basename))) return true;
  if (['.npmrc', '.pypirc', '.git-credentials', '.netrc'].includes(basename)) return true;
  if (SENSITIVE_BROWSER_BASENAME_RE.test(basename) || SENSITIVE_GENERIC_BASENAME_RE.test(basename)) return true;

  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    const next = segments[index + 1] || '';
    const afterNext = segments[index + 2] || '';
    if (segment === '.aws' && next) return true;
    if (segment === '.azure' && next) return true;
    if (segment === '.config' && ['gh', 'gcloud'].includes(next) && afterNext) return true;
    if (segment === '.ssh' && next) return true;
    if (segment === '.docker' && next === 'config.json') return true;
    if (segment === '.kube' && next === 'config') return true;
    if (segment === '.git' && next === 'config') return true;
  }
  return false;
}

/** @param {string} reason @param {string} eventName */
export function denyHook(reason, eventName = 'PreToolUse') {
  if (eventName === 'ConfigChange') return { decision: 'block', reason };
  return {
    hookSpecificOutput: {
      hookEventName: eventName,
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  };
}

/** @param {string} reason @param {string} eventName */
export function askHook(reason, eventName = 'PreToolUse') {
  return {
    hookSpecificOutput: {
      hookEventName: eventName,
      permissionDecision: 'ask',
      permissionDecisionReason: reason,
    },
  };
}

/**
 * Decide whether an AI tool call may proceed.
 * @param {object} payload
 * @param {{cwd?:string,baselinePath?:string,skipBaseline?:boolean}} [options]
 * @returns {{allow:boolean,output?:object,reason?:string}}
 */
export function evaluateHook(payload, options = {}) {
  const eventName = getEventName(payload);
  const input = getToolInput(payload);
  const cwd = firstString(payload.cwd, input.cwd, options.cwd, process.cwd());

  const toolName = firstString(
    payload.tool_name,
    payload.toolName,
    input.tool_name,
    input.toolName,
    payload.name,
    input.name,
  );
  if (MCP_TOOL_RE.test(toolName) && MCP_MUTATION_RE.test(toolName) && !READ_ONLY_WEB_MCP_RE.test(toolName)) {
    const reason = `VibeGuard blocked the external MCP action ${toolName}. Review its provider, target, payload, and data scope before running it manually.`;
    return { allow: false, reason, output: denyHook(reason, eventName) };
  }

  const command = firstString(input.command, input.cmd, input.script, payload.command);
  let reviewReason = '';
  if (command) {
    if (APPROVAL_COMMAND_RE.test(command)) {
      const reason = 'VibeGuard trust and baseline commands must be run manually, never by an AI agent.';
      return { allow: false, reason, output: denyHook(reason, eventName) };
    }
    // Check only agent files named by this command. A global sweep lets an
    // unrelated new skill or plugin block every tool call and makes each call slow.
    if (!options.skipBaseline) {
      try {
        if (readBaseline(options.baselinePath)) {
          const referenced = inspectReferencedAgentFiles(command, { cwd, baselinePath: options.baselinePath });
          if (!referenced.ok) {
            const target = referenced.changed[0] || referenced.missing[0];
            const issue = referenced.suspicious?.[0];
            const reason = issue
              ? `VibeGuard blocked suspicious instructions in an agent script: ${issue.file}:${issue.line}. ${issue.message}`
              : `VibeGuard blocked a changed or missing agent script: ${target}. Review and trust the file before running it.`;
            return { allow: false, reason, output: denyHook(reason, eventName) };
          }
        }
      } catch {
        // A broken baseline skips provenance checks, not the command safety checks below.
      }
    }
    const analysis = analyzeCommand(command);
    if (analysis.decision === 'deny') {
      const reason = `VibeGuard blocked this dangerous command. ${analysis.summary}`;
      return { allow: false, reason, output: denyHook(reason, eventName) };
    }
    // Review-level actions are not blocked, but the host must ask the person first.
    // Without this, a host in bypass mode would run installs and clones with no prompt at all.
    if (analysis.decision === 'review') {
      reviewReason = `VibeGuard wants a person to approve this command. ${analysis.summary}`;
    }
  }

  const filePath = firstString(input.file_path, input.filePath, input.path, payload.file_path);
  // A single patch can touch many files, and a tool can carry it in any field,
  // so every file header in every string counts, not just the first one found.
  const patchPaths = findPatchPaths(collectStrings([input, payload.content]));
  // Credential files get the same every-file check as agent files: a patch naming .env is a write to .env.
  const sensitiveTarget = [filePath, ...patchPaths].find((path) => path && isSensitiveFilePath(path));
  if (sensitiveTarget) {
    const reason = `VibeGuard blocked an AI read or edit of a credential-bearing path: ${sensitiveTarget}. Inspect or change this file manually; never expose its contents to an agent.`;
    return { allow: false, reason, output: denyHook(reason, eventName) };
  }
  const hasWritePayload = ['content', 'contents', 'new_string', 'newString', 'patch', 'edits', 'new_source'].some((key) => input[key] !== undefined);
  // Fail closed: a tool touching an agent control file must be a known reader, not merely "not a known writer".
  // Name matching alone misses tools like MultiEdit and NotebookEdit.
  const knownReadOnlyTool = READ_ONLY_TOOL_RE.test(toolName);
  const agentTarget = [filePath, ...patchPaths].find((path) => path && isAgentControlPath(path));

  if (agentTarget && (!knownReadOnlyTool || hasWritePayload)) {
    const reason = `VibeGuard blocked an AI edit to ${agentTarget}. Edit it manually, review every line, then trust its new hash.`;
    return { allow: false, reason, output: denyHook(reason, eventName) };
  }

  if (/configchange/i.test(eventName)) {
    const reason = 'VibeGuard blocked an unmanaged AI configuration change. Apply and review security configuration changes manually.';
    return { allow: false, reason, output: denyHook(reason, eventName) };
  }

  // Every deny check above runs first, so a review request never hides a block.
  if (reviewReason) return { allow: true, ask: true, reason: reviewReason, output: askHook(reviewReason, eventName) };
  return { allow: true };
}

/** @param {NodeJS.ReadableStream} stream */
export async function readHookInput(stream = process.stdin) {
  let raw = '';
  for await (const chunk of stream) {
    raw += chunk;
    if (Buffer.byteLength(raw, 'utf8') > MAX_HOOK_INPUT) {
      throw new Error(`hook input exceeds ${MAX_HOOK_INPUT} bytes`);
    }
  }
  if (!raw.trim()) throw new Error('hook input was empty');
  return JSON.parse(raw);
}
