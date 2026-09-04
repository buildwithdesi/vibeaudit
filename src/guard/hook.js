import { isAgentControlPath } from './agent-files.js';
import { inspectAgentBaseline, inspectReferencedAgentFiles, readBaseline } from './baseline.js';
import { analyzeCommand } from './command.js';

const MAX_HOOK_INPUT = 1024 * 1024;
const APPROVAL_COMMAND_RE = /\bvibeguard(?:\.cmd|\.exe)?\b[\s\S]{0,120}\b(?:trust-file|trust-current|baseline|approve)\b/i;
const MCP_TOOL_RE = /^mcp(?:__|_)/i;
const MCP_MUTATION_RE = /(?:^|[_-])(?:create|update|delete|remove|write|send|post|upload|publish|install|execute|exec|run|shell|push|deploy|pay|charge|fund|auth|token|credential|secret|share|move|rename|set|grant|revoke)(?:[_-]|$)/i;
const READ_ONLY_WEB_MCP_RE = /^mcp(?:__|_)web(?:__|_)(?:run|search|open|click|find|screenshot|finance|weather|sports|time)$/i;
const SAFE_ENV_BASENAME_RE = /^\.env\.(?:example|sample|template)$/i;
const SENSITIVE_BROWSER_BASENAME_RE = /^(?:login data|local state|cookies)$/i;
const SENSITIVE_GENERIC_BASENAME_RE = /^(?:credentials?|secrets?|tokens?)\.(?:json|jsonl|txt|db|sqlite|yaml|yml|ini|toml)$/i;

function firstString(...values) {
  return values.find((value) => typeof value === 'string' && value.length > 0) || '';
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
  return {
    hookSpecificOutput: {
      hookEventName: eventName,
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  };
}

function baselineDenial(inspection) {
  if (!inspection.baselineExists) {
    return `VibeGuard blocked agent tools because no reviewed agent-file baseline exists. Run "vibeguard trust-current --i-reviewed-these-files" manually after reviewing every listed file.`;
  }
  if (inspection.suspicious.length > 0) {
    const issue = inspection.suspicious[0];
    return `VibeGuard found suspicious agent instructions in ${issue.file}:${issue.line}. ${issue.message}`;
  }
  const changed = [...inspection.added, ...inspection.changed];
  if (changed.length > 0) {
    return `VibeGuard blocked agent tools because this control file is new or changed: ${changed[0]}. Review it, then run "vibeguard trust-file <path> --i-reviewed-this-file" manually.`;
  }
  if (inspection.errors.length > 0) {
    return `VibeGuard could not complete the agent-file check: ${inspection.errors[0]}`;
  }
  return '';
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

  if (!options.skipBaseline) {
    if (!readBaseline(options.baselinePath)) {
      const reason = 'VibeGuard blocked agent tools because no reviewed agent-file baseline exists. Run "vibeguard trust-current --i-reviewed-these-files" manually after reviewing every listed file.';
      return { allow: false, reason, output: denyHook(reason, eventName) };
    }
    const inspection = inspectAgentBaseline({ cwd, baselinePath: options.baselinePath, authorityOnly: true });
    const reason = baselineDenial(inspection);
    if (reason) return { allow: false, reason, output: denyHook(reason, eventName) };
  }

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
  if (command) {
    if (APPROVAL_COMMAND_RE.test(command)) {
      const reason = 'VibeGuard trust and baseline commands must be run manually, never by an AI agent.';
      return { allow: false, reason, output: denyHook(reason, eventName) };
    }
    if (!options.skipBaseline) {
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
    const analysis = analyzeCommand(command);
    if (analysis.decision !== 'allow') {
      const reason = `VibeGuard blocked this ${analysis.decision === 'deny' ? 'dangerous' : 'unverified'} command. ${analysis.summary}`;
      return { allow: false, reason, output: denyHook(reason, eventName) };
    }
  }

  const filePath = firstString(input.file_path, input.filePath, input.path, payload.file_path);
  if (filePath && isSensitiveFilePath(filePath)) {
    const reason = `VibeGuard blocked an AI read or edit of a credential-bearing path: ${filePath}. Inspect or change this file manually; never expose its contents to an agent.`;
    return { allow: false, reason, output: denyHook(reason, eventName) };
  }
  const content = firstString(input.content, input.new_string, input.newString, input.patch, payload.content);
  const patchTouchesAgentFile = /(?:^|[\\/])(?:SKILL|AGENTS(?:\.override)?|CLAUDE(?:\.local)?|GEMINI)\.md\b|(?:^|[\\/])(?:\.mcp|\.claude)\.json\b|(?:^|[\\/])\.(?:claude|codex)[\\/](?:settings|hooks|config|managed_config)/im.test(content);

  if ((filePath && isAgentControlPath(filePath)) || patchTouchesAgentFile) {
    const reason = `VibeGuard blocked an AI edit to ${filePath || 'an agent control file'}. Edit it manually, review every line, then trust its new hash.`;
    return { allow: false, reason, output: denyHook(reason, eventName) };
  }

  if (/configchange/i.test(eventName)) {
    const reason = 'VibeGuard blocked an unmanaged AI configuration change. Apply and review security configuration changes manually.';
    return { allow: false, reason, output: denyHook(reason, eventName) };
  }

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
