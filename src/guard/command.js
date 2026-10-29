/**
 * Classify a command before a human shell or AI agent executes it.
 *
 * This is intentionally conservative around the incident shape: unverified
 * network content crossing directly into an interpreter. It is a guardrail,
 * not proof that every command marked "allow" is safe.
 */

const URL_RE = /https?:\/\/[^\s'"`)]+/i;
const DOWNLOAD_TOOL_RE = /\b(?:curl(?:\.exe)?|wget(?:\.exe)?|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|downloadstring)\b/i;
const INTERPRETER_RE = /\b(?:sh|bash|zsh|fish|pwsh|powershell(?:\.exe)?|iex|invoke-expression|python(?:3)?|node|cmd(?:\.exe)?|ruby|perl|osascript)\b/i;
const REMOTE_PROCESS_SUBSTITUTION_RE = /\b(?:sh|bash|zsh|fish|pwsh|powershell(?:\.exe)?|python(?:3)?|node|ruby|perl)\b\s+<\s*\(\s*(?:curl(?:\.exe)?|wget(?:\.exe)?|iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b/i;
const REMOTE_EVAL_RE = /\b(?:source|eval|iex|invoke-expression)\b[^\r\n]{0,180}(?:<\s*\(\s*)?(?:curl(?:\.exe)?|wget(?:\.exe)?|iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b/i;
const EXECUTABLE_DOWNLOAD_RE = /\.(?:exe|msi|msix|dll|scr|com|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|sh|bash|zsh|py|zip|rar|7z|tar|tgz|gz)(?:[?#\s'"`]|$)/i;
const CREDENTIAL_TARGET_RE = /(?:\.ssh|\.aws|\.azure|\.npmrc|\.pypirc|\.env\b|login data|local state|cookies|keychain|credential|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|process\.env|os\.(?:environ|getenv)|printenv|\benv\b|\$env:|%appdata%|\\appdata\\)/i;
const NETWORK_SEND_RE = /\b(?:curl|wget|invoke-webrequest|invoke-restmethod|irm|iwr|fetch|requests?\.(?:post|put)|webclient|uploadfile|scp|sftp|nc|ncat)\b/i;
const GUARD_STATE_RE = /(?:\.vibeaudit[\\/](?:agent-baseline|command-approvals)\.json|[\\/]vibeaudit[\\/]guard[\\/])/i;
// PowerShell aliases (ri, rd, sc, ac, ren, rni, mi, cpi, cli) run the same cmdlets as their long names.
const FILE_MUTATION_RE = /\b(?:remove-item|set-content|add-content|out-file|move-item|copy-item|rename-item|clear-item|del|erase|rm|mv|cp|unlink|writefilesync|writefile|rename|rmdir|ri|rd|sc|ac|ren|rni|mi|cpi|cli)\b|(?:>>|>)/i;
const AGENT_CONTROL_TARGET_RE = /(?:[\\/]?)(?:SKILL|AGENTS(?:\.override)?|CLAUDE(?:\.local)?|GEMINI)\.md\b|(?:[\\/]?)(?:\.mcp|\.claude)\.json\b|(?:[\\/]?)\.(?:claude|codex)[\\/](?:settings|hooks|config|managed_config)(?:\.|[\\/]|$)/i;
const AGENT_CONTROL_WRITE_RE = /(?:\b(?:set-content|add-content|out-file|remove-item|move-item|copy-item|rename-item|clear-item|del|erase|rm|mv|cp|unlink|writefilesync|writefile|write_text|write_bytes|sed\s+-i|perl\s+-i|tee|git\s+(?:checkout|restore|apply|mv|rm))\b|\bopen\s*\([^\r\n]{0,220}(?:['\"][wax][b+]?['\"]|mode\s*=\s*['\"][wax])|(?:>>|>))/i;
// Short aliases that write files: Set-Content, Add-Content, Remove-Item, Rename-Item, Move-Item,
// Copy-Item, Clear-Item, and cmd's copy and move. In a command they count anywhere.
const AGENT_CONTROL_ALIAS_RE = /\b(?:ri|rd|sc|ac|ren|rni|mi|cpi|cli|move|copy)\b/i;
// In a document (an AGENTS.md or SKILL.md being scanned) the same aliases are also ordinary words:
// "the CLI", "copy the file". Matched anywhere, they flagged every AGENTS.md that mentions its CLI
// and links a SKILL.md. So there they count only as the command word, on a line that also names
// an agent control file.
const AGENT_CONTROL_ALIAS_COMMAND_RE = /(?:^|[;&|({`'"=@,!]|\$\(|\b(?:do|then|else|call|if|exec)\s|\bexist\s+\S+\s|\b(?:powershell|pwsh|cmd)(?:\.exe)?\s|(?:^|\s)(?:-c|-command|\/c|\/k)\s)\s*(?:ri|rd|sc|ac|ren|rni|mi|cpi|cli|move|copy)(?=[\s\/,;="'|&)]|$)/i;
// A backtick, backslash or caret at the end of a line continues the command on the next line.
const LINE_CONTINUATION_RE = /[`\\^][ \t]*\r?\n/g;
const HIGH_IMPACT_COMMAND_RE = /(?:\bgit\s+(?:commit|push|tag)\b|\b(?:npm|pnpm|yarn|bun)(?:\.cmd)?\s+publish\b|\b(?:vercel|netlify|railway|wrangler)(?:\.cmd)?\s+(?:deploy|up|publish)\b|\bgh(?:\.exe)?\s+(?:api|gist\s+(?:create|edit)|release\s+(?:create|upload))\b|\b(?:curl|wget|invoke-webrequest|invoke-restmethod|irm|iwr)\b[^\r\n]{0,180}(?:-X|--request)\s*(?:POST|PUT|PATCH|DELETE)\b)/i;
const DESTRUCTIVE_COMMAND_RE = /(?:\b(?:rm|remove-item|rmdir|del|erase|ri|rd)\b[^\r\n]{0,120}(?:-rf|-fr|-r\b|--recursive|--force|-recurse\b|-force\b|\/s\b|\/q\b)|\b(?:format|diskpart|shutdown|stop-computer|restart-computer|taskkill)\b[^\r\n]{0,120}(?:\/f|-force|-y)\b)/i;
const CREDENTIAL_COMMAND_RE = /(?:\b(?:hf|gh|aws|az|gcloud|vercel|npm|docker)\b[\s-]*(?:auth\s+(?:(?:application-default\s+)?(?:token|print-access-token))|token\s+(?:view|print|get|create|list)|get-(?:access-)?token|credentials?|env\s+pull)\b|\bnpm\b[^\r\n]{0,100}\bconfig\s+get\b[^\r\n]{0,100}(?:auth[_-]?token|password)\b|\bgit\s+credential\s+fill\b|\b(?:cmdkey\s+\/list|vaultcmd\b[^\r\n]{0,30}\/list|security\s+find-generic-password)\b)/i;
const ENV_OUTPUT_RE = /\b(?:printenv|set|env)\b[^\r\n]{0,120}\b(?:key|token|secret|password|credential)\b/i;
const ENV_VARIABLE_OUTPUT_RE = /\b(?:echo|printf|print|write-output|write-host)\b[^\r\n]{0,120}(?:\$(?:env:)?[a-z0-9_]*(?:key|token|secret|password|credential)|%[a-z0-9_]*(?:key|token|secret|password|credential)%)/i;
const ENV_DUMP_RE = /(?:\bprintenv\b|\b(?:set|env)\s*$|\b(?:get-childitem|gci|dir)\s+env:|\bset\s+env:)/i;
const ENV_OBJECT_OUTPUT_RE = /(?:\b(?:console\.log|print|printf|echo|write-output|write-host)\b[^\r\n]{0,160}\b(?:process\.env|os\.environ|environment\.getenvironmentvariables)\b|\b(?:process\.env|os\.environ|environment\.getenvironmentvariables)\b[^\r\n]{0,160}\b(?:console\.log|print|printf|echo|write-output|write-host)\b)/i;
const SECRET_FILE_READ_RE = /\b(?:cat|type|more|gc|get-content|read-file|open|readfile|readfilesync|read_text|read_bytes)\b[^\r\n]{0,260}(?:[\\/](?:\.env(?:\.[a-z0-9_-]+)?|\.npmrc|\.pypirc|\.git-credentials|\.aws[\\/](?:credentials|config)|\.azure[\\/]|\.config[\\/](?:gh|gcloud)[\\/]|\.ssh[\\/](?:id_(?:rsa|dsa|ecdsa|ed25519)|known_hosts)|id_(?:rsa|dsa|ecdsa|ed25519)|credentials(?:\.(?:json|jsonl|txt|db|sqlite|yaml|yml|ini|toml))?|secrets?(?:\.(?:json|jsonl|txt|db|sqlite|yaml|yml|ini|toml))?|tokens?(?:\.(?:json|jsonl|txt|db|sqlite|yaml|yml|ini|toml))?|login\s+data|local\s+state|cookies)|(?:^|[\s'\"(])\.env(?:\.[a-z0-9_-]+)?(?:\s|$|['\"])|(?:^|[\s'\"(])(?:credentials?|secrets?|tokens?)\.(?:json|jsonl|txt|db|sqlite|yaml|yml|ini|toml)(?:\s|$|['\"]))/i;
const EXECUTION_POLICY_BYPASS_RE = /(?:\b(?:powershell|pwsh)\b[^\r\n]{0,180}-(?:executionpolicy|ep)\s+(?:bypass|unrestricted)\b|\bset-executionpolicy\b[^\r\n]{0,120}\b(?:bypass|unrestricted)\b)/i;
const AGENT_INSTALL_RE = /(?:\bnpx(?:\.cmd)?\b[^\r\n]{0,240}\b(?:add-plugin|add-skill|install-plugin|install-skill)\b|\bhf(?:\.exe)?\s+skills?\s+(?:add|install|update|upgrade)\b|\b(?:claude|codex)\b[^\r\n]{0,120}\b(?:plugin|skill)\s+(?:add|install|update|upgrade)\b|\b(?:gh|npm|pnpm|yarn|bun)\b[^\r\n]{0,180}\b(?:extension|plugin|skill)\s+(?:install|add|update|upgrade)\b)/i;
const EXTERNAL_REPO_RE = /\b(?:git\s+clone|git\s+remote\s+add)\b[^\r\n]{0,240}https?:\/\//i;

function result(decision, findings = []) {
  return {
    decision,
    findings,
    summary: findings.map((finding) => finding.message).join(' '),
  };
}

function finding(id, message) {
  return { id, message };
}

/**
 * @param {unknown} value
 * @returns {string}
 */
export function normalizeCommand(value) {
  return String(value ?? '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, ' ')
    .replace(/[\u2028\u2029]/g, '\n')
    .trim();
}

/**
 * Undo quoting tricks that split a keyword without changing what the shell runs:
 * c''url and c"u"rl (POSIX quotes), c\url (POSIX escape), c`url (PowerShell), c^url (cmd),
 * and shell expansions wedged into a word such as c$@url, c"$@"url, c${x}url or c$(echo)url.
 * Every expansion inside a word is removed, whether or not it is really empty. The caller keeps
 * whichever reading is stricter, so removing a non-empty one can only make the verdict stricter.
 * @param {string} command
 * @returns {string}
 */
export function deobfuscateCommand(command) {
  return collapseWordTricks(command, false);
}

/**
 * @param {string} command
 * @param {boolean} dropBacktickBlocks Also remove `...` substitutions. PowerShell uses a lone
 *   backtick as an escape (i`ex), so this runs as a separate reading, not as part of the main one.
 */
function collapseWordTricks(command, dropBacktickBlocks) {
  let current = command;
  // Repeat until stable, because tricks can be stacked (c$@''url) and nested (c$(echo $(true))url).
  // No pass limit: every pass that changes the string makes it shorter, so this always ends,
  // and a limit would let deep enough nesting leave an expansion in place.
  for (;;) {
    let next = current.replace(WORD_EXPANSION_RE, '');
    if (dropBacktickBlocks) next = next.replace(WORD_BACKTICK_BLOCK_RE, '');
    next = next
      .replace(WORD_QUOTE_RUN_RE, (run) => (isEmptyQuotePairs(run) ? '' : run))
      .replace(/(?<=\w)['"`^\\]+(?=\w)/g, '');
    if (next === current) return current;
    current = next;
  }
}

/**
 * True when a run of quotes is only empty pairs ('' or ""), which the shell drops.
 * A check in code instead of /^(?:''|"")+$/, which works the same but trips the
 * repo's own regex-dos rule and fails the strict self-scan.
 * @param {string} run
 */
function isEmptyQuotePairs(run) {
  if (run.length % 2 !== 0) return false;
  for (let i = 0; i < run.length; i += 2) {
    if (run[i] !== run[i + 1]) return false;
  }
  return true;
}

/**
 * @param {string} command
 * @param {boolean} isDocument
 */
function writesAgentControlByAlias(command, isDocument) {
  if (!isDocument) return AGENT_CONTROL_ALIAS_RE.test(command);
  return command
    .replace(LINE_CONTINUATION_RE, ' ')
    .split(/\r?\n/)
    .some((line) => AGENT_CONTROL_TARGET_RE.test(line) && AGENT_CONTROL_ALIAS_COMMAND_RE.test(line));
}

// An expansion touching a word, a quote or an escape on its right (c$(echo)\url),
// and a word, a quote or a separator on its left.
// Innermost $(...) first, so nested substitutions peel off one pass at a time.
const WORD_EXPANSION_RE = /(?<=\w|^|[\s;|&("'])(?:\$[@*#?!$0-9]|\$\{[^{}]*\}|\$\([^()]*\))+(?=\w|["')\\`^])/g;
const WORD_BACKTICK_BLOCK_RE = /(?<=\w|^|[\s;|&("'])`[^`\n]*`(?=\w|["'\\^])/g;
// A run of quotes between a separator and a word (c''url). Dropped only when it is all empty pairs.
const WORD_QUOTE_RUN_RE = /(?<=\w|^|[\s;|&(])['"]+(?=\w)/g;

const DECISION_RANK = { allow: 0, review: 1, deny: 2 };

/**
 * @param {unknown} input
 * @param {{source?: 'command'|'document'}} [options] Use source 'document' when the input is a whole
 *   file being scanned (an AGENTS.md or SKILL.md) rather than one command about to run.
 * @returns {{decision:'allow'|'review'|'deny', findings:Array<{id:string,message:string}>, summary:string}}
 */
export function analyzeCommand(input, options = {}) {
  const command = normalizeCommand(input);
  if (!command) return result('allow');
  const isDocument = options.source === 'document';

  // Check the command as written and with each set of tricks removed, and keep the strictest verdict.
  const direct = analyzeNormalized(command, isDocument);
  let strictest = direct;
  const readings = new Set([collapseWordTricks(command, false), collapseWordTricks(command, true)]);
  readings.delete(command);
  for (const reading of readings) {
    const verdict = analyzeNormalized(reading, isDocument);
    if (DECISION_RANK[verdict.decision] > DECISION_RANK[strictest.decision]) strictest = verdict;
  }
  if (strictest === direct) return direct;
  return result(strictest.decision, strictest.findings.map((item) => finding(
    item.id,
    `${item.message} Quoting or a shell expansion was used to hide a command name.`,
  )));
}

/**
 * @param {string} command
 * @param {boolean} isDocument
 */
function analyzeNormalized(command, isDocument) {
  const findings = [];

  if (GUARD_STATE_RE.test(command) && FILE_MUTATION_RE.test(command)) {
    findings.push(finding(
      'guard-tampering',
      'The command attempts to modify VibeGuard state or runtime files.',
    ));
  }

  const downloadToInterpreter = new RegExp(
    `${DOWNLOAD_TOOL_RE.source}[\\s\\S]{0,1200}(?:\\||\\|&)[\\s\\S]{0,160}${INTERPRETER_RE.source}`,
    'i',
  );
  const interpreterPullsRemote = new RegExp(
    `${INTERPRETER_RE.source}[\\s\\S]{0,500}(?:-c|/c)[\\s\\S]{0,800}${DOWNLOAD_TOOL_RE.source}`,
    'i',
  );
  if ((URL_RE.test(command) && downloadToInterpreter.test(command)) || interpreterPullsRemote.test(command) || REMOTE_PROCESS_SUBSTITUTION_RE.test(command) || REMOTE_EVAL_RE.test(command)) {
    findings.push(finding(
      'remote-content-execution',
      'Remote content is being sent directly into an interpreter.',
    ));
  }

  if (/\b(?:powershell|pwsh)(?:\.exe)?\b[\s\S]{0,500}\s-(?:e|en|enc|enco|encod|encode|encodedcommand)\b/i.test(command)) {
    findings.push(finding(
      'encoded-powershell',
      'Encoded PowerShell hides the instructions that would execute.',
    ));
  }

  if (/\b(?:iex|invoke-expression)\b[\s\S]{0,600}\b(?:irm|iwr|invoke-restmethod|invoke-webrequest|downloadstring)\b/i.test(command) ||
      /\b(?:irm|iwr|invoke-restmethod|invoke-webrequest|downloadstring)\b[\s\S]{0,600}\b(?:iex|invoke-expression)\b/i.test(command)) {
    findings.push(finding(
      'powershell-download-execute',
      'PowerShell downloads text and executes it without a review step.',
    ));
  }

  if (URL_RE.test(command) &&
      /\b(?:python(?:3)?|node|ruby|perl)\b/i.test(command) &&
      /\b(?:requests?\.get|urllib|fetch|https?\.get)\b/i.test(command) &&
      /\b(?:exec|eval|function)\b/i.test(command)) {
    findings.push(finding(
      'language-download-execute',
      'A language one-liner downloads remote content and evaluates it as code.',
    ));
  }

  const lolbinPatterns = [
    /\bmshta(?:\.exe)?\b[\s\S]{0,500}(?:https?:\/\/|javascript:)/i,
    /\bregsvr32(?:\.exe)?\b[\s\S]{0,500}\/(?:i|u):?[^\r\n]*https?:\/\//i,
    /\brundll32(?:\.exe)?\b[\s\S]{0,500}(?:javascript:|https?:\/\/)/i,
    /\bcertutil(?:\.exe)?\b[\s\S]{0,500}-(?:urlcache|decode)\b/i,
    /\bbitsadmin(?:\.exe)?\b[\s\S]{0,500}\/(?:transfer|addfile)\b[\s\S]{0,500}https?:\/\//i,
  ];
  if (lolbinPatterns.some((pattern) => pattern.test(command))) {
    findings.push(finding(
      'windows-proxy-execution',
      'A Windows system utility is being used to download or proxy code execution.',
    ));
  }

  if (CREDENTIAL_TARGET_RE.test(command) && NETWORK_SEND_RE.test(command)) {
    findings.push(finding(
      'credential-exfiltration',
      'The command combines credential locations with outbound network access.',
    ));
  }

  if (CREDENTIAL_COMMAND_RE.test(command) || ENV_OUTPUT_RE.test(command) || ENV_VARIABLE_OUTPUT_RE.test(command) || ENV_DUMP_RE.test(command) || ENV_OBJECT_OUTPUT_RE.test(command) || SECRET_FILE_READ_RE.test(command)) {
    findings.push(finding(
      'credential-output',
      'The command would print or expose a credential, token, or secret-bearing file.',
    ));
  }

  if (AGENT_CONTROL_TARGET_RE.test(command) && (AGENT_CONTROL_WRITE_RE.test(command) || writesAgentControlByAlias(command, isDocument))) {
    findings.push(finding(
      'agent-control-tampering',
      'The command attempts to write, restore, or remove an agent control file. Change agent instructions only through a reviewed manual edit.',
    ));
  }

  if (HIGH_IMPACT_COMMAND_RE.test(command)) {
    findings.push(finding(
      'high-impact-action',
      'The command publishes, deploys, pushes, or mutates external state. Run it manually after reviewing the exact target and data scope.',
    ));
  }

  if (DESTRUCTIVE_COMMAND_RE.test(command)) {
    findings.push(finding(
      'destructive-file-operation',
      'The command performs a recursive, forced, or system-destructive operation that requires a human decision.',
    ));
  }

  if (EXECUTION_POLICY_BYPASS_RE.test(command)) {
    findings.push(finding(
      'execution-policy-bypass',
      'The command disables PowerShell execution-policy protections and needs explicit review.',
    ));
  }

  const chainedExecution = new RegExp(
    `${DOWNLOAD_TOOL_RE.source}[\\s\\S]{0,1200}${URL_RE.source}[\\s\\S]{0,500}(?:;|&&|\\|&|\\r?\\n)[\\s\\S]{0,300}(?:start-process|chmod\\s+\\+x|${INTERPRETER_RE.source}|\\.\\\\|\\.\\/)`,
    'i',
  );
  if (chainedExecution.test(command)) {
    findings.push(finding(
      'download-then-execute',
      'The command downloads a file and executes it in the same command chain.',
    ));
  }

  if (findings.length > 0) return result('deny', findings);

  if (AGENT_INSTALL_RE.test(command)) {
    return result('review', [finding(
      'agent-install',
      'The command installs or updates an agent skill, plugin, or extension. Verify the publisher, exact source, and files before allowing it.',
    )]);
  }

  if (EXTERNAL_REPO_RE.test(command)) {
    return result('review', [finding(
      'external-repository',
      'The command clones or adds an external repository. Review its agent files and install scripts before using it.',
    )]);
  }

  if (DOWNLOAD_TOOL_RE.test(command) && URL_RE.test(command) && EXECUTABLE_DOWNLOAD_RE.test(command)) {
    return result('review', [finding(
      'unverified-executable-download',
      'The command downloads an executable, script, or archive that needs source and signature verification.',
    )]);
  }

  if (/\b(?:npm|pnpm|yarn|bun|pip(?:3)?|pipx|python(?:3)?\s+-m\s+pip|gem|cargo|go|winget|choco|scoop|brew|apt(?:-get)?|dnf|dotnet\s+tool)(?:\.exe|\.cmd|\.ps1)?\b["']?\s+[\s\S]{0,120}\b(?:install|add|get|ci|update|upgrade)\b/i.test(command) ||
      /\b(?:install-module|install-script|install-package|update-module|npx|pnpx|bunx|uvx)\b/i.test(command)) {
    return result('review', [finding(
      'package-install',
      'A package install can execute third-party lifecycle code and needs a pre-install review.',
    )]);
  }

  return result('allow');
}
