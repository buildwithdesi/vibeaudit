#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { analyzeAgentControlContent, isAgentControlPath } from '../src/guard/agent-files.js';
import { inspectAgentBaseline, trustCurrentAgentFiles, trustOneAgentFile } from '../src/guard/baseline.js';
import { analyzeCommand } from '../src/guard/command.js';
import { approveReviewCommand, consumeReviewApproval } from '../src/guard/approvals.js';
import { pilotCli } from '../src/guard/pilot-cli.js';
import { installCli } from '../src/precheck/install-cli.js';

const [commandName, ...rest] = process.argv.slice(2);
if (commandName === 'pilot') {
  process.exitCode = await pilotCli(rest);
} else if (commandName === 'npm') {
  process.exitCode = await installCli(rest);
} else {
const { values, positionals } = parseArgs({
  args: rest,
  allowPositionals: true,
  strict: true,
  options: {
    command: { type: 'string' },
    json: { type: 'boolean' },
    quiet: { type: 'boolean' },
    'i-reviewed-these-files': { type: 'boolean' },
    'i-reviewed-this-file': { type: 'boolean' },
  },
});

function print(value) {
  if (values.json) console.log(JSON.stringify(value, null, 2));
  else console.log(value);
}

function requireManualFlag(flag, message) {
  if (!values[flag]) throw new Error(message);
}

try {
  switch (commandName) {
    case 'check-command': {
      const analysis = analyzeCommand(values.command || positionals.join(' '));
      const approved = analysis.decision === 'review' && consumeReviewApproval(values.command || positionals.join(' '));
      if (!values.quiet) {
        print(values.json
          ? { ...analysis, approved }
          : approved
            ? 'APPROVED: Exact reviewed command allowed once.'
            : `${analysis.decision.toUpperCase()}: ${analysis.summary || 'No checked danger pattern found.'}`);
      }
      process.exitCode = analysis.decision === 'allow' || approved ? 0 : analysis.decision === 'review' ? 3 : 4;
      break;
    }
    case 'approve-command': {
      if (!process.stdin.isTTY || !process.stdout.isTTY) {
        throw new Error('approve-command requires a person at an interactive terminal.');
      }
      const prompt = createInterface({ input: process.stdin, output: process.stdout });
      try {
        const command = await prompt.question('Paste the exact command you independently verified: ');
        const analysis = analyzeCommand(command);
        if (analysis.decision === 'deny') {
          throw new Error(`Dangerous commands cannot be approved. ${analysis.summary}`);
        }
        if (analysis.decision !== 'review') {
          throw new Error('This command does not need approval.');
        }
        console.log(`\nVibeGuard review: ${analysis.summary}`);
        const confirmation = await prompt.question('Type VERIFIED SOURCE to allow this exact command once: ');
        if (confirmation !== 'VERIFIED SOURCE') throw new Error('Approval cancelled.');
        const approval = approveReviewCommand(command);
        console.log(`Approved once for this terminal. Expires at ${new Date(approval.expiresAt).toLocaleTimeString()}.`);
      } finally {
        prompt.close();
      }
      break;
    }
    case 'scan-agent-file': {
      const filePath = resolve(positionals[0] || '');
      if (!isAgentControlPath(filePath)) throw new Error(`${filePath} is not a recognized agent control file.`);
      const issues = analyzeAgentControlContent(readFileSync(filePath, 'utf8'), filePath);
      print(values.json ? { file: filePath, issues } : issues.length ? issues.map((issue) => `${issue.file}:${issue.line} ${issue.message}`).join('\n') : `No checked danger pattern found in ${filePath}.`);
      process.exitCode = issues.length ? 4 : 0;
      break;
    }
    case 'status': {
      const inspection = inspectAgentBaseline();
      print(values.json ? inspection : [
        `Baseline: ${inspection.baselineExists ? inspection.baselinePath : 'missing'}`,
        `Scanned: ${inspection.scanned}`,
        `New: ${inspection.added.length}`,
        `Changed: ${inspection.changed.length}`,
        `Suspicious: ${inspection.suspicious.length}`,
        `Errors: ${inspection.errors.length}`,
        ...inspection.suspicious.map((issue) => `${issue.severity.toUpperCase()}: ${issue.file}:${issue.line} ${issue.message}`),
        ...inspection.errors.map((error) => `ERROR: ${error}`),
        ...inspection.added.slice(0, 20).map((file) => `NEW: ${file}`),
        ...(inspection.added.length > 20 ? [`... ${inspection.added.length - 20} more new files. Use --json for the complete list.`] : []),
        ...inspection.changed.slice(0, 20).map((file) => `CHANGED: ${file}`),
        ...(inspection.changed.length > 20 ? [`... ${inspection.changed.length - 20} more changed files. Use --json for the complete list.`] : []),
      ].join('\n'));
      process.exitCode = inspection.ok ? 0 : 4;
      break;
    }
    case 'preflight': {
      const inspection = inspectAgentBaseline({ forceReview: true });
      const critical = inspection.suspicious.filter((issue) => issue.severity === 'critical');
      print(values.json ? inspection : [
        `Scanned: ${inspection.scanned}`,
        `Critical: ${critical.length}`,
        `Warnings: ${inspection.suspicious.length - critical.length}`,
        `Errors: ${inspection.errors.length}`,
        ...inspection.suspicious.map((issue) => `${issue.severity.toUpperCase()}: ${issue.file}:${issue.line} ${issue.message}`),
        ...inspection.errors.map((error) => `ERROR: ${error}`),
      ].join('\n'));
      process.exitCode = critical.length || inspection.errors.length ? 4 : inspection.suspicious.length ? 3 : 0;
      break;
    }
    case 'trust-current': {
      requireManualFlag('i-reviewed-these-files', 'Refusing to create a baseline until --i-reviewed-these-files is supplied after manual review.');
      const trusted = trustCurrentAgentFiles();
      const warnings = trusted.suspicious.filter((issue) => issue.severity === 'warning');
      print(values.json ? trusted : [
        ...warnings.map((issue) => `REVIEWED WARNING: ${issue.file}:${issue.line} ${issue.message}`),
        `Trusted ${trusted.trusted} reviewed agent control files.`,
      ].join('\n'));
      break;
    }
    case 'trust-file': {
      requireManualFlag('i-reviewed-this-file', 'Refusing to trust this file until --i-reviewed-this-file is supplied after manual review.');
      const filePath = positionals[0];
      if (!filePath) throw new Error('trust-file requires a file path.');
      const entry = trustOneAgentFile(filePath);
      print(values.json ? entry : [
        ...(entry.warnings || []).map((issue) => `REVIEWED WARNING: ${issue.file}:${issue.line} ${issue.message}`),
        `Trusted reviewed file: ${entry.path}`,
      ].join('\n'));
      break;
    }
    default:
      console.log(`VibeGuard\n\nCommands:\n  npm (protected npm installation; use npm --help)\n  pilot (offline protection pilot; use pilot --help)\n  check-command --command <text>\n  approve-command\n  scan-agent-file <path>\n  preflight [--json]\n  status [--json]\n  trust-current --i-reviewed-these-files\n  trust-file <path> --i-reviewed-this-file`);
      process.exitCode = commandName ? 2 : 0;
  }
} catch (error) {
  console.error(`VibeGuard: ${error.message}`);
  process.exitCode = 4;
}
}
