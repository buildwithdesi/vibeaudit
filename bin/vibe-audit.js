#!/usr/bin/env node

/**
 * vibe-audit CLI
 * Zero-dependency security scanner for AI-generated codebases.
 *
 * Usage:
 *   npx vibe-audit [directory] [options]
 *
 * Options:
 *   --format <terminal|json|markdown>  Output format (default: terminal)
 *   --rules <id,id,...>                Only run specific rules
 *   --exclude <id,id,...>              Exclude specific rules
 *   --strict                           Exit 1 on warnings too
 *   --list-rules                       Show available rules and exit
 *   --help                             Show help
 *   --version                          Show version
 */

import { resolve } from 'node:path';
import { stat } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline/promises';
import { audit } from '../src/index.js';
import { generateFixes } from '../src/fix.js';
import { ALL_RULES } from '../src/rules/index.js';
import { CWE_MAP } from '../src/data/cwe-map.js';
import { bold, cyan, dim, red, yellow, gray } from '../src/colors.js';

const green_ok = (t) => `[32m${t}[0m`;
import { parseGitHubTarget, fetchRepoFiles, resolveGitHubCommit } from '../src/github.js';
import { BASELINE_IGNORE } from '../src/baseline-ignore.js';
import { precheck } from '../src/precheck/index.js';
import { closeAndSetExitCode } from '../src/precheck/close-and-exit.js';
import { analyzeCommand } from '../src/guard/command.js';
import {
  createAgentIntegrityBaseline,
  scanAgentControlPlane,
  verifyAgentIntegrityBaseline,
} from '../src/guard/control-plane.js';
import {
  applySkillInstallPlan,
  createSkillInstallPlan,
  readSkillMarkdown,
} from '../src/skill.js';

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    format: { type: 'string', short: 'f' },
    rules: { type: 'string', short: 'r' },
    exclude: { type: 'string', short: 'e' },
    strict: { type: 'boolean', short: 's' },
    fix: { type: 'boolean' },
    'fix-file': { type: 'boolean' },
    'skip-sca': { type: 'boolean' },
    osv: { type: 'boolean' },
    'skip-osv': { type: 'boolean' },
    deep: { type: 'boolean' },
    'trust-target-config': { type: 'boolean' },
    baseline: { type: 'string' },
    command: { type: 'string' },
    stdin: { type: 'boolean' },
    'i-reviewed-these-files': { type: 'boolean' },
    only: { type: 'string' },
    gitleaks: { type: 'boolean' },
    'list-rules': { type: 'boolean' },
    precheck: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'v' },
  },
});

// ??? Help ?????????????????????????????????????????????????????????????????????

if (values.help) {
  console.log(`
${bold('??  vibe-audit')} ? Security scanner for AI-generated code

${bold('USAGE')}
  ${cyan('npx vibe-audit')} ${dim('[directory | github-url | owner/repo]')} ${dim('[options]')}

${bold('OPTIONS')}
  ${cyan('-f, --format')} <terminal|json|markdown|html>  Output format ${dim('(default: terminal)')}
  ${cyan('-r, --rules')}  <id,id,...>               Only run these rules
  ${cyan('-e, --exclude')} <id,id,...>               Skip these rules
  ${cyan('-s, --strict')}                            Exit 1 on warnings too
  ${cyan('--fix')}                                   Show copy-paste fix prompts + save VIBE-AUDIT-FIXES.md
  ${cyan('--fix-file')}                              Only save fix file (no terminal prompts)
  ${cyan('--skip-sca')}                              Skip dependency vulnerability scanning
  ${cyan('--osv')}                                   Explicitly enable the default OSV-Scanner pass
  ${cyan('--skip-osv')}                              Skip OSV only, while preserving npm dependency checks
  ${cyan('--deep')}                                  Enable deep scanning (git history secrets)
  ${cyan('--list-rules')}                            Show all available rules
  ${cyan('--precheck <pkg>')}                        Vet a package BEFORE installing it
  ${cyan('-h, --help')}                              Show this help
  ${cyan('-v, --version')}                           Show version
  ${cyan('--trust-target-config')}                   Apply the scanned repo's config and inline suppressions

${bold('AGENT SHIELD')}
  ${cyan('vibeaudit agent scan <backup>')}           Offline, fail-closed control-file scan
  ${cyan('  --gitleaks')}                            Add local secret scanning, fail if unavailable
  ${cyan('vibeaudit agent baseline <backup>')}       Save reviewed hashes outside the backup
  ${cyan('vibeaudit agent verify <backup>')}         Detect added, changed, or deleted controls
  ${cyan('vibeaudit command inspect --stdin')}       Inspect a pasted command without running it
  ${cyan('vibeaudit skill plan')}                    Verify publisher, transparency proof, hashes, and diffs
  ${cyan('vibeaudit skill install')}                 Reverify, confirm, write, and trust the official skill

${bold('EXAMPLES')}
  ${dim('# Audit current directory')}
  npx vibe-audit

  ${dim('# Audit a specific project')}
  npx vibe-audit ./my-app

  ${dim('# Audit a GitHub repo directly')}
  npx vibe-audit https://github.com/user/repo
  npx vibe-audit user/repo

  ${dim('# Get fix prompts for your AI tool')}
  npx vibe-audit --fix

  ${dim('# JSON output for CI pipelines')}
  npx vibe-audit --format json --strict

  ${dim('# Only check for secrets and auth')}
  npx vibe-audit --rules exposed-secrets,missing-auth

${bold('CONFIG')}
  Add ${cyan('.vibe-audit.json')} to your project root to set defaults.

${bold('RULES')}
  Run ${cyan('npx vibe-audit --list-rules')} to see all available rules.

${dim('Built by Digital Alchemy Academy ? https://digitalalchemy.dev')}
`);
  process.exit(0);
}

// ??? Version ??????????????????????????????????????????????????????????????????

if (values.version) {
  // Read version from package.json.
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const pkg = require('../package.json');
  console.log(pkg.version);
  process.exit(0);
}

// Agent Shield commands are isolated from the normal project scanner. They do
// not load configuration or suppression rules from the inspected target.
if (positionals[0] === 'agent') {
  const action = positionals[1];
  const target = positionals[2];
  try {
    if (!target) throw new Error(`agent ${action || '<action>'} requires a file or directory path.`);
    let report;
    if (action === 'scan') {
      report = scanAgentControlPlane(target, { externalTools: values.gitleaks ? ['gitleaks'] : [] });
      process.exitCode = report.decision === 'pass' ? 0 : report.decision === 'review' ? 3 : 4;
    } else if (action === 'baseline') {
      if (!values.baseline) throw new Error('agent baseline requires --baseline <outside-path>.');
      if (!values['i-reviewed-these-files']) {
        throw new Error('Refusing to save trusted hashes until --i-reviewed-these-files is supplied after manual review.');
      }
      report = createAgentIntegrityBaseline(target, values.baseline);
      process.exitCode = 0;
    } else if (action === 'verify') {
      if (!values.baseline) throw new Error('agent verify requires --baseline <path>.');
      report = verifyAgentIntegrityBaseline(target, values.baseline);
      process.exitCode = report.ok ? 0 : 4;
    } else {
      throw new Error('Unknown agent action. Use scan, baseline, or verify.');
    }
    if (values.format === 'json') console.log(JSON.stringify(report, null, 2));
    else if (action === 'scan') {
      console.log([
        `Decision: ${report.decision.toUpperCase()}`,
        `Scanned: ${report.coverage.scanned}`,
        `Coverage: ${report.coverage.complete ? 'complete' : 'incomplete'}`,
        ...report.findings.map((finding) => `${finding.severity.toUpperCase()}: ${finding.file}:${finding.line} ${finding.message}`),
        ...report.coverage.errors.map((error) => `ERROR: ${error}`),
        ...report.adapters.results.flatMap((adapter) => [
          `${adapter.tool}: ${adapter.status.toUpperCase()}${adapter.coverage.reason ? `, ${adapter.coverage.reason}` : ''}`,
          ...adapter.findings.map((finding) => `CRITICAL: ${finding.file}:${finding.startLine} ${finding.description} (${finding.ruleId})`),
        ]),
      ].join('\n'));
    } else if (action === 'baseline') {
      console.log(`Saved ${report.trusted} reviewed SHA-256 hashes to ${report.baselinePath}.`);
    } else {
      console.log([
        `Decision: ${report.decision.toUpperCase()}`,
        `Added: ${report.added.length}`,
        `Changed: ${report.changed.length}`,
        `Missing: ${report.missing.length}`,
        ...report.added.map((file) => `ADDED: ${file}`),
        ...report.changed.map((file) => `CHANGED: ${file}`),
        ...report.missing.map((file) => `MISSING: ${file}`),
        ...report.coverage.errors.map((error) => `ERROR: ${error}`),
      ].join('\n'));
    }
  } catch (error) {
    console.error(`Agent Shield: ${error.message}`);
    process.exitCode = 4;
  }
  process.exit(process.exitCode);
}

if (positionals[0] === 'command') {
  try {
    if (positionals[1] !== 'inspect') throw new Error('Unknown command action. Use command inspect.');
    let commandText = values.command || positionals.slice(2).join(' ');
    if (values.stdin) {
      let size = 0;
      const chunks = [];
      for await (const chunk of process.stdin) {
        size += Buffer.byteLength(chunk);
        if (size > 1024 * 1024) throw new Error('Command input exceeds the 1 MiB safety limit.');
        chunks.push(chunk);
      }
      commandText = chunks.join('');
    }
    if (!commandText.trim()) throw new Error('command inspect requires --stdin or --command <text>.');
    const report = analyzeCommand(commandText);
    if (values.format === 'json') console.log(JSON.stringify(report, null, 2));
    else console.log(`${report.decision.toUpperCase()}: ${report.summary || 'No checked danger pattern found.'}`);
    process.exit(report.decision === 'allow' ? 0 : report.decision === 'review' ? 3 : 4);
  } catch (error) {
    console.error(`Agent Shield: ${error.message}`);
    process.exit(4);
  }
}

if (positionals[0] === 'skill') {
  try {
    const action = positionals[1] || 'plan';
    if (action === 'print') {
      console.log(await readSkillMarkdown());
      process.exit(0);
    }
    const only = values.only?.split(',').map((value) => value.trim()).filter(Boolean) || [];
    const plan = await createSkillInstallPlan({ only });
    const visiblePlan = {
      sourcePath: plan.sourcePath,
      sourceHash: plan.sourceHash,
      sourceFindings: plan.sourceFindings,
      publisherVerification: {
        verified: plan.publisherVerification.verified,
        transparencyLogVerified: plan.publisherVerification.transparencyLogVerified,
        publisherIdentityPolicy: plan.publisherVerification.publisherIdentityPolicy,
        oidcIssuer: plan.publisherVerification.oidcIssuer,
        baseline: plan.publisherVerification.baseline,
      },
      targets: plan.targets.map((target) => ({
        id: target.id,
        displayName: target.displayName,
        installPath: target.installPath,
        action: target.action,
        beforeHash: target.beforeHash,
        sourceHash: plan.sourceHash,
        currentFindings: target.currentFindings || [],
        diff: target.diff,
      })),
    };
    if (values.format === 'json') console.log(JSON.stringify(visiblePlan, null, 2));
    else {
      console.log(`Publisher signature: VERIFIED`);
      console.log(`Transparency proof: VERIFIED`);
      console.log(`Publisher identity policy: ${visiblePlan.publisherVerification.publisherIdentityPolicy}`);
      console.log(`Packaged skill SHA-256: ${plan.sourceHash}`);
      for (const target of visiblePlan.targets) {
        console.log(`\n${target.displayName}: ${target.action.toUpperCase()}\nTarget: ${target.installPath}\nCurrent SHA-256: ${target.beforeHash || 'missing'}\nNew SHA-256: ${plan.sourceHash}`);
        for (const finding of target.currentFindings) {
          console.log(`${finding.severity.toUpperCase()}: ${finding.file}:${finding.line} ${finding.message}`);
        }
        if (target.diff) console.log(`\n${target.diff}`);
      }
    }
    if (action === 'plan' || action === 'status') process.exit(0);
    if (action !== 'install') throw new Error('Unknown skill action. Use plan, install, status, or print.');
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      throw new Error('skill install requires a person at an interactive terminal. Run skill plan first.');
    }
    const prompt = createInterface({ input: process.stdin, output: process.stdout });
    let confirmation;
    try {
      confirmation = await prompt.question(`\nType INSTALL ${plan.sourceHash} to apply this exact reviewed plan: `);
    } finally {
      prompt.close();
    }
    if (confirmation !== `INSTALL ${plan.sourceHash}`) throw new Error('Skill installation cancelled.');
    const results = await applySkillInstallPlan(plan, { confirmedSourceHash: plan.sourceHash });
    for (const result of results) {
      console.log(`${result.id}: ${result.status}${result.verifiedHash ? `, verified ${result.verifiedHash}` : ''}${result.backupPath ? `, backup ${result.backupPath}` : ''}`);
    }
    process.exit(0);
  } catch (error) {
    console.error(`Agent Shield installer: ${error.message}`);
    process.exit(4);
  }
}

// ??? List Rules ???????????????????????????????????????????????????????????????

if (values['list-rules']) {
  console.log('');
  console.log(bold('  ??  Available Rules'));
  console.log(dim('  ?????????????????????????????????????'));
  console.log('');

  for (const rule of ALL_RULES) {
    const sev =
      rule.severity === 'critical'
        ? red(bold('CRIT'))
        : rule.severity === 'warning'
          ? yellow('WARN')
          : cyan('INFO');

    const cwe = CWE_MAP[rule.id];
    const cweStr = cwe ? gray(` [${cwe.cweId}]`) : '';
    console.log(`  ${sev}  ${bold(rule.id)}${cweStr}`);
    console.log(`       ${dim(rule.description)}`);
    console.log('');
  }

  process.exit(0);
}

// ??? Pre-install Gate ?????????????????????????????????????????????????????????

if (values.precheck) {
  const spec = values.precheck;
  console.log('');
  console.log(bold(`  ??  Pre-install gate ? ${spec}`));
  console.log(dim('  Resolving the full dependency tree without installing it...'));

  let report;
  try {
    report = await precheck(spec);
  } catch (err) {
    console.error(red(`  Could not resolve ${spec}: ${err.message}`));
    await closeAndSetExitCode(2);
  }

  if (report) {
  console.log(dim(`  ${report.total} package(s) would be added.`));
  console.log('');

  for (const r of report.results.filter((x) => x.level !== 'ok')) {
    const tag = r.level === 'block' ? red(bold('BLOCK')) : yellow('WARN ');
    console.log(`  ${tag}  ${bold(r.name)}@${r.version}`);
    for (const reason of r.reasons) console.log(`         ${dim(reason)}`);
  }

  if (report.exitCode === 0) {
    console.log(green_ok('  No checked warning signs found. This does not prove the package is safe.'));
  } else if (report.exitCode === 1) {
    console.log('');
    console.log(yellow(`  ${report.warned.length} package(s) worth a look. Not blocking.`));
  } else {
    console.log('');
    console.log(red(bold(`  DO NOT INSTALL ? ${report.blocked.length} package(s) failed the gate.`)));
  }
  console.log('');
  await closeAndSetExitCode(report.exitCode);
  }
} else {

// ??? Run Audit ????????????????????????????????????????????????????????????????

const rawTarget = positionals[0] || '.';

const cliOptions = {
  format: values.format,
  rules: values.rules?.split(',').filter(Boolean),
  exclude: values.exclude?.split(',').filter(Boolean),
  strict: values.strict,
  skipSca: values['skip-sca'],
  osv: values['skip-osv'] ? false : values.osv,
  deep: values.deep,
  trustTargetConfig: values['trust-target-config'],
  // Baseline ignore, always applied on top of resolved config ? matches scripts/morning-scan.js
  // so a self-scan never depends on .vibe-audit.json being read/resolved correctly to exclude
  // reports/ and test fixtures.
  extraIgnore: BASELINE_IGNORE,
};

let targetDir;

try {
  // Detect GitHub repo vs local directory.
  const gh = parseGitHubTarget(rawTarget);

  if (gh) {
    // GitHub mode ? fetch files directly via API, no clone needed.
    const label = `${gh.owner}/${gh.repo}`;
    // stderr ? keep stdout clean for --format json pipelines
    console.error(cyan(`\n  ??  Scanning GitHub repo: ${label}\n`));
    targetDir = `github://${label}`;
    const snapshot = await resolveGitHubCommit(gh.owner, gh.repo);
    cliOptions.remoteRef = snapshot;
    cliOptions.fileSource = fetchRepoFiles(gh.owner, gh.repo, { commitSha: snapshot });
    cliOptions.skipSca = true; // SCA needs local package-lock.json, skip for remote
  } else {
    targetDir = resolve(rawTarget);

    // Verify the local directory exists.
    try {
      const s = await stat(targetDir);
      if (!s.isDirectory()) {
        console.error(red(`\n  Error: ${targetDir} is not a directory\n`));
        process.exit(2);
      }
    } catch {
      console.error(red(`\n  Error: Directory not found ? ${targetDir}\n`));
      console.error(dim(`  If this is a GitHub repo, use the full URL or owner/repo shorthand:\n`));
      console.error(dim(`    npx vibe-audit https://github.com/owner/repo`));
      console.error(dim(`    npx vibe-audit owner/repo\n`));
      process.exit(2);
    }
  }

  const { findings, exitCode } = await audit(targetDir, cliOptions);

  // Fix mode: generate prompts after the normal report
  if (values.fix || values['fix-file']) {
    const fixMode = values['fix-file'] ? 'file' : 'all';
    await generateFixes(findings, targetDir, fixMode);
  }

  process.exit(exitCode);
} catch (err) {
  console.error(red(`\n  Error: ${err.message}\n`));
  process.exit(2);
}
}
