/**
 * Rule: git-history-secrets
 * Detects secrets that were committed in git history (even if later deleted).
 * Only runs when --deep flag is passed.
 *
 * Note: This rule uses a different approach — it runs git commands rather
 * than scanning file content. The check() receives a special file context
 * for the .git directory marker.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { execFileSync } from 'node:child_process';
import { dirname } from 'node:path';

const SECRET_INDICATORS = [
  /sk_live_[0-9a-zA-Z]{24,}/,
  /sk_test_[0-9a-zA-Z]{24,}/,
  /AIza[0-9A-Za-z_-]{35}/,
  /AKIA[0-9A-Z]{16}/,
  /sk-[A-Za-z0-9]{20}T3BlbkFJ/,
  /sk-proj-[A-Za-z0-9_-]{40,}/,
  /sk-ant-[A-Za-z0-9_-]{40,}/,
  /gh[pousr]_[A-Za-z0-9_]{36,}/,
  /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,
];

function redact(secret) {
  if (secret.length <= 12) return '***REDACTED***';
  return `${secret.slice(0, 4)}...(redacted)...${secret.slice(-4)}`;
}

/** @type {Rule} */
export const gitHistorySecrets = {
  id: 'git-history-secrets',
  name: 'Git History Secrets',
  severity: 'critical',
  description: 'Detects secrets committed in git history (requires --deep flag).',

  check(file) {
    // This rule only runs on the .gitignore file as a trigger — once per project
    if (file.relativePath !== '.gitignore') return [];

    // Check if we're in deep mode (set by the audit pipeline)
    if (!file._deepMode) return [];

    const findings = [];

    try {
      const projectDir = dirname(file.path);
      // Search recent git history for secret patterns (limit to last 50 commits for speed)
      const gitLog = execFileSync(
        'git',
        ['log', '--all', '-n', '50', '--diff-filter=D', '-p', '--', '*.env', '*.json', '*.js', '*.ts', '*.yaml', '*.yml'],
        { cwd: projectDir, encoding: 'utf-8', timeout: 10000 }
      );
      const truncatedLines = gitLog.split('\n').slice(0, 500).join('\n');

      for (const pattern of SECRET_INDICATORS) {
        const match = truncatedLines.match(pattern);
        if (match) {
          findings.push({
            ruleId: 'git-history-secrets',
            ruleName: 'Git History Secrets',
            severity: 'critical',
            message: `Secret found in git history: ${redact(match[0])}. Even deleted secrets remain in git history.`,
            file: '.git (history)',
            line: 0,
            evidence: redact(match[0]),
            fix: 'Rotate the compromised secret immediately. Use git-filter-repo or BFG Repo-Cleaner to remove it from history. Then force-push the cleaned history.',
          });
        }
      }
    } catch {
      // Git not available or command failed — skip silently
    }

    return findings;
  },
};
