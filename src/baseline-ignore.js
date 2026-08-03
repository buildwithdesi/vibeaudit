/**
 * Directories that are never production attack surface: test fixtures (often
 * deliberately vulnerable) and generated scan reports. Passed as `extraIgnore`
 * so a scan never silently depends on config resolution (local .vibe-audit.json
 * read, or fetchRemoteConfig() for GitHub-fetched scans) landing correctly —
 * these paths are excluded regardless of whether that resolution succeeds.
 *
 * Shared by bin/vibe-audit.js (self/local scans) and scripts/morning-scan.js
 * (batch GitHub scans) so both entry points can't drift out of sync.
 */
export const BASELINE_IGNORE = [
  'reports',
  'tests',
  'fixtures',
  '__tests__',
  '__fixtures__',
  // Claude Code keeps full working copies of the repo under .claude/worktrees/.
  // Scanning them reports every finding a second time, against a path that is
  // never deployed. Observed doubling content-drop's local finding count.
  '.claude',
];
