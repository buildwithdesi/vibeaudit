/**
 * Rule: unpinned-dependencies
 * Detects dependencies pinned to a moving target — `*`, `latest`, or `x`. `npm install`
 * then pulls whatever's newest, so a breaking change (or a compromised release) lands in
 * your build with no review. AI scaffolds `"react": "latest"` constantly.
 *
 * Only flags the truly-wild ranges. Caret/tilde (`^1.2.3`, `~1.2.3`) and exact pins are
 * standard practice and NOT flagged — that would be noise.
 */

/** @typedef {import('./types.js').Rule} Rule */

const PKG_JSON = /(?:^|\/)package\.json$/;
// Fully unpinned: any version at all.
const WILD = /^(?:\*|latest|x|X|)$/;

/** @type {Rule} */
export const unpinnedDependencies = {
  id: 'unpinned-dependencies',
  name: 'Unpinned Dependencies',
  severity: 'warning',
  description: 'Detects dependencies pinned to `*` / `latest` / `x` — npm pulls whatever is newest, so a breaking or compromised release lands with no review.',

  check(file) {
    if (!PKG_JSON.test(file.relativePath)) return [];

    let pkg;
    try {
      pkg = JSON.parse(file.content);
    } catch {
      return [];
    }

    const findings = [];
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      const deps = pkg[field];
      if (!deps || typeof deps !== 'object') continue;
      for (const [name, range] of Object.entries(deps)) {
        if (typeof range !== 'string' || !WILD.test(range.trim())) continue;
        // Find the line for a useful pointer.
        const idx = file.lines.findIndex((l) => l.includes(`"${name}"`));
        findings.push({
          ruleId: 'unpinned-dependencies',
          ruleName: 'Unpinned Dependencies',
          severity: 'warning',
          message: `"${name}" is pinned to "${range || '(empty)'}" — npm installs whatever is newest, so a breaking or compromised release lands in your build with no review.`,
          file: file.relativePath,
          line: idx >= 0 ? idx + 1 : 1,
          evidence: idx >= 0 ? file.lines[idx].trim().slice(0, 120) : undefined,
          fix: `Pin "${name}" to a real range: "^1.2.3" (compatible updates) or an exact "1.2.3". Commit your lockfile so installs are reproducible. Never ship "*" or "latest".`,
        });
      }
    }
    return findings;
  },
};
