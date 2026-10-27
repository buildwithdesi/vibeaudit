# Contributing to Vibe Audit

Start in the Git checkout containing `package.json` and `src/`.
The [agent instructions](AGENTS.md) map the code and security boundaries.

## Adding a New Rule

Every rule lives in `src/rules/` and follows the same interface:

```js
export const yourRule = {
  id: 'your-rule-id',        // kebab-case, unique
  name: 'Your Rule Name',    // Human-readable
  severity: 'critical',      // 'critical' | 'warning' | 'info'
  description: 'What this rule checks for.',
  check(file) {
    // file = { path, relativePath, content, lines }
    // Return an array of findings (see src/rules/types.js)
    return [];
  },
};
```

Then register it in `src/rules/index.js`.

## Rules for Rules

1. **Zero false positives over catching everything.** A rule that cries wolf gets disabled.
2. **Skip comments and documentation.** Don't flag `// TODO: add auth` as a missing auth issue.
3. **Redact secrets in evidence.** Never put the full secret in the finding output.
4. **Every finding needs a fix.** Tell the user exactly what to do, not just what's wrong.
5. **Write tests.** Every rule needs test cases for both detection and non-detection.

## Development

Use Node >=18.19.0. CI exercises Node 18, 20, and 22 on Linux.
The shared source gate also runs on Windows with Node 22.
Dependencies are not assumed to be installed. This project has no build step,
web server, or database to start.

```bash
# Install dev dependencies
npm ci --ignore-scripts

# Shared source gate: official skill baseline, lint, and all tests
npm run verify
```

Run the checkout directly with `node bin/vibe-audit.js <target> [options]`.
Use an absolute path or a `./` prefix for local targets containing a slash;
otherwise `owner/repo` syntax selects GitHub scanning.
For a local scan without dependency-service calls, add `--skip-sca`.
No credentials are needed for the source gate. Remote scans use `GITHUB_TOKEN`
or `GH_TOKEN` from an account authorized to read the selected repositories.
The scheduled workflow supplies that token through its `SCAN_TOKEN` secret.
Never copy token values into fixtures, reports, or commits.

## Verification

`package.json` owns the source gate commands. CI and the prepublish hook call
`npm run verify`; keep them aligned by changing that script once.

| Changed behavior | Additional evidence |
|---|---|
| Detection or scan configuration | Positive and negative fixtures, then `npm run audit:self` |
| CLI or reports | Invoke the CLI on a temporary fixture; assert exit status and read the generated output |
| Protected npm installation | `npm run test:install` (also in `verify`) exercises real offline npm with signed fixture archives; live registry resolution and OSV require a separate disposable-project run |
| Agent controls or packaged skill | `npm run benchmark:agent -- --strict`; never execute fixture instructions |
| Protection pilot | `npm run test:pilot` with a running local Linux Docker engine and a pre-pulled `VIBEGUARD_PILOT_IMAGE` digest; see the [pilot guide](docs/protection-pilot.md) |
| Morning scan or its workflow | `node --test tests/morning-scan.test.js tests/morning-scan-runner.test.js` |
| External adapter, approval, or publishing | Relevant adapter tests plus explicit disclosure of any service or release step not exercised |

`npm run audit:self` uses this checkout's reviewed config in strict mode. It skips
OSV but still invokes npm dependency analysis, so it is not an offline test.
CI runs the same strict self-scan with this repository's reviewed config,
plus independent Gitleaks and pinned OSV checks. Ordinary target scans still
ignore target-controlled exclusions and suppressions unless explicitly trusted.
Passing the local source gate does not prove those external jobs passed.

For the portfolio scan, use `npm run scan:morning -- --top 1` with authorized
GitHub access. It reads `scripts/repos.json`, runs the scanner, and validates
fresh JSON and Markdown reports under `reports/morning-run-*/`.
Findings do not fail this command. Crashes, invalid reports, and zero scanned
repositories do. Partial coverage remains visible in the report and is allowed
by the existing scheduled-scan policy; success is not a claim of full coverage.
The scanner runs concurrent batches in one process, without a queue or database.
GitHub Actions schedules the run and retains report artifacts.

## Skills

The checkout's [verify-change skill](.agents/skills/verify-change/SKILL.md) applies
these verification rules to a specific change. Read it when implementing or
finishing work. It points here rather than maintaining another command list.
Load other installed skills only for their stated purpose. For example, an
interactive issue-filing QA skill does not replace regression verification.

## Pull Request Process

1. Fork and create a feature branch.
2. State the observable outcome and trace the affected CLI/API, scanner, report,
   persistence, and external-tool path. Mark absent layers as not applicable.
3. Add regression coverage for changed logic. Run `npm run verify` and the
   relevant checks above. Read expected outputs; report failures honestly.
4. Review the diff for unrelated edits and secrets. Describe what changed,
   the outcome exercised, mocked or unverified boundaries, and blocking defects.
   Keep optional improvements outside the current scope. Auth or upload changes
   must explicitly confirm authorization checks in the PR description.
5. Keep one owner responsible through integration. Stop when this scope is
   verified; merging, deploying, and publishing need separate authorization.

## Dependency policy

The scanner uses `acorn` and `acorn-loose` for JavaScript parsing. Check existing
code and Node built-ins before adding a library or custom integration.

## Release

Publishing is controlled by `.github/workflows/ci.yml`, including required scan
jobs, matching version tags, the `npm-publish` environment, and signed skill
assets. A local verification pass does not authorize creating a release tag.

## Code of Conduct

Be respectful. We're all here to make the ecosystem safer. No gatekeeping, no elitism. If someone's first PR isn't perfect, help them improve it.
