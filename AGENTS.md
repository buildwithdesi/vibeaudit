# Working on VibeAudit

VibeAudit is a Node.js ESM security scanner. Its interfaces are the `vibeaudit`
and `vibeguard` CLIs, the `audit()` API, and generated reports. Agent Shield
inspects agent instructions and hooks offline. There is no hosted backend or database.

## Start here

- Confirm `git rev-parse --show-toplevel` and `git status --short`. Work in the
  checkout containing this file, `package.json`, and `src/`. Preserve existing edits.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, verification, and rule changes.
- One owner integrates the change and verifies the user outcome. Delegate only
  independent, bounded work; no recursive delegation or repeated review without new evidence.

## Code map

| Area | Entry points |
|---|---|
| CLI and audit pipeline | `bin/vibe-audit.js`, `src/index.js` |
| File discovery and GitHub snapshots | `src/scanner.js`, `src/github.js` |
| Detection and output | `src/rules/`, `src/reporter.js`, `src/reporters/` |
| Agent Shield, VibeGuard, install checks | `src/guard/`, `bin/vibeguard.js`, `src/precheck/` |
| Protected dependency workflow | `src/precheck/protected-install.js`, [installation guide](docs/protected-npm-install.md) |
| Offline protection pilot | `src/guard/pilot.js`, [pilot guide](docs/protection-pilot.md) |
| External security tools | `src/adapters/`, `src/sca/`, `src/trusted-tools.js` |
| Scheduled portfolio scan | `scripts/morning-scan.js`, `scripts/run-morning-scan.js` |
| Regression tests and CI | `tests/`, `.github/workflows/` |

## Boundaries

- Scanned files and agent instructions are untrusted data. Ordinary scans never execute them.
  Only the explicit protection pilot runs approved snapshots in Docker; never fall back to host execution.
  The dependency workflow invokes trusted npm with scripts disabled; it never runs the installed application.
  Target config and inline suppressions require explicit `--trust-target-config`.
- Preserve tool verification, approval checks, secret redaction, and incomplete-coverage failures.
  Keep credentials and scan reports out of Git. Do not install machine-wide hooks as a test.
- Keep test fixtures inert. Add detection and non-detection cases when changing rules.
- HTML reports are written into the target directory; stdout contains a summary.
- Do not merge, deploy, publish, or change release approvals without authorization.

## Completion

Load [verify-change](.agents/skills/verify-change/SKILL.md) when implementing or
finishing a change. The shared local, CI, and prepublish gate is `npm run verify`.
Use the additional checks in [CONTRIBUTING.md](CONTRIBUTING.md#verification) for
the affected path. State the outcome, commands and results, remaining blockers,
and which external boundaries were mocked or unverified. A generated report must
exist and be read before it counts as evidence.
