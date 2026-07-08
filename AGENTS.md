# AGENTS.md

## Cursor Cloud specific instructions

Vibe Audit is a **zero-config Node.js CLI** (ESM, `"type": "module"`) that statically
scans a codebase for security issues. There is no long-running server or GUI — the
"application" is the `vibeaudit` CLI plus its report generators. The update script runs
`npm ci`, so dependencies are already installed when a session starts.

- Requires Node `>=18.3.0` (CI uses Node 20; this VM runs Node 22 — both work).
- Standard commands live in `package.json` scripts:
  - Lint: `npm run lint`
  - Tests: `npm test` (Node's built-in test runner, ~292 tests)
  - Self-audit: `npm run audit:self` (runs the scanner on this repo)
- Run the CLI directly with `node bin/vibe-audit.js <target> [options]`, e.g.
  `node bin/vibe-audit.js . --skip-sca`. Target can be a local dir or a GitHub `owner/repo`.
- Non-obvious: `--format html` does **not** print HTML to stdout. It writes
  `vibe-audit-report.html` into the *scanned target directory* and prints only a summary
  to stdout. Grab the report from the target dir, not from redirected stdout.
- `npm run audit:self` normally exits non-zero (grade F) because `npm audit` (SCA) reports
  known-vulnerable transitive dev dependencies. That is expected, not a setup failure; the
  static code rules on this repo are clean. Use `--skip-sca` to exclude dependency findings.
- The `ui` / `ui:dev` package scripts reference `src/web/server.js`, which does not exist in
  the repo — there is no web UI to run. Ignore those scripts.
