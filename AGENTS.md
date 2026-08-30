<!-- vibe-audit-ignore download-execution: reviewed local development commands, no remote execution -->
# AGENTS.md

## Cursor Cloud specific instructions

Vibe Audit is a **zero-config Node.js CLI** (ESM, `"type": "module"`) that statically
scans a codebase for security issues. There is no long-running server or GUI — the
"application" is the `vibeaudit` CLI plus its report generators. The update script runs
`npm ci`, so dependencies are already installed when a session starts.

- Requires Node `>=18.19.0` (CI checks Node 18, 20, and 22).
- Standard commands live in `package.json` scripts:
  - Lint: `npm run lint`
  - Tests: `npm test` (Node's built-in test runner, more than 480 tests)
  - Self-audit: `npm run audit:self` (runs the scanner on this repo)
- Run the CLI directly with `node bin/vibe-audit.js <target> [options]`, e.g.
  `node bin/vibe-audit.js . --skip-sca`. Target can be a local dir or a GitHub `owner/repo`.
- Non-obvious: `--format html` does **not** print HTML to stdout. It writes
  `vibe-audit-report.html` into the *scanned target directory* and prints only a summary
  to stdout. Grab the report from the target dir, not from redirected stdout.
- `npm run audit:self` must exit zero. It trusts this repository's reviewed config while
  untrusted scan targets cannot disable rules or inline suppressions by default.
- The `ui` / `ui:dev` package scripts reference `src/web/server.js`, which does not exist in
  the repo — there is no web UI to run. Ignore those scripts.
