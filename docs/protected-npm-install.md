# Protected npm installation

Use this workflow to add one public npm dependency to a single project. Review
does not modify the project. Install uses the reviewed archives and keeps the
previous files for rollback. All installation scripts stay disabled.

## Run it

From the VibeAudit checkout, use `node bin/vibeguard.js` below. Once a release
containing this workflow is installed, the equivalent entry point is `vibeguard`.

```bash
node bin/vibeguard.js npm review picocolors@1.1.1 --project /path/to/app
node bin/vibeguard.js npm install <review-id> --accept <review-id>
node bin/vibeguard.js npm status <review-id>
node bin/vibeguard.js npm rollback <review-id>
```

Use `--dev` on review to add a development dependency. All commands return JSON;
`--json` is accepted for callers that already use that convention. Exit 4 means
blocked, failed, or recovery required. Exit 0 means that operation completed;
read the result to distinguish a review from an installation.

Read every package result before accepting its complete review ID. Acceptance
covers warnings as well as the exact manifest, lockfile, package bytes, project
inputs, Node/npm identity, and platform. A blocked review cannot be installed.
Reviews expire after ten minutes and allow one installation attempt. A failed
attempt requires a new review; it cannot silently retry against different bytes.

The existing precheck policy still blocks known malicious versions, known
vulnerabilities, incomplete checks, suspicious archive content, certain license
categories, and fresh releases with installation scripts. An established package
with declared installation scripts can be reviewed, but those scripts remain off.
That package may need additional setup before it works. There is no script-enable
or bypass flag in this pilot.

## What gets verified

1. Snapshot the project's manifest, lockfile, and supported npm configuration.
   Reject unsupported inputs before invoking npm.
2. Resolve in a private directory using the trusted npm installation beside Node.
   A temporary local registry broker validates candidate dependency metadata before
   npm receives it. It fetches only public npm metadata, rejects redirects and
   unsupported dependency sources, and closes when resolution ends.
3. Reuse precheck for every resolved package version, including old releases.
   Check registry signatures, SHA512 archive integrity, archive structure/content,
   and exact-version OSV advisories. Store authenticated archives outside the app.
4. After acceptance, verify the review, archives, tool identity, and current
   project inputs again. Populate an empty private npm cache with those archives.
   Run `npm ci --offline --ignore-scripts` in a separate directory on the same
   filesystem. No package is re-resolved during installation.
5. Check installed package identities and record optional packages omitted for the
   current platform. Recheck the project inputs, retain originals, and move the
   prepared `node_modules`, lockfile, and manifest into place. Save a receipt.

The interfaces are CLI commands and JSON results. Policy and installation run in
the local Node process and its trusted npm child. Persistence consists of review
files, archives, locks, backups, and receipts. There is no database, background
worker, or hosted service. Network dependencies during review are the public npm
registry and OSV; the installation phase is offline.

## Recovery and data

The default private review store is `~/.vibeaudit/npm`. `--store <directory>` can
select another directory outside the project; use it consistently on subsequent
commands. Reports and backups can contain private project metadata. Do not commit
or upload them. Package names and versions are sent to npm and OSV during review.

Prepared installs and backups live in a `.vibeguard-npm-*` directory beside the
project, on the same filesystem. A project lock prevents another VibeGuard
installation even when it uses a different review store. Stop other package
managers and avoid editing dependency files during the final replacement.

On a normal failure, VibeGuard restores the originals when it can do so without
overwriting later edits. After an interrupted process, inspect `npm status`, then
use `npm rollback` after that process has stopped. Rollback also works after a
successful install. If any published file changed, rollback reports
`recovery-required` and retains all files for inspection. It does not discard the
newer file or partially roll back the remaining paths.

If the recovery process itself is interrupted, its exclusive recovery claim stays
in place. Inspect the retained process, receipt, claim, and backups before manual
recovery. Repeated recovery crashes are not automatically resolved. Keep backups
until the app has been checked; removing them ends the ability to roll back.

## Supported boundary

- Single public-registry npm projects, with no lockfile or a v2/v3 lockfile.
- Registry aliases and root overrides are supported within the same source rules.
- Workspaces, shrinkwrap, bundled dependencies, custom project npm settings,
  private registries, Git/URL/local dependencies, and linked project inputs are
  rejected. A candidate package version with an unsupported production dependency
  can block resolution even when another version would have been acceptable.
- At most 500 distinct package versions and 200 MiB of compressed archives per
  review. Individual archives remain subject to the existing inspection limits.
- A trusted Node/npm installation and writable project parent are required.
  Inherited npm configuration, application secrets, and `NODE_OPTIONS` are not
  passed to npm. TLS failures block verification; configure the intended CA trust
  for the calling Node process rather than disabling certificate verification.

Registry signatures authenticate published bytes; they do not establish that
code is harmless. Review depends on the registry's metadata, signing keys, and
available vulnerability information. This is a user-level workflow, not an OS
security boundary against another process with the same account privileges.

Installed packages are not executed by this workflow. Later imports, builds,
`npm run`, `npx`, and application startup need their own review or isolation. The
receipt therefore says installation was verified and application execution was
not tested. Run an appropriate application check separately, in a trusted or
isolated environment. Existing machine-wide hooks are not modified by these commands.

## Development evidence

Run `npm run verify`. It includes fixture regression tests and `npm run
test:install`, which uses real offline npm to install signed inert archives and
check rollback. The fixture suite does not establish live registry or OSV health.
For live evidence, use a disposable copy of a real app, review a pinned package,
install the accepted ID, inspect the receipt, exercise a known app operation, and
roll back. Record service failures and human interventions as well as successes.
