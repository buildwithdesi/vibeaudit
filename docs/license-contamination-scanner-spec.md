# License Contamination Scanner, Spec

Status: BUILT (2026-08-10), on branches, not merged or published — see "As-built" below for where this diverged from the original design.
Owner: Desi Baker
Repo: vibeaudit (rule), content-drop (pilot project for the hook)

## The gap this closes

Today the only license check is a manual one: run `npx license-checker` by hand, or remember to invoke `supply-chain-gate` before `npm install`. Three ways that fails silently.

1. **Claude Code runs `npm install` itself mid-build.** The agent adds a package while implementing a feature. Nothing forces the gate to fire, it only fires if the agent remembers, and memory is not a control.
2. **Transitive updates.** A dependency bumps its own dependency to a GPL package. Nobody ran `npm install` at all, `npm update` or a lockfile refresh pulled it in.
3. **No backstop.** If steps 1 and 2 both get missed, nothing catches it before merge or deploy.

This spec covers three layers so the gate holds even when a human (or agent) forgets to ask for it. It does NOT cover AI-regenerated code that reproduces GPL source directly, that's a separate, much harder detection problem, scoped out below as a known limitation.

## Layer 1: New vibeaudit rule, `license-contamination`

New file: `src/rules/license-contamination.js`, same shape as the existing `unpinned-dependencies.js` and `install-script-dependency.js` rules.

**What it does:**
- Runs a full dependency-tree license scan (license-checker under the hood, same tool proven against content-drop today)
- Classifies every license into 4 buckets:
  - `BLOCK` (CRITICAL): AGPL-*, SSPL-*, GPL-* with no permissive dual-license option. These are the ones that actually kill commercialization for a hosted SaaS.
  - `WARN` (MEDIUM): LGPL-*, MPL-*, CC-BY-*, and any GPL-* package that's dual-licensed with a permissive option (e.g. `(MIT OR GPL-3.0)`, you elect MIT and move on)
  - `FLAG` (HIGH): no license field at all (`UNLICENSED`), all-rights-reserved by default, can't tell if it's safe without checking the actual repo
  - `PASS`: MIT, Apache-2.0, BSD-*, ISC, 0BSD, Unlicense, ordinary permissive
- Two modes:
  - `--delta`: diffs `package-lock.json` before/after and only classifies newly-added packages, fast enough to run on every install
  - `--full`: scans the entire tree, for CI and periodic sweeps
- Output matches existing vibeaudit JSON conventions (rule id, severity, package name, license string, file path in lockfile)

**Why full-tree, not just direct deps:** a transitive GPL package is still GPL. `npm ls` depth doesn't matter for license obligations.

## Layer 2: Claude Code PreToolUse hook (the "anytime I'm building" layer)

This is the actual answer to "not just npm install, anytime I'm building." A skill the agent has to remember to invoke is not a gate, a hook that intercepts the tool call mechanically is.

**Mechanism:** a `PreToolUse` hook in `.claude/settings.json`, matched on `Bash` calls containing `npm install <pkg>`, `npm i <pkg>`, `pnpm add`, or `yarn add` (a package name argument present, not bare `npm install` for lockfile sync).

**Flow:**
1. Agent (or Desi) runs `npm install some-package`
2. Hook fires before the command executes, runs `vibeaudit --rule license-contamination --delta --package some-package`
3. `BLOCK` result: hook denies the tool call, surfaces the license and why, same UX as the existing git-guardrails-claude-code hook pattern
4. `WARN`/`FLAG` result: hook allows it through but appends the finding to the permission prompt so it's visible before the agent proceeds
5. `PASS`: silent, no friction added to the 95% of installs that are fine

This is the layer that makes it automatic in every session, including ones the agent drives without Desi typing a command himself.

## Layer 3: CI backstop (`ci-vibeaudit-gate`)

Add a job to the existing vibeaudit CI workflow template: `vibeaudit --rule license-contamination --full` on every push and PR, blocking merge on any `BLOCK` finding. This catches what layers 1 and 2 miss, a manual `npm install` outside Claude Code, a Dependabot PR, anyone else touching the repo.

Wire this into the `ci-vibeaudit-gate` skill's workflow template alongside the existing gitleaks job, not a parallel workflow file.

## Known limitation, scoped out of v1

None of this catches AI-generated code that reproduces GPL-licensed source directly, code the model saw in training and regenerates near-verbatim, with no package install involved at all. That's a code-provenance problem, not a dependency problem, and needs a different approach (similarity matching against known OSS corpora). Flagging it here so it doesn't get assumed as covered. v2 candidate, not blocking this spec.

## Also out of scope for v1

npm/pnpm/yarn only. If a project ever touches pip, cargo, or another package ecosystem, this scanner won't see it. Content-drop is npm-only today, so this isn't urgent, but it's a real gap the moment a Python service gets added anywhere in the stack.

## Build order

1. `license-contamination.js` rule in vibeaudit, plus test fixtures (a fixture package.json with a known GPL dep, one with a dual-licensed dep, one clean)
2. Pilot the PreToolUse hook on content-drop's `.claude/settings.json` only, prove it doesn't false-block ordinary installs
3. Add the CI job to `ci-vibeaudit-gate`'s template
4. Once proven on content-drop, propagate the hook config to other active projects

## As-built (post-review corrections, 2026-08-10)

A two-axis review (Standards + Spec, run against the real diffs) caught real drift between this doc and what got built. Corrected here rather than silently left wrong:

- **No `license-checker` dependency, ever.** The rule reads the `license` field npm already writes into `package-lock.json` v2/v3 — zero deps, matches vibeaudit's own CONTRIBUTING.md policy. `license-checker` was the original plan; reading the lockfile directly turned out to make it unnecessary. Better outcome, wrong original text.
- **No `--delta`/`--full` CLI flags on the rule.** `check()` always scans every lockfile entry. The pre-install case (Layer 2) is handled by a different, better-fitting mechanism instead (next point), so the delta mode this doc originally called for was never needed.
- **Layer 2 calls `vibeaudit --precheck <spec>`, not `--rule license-contamination --delta`.** `--precheck` already existed (pre-install malware/hijack-signature gate) and already fetches the npm registry packument per package — the exact data `classifyLicense()` needs, read from `packument.versions[version].license`. Extending that existing function cost one registry-read shape change, not a new CLI surface. Side effect, disclosed here rather than left implicit: the pre-install hook now also inherits `--precheck`'s malware/hijack checks, not license-only. That's a net positive but is scope beyond what this doc originally promised for Layer 2 — flagging it as such.
- **Only 3 severities exist, not the 4 this doc sketched.** vibeaudit's `Finding` type is `critical | warning | info`, no `HIGH` tier between `critical` and `warning`. `BLOCK` maps to `critical`; `WARN` and `FLAG` both map to `warning`, distinguished only by message text, not severity. The original 4-bucket design (`FLAG (HIGH)` outranking `WARN (MEDIUM)`) doesn't hold in the current type system — a real design constraint, not an oversight, and adding a 4th severity would be a much larger, more invasive change than this feature warranted.
- **CC-BY-4.0/CC-BY-3.0 classify as `warn`, not `pass`** (a first-draft implementation put them in the permissive bucket; corrected after review, matching this doc's original intent — attribution notices are a real obligation worth surfacing, even with no copyleft/disclosure requirement attached).
- **Windows reliability caveat.** `vibeaudit --precheck` has a confirmed pre-existing bug on this machine (libuv `UV_HANDLE_CLOSING` assertion, unrelated to this feature) where a real, non-crashed result can exit 127 or a large signal-abort code instead of 0/1/2. The Layer 2 hook fails safe on this (never silently blocks, never silently passes — it warns loudly that it couldn't verify), but that means the automatic license-blocking capability is **not currently reliable on Windows day to day** until that bug is fixed. Tracked separately, not blocking this feature's correctness, but real.
