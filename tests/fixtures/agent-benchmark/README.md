# Safe Agent Shield benchmark corpus

This corpus makes Agent Shield measurable without asking a developer to find or handle malware.

## What is inside

- `benign-*` cases are harmless control files that should pass.
- `malicious-*` cases are inert text or harmless scripts that reproduce documented behavior signals.
- `known-gap-*` cases are deliberately adversarial examples that document a current static-analysis limitation.
- `incomplete-*` cases prove that missing coverage blocks instead of becoming a clean result.
- `manifest.json` records the expected decision, case class, evaluation status, and public source references.

Public incidents and research provide the behavior labels. The fixtures do not contain real malware, live credentials, real tokens, or working exfiltration code. Nothing in this directory should be executed.

## Run it

```powershell
npm run benchmark:agent
npm run benchmark:agent -- --json
npm run benchmark:agent -- --strict
```

The normal command prints known gaps as `GAP` and exits successfully. `--strict` exits nonzero when a required expected decision is missed. This is a small regression corpus, not a detection certification or a claim that passing makes a skill safe.

