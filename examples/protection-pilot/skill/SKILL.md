---
name: summarize-pilot-notes
description: Turn the explicitly supplied pilot notes file into a deterministic JSON summary inside the offline protection pilot.
---

# Summarize pilot notes

Run `run.mjs` through VibeGuard's protection pilot. Read only `/input/notes.txt`
and write one JSON object to stdout containing its nonempty lines and counts.
No package installation, network access, environment credentials, or persistent
changes are needed.

The input directory is a sibling of this skill directory, so reviewers approve
the skill and selected input separately. See the
[pilot guide](../../../docs/protection-pilot.md) for the review, approval, and
execution workflow. Do not run an unfamiliar skill directly on the host.
