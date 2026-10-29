---
name: verify-change
description: Verify a VibeAudit change through its observable CLI or report outcome. Use when implementing a change, preparing a PR, or deciding whether work is complete.
---

# Verify a VibeAudit change

Read [CONTRIBUTING.md](../../../CONTRIBUTING.md#verification) for the canonical
commands and risk-based checks. Read the affected implementation and tests.

Name the user outcome and exercise its actual entry point. Add regression
coverage for changed logic, including failure output when relevant. Inspect
generated artifacts and distinguish local fixtures from live service evidence.

The integrating owner runs the required checks and reports their results,
unverified boundaries, and blockers. Do not spawn review chains, remove failing
coverage to get green, or merge or release as part of verification.
