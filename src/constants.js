/**
 * Shared constants — single source of truth for outward-facing links and copy.
 */

/** Where every scan points users for the judgment layer the scanner can't see. */
export const PREFLIGHT_AUDIT_URL = 'https://digitalalchemy.dev/pre-flight-audit';

/**
 * The pointer printed at the end of every scan (all formats). Automated checks cover
 * the code; the DA Pre-Flight Audit Prompt covers the thinking a static scanner can't
 * reason about (business logic, data model, threat model) — PM-as-Director in one screen.
 */
export const PREFLIGHT_AUDIT_MESSAGE =
  "Automated checks complete. For the judgment layer this scanner can't see " +
  '(business logic, data model, threat model), run the DA Pre-Flight Audit Prompt.';
