/**
 * CWE / CVSS / OWASP mapping for every rule.
 *
 * Each entry enriches findings with industry-standard metadata:
 *   - cweId:         Common Weakness Enumeration identifier
 *   - cvssScore:     CVSS v3.1 base score (0–10)
 *   - owaspCategory: OWASP Top 10 2021 category
 */

/** @type {Record<string, { cweId: string, cvssScore: number, owaspCategory: string }>} */
export const CWE_MAP = {
  // ── Secrets & Credentials ──────────────────────────────────────────────────
  'exposed-secrets':            { cweId: 'CWE-798', cvssScore: 7.5, owaspCategory: 'A07:2021' },
  'hardcoded-credentials':      { cweId: 'CWE-798', cvssScore: 7.5, owaspCategory: 'A07:2021' },
  'exposed-env-vars':           { cweId: 'CWE-200', cvssScore: 7.5, owaspCategory: 'A02:2021' },
  'client-bundle-secrets':      { cweId: 'CWE-200', cvssScore: 7.5, owaspCategory: 'A02:2021' },
  'sensitive-browser-storage':  { cweId: 'CWE-922', cvssScore: 6.5, owaspCategory: 'A04:2021' },
  'missing-gitignore':          { cweId: 'CWE-538', cvssScore: 5.3, owaspCategory: 'A05:2021' },
  'insecure-jwt':               { cweId: 'CWE-347', cvssScore: 7.5, owaspCategory: 'A02:2021' },
  'secrets-in-urls':            { cweId: 'CWE-598', cvssScore: 5.3, owaspCategory: 'A04:2021' },
  'high-entropy-strings':       { cweId: 'CWE-798', cvssScore: 5.0, owaspCategory: 'A07:2021' },
  'git-history-secrets':        { cweId: 'CWE-798', cvssScore: 7.5, owaspCategory: 'A07:2021' },

  // ── Auth & Authorization ───────────────────────────────────────────────────
  'missing-auth':               { cweId: 'CWE-306', cvssScore: 9.8, owaspCategory: 'A07:2021' },
  'idor-vulnerability':         { cweId: 'CWE-639', cvssScore: 8.6, owaspCategory: 'A01:2021' },
  'client-only-auth':           { cweId: 'CWE-602', cvssScore: 6.5, owaspCategory: 'A04:2021' },
  'plaintext-passwords':        { cweId: 'CWE-256', cvssScore: 7.5, owaspCategory: 'A02:2021' },
  'no-account-lockout':         { cweId: 'CWE-307', cvssScore: 5.3, owaspCategory: 'A07:2021' },

  // ── Injection & Input ──────────────────────────────────────────────────────
  'no-input-validation':        { cweId: 'CWE-20',  cvssScore: 8.6, owaspCategory: 'A03:2021' },
  'mass-assignment':            { cweId: 'CWE-915', cvssScore: 8.1, owaspCategory: 'A08:2021' },
  'unsafe-file-upload':         { cweId: 'CWE-434', cvssScore: 8.1, owaspCategory: 'A04:2021' },
  'path-traversal':             { cweId: 'CWE-22',  cvssScore: 8.6, owaspCategory: 'A01:2021' },
  'prototype-pollution':        { cweId: 'CWE-1321', cvssScore: 8.1, owaspCategory: 'A03:2021' },

  // ── Server-Side Exploits ───────────────────────────────────────────────────
  'ssrf-vulnerability':         { cweId: 'CWE-918', cvssScore: 8.6, owaspCategory: 'A10:2021' },
  'unverified-webhook':         { cweId: 'CWE-345', cvssScore: 7.5, owaspCategory: 'A08:2021' },
  'insecure-randomness':        { cweId: 'CWE-330', cvssScore: 5.3, owaspCategory: 'A02:2021' },

  // ── Data Exposure ──────────────────────────────────────────────────────────
  'api-data-overfetch':         { cweId: 'CWE-200', cvssScore: 4.3, owaspCategory: 'A01:2021' },
  'console-data-leak':          { cweId: 'CWE-532', cvssScore: 4.3, owaspCategory: 'A09:2021' },
  'insecure-error-handling':    { cweId: 'CWE-209', cvssScore: 4.3, owaspCategory: 'A09:2021' },
  'source-maps-exposed':        { cweId: 'CWE-540', cvssScore: 3.7, owaspCategory: 'A05:2021' },

  // ── Transport & Config ─────────────────────────────────────────────────────
  'open-database-rules':        { cweId: 'CWE-284', cvssScore: 9.8, owaspCategory: 'A01:2021' },
  'missing-security-headers':   { cweId: 'CWE-693', cvssScore: 4.3, owaspCategory: 'A05:2021' },
  'missing-rate-limiting':      { cweId: 'CWE-770', cvssScore: 5.3, owaspCategory: 'A04:2021' },
  'insecure-connections':       { cweId: 'CWE-319', cvssScore: 5.3, owaspCategory: 'A02:2021' },
  'missing-csrf':               { cweId: 'CWE-352', cvssScore: 6.5, owaspCategory: 'A01:2021' },
  'insecure-cookies':           { cweId: 'CWE-614', cvssScore: 4.3, owaspCategory: 'A05:2021' },

  // ── Client-Side Trust ──────────────────────────────────────────────────────
  'client-side-trust':          { cweId: 'CWE-602', cvssScore: 5.3, owaspCategory: 'A04:2021' },
  'client-side-db-access':      { cweId: 'CWE-602', cvssScore: 8.6, owaspCategory: 'A04:2021' },
  'no-pagination':              { cweId: 'CWE-770', cvssScore: 4.3, owaspCategory: 'A04:2021' },
  'cors-credentials':           { cweId: 'CWE-942', cvssScore: 5.3, owaspCategory: 'A05:2021' },
  'debug-mode-exposed':         { cweId: 'CWE-489', cvssScore: 3.7, owaspCategory: 'A05:2021' },

  // ── Bot & Auth Flow ────────────────────────────────────────────────────────
  'no-bot-protection':          { cweId: 'CWE-799', cvssScore: 3.7, owaspCategory: 'A07:2021' },
  'predictable-ids':            { cweId: 'CWE-340', cvssScore: 3.7, owaspCategory: 'A04:2021' },
  'unsafe-redirect':            { cweId: 'CWE-601', cvssScore: 5.3, owaspCategory: 'A01:2021' },
  'timing-attack':              { cweId: 'CWE-208', cvssScore: 3.7, owaspCategory: 'A02:2021' },

  // ── Framework-Specific (NEW) ───────────────────────────────────────────────
  'nextjs-server-action-exposure': { cweId: 'CWE-306', cvssScore: 8.6, owaspCategory: 'A07:2021' },
  'nextjs-middleware-bypass':      { cweId: 'CWE-863', cvssScore: 7.5, owaspCategory: 'A01:2021' },
  'nextjs-api-route-no-method-check': { cweId: 'CWE-749', cvssScore: 4.3, owaspCategory: 'A04:2021' },
  'supabase-missing-rls':         { cweId: 'CWE-284', cvssScore: 9.8, owaspCategory: 'A01:2021' },
  'supabase-service-key-client':  { cweId: 'CWE-798', cvssScore: 9.8, owaspCategory: 'A07:2021' },
  'supabase-anon-key-abuse':      { cweId: 'CWE-269', cvssScore: 5.3, owaspCategory: 'A04:2021' },
  'firebase-admin-client':        { cweId: 'CWE-798', cvssScore: 9.8, owaspCategory: 'A07:2021' },
  'vercel-env-leak':              { cweId: 'CWE-200', cvssScore: 7.5, owaspCategory: 'A02:2021' },
  'netlify-redirect-open':        { cweId: 'CWE-601', cvssScore: 5.3, owaspCategory: 'A01:2021' },
  'deployment-config-insecure':   { cweId: 'CWE-16',  cvssScore: 4.3, owaspCategory: 'A05:2021' },

  // ── AI & API Security (NEW) ────────────────────────────────────────────────
  'ai-prompt-injection':          { cweId: 'CWE-77',  cvssScore: 8.6, owaspCategory: 'A03:2021' },
  'ai-response-trusted':          { cweId: 'CWE-20',  cvssScore: 6.5, owaspCategory: 'A03:2021' },
  'ai-cost-exposure':             { cweId: 'CWE-770', cvssScore: 5.3, owaspCategory: 'A04:2021' },
  'stripe-webhook-no-verify':     { cweId: 'CWE-345', cvssScore: 8.1, owaspCategory: 'A08:2021' },
  'payment-amount-client':        { cweId: 'CWE-602', cvssScore: 8.6, owaspCategory: 'A04:2021' },

  // ── Data & Privacy (NEW) ───────────────────────────────────────────────────
  'pii-logging':                  { cweId: 'CWE-532', cvssScore: 4.3, owaspCategory: 'A09:2021' },
  'missing-data-encryption':      { cweId: 'CWE-311', cvssScore: 5.3, owaspCategory: 'A02:2021' },
  'graphql-introspection':        { cweId: 'CWE-200', cvssScore: 3.7, owaspCategory: 'A05:2021' },
  'graphql-depth-limit':          { cweId: 'CWE-770', cvssScore: 5.3, owaspCategory: 'A04:2021' },
  'graphql-no-auth':              { cweId: 'CWE-306', cvssScore: 8.6, owaspCategory: 'A07:2021' },

  // ── Session & Auth Hardening (NEW) ─────────────────────────────────────────
  'session-fixation':             { cweId: 'CWE-384', cvssScore: 7.5, owaspCategory: 'A07:2021' },
  'oauth-state-missing':          { cweId: 'CWE-352', cvssScore: 8.1, owaspCategory: 'A07:2021' },
  'password-reset-weak':          { cweId: 'CWE-640', cvssScore: 5.3, owaspCategory: 'A07:2021' },
  'mfa-bypass':                   { cweId: 'CWE-287', cvssScore: 6.5, owaspCategory: 'A07:2021' },
  'auth-token-no-expiry':         { cweId: 'CWE-613', cvssScore: 5.3, owaspCategory: 'A07:2021' },

  // ── Expanded Categories (NEW) ──────────────────────────────────────────────
  'race-condition':               { cweId: 'CWE-362', cvssScore: 8.1, owaspCategory: 'A04:2021' },
  'nosql-injection':              { cweId: 'CWE-943', cvssScore: 8.6, owaspCategory: 'A03:2021' },
  'xml-xxe':                      { cweId: 'CWE-611', cvssScore: 8.6, owaspCategory: 'A05:2021' },
  'ldap-injection':               { cweId: 'CWE-90',  cvssScore: 8.6, owaspCategory: 'A03:2021' },
  'header-injection':             { cweId: 'CWE-113', cvssScore: 5.3, owaspCategory: 'A03:2021' },
  'subdomain-takeover':           { cweId: 'CWE-284', cvssScore: 5.3, owaspCategory: 'A05:2021' },
  'clickjacking':                 { cweId: 'CWE-1021', cvssScore: 4.3, owaspCategory: 'A05:2021' },
  'dangerously-set-inner-html':   { cweId: 'CWE-79',  cvssScore: 6.1, owaspCategory: 'A03:2021' },
  'eval-usage':                   { cweId: 'CWE-95',  cvssScore: 8.6, owaspCategory: 'A03:2021' },
  'regex-dos':                    { cweId: 'CWE-1333', cvssScore: 5.3, owaspCategory: 'A04:2021' },
  'hardcoded-ip':                 { cweId: 'CWE-547', cvssScore: 2.0, owaspCategory: 'A05:2021' },

  // ── Infrastructure (v3) ─────────────────────────────────────────────────────
  'docker-root-user':             { cweId: 'CWE-250', cvssScore: 6.5, owaspCategory: 'A05:2021' },
  'exposed-database-port':        { cweId: 'CWE-284', cvssScore: 5.3, owaspCategory: 'A05:2021' },

  // ── SCA ────────────────────────────────────────────────────────────────────
  'vulnerable-dependency':        { cweId: 'CWE-1035', cvssScore: 7.5, owaspCategory: 'A06:2021' },
};
