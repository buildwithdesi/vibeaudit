/**
 * Rule: exposed-env-vars
 * Detects dangerous patterns where server secrets leak through
 * client-prefixed env vars (VITE_, NEXT_PUBLIC_, REACT_APP_, etc.)
 */

/** @typedef {import('./types.js').Rule} Rule */

import { isDesignedPublicKey } from '../context.js';

/**
 * Client-side env prefixes — these get bundled into the browser build.
 * People vibe-coding often don't realize VITE_ vars are PUBLIC.
 */
const CLIENT_PREFIXES = ['VITE_', 'NEXT_PUBLIC_', 'REACT_APP_', 'NUXT_PUBLIC_', 'EXPO_PUBLIC_'];

/** Test/spec files and fixtures intentionally contain fake env vars to exercise this rule. */
const SKIP = /(?:\.test\.|\.spec\.|__tests__|fixtures\/|src\/rules\/|reports\/)/i;

/** Keywords that suggest sensitive data — these should NEVER be client-prefixed. */
const SENSITIVE_KEYWORDS = [
  'SECRET',
  'PRIVATE',
  'PASSWORD',
  'PASSWD',
  'CREDENTIAL',
  'TOKEN',
  'AUTH_KEY',
  'SERVICE_KEY',
  'SERVICE_ROLE',
  'ADMIN_KEY',
  'MASTER_KEY',
  'DATABASE_URL',
  'DB_PASSWORD',
  'SIGNING_KEY',
  'ENCRYPTION_KEY',
  'SMTP_PASSWORD',
  'SENDGRID',
  'TWILIO_AUTH',
  'STRIPE_SECRET',
  'OPENAI_KEY',
  'ANTHROPIC_KEY',
];

/** @type {Rule} */
export const exposedEnvVars = {
  id: 'exposed-env-vars',
  name: 'Exposed Environment Variables',
  severity: 'critical',
  description: 'Detects server-side secrets exposed through client-side environment variable prefixes.',

  check(file) {
    // Skip test fixtures — fake env vars there are intentional, not real leaks.
    if (SKIP.test(file.relativePath)) return [];

    // Only check env files and source files that reference process.env / import.meta.env.
    const isEnvFile = file.relativePath.includes('.env');
    const referencesEnv = file.content.includes('process.env') || file.content.includes('import.meta.env');
    if (!isEnvFile && !referencesEnv) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];

      for (const prefix of CLIENT_PREFIXES) {
        if (!line.includes(prefix)) continue;

        for (const keyword of SENSITIVE_KEYWORDS) {
          // Match the full env var name.
          const pattern = new RegExp(`${prefix}[A-Z0-9_]*${keyword}[A-Z0-9_]*`, 'g');
          let match;
          while ((match = pattern.exec(line)) !== null) {
            // Designed-public keys (publishable, mapbox, posthog, anon, …) are safe.
            if (isDesignedPublicKey(match[0])) continue;
            findings.push({
              ruleId: 'exposed-env-vars',
              ruleName: 'Exposed Environment Variables',
              severity: 'critical',
              message: `"${match[0]}" exposes a secret to the browser. The ${prefix} prefix makes this variable public in your build output.`,
              file: file.relativePath,
              line: i + 1,
              evidence: match[0],
              fix: `Remove the "${prefix}" prefix from this variable. Server-side secrets must NOT use client-prefixed env vars. Access it only in server-side code (API routes, server components, middleware).`,
            });
          }
        }
      }
    }

    return findings;
  },
};
