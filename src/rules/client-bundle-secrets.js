/**
 * Rule: client-bundle-secrets
 * Detects secrets referenced in client-side code that will be visible
 * in browser DevTools → Sources tab after bundling.
 *
 * The DevTools attack: View Source → search for "sk_" or "key" → game over.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { isDesignedPublicKey } from '../context.js';

/** Client-side file patterns — these get bundled and sent to the browser. */
const CLIENT_FILE_PATTERNS = /(?:^src\/(?:components|pages|app|views|layouts|hooks|context|lib\/client)|\.client\.|\/client\/|^app\/|^pages\/(?!api\/))/i;

/**
 * Non-client file patterns (server-only). Root scripts/ and bin/ run in Node,
 * not the browser (public/scripts/ is still served, so only the root counts).
 */
const SERVER_FILE_PATTERNS = /(?:api\/|server\/|\.server\.|middleware|functions\/|lib\/server|_worker\.|backend\/|^(?:scripts|bin)\/|\.cjs$)/i;

/** Node built-in imports mark a file that never ships to the browser. */
const NODE_ONLY_IMPORT = /(?:from\s+|require\s*\(\s*)['"]node:/;

/** Words that mark a value as a stand-in, not a credential. */
const PLACEHOLDER_WORDS = new Set(['fixture', 'placeholder', 'dummy', 'example', 'sample', 'test', 'fake', 'mock', 'local', 'your', 'changeme', 'redacted', 'xxx']);

/**
 * True for values like "local-fixture-key" or "your_api_key_here". A value with
 * a long random-looking segment (e.g. sk_test_51Hx...) is still treated as real.
 */
function isPlaceholderValue(value) {
  const parts = value.toLowerCase().split(/[-_]+/).filter(Boolean);
  const looksRandom = parts.some((p) => p.length >= 16 && /\d/.test(p) && /[a-z]/.test(p));
  if (looksRandom) return false;
  return parts.some((p) => PLACEHOLDER_WORDS.has(p));
}

/**
 * Env var references that pull secrets into client bundles.
 * process.env.NEXT_PUBLIC_* and import.meta.env.VITE_* are intentionally public,
 * but people stuff secrets into them thinking "env var = safe."
 */
const CLIENT_ENV_REFS = [
  // Direct references to env vars with secret-sounding names in client code
  { regex: /process\.env\.(?:(?:NEXT_PUBLIC_|REACT_APP_)[A-Z_]*(?:SECRET|PRIVATE|TOKEN|PASSWORD|KEY|CREDENTIAL|AUTH)[A-Z_]*)/g, label: 'Secret env var referenced in client code — visible in DevTools Sources' },
  { regex: /import\.meta\.env\.(?:VITE_[A-Z_]*(?:SECRET|PRIVATE|TOKEN|PASSWORD|KEY|CREDENTIAL|AUTH)[A-Z_]*)/g, label: 'Secret env var referenced in client code — visible in DevTools Sources' },
];

/** Patterns where secret values are assigned directly in client code. */
const INLINE_SECRET_PATTERNS = [
  // Hardcoded API keys passed to SDK constructors in client files
  { regex: /(?:apiKey|api_key|authKey|auth_key|secretKey|secret_key|privateKey|private_key)\s*[:=]\s*['"`]([A-Za-z0-9_-]{16,})['"`]/gi, label: 'API key hardcoded in client-side code — visible in DevTools Sources' },
  // Authorization headers built client-side with hardcoded tokens
  { regex: /['"`](?:Bearer|Basic)\s+([A-Za-z0-9_+/=-]{20,})['"`]/g, label: 'Hardcoded auth header in client code — visible in DevTools Network tab' },
];

/** @type {Rule} */
export const clientBundleSecrets = {
  id: 'client-bundle-secrets',
  name: 'Client Bundle Secrets',
  severity: 'critical',
  description: 'Detects secrets in client-side code that end up in the browser bundle, visible via DevTools → Sources.',

  check(file) {
    // Only flag client-side files.
    const isClient = CLIENT_FILE_PATTERNS.test(file.relativePath);
    const isServer = SERVER_FILE_PATTERNS.test(file.relativePath);

    // If it's clearly server-side, skip.
    if (isServer || NODE_ONLY_IMPORT.test(file.content)) return [];
    // If we can't tell, still check — most vibe-coded files are client-side by default.
    // But only for direct inline secrets, not env var references.
    const checkEnvRefs = isClient;

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;

      // Check for inline secrets (always).
      for (const { regex, label } of INLINE_SECRET_PATTERNS) {
        regex.lastIndex = 0;
        let real = false;
        let m;
        while ((m = regex.exec(line)) !== null) {
          if (!isPlaceholderValue(m[1])) { real = true; break; }
        }
        if (real) {
          findings.push({
            ruleId: 'client-bundle-secrets',
            ruleName: 'Client Bundle Secrets',
            severity: 'critical',
            message: label,
            file: file.relativePath,
            line: i + 1,
            evidence: trimmed.slice(0, 100),
            fix: `Never put secrets in client-side code. Move sensitive operations to a server-side API route. The browser bundle is fully readable — open DevTools → Sources and search for any string.`,
          });
        }
      }

      // Check for env var secret references (only confirmed client files).
      if (checkEnvRefs) {
        for (const { regex, label } of CLIENT_ENV_REFS) {
          regex.lastIndex = 0;
          let match;
          while ((match = regex.exec(line)) !== null) {
            // Publishable / analytics keys are meant to be in the browser.
            if (isDesignedPublicKey(match[0])) continue;
            findings.push({
              ruleId: 'client-bundle-secrets',
              ruleName: 'Client Bundle Secrets',
              severity: 'critical',
              message: `${label}: ${match[0]}`,
              file: file.relativePath,
              line: i + 1,
              evidence: match[0],
              fix: `This env var will be embedded in the browser JS bundle. Anyone can see it in DevTools → Sources. Move this logic to a server-side API route and call it from the client instead.`,
            });
          }
        }
      }
    }

    return findings;
  },
};
