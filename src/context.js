/**
 * Framework-context helpers for Vibe Audit.
 *
 * The #1 source of false positives is the scanner guessing wrong about
 * whether code runs on the server or the client. In Next.js App Router a
 * file is a SERVER component by default — importing React does NOT make it
 * client. These helpers encode that reality so rules stop flagging correct
 * server-only code as client-exposed.
 */

/** `import 'server-only'` (or require) — the strongest "this never reaches the browser" signal. */
const SERVER_ONLY_IMPORT = /(?:import\s+['"]server-only['"]|require\(\s*['"]server-only['"]\s*\))/;

/** Paths that are unambiguously server-side. */
const SERVER_PATH =
  /(?:(?:^|\/)(?:app|pages)\/api\/|(?:^|\/)api\/|(?:^|\/)server\/|\.server\.[mc]?[jt]sx?$|(?:^|\/)route\.[mc]?[jt]sx?$|(?:^|\/)middleware\.[mc]?[jt]sx?$|\.(?:server-action|actions)\.[mc]?[jt]sx?$)/i;

/** Conventionally client-side locations (only when there is no server marker). */
const CLIENT_DIR = /(?:^|\/)(?:components|hooks)\//i;

/** Non-React client file types (plain web pages, Vue, Svelte). */
const CLIENT_FILE_EXT = /\.(?:html|vue|svelte)$/i;

/**
 * Does a top-of-module directive (e.g. 'use client' / 'use server') exist?
 * Directives are string-literal statements that must appear before any real
 * code, so we only scan the leading lines and stop at the first statement.
 *
 * @param {string} content
 * @param {'use client' | 'use server'} directive
 * @returns {boolean}
 */
export function hasDirective(content, directive) {
  const lines = content.split('\n');
  const directiveRe = new RegExp(`^['"]${directive}['"];?$`);
  const anyDirectiveRe = /^['"][^'"]+['"];?$/;
  for (let i = 0; i < Math.min(lines.length, 25); i++) {
    const t = lines[i].trim();
    if (!t || t.startsWith('//') || t.startsWith('/*') || t.startsWith('*')) continue;
    if (directiveRe.test(t)) return true;
    // Another directive (e.g. 'use strict') can precede ours — keep scanning.
    if (anyDirectiveRe.test(t)) continue;
    // First real statement reached; directives can't legally follow it.
    return false;
  }
  return false;
}

/** @param {{content: string}} file */
export function hasUseClient(file) {
  return hasDirective(file.content, 'use client');
}

/** @param {{content: string}} file */
export function hasUseServer(file) {
  return hasDirective(file.content, 'use server');
}

/**
 * Is this file guaranteed to run server-side (never shipped to the browser)?
 * @param {{content: string, relativePath: string}} file
 */
export function isServerOnly(file) {
  return (
    SERVER_ONLY_IMPORT.test(file.content) ||
    SERVER_PATH.test(file.relativePath) ||
    hasUseServer(file)
  );
}

/**
 * Does this file run on the client?
 *
 * TRUE only when there's an explicit `'use client'` directive, a plainly
 * client file type (.html/.vue/.svelte), or a conventional client path
 * (components/, hooks/) WITHOUT a server marker. Importing React is NOT
 * sufficient — App Router components are server-rendered by default.
 *
 * @param {{content: string, relativePath: string}} file
 */
export function isClient(file) {
  if (hasUseClient(file)) return true;
  if (isServerOnly(file)) return false;
  if (CLIENT_FILE_EXT.test(file.relativePath)) return true;
  return CLIENT_DIR.test(file.relativePath);
}

/** Default escaper / sanitizer function names that neutralize HTML before injection. */
export const DEFAULT_ESCAPERS = [
  'esc',
  'escape',
  'escapeHtml',
  'escapeHTML',
  'htmlEscape',
  'sanitize',
  'sanitizeHtml',
  'sanitizeHTML',
  'DOMPurify',
  'dompurify',
  'purify',
  'xss',
  'encodeURI',
  'encodeURIComponent',
  'textContent',
];

/**
 * Merge built-in escapers with any user-configured ones.
 * @param {{_config?: {customEscapers?: string[]}}} file
 * @returns {string[]}
 */
export function escapersFor(file) {
  const custom = file?._config?.customEscapers;
  return Array.isArray(custom) ? [...DEFAULT_ESCAPERS, ...custom] : DEFAULT_ESCAPERS;
}

/**
 * Build a regex that matches any escaper call (e.g. `esc(`, `DOMPurify.sanitize(`).
 * @param {string[]} escapers
 * @returns {RegExp}
 */
export function escaperRegex(escapers) {
  const names = escapers.map((e) => e.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  return new RegExp(`(?:${names})\\s*[.(]`, 'i');
}

/** Key/env-var names that are DESIGNED to ship to the browser (publishable, analytics, etc.). */
const PUBLIC_KEY_ALLOW =
  /PUBLISHABLE|MAPBOX|POSTHOG|GOOGLE_?MAPS|MAPS_API_KEY|RECAPTCHA_SITE|HCAPTCHA_SITE|TURNSTILE_SITE|ANON_KEY|SUPABASE_ANON|ALGOLIA_(?:APP|SEARCH)|SENTRY_DSN|MEASUREMENT_ID|MIXPANEL|AMPLITUDE|SEGMENT_WRITE|GA_TRACKING|GTAG/i;

/** ...unless the name ALSO carries a genuinely sensitive marker (then it's still a leak). */
const KEY_STILL_DANGEROUS =
  /SECRET|PRIVATE|SERVICE_ROLE|SERVICE_KEY|PASSWORD|PASSWD|ADMIN_KEY|MASTER_KEY|DATABASE_URL|DB_PASSWORD/i;

/**
 * Is this key/env-var name one that is intentionally public (safe in a client
 * bundle)? e.g. CLERK_PUBLISHABLE_KEY, NEXT_PUBLIC_MAPBOX_TOKEN, POSTHOG_KEY.
 * A GEMINI/STRIPE_SECRET/etc. key is NOT public and stays flagged.
 *
 * @param {string} name
 * @returns {boolean}
 */
export function isDesignedPublicKey(name) {
  return PUBLIC_KEY_ALLOW.test(name) && !KEY_STILL_DANGEROUS.test(name);
}

/**
 * Route paths that are public by convention — auth is not expected, so flagging
 * them as "missing auth" is noise. Webhooks authenticate by signature (a
 * separate rule covers that), so they're excluded here too.
 */
export const PUBLIC_ROUTE_CONVENTION =
  /(?:^|\/)(?:manifest|sitemap|robots|rss|feed|og|opengraph|icon|favicon|health|healthz|ping|status|version|webhooks?)(?:[.-][\w.-]*)?(?:\/|$)|\/public\//i;
