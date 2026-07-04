/**
 * Rule registry.
 * Each rule exports: { id, name, severity, description, check(file) }
 * check() returns an array of findings.
 */

import { exposedSecrets } from './exposed-secrets.js';
import { hardcodedCredentials } from './hardcoded-credentials.js';
import { exposedEnvVars } from './exposed-env-vars.js';
import { openDatabaseRules } from './open-database-rules.js';
import { missingAuth } from './missing-auth.js';
import { noInputValidation } from './no-input-validation.js';
import { insecureErrorHandling } from './insecure-error-handling.js';
import { missingSecurityHeaders } from './missing-security-headers.js';
import { missingRateLimiting } from './missing-rate-limiting.js';
import { insecureConnections } from './insecure-connections.js';
// DevTools exposure rules
import { clientBundleSecrets } from './client-bundle-secrets.js';
import { clientOnlyAuth } from './client-only-auth.js';
import { sensitiveBrowserStorage } from './sensitive-browser-storage.js';
import { consoleDataLeak } from './console-data-leak.js';
import { sourceMapsExposed } from './source-maps-exposed.js';
import { clientSideTrust } from './client-side-trust.js';
import { apiDataOverfetch } from './api-data-overfetch.js';
// Vibe coder blindspot rules
import { idorVulnerability } from './idor-vulnerability.js';
import { missingCsrf } from './missing-csrf.js';
import { unsafeFileUpload } from './unsafe-file-upload.js';
import { massAssignment } from './mass-assignment.js';
import { unverifiedWebhook } from './unverified-webhook.js';
import { noPagination } from './no-pagination.js';
// Advanced blindspot rules
import { pathTraversal } from './path-traversal.js';
import { insecureJwt } from './insecure-jwt.js';
import { plaintextPasswords } from './plaintext-passwords.js';
import { insecureRandomness } from './insecure-randomness.js';
import { insecureCookies } from './insecure-cookies.js';
import { ssrfVulnerability } from './ssrf-vulnerability.js';
import { prototypePollution } from './prototype-pollution.js';
import { missingGitignore } from './missing-gitignore.js';
import { timingAttack } from './timing-attack.js';
import { corsCredentials } from './cors-credentials.js';
import { noAccountLockout } from './no-account-lockout.js';
import { unsafeRedirect } from './unsafe-redirect.js';
// Bot/agent attack rules
import { noBotProtection } from './no-bot-protection.js';
import { predictableIds } from './predictable-ids.js';
import { debugModeExposed } from './debug-mode-exposed.js';
import { secretsInUrls } from './secrets-in-urls.js';
// Framework-specific rules (v2)
import { nextjsServerActionExposure } from './nextjs-server-action-exposure.js';
import { nextjsMiddlewareBypass } from './nextjs-middleware-bypass.js';
import { nextjsApiRouteNoMethodCheck } from './nextjs-api-route-no-method-check.js';
import { supabaseMissingRls } from './supabase-missing-rls.js';
import { supabaseServiceKeyClient } from './supabase-service-key-client.js';
import { supabaseAnonKeyAbuse } from './supabase-anon-key-abuse.js';
import { firebaseAdminClient } from './firebase-admin-client.js';
import { vercelEnvLeak } from './vercel-env-leak.js';
import { netlifyRedirectOpen } from './netlify-redirect-open.js';
import { deploymentConfigInsecure } from './deployment-config-insecure.js';
// AI & API security rules (v2)
import { aiPromptInjection } from './ai-prompt-injection.js';
import { aiResponseTrusted } from './ai-response-trusted.js';
import { aiCostExposure } from './ai-cost-exposure.js';
import { stripeWebhookNoVerify } from './stripe-webhook-no-verify.js';
import { paymentAmountClient } from './payment-amount-client.js';
// Data & privacy rules (v2)
import { piiLogging } from './pii-logging.js';
import { missingDataEncryption } from './missing-data-encryption.js';
import { graphqlIntrospection } from './graphql-introspection.js';
import { graphqlDepthLimit } from './graphql-depth-limit.js';
import { graphqlNoAuth } from './graphql-no-auth.js';
// Session & auth hardening rules (v2)
import { sessionFixation } from './session-fixation.js';
import { oauthStateMissing } from './oauth-state-missing.js';
import { passwordResetWeak } from './password-reset-weak.js';
import { mfaBypass } from './mfa-bypass.js';
import { authTokenNoExpiry } from './auth-token-no-expiry.js';
// Expanded category rules (v2)
import { raceCondition } from './race-condition.js';
import { nosqlInjection } from './nosql-injection.js';
import { xmlXxe } from './xml-xxe.js';
import { ldapInjection } from './ldap-injection.js';
import { headerInjection } from './header-injection.js';
import { subdomainTakeover } from './subdomain-takeover.js';
import { clickjacking } from './clickjacking.js';
import { dangerouslySetInnerHtml } from './dangerously-set-inner-html.js';
import { evalUsage } from './eval-usage.js';
import { regexDos } from './regex-dos.js';
import { hardcodedIp } from './hardcoded-ip.js';
// Extended secrets detection (v2)
import { highEntropyStrings } from './high-entropy-strings.js';
import { gitHistorySecrets } from './git-history-secrets.js';
import { dockerRootUser } from './docker-root-user.js';
import { exposedDatabasePort } from './exposed-database-port.js';
import { serverlessFsWrite } from './serverless-fs-write.js';
import { clientSideDbAccess } from './client-side-db-access.js';
// Accessibility / WCAG (v1.2)
import { a11yImgNoAlt } from './a11y-img-no-alt.js';
import { a11yFormNoLabel } from './a11y-form-no-label.js';
import { a11yNoLang } from './a11y-no-lang.js';
import { a11yButtonNoName } from './a11y-button-no-name.js';
import { a11yPositiveTabindex } from './a11y-positive-tabindex.js';
import { a11yClickNoKeyboard } from './a11y-click-no-keyboard.js';
// Scale / Performance (v1.2)
import { perfNPlusOne } from './perf-n-plus-one.js';
import { perfNoAwaitParallel } from './perf-no-await-parallel.js';
import { perfDbClientPerRequest } from './perf-db-client-per-request.js';
// Injection & observability (v1.2)
import { commandInjection } from './command-injection.js';
import { unsafeDeserialization } from './unsafe-deserialization.js';
import { noErrorMonitoring } from './no-error-monitoring.js';
// Supply chain & template injection (v1.2)
import { templateInjection } from './template-injection.js';
import { missingSri } from './missing-sri.js';
import { unpinnedDependencies } from './unpinned-dependencies.js';

/** @type {import('./types.js').Rule[]} */
export const ALL_RULES = [
  // Core security
  exposedSecrets,
  hardcodedCredentials,
  exposedEnvVars,
  openDatabaseRules,
  missingAuth,
  noInputValidation,
  insecureErrorHandling,
  missingSecurityHeaders,
  missingRateLimiting,
  insecureConnections,
  clientSideDbAccess,
  // DevTools exposure
  clientBundleSecrets,
  clientOnlyAuth,
  sensitiveBrowserStorage,
  consoleDataLeak,
  sourceMapsExposed,
  clientSideTrust,
  apiDataOverfetch,
  // Vibe coder blindspots
  idorVulnerability,
  missingCsrf,
  unsafeFileUpload,
  massAssignment,
  unverifiedWebhook,
  noPagination,
  // Advanced blindspots
  pathTraversal,
  insecureJwt,
  plaintextPasswords,
  insecureRandomness,
  insecureCookies,
  ssrfVulnerability,
  prototypePollution,
  missingGitignore,
  timingAttack,
  corsCredentials,
  noAccountLockout,
  unsafeRedirect,
  // Bot/agent attacks
  noBotProtection,
  predictableIds,
  debugModeExposed,
  secretsInUrls,
  // Framework-specific (v2)
  nextjsServerActionExposure,
  nextjsMiddlewareBypass,
  nextjsApiRouteNoMethodCheck,
  supabaseMissingRls,
  supabaseServiceKeyClient,
  supabaseAnonKeyAbuse,
  firebaseAdminClient,
  vercelEnvLeak,
  netlifyRedirectOpen,
  deploymentConfigInsecure,
  // AI & API security (v2)
  aiPromptInjection,
  aiResponseTrusted,
  aiCostExposure,
  stripeWebhookNoVerify,
  paymentAmountClient,
  // Data & privacy (v2)
  piiLogging,
  missingDataEncryption,
  graphqlIntrospection,
  graphqlDepthLimit,
  graphqlNoAuth,
  // Session & auth hardening (v2)
  sessionFixation,
  oauthStateMissing,
  passwordResetWeak,
  mfaBypass,
  authTokenNoExpiry,
  // Expanded categories (v2)
  raceCondition,
  nosqlInjection,
  xmlXxe,
  ldapInjection,
  headerInjection,
  subdomainTakeover,
  clickjacking,
  dangerouslySetInnerHtml,
  evalUsage,
  regexDos,
  hardcodedIp,
  // Extended secrets (v2)
  highEntropyStrings,
  gitHistorySecrets,
  // Infrastructure (v3)
  dockerRootUser,
  exposedDatabasePort,
  serverlessFsWrite,
  // Accessibility / WCAG (v1.2)
  a11yImgNoAlt,
  a11yFormNoLabel,
  a11yNoLang,
  a11yButtonNoName,
  a11yPositiveTabindex,
  a11yClickNoKeyboard,
  // Scale / Performance (v1.2)
  perfNPlusOne,
  perfNoAwaitParallel,
  perfDbClientPerRequest,
  // Injection & observability (v1.2)
  commandInjection,
  unsafeDeserialization,
  noErrorMonitoring,
  // Supply chain & template injection (v1.2)
  templateInjection,
  missingSri,
  unpinnedDependencies,
];

/**
 * @param {string[]} ruleIds - IDs of rules to include (empty = all)
 * @param {string[]} excludeIds - IDs of rules to exclude
 * @returns {import('./types.js').Rule[]}
 */
export function resolveRules(ruleIds = [], excludeIds = []) {
  const excludeSet = new Set(excludeIds);
  let rules = ALL_RULES.filter((r) => !excludeSet.has(r.id));

  if (ruleIds.length > 0) {
    const includeSet = new Set(ruleIds);
    rules = rules.filter((r) => includeSet.has(r.id));
  }

  return rules;
}
