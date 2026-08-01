/**
 * Rule: exposed-secrets
 * Detects API keys, tokens, and secrets committed directly in source files.
 * This is the #1 vibe-code security failure.
 */

/** @typedef {import('./types.js').Rule} Rule */

/**
 * Patterns that indicate a secret value (not a variable reference).
 * Each entry: [regex, label, fix advice].
 * Regexes are intentionally strict to reduce false positives.
 */
const SECRET_PATTERNS = [
  // Firebase / Google
  [/AIza[0-9A-Za-z_-]{35}/g, 'Google API key'],
  // AWS
  [/AKIA[0-9A-Z]{16}/g, 'AWS access key ID'],
  [/(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g, 'Possible AWS secret key', true],
  // Stripe
  [/sk_live_[0-9a-zA-Z]{24,}/g, 'Stripe live secret key'],
  [/sk_test_[0-9a-zA-Z]{24,}/g, 'Stripe test secret key'],
  [/rk_live_[0-9a-zA-Z]{24,}/g, 'Stripe restricted key'],
  // OpenAI
  [/sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, 'OpenAI API key'],
  [/sk-proj-[A-Za-z0-9_-]{40,}/g, 'OpenAI project API key'],
  // Anthropic
  [/sk-ant-[A-Za-z0-9_-]{40,}/g, 'Anthropic API key'],
  // GitHub
  [/gh[pousr]_[A-Za-z0-9_]{36,}/g, 'GitHub token'],
  // Slack
  [/xox[bpoas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}/g, 'Slack token'],
  // Supabase
  [/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/g, 'JWT / Supabase service key'],
  // Twilio
  [/SK[0-9a-fA-F]{32}/g, 'Twilio API key'],
  // SendGrid
  [/SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, 'SendGrid API key'],
  // Private keys
  [/-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, 'Private key'],
  // Database URLs with credentials
  [/(?:postgres|postgresql|mysql|mongodb|mongodb\+srv):\/\/[^:]+:[^@]+@[^/\s'"]+/g, 'Database URL with credentials'],
  // Discord
  [/(?:discord|bot).*['"]\s*[:=]\s*['"][A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/g, 'Discord bot token', true],
  // Heroku
  [/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, 'Possible Heroku API key / UUID secret', true],
  // Vercel
  [/vercel_[A-Za-z0-9_-]{24,}/g, 'Vercel token'],
  // Cloudflare
  [/(?:cloudflare|cf).*['"]\s*[:=]\s*['"][A-Za-z0-9_-]{37,}/g, 'Cloudflare API token', true],
  // DigitalOcean
  [/dop_v1_[A-Fa-f0-9]{64}/g, 'DigitalOcean personal access token'],
  [/doo_v1_[A-Fa-f0-9]{64}/g, 'DigitalOcean OAuth token'],
  // Mailgun
  [/key-[0-9a-zA-Z]{32}/g, 'Mailgun API key'],
  // Azure
  [/(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{40,}/g, 'Azure storage connection string'],
];

/** Files where secrets are expected and NOT a problem. */
const IGNORE_FILES = /\.(env\.example|env\.sample|env\.template)$/;

/** Test/spec files and fixtures intentionally contain fake secrets to exercise this rule. */
const SKIP = /(?:\.test\.|\.spec\.|__tests__|fixtures\/|src\/rules\/|reports\/)/i;

/** Lines that are clearly commented out or documentation. */
function isCommentOrDoc(line) {
  const trimmed = line.trim();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('#') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('<!--') ||
    trimmed.startsWith('/*')
  );
}

/** Redact a secret for safe display: show first 4 and last 4 chars. */
function redact(secret) {
  if (secret.length <= 12) return '***REDACTED***';
  return `${secret.slice(0, 4)}...(redacted)...${secret.slice(-4)}`;
}

/** @type {Rule} */
export const exposedSecrets = {
  id: 'exposed-secrets',
  name: 'Exposed Secrets',
  severity: 'critical',
  description: 'Detects API keys, tokens, and secrets committed in source code.',

  check(file) {
    // Skip example env files.
    if (IGNORE_FILES.test(file.relativePath)) return [];
    // Skip test fixtures — fake secrets there are intentional, not real leaks.
    if (SKIP.test(file.relativePath)) return [];

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (isCommentOrDoc(line)) continue;

      for (const [pattern, label, isLoose] of SECRET_PATTERNS) {
        // Reset regex lastIndex for global patterns.
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(line)) !== null) {
          // For loose patterns (like AWS secret), require assignment context.
          if (isLoose) {
            const before = line.slice(0, match.index);
            if (!/(?:secret|key|token|password|credential|auth)\s*[:=]/i.test(before)) {
              continue;
            }
          }

          findings.push({
            ruleId: 'exposed-secrets',
            ruleName: 'Exposed Secrets',
            severity: 'critical',
            message: `${label} found in source code.`,
            file: file.relativePath,
            line: i + 1,
            evidence: redact(match[0]),
            fix: `Move this ${label} to an environment variable. Add the variable to .env (git-ignored) and reference it via process.env.YOUR_KEY_NAME. Never commit secrets to source control.`,
          });
        }
      }
    }

    return findings;
  },
};
