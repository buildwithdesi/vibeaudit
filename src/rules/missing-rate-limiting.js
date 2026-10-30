/**
 * Rule: missing-rate-limiting
 * Detects API routes that call paid external APIs without rate limiting.
 * This is how vibe-coded apps get $10K surprise bills.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Paid API SDKs and fetch patterns. */
const PAID_API_PATTERNS = [
  /new\s+(?:OpenAI|Anthropic|Stripe|Twilio|SendGrid)\s*\(/i,
  /openai\.(?:chat|completions|images|embeddings)\./i,
  /anthropic\.messages\./i,
  /stripe\.(?:charges|customers|subscriptions|paymentIntents)\./i,
  /twilio\.messages\.create/i,
  /fetch\s*\(\s*['"`]https:\/\/api\.openai\.com/i,
  /fetch\s*\(\s*['"`]https:\/\/api\.anthropic\.com/i,
  /fetch\s*\(\s*['"`]https:\/\/api\.stripe\.com/i,
];

/** Rate limiter indicators. */
const RATE_LIMIT_INDICATORS = [
  /rateLimit/i,
  /rateLimiter/i,
  /upstash.*ratelimit/i,
  /slidingWindow/i,
  /fixedWindow/i,
  /tokenBucket/i,
  /express-rate-limit/i,
  /bottleneck/i,
  /p-throttle/i,
  /limiter/i,
];

/** Only check server-side files. */
const SERVER_FILE_PATTERNS = /(?:api\/|routes\/|server\/|functions\/|middleware|\.server\.|pages\/api\/)/i;

/** Route names that are high-risk for brute-force or resource/cost abuse. */
const HIGH_RISK_ROUTE_NAMES = /(?:login|signup|register|forgot|reset|checkout|pay|stripe|payment|chat|ai\/|generate|translate|openai|anthropic|claude|gemini)/i;

/** Tests and type-only modules never serve requests. */
const SKIP_FILE = /(?:\.test\.|\.spec\.|__tests__\/|(?:^|\/)tests?\/|\.d\.ts$|(?:^|\/)types?\.[cm]?[jt]sx?$|\.types\.[cm]?[jt]sx?$)/i;

/**
 * Evidence the file actually serves HTTP requests. A server/ or api/ path alone
 * is not enough: helpers, types and local tool registries live there too.
 */
const ROUTE_SIGNALS = [
  // Next.js App Router handlers and Server Actions
  /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b/,
  /export\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)\s*=/,
  /['"]use server['"]/,
  // Express, Hono, Fastify, Koa, Flask, FastAPI style route registration
  /\b(?:app|router|api|route|routes|hono|fastify|server|bp|blueprint)\.(?:get|post|put|patch|delete|all|route|use)\s*\(/i,
  /\bnew\s+Hono\s*\(/,
  /\bcreateServer\s*\(/,
  // (req, res) handlers: Pages Router API routes, Vercel/Netlify functions
  /\(\s*req\b[^)]*,\s*res\b/,
  /export\s+(?:default\s+)?(?:async\s+)?function\s+handler\b|export\s+const\s+handler\s*=|exports\.handler\s*=/,
  /functions\.https\.on(?:Request|Call)\b|\bonRequest\s*\(/,
  // Workers-style fetch handlers and Python views
  /\basync\s+fetch\s*\(\s*request\b/,
  /\bdef\s+\w+\s*\(\s*request\b|@api_view\b/,
];

/** @type {Rule} */
export const missingRateLimiting = {
  id: 'missing-rate-limiting',
  name: 'Missing Rate Limiting',
  severity: 'warning',
  description: 'Detects API routes calling paid services or handling sensitive operations without rate limiting.',

  check(file) {
    if (!SERVER_FILE_PATTERNS.test(file.relativePath)) return [];
    if (SKIP_FILE.test(file.relativePath)) return [];

    // Without a real route or handler there is no endpoint to rate limit.
    // MCP tool registration (server.registerTool, register*Tools) is served
    // over stdio to a local client, so it only counts with an HTTP route too.
    const servesHttp = ROUTE_SIGNALS.some((p) => p.test(file.content));
    if (!servesHttp) return [];

    // Check if file calls any paid APIs or is a high-risk endpoint.
    let callsPaidAPI = false;
    let paidAPIName = '';
    const isHighRiskRoute = HIGH_RISK_ROUTE_NAMES.test(file.relativePath);

    if (isHighRiskRoute) {
      callsPaidAPI = true;
      paidAPIName = 'high-risk route path';
    } else {
      for (const pattern of PAID_API_PATTERNS) {
        if (pattern.test(file.content)) {
          callsPaidAPI = true;
          paidAPIName = file.content.match(pattern)?.[0] || 'paid API';
          break;
        }
      }
    }

    if (!callsPaidAPI) return [];

    // Check if file has rate limiting.
    const hasRateLimiting = RATE_LIMIT_INDICATORS.some((p) => p.test(file.content));

    if (hasRateLimiting) return [];

    const message = isHighRiskRoute
      ? `High-risk API route (path suggests auth, payments, or AI) has no rate limiting. A bot or abusive user could brute-force or abuse this endpoint.`
      : `API route calls a paid service but has no rate limiting. A bot or abusive user could run up your bill.`;

    return [
      {
        ruleId: 'missing-rate-limiting',
        ruleName: 'Missing Rate Limiting',
        severity: 'warning',
        message,
        file: file.relativePath,
        line: 1,
        evidence: isHighRiskRoute ? file.relativePath : paidAPIName.slice(0, 80),
        fix: `Add rate limiting before calling paid APIs or exposing sensitive actions. Use Upstash Ratelimit (serverless-friendly) or express-rate-limit. Set sensible per-user and global limits.`,
      },
    ];
  },
};
