/**
 * Free-credit pack (FCA-01 … FCA-11).
 *
 * Static checks for the drain pattern in the Oct 30, 2026 audit: a paid AI or
 * data API that a free or unverified caller can reach, with limits that reset
 * on deploy and no dollar ceiling. Rule sources live under src/rules/ and
 * contain these literals, so that tree is not treated as an application.
 *
 * Cross-file reachability is one import hop. A route that only calls a helper
 * emits a provisional finding; project-context resolves it after the file
 * stream ends. Direct hits are final on their own.
 */

/** @typedef {import('./types.js').Rule} Rule */
/** @typedef {import('./types.js').Finding} Finding */

import { redactSecretValues } from '../redact-secrets.js';

const PROVIDERS = [
  {
    id: 'openai',
    llm: true,
    call: /(?:openai|client)\.chat\.completions\.create\s*\(|openai\.(?:completions|responses|images|embeddings)(?:\.[A-Za-z]+)?\.create\s*\(|api\.openai\.com/g,
    mention: /from\s+['"]openai['"]|require\(\s*['"]openai['"]\)/g,
  },
  {
    id: 'anthropic',
    llm: true,
    call: /anthropic\.messages\.create\s*\(|api\.anthropic\.com/g,
    mention: /from\s+['"]@anthropic-ai\/sdk['"]/g,
  },
  {
    id: 'gemini',
    llm: true,
    call: /generateContent\s*\(|generativelanguage\.googleapis\.com/g,
    mention: /@google\/genai|@google\/generative-ai|GoogleGenerativeAI|GoogleGenAI/g,
  },
  {
    id: 'deepgram',
    llm: false,
    call: /api\.deepgram\.com|deepgram\.listen\.|new\s+DeepgramClient\s*\(/g,
    mention: /@deepgram\/sdk/g,
  },
  {
    id: 'openrouter',
    llm: true,
    call: /openrouter\.ai/g,
    mention: /from\s+['"]@openrouter\/sdk['"]/g,
  },
  {
    id: 'deepseek',
    llm: true,
    call: /api\.deepseek\.com/g,
    mention: /from\s+['"]deepseek['"]/g,
  },
  {
    id: 'xai',
    llm: true,
    call: /api\.x\.ai/g,
    mention: /from\s+['"]@ai-sdk\/xai['"]/g,
  },
  {
    id: 'replicate',
    llm: false,
    call: /api\.replicate\.com|replicate\.run\s*\(/g,
    mention: /from\s+['"]replicate['"]/g,
  },
  {
    id: 'firecrawl',
    llm: false,
    call: /api\.firecrawl\.dev/g,
    mention: /@mendable\/firecrawl|from\s+['"]firecrawl['"]/g,
  },
  {
    id: 'scrapecreators',
    llm: false,
    call: /scrapecreators\.com/g,
    mention: /from\s+['"]scrapecreators['"]/g,
  },
];

const CLIENT_KEY = /(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)[A-Z0-9_]*(?:OPENAI|ANTHROPIC|GEMINI|GOOGLE_AI|DEEPGRAM|OPENROUTER|DEEPSEEK|XAI|REPLICATE|FIRECRAWL)[A-Z0-9_]*/g;

const VERIFIED_CHECK = /verification(?:\??\.status)?\s*(?:===|!==|==|!=)\s*['"]verified['"]|verifiedPrimaryEmail/;
const ENTITLEMENT = /requireAuthedApiFromReq\s*\([^)]*['"](?:engine|admin|paid)['"]|\bcanEngine\b|ATLAS_ALLOWED_EMAIL|ALLOWED_EMAIL|allowlist|\bassertAdmin\s*\(|\brequireAdmin\s*\(|\bisPaid\b|\bhasActiveSubscription\b/;
const SESSION_GATE = /requireAuthedApiFromReq\s*\([^)]*['"]session['"]|['"]any-user['"]|mode\s*[:=]\s*['"]session['"]/;
const AUTH_GATE = /requireAuthedApiFromReq\s*\(|\bauth\s*\(|\bgetUser\s*\(|getServerSession\s*\(|\bcurrentUser\s*\(|verifyIdToken\s*\(|requireAuth\s*\(|withAuth\s*\(|clerkMiddleware\s*\(|headers\.get\(\s*['"]authorization['"]\)|startsWith\(\s*['"]Bearer|ATLAS_ALLOWED_EMAIL|ALLOWED_EMAIL|allowlist/;
const PER_USER_CAP = /checkKeyedRateLimit\s*\(|ratelimit\.limit\s*\(|\.limit\s*\(\s*(?:userId|user\.id|session\.user)|consumeQuota\s*\(|checkQuota\s*\(|rpc\(\s*['"][^'"]*(?:quota|credit)/i;
const SHARED_LIMITER = /@upstash\/|upstash|ioredis|from\s+['"]redis['"]|new\s+Redis\b|@vercel\/kv/i;
const KEY_MINT = /(?:apiKeys|api_keys)\s*\.\s*create\s*\(|createApiKey\s*\(|mintApiKey\s*\(|generateApiKey\s*\(/;
const KEY_CAP = /\.count\s*\(|\.length\s*>=|maxKeys|activeKeys|keyLimit|keys\.length/;
const EMAIL_TRUST = /ADMIN_EMAILS|allowlist|community_members|communityMembers|ALLOWED_EMAIL|entitlement/;
const EMAIL_READ = /primaryEmailAddress|emailAddresses/;
const EMAIL_NORMALIZE = /split\(\s*['"]\+['"]\)|replace\(\s*\/\\\.\/g|DISPOSABLE|disposable|normalizeEmail|stripPlus|stripDots/;

function normalize(relativePath) {
  return String(relativePath || '').replace(/\\/g, '/');
}

function skip(file) {
  const p = normalize(file.relativePath);
  if (/(?:^|\/)src\/rules\//.test(p)) return true;
  if (/(?:^|\/)node_modules\//.test(p)) return true;
  if (/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(p)) return true;
  if (/(?:^|\/)(?:__tests__|fixtures|coverage|dist|build)\//.test(p)) return true;
  if (/\.(?:json|lock|yaml|yml|md|mdx|css|map)$/.test(p) || /\.d\.ts$/.test(p)) return true;
  if (/(?:^|\/)package(?:-lock)?\.json$/.test(p)) return true;
  return false;
}

function isSource(file) {
  return /\.(?:js|jsx|ts|tsx|mjs|cjs|vue|svelte|py|rb|go|php|html?)$/.test(normalize(file.relativePath));
}

function isEnvFile(file) {
  return /(?:^|\/)\.env(?:\.|$)/.test(normalize(file.relativePath));
}

export function isClientFile(file, content) {
  const p = normalize(file.relativePath);
  if (/\.server\.[cm]?[jt]sx?$/.test(p)) return false;
  if (/(?:^|\/)(?:app\/api|pages\/api)\//.test(p)) return false;
  const head = String(content || '').slice(0, 400);
  if (/['"]use client['"]/.test(head)) return true;
  return /(?:^|\/)(?:src\/components|components|public|mobile)\//.test(p);
}

function isRouteFile(file) {
  const p = normalize(file.relativePath);
  return /(?:^|\/)app\/(?:.+\/)?route\.[cm]?[jt]sx?$/.test(p)
    || /(?:^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/.test(p)
    || /(?:^|\/)api\/.+\.[cm]?[jt]sx?$/.test(p)
    || /(?:^|\/)routes\/.+\.[cm]?[jt]sx?$/.test(p)
    || /(?:^|\/)functions\/.+\.[cm]?[jt]sx?$/.test(p);
}

function isMiddlewareFile(file) {
  return /(?:^|\/)(?:src\/)?middleware\.[cm]?[jt]sx?$/.test(normalize(file.relativePath));
}

/**
 * Drop comments without shifting line numbers. Strings stay, so a fetch URL
 * is still visible and a commented-out example is not.
 *
 * @param {string} source
 */
export function stripComments(source) {
  const text = String(source || '');
  let out = '';
  let i = 0;
  let state = 'code';
  while (i < text.length) {
    const c = text[i];
    const n = text[i + 1];
    if (state === 'code') {
      if (c === '/' && n === '/') {
        state = 'line';
        i += 2;
        continue;
      }
      if (c === '/' && n === '*') {
        state = 'block';
        i += 2;
        continue;
      }
      if (c === "'" || c === '"' || c === '`') {
        state = c;
        out += c;
        i += 1;
        continue;
      }
      out += c;
      i += 1;
      continue;
    }
    if (state === 'line') {
      if (c === '\n') {
        state = 'code';
        out += c;
      }
      i += 1;
      continue;
    }
    if (state === 'block') {
      if (c === '*' && n === '/') {
        state = 'code';
        i += 2;
        continue;
      }
      if (c === '\n') out += c;
      i += 1;
      continue;
    }
    out += c;
    if (c === '\\') {
      if (n) out += n;
      i += 2;
      continue;
    }
    if (c === state) state = 'code';
    i += 1;
  }
  return out;
}

function codeOf(file) {
  if (typeof file._freeCreditCode === 'string') return file._freeCreditCode;
  file._freeCreditCode = stripComments(file.content);
  return file._freeCreditCode;
}

function lineAt(text, index) {
  return text.slice(0, index).split('\n').length;
}

function evidenceLine(file, line) {
  const raw = file.lines?.[line - 1] ?? '';
  return redactSecretValues(raw.trim()).slice(0, 120);
}

function finding(rule, file, line, message, fix, evidence) {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    message: redactSecretValues(message),
    file: file.relativePath,
    line,
    evidence: redactSecretValues(evidence ?? evidenceLine(file, line)).slice(0, 120),
    fix,
  };
}

function execAll(pattern, text) {
  pattern.lastIndex = 0;
  const hits = [];
  let match = pattern.exec(text);
  while (match) {
    hits.push(match.index);
    if (match[0].length === 0) pattern.lastIndex += 1;
    match = pattern.exec(text);
  }
  return hits;
}

/** Actual billed calls and provider URLs. Imports alone are not calls. */
export function findProviderCalls(code) {
  const hits = [];
  for (const provider of PROVIDERS) {
    for (const index of execAll(provider.call, code)) {
      hits.push({ provider: provider.id, index, llm: provider.llm });
    }
  }
  return hits;
}

function findProviderMentions(code) {
  const ids = new Set(findProviderCalls(code).map((hit) => hit.provider));
  for (const provider of PROVIDERS) {
    if (execAll(provider.mention, code).length > 0) ids.add(provider.id);
  }
  return [...ids];
}

function routeUrl(relativePath) {
  const p = normalize(relativePath);
  const app = /(?:^|\/)app\/(.+)\/route\.[cm]?[jt]sx?$/.exec(p);
  if (app) {
    const segments = app[1].split('/').filter((segment) => !/^\(.*\)$/.test(segment) && !segment.startsWith('@'));
    return `/${segments.join('/')}`;
  }
  const pages = /(?:^|\/)pages\/(api\/.+)\.[cm]?[jt]sx?$/.exec(p);
  if (pages) return `/${pages[1].replace(/\/index$/, '')}`;
  return null;
}

function moduleIds(relativePath) {
  const base = normalize(relativePath).replace(/\.(?:[cm]?[jt]sx?|vue|svelte|py)$/, '');
  const ids = new Set([base]);
  if (base.endsWith('/index')) ids.add(base.slice(0, -'/index'.length));
  return [...ids];
}

function resolveImport(spec, fromFile) {
  if (spec.startsWith('@/')) return `src/${spec.slice(2)}`.replace(/\.(?:[cm]?[jt]sx?)$/, '');
  if (!spec.startsWith('.')) return null;
  const dir = normalize(fromFile).split('/').slice(0, -1);
  const parts = dir.concat(spec.split('/'));
  const out = [];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') out.pop();
    else out.push(part);
  }
  return out.join('/').replace(/\.(?:[cm]?[jt]sx?)$/, '');
}

function calledLocalImports(code) {
  const specs = [];
  const re = /import\s+(?:type\s+)?([^'";]+?)\s+from\s+['"]([^'"]+)['"]/g;
  let match = re.exec(code);
  while (match) {
    const clause = match[1];
    const spec = match[2];
    if (spec.startsWith('.') || spec.startsWith('@/')) {
      const names = [];
      const brace = /\{([^}]+)\}/.exec(clause);
      if (brace) {
        for (const part of brace[1].split(',')) {
          const piece = part.trim();
          if (!piece) continue;
          const alias = piece.split(/\s+as\s+/);
          names.push((alias[1] || alias[0]).trim());
        }
      }
      const rest = clause.replace(/\{[^}]*\}/g, '').split(',').map((part) => part.trim()).filter(Boolean);
      names.push(...rest);
      const called = names.some((name) => name && new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\(`).test(code));
      if (called) specs.push(spec);
    }
    match = re.exec(code);
  }
  return specs;
}

function providersForSpec(spec, fromFile, modules) {
  const resolved = resolveImport(spec, fromFile);
  if (!resolved || !modules) return [];
  const direct = modules.get(resolved) || modules.get(`${resolved}/index`);
  return direct ? [...direct] : [];
}

function hasVerifiedCheck(code) {
  return VERIFIED_CHECK.test(code);
}

function hasEntitlement(code) {
  return ENTITLEMENT.test(code) || hasVerifiedCheck(code);
}

export function hasPerUserCap(code) {
  return PER_USER_CAP.test(code);
}

export function hasSharedLimiter(code) {
  return SHARED_LIMITER.test(code);
}

export function hasSpendGuardBefore(code, index) {
  const before = code.slice(Math.max(0, index - 2000), index);
  if (/reserve[A-Za-z]*\s*\(/.test(before)) return true;
  if (/(?:assertBudget|withinSpendCap|checkSpend|creditFuse|credit_fuse)\s*\(/.test(before)) return true;
  if (/logUsage\s*\(/.test(before) && /(?:cap|ceiling|budget|allowance|quota|remaining)\s*(?:<=|>=|<|>|===)/.test(before)) {
    return true;
  }
  return false;
}

/** Free accounts, or an identity check that never asks whether the email is verified. */
export function reachableByFreeOrUnverified(code) {
  const unverifiedIdentity = EMAIL_READ.test(code) && !hasVerifiedCheck(code) && EMAIL_TRUST.test(code);
  if (unverifiedIdentity) return true;
  return !hasEntitlement(code);
}

function hasAuth(code) {
  return AUTH_GATE.test(code) || hasEntitlement(code);
}

function isSessionOnly(code) {
  return SESSION_GATE.test(code) && !hasEntitlement(code);
}

function extractPublicPaths(code) {
  const blocks = [];
  const matcher = /createRouteMatcher\s*\(\s*\[([\s\S]*?)\]\s*\)/g;
  let match = matcher.exec(code);
  while (match) {
    blocks.push(match[1]);
    match = matcher.exec(code);
  }
  const lists = /(?:publicRoutes|PUBLIC_ROUTES)\s*=\s*\[([\s\S]*?)\]/g;
  match = lists.exec(code);
  while (match) {
    blocks.push(match[1]);
    match = lists.exec(code);
  }
  const paths = [];
  for (const block of blocks) {
    const literals = block.matchAll(/['"`]([^'"`]+)['"`]/g);
    for (const literal of literals) paths.push(literal[1]);
  }
  return paths;
}

function pathListed(url, patterns) {
  if (!url) return false;
  return patterns.some((raw) => {
    let pattern = String(raw).trim();
    if (!pattern.startsWith('/')) return false;
    if (pattern === '/(.*)' || pattern === '/:path*' || pattern === '/:path(.*)') return false;
    pattern = pattern.replace(/\(\.\*\)$/, '').replace(/\/:path\*$/, '').replace(/\/+$/, '') || '/';
    return url === pattern || url.startsWith(`${pattern}/`);
  });
}

function outputCapped(code, index) {
  return /max_tokens|maxTokens|max_completion_tokens|maxOutputTokens|max_output_tokens/i.test(code.slice(index, index + 700));
}

const FIX = {
  'fca-01': 'Treat this file as a spend site. Put it behind an entitlement check, a per-user cap, a shared limiter, and a dollar ceiling before the provider call.',
  'fca-02': 'Remove the provider key from any NEXT_PUBLIC_, VITE_, or EXPO_PUBLIC_ variable and from client components. Call the provider from a server handler that never ships the key, then rotate the key that was exposed.',
  'fca-03': 'Require auth and an entitlement (paid, trial allowlist, or engine) before the provider call. Keep the route off the middleware public list unless it truly must be anonymous, and anonymous routes must not call a paid API.',
  'fca-04': 'Do not spend from a session-only or any-signed-in gate. Require a paid plan, an allowlist, or an engine entitlement, and require the email to be verified.',
  'fca-05': 'Add a per-user cap in the handler, such as checkKeyedRateLimit(bucket, userId) or ratelimit.limit(userId), before the provider call.',
  'fca-06': 'Back the limiter with Redis, Upstash, or a database so a deploy or a second instance does not reset the budget. Keep an in-memory Map only for local development.',
  'fca-07': 'Reserve or check a per-account and global dollar ceiling before the provider call (reserveCredits, or logUsage that stops when the cap is hit). Logging the cost after the call does not stop the bill.',
  'fca-08': 'Trust an email for admin, trial, or entitlement only when verification.status is "verified". Return null from the email helper otherwise.',
  'fca-09': 'Normalize emails before allowlist or signup matching: lowercase, strip +tags, strip dots for gmail.com and googlemail.com, and reject disposable domains.',
  'fca-10': 'Count active keys for the user and refuse to mint another once the plan cap is reached.',
  'fca-11': 'Turn on CAPTCHA at signup (Cloudflare Turnstile, hCaptcha, or reCAPTCHA) and record that Clerk bot protection is enabled. A note in the component is not a substitute for the dashboard setting, but the scanner needs one of those signals.',
};

function baseRule(id, name, severity, description, check) {
  return { id, name, severity, description, check };
}

function serverCode(file) {
  if (skip(file) || !isSource(file) || isEnvFile(file)) return null;
  const code = codeOf(file);
  if (isClientFile(file, file.content)) return null;
  return code;
}

export const fca01 = baseRule(
  'fca-01',
  'FCA-01 Provider call map',
  'info',
  'Inventory of server files that import or call a paid AI or data API.',
  (file) => {
    const code = serverCode(file);
    if (code === null) return [];
    const route = routeUrl(file.relativePath) || 'n/a';
    const mentions = findProviderMentions(code);
    const findings = mentions.map((provider) => {
      const index = findProviderCalls(code).find((hit) => hit.provider === provider)?.index ?? 0;
      return finding(
        fca01,
        file,
        lineAt(code, index),
        `FCA-01: ${provider} in this server file (route: ${route}). Inventory of a paid API call. A route that can reach it spends the ${provider} wallet.`,
        FIX['fca-01'],
        `${file.relativePath} | ${provider} | ${route}`,
      );
    });
    requestHop(fca01, file);
    return findings;
  },
);

export const fca02 = baseRule(
  'fca-02',
  'FCA-02 AI key in client',
  'critical',
  'Provider key or provider call reachable by the browser. Reports the variable name and file, never the value.',
  (file) => {
    if (skip(file)) return [];
    const findings = [];
    CLIENT_KEY.lastIndex = 0;
    const seen = new Set();
    let match = CLIENT_KEY.exec(file.content || '');
    while (match) {
      const name = match[0];
      if (!seen.has(name)) {
        seen.add(name);
        const line = lineAt(file.content, match.index);
        findings.push(finding(
          fca02,
          file,
          line,
          `FCA-02: browser-exposed provider variable ${name}. A bot farm can read this key and spend the wallet without an account.`,
          FIX['fca-02'],
          name,
        ));
      }
      match = CLIENT_KEY.exec(file.content || '');
    }
    if (!isSource(file) || isEnvFile(file) || !isClientFile(file, file.content)) return findings;
    const code = codeOf(file);
    const calls = findProviderCalls(code);
    const reported = new Set();
    for (const hit of calls) {
      if (reported.has(hit.provider)) continue;
      reported.add(hit.provider);
      findings.push(finding(
        fca02,
        file,
        lineAt(code, hit.index),
        `FCA-02: ${hit.provider} call in client code. The browser can trigger paid spend. The finding names the provider and file only.`,
        FIX['fca-02'],
        `${hit.provider} call`,
      ));
    }
    return findings;
  },
);

export const fca03 = baseRule(
  'fca-03',
  'FCA-03 Unauthed spend path',
  'critical',
  'Route that reaches a paid API with no auth, entitlement, Bearer check, or allowlist, including routes listed as public in middleware.',
  (file) => {
    const code = serverCode(file);
    if (code === null) return [];
    const findings = [];
    if (isMiddlewareFile(file)) requestPublicList(file, extractPublicPaths(code));
    if (!isRouteFile(file)) return findings;
    const calls = findProviderCalls(code);
    if (calls.length > 0 && !hasAuth(code)) {
      const hit = calls[0];
      findings.push(finding(
        fca03,
        file,
        lineAt(code, hit.index),
        `FCA-03: this route calls ${hit.provider} with no auth or entitlement gate. A bot farm can call it and drain the wallet.`,
        FIX['fca-03'],
      ));
    } else if (calls.length === 0 && !hasAuth(code)) {
      requestHop(fca03, file);
    }
    return findings;
  },
);

export const fca04 = baseRule(
  'fca-04',
  'FCA-04 Sign-in-only spend',
  'warning',
  'Spend path gated only by being signed in, not by a paid plan, trial allowlist, or engine entitlement.',
  (file) => {
    const code = serverCode(file);
    if (code === null || !isRouteFile(file) || !isSessionOnly(code)) return [];
    const calls = findProviderCalls(code);
    if (calls.length > 0) {
      return [finding(
        fca04,
        file,
        lineAt(code, calls[0].index),
        `FCA-04: this ${calls[0].provider} path is open to any signed-in user. A bot farm can make free accounts and spend the wallet.`,
        FIX['fca-04'],
      )];
    }
    requestHop(fca04, file);
    return [];
  },
);

export const fca05 = baseRule(
  'fca-05',
  'FCA-05 No per-user cap',
  'warning',
  'Spend route with no per-user limit (checkKeyedRateLimit, ratelimit.limit(userId), or a quota RPC).',
  (file) => {
    const code = serverCode(file);
    if (code === null || !isRouteFile(file) || hasPerUserCap(code)) return [];
    const calls = findProviderCalls(code);
    if (calls.length > 0) {
      return [finding(
        fca05,
        file,
        lineAt(code, calls[0].index),
        `FCA-05: this ${calls[0].provider} route has no per-user cap. One account can repeat the call until the bill spikes.`,
        FIX['fca-05'],
      )];
    }
    requestHop(fca05, file);
    return [];
  },
);

export const fca06 = baseRule(
  'fca-06',
  'FCA-06 Memory-only limiter',
  'warning',
  'Limiter stored in a Map or globalThis with no Redis, Upstash, or database fallback.',
  (file) => {
    const code = serverCode(file);
    if (code === null) return [];
    const looksLikeLimiter = /rate[-_ ]?limit|slidingWindow|tokenBucket|checkKeyedRateLimit/i.test(code);
    const memory = /new\s+Map\s*\(|globalThis\b/.test(code);
    if (!looksLikeLimiter || !memory || hasSharedLimiter(code)) return [];
    const index = /new\s+Map\s*\(|globalThis\b/.exec(code)?.index ?? 0;
    return [finding(
      fca06,
      file,
      lineAt(code, index),
      'FCA-06: this limiter lives in process memory. A deploy or a second instance resets it, so a bot farm can outrun the cap.',
      FIX['fca-06'],
    )];
  },
);

export const fca07 = baseRule(
  'fca-07',
  'FCA-07 No dollar ceiling',
  'warning',
  'Paid call with no reservation or capped usage ledger before the provider request.',
  (file) => {
    const code = serverCode(file);
    if (code === null) return [];
    const calls = findProviderCalls(code);
    const exposed = calls.find((hit) => !hasSpendGuardBefore(code, hit.index));
    if (!exposed) return [];
    return [finding(
      fca07,
      file,
      lineAt(code, exposed.index),
      `FCA-07: nothing reserves or checks a dollar ceiling before the ${exposed.provider} call. There is no ledger to stop a runaway bill.`,
      FIX['fca-07'],
    )];
  },
);

export const fca08 = baseRule(
  'fca-08',
  'FCA-08 Unverified identity trusted',
  'warning',
  'Email used for admin, trial, or entitlement without a verified-status check.',
  (file) => {
    const code = serverCode(file);
    if (code === null) return [];
    if (!EMAIL_READ.test(code) || !EMAIL_TRUST.test(code) || hasVerifiedCheck(code)) return [];
    const index = /primaryEmailAddress|emailAddresses/.exec(code)?.index ?? 0;
    return [finding(
      fca08,
      file,
      lineAt(code, index),
      'FCA-08: an email is trusted for admin, trial, or entitlement without checking that it is verified. A bot farm can claim a privileged address and skip every limit.',
      FIX['fca-08'],
    )];
  },
);

export const fca09 = baseRule(
  'fca-09',
  'FCA-09 Alias and disposable gaps',
  'warning',
  'Allowlist or signup email compare that only lowercases, with no plus-tag, Gmail-dot, or disposable-domain handling.',
  (file) => {
    const code = serverCode(file);
    if (code === null) return [];
    if (!/email/i.test(code) || !/toLowerCase\s*\(/.test(code) || !EMAIL_TRUST.test(code)) return [];
    if (EMAIL_NORMALIZE.test(code)) return [];
    const index = /toLowerCase\s*\(/.exec(code)?.index ?? 0;
    return [finding(
      fca09,
      file,
      lineAt(code, index),
      'FCA-09: email matching only lowercases the address. Gmail dots, plus-tags, and disposable inboxes can each become another free account.',
      FIX['fca-09'],
    )];
  },
);

export const fca10 = baseRule(
  'fca-10',
  'FCA-10 Unbounded key minting',
  'info',
  'API-key create handler with no per-user count check.',
  (file) => {
    const code = serverCode(file);
    if (code === null || !KEY_MINT.test(code) || KEY_CAP.test(code)) return [];
    const keyPath = /api[-_]?key|keys\/route|mint/i.test(normalize(file.relativePath));
    if (!isRouteFile(file) && !keyPath) return [];
    const index = KEY_MINT.exec(code)?.index ?? 0;
    return [finding(
      fca10,
      file,
      lineAt(code, index),
      'FCA-10: this handler mints API keys with no per-user count. One account can create unlimited keys that share the same spend path.',
      FIX['fca-10'],
    )];
  },
);

export const fca11 = baseRule(
  'fca-11',
  'FCA-11 Signup without bot check',
  'warning',
  'Clerk, Supabase, or Firebase signup with no Turnstile, hCaptcha, reCAPTCHA, or bot-protection note.',
  (file) => {
    if (skip(file)) return [];
    const p = normalize(file.relativePath);
    if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|vue|svelte|html?)$/.test(p)) return [];
    const content = file.content || '';
    const signup = /<SignUp[\s/>]|supabase\.auth\.signUp\s*\(|supabase\.auth\.sign_up\s*\(|createUserWithEmailAndPassword\s*\(/.test(content);
    if (!signup) return [];
    if (/turnstile|hcaptcha|recaptcha|captcha|bot_protection|botProtection|bot protection/i.test(content)) return [];
    const index = /<SignUp|signUp\s*\(|sign_up\s*\(|createUserWithEmailAndPassword\s*\(/.exec(content)?.index ?? 0;
    return [finding(
      fca11,
      file,
      lineAt(content, index),
      'FCA-11: signup is on screen with no CAPTCHA or bot-protection note. A bot farm can make accounts and spend a provider wallet.',
      FIX['fca-11'],
    )];
  },
);

function creditCtx(file) {
  return file._freeCreditCtx?.freeCredit || null;
}

function requestHop(rule, file) {
  const bucket = creditCtx(file);
  if (!bucket) return;
  const specs = calledLocalImports(codeOf(file));
  if (specs.length === 0) return;
  bucket.hops.push({ rule, file: file.relativePath, specs });
}

function requestPublicList(file, paths) {
  const bucket = creditCtx(file);
  if (!bucket || paths.length === 0) return;
  bucket.publicLists.push({ paths });
}

/** @type {Rule[]} */
export const FREE_CREDIT_RULES = [
  fca01, fca02, fca03, fca04, fca05, fca06, fca07, fca08, fca09, fca10, fca11,
];

/**
 * Record provider modules, routes, and public-path lists while the file
 * stream is consumed. Safe to call for every file.
 *
 * @param {{ relativePath: string, content: string }} file
 * @param {{ freeCredit?: object }} ctx
 */
export function noteFreeCreditFacts(file, ctx) {
  if (!ctx.freeCredit) ctx.freeCredit = { modules: new Map(), routes: [], hops: [], publicLists: [] };
  file._freeCreditCtx = ctx;
  if (skip(file) || !isSource(file)) return;
  const code = codeOf(file);
  if (!isClientFile(file, file.content)) {
    const names = new Set(findProviderMentions(code));
    if (names.size > 0) {
      for (const id of moduleIds(file.relativePath)) ctx.freeCredit.modules.set(id, names);
    }
  }
  if (!isRouteFile(file)) return;
  ctx.freeCredit.routes.push({
    file: file.relativePath,
    line: 1,
    url: routeUrl(file.relativePath),
    specs: calledLocalImports(code),
    direct: findProviderCalls(code).map((hit) => hit.provider),
  });
}

function routeReaches(route, modules) {
  const providers = new Set(route.direct || []);
  for (const spec of route.specs || []) {
    for (const provider of providersForSpec(spec, route.file, modules)) providers.add(provider);
  }
  return [...providers];
}

/**
 * Resolve one-hop provisional findings now that every module has been seen.
 * Drops hops that do not land on a provider. Strips the internal `_hop` field
 * so reports never show it.
 *
 * @param {Finding[]} findings
 * @param {{ freeCredit?: { modules: Map<string, Set<string>>, routes: object[] } }} ctx
 */
export function finalizeFreeCreditFindings(findings, ctx) {
  const modules = ctx?.freeCredit?.modules || new Map();
  const routes = ctx?.freeCredit?.routes || [];
  const out = [];
  const seen = new Set();

  const push = (item) => {
    if (item._hop) return;
    const key = `${item.ruleId}|${item.file}|${item.line}|${item.message}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(item);
  };

  for (const item of findings) push(item);

  for (const hop of ctx?.freeCredit?.hops || []) {
    const providers = new Set();
    for (const spec of hop.specs || []) {
      for (const provider of providersForSpec(spec, hop.file, modules)) providers.add(provider);
    }
    if (providers.size === 0) continue;
    const provider = [...providers][0];
    const route = routeUrl(hop.file) || 'n/a';
    push({
      ruleId: hop.rule.id,
      ruleName: hop.rule.name,
      severity: hop.rule.severity,
      message: hopMessage(hop.rule.id, provider, route),
      file: hop.file,
      line: 1,
      evidence: `${hop.file} | ${provider} | ${route}`,
      fix: FIX[hop.rule.id],
    });
  }

  for (const list of ctx?.freeCredit?.publicLists || []) {
    for (const route of routes) {
      const providers = routeReaches(route, modules);
      if (providers.length === 0 || !pathListed(route.url, list.paths || [])) continue;
      push({
        ruleId: 'fca-03',
        ruleName: fca03.name,
        severity: 'critical',
        message: `FCA-03: ${route.file} spends on ${providers[0]} and middleware lists ${route.url} as public. A bot farm can call it without a session and drain the wallet.`,
        file: route.file,
        line: route.line || 1,
        evidence: `${route.url} | ${providers[0]}`,
        fix: FIX['fca-03'],
      });
    }
  }
  return out;
}

function hopMessage(ruleId, provider, route) {
  if (ruleId === 'fca-01') {
    return `FCA-01: ${provider} reached from this route (route: ${route}). Inventory of a paid API call. A bot that can open the route spends the ${provider} wallet.`;
  }
  if (ruleId === 'fca-03') {
    return `FCA-03: this route reaches ${provider} through a helper and has no auth or entitlement gate. A bot farm can call it and drain the wallet.`;
  }
  if (ruleId === 'fca-04') {
    return `FCA-04: this route reaches ${provider} and the only gate is signed-in. A bot farm can make free accounts and spend the wallet.`;
  }
  if (ruleId === 'fca-05') {
    return `FCA-05: this route reaches ${provider} and has no per-user cap. One account can repeat the call until the bill spikes.`;
  }
  return `${ruleId}: reaches ${provider} (route: ${route}).`;
}

/**
 * Signals for the widened ai-cost-exposure rule. LLM calls with no output cap,
 * and any paid call a free or unverified user can reach with no per-user cap,
 * shared limiter, or spend cap.
 *
 * @param {{ relativePath: string, content: string, lines?: string[] }} file
 */
export function aiCostHits(file) {
  if (skip(file) || !isSource(file) || isEnvFile(file)) return [];
  const p = normalize(file.relativePath);
  if (/(?:^|\/)(?:scripts|bin)\//.test(p)) return [];
  if (isClientFile(file, file.content)) return [];
  const code = codeOf(file);
  const free = reachableByFreeOrUnverified(code);
  const perUser = hasPerUserCap(code);
  const shared = hasSharedLimiter(code);
  const hits = [];
  for (const hit of findProviderCalls(code)) {
    const spend = hasSpendGuardBefore(code, hit.index);
    const uncapped = hit.llm && !outputCapped(code, hit.index);
    const unprotected = free && !perUser && !shared && !spend;
    if (!uncapped && !unprotected) continue;
    hits.push({
      ...hit,
      line: lineAt(code, hit.index),
      uncapped,
      unprotected,
      evidence: evidenceLine(file, lineAt(code, hit.index)),
    });
  }
  return hits;
}
