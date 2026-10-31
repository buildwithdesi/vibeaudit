import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ALL_RULES } from '../../src/rules/index.js';
import { CWE_MAP } from '../../src/data/cwe-map.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeFile(relativePath, content) {
  return {
    path: `/project/${relativePath}`,
    relativePath,
    content,
    lines: content.split('\n'),
  };
}

function ruleById(id) {
  return ALL_RULES.find((r) => r.id === id);
}

// ── Framework-Specific Rules ─────────────────────────────────────────────────

describe('nextjs-server-action-exposure', () => {
  const rule = ruleById('nextjs-server-action-exposure');

  it('flags "use server" files without auth', () => {
    const file = makeFile('app/actions.ts', `
"use server";
export async function deleteUser(id) {
  await db.user.delete({ where: { id } });
}
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag server action without auth');
  });

  it('skips files with auth checks', () => {
    const file = makeFile('app/actions.ts', `
"use server";
export async function deleteUser(id) {
  const session = await getServerSession();
  if (!session) throw new Error("Unauthorized");
  await db.user.delete({ where: { id } });
}
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0, 'Should not flag server action with auth');
  });
});

describe('supabase-missing-rls', () => {
  const rule = ruleById('supabase-missing-rls');

  it('flags SQL CREATE TABLE without ENABLE RLS', () => {
    const file = makeFile('supabase/migrations/001.sql', `
CREATE TABLE public.users (
  id uuid PRIMARY KEY,
  email text NOT NULL
);
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag table without RLS');
  });

  it('passes when RLS is enabled', () => {
    const file = makeFile('supabase/migrations/001.sql', `
CREATE TABLE public.users (
  id uuid PRIMARY KEY,
  email text NOT NULL
);
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read own" ON users FOR SELECT USING (auth.uid() = id);
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0, 'Should not flag table with RLS');
  });
});

describe('supabase-service-key-client', () => {
  const rule = ruleById('supabase-service-key-client');

  it('flags service_role in client component', () => {
    const file = makeFile('src/components/Admin.tsx', `
"use client";
import { createClient } from '@supabase/supabase-js';
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE);
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag service_role in client');
  });

  it('skips server-side files', () => {
    const file = makeFile('api/admin.ts', `
import { createClient } from '@supabase/supabase-js';
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE);
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0, 'Should not flag service_role in API route');
  });
});

describe('vercel-env-leak', () => {
  const rule = ruleById('vercel-env-leak');

  it('flags NEXT_PUBLIC_ with secret names', () => {
    const file = makeFile('.env', 'NEXT_PUBLIC_SECRET_KEY=abc123');
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag NEXT_PUBLIC_ secret');
  });

  it('allows NEXT_PUBLIC_ with safe names', () => {
    const file = makeFile('.env', 'NEXT_PUBLIC_APP_NAME=MyApp');
    const findings = rule.check(file);
    assert.equal(findings.length, 0, 'Should not flag safe NEXT_PUBLIC_ var');
  });
});

// ── AI & API Security Rules ─────────────────────────────────────────────────

describe('ai-prompt-injection', () => {
  const rule = ruleById('ai-prompt-injection');

  it('flags user input interpolated into prompt', () => {
    const file = makeFile('api/chat.js', `
const response = await openai.chat.completions.create({
  messages: [{ role: "user", content: \`You are a helper. Question: \${req.body.message}\` }]
});
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag prompt injection');
  });

  it('skips files without AI API calls', () => {
    const file = makeFile('api/users.js', `
const users = await db.user.findMany();
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0);
  });
});

describe('stripe-webhook-no-verify', () => {
  const rule = ruleById('stripe-webhook-no-verify');

  it('flags webhook handler without constructEvent', () => {
    const file = makeFile('api/stripe-webhook.js', `
const event = JSON.parse(req.body);
if (event.type === 'checkout.session.completed') {
  await fulfillOrder(event.data.object);
}
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag unverified webhook');
  });

  it('passes when constructEvent is used', () => {
    const file = makeFile('api/stripe-webhook.js', `
const event = stripe.webhooks.constructEvent(rawBody, sig, secret);
if (event.type === 'checkout.session.completed') {
  await fulfillOrder(event.data.object);
}
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0);
  });
});

describe('payment-amount-client', () => {
  const rule = ruleById('payment-amount-client');

  it('flags amount from request body', () => {
    const file = makeFile('api/payment.js', `
const intent = await stripe.paymentIntents.create({
  amount: req.body.amount,
  currency: 'usd',
});
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag client-provided amount');
  });
});

// ── Data & Privacy Rules ─────────────────────────────────────────────────────

describe('pii-logging', () => {
  const rule = ruleById('pii-logging');

  it('flags console.log with email variable', () => {
    const file = makeFile('api/users.js', 'console.log("User email:", email);');
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag PII in log');
  });

  it('allows non-PII logging', () => {
    const file = makeFile('api/users.js', 'console.log("Request received", requestId);');
    const findings = rule.check(file);
    assert.equal(findings.length, 0);
  });
});

describe('graphql-no-auth', () => {
  const rule = ruleById('graphql-no-auth');

  it('flags resolvers without auth', () => {
    const file = makeFile('api/resolvers.js', `
const resolvers = {
  Query: {
    users: async () => await db.user.findMany(),
  },
};
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag resolvers without auth');
  });

  it('passes when context.user is checked', () => {
    const file = makeFile('api/resolvers.js', `
const resolvers = {
  Query: {
    users: async (_, __, context) => {
      if (!context.user) throw new Error("Not authenticated");
      return db.user.findMany();
    },
  },
};
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0);
  });
});

// ── Session & Auth Hardening Rules ───────────────────────────────────────────

describe('oauth-state-missing', () => {
  const rule = ruleById('oauth-state-missing');

  it('flags OAuth URL without state', () => {
    const file = makeFile('api/auth.js', `
const url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&response_type=code&redirect_uri=http://localhost:3000/callback";
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag OAuth without state');
  });

  it('passes when state param is present', () => {
    const file = makeFile('api/auth.js', `
const state = crypto.randomUUID();
const url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&response_type=code&state=" + state;
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0);
  });

  it('passes when using next-auth', () => {
    const file = makeFile('api/auth.js', `
import NextAuth from 'next-auth';
const url = "https://accounts.google.com/o/oauth2/v2/auth?response_type=code";
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0, 'NextAuth handles state automatically');
  });
});

describe('auth-token-no-expiry', () => {
  const rule = ruleById('auth-token-no-expiry');

  it('flags jwt.sign without expiresIn', () => {
    const file = makeFile('api/auth.js', `
const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag JWT without expiry');
  });

  it('passes when expiresIn is set', () => {
    const file = makeFile('api/auth.js', `
const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0);
  });
});

// ── Expanded Category Rules ──────────────────────────────────────────────────

describe('nosql-injection', () => {
  const rule = ruleById('nosql-injection');

  it('flags req.body passed to MongoDB find', () => {
    const file = makeFile('api/users.js', `
const users = await User.find(req.body);
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag NoSQL injection');
  });
});

describe('dangerously-set-inner-html', () => {
  const rule = ruleById('dangerously-set-inner-html');

  it('flags unsanitized dangerouslySetInnerHTML', () => {
    const file = makeFile('components/Post.tsx', `
return <div dangerouslySetInnerHTML={{ __html: post.content }} />;
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag unsanitized HTML');
  });

  it('passes when DOMPurify is used', () => {
    const file = makeFile('components/Post.tsx', `
return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.content) }} />;
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0);
  });
});

describe('eval-usage', () => {
  const rule = ruleById('eval-usage');

  it('flags eval with variable', () => {
    const file = makeFile('utils/calc.js', `
function calculate(expr) {
  return eval(expr);
}
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag eval with dynamic input');
  });

  it('skips eval with string literal', () => {
    const file = makeFile('config/init.js', `
eval("console.log('init')");
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0, 'Should not flag eval with static string');
  });
});

// ── Secrets Detection ────────────────────────────────────────────────────────

describe('high-entropy-strings', () => {
  const rule = ruleById('high-entropy-strings');

  it('flags high-entropy string in secret variable', () => {
    const file = makeFile('config.js', `
const apiKey = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag high-entropy secret');
  });

  it('skips non-secret variables', () => {
    const file = makeFile('config.js', `
const appName = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0, 'Should not flag non-secret variable');
  });
});

// ── CWE/CVSS Metadata ───────────────────────────────────────────────────────

describe('cwe-metadata', () => {
  it('all rules have CWE mappings (a11y rules carry a WCAG criterion instead)', () => {
    for (const rule of ALL_RULES) {
      // Accessibility (a11y-), scale/performance (perf-), and production-readiness
      // (serverless-fs-write) rules are not security weaknesses: a11y classifies with a
      // WCAG success criterion, the rest are quality/scale/ops checks with no CWE taxonomy.
      // license-contamination is a legal/compliance risk, not a vulnerability — CWE and
      // CVSS both model exploitability, and there is no honest score for "this is GPL".
      // php-stack is the same shape: a stack-policy rule (standing doctrine: no PHP),
      // and the presence of a language runtime has no honest CWE or CVSS either.
      if (rule.id.startsWith('a11y-') || rule.id.startsWith('perf-') || rule.id === 'serverless-fs-write' || rule.id === 'no-error-monitoring' || rule.id === 'license-contamination' || rule.id === 'php-stack') continue;
      assert.ok(CWE_MAP[rule.id], `Rule ${rule.id} missing CWE mapping`);
    }
  });

  it('all a11y rules attach a WCAG success criterion to their findings', () => {
    const badSnippets = {
      'a11y-img-no-alt': ['A.jsx', '<img src="/x.png" />'],
      'a11y-form-no-label': ['A.jsx', '<input type="text" placeholder="x" />'],
      'a11y-no-lang': ['a.html', '<html><body></body></html>'],
      'a11y-button-no-name': ['A.jsx', '<button></button>'],
      'a11y-positive-tabindex': ['A.jsx', '<div tabIndex={5}>x</div>'],
      'a11y-click-no-keyboard': ['A.jsx', '<div onClick={handle}>x</div>'],
    };
    for (const rule of ALL_RULES.filter((r) => r.id.startsWith('a11y-'))) {
      const [path, src] = badSnippets[rule.id];
      const findings = rule.check(makeFile(path, src));
      assert.ok(findings.length > 0, `${rule.id} should flag its bad snippet`);
      assert.ok(
        findings.every((f) => /^WCAG /.test(f.wcag || '')),
        `${rule.id} findings must carry a WCAG success criterion`,
      );
    }
  });

  it('all CWE entries have required fields', () => {
    for (const [ruleId, meta] of Object.entries(CWE_MAP)) {
      assert.ok(meta.cweId, `${ruleId} missing cweId`);
      assert.ok(typeof meta.cvssScore === 'number', `${ruleId} missing cvssScore`);
      assert.ok(meta.owaspCategory, `${ruleId} missing owaspCategory`);
      assert.ok(meta.cvssScore >= 0 && meta.cvssScore <= 10, `${ruleId} cvssScore out of range`);
    }
  });

  it('OWASP categories are valid', () => {
    const validCategories = /^A(?:0[1-9]|10):2021$/;
    for (const [ruleId, meta] of Object.entries(CWE_MAP)) {
      assert.ok(validCategories.test(meta.owaspCategory), `${ruleId} has invalid OWASP category: ${meta.owaspCategory}`);
    }
  });
});

// ── Rule Registry ────────────────────────────────────────────────────────────

describe('v2-rule-registry', () => {
  it('registers every rule exactly once, with no gaps', () => {
    // Deliberately not a hardcoded total: that number went stale on every new
    // rule and taught nothing when it failed. What matters is that the registry
    // has no duplicates and no blank ids.
    const ids = ALL_RULES.map((r) => r.id);
    assert.equal(new Set(ids).size, ids.length, 'duplicate rule id in ALL_RULES');
    assert.ok(ids.every((id) => typeof id === 'string' && id.length > 0), 'every rule needs an id');
    assert.ok(ALL_RULES.length >= 100, `registry looks truncated: ${ALL_RULES.length} rules`);
  });

  it('all new rules have fix prompts', async () => {
    const { FIX_PROMPTS } = await import('../../src/data/prompts.js');
    const newRuleIds = [
      'nextjs-server-action-exposure', 'nextjs-middleware-bypass', 'nextjs-api-route-no-method-check',
      'supabase-missing-rls', 'supabase-service-key-client', 'supabase-anon-key-abuse',
      'firebase-admin-client', 'vercel-env-leak', 'netlify-redirect-open', 'deployment-config-insecure',
      'ai-prompt-injection', 'ai-response-trusted', 'ai-cost-exposure',
      'stripe-webhook-no-verify', 'payment-amount-client',
      'pii-logging', 'missing-data-encryption', 'graphql-introspection', 'graphql-depth-limit', 'graphql-no-auth',
      'session-fixation', 'oauth-state-missing', 'password-reset-weak', 'mfa-bypass', 'auth-token-no-expiry',
      'race-condition', 'nosql-injection', 'xml-xxe', 'ldap-injection', 'header-injection',
      'subdomain-takeover', 'clickjacking', 'dangerously-set-inner-html', 'eval-usage', 'regex-dos', 'hardcoded-ip',
      'high-entropy-strings', 'git-history-secrets',
      'docker-root-user', 'exposed-database-port', 'client-side-db-access',
    ];
    for (const id of newRuleIds) {
      assert.ok(FIX_PROMPTS[id], `Missing fix prompt for ${id}`);
    }
  });

  it('no duplicate rule IDs', () => {
    const ids = ALL_RULES.map((r) => r.id);
    const unique = new Set(ids);
    assert.equal(ids.length, unique.size, `Duplicate rule IDs found: ${ids.filter((id, i) => ids.indexOf(id) !== i)}`);
  });
});

describe('client-side-db-access', () => {
  const rule = ruleById('client-side-db-access');

  it('flags direct Supabase queries in client component', () => {
    const file = makeFile('src/components/UserList.tsx', `
import { supabase } from '../lib/supabase';
export default function UserList() {
  const getUsers = async () => {
    const { data } = await supabase.from('users').select('*');
    return data;
  };
}
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag direct client-side query');
  });

  it('flags direct Drizzle queries in client component', () => {
    const file = makeFile('src/components/UserList.tsx', `
import { db } from '../db';
export default function UserList() {
  const getUsers = async () => {
    return db.select().from(users);
  };
}
`);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag direct Drizzle query');
  });

  it('skips server-only files', () => {
    const file = makeFile('src/app/api/users/route.ts', `
import { db } from '../db';
export async function GET() {
  return Response.json(await db.select().from(users));
}
`);
    const findings = rule.check(file);
    assert.equal(findings.length, 0);
  });
});

describe('hardened-rules-2026', () => {
  it('vercel-env-leak catches VITE_ and PUBLIC_ secrets', () => {
    const rule = ruleById('vercel-env-leak');
    const file1 = makeFile('.env', 'VITE_STRIPE_SECRET_KEY=sk_test_123');
    const findings1 = rule.check(file1);
    assert.ok(findings1.length > 0, 'Should flag VITE_ prefix secret');
    assert.ok(findings1[0].message.includes('VITE_STRIPE_SECRET_KEY'), 'Should name the variable in message');

    const file2 = makeFile('.env', 'PUBLIC_DATABASE_URL=postgres://...');
    const findings2 = rule.check(file2);
    assert.ok(findings2.length > 0, 'Should flag PUBLIC_ prefix secret');
  });

  it('payment-amount-client catches unit_amount from request body', () => {
    const rule = ruleById('payment-amount-client');
    const file = makeFile('api/checkout.js', `
      stripe.checkout.sessions.create({
        line_items: [{
          price_data: {
            unit_amount: req.body.amount,
            currency: 'usd'
          }
        }]
      });
    `);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag client-provided unit_amount');
  });

  it('missing-rate-limiting flags high-risk paths without rate limiting', () => {
    const rule = ruleById('missing-rate-limiting');
    // Path includes 'checkout' but file content has no direct OpenAI/Stripe calls, still flags it
    const file = makeFile('api/checkout/route.js', `
      export async function POST(req) {
        return Response.json({ ok: true });
      }
    `);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag high-risk path missing rate limit');
    assert.ok(findings[0].message.includes('High-risk API route'), 'Should have high-risk message');
  });

  it('missing-auth flags unauthenticated demo/debug endpoints with specific warnings', () => {
    const rule = ruleById('missing-auth');
    const file = makeFile('api/demo-login.js', `
      export async function GET(req) {
        return Response.json({ debug: true });
      }
    `);
    const findings = rule.check(file);
    assert.ok(findings.length > 0, 'Should flag missing auth in demo route');
    assert.ok(findings[0].message.includes('Unauthenticated test/demo/debug endpoint'), 'Should have custom demo route warning');
  });
});

// ── False-positive regressions (third-party MCP server scan) ─────────────────

describe('hardcoded-ip false positives', () => {
  const rule = () => ruleById('hardcoded-ip');

  it('does not flag X.509 OIDs in an OID-to-name map', () => {
    const file = makeFile('src/crypto/x509-names.ts', `
export const OID_NAMES = {
  "2.5.4.3": "commonName",
  "2.5.4.10": "organizationName",
  "2.5.29.14": "subjectKeyIdentifier",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
};
`);
    assert.equal(rule().check(file).length, 0);
  });

  it('does not flag a bare 2.5.4.x / 2.5.29.x OID comparison', () => {
    const file = makeFile('src/cert.js', 'if (attr.type === "2.5.4.3") return attr.value;\nconst ext = "2.5.29.17";');
    assert.equal(rule().check(file).length, 0);
  });

  it('does not flag dotted strings with an out-of-range octet', () => {
    const file = makeFile('src/version.js', 'const v = "1.2.840.10";');
    assert.equal(rule().check(file).length, 0);
  });

  it('still flags a real public IPv4 address', () => {
    const file = makeFile('src/config.js', 'const host = "203.0.113.50";');
    const findings = rule().check(file);
    assert.equal(findings.length, 1);
    assert.ok(findings[0].message.includes('203.0.113.50'));
  });

  it('still flags an IP mapped to a name when the file has no OID context', () => {
    const file = makeFile('src/hosts.js', 'const HOSTS = { "203.0.113.7": "primary" };');
    assert.equal(rule().check(file).length, 1);
  });
});

describe('missing-rate-limiting false positives', () => {
  const rule = () => ruleById('missing-rate-limiting');

  it('skips type-only modules under a high-risk server path', () => {
    const file = makeFile('src/server/register/types.ts', 'export interface ToolResult { text: string }\nexport type Handler = () => Promise<ToolResult>;');
    assert.equal(rule().check(file).length, 0);
  });

  it('skips helpers with no route or handler signal', () => {
    const file = makeFile('src/server/register/helpers.ts', 'export function textResult(text) { return { content: [{ type: "text", text }] }; }');
    assert.equal(rule().check(file).length, 0);
  });

  it('skips test files even when they contain handler code', () => {
    const file = makeFile('src/server/register/route.test.ts', 'export async function POST() { return Response.json({}); }');
    assert.equal(rule().check(file).length, 0);
  });

  it('skips MCP tool registration on a stdio server', () => {
    const file = makeFile('src/server/register/register-analysis-tools.ts', `
export function registerAnalysisTools(server) {
  server.registerTool("decompile", { description: "Decompile" }, async () => ({ content: [] }));
}
`);
    assert.equal(rule().check(file).length, 0);
  });

  it('still flags an Express route on a high-risk path', () => {
    const file = makeFile('server/routes/signup.js', 'router.post("/signup", async (req, res) => { res.json({ ok: true }); });');
    assert.equal(rule().check(file).length, 1);
  });

  it('still flags an MCP file that also exposes an HTTP route', () => {
    const file = makeFile('src/server/register/http.ts', `
server.registerTool("decompile", {}, async () => ({ content: [] }));
app.post("/mcp", async (req, res) => { res.json({}); });
`);
    assert.equal(rule().check(file).length, 1);
  });

  it('still flags a paid API call inside a route handler', () => {
    const file = makeFile('api/summarize.js', `
export default async function handler(req, res) {
  const out = await openai.chat.completions.create({ model: "x", messages: [] });
  res.json(out);
}
`);
    assert.equal(rule().check(file).length, 1);
  });
});

describe('insecure-connections false positives', () => {
  const rule = () => ruleById('insecure-connections');
  const httpFindings = (file) => rule().check(file).filter((f) => f.message.includes('HTTP URL'));

  it('does not flag the SVG xmlns inside a CSS data: URI', () => {
    const line = `.icon { background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg'><path d='M0 0'/></svg>"); }`;
    assert.equal(httpFindings(makeFile('src/ui/styles.ts', line)).length, 0);
  });

  it('does not flag W3C namespace constants', () => {
    const file = makeFile('src/ui/svg.js', 'const SVG_NS = "http://www.w3.org/2000/svg";\nconst XLINK = "http://www.w3.org/1999/xlink";');
    assert.equal(httpFindings(file).length, 0);
  });

  it('does not flag other URLs inside a data: URI or an xmlns attribute', () => {
    const file = makeFile('src/ui/icon.js', [
      `const icon = "data:image/svg+xml,<svg><a href='http://vendor-icons.com/x'/></svg>";`,
      `const doc = '<feed xmlns="http://purl.org/atom/ns#">';`,
    ].join('\n'));
    assert.equal(httpFindings(file).length, 0);
  });

  it('still flags a plain HTTP API URL', () => {
    const file = makeFile('src/config.js', 'const API = "http://api.partner-service.com/v1";');
    assert.equal(httpFindings(file).length, 1);
  });
});

describe('xml-xxe false positives', () => {
  const rule = () => ruleById('xml-xxe');

  it('does not flag Gson JsonParser.parseString or a bare SAX import', () => {
    const file = makeFile('bridge/android/ReaJadxBridge.java', [
      'import com.google.gson.JsonParser;',
      'import org.xml.sax.InputSource;',
      'JsonObject args = JsonParser.parseString(arguments.toString()).getAsJsonObject();',
    ].join('\n'));
    assert.equal(rule().check(file).length, 0);
  });

  it('does not flag a JS XML parser import on its own', () => {
    const file = makeFile('src/feed.js', "import { XMLParser } from 'fast-xml-parser';\nconst sax = require('sax');");
    assert.equal(rule().check(file).length, 0);
  });

  it('flags an unhardened DocumentBuilderFactory', () => {
    const file = makeFile('src/main/java/Xml.java', 'import javax.xml.parsers.DocumentBuilderFactory;\nDocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();');
    const findings = rule().check(file);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
  });

  it('does not flag a DocumentBuilderFactory with doctype declarations disabled', () => {
    const file = makeFile('src/main/java/Xml.java', [
      'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();',
      'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
    ].join('\n'));
    assert.equal(rule().check(file).length, 0);
  });

  it('flags an unhardened XMLInputFactory and still flags libxmljs noent: true', () => {
    assert.equal(rule().check(makeFile('src/Stax.java', 'XMLInputFactory f = XMLInputFactory.newInstance();')).length, 1);
    assert.equal(rule().check(makeFile('src/xml.js', 'libxmljs.parseXml(body, { noent: true });')).length, 1);
  });

  it('flags a factory whose doctype setting is named but turned off', () => {
    const file = makeFile('src/main/java/Xml.java', [
      'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();',
      'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);',
    ].join('\n'));
    assert.equal(rule().check(file).length, 1);
  });

  it('flags a factory when the hardening only appears in comments', () => {
    const file = makeFile('src/main/java/Xml.java', [
      '// TODO: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
      'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); // dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
      '/* dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); */',
    ].join('\n'));
    assert.equal(rule().check(file).length, 1);
  });

  it('flags the unhardened factory when another factory in the file is hardened', () => {
    const file = makeFile('src/main/java/Xml.java', [
      'DocumentBuilderFactory safe = DocumentBuilderFactory.newInstance();',
      'safe.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
      'SAXParserFactory risky = SAXParserFactory.newInstance();',
    ].join('\n'));
    const findings = rule().check(file);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].line, 3);
  });

  it('does not flag factories hardened through constants or StAX properties', () => {
    const viaConstant = makeFile('src/main/java/Xml.java', [
      'static final String NO_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";',
      'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();',
      'dbf.setFeature(NO_DOCTYPE, Boolean.TRUE);',
    ].join('\n'));
    const viaEntities = makeFile('src/main/java/Sax.java', [
      'SAXParserFactory spf = SAXParserFactory.newInstance();',
      'spf.setFeature("http://xml.org/sax/features/external-general-entities", false);',
      'spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);',
    ].join('\n'));
    const viaStax = makeFile('src/main/java/Stax.java', [
      'XMLInputFactory f = XMLInputFactory.newInstance();',
      'f.setProperty(XMLInputFactory.SUPPORT_DTD, false);',
    ].join('\n'));
    for (const file of [viaConstant, viaEntities, viaStax]) assert.equal(rule().check(file).length, 0, file.relativePath);
  });
});

// Fake keys are joined at runtime so no full key-shaped literal sits in the
// file. That keeps gitleaks strict without an allowlist entry.
const FAKE_ANTHROPIC_KEY = 'sk-ant-' + 'api03-Zx9Qw8Er7Ty6Ui5Op4As3Df2';
const FAKE_GOOGLE_KEY = 'AIza' + 'SyD8kq3Lm9Zt2Vw7Xp4Rb6Nc1Hs5Jf0Gy2';
const FAKE_STRIPE_TEST_KEY = 'sk_' + 'test_' + '51HxQz8Lm2Vw7Xp4Rb6Nc1Hs5Jf0Gy2Ab';

describe('client-bundle-secrets false positives', () => {
  const rule = () => ruleById('client-bundle-secrets');

  it('does not flag Node scripts under scripts/', () => {
    const file = makeFile('scripts/verify-anthropic-client.mjs', 'const env = { ANTHROPIC_API_KEY: "' + FAKE_ANTHROPIC_KEY + '" };');
    assert.equal(rule().check(file).length, 0);
  });

  it('does not flag files that import Node built-ins', () => {
    const file = makeFile('tools/smoke.mjs', 'import { spawnSync } from "node:child_process";\nconst apiKey = "' + FAKE_ANTHROPIC_KEY + '";');
    assert.equal(rule().check(file).length, 0);
  });

  it('does not flag obvious placeholder values, even in client code', () => {
    const file = makeFile('src/components/Demo.tsx', [
      'const a = { ANTHROPIC_API_KEY: "local-fixture-key" };',
      'const b = { COMMAND_CODE_API_KEY: "local-fixture-only" };',
      'api_key = "local-fixture-key"',
      'const c = { apiKey: "your-api-key-goes-here" };',
    ].join('\n'));
    assert.equal(rule().check(file).length, 0);
  });

  it('still flags a real-looking key in a client component', () => {
    const file = makeFile('src/components/Chat.tsx', 'const client = createClient({ apiKey: "' + FAKE_GOOGLE_KEY + '" });');
    assert.equal(rule().check(file).length, 1);
  });

  it('still flags a Stripe test secret key, which is a real credential', () => {
    const file = makeFile('src/components/Pay.tsx', 'const secret_key = "' + FAKE_STRIPE_TEST_KEY + '";');
    assert.equal(rule().check(file).length, 1);
  });

  it('still flags keys in public/scripts, which the browser downloads', () => {
    const file = makeFile('public/scripts/widget.js', 'const apiKey = "' + FAKE_GOOGLE_KEY + '";');
    assert.equal(rule().check(file).length, 1);
  });
});
