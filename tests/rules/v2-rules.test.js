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
      // Accessibility (a11y-) and scale/performance (perf-) rules are not security
      // weaknesses: a11y classifies with a WCAG success criterion, and perf rules are
      // quality/scale checks with no CWE/CVSS/OWASP taxonomy. Skip both here.
      if (rule.id.startsWith('a11y-') || rule.id.startsWith('perf-')) continue;
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
  it('has 88 rules', () => {
    assert.equal(ALL_RULES.length, 88, `Expected 88 rules, got ${ALL_RULES.length}`);
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
