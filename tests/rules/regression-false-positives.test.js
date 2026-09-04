/**
 * Regression tests for the framework-awareness false-positive fixes.
 *
 * Two directions, both enforced:
 *  - MUST NOT flag: correct server-only / guarded / escaped / static code.
 *  - MUST STILL flag: genuinely exploitable patterns (signal preserved).
 *
 * These lock in the ~99%-false-positive fix without letting the scanner go
 * blind to real vulnerabilities.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import { supabaseServiceKeyClient } from '../../src/rules/supabase-service-key-client.js';
import { missingAuth } from '../../src/rules/missing-auth.js';
import { nextjsServerActionExposure } from '../../src/rules/nextjs-server-action-exposure.js';
import { noInputValidation } from '../../src/rules/no-input-validation.js';
import { dangerouslySetInnerHtml } from '../../src/rules/dangerously-set-inner-html.js';
import { clientSideDbAccess } from '../../src/rules/client-side-db-access.js';
import { clientBundleSecrets } from '../../src/rules/client-bundle-secrets.js';
import { exposedEnvVars } from '../../src/rules/exposed-env-vars.js';
import { exposedSecrets } from '../../src/rules/exposed-secrets.js';
import { hardcodedCredentials } from '../../src/rules/hardcoded-credentials.js';
import { firebaseAdminClient } from '../../src/rules/firebase-admin-client.js';
import { isSuppressed, pathDisabledFor } from '../../src/suppress.js';
import { audit } from '../../src/index.js';

/** Build a FileContext like the scanner passes to rules. */
function mk(relativePath, content, _config) {
  return { path: '/proj/' + relativePath, relativePath, content, lines: content.split('\n'), _config };
}

describe('FP fix: supabase-service-key-client', () => {
  it('does NOT flag service_role in a server-only file', () => {
    const file = mk('src/lib/supabase/server.ts',
      `import 'server-only';\nimport { createClient } from '@supabase/supabase-js';\nexport const admin = createClient(URL, process.env.SUPABASE_SERVICE_ROLE_KEY);`);
    assert.equal(supabaseServiceKeyClient.check(file).length, 0);
  });

  it('does NOT flag a server component (App Router default) that imports React and uses the service client', () => {
    const file = mk('src/app/admin/page.tsx',
      `import React from 'react';\nimport { createServiceRoleClient } from '@/lib/supabase/server';\nexport default function Page() {\n  const db = createServiceRoleClient();\n  return null;\n}`);
    assert.equal(supabaseServiceKeyClient.check(file).length, 0);
  });

  it('STILL flags service_role inside an explicit "use client" component', () => {
    const file = mk('src/app/admin/Widget.tsx',
      `'use client';\nimport { createClient } from '@supabase/supabase-js';\nexport function Widget() {\n  const admin = createClient(URL, SERVICE_ROLE_KEY);\n  return null;\n}`);
    assert.ok(supabaseServiceKeyClient.check(file).some((f) => f.ruleId === 'supabase-service-key-client'));
  });

  it('STILL flags a NEXT_PUBLIC_*SERVICE_ROLE env var anywhere (bundled to client)', () => {
    const file = mk('src/lib/config.ts',
      `export const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;`);
    assert.ok(supabaseServiceKeyClient.check(file).length >= 1);
  });
});

describe('FP fix: missing-auth', () => {
  it('does NOT flag a route guarded by a custom imported guard', () => {
    const file = mk('src/app/api/admin/disk/route.ts',
      `import { requireAuthedApiFromReq } from '@/lib/api-auth';\nexport async function GET(req) {\n  const auth = await requireAuthedApiFromReq(req, 'admin');\n  if (!auth.ok) return auth.response;\n  return Response.json({ ok: true });\n}`);
    assert.equal(missingAuth.check(file).length, 0);
  });

  it('does NOT flag a wrapped export (export const POST = withAuth(handler))', () => {
    const file = mk('src/app/api/x/route.ts',
      `import { withAuth } from '@/lib/auth';\nasync function handler(req) { return Response.json({}); }\nexport const POST = withAuth(handler);`);
    assert.equal(missingAuth.check(file).length, 0);
  });

  it('STILL flags an exported handler with no auth at all', () => {
    const file = mk('src/app/api/secret/route.ts',
      `export async function DELETE(req) {\n  const { id } = await req.json();\n  await db.delete(id);\n  return Response.json({ ok: true });\n}`);
    assert.ok(missingAuth.check(file).some((f) => f.ruleId === 'missing-auth'));
  });
});

describe('FP fix: nextjs-server-action-exposure', () => {
  it('does NOT flag non-exported helpers, and does NOT flag exported actions that check auth', () => {
    const file = mk('src/app/actions.ts',
      `'use server';\nimport { getServerSession } from 'next-auth';\nfunction internalHelper() { return 1; }\nexport async function createThing(data) {\n  const session = await getServerSession();\n  if (!session) throw new Error('Unauthorized');\n  return 1;\n}`);
    assert.equal(nextjsServerActionExposure.check(file).length, 0);
  });

  it('STILL flags an exported server action with no auth', () => {
    const file = mk('src/app/actions.ts',
      `'use server';\nexport async function deleteThing(id) {\n  await db.delete(id);\n  return { ok: true };\n}`);
    const f = nextjsServerActionExposure.check(file);
    assert.ok(f.some((x) => x.ruleId === 'nextjs-server-action-exposure'));
  });

  it('does NOT flag a file that merely mentions "use server" in a comment or string literal, not as a real directive', () => {
    // Mirrors src/context.js: a helper module that documents/detects the
    // directive by name, without actually being a "use server" file itself.
    const file = mk('src/lib/directive-helpers.js',
      `/**\n * Checks for the 'use server' directive.\n */\nexport function hasUseServer(content) {\n  return /^['"]use server['"]/.test(content);\n}\nexport function checkIt(x) {\n  return hasUseServer(x, 'use server');\n}`);
    assert.equal(nextjsServerActionExposure.check(file).length, 0);
  });
});

describe('FP fix: no-input-validation (innerHTML)', () => {
  it('does NOT flag static or escaped innerHTML', () => {
    for (const line of [
      `el.innerHTML = '';`,
      'container.innerHTML = `<button class="x">Download All</button>`;',
      `node.innerHTML = esc(userTitle);`,
      'box.innerHTML = `<b>${esc(name)}</b>`;',
      `btn.innerHTML = '&#10024; Generate';`, // HTML entity has a ; inside the string
      `if (!x.length) { c.innerHTML = '<div class="empty">none</div>'; return; }`, // static + trailing code
      'el.innerHTML = `<div class="empty-state">nothing here</div>`; return;',
    ]) {
      const file = mk('public/app.js', line);
      assert.equal(noInputValidation.check(file).length, 0, `should not flag: ${line}`);
    }
  });

  it('STILL flags dynamic, unescaped innerHTML', () => {
    for (const line of [
      `bar.innerHTML = userInput;`,
      'box.innerHTML = `<b>${userInput}</b>`;',
      `el.innerHTML = '<div>' + data + '</div>';`,
      `el.innerHTML = '<b>' + x; return;`, // concatenation, even with trailing code
    ]) {
      const file = mk('public/app.js', line);
      assert.ok(noInputValidation.check(file).length >= 1, `should flag: ${line}`);
    }
  });
});

describe('FP fix: dangerously-set-inner-html', () => {
  it('does NOT flag escaped or static __html', () => {
    const esc = mk('src/components/A.tsx', `export const A = () => <div dangerouslySetInnerHTML={{ __html: esc(html) }} />;`);
    const stat = mk('src/components/B.tsx', `export const B = () => <div dangerouslySetInnerHTML={{ __html: '<b>hi</b>' }} />;`);
    assert.equal(dangerouslySetInnerHtml.check(esc).length, 0);
    assert.equal(dangerouslySetInnerHtml.check(stat).length, 0);
  });

  it('honors customEscapers from config', () => {
    const file = mk('src/components/C.tsx',
      `export const C = () => <div dangerouslySetInnerHTML={{ __html: myClean(html) }} />;`,
      { customEscapers: ['myClean'] });
    assert.equal(dangerouslySetInnerHtml.check(file).length, 0);
  });

  it('STILL flags unsanitized dynamic __html', () => {
    const file = mk('src/components/D.tsx', `export const D = ({ userHtml }) => <div dangerouslySetInnerHTML={{ __html: userHtml }} />;`);
    assert.ok(dangerouslySetInnerHtml.check(file).length >= 1);
  });
});

describe('FP fix: client-side-db-access', () => {
  it('does NOT flag a "use server" file querying the db', () => {
    const file = mk('src/app/actions.ts', `'use server';\nexport async function load() { return db.select().from(users); }`);
    assert.equal(clientSideDbAccess.check(file).length, 0);
  });

  it('does NOT flag an App Router server component', () => {
    const file = mk('src/app/dashboard/page.tsx', `export default async function Page() {\n  const rows = await supabase.from('posts').select();\n  return null;\n}`);
    assert.equal(clientSideDbAccess.check(file).length, 0);
  });

  it('STILL flags a "use client" component querying the db directly', () => {
    const file = mk('src/components/List.tsx', `'use client';\nexport function List() {\n  const load = () => supabase.from('posts').select();\n  return null;\n}`);
    assert.ok(clientSideDbAccess.check(file).some((f) => f.ruleId === 'client-side-db-access'));
  });
});

describe('suppression', () => {
  const file = mk('a.ts', `const x = 1;\nconst y = 2;\nconst z = 3;`);

  it('suppresses same-line by rule id', () => {
    const f = mk('a.ts', `dangerous(); // vibe-audit-ignore some-rule`);
    assert.equal(isSuppressed(f, { line: 1, ruleId: 'some-rule' }), true);
    assert.equal(isSuppressed(f, { line: 1, ruleId: 'other-rule' }), false);
  });

  it('suppresses via -next-line on the line above', () => {
    const f = mk('a.ts', `// vibe-audit-ignore-next-line missing-auth\nexport function GET() {}`);
    assert.equal(isSuppressed(f, { line: 2, ruleId: 'missing-auth' }), true);
  });

  it('bare ignore suppresses any rule on the line', () => {
    const f = mk('a.ts', `bad(); // vibe-audit-ignore`);
    assert.equal(isSuppressed(f, { line: 1, ruleId: 'anything' }), true);
  });

  it('does not suppress unrelated lines', () => {
    assert.equal(isSuppressed(file, { line: 2, ruleId: 'r' }), false);
  });

  it('pathDisabledFor honors per-rule path substring patterns', () => {
    const config = { disableForPaths: { 'missing-auth': ['public/'] } };
    assert.equal(pathDisabledFor(config, 'missing-auth', 'public/api.js'), true);
    assert.equal(pathDisabledFor(config, 'missing-auth', 'src/api.js'), false);
    assert.equal(pathDisabledFor(config, 'other', 'public/api.js'), false);
  });
});

describe('FP fix: designed-public keys', () => {
  it('does NOT flag publishable / analytics keys', () => {
    assert.equal(clientBundleSecrets.check(mk('src/App.tsx', `const k = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY;`)).length, 0);
    assert.equal(clientBundleSecrets.check(mk('src/components/Map.tsx', `const t = process.env.NEXT_PUBLIC_MAPBOX_TOKEN;`)).length, 0);
    assert.equal(exposedEnvVars.check(mk('.env', `NEXT_PUBLIC_MAPBOX_TOKEN=pk.y\nNEXT_PUBLIC_POSTHOG_KEY=phc_x`)).length, 0);
  });

  it('STILL flags real secrets in client env', () => {
    assert.ok(clientBundleSecrets.check(mk('src/App.tsx', `const k = import.meta.env.VITE_GEMINI_API_KEY;`)).length >= 1);
    assert.ok(exposedEnvVars.check(mk('.env', `NEXT_PUBLIC_STRIPE_SECRET=sk_live_x\nREACT_APP_DATABASE_URL=postgres://u:p@h/db`)).length >= 1);
  });
});

describe('FP fix: public-by-convention routes (missing-auth)', () => {
  it('does NOT flag manifest / og / public / fixtures', () => {
    for (const p of [
      'src/app/api/manifest/route.ts',
      'src/app/api/og/route.tsx',
      'src/app/api/library/public/clips/route.ts',
      'tests/fixtures/api/demo.js',
    ]) {
      const file = mk(p, `export async function GET() { return Response.json({}); }`);
      assert.equal(missingAuth.check(file).length, 0, `should not flag ${p}`);
    }
  });

  it('STILL flags a normal unauthed mutation route', () => {
    const file = mk('src/app/api/account/route.ts', `export async function DELETE(req) { await db.deleteUser(); return Response.json({}); }`);
    assert.ok(missingAuth.check(file).some((f) => f.ruleId === 'missing-auth'));
  });
});

describe('FP fix: test fixtures are not real secrets (exposed-secrets, exposed-env-vars)', () => {
  const fakeGoogleKey = 'AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

  it('does NOT flag a fake secret living in tests/fixtures', () => {
    const file = mk('tests/fixtures/.env', `GOOGLE_API_KEY=${fakeGoogleKey}`);
    assert.equal(exposedSecrets.check(file).length, 0);

    const envFile = mk('tests/fixtures/.env', `VITE_STRIPE_SECRET_KEY=sk_test_123`);
    assert.equal(exposedEnvVars.check(envFile).length, 0);
  });

  it('does NOT flag a fake secret in a __tests__ or .test. file', () => {
    assert.equal(exposedSecrets.check(mk('src/rules/__tests__/fixtures.js', `const key = "${fakeGoogleKey}";`)).length, 0);
    assert.equal(exposedSecrets.check(mk('src/lib/auth.test.js', `const key = "${fakeGoogleKey}";`)).length, 0);
  });

  it('STILL flags the same secret shape outside tests/fixtures', () => {
    const file = mk('src/lib/firebase.js', `const key = "${fakeGoogleKey}";`);
    assert.ok(exposedSecrets.check(file).length > 0);

    const envFile = mk('.env', `VITE_STRIPE_SECRET_KEY=sk_test_123`);
    assert.ok(exposedEnvVars.check(envFile).length > 0);
  });
});

describe('FP fix: remote scans (audit()) respect the target repo\'s .vibe-audit.json ignore list', () => {
  const fakeSecret = 'AIzaSyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

  /** Build a fake remote file source like fetchRepoFiles() would yield. */
  async function* fakeRemoteFileSource(files) {
    for (const [relativePath, content] of files) {
      yield { path: `github://owner/repo/${relativePath}`, relativePath, content, lines: content.split('\n') };
    }
  }

  it('excludes findings from a directory the repo\'s own config ignores, but keeps real ones', async () => {
    const files = [
      ['legacy/old-config.js', `const key = "${fakeSecret}";`], // should be ignored
      ['src/lib/config.js', `const key = "${fakeSecret}";`], // should still be flagged
    ];

    const { findings } = await audit('owner/repo', {
      fileSource: fakeRemoteFileSource(files),
      format: 'json',
      skipSca: true,
      // Simulates the target repo's own .vibe-audit.json — passed directly so this
      // test never touches the network (fetchRemoteConfig is only exercised in prod).
      config: { ignore: ['legacy'], rules: [], exclude: [], format: 'json', strict: false, customEscapers: [], customAuthGuards: [], disableForPaths: {} },
    });

    const flaggedFiles = new Set(findings.filter((f) => f.ruleId === 'exposed-secrets').map((f) => f.file));
    assert.ok(!flaggedFiles.has('legacy/old-config.js'), 'should not flag ignored directory');
    assert.ok(flaggedFiles.has('src/lib/config.js'), 'should still flag non-ignored directory');
  });

  it('without an ignore config, flags both (control — proves the ignore list is what suppressed it above)', async () => {
    const files = [
      ['legacy/old-config.js', `const key = "${fakeSecret}";`],
      ['src/lib/config.js', `const key = "${fakeSecret}";`],
    ];

    const { findings } = await audit('owner/repo', {
      fileSource: fakeRemoteFileSource(files),
      format: 'json',
      skipSca: true,
      config: { ignore: [], rules: [], exclude: [], format: 'json', strict: false, customEscapers: [], customAuthGuards: [], disableForPaths: {} },
    });

    const flaggedFiles = new Set(findings.filter((f) => f.ruleId === 'exposed-secrets').map((f) => f.file));
    assert.ok(flaggedFiles.has('legacy/old-config.js'));
    assert.ok(flaggedFiles.has('src/lib/config.js'));
  });
});

describe('FP fix: no-input-validation — document.write context', () => {
  it('does NOT flag document.write with static markup', () => {
    assert.equal(noInputValidation.check(mk('app/a.js', `document.write('<p>hi</p>');`)).length, 0);
    assert.equal(
      noInputValidation.check(mk('app/b.js', 'document.write(`<div class="banner">Sale</div>`);')).length,
      0,
    );
  });

  it('does NOT flag an escaped value', () => {
    assert.equal(noInputValidation.check(mk('app/c.js', 'document.write(esc(name));')).length, 0);
  });

  it('MUST STILL flag document.write with a dynamic value', () => {
    const bare = noInputValidation.check(mk('app/d.js', 'document.write(location.hash);'));
    assert.ok(bare.length > 0, 'variable argument is the XSS vector');
    assert.equal(bare[0].severity, 'critical');

    const interpolated = noInputValidation.check(mk('app/e.js', 'document.write(`<b>${userInput}</b>`);'));
    assert.ok(interpolated.length > 0, 'interpolated markup is the XSS vector');
  });
});

describe('FP fix: no-input-validation — path and extension scope', () => {
  it('does NOT scan generated bundles or non-JS files', () => {
    const dangerous = 'document.write(location.hash);';
    assert.equal(noInputValidation.check(mk('dist/bundle.min.js', dangerous)).length, 0);
    assert.equal(noInputValidation.check(mk('scripts/build.py', dangerous)).length, 0);
    assert.equal(noInputValidation.check(mk('app/a.test.js', dangerous)).length, 0);
  });

  it('MUST STILL scan ordinary source files', () => {
    assert.ok(noInputValidation.check(mk('app/real.js', 'document.write(location.hash);')).length > 0);
  });
});

describe('FP fix: SQL is owned by sql-injection only (no double-count)', () => {
  it('no-input-validation no longer reports SQL', () => {
    const sqlish = 'db.query(`SELECT * FROM users WHERE id = ${id}`);';
    const findings = noInputValidation.check(mk('api/u.js', sqlish));
    assert.equal(findings.length, 0, 'sql-injection owns this; two rules reporting it doubled every count');
  });

  it('MUST STILL be caught by the dedicated rule', async () => {
    const { sqlInjection } = await import('../../src/rules/sql-injection.js');
    const sqlish = 'db.query(`SELECT * FROM users WHERE id = ${id}`);';
    assert.ok(sqlInjection.check(mk('api/u.js', sqlish)).length > 0, 'signal must survive the de-duplication');
  });
});

describe('FP fix: missing-auth resolves a guard declared in the same file', () => {
  const guardedRoute = `async function isCookieRouteAuthorized(req) {
  return Boolean(req.headers.get('x-admin'));
}
export async function GET(req) {
  if (!(await isCookieRouteAuthorized(req))) return new Response('no', { status: 401 });
  return Response.json({ ok: true });
}`;

  it('does NOT flag a route guarded by a local auth helper', () => {
    assert.equal(missingAuth.check(mk('app/api/cookies/route.ts', guardedRoute)).length, 0);
  });

  it('MUST STILL flag a route whose local helper is not a guard', () => {
    const content = `function formatRow(r) { return r; }
export async function DELETE(req) {
  const { id } = await req.json();
  await db.delete(id);
  return Response.json({ ok: true });
}`;
    assert.ok(missingAuth.check(mk('app/api/rows/route.ts', content)).length > 0);
  });

  it('MUST STILL flag when the local helper only looks data-shaped', () => {
    const content = `function parseBody(req) { return req.json(); }
export async function POST(req) {
  const body = await parseBody(req);
  return Response.json(body);
}`;
    assert.ok(
      missingAuth.check(mk('app/api/echo/route.ts', content)).length > 0,
      'a non-guard local helper must not rescue an unauthenticated route',
    );
  });
});

describe('FP fix: nextjs-middleware-bypass recognises modern helpers', () => {
  const withMatcher = `export const config = { matcher: ['/((?!_next/static).*)'] };`;

  it('does NOT flag clerkMiddleware() as having no auth logic', async () => {
    const { nextjsMiddlewareBypass } = await import('../../src/rules/nextjs-middleware-bypass.js');
    const content = `import { clerkMiddleware } from '@clerk/nextjs/server';\nexport default clerkMiddleware();\n${withMatcher}`;
    const noAuthFinding = nextjsMiddlewareBypass
      .check(mk('middleware.ts', content))
      .find((f) => /no authentication/i.test(f.message));
    assert.equal(noAuthFinding, undefined);
  });

  it('MUST STILL flag middleware that only sets headers', async () => {
    const { nextjsMiddlewareBypass } = await import('../../src/rules/nextjs-middleware-bypass.js');
    const content = `import { NextResponse } from 'next/server';
export function middleware() {
  const res = NextResponse.next();
  res.headers.set('x-app', '1');
  return res;
}
${withMatcher}`;
    const noAuthFinding = nextjsMiddlewareBypass
      .check(mk('middleware.ts', content))
      .find((f) => /no authentication/i.test(f.message));
    assert.ok(noAuthFinding, 'header-only middleware really is unprotected');
  });

  it('MUST STILL flag an import with no call', async () => {
    const { nextjsMiddlewareBypass } = await import('../../src/rules/nextjs-middleware-bypass.js');
    const content = `import { clerkMiddleware } from '@clerk/nextjs/server';
export function middleware() { return NextResponse.next(); }
${withMatcher}`;
    const noAuthFinding = nextjsMiddlewareBypass
      .check(mk('middleware.ts', content))
      .find((f) => /no authentication/i.test(f.message));
    assert.ok(noAuthFinding, 'importing Clerk without calling it protects nothing');
  });
});

describe('project-context: middleware-aware missing-auth scoring', () => {
  const route = `export async function GET(req) { return Response.json({ ok: true }); }`;

  async function scan(middlewareContent, matcher) {
    const files = [
      mk('middleware.ts', `${middlewareContent}\nexport const config = { matcher: ${matcher} };`),
      mk('app/api/things/route.ts', route),
    ];
    async function* source() { for (const f of files) yield f; }
    const { findings } = await audit('proj', {
      fileSource: source(),
      skipSca: true,
      rules: ['missing-auth'],
      config: { ignore: [], rules: [], exclude: [], format: 'json', strict: false },
    });
    return findings.filter((f) => f.ruleId === 'missing-auth');
  }

  const clerk = `import { clerkMiddleware } from '@clerk/nextjs/server';\nexport default clerkMiddleware();`;

  it('downgrades to warning when a guarded matcher covers the route', async () => {
    const found = await scan(clerk, `['/api/:path*']`);
    assert.equal(found.length, 1, 'finding stays visible — downgraded, never deleted');
    assert.equal(found[0].severity, 'warning');
    assert.match(found[0].message, /enforced by middleware/i);
  });

  it('MUST STILL be critical when the matcher does not cover the route', async () => {
    const found = await scan(clerk, `['/dashboard/:path*']`);
    assert.equal(found[0].severity, 'critical');
  });

  it('MUST STILL be critical when middleware does not authenticate', async () => {
    const headersOnly = `import { NextResponse } from 'next/server';\nexport function middleware() { return NextResponse.next(); }`;
    const found = await scan(headersOnly, `['/api/:path*']`);
    assert.equal(found[0].severity, 'critical');
  });
});

describe('project-context: helpers', () => {
  it('normalizeMatcher reduces Next matcher syntax to a prefix', async () => {
    const { normalizeMatcher } = await import('../../src/project-context.js');
    assert.equal(normalizeMatcher('/api/:path*'), '/api');
    assert.equal(normalizeMatcher('/api/(.*)'), '/api');
    assert.equal(normalizeMatcher('/((?!_next/static).*)'), '/');
    assert.equal(normalizeMatcher('relative/path'), null);
  });

  it('routeUrlFor maps route files to URLs, ignoring route groups', async () => {
    const { routeUrlFor } = await import('../../src/project-context.js');
    assert.equal(routeUrlFor('src/app/api/things/route.ts'), '/api/things');
    assert.equal(routeUrlFor('app/(marketing)/api/x/route.js'), '/api/x');
    assert.equal(routeUrlFor('pages/api/legacy.ts'), '/api/legacy');
    assert.equal(routeUrlFor('src/lib/util.ts'), null);
  });
});

describe('FP fix: disableForPaths tolerates regex-style anchors', () => {
  const cfg = (patterns) => ({ disableForPaths: { 'missing-auth': patterns } });

  it('an anchored pattern now matches (README taught this form)', () => {
    assert.equal(pathDisabledFor(cfg(['^public/']), 'missing-auth', 'public/app.js'), true);
  });

  it('a plain substring pattern still matches', () => {
    assert.equal(pathDisabledFor(cfg(['reports/']), 'missing-auth', 'reports/a.json'), true);
  });

  it('stripping the anchor MUST NOT create a spurious match', () => {
    assert.equal(pathDisabledFor(cfg(['^public/']), 'missing-auth', 'src/publicUtils.ts'), false);
  });

  it('does not leak across rules', () => {
    assert.equal(pathDisabledFor(cfg(['^public/']), 'sql-injection', 'public/app.js'), false);
  });
});

describe('FP fix: stripe-webhook-no-verify requires an actual handler', () => {
  let rule;
  before(async () => {
    ({ stripeWebhookNoVerify: rule } = await import('../../src/rules/stripe-webhook-no-verify.js'));
  });

  it('does NOT flag a data file that merely links to stripe.com', () => {
    // Real finding: bookmark-universe/data/demo-bookmarks.json was reported as
    // an unverified webhook handler because it contained bookmark URLs.
    const content = '[{"url":"https://stripe.com/rate-limiting","title":"Usage","folder":"Ship"}]';
    assert.equal(rule.check(mk('data/demo-bookmarks.json', content)).length, 0);
  });

  it('does NOT flag prose that lists Stripe among other services', () => {
    const content = `export const copy = "Integrations: Stripe, Twilio, SendGrid, Airtable, and more.";`;
    assert.equal(rule.check(mk('src/lib/monetization-content.ts', content)).length, 0);
  });

  it('does NOT flag a schema comment describing the webhook', () => {
    const content = `// One row per verified checkout.session.completed webhook event.\nexport const purchases = pgTable('purchases', {});`;
    assert.equal(rule.check(mk('src/db/schema.ts', content)).length, 0);
  });

  it('does NOT flag middleware that only routes the webhook path', () => {
    const content = `export const config = { matcher: ['/api/wh/(.*)'] };\nexport function middleware(req) { return NextResponse.next(); }`;
    assert.equal(rule.check(mk('src/middleware.ts', content)).length, 0);
  });

  it('does NOT flag a handler that DOES verify', () => {
    const content = `export async function POST(req) {
  const body = await req.text();
  const sig = req.headers.get('stripe-signature');
  const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  if (event.type === 'checkout.session.completed') await fulfill(event.data.object);
}`;
    assert.equal(rule.check(mk('app/api/wh/route.ts', content)).length, 0);
  });

  it('MUST STILL flag a real handler that parses the body unverified', () => {
    const content = `export async function POST(req) {
  const event = await req.json();
  if (event.type === 'checkout.session.completed') await fulfill(event.data.object);
  return Response.json({ received: true });
}`;
    const found = rule.check(mk('app/api/stripe/webhook/route.ts', content));
    assert.ok(found.length > 0, 'an unverified handler is the whole point of this rule');
    assert.equal(found[0].severity, 'critical');
  });

  it('MUST STILL flag an Express handler reading the signature but never verifying', () => {
    const content = `app.post('/webhook', (req, res) => {
  const sig = req.headers['stripe-signature'];
  const event = JSON.parse(req.body);
  res.json({ ok: true });
});`;
    assert.ok(rule.check(mk('server/routes.js', content)).length > 0);
  });
});

describe('FP fix: dangerously-set-inner-html resolves values file-wide', () => {
  it('does NOT flag the identifier appearing in a comment', () => {
    // Real findings: three repos had comments stating they AVOID this API.
    const a = `// We avoid dangerouslySetInnerHTML and rely on React escaping.\nexport const A = () => <div>hi</div>;`;
    assert.equal(dangerouslySetInnerHtml.check(mk('src/A.tsx', a)).length, 0);

    const b = `// eslint-disable-next-line react/no-danger -- dangerouslySetInnerHTML is intentional\nexport const B = () => <div />;`;
    assert.equal(dangerouslySetInnerHtml.check(mk('src/B.tsx', b)).length, 0);
  });

  it('does NOT flag a const holding a static template literal', () => {
    // Real finding: content-drop's inline theme script.
    const content = `const themeScript = \`(function(){try{var t=localStorage.getItem('t');}catch(e){}})();\`;
export default function Layout() {
  return <script dangerouslySetInnerHTML={{ __html: themeScript }} />;
}`;
    assert.equal(dangerouslySetInnerHtml.check(mk('src/app/layout.tsx', content)).length, 0);
  });

  it('does NOT flag a locally-defined escape-then-decorate helper', () => {
    // Real finding: highlight() declared ~580 lines above its use, far outside
    // the old byte window. It escapes first, then swaps sentinels for <mark>.
    const content = `function highlight(snippet: string): string {
  const esc = snippet.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return esc.replaceAll("\u27ea", '<mark>').replaceAll("\u27eb", "</mark>");
}
${'\n'.repeat(40)}
export function Results({ h }) {
  return <p dangerouslySetInnerHTML={{ __html: highlight(h.snippet) }} />;
}`;
    assert.equal(dangerouslySetInnerHtml.check(mk('src/library-browser.tsx', content)).length, 0);
  });

  it('MUST STILL flag a raw user value', () => {
    const content = `export const D = ({ userHtml }) => <div dangerouslySetInnerHTML={{ __html: userHtml }} />;`;
    const found = dangerouslySetInnerHtml.check(mk('src/D.tsx', content));
    assert.ok(found.length > 0, 'an unresolvable value is still a sink');
    assert.equal(found[0].severity, 'critical');
  });

  it('MUST STILL flag a variable reassigned unsanitized after sanitizing', () => {
    const content = `export function E({ raw }) {
  let clean = DOMPurify.sanitize(raw);
  clean = raw;
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}`;
    assert.ok(
      dangerouslySetInnerHtml.check(mk('src/E.tsx', content)).length > 0,
      'two bindings means the single-binding guard must refuse to clear it',
    );
  });

  it('MUST STILL flag a local helper that does NOT escape', () => {
    const content = `function wrap(s) { return '<b>' + s + '</b>'; }
${'\n'.repeat(40)}
export const F = ({ q }) => <p dangerouslySetInnerHTML={{ __html: wrap(q) }} />;`;
    assert.ok(
      dangerouslySetInnerHtml.check(mk('src/F.tsx', content)).length > 0,
      'a local helper is only safe if it actually escapes',
    );
  });

  it('MUST STILL flag an interpolated template literal', () => {
    const content = 'export const G = ({ q }) => <p dangerouslySetInnerHTML={{ __html: `<b>${q}</b>` }} />;';
    assert.ok(dangerouslySetInnerHtml.check(mk('src/G.tsx', content)).length > 0);
  });
});

describe('FP fix: dangerously-set-inner-html understands JSON-LD script escaping', () => {
  // Real pair. homiedex hardens its JSON-LD against a `</script>` breakout;
  // content-drop stringifies straight in. The rule must tell them apart.
  const hardened = `function escapeJsonForScriptTag(json: string): string {
  let out = json.replace(/<\/(script)/gi, "<\\/$1").replace(/<!--/g, "<\\!--");
  return out;
}
export function JsonLd({ data }) {
  const safe = escapeJsonForScriptTag(JSON.stringify(data));
  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safe }} />;
}`;

  const unhardened = `export function Faq({ c }) {
  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(faqSchema(c)) }} />;
}`;

  it('does NOT flag JSON-LD escaped for script context', () => {
    assert.equal(dangerouslySetInnerHtml.check(mk('src/json-ld.tsx', hardened)).length, 0);
  });

  it('MUST STILL flag a bare JSON.stringify into a script tag', () => {
    assert.ok(
      dangerouslySetInnerHtml.check(mk('src/faq.tsx', unhardened)).length > 0,
      'an unescaped value containing </script> closes the tag early',
    );
  });
});

describe('FP fix: hardcoded-credentials — "Basic" must be real base64 auth', () => {
  // The charset [A-Za-z0-9+/=] accepts ordinary English, so the 2026-08-13
  // portfolio scan read 'Basic electrical' out of a job-training skills array in
  // the public trade-match repo and called it a critical hardcoded credential.
  it('does NOT flag an English phrase that merely starts with "Basic"', () => {
    const file = mk('index.html', `earns: ['Industry certifications','Basic electrical'],`);
    assert.equal(hardcodedCredentials.check(file).length, 0);
  });

  it('does NOT flag other base64-shaped words after "Basic"', () => {
    const file = mk('src/copy.ts', `const tagline = 'Basic understanding';`);
    assert.equal(hardcodedCredentials.check(file).length, 0);
  });

  it('STILL flags base64 that decodes to user:pass', () => {
    // ZGVtbzpkZW1v === base64('demo:demo')
    const file = mk('src/api.ts', `const h = { Authorization: "Basic ZGVtbzpkZW1v" };`);
    const found = hardcodedCredentials.check(file);
    assert.equal(found.length, 1);
    assert.match(found[0].message, /basic auth/i);
    assert.equal(found[0].evidence, '***REDACTED***', 'the credential itself must never be echoed');
  });

  it('STILL flags padded base64 credentials', () => {
    // YWRtaW46c3VwZXJzZWNyZXQxMjM= === base64('admin:supersecret123')
    const file = mk('src/api.ts', `headers.set("Authorization", "Basic YWRtaW46c3VwZXJzZWNyZXQxMjM=")`);
    assert.equal(hardcodedCredentials.check(file).length, 1);
  });

  it('leaves the other credential patterns alone', () => {
    const bearer = mk('src/api.ts', `const t = "Bearer abcdefghijklmnopqrstuvwxyz123";`);
    assert.equal(hardcodedCredentials.check(bearer).length, 1);
    const pw = mk('src/api.ts', `const password = "hunter2abc";`);
    assert.equal(hardcodedCredentials.check(pw).length, 1);
  });
});

describe('FP fix: supabase-service-key-client — SQL naming the role is not the key', () => {
  // interactive-portfolio renders .sql files in a code viewer, so correct RLS
  // policy text lives inside a template literal in a 'use client' page. The
  // 2026-08-13 scan read `FOR ALL TO service_role` as a leaked key.
  const SQL_DISPLAY = `"use client";
const CODE_FILES = [{
  name: "rls_rules.sql",
  code: \`-- Enable RLS
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;

-- Allow service_role complete access
CREATE POLICY "Service role admin access" ON projects
FOR ALL TO service_role USING (true);\`
}];`;

  it('does NOT flag a policy/grant that names the service_role Postgres role', () => {
    assert.equal(supabaseServiceKeyClient.check(mk('src/app/page.tsx', SQL_DISPLAY)).length, 0);
  });

  it('does NOT flag a GRANT listing service_role among several roles', () => {
    const file = mk('src/app/docs.tsx',
      `"use client";\nconst s = \`GRANT SELECT ON projects TO authenticated, service_role;\`;`);
    assert.equal(supabaseServiceKeyClient.check(file).length, 0);
  });

  it('STILL flags a real service_role key read in a client component', () => {
    const file = mk('src/app/Widget.tsx',
      `'use client';\nconst admin = createClient(URL, process.env.SUPABASE_SERVICE_ROLE_KEY);`);
    assert.equal(supabaseServiceKeyClient.check(file).length, 1);
  });

  it('STILL flags the NEXT_PUBLIC service-role footgun', () => {
    const file = mk('src/app/W2.tsx',
      `'use client';\nconst k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;`);
    assert.equal(supabaseServiceKeyClient.check(file).length, 1);
  });
});

describe('FP fix: firebase-admin-client — src/ alone does not mean client', () => {
  // chibi-forge's src/lib/firebaseAdmin.js is a textbook server module, flagged
  // critical on 2026-08-13 purely for living under src/.
  const SERVER_MODULE = `import admin from 'firebase-admin';

export function getFirebaseAdminApp() {
  if (!admin.apps.length) {
    if (!process.env.FIREBASE_PRIVATE_KEY) return null;
    admin.initializeApp({
      credential: admin.credential.cert({
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY,
      }),
    });
  }
}`;

  it('does NOT flag a server module that initializes from non-public env secrets', () => {
    assert.equal(firebaseAdminClient.check(mk('src/lib/firebaseAdmin.js', SERVER_MODULE)).length, 0);
  });

  it('does NOT flag a file importing server-only', () => {
    const file = mk('src/lib/adminServer.ts',
      `import 'server-only';\nimport admin from 'firebase-admin';\nadmin.initializeApp({});`);
    assert.equal(firebaseAdminClient.check(file).length, 0);
  });

  it('STILL flags the Admin SDK inside a "use client" component', () => {
    const file = mk('src/components/Dash.tsx',
      `'use client';\nimport admin from 'firebase-admin';\nadmin.initializeApp({});`);
    assert.ok(firebaseAdminClient.check(file).length > 0);
  });

  it('STILL flags a Pages Router page, which really does bundle to the browser', () => {
    const file = mk('pages/dashboard.tsx',
      `import React from 'react';\nimport admin from 'firebase-admin';\nexport default function P(){ const [x] = useState(); admin.auth(); return null; }`);
    assert.ok(firebaseAdminClient.check(file).length > 0);
  });

  it('STILL flags NEXT_PUBLIC_ credentials — those genuinely ship to the browser', () => {
    const file = mk('src/lib/leak.ts',
      `import admin from 'firebase-admin';\nadmin.initializeApp({ credential: process.env.NEXT_PUBLIC_FIREBASE_PRIVATE_KEY });\nuseEffect(() => {});`);
    assert.ok(firebaseAdminClient.check(file).length > 0);
  });
});
