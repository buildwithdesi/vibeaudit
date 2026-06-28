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

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { supabaseServiceKeyClient } from '../../src/rules/supabase-service-key-client.js';
import { missingAuth } from '../../src/rules/missing-auth.js';
import { nextjsServerActionExposure } from '../../src/rules/nextjs-server-action-exposure.js';
import { noInputValidation } from '../../src/rules/no-input-validation.js';
import { dangerouslySetInnerHtml } from '../../src/rules/dangerously-set-inner-html.js';
import { clientSideDbAccess } from '../../src/rules/client-side-db-access.js';
import { clientBundleSecrets } from '../../src/rules/client-bundle-secrets.js';
import { exposedEnvVars } from '../../src/rules/exposed-env-vars.js';
import { isSuppressed, pathDisabledFor } from '../../src/suppress.js';

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

  it('pathDisabledFor honors per-rule path patterns', () => {
    const config = { disableForPaths: { 'missing-auth': ['^public/'] } };
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
