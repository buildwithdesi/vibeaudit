/**
 * Scale / Performance rule pack (v1.2).
 *
 * These are AST rules, so the tests lock the thing regex can't do: telling the N+1
 * antipattern apart from the correct batched / parallel / helper-called-once shapes.
 * The "MUST NOT flag" cases are the zero-false-positive guard.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { perfNPlusOne } from '../../src/rules/perf-n-plus-one.js';
import { perfNoAwaitParallel } from '../../src/rules/perf-no-await-parallel.js';
import { perfDbClientPerRequest } from '../../src/rules/perf-db-client-per-request.js';
import { serverlessFsWrite } from '../../src/rules/serverless-fs-write.js';

function mk(relativePath, content) {
  return { path: `/project/${relativePath}`, relativePath, content, lines: content.split('\n') };
}
const fires = (rule, path, src) => rule.check(mk(path, src)).length > 0;
const clean = (rule, path, src) => rule.check(mk(path, src)).length === 0;

// ─── perf-n-plus-one ──────────────────────────────────────────────────────────
describe('perf-n-plus-one', () => {
  it('flags a query inside a for/for-of loop (the $50k-bill fixture)', () => {
    assert.ok(fires(perfNPlusOne, 'api/orders.js',
      `for (const id of ids) {\n  const u = await prisma.user.findUnique({ where: { id } });\n  out.push(u);\n}`));
    assert.ok(fires(perfNPlusOne, 'api/orders.js',
      `for (let i = 0; i < rows.length; i++) {\n  const r = await db.query('SELECT * FROM t WHERE id=$1', [rows[i].id]);\n}`));
  });
  it('flags a query inside .map / .forEach', () => {
    assert.ok(fires(perfNPlusOne, 'api/x.js',
      'const profiles = users.map((u) => prisma.profile.findUnique({ where: { id: u.id } }));'));
    assert.ok(fires(perfNPlusOne, 'api/x.js',
      'orders.forEach(async (o) => { await db.shipment.create({ data: { orderId: o.id } }); });'));
  });
  it('does NOT flag a bare fetch in a loop (that is perf-no-await-parallel, not N+1)', () => {
    // A network fetch is not batchable with WHERE IN, so it is not an N+1 query.
    assert.ok(clean(perfNPlusOne, 'api/x.js', 'for (const id of ids) { await fetch(`/api/${id}`); }'));
  });
  it('does NOT flag a single query, or a query in a helper called once', () => {
    assert.ok(clean(perfNPlusOne, 'api/x.js', 'const u = await prisma.user.findUnique({ where: { id } });'));
    assert.ok(clean(perfNPlusOne, 'api/x.js',
      'function load(id) {\n  return prisma.user.findUnique({ where: { id } });\n}'));
  });
  it('does NOT flag iteration with no query (plain transform / Array.find)', () => {
    assert.ok(clean(perfNPlusOne, 'api/x.js', 'const names = users.map((u) => u.name.toUpperCase());'));
    assert.ok(clean(perfNPlusOne, 'api/x.js', 'const match = users.find((u) => u.id === wanted);'));
  });
  it('does NOT run on non-parseable / skipped files', () => {
    assert.ok(clean(perfNPlusOne, 'styles.css', 'for (const x of y) db.query(x)'));
    assert.ok(clean(perfNPlusOne, 'api/x.test.js', 'for (const id of ids) { await prisma.user.findUnique({ where: { id } }); }'));
  });
});

// ─── perf-no-await-parallel ───────────────────────────────────────────────────
describe('perf-no-await-parallel', () => {
  it('flags sequential await inside a loop', () => {
    assert.ok(fires(perfNoAwaitParallel, 'api/x.js',
      `for (const id of ids) {\n  const r = await fetch('/api/' + id);\n  results.push(r);\n}`));
    assert.ok(fires(perfNoAwaitParallel, 'api/x.js',
      `for (let i = 0; i < n; i++) {\n  await doThing(i);\n}`));
  });
  it('does NOT flag the parallel pattern (await inside a .map callback + Promise.all)', () => {
    assert.ok(clean(perfNoAwaitParallel, 'api/x.js',
      'const results = await Promise.all(ids.map(async (id) => await fetch(id)));'));
  });
  it('does NOT flag await Promise.all(...) inside a loop (chunked concurrency — the fix, not the bug)', () => {
    assert.ok(clean(perfNoAwaitParallel, 'api/x.js',
      'for (const chunk of chunks) {\n  await Promise.all(chunk.map((f) => f()));\n}'));
  });
  it('does NOT flag a single await, or `for await…of` async iteration', () => {
    assert.ok(clean(perfNoAwaitParallel, 'api/x.js', 'const r = await fetch(url);'));
    assert.ok(clean(perfNoAwaitParallel, 'api/x.js',
      `for await (const chunk of stream) {\n  await save(chunk);\n}`));
  });
});

// ─── Realistic route: both fire together, batched version stays clean ─────────
describe('perf pack: N+1 route vs batched route', () => {
  const nPlusOneRoute = mk('app/api/report/route.js',
    `export async function GET() {
  const ids = await getIds();
  const rows = [];
  for (const id of ids) {
    const user = await prisma.user.findUnique({ where: { id } });
    rows.push(user);
  }
  return Response.json(rows);
}`);
  const batchedRoute = mk('app/api/report/route.js',
    `export async function GET() {
  const ids = await getIds();
  const rows = await prisma.user.findMany({ where: { id: { in: ids } } });
  return Response.json(rows);
}`);

  it('flags the N+1 route on both rules', () => {
    assert.ok(perfNPlusOne.check(nPlusOneRoute).length > 0, 'N+1 query should fire');
    assert.ok(perfNoAwaitParallel.check(nPlusOneRoute).length > 0, 'sequential await should fire');
  });
  it('leaves the batched route clean', () => {
    assert.equal(perfNPlusOne.check(batchedRoute).length, 0);
    assert.equal(perfNoAwaitParallel.check(batchedRoute).length, 0);
  });
});

// ─── perf-db-client-per-request ───────────────────────────────────────────────
describe('perf-db-client-per-request', () => {
  it('flags a pooled client created inside a handler/function', () => {
    assert.ok(fires(perfDbClientPerRequest, 'app/api/users/route.ts',
      'export async function GET() {\n  const prisma = new PrismaClient();\n  return Response.json(await prisma.user.findMany());\n}'));
    assert.ok(fires(perfDbClientPerRequest, 'api/db.js',
      'function handler() {\n  const pool = new Pool();\n  return pool.query("select 1");\n}'));
  });
  it('does NOT flag a module-scope singleton', () => {
    assert.ok(clean(perfDbClientPerRequest, 'lib/db.ts',
      'const prisma = new PrismaClient();\nexport async function GET() { return prisma.user.findMany(); }'));
  });
  it('does NOT flag the globalThis singleton (module scope OR memoized getter)', () => {
    assert.ok(clean(perfDbClientPerRequest, 'lib/db.ts',
      "const prisma = globalThis.prisma ?? new PrismaClient();\nif (process.env.NODE_ENV !== 'production') globalThis.prisma = prisma;"));
    assert.ok(clean(perfDbClientPerRequest, 'lib/db.ts',
      'export function getPrisma() {\n  return globalThis.__prisma ??= new PrismaClient();\n}'));
  });
  it('does NOT flag non-pooled constructors', () => {
    assert.ok(clean(perfDbClientPerRequest, 'app/api/x/route.ts',
      'export function GET() {\n  const m = new Map();\n  const d = new Date();\n  return Response.json({});\n}'));
  });
});

// ─── serverless-fs-write ──────────────────────────────────────────────────────
describe('serverless-fs-write', () => {
  it('flags fs writes / embedded SQLite in server-runtime files', () => {
    assert.ok(fires(serverlessFsWrite, 'app/api/save/route.ts',
      "import fs from 'fs';\nexport async function POST(req) {\n  fs.writeFileSync('./data.json', await req.text());\n  return Response.json({ ok: true });\n}"));
    assert.ok(fires(serverlessFsWrite, 'app/api/log/route.ts', "const db = new Database('app.db');"));
  });
  it('does NOT flag writes to /tmp (the allowed ephemeral path)', () => {
    assert.ok(clean(serverlessFsWrite, 'app/api/x/route.ts',
      "import os from 'os';\nfs.writeFileSync(os.tmpdir() + '/scratch', data);"));
    assert.ok(clean(serverlessFsWrite, 'app/api/x/route.ts', "fs.writeFileSync('/tmp/x.json', data);"));
  });
  it('does NOT flag reads, or writes outside server-runtime files', () => {
    assert.ok(clean(serverlessFsWrite, 'app/api/x/route.ts', "const cfg = fs.readFileSync('./config.json', 'utf8');"));
    assert.ok(clean(serverlessFsWrite, 'scripts/build.js', "fs.writeFileSync('./dist/out.json', data);"));
  });
});
