import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { parseSource, findFunctions, isParseable } from '../../src/ast.js';
import { idorVulnerability } from '../../src/rules/idor-vulnerability.js';
import { massAssignment } from '../../src/rules/mass-assignment.js';
import { missingAuth } from '../../src/rules/missing-auth.js';

function makeFile(relativePath, content) {
  return { path: `/project/${relativePath}`, relativePath, content, lines: content.split('\n') };
}

// ─── AST Parser ───────────────────────────────────────────────────────────────

describe('ast-parser', () => {
  it('parses valid JavaScript', () => {
    const ast = parseSource('const x = 1;');
    assert.ok(ast, 'Should parse valid JS');
    assert.equal(ast.type, 'Program');
  });

  it('parses with loose mode on syntax errors', () => {
    const ast = parseSource('const x = {; broken');
    assert.ok(ast, 'Should parse with loose mode');
  });

  it('handles TypeScript annotations', () => {
    const ast = parseSource('function greet(name: string): void { console.log(name); }');
    assert.ok(ast, 'Should handle TS');
  });

  it('finds functions', () => {
    const ast = parseSource(`
      function hello() { return 1; }
      const fn = () => { return 2; };
      async function getData() { return 3; }
    `);
    const funcs = findFunctions(ast);
    assert.ok(funcs.length >= 2, `Should find functions, got ${funcs.length}`);
  });

  it('identifies parseable files', () => {
    assert.ok(isParseable('src/app.js'));
    assert.ok(isParseable('pages/api/route.ts'));
    assert.ok(isParseable('components/Card.jsx'));
    assert.ok(isParseable('utils/helper.mjs'));
    assert.ok(!isParseable('styles.css'));
    assert.ok(!isParseable('data.json'));
    assert.ok(!isParseable('firestore.rules'));
  });
});

// ─── AST-Enhanced IDOR ────────────────────────────────────────────────────────

describe('ast-idor', () => {
  it('catches IDOR: function uses params.id without ownership check', () => {
    const file = makeFile('api/orders/[id].js', `
      export async function GET(req, { params }) {
        const order = await db.order.findUnique({ where: { id: params.id } });
        return Response.json(order);
      }
    `);
    const findings = idorVulnerability.check(file);
    assert.ok(findings.length > 0, 'Should catch IDOR');
  });

  it('passes when ownership check is in SAME function', () => {
    const file = makeFile('api/orders/[id].js', `
      export async function GET(req, { params }) {
        const session = await getServerSession();
        const order = await db.order.findUnique({ where: { id: params.id } });
        if (order.userId !== session.user.id) return new Response(null, { status: 403 });
        return Response.json(order);
      }
    `);
    const findings = idorVulnerability.check(file);
    assert.equal(findings.length, 0, 'Should pass — ownership checked in same function');
  });

  it('catches IDOR when ownership check is in DIFFERENT function', () => {
    const file = makeFile('api/orders/[id].js', `
      export async function GET(req, { params }) {
        const order = await db.order.findUnique({ where: { id: params.id } });
        return Response.json(order);
      }
      
      export async function DELETE(req, { params }) {
        const session = await getServerSession();
        const order = await db.order.findUnique({ where: { id: params.id } });
        if (order.userId !== session.user.id) return new Response(null, { status: 403 });
        await db.order.delete({ where: { id: params.id } });
      }
    `);
    const findings = idorVulnerability.check(file);
    // GET should be flagged, DELETE should not
    assert.ok(findings.length > 0, 'Should catch GET handler missing ownership');
    assert.ok(findings.some(f => f.message.includes('GET')), 'Should specifically flag GET');
  });
});

// ─── AST-Enhanced Mass Assignment ─────────────────────────────────────────────

describe('ast-mass-assignment', () => {
  it('catches raw req.body in DB create within function', () => {
    const file = makeFile('api/users.js', `
      export async function POST(req) {
        const body = await req.json();
        const user = await prisma.user.create({ data: body });
        return Response.json(user);
      }
    `);
    const findings = massAssignment.check(file);
    assert.ok(findings.length > 0, 'Should catch body passed to create');
  });

  it('passes when body is destructured in SAME function', () => {
    const file = makeFile('api/users.js', `
      export async function POST(req) {
        const { name, email } = await req.json();
        const user = await prisma.user.create({ data: { name, email } });
        return Response.json(user);
      }
    `);
    const findings = massAssignment.check(file);
    assert.equal(findings.length, 0, 'Should pass — body destructured first');
  });

  it('passes when schema.parse is used in same function', () => {
    const file = makeFile('api/users.js', `
      export async function POST(req) {
        const body = await req.json();
        const data = schema.parse(body);
        const user = await prisma.user.create({ data: body });
        return Response.json(user);
      }
    `);
    const findings = massAssignment.check(file);
    assert.equal(findings.length, 0, 'Should pass — schema validation before DB call');
  });

  it('catches when Zod is imported but NOT used in the vulnerable function', () => {
    const file = makeFile('api/users.js', `
      import { z } from 'zod';
      
      const safeSchema = z.object({ name: z.string() });
      
      export async function POST(req) {
        const body = await req.json();
        const user = await prisma.user.create({ data: body });
        return Response.json(user);
      }
      
      export async function PUT(req) {
        const body = await req.json();
        const data = safeSchema.parse(body);
        return Response.json(data);
      }
    `);
    const findings = massAssignment.check(file);
    // POST should be flagged (no validation in its scope), PUT should not
    assert.ok(findings.length > 0, 'Should catch POST even though Zod is imported');
  });
});

// ─── AST-Enhanced Missing Auth ────────────────────────────────────────────────

describe('ast-missing-auth', () => {
  it('catches individual handler without auth', () => {
    const file = makeFile('app/api/users/route.js', `
      export async function GET(req) {
        const users = await prisma.user.findMany();
        return Response.json(users);
      }
      
      export async function POST(req) {
        const session = await getServerSession();
        if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
        const user = await prisma.user.create({ data: await req.json() });
        return Response.json(user);
      }
    `);
    const findings = missingAuth.check(file);
    // GET should be flagged, POST should not
    assert.ok(findings.length > 0, 'Should flag GET handler');
    assert.ok(findings.some(f => f.message.includes('GET')), 'Should specifically flag GET');
    assert.ok(!findings.some(f => f.message.includes('POST')), 'Should NOT flag POST');
  });

  it('passes when all handlers have auth', () => {
    const file = makeFile('app/api/users/route.js', `
      export async function GET(req) {
        const session = await getServerSession();
        if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
        const users = await prisma.user.findMany();
        return Response.json(users);
      }
      
      export async function POST(req) {
        const session = await getServerSession();
        if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
        return Response.json({ ok: true });
      }
    `);
    const findings = missingAuth.check(file);
    assert.equal(findings.length, 0, 'All handlers have auth — should pass');
  });

  it('catches handler using req.user without calling auth function', () => {
    const file = makeFile('app/api/data/route.js', `
      export async function GET(req) {
        const data = await fetchData();
        return Response.json(data);
      }
    `);
    const findings = missingAuth.check(file);
    assert.ok(findings.length > 0, 'Should catch missing auth');
  });
});
