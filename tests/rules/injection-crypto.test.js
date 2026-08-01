import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sqlInjection } from '../../src/rules/sql-injection.js';
import { weakHashing } from '../../src/rules/weak-hashing.js';
import { insecureCipher } from '../../src/rules/insecure-cipher.js';

function makeFile(relativePath, content) {
  return { path: `/project/${relativePath}`, relativePath, content, lines: content.split('\n') };
}

// ── sql-injection ────────────────────────────────────────────────────────────

describe('sql-injection', () => {
  it('flags template-literal interpolation into a query', () => {
    const file = makeFile('api/users.js', 'const q = db.query(`SELECT * FROM users WHERE name = \'${name}\'`);');
    const findings = sqlInjection.check(file);
    assert.ok(findings.length > 0, 'Should flag interpolated SQL template');
    assert.equal(findings[0].severity, 'critical');
    assert.match(findings[0].message, /template-literal/i);
  });

  it('flags string concatenation into a query', () => {
    const file = makeFile('api/orders.js', 'const sql = "SELECT id FROM orders WHERE user = " + userId;');
    const findings = sqlInjection.check(file);
    assert.ok(findings.length > 0, 'Should flag concatenated SQL');
    assert.match(findings[0].message, /concatenation/i);
  });

  it('flags an interpolated DELETE statement', () => {
    const file = makeFile('api/admin.js', 'await conn.execute(`DELETE FROM sessions WHERE id = ${sessionId}`);');
    assert.ok(sqlInjection.check(file).length > 0);
  });

  it('passes parameterized pg queries ($1 placeholders)', () => {
    const file = makeFile('api/users.js', 'const q = db.query("SELECT * FROM users WHERE id = $1", [id]);');
    assert.equal(sqlInjection.check(file).length, 0);
  });

  it('passes parameterized mysql2 queries (? placeholders)', () => {
    const file = makeFile('api/users.js', 'conn.execute("SELECT * FROM users WHERE email = ?", [email]);');
    assert.equal(sqlInjection.check(file).length, 0);
  });

  it('does not flag static SQL with no dynamic input', () => {
    const file = makeFile('api/init.js', 'db.query("SELECT * FROM users WHERE active = true");');
    assert.equal(sqlInjection.check(file).length, 0);
  });

  it('does not flag a Prisma select object', () => {
    const file = makeFile('api/users.js', 'const user = await prisma.user.findMany({ select: { id: true, email: true } });');
    assert.equal(sqlInjection.check(file).length, 0);
  });

  it('does not flag prose that merely mentions a SQL word', () => {
    const file = makeFile('api/log.js', 'logger.info(`Failed to update user ${id}`);');
    assert.equal(sqlInjection.check(file).length, 0);
  });

  it('skips comments and test files', () => {
    assert.equal(sqlInjection.check(makeFile('api/x.js', '// db.query(`SELECT * FROM t WHERE id = ${id}`)')).length, 0);
    assert.equal(sqlInjection.check(makeFile('api/x.test.js', 'db.query(`SELECT * FROM t WHERE id = ${id}`)')).length, 0);
  });
});

// ── weak-hashing ─────────────────────────────────────────────────────────────

describe('weak-hashing', () => {
  it('flags createHash("md5")', () => {
    const file = makeFile('lib/hash.js', "const h = crypto.createHash('md5').update(data).digest('hex');");
    const findings = weakHashing.check(file);
    assert.ok(findings.length > 0, 'Should flag MD5');
    assert.equal(findings[0].severity, 'warning');
  });

  it('flags createHash("sha1")', () => {
    const file = makeFile('lib/hash.js', 'const h = crypto.createHash("sha1").update(x).digest("hex");');
    assert.ok(weakHashing.check(file).length > 0);
  });

  it('passes createHash("sha256")', () => {
    const file = makeFile('lib/hash.js', "const h = crypto.createHash('sha256').update(data).digest('hex');");
    assert.equal(weakHashing.check(file).length, 0);
  });

  it('does not flag HMAC-SHA256', () => {
    const file = makeFile('lib/sign.js', "const mac = crypto.createHmac('sha256', secret).update(body).digest('hex');");
    assert.equal(weakHashing.check(file).length, 0);
  });

  it('skips test files', () => {
    assert.equal(weakHashing.check(makeFile('lib/hash.test.js', "crypto.createHash('md5')")).length, 0);
  });
});

// ── insecure-cipher ──────────────────────────────────────────────────────────

describe('insecure-cipher', () => {
  it('flags deprecated createCipher (no IV)', () => {
    const file = makeFile('lib/crypto.js', "const c = crypto.createCipher('aes-256-cbc', password);");
    const findings = insecureCipher.check(file);
    assert.ok(findings.length > 0, 'Should flag legacy createCipher');
    assert.match(findings[0].message, /createCipher/);
  });

  it('flags a DES cipher via createCipheriv', () => {
    const file = makeFile('lib/crypto.js', "const c = crypto.createCipheriv('des-ede3', key, iv);");
    const findings = insecureCipher.check(file);
    assert.ok(findings.length > 0, 'Should flag DES');
    assert.match(findings[0].message, /Broken cipher/);
  });

  it('flags an ECB-mode cipher', () => {
    const file = makeFile('lib/crypto.js', "const c = crypto.createCipheriv('aes-256-ecb', key, null);");
    assert.ok(insecureCipher.check(file).length > 0);
  });

  it('passes createCipheriv with AES-GCM', () => {
    const file = makeFile('lib/crypto.js', "const c = crypto.createCipheriv('aes-256-gcm', key, iv);");
    assert.equal(insecureCipher.check(file).length, 0);
  });

  it('skips test files', () => {
    assert.equal(insecureCipher.check(makeFile('lib/crypto.test.js', "crypto.createCipher('des', pw)")).length, 0);
  });
});
