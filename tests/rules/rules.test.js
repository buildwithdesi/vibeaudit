import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { exposedSecrets } from '../../src/rules/exposed-secrets.js';
import { hardcodedCredentials } from '../../src/rules/hardcoded-credentials.js';
import { exposedEnvVars } from '../../src/rules/exposed-env-vars.js';
import { openDatabaseRules } from '../../src/rules/open-database-rules.js';
import { noInputValidation } from '../../src/rules/no-input-validation.js';
import { sqlInjection } from '../../src/rules/sql-injection.js';
import { insecureErrorHandling } from '../../src/rules/insecure-error-handling.js';
import { insecureConnections } from '../../src/rules/insecure-connections.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function loadFixture(relativePath) {
  const fullPath = resolve(__dirname, '..', 'fixtures', relativePath);
  const content = await readFile(fullPath, 'utf-8');
  return {
    path: fullPath,
    relativePath,
    content,
    lines: content.split('\n'),
  };
}

// ─── Exposed Secrets ──────────────────────────────────────────────────────────

describe('exposed-secrets', () => {
  it('detects Google API keys', async () => {
    const file = await loadFixture('vulnerable.js');
    const findings = exposedSecrets.check(file);
    const googleKey = findings.find((f) => f.message.includes('Google API key'));
    assert.ok(googleKey, 'Should detect Google API key');
    assert.equal(googleKey.severity, 'critical');
    // Verify secret is redacted
    assert.ok(!googleKey.evidence.includes('AIzaSyC1234567890'), 'Secret should be redacted');
  });

  it('skips .env.example files', () => {
    const file = {
      path: '/project/.env.example',
      relativePath: '.env.example',
      content: 'API_KEY=AIzaSyC1234567890abcdefghijklmnopqrstuv',
      lines: ['API_KEY=AIzaSyC1234567890abcdefghijklmnopqrstuv'],
    };
    const findings = exposedSecrets.check(file);
    assert.equal(findings.length, 0, 'Should skip .env.example');
  });

  it('skips commented lines', () => {
    const file = {
      path: '/project/config.js',
      relativePath: 'config.js',
      content: '// const key = "AIzaSyC1234567890abcdefghijklmnopqrstuv"',
      lines: ['// const key = "AIzaSyC1234567890abcdefghijklmnopqrstuv"'],
    };
    const findings = exposedSecrets.check(file);
    assert.equal(findings.length, 0, 'Should skip comments');
  });
});

// ─── Hardcoded Credentials ────────────────────────────────────────────────────

describe('hardcoded-credentials', () => {
  it('detects hardcoded passwords', async () => {
    const file = await loadFixture('vulnerable.js');
    const findings = hardcodedCredentials.check(file);
    const passwd = findings.find((f) => f.message.includes('password'));
    assert.ok(passwd, 'Should detect hardcoded password');
  });

  it('detects database connection strings', async () => {
    const file = await loadFixture('vulnerable.js');
    const findings = hardcodedCredentials.check(file);
    const dbConn = findings.find((f) => f.message.includes('connection string'));
    assert.ok(dbConn, 'Should detect database connection string');
  });

  it('skips test files', () => {
    const file = {
      path: '/project/tests/auth.test.js',
      relativePath: 'tests/auth.test.js',
      content: 'const password = "testpassword123"',
      lines: ['const password = "testpassword123"'],
    };
    const findings = hardcodedCredentials.check(file);
    assert.equal(findings.length, 0, 'Should skip test files');
  });

  it('skips placeholder values', () => {
    const file = {
      path: '/project/config.js',
      relativePath: 'config.js',
      content: 'const password = "changeme"',
      lines: ['const password = "changeme"'],
    };
    const findings = hardcodedCredentials.check(file);
    assert.equal(findings.length, 0, 'Should skip placeholder values');
  });
});

// ─── Exposed Env Vars ─────────────────────────────────────────────────────────

describe('exposed-env-vars', () => {
  it('detects client-prefixed secrets', async () => {
    const file = await loadFixture('.env');
    const findings = exposedEnvVars.check(file);
    assert.ok(findings.length >= 2, `Should find at least 2 exposed vars, found ${findings.length}`);
    const viteSecret = findings.find((f) => f.message.includes('VITE_SECRET_KEY'));
    assert.ok(viteSecret, 'Should catch VITE_SECRET_KEY');
  });

  it('ignores non-secret client vars', () => {
    const file = {
      path: '/project/.env',
      relativePath: '.env',
      content: 'VITE_API_URL=https://api.example.com\nVITE_APP_NAME=MyApp',
      lines: ['VITE_API_URL=https://api.example.com', 'VITE_APP_NAME=MyApp'],
    };
    const findings = exposedEnvVars.check(file);
    assert.equal(findings.length, 0, 'Should not flag non-secret vars');
  });
});

// ─── Open Database Rules ──────────────────────────────────────────────────────

describe('open-database-rules', () => {
  it('detects allow read, write: if true', async () => {
    const file = await loadFixture('firestore.rules');
    const findings = openDatabaseRules.check(file);
    assert.ok(findings.length > 0, 'Should detect open rules');
    assert.equal(findings[0].severity, 'critical');
  });

  it('skips non-rules files', () => {
    const file = {
      path: '/project/index.js',
      relativePath: 'index.js',
      content: 'console.log("hello")',
      lines: ['console.log("hello")'],
    };
    const findings = openDatabaseRules.check(file);
    assert.equal(findings.length, 0);
  });
});

// ─── No Input Validation ──────────────────────────────────────────────────────

describe('no-input-validation', () => {
  it('detects innerHTML assignment', async () => {
    const file = await loadFixture('vulnerable.js');
    const findings = noInputValidation.check(file);
    const xss = findings.find((f) => f.message.includes('innerHTML'));
    assert.ok(xss, 'Should detect innerHTML XSS');
  });

  it('detects eval usage', async () => {
    const file = await loadFixture('vulnerable.js');
    const findings = noInputValidation.check(file);
    const evalFinding = findings.find((f) => f.message.includes('eval'));
    assert.ok(evalFinding, 'Should detect eval');
  });

  it('leaves SQL injection to the dedicated rule (no double-counting)', async () => {
    const file = await loadFixture('vulnerable.js');

    // This rule used to carry its own SQL patterns, so the one bad query in
    // the fixture produced two criticals. Ownership now sits with
    // sql-injection; the signal must survive the move.
    assert.equal(
      noInputValidation.check(file).find((f) => f.message.includes('SQL')),
      undefined,
    );
    assert.ok(
      sqlInjection.check(file).length > 0,
      'sql-injection must still catch the fixture it now owns',
    );
  });
});

// ─── Insecure Error Handling ──────────────────────────────────────────────────

describe('insecure-error-handling', () => {
  it('detects empty catch blocks', () => {
    const file = {
      path: '/project/api/handler.js',
      relativePath: 'api/handler.js',
      content: 'try { doThing() } catch (e) {}',
      lines: ['try { doThing() } catch (e) {}'],
    };
    const findings = insecureErrorHandling.check(file);
    const empty = findings.find((f) => f.message.includes('Empty catch'));
    assert.ok(empty, 'Should detect empty catch block');
  });
});

// ─── Insecure Connections ─────────────────────────────────────────────────────

describe('insecure-connections', () => {
  it('detects HTTP URLs', () => {
    const file = {
      path: '/project/config.js',
      relativePath: 'config.js',
      content: 'const api = "http://production-api.example.com/data"',
      lines: ['const api = "http://production-api.example.com/data"'],
    };
    const findings = insecureConnections.check(file);
    assert.ok(findings.length > 0, 'Should detect HTTP URL');
  });

  it('allows localhost HTTP', () => {
    const file = {
      path: '/project/config.js',
      relativePath: 'config.js',
      content: 'const api = "http://localhost:3000/api"',
      lines: ['const api = "http://localhost:3000/api"'],
    };
    const findings = insecureConnections.check(file);
    assert.equal(findings.length, 0, 'Should allow localhost');
  });

  it('detects CORS wildcard', () => {
    const file = {
      path: '/project/server.js',
      relativePath: 'server.js',
      content: 'const corsOptions = { origin: "*" }',
      lines: ['const corsOptions = { origin: "*" }'],
    };
    const findings = insecureConnections.check(file);
    assert.ok(findings.length > 0, 'Should detect CORS wildcard');
  });

  it('detects disabled TLS', () => {
    const file = {
      path: '/project/db.js',
      relativePath: 'db.js',
      content: '{ rejectUnauthorized: false }',
      lines: ['{ rejectUnauthorized: false }'],
    };
    const findings = insecureConnections.check(file);
    const tls = findings.find((f) => f.message.includes('TLS'));
    assert.ok(tls, 'Should detect disabled TLS');
    assert.equal(tls.severity, 'critical');
  });
});
