import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

import { ALL_RULES } from '../../src/rules/index.js';
import { FREE_CREDIT_PACK } from '../../src/rules/packs.js';
import { audit } from '../../src/index.js';
import { getDefaultConfig } from '../../src/config.js';
import { report } from '../../src/reporter.js';
import {
  fca01, fca02, fca03, fca04, fca05, fca06, fca07, fca08, fca09, fca10, fca11,
} from '../../src/rules/free-credit.js';
import { aiCostExposure } from '../../src/rules/ai-cost-exposure.js';

const SECRET = 'sk-AAAAAAAAAAAAAAAAAAAAAAAA';
const cli = resolve('bin/vibe-audit.js');

function makeFile(relativePath, content) {
  return { path: `/project/${relativePath}`, relativePath, content, lines: content.split('\n') };
}

function runCli(args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    child.stdout.on('data', (chunk) => out.push(chunk));
    child.stderr.on('data', (chunk) => err.push(chunk));
    child.on('error', reject);
    child.on('close', (status) => resolvePromise({
      status,
      stdout: Buffer.concat(out).toString('utf8'),
      stderr: Buffer.concat(err).toString('utf8'),
    }));
  });
}

async function scanPack(dir, extra = []) {
  const result = await runCli([dir, '--pack', 'free-credit', '--format', 'json', '--skip-sca', '--skip-osv', ...extra]);
  let reportJson;
  try {
    reportJson = JSON.parse(result.stdout);
  } catch {
    assert.fail(`stdout was not JSON (exit ${result.status}): ${result.stderr}\n${result.stdout.slice(0, 400)}`);
  }
  return { ...result, report: reportJson };
}

function ruleIds(reportJson) {
  return reportJson.findings.map((finding) => finding.ruleId);
}

async function silentAudit(opts) {
  const orig = console.log;
  console.log = () => {};
  try {
    return await audit('fixture', opts);
  } finally {
    console.log = orig;
  }
}

async function* listed(entries) {
  for (const [relativePath, content] of entries) {
    yield { path: relativePath, relativePath, content, lines: content.split('\n') };
  }
}

describe('free-credit pack', () => {
  it('registers FCA-01 through FCA-11 on the default rule set', () => {
    const ids = new Set(ALL_RULES.map((rule) => rule.id));
    assert.equal(FREE_CREDIT_PACK.length, 11);
    for (const id of FREE_CREDIT_PACK) assert.ok(ids.has(id), id);
    assert.equal(new Set(FREE_CREDIT_PACK).size, 11);
  });
});

describe('fca-01 provider call map', () => {
  it('flags a server Gemini call and records the provider', () => {
    const findings = fca01.check(makeFile('src/lib/gemini.js', `
      import { GoogleGenAI } from '@google/genai';
      export function run() { return generateContent({ model: 'flash' }); }
    `));
    assert.ok(findings.some((finding) => finding.message.includes('gemini')));
    assert.ok(findings.every((finding) => finding.severity === 'info'));
  });

  it('ignores a provider name that appears only in a comment', () => {
    const findings = fca01.check(makeFile('src/lib/notes.js', `
      // generateContent and https://api.openai.com are examples, not calls.
      export const ready = true;
    `));
    assert.equal(findings.length, 0);
  });
});

describe('fca-02 AI key in client', () => {
  it('names the variable and not the value', () => {
    const findings = fca02.check(makeFile('src/components/Chat.js', `
      const key = process.env.NEXT_PUBLIC_GEMINI_API_KEY || '${SECRET}';
    `));
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.equal(findings[0].evidence, 'NEXT_PUBLIC_GEMINI_API_KEY');
    assert.equal(JSON.stringify(findings).includes(SECRET), false);
  });

  it('flags a provider call in a use-client file', () => {
    const findings = fca02.check(makeFile('src/ui/Ask.js', `
      'use client';
      export function Ask() { return generateContent({ contents: 'hi' }); }
    `));
    assert.ok(findings.some((finding) => finding.message.includes('gemini')));
  });

  it('does not flag a publishable admin email or a server-only key name', () => {
    const client = fca02.check(makeFile('src/components/Footer.js', `
      export const admin = process.env.NEXT_PUBLIC_ADMIN_EMAIL;
    `));
    const server = fca02.check(makeFile('src/lib/env.js', `
      export const key = process.env.GEMINI_API_KEY;
    `));
    assert.equal(client.length, 0);
    assert.equal(server.length, 0);
  });
});

describe('fca-03 unauthed spend path', () => {
  it('flags a route that calls a provider with no auth', () => {
    const findings = fca03.check(makeFile('src/app/api/chat/route.js', `
      export async function POST() {
        await fetch('https://api.openai.com/v1/chat/completions');
      }
    `));
    assert.ok(findings.some((finding) => finding.ruleId === 'fca-03' && !finding._hop));
  });

  it('does not flag an engine-gated route that calls the provider itself', () => {
    const findings = fca03.check(makeFile('src/app/api/jobs/route.js', `
      export async function POST(req) {
        const auth = await requireAuthedApiFromReq(req, 'engine');
        if (!auth.ok) return auth.response;
        return generateContent({ contents: 'x' });
      }
    `));
    assert.equal(findings.filter((finding) => !finding._hop).length, 0);
  });
});

describe('fca-04 sign-in-only spend', () => {
  it('flags a session gate on a provider call', () => {
    const findings = fca04.check(makeFile('src/app/api/ask/route.js', `
      export async function POST(req) {
        const auth = await requireAuthedApiFromReq(req, 'session');
        if (!auth.ok) return auth.response;
        return generateContent({ contents: 'x' });
      }
    `));
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'warning');
  });

  it('does not flag an engine gate', () => {
    const findings = fca04.check(makeFile('src/app/api/jobs/route.js', `
      export async function POST(req) {
        await requireAuthedApiFromReq(req, 'engine');
        return generateContent({ contents: 'x' });
      }
    `));
    assert.equal(findings.length, 0);
  });
});

describe('fca-05 no per-user cap', () => {
  it('flags a spend route with no per-user limit', () => {
    const findings = fca05.check(makeFile('src/app/api/chat/route.js', `
      export async function POST() {
        await fetch('https://api.deepgram.com/v1/listen');
      }
    `));
    assert.equal(findings.length, 1);
  });

  it('accepts checkKeyedRateLimit in the handler', () => {
    const findings = fca05.check(makeFile('src/app/api/chat/route.js', `
      export async function POST(req) {
        await checkKeyedRateLimit('listen', req.userId);
        await fetch('https://api.deepgram.com/v1/listen');
      }
    `));
    assert.equal(findings.length, 0);
  });
});

describe('fca-06 memory-only limiter', () => {
  it('flags a Map-backed limiter', () => {
    const findings = fca06.check(makeFile('src/lib/rate-limit.js', `
      const buckets = globalThis.__buckets ?? new Map();
      export function checkKeyedRateLimit() { return buckets; }
    `));
    assert.equal(findings.length, 1);
    assert.match(findings[0].message, /process memory/);
  });

  it('accepts an Upstash limiter', () => {
    const findings = fca06.check(makeFile('src/lib/rate-limit.js', `
      import { Ratelimit } from '@upstash/ratelimit';
      import { Redis } from '@upstash/redis';
      export const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, '1 d') });
    `));
    assert.equal(findings.length, 0);
  });
});

describe('fca-07 no dollar ceiling', () => {
  it('flags a provider call with no reservation', () => {
    const findings = fca07.check(makeFile('src/lib/gemini.js', `
      export function run() { return generateContent({ contents: 'x' }); }
    `));
    assert.equal(findings.length, 1);
  });

  it('accepts a reservation before the call', () => {
    const findings = fca07.check(makeFile('src/lib/gemini.js', `
      export async function run(userId) {
        await reserveCredits(userId, 1);
        return generateContent({ contents: 'x' });
      }
    `));
    assert.equal(findings.length, 0);
  });
});

describe('fca-08 unverified identity', () => {
  it('flags an admin compare that never checks verification', () => {
    const findings = fca08.check(makeFile('src/lib/auth.js', `
      export function isAdmin(user) {
        const email = user.primaryEmailAddress?.emailAddress?.toLowerCase();
        return ADMIN_EMAILS.includes(email);
      }
    `));
    assert.equal(findings.length, 1);
  });

  it('accepts a verified-status check', () => {
    const findings = fca08.check(makeFile('src/lib/auth.js', `
      export function isAdmin(user) {
        if (user.primaryEmailAddress?.verification?.status !== 'verified') return false;
        return ADMIN_EMAILS.includes(user.primaryEmailAddress.emailAddress);
      }
    `));
    assert.equal(findings.length, 0);
  });
});

describe('fca-09 alias and disposable gaps', () => {
  it('flags an allowlist compare that only lowercases', () => {
    const findings = fca09.check(makeFile('src/lib/auth.js', `
      export function allowed(user, allowlist) {
        return allowlist.includes(user.email.toLowerCase());
      }
    `));
    assert.equal(findings.length, 1);
  });

  it('accepts plus-tag, dot stripping, and a disposable-domain list', () => {
    const findings = fca09.check(makeFile('src/lib/auth.js', `
      const DISPOSABLE_DOMAINS = new Set(['mailinator.com']);
      function normalizeEmail(raw) {
        const local = raw.toLowerCase().split('@')[0].split('+')[0].replace(/\\./g, '');
        if (DISPOSABLE_DOMAINS.has('x')) return '';
        return local;
      }
      export function allowed(user, allowlist) {
        return allowlist.includes(normalizeEmail(user.email));
      }
    `));
    assert.equal(findings.length, 0);
  });
});

describe('fca-10 unbounded key minting', () => {
  it('flags a key route with no count', () => {
    const findings = fca10.check(makeFile('src/app/api/keys/route.js', `
      export async function POST(req) {
        const auth = await requireAuthedApiFromReq(req, 'engine');
        return createApiKey({ userId: auth.userId });
      }
    `));
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'info');
  });

  it('accepts a per-user count before minting', () => {
    const findings = fca10.check(makeFile('src/app/api/keys/route.js', `
      export async function POST(req) {
        const existing = await keys.count({ userId: req.userId });
        if (existing.length >= maxKeys) return;
        return createApiKey({ userId: req.userId });
      }
    `));
    assert.equal(findings.length, 0);
  });
});

describe('fca-11 signup without bot check', () => {
  it('flags a Clerk SignUp with no captcha', () => {
    const findings = fca11.check(makeFile('src/app/sign-up/page.js', `
      export function Page() { return <SignUp />; }
    `));
    assert.equal(findings.length, 1);
  });

  it('accepts a bot-protection note', () => {
    const findings = fca11.check(makeFile('src/app/sign-up/page.js', `
      // Clerk bot protection (Turnstile) is enabled for this SignUp.
      export function Page() { return <SignUp />; }
    `));
    assert.equal(findings.length, 0);
  });
});

describe('ai-cost-exposure widened providers', () => {
  it('still flags an OpenAI create with no output cap', () => {
    const findings = aiCostExposure.check(makeFile('src/app/api/chat/route.js', `
      export async function POST() {
        return openai.chat.completions.create({ model: 'gpt-4o', messages: [] });
      }
    `));
    assert.ok(findings.some((finding) => finding.message.includes('openai')));
  });

  it('flags an uncapped Gemini call outside an api/ directory', () => {
    const findings = aiCostExposure.check(makeFile('src/lib/gemini.js', `
      export function run() { return generateContent({ contents: 'x' }); }
    `));
    assert.ok(findings.some((finding) => finding.message.includes('gemini')));
  });

  it('flags a Firecrawl call a free user can reach with no cap, limiter, or spend ceiling', () => {
    const findings = aiCostExposure.check(makeFile('src/app/api/search/route.js', `
      export async function POST() {
        await fetch('https://api.firecrawl.dev/v1/search');
      }
    `));
    assert.ok(findings.some((finding) => finding.message.includes('firecrawl')));
    assert.match(findings[0].message, /free or unverified/);
  });

  it('does not flag a capped, entitled call with a per-user cap, shared limiter, and reservation', () => {
    const findings = aiCostExposure.check(makeFile('src/lib/gemini.js', `
      import { Ratelimit } from '@upstash/ratelimit';
      export async function POST(req) {
        const auth = await requireAuthedApiFromReq(req, 'engine');
        await checkKeyedRateLimit('job', auth.userId);
        await reserveCredits(auth.userId);
        return generateContent({ contents: 'x', maxOutputTokens: 200 });
      }
    `));
    assert.equal(findings.length, 0);
  });
});

describe('free-credit one hop', () => {
  it('does not keep a provisional finding for a helper that is not a provider', async () => {
    const { findings } = await silentAudit({
      format: 'json',
      skipSca: true,
      rules: ['fca-03'],
      config: getDefaultConfig(),
      fileSource: listed([
        ['src/lib/format.js', 'export function format() { return 1; }\n'],
        ['src/app/api/spend/route.js', `import { format } from '@/lib/format';\nexport async function POST() { return format(); }\n`],
      ]),
    });
    assert.equal(findings.filter((finding) => finding.ruleId === 'fca-03').length, 0);
  });

  it('flags an authed spend route that middleware lists as public', async () => {
    const { findings } = await silentAudit({
      format: 'json',
      skipSca: true,
      rules: ['fca-03'],
      config: getDefaultConfig(),
      fileSource: listed([
        ['src/middleware.js', `const isPublic = createRouteMatcher(['/api/spend']);\nexport default function middleware() {}\n`],
        ['src/app/api/spend/route.js', `
          export async function POST(req) {
            const auth = await requireAuthedApiFromReq(req, 'engine');
            await fetch('https://api.openai.com/v1/chat/completions');
            return auth;
          }
        `],
      ]),
    });
    assert.ok(findings.some((finding) => finding.ruleId === 'fca-03' && finding.file.endsWith('spend/route.js')));
    assert.ok(findings.every((finding) => !finding._hop));
  });
});

describe('free-credit acceptance fixtures', () => {
  it('content-drop shape flags FCA-06, 07, 08, 09, and 10, and not FCA-02 or FCA-03', async () => {
    const result = await scanPack('tests/fixtures/free-credit/content-drop');
    const found = new Set(ruleIds(result.report));
    for (const id of ['fca-06', 'fca-07', 'fca-08', 'fca-09', 'fca-10']) {
      assert.ok(found.has(id), `missing ${id}; saw ${[...found].join(', ')}`);
    }
    assert.equal(found.has('fca-02'), false);
    assert.equal(found.has('fca-03'), false);
    assert.equal(result.report.findings.some((finding) => finding.severity === 'critical'), false);
    const jobs = result.report.findings.filter((finding) => finding.file.endsWith('api/jobs/route.js'));
    assert.equal(jobs.some((finding) => finding.ruleId === 'fca-03' || finding.ruleId === 'fca-04'), false);
    assert.equal(result.report.summary.rulesRun, 11);
    assert.equal(result.status, 0);
  });

  it('opportunity-atlas shape has no critical findings', async () => {
    const result = await scanPack('tests/fixtures/free-credit/opportunity-atlas');
    assert.equal(result.report.findings.some((finding) => finding.severity === 'critical'), false);
    assert.equal(result.status, 0);
  });

  it('digitalalchemy-dev shape has no critical findings', async () => {
    const result = await scanPack('tests/fixtures/free-credit/digitalalchemy-dev');
    assert.equal(result.report.findings.some((finding) => finding.severity === 'critical'), false);
    assert.equal(result.status, 0);
  });

  it('flags an unauthed route that reaches Gemini through one import', async () => {
    const result = await scanPack('tests/fixtures/free-credit/unauthed-hop');
    assert.ok(ruleIds(result.report).includes('fca-03'));
    assert.equal(result.status, 1);
  });

  it('never prints a key-shaped string, and --warn does not fail the build', async () => {
    const blocked = await scanPack('tests/fixtures/free-credit/secret-leak');
    assert.equal(blocked.stdout.includes(SECRET), false);
    assert.equal(blocked.stderr.includes(SECRET), false);
    assert.equal(blocked.status, 1);
    const warned = await scanPack('tests/fixtures/free-credit/secret-leak', ['--warn']);
    assert.equal(warned.stdout.includes(SECRET), false);
    assert.equal(warned.status, 0);
  });

  it('accepts --format md', async () => {
    const result = await runCli([
      'tests/fixtures/free-credit/content-drop',
      '--pack', 'free-credit', '--format', 'md', '--skip-sca', '--skip-osv',
    ]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /FCA\\?-06/);
    assert.match(result.stdout, /process memory/);
    assert.doesNotMatch(result.stdout, /sk-[A-Za-z0-9]{20,}/);
  });

  it('rejects an unknown pack', async () => {
    const result = await runCli(['.', '--pack', 'no-such-pack', '--skip-sca']);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /Unknown pack/);
  });
});

describe('report redaction', () => {
  it('strips a key-shaped string from finding text', () => {
    const lines = [];
    const orig = console.log;
    console.log = (line) => lines.push(String(line));
    try {
      report([{
        ruleId: 'fca-03',
        ruleName: 'FCA-03 Unauthed spend path',
        severity: 'critical',
        message: `header Bearer ${SECRET}`,
        file: 'src/app/api/chat/route.js',
        line: 2,
        evidence: SECRET,
        fix: 'Remove it.',
      }], 'json', { filesScanned: 1, rulesRun: 1, durationMs: 1, targetDir: 'fixture' });
    } finally {
      console.log = orig;
    }
    const out = lines.join('\n');
    assert.equal(out.includes(SECRET), false);
    assert.match(out, /\[redacted\]/);
  });
});

describe('scanner sources are not spend paths', () => {
  it('does not flag the rule implementation itself', () => {
    const file = makeFile('src/rules/free-credit.js', `
      generateContent();
      primaryEmailAddress;
      ADMIN_EMAILS.includes(email.toLowerCase());
      new Map();
      checkKeyedRateLimit();
    `);
    for (const rule of [fca01, fca02, fca03, fca06, fca07, fca08, fca09]) {
      assert.equal(rule.check(file).length, 0, rule.id);
    }
  });
});
