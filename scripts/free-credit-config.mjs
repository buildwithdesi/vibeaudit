#!/usr/bin/env node
/**
 * Read-only live-config checklist for the free-credit pack.
 *
 * GET requests only. It never updates Clerk or Supabase, never follows
 * redirects, and never prints a secret value. Missing tokens are a gap in the
 * checklist, not a failure.
 *
 *   CLERK_FRONTEND_API     Comma-separated public Frontend API origins.
 *   CLERK_APP_NAMES        Optional names, same order as the origins.
 *   CLERK_SECRET_KEY       Optional. Used only for GET /v1/instance.
 *   SUPABASE_ACCESS_TOKEN  Optional management-API token (auth:read).
 *   SUPABASE_PROJECT_REFS  Comma-separated project refs.
 *
 *   node scripts/free-credit-config.mjs --out free-credit-config.md
 */

import { writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { assertNoSecretValues } from '../src/redact-secrets.js';

const MANUAL = [
  'Gemini: spend cap and alert set in Google Cloud',
  'Deepgram: spend cap and alert set',
  'OpenRouter: per-key credit limit set',
  'DeepSeek: spend cap and alert set',
  'Firecrawl: spend cap and alert set',
  'ScrapeCreators: low-balance alert set',
  'Sign-up spike alert exists (PostHog or Clerk webhook, more than 50 new users per hour)',
];

export function createReadOnlyFetch(fetchImpl, allowedHosts = new Set()) {
  return async function readOnlyFetch(url, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    if (method !== 'GET') {
      throw new Error(`free-credit-config only reads; refused ${method}`);
    }
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
      throw new Error('free-credit-config only reads https URLs without credentials');
    }
    const known = parsed.host === 'api.clerk.com' || parsed.host === 'api.supabase.com' || allowedHosts.has(parsed.host);
    if (!known) throw new Error('free-credit-config refused an unexpected host');
    return fetchImpl(parsed.toString(), {
      method: 'GET',
      headers: options.headers || {},
      redirect: 'manual',
    });
  };
}

function httpsOrigin(raw) {
  const parsed = new URL(String(raw).trim());
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) return null;
  return parsed.origin;
}

function flag(value) {
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (value && typeof value === 'object' && typeof value.enabled === 'boolean') {
    return value.enabled ? 'yes' : 'no';
  }
  return 'not returned';
}

export function clerkFieldsFromEnvironment(body) {
  const settings = body?.user_settings || body?.display_config || {};
  const signUp = settings.sign_up || {};
  const restrictions = settings.restrictions || body?.restrictions || {};
  const email = settings.attributes?.email_address || {};
  return {
    sign_up_mode: typeof signUp.mode === 'string' ? signUp.mode : 'not returned',
    'bot_protection.captcha_enabled': flag(signUp.captcha_enabled),
    block_disposable_email_domains: flag(restrictions.block_disposable_email_domains),
    block_email_subaddresses: flag(restrictions.block_email_subaddresses),
    verify_at_sign_up: flag(email.verify_at_sign_up),
  };
}

export function clerkFieldsFromInstance(body) {
  const environment = typeof body?.environment_type === 'string' ? body.environment_type : 'not returned';
  return { environment_type: environment };
}

export function supabaseFields(body) {
  const signups = body?.disable_signup === true ? 'disabled' : body?.disable_signup === false ? 'enabled' : 'not returned';
  const captcha = body?.security_captcha_enabled === true ? 'yes' : body?.security_captcha_enabled === false ? 'no' : 'not returned';
  let emailConfirm = 'not returned';
  if (body?.mailer_autoconfirm === false) emailConfirm = 'yes';
  else if (body?.mailer_autoconfirm === true) emailConfirm = 'no (mailer autoconfirm is on)';
  return {
    signups,
    captcha_enabled: captcha,
    email_confirm_required: emailConfirm,
  };
}

function section(title, rows) {
  const lines = [`### ${title}`, '', '| Check | Value |', '| --- | --- |'];
  for (const [key, value] of Object.entries(rows)) lines.push(`| ${key} | ${value} |`);
  lines.push('');
  return lines.join('\n');
}

export function renderChecklist({ clerk = [], instance = null, supabase = [], notes = [] } = {}) {
  const lines = [
    '# Free-credit live-config checklist',
    '',
    'Read-only. This script sends GET requests only. It does not change settings and it does not print secret values.',
    '',
    '## Clerk',
    '',
  ];
  if (instance) lines.push(section('Instance (GET /v1/instance)', instance));
  if (clerk.length === 0) {
    lines.push('Not checked (no CLERK_FRONTEND_API). Set it to each production Frontend API origin. Signup fields are not on GET /v1/instance.');
    lines.push('');
  }
  for (const app of clerk) lines.push(section(app.name, app.fields));

  lines.push('## Supabase Auth', '');
  if (supabase.length === 0) {
    lines.push('Not checked (no read token or project ref). Set SUPABASE_ACCESS_TOKEN and SUPABASE_PROJECT_REFS.');
    lines.push('');
  }
  for (const project of supabase) lines.push(section(project.name, project.fields));

  lines.push('## Manual (tick once a month)', '');
  lines.push('These consoles are not queried. Answer Yes or No.', '');
  for (const item of MANUAL) lines.push(`- [ ] ${item} — Yes/No`);
  lines.push('');
  if (notes.length > 0) {
    lines.push('## Read errors', '');
    for (const note of notes) lines.push(`- ${note}`);
    lines.push('');
  }
  return lines.join('\n');
}

function secretValues(env) {
  return [env.CLERK_SECRET_KEY, env.SUPABASE_ACCESS_TOKEN].filter((value) => typeof value === 'string' && value.length >= 8);
}

async function readJson(fetchImpl, url, headers) {
  const response = await fetchImpl(url, { method: 'GET', headers });
  if (response.status >= 300 && response.status < 400) return { error: `redirect refused (${response.status})` };
  if (!response.ok) return { error: `HTTP ${response.status}` };
  try {
    return { json: JSON.parse(await response.text()) };
  } catch {
    return { error: 'response was not JSON' };
  }
}

export async function buildChecklist({ env = {}, fetchImpl = fetch } = {}) {
  const notes = [];
  const hosts = new Set();
  const apps = [];
  const origins = String(env.CLERK_FRONTEND_API || '').split(',').map((item) => item.trim()).filter(Boolean);
  const names = String(env.CLERK_APP_NAMES || '').split(',').map((item) => item.trim());
  for (const [index, raw] of origins.entries()) {
    const origin = httpsOrigin(raw);
    if (!origin) {
      notes.push('Skipped a Clerk frontend API that was not an https origin without credentials.');
      continue;
    }
    hosts.add(new URL(origin).host);
    apps.push({ name: names[index] || `Clerk app ${index + 1}`, origin });
  }

  const readOnly = createReadOnlyFetch(fetchImpl, hosts);
  let instance = null;
  if (env.CLERK_SECRET_KEY) {
    const result = await readJson(readOnly, 'https://api.clerk.com/v1/instance', {
      Authorization: `Bearer ${env.CLERK_SECRET_KEY}`,
    });
    if (result.json) instance = clerkFieldsFromInstance(result.json);
    else notes.push(`Clerk instance: ${result.error}`);
  }

  const unchecked = {
    sign_up_mode: 'not checked',
    'bot_protection.captcha_enabled': 'not checked',
    block_disposable_email_domains: 'not checked',
    block_email_subaddresses: 'not checked',
    verify_at_sign_up: 'not checked',
  };
  const clerkRows = await Promise.all(apps.map(async (app) => {
    const result = await readJson(readOnly, `${app.origin}/v1/environment`, {});
    if (result.json) return { name: app.name, fields: clerkFieldsFromEnvironment(result.json), note: '' };
    return { name: app.name, fields: unchecked, note: `${app.name}: ${result.error}` };
  }));
  const clerk = [];
  for (const row of clerkRows) {
    if (row.note) notes.push(row.note);
    clerk.push({ name: row.name, fields: row.fields });
  }

  const projects = [];
  const refs = String(env.SUPABASE_PROJECT_REFS || env.SUPABASE_PROJECT_REF || '').split(',').map((item) => item.trim()).filter(Boolean);
  const validRefs = [];
  if (env.SUPABASE_ACCESS_TOKEN) {
    for (const ref of refs) {
      if (/^[a-z0-9]{10,40}$/i.test(ref)) validRefs.push(ref);
      else notes.push('Skipped a Supabase project ref that was not a short id.');
    }
  }
  const projectRows = await Promise.all(validRefs.map(async (ref) => {
    const result = await readJson(readOnly, `https://api.supabase.com/v1/projects/${ref}/config/auth`, {
      Authorization: `Bearer ${env.SUPABASE_ACCESS_TOKEN}`,
    });
    if (result.json) return { name: `Supabase ${ref}`, fields: supabaseFields(result.json), note: '' };
    return { name: `Supabase ${ref}`, fields: null, note: `Supabase ${ref}: ${result.error}` };
  }));
  for (const row of projectRows) {
    if (row.note) notes.push(row.note);
    if (row.fields) projects.push({ name: row.name, fields: row.fields });
  }

  return renderChecklist({ clerk, instance, supabase: projects, notes });
}

function outputPath(argv) {
  const index = argv.indexOf('--out');
  return index >= 0 ? argv[index + 1] : '';
}

export async function main(argv = process.argv.slice(2), env = process.env, fetchImpl = fetch) {
  const markdown = assertNoSecretValues(await buildChecklist({ env, fetchImpl }), secretValues(env));
  const out = outputPath(argv);
  if (out) await writeFile(out, markdown);
  else process.stdout.write(markdown);
  return markdown;
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  main().catch((error) => {
    let message = 'free-credit-config failed';
    try {
      message = assertNoSecretValues(error?.message || message, secretValues(process.env));
    } catch {
      message = 'free-credit-config failed and hid an error that contained a secret';
    }
    console.error(message);
    process.exitCode = /secret/.test(message) ? 2 : 0;
  });
}
