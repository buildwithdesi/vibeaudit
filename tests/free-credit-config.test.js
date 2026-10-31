import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  buildChecklist,
  clerkFieldsFromEnvironment,
  createReadOnlyFetch,
  renderChecklist,
  supabaseFields,
} from '../scripts/free-credit-config.mjs';

const LEAK = `sk-${'B'.repeat(24)}`;

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() { return JSON.stringify(body); },
  };
}

describe('free-credit config checklist', () => {
  it('only sends GET and refuses anything else before calling the network', async () => {
    const calls = [];
    const wrapped = createReadOnlyFetch(async (url, options) => {
      calls.push({ url, options });
      return jsonResponse({});
    });
    await assert.rejects(
      () => wrapped('https://api.clerk.com/v1/instance', { method: 'POST', body: '{}' }),
      /refused POST/,
    );
    await assert.rejects(
      () => wrapped('https://api.clerk.com/v1/instance', { method: 'PATCH' }),
      /refused PATCH/,
    );
    assert.equal(calls.length, 0);
    await wrapped('https://api.clerk.com/v1/instance', { method: 'GET', headers: { Authorization: 'Bearer test-token' } });
    assert.equal(calls[0].options.method, 'GET');
    assert.equal(calls[0].options.redirect, 'manual');
    assert.equal(calls[0].options.body, undefined);
  });

  it('the script source never sets a write method', () => {
    const source = readFileSync(new URL('../scripts/free-credit-config.mjs', import.meta.url), 'utf8');
    assert.doesNotMatch(source, /method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/);
  });

  it('renders the manual spend-cap questions when no tokens are set', async () => {
    const markdown = await buildChecklist({ env: {}, fetchImpl: async () => { throw new Error('network'); } });
    assert.match(markdown, /does not change settings/);
    assert.match(markdown, /Not checked \(no CLERK_FRONTEND_API\)/);
    assert.match(markdown, /Not checked \(no read token or project ref\)/);
    assert.match(markdown, /more than 50 new users per hour/);
    assert.match(markdown, /Gemini: spend cap/);
    assert.match(markdown, /ScrapeCreators: low-balance alert/);
  });

  it('reads Clerk signup fields and drops every other response field', async () => {
    const fields = clerkFieldsFromEnvironment({
      user_settings: {
        sign_up: { mode: 'public', captcha_enabled: true },
        restrictions: {
          block_disposable_email_domains: { enabled: false },
          block_email_subaddresses: { enabled: false },
        },
        attributes: { email_address: { verify_at_sign_up: false } },
      },
      leak: LEAK,
    });
    assert.equal(fields.sign_up_mode, 'public');
    assert.equal(fields['bot_protection.captcha_enabled'], 'yes');
    assert.equal(fields.block_disposable_email_domains, 'no');
    assert.equal(fields.block_email_subaddresses, 'no');
    assert.equal(fields.verify_at_sign_up, 'no');
    assert.equal(JSON.stringify(fields).includes(LEAK), false);
  });

  it('reads Supabase signup, captcha, and email-confirm flags only', () => {
    const fields = supabaseFields({
      disable_signup: false,
      security_captcha_enabled: true,
      mailer_autoconfirm: true,
      external_google_secret: LEAK,
    });
    assert.equal(fields.signups, 'enabled');
    assert.equal(fields.captcha_enabled, 'yes');
    assert.match(fields.email_confirm_required, /autoconfirm is on/);
    assert.equal(JSON.stringify(fields).includes(LEAK), false);
  });

  it('does not print secrets returned by the read APIs', async () => {
    const fetchImpl = async (url) => {
      if (String(url).includes('api.clerk.com/v1/instance')) {
        return jsonResponse({ environment_type: 'production', secret: LEAK });
      }
      if (String(url).includes('/v1/environment')) {
        return jsonResponse({
          user_settings: {
            sign_up: { mode: 'public', captcha_enabled: true },
            restrictions: {
              block_disposable_email_domains: { enabled: false },
              block_email_subaddresses: { enabled: true },
            },
            attributes: { email_address: { verify_at_sign_up: false } },
          },
          leak: LEAK,
        });
      }
      if (String(url).includes('api.supabase.com')) {
        return jsonResponse({
          disable_signup: true,
          security_captcha_enabled: false,
          mailer_autoconfirm: false,
          service_role: LEAK,
        });
      }
      throw new Error(`unexpected ${url}`);
    };
    const markdown = await buildChecklist({
      env: {
        CLERK_SECRET_KEY: 'clerk_test_token_value',
        CLERK_FRONTEND_API: 'https://clerk.example.com',
        CLERK_APP_NAMES: 'Content Drop',
        SUPABASE_ACCESS_TOKEN: 'sb_test_token_value',
        SUPABASE_PROJECT_REFS: 'abcdefghijklmnopqrst',
      },
      fetchImpl,
    });
    assert.match(markdown, /Content Drop/);
    assert.match(markdown, /sign_up_mode \| public/);
    assert.match(markdown, /environment_type \| production/);
    assert.match(markdown, /signups \| disabled/);
    assert.match(markdown, /email_confirm_required \| yes/);
    assert.equal(markdown.includes(LEAK), false);
    assert.equal(markdown.includes('clerk_test_token_value'), false);
    assert.equal(markdown.includes('sb_test_token_value'), false);
  });

  it('records a redirect as refused and does not follow it', async () => {
    const calls = [];
    const markdown = await buildChecklist({
      env: { CLERK_FRONTEND_API: 'https://clerk.example.com' },
      fetchImpl: async (url, options) => {
        calls.push({ url: String(url), redirect: options.redirect, method: options.method });
        return { ok: false, status: 302, async text() { return LEAK; } };
      },
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].method, 'GET');
    assert.equal(calls[0].redirect, 'manual');
    assert.match(markdown, /redirect refused \(302\)/);
    assert.equal(markdown.includes(LEAK), false);
  });

  it('includes the manual section from the renderer', () => {
    const markdown = renderChecklist();
    assert.match(markdown, /Manual/);
    assert.match(markdown, /Yes\/No/);
  });
});
