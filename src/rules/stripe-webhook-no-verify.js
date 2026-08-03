/**
 * Rule: stripe-webhook-no-verify
 * Detects Stripe webhook handlers that don't verify the webhook signature
 * using stripe.webhooks.constructEvent().
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules|src\/rules\/)/i;

// Only source can be a handler. The old rule matched on file content alone, so
// a demo-bookmarks.json containing links to stripe.com was reported as an
// unverified webhook handler.
const SOURCE_FILE = /\.(?:[cm]?[jt]sx?|py|rb|go|php)$/i;

// Stripe's own event names. Prose mentioning "Stripe" is not a webhook.
const STRIPE_EVENT =
  /(?:checkout\.session|payment_intent|invoice\.[a-z_]+|customer\.subscription|charge\.[a-z_]+|payout\.[a-z_]+|setup_intent)/i;

// Reading this header is the single strongest proof a file IS a Stripe webhook.
const READS_SIGNATURE = /['"`]stripe-signature['"`]|STRIPE_WEBHOOK_SECRET/i;

// Evidence the file actually receives an HTTP request, rather than merely
// mentioning payments. Kept broad on purpose: handlers are written many ways.
const IS_HANDLER =
  /\breq(?:uest)?\s*\.\s*(?:body|headers|method|text|json|rawBody)|\bres\s*\.\s*(?:status|json|send|end)|export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH)|export\s+const\s+(?:POST|PUT|PATCH)\s*=|\b(?:app|router)\s*\.\s*(?:post|use)\s*\(|export\s+default\s+(?:async\s+)?function|def\s+\w*webhook\w*\s*\(/i;

// Signature verification, across the SDKs.
const VERIFIES = /constructEvent|webhooks\.construct|construct_event|verify_header|Webhook\.constructEvent/i;

/** @type {Rule} */
export const stripeWebhookNoVerify = {
  id: 'stripe-webhook-no-verify',
  name: 'Stripe Webhook No Verification',
  severity: 'critical',
  description: 'Detects Stripe webhook handlers without signature verification.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!SOURCE_FILE.test(file.relativePath)) return [];

    const content = file.content;

    // Must actually receive a request. A schema comment, an env module, or a
    // marketing page listing "Stripe, Twilio, SendGrid" is not a handler.
    if (!IS_HANDLER.test(content)) return [];

    // Must actually process Stripe webhook events. Either it reads the
    // signature header / secret, or it branches on a real Stripe event name.
    const readsSignature = READS_SIGNATURE.test(content);
    const dispatchesEvent = /\b(?:event|evt)\s*\.\s*type\b/.test(content) && STRIPE_EVENT.test(content);
    if (!readsSignature && !dispatchesEvent) return [];

    if (VERIFIES.test(content)) return [];

    // Find the webhook handler line
    const lineIdx = file.lines.findIndex((l) =>
      /event\.type|checkout\.session|payment_intent|stripe-signature/i.test(l)
    );

    return [{
      ruleId: 'stripe-webhook-no-verify',
      ruleName: 'Stripe Webhook No Verification',
      severity: 'critical',
      message: 'Stripe webhook handler does not verify the signature — anyone can send fake events.',
      file: file.relativePath,
      line: lineIdx >= 0 ? lineIdx + 1 : 1,
      evidence: file.lines[lineIdx]?.trim().slice(0, 120),
      fix: 'Verify the webhook: const event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET). Never parse the body as JSON first — use the raw body.',
    }];
  },
};
