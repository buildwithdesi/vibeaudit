/**
 * Rule: payment-amount-client
 * Detects payment amounts passed from client input instead of being
 * calculated server-side. Attackers can modify amounts in DevTools.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;
const API_FILES = /(?:api\/|routes\/|server\/|functions\/|\.server\.|pages\/api\/|app\/api\/)/i;

const PAYMENT_AMOUNT_FROM_REQUEST = [
  // Stripe amount from request body
  { pattern: /amount\s*:\s*(?:req\.body|request\.body|body)\.\w*(?:amount|price|total|cost)/gi, label: 'Stripe payment amount from request body' },
  // Stripe unit_amount (individual item pricing) from request
  { pattern: /unit_amount\s*:\s*(?:req\.body|request\.body|body|req\.query|req\.params)\.\w*(?:amount|price|total|cost)/gi, label: 'Stripe unit_amount from request body' },
  // Stripe unit_amount directly from request
  { pattern: /unit_amount\s*:\s*(?:req\.body|request\.body|body|req\.query|req\.params)\.(?:amount|price|total|cost)/gi, label: 'Stripe unit_amount directly from request body' },
  // Generic: create payment with body amount
  { pattern: /(?:paymentIntents|charges|checkout\.sessions)\.create\s*\(\s*\{[\s\S]{0,200}amount\s*:\s*(?:req|request|body)\./gi, label: 'Payment created with client-provided amount' },
  // amount directly from params/query
  { pattern: /amount\s*[:=]\s*(?:parseInt|Number|parseFloat)\s*\(\s*(?:req\.(?:body|query|params)|request\.(?:body|query))\./gi, label: 'Payment amount parsed from request' },
];

/** @type {Rule} */
export const paymentAmountClient = {
  id: 'payment-amount-client',
  name: 'Payment Amount from Client',
  severity: 'critical',
  description: 'Detects payment amounts taken from client input instead of server-side calculation.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!API_FILES.test(file.relativePath)) return [];
    if (!/(?:amount|price|payment|stripe|charge)/i.test(file.content)) return [];

    const findings = [];

    for (const { pattern, label } of PAYMENT_AMOUNT_FROM_REQUEST) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(file.content)) !== null) {
        const lineNum = file.content.slice(0, match.index).split('\n').length;
        findings.push({
          ruleId: 'payment-amount-client',
          ruleName: 'Payment Amount from Client',
          severity: 'critical',
          message: `${label} — attacker can modify the amount to pay $0.01.`,
          file: file.relativePath,
          line: lineNum,
          evidence: file.lines[lineNum - 1]?.trim().slice(0, 120),
          fix: 'Calculate the payment amount server-side from your database (product price × quantity). Never trust the amount from the client request.',
        });
      }
    }

    return findings;
  },
};
