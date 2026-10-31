/**
 * Rule: ai-cost-exposure
 * Paid AI or data API calls that can run up a bill: no output cap, or a call
 * a free or unverified user can reach without a per-user cap, a shared limiter,
 * or a spend cap.
 *
 * Provider coverage includes Gemini, Deepgram, OpenRouter, DeepSeek, xAI,
 * Replicate, Firecrawl, and ScrapeCreators in addition to OpenAI and Anthropic.
 */

/** @typedef {import('./types.js').Rule} Rule */

import { aiCostHits } from './free-credit.js';

/** @type {Rule} */
export const aiCostExposure = {
  id: 'ai-cost-exposure',
  name: 'AI Cost Exposure',
  severity: 'warning',
  description: 'Paid AI or data API calls with no output cap, or calls a free or unverified user can reach without a per-user cap, a shared limiter, and a spend cap.',

  check(file) {
    const seen = new Set();
    const findings = [];
    for (const hit of aiCostHits(file)) {
      const key = `${hit.provider}|${hit.uncapped}|${hit.unprotected}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const reasons = [];
      if (hit.uncapped) reasons.push('no output cap (max_tokens or maxOutputTokens)');
      if (hit.unprotected) reasons.push('reachable by a free or unverified user with no per-user cap, shared limiter, or spend cap');
      findings.push({
        ruleId: 'ai-cost-exposure',
        ruleName: 'AI Cost Exposure',
        severity: 'warning',
        message: `AI call (${hit.provider}): ${reasons.join('; ')}.`,
        file: file.relativePath,
        line: hit.line,
        evidence: hit.evidence,
        fix: 'Cap each request (max_tokens or maxOutputTokens). If a free or unverified user can reach the call, require a verified paid or allowlisted identity and add a per-user cap, a shared limiter (Redis or Upstash), and a dollar ceiling before the provider call.',
      });
    }
    return findings;
  },
};
