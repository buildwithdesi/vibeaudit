# The Next 50 — What the Viral Checklist Forgot

The "20 things / 50 things that get your vibe-coded app hacked" lists are real, but
incomplete. Here's the **next 50** — the layer a production audit actually covers — mapped
against Vibe Audit.

**The headline: Vibe Audit already catches 36 of these 50 that the viral list never mentioned.**
The tool doesn't play catch-up to the meme; it laps it.

- ✅ **covered** by a Vibe Audit rule
- 🟨 **partial** (an adjacent rule catches some of it)
- 🆕 **gap** (not yet a rule — mostly judgment/infra that belongs to the Pre-Flight Audit Prompt)

**Tally: 36 ✅ · 3 🟨 · 11 🆕**

---

## A · Auth, session & identity
1. OAuth `state` missing → OAuth CSRF — ✅ `oauth-state-missing`
2. MFA not enforced / skippable — ✅ `mfa-bypass`
3. Tokens with no expiry — ✅ `auth-token-no-expiry`
4. Non-constant-time token compare — ✅ `timing-attack`
5. `Math.random()` for tokens/IDs — ✅ `insecure-randomness`
6. Session not regenerated on login (fixation) — ✅ `session-fixation`
7. Sequential IDs → enumeration — ✅ `predictable-ids`
8. No password strength policy — 🆕
9. No breached-password / credential-stuffing defense — 🆕 (needs an external service — judgment lane)
10. Email/phone unverified before privileged actions — 🆕

## B · Injection & unsafe execution
11. **OS command injection** (`exec`/`spawn` + interpolated input) — ✅ `command-injection` *(shipped)*
12. XXE — ✅ `xml-xxe`
13. LDAP injection — ✅ `ldap-injection`
14. Server-side template injection (SSTI) — ✅ `template-injection` *(shipped)*
15. CRLF / header injection — ✅ `header-injection`
16. ReDoS — ✅ `regex-dos`
17. Prototype pollution — ✅ `prototype-pollution`
18. Unsafe deserialization (`unserialize`, `vm.runIn*`) — ✅ `unsafe-deserialization` *(shipped)*
19. `eval()` / `new Function()` — ✅ `eval-usage`
20. Open redirect — ✅ `unsafe-redirect`

## C · API, GraphQL & data exposure
21. Overfetch full DB objects — ✅ `api-data-overfetch`
22. No pagination → scrape/DoS — ✅ `no-pagination`
23. GraphQL introspection in prod — ✅ `graphql-introspection`
24. No GraphQL depth cap — ✅ `graphql-depth-limit`
25. GraphQL resolvers without auth — ✅ `graphql-no-auth`
26. Mass assignment / over-posting — ✅ `mass-assignment`
27. Race condition / TOCTOU — ✅ `race-condition`
28. Guessable / un-randomized webhook path — 🆕
29. Missing SRI on CDN scripts — ✅ `missing-sri` *(shipped)*
30. Fingerprinting headers (`X-Powered-By`/`Server`) — 🆕

## D · Infra, deploy & supply chain
31. Subdomain takeover — ✅ `subdomain-takeover`
32. Clickjacking (`frame-ancestors`) — ✅ `clickjacking`
33. Docker running as root — ✅ `docker-root-user`
34. DB port exposed to host — ✅ `exposed-database-port`
35. Insecure deploy config (vercel/netlify) — ✅ `deployment-config-insecure`
36. Lockfile missing / deps unpinned — 🟨 `unpinned-dependencies` *(shipped — catches `*`/`latest`; lockfile-missing still open)*
37. Untrusted `postinstall` scripts (supply chain) — 🆕
38. Hardcoded secrets in CI/CD workflow files — 🆕
39. `.git` / `.env` reachable at web root — 🆕
40. Vulnerable / outdated deps — ✅ SCA (`vulnerable-dependency`)

## E · AI-specific
41. Unbounded LLM cost (no token/spend cap) — ✅ `ai-cost-exposure`
42. Trusting AI output un-validated — ✅ `ai-response-trusted`
43. System prompt leaked to client — 🆕
44. AI output rendered as raw HTML (LLM → XSS) — 🟨 `dangerously-set-inner-html`
45. Agent/tool-calling with no action guardrails — 🆕 (judgment lane)

## F · Privacy, a11y, scale & ops (boring but sued)
46. PII to third-party analytics without consent — 🟨 `pii-logging`
47. No data-retention / deletion path (GDPR erasure) — 🆕 (process — judgment lane)
48. Accessibility / WCAG failures (ADA) — ✅ `a11y-*` pack
49. No error monitoring / alerting — ✅ `no-error-monitoring` *(shipped)*
50. Scale footguns: N+1 / connection exhaustion / ephemeral disk — ✅ `perf-*` + `serverless-fs-write`

---

## Remaining gaps → roadmap vs judgment lane

**Buildable next (static rules):** guessable webhook path (28), fingerprinting headers (30),
untrusted postinstall (37), CI/CD secrets / Actions script injection (38), `.git` exposed (39),
password policy (8), system-prompt leak (43).

**Not rules — Pre-Flight Audit Prompt / process:** breached-password (9), email-verification
enforcement (10), GDPR erasure (47), AI tool guardrails (45), consent-for-PII (46). These need
judgment about *your* business logic and data model — the layer a static scanner can't see.
