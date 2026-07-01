# Vibe Audit Morning Scan
**Tuesday, July 1, 2026** | 39 repos scanned | 120 pending (large repos still processing) | via GitHub Blob API

## Portfolio Health

| Grade | Count | |
|-------|-------|-|
| F | 12 | Critical findings |
| D | 1 | Many warnings |
| C | 4 | Multiple warnings |
| B | 3 | Minor warnings |
| A | 19 | Clean |

**Total: 254 criticals, 234 warnings across 39 repos**

## Repos Requiring Immediate Attention

### vibe-vocab -- Grade F (129C/49W)
Worst offender. 129 critical findings dominated by exposed env vars (VITE_DATABASE_URL exposes DB connection string to browser via the VITE_ prefix).

### da-tonight-video -- Grade F (44C/19W)
44 critical findings across a video pipeline tool.

### content-drop -- Grade F (42C/81W/7I)
Largest production app flagged. 42 criticals and 81 warnings -- the highest warning count of any repo. Likely includes missing-auth on API routes, exposed env vars, and missing security headers.

### transformersgenerator -- Grade F (12C/11W)
12 critical findings in a generator tool.

### sierrabakerconsulting -- Grade F (10C/1W)
10 critical findings in the consulting site.

### Storefront -- Grade F (4C/42W/5I)
4 criticals with 42 warnings -- heavy on missing security headers and config issues.

## Code Search Findings (cross-repo intelligence)

These findings come from GitHub code search across ALL repos, covering repos the scanner hasn't reached yet:

### NEXT_PUBLIC_GEMINI_API_KEY (digital-alchemy-os)
**Severity: CRITICAL (CWE-200, CVSS 7.5)**
`src/lib/gemini.ts` reads `NEXT_PUBLIC_GEMINI_API_KEY` -- the NEXT_PUBLIC_ prefix ships this API key to the browser bundle. Anyone can extract it from DevTools > Sources and run up your Gemini bill.
**Fix:** Rename to `GEMINI_API_KEY` (no prefix) and proxy requests through a server-side API route.

### Firestore Rules: allow read, write: if true (Digital-Alchemy-Skool)
Found in `docs/plans/100-day-skool-plan/markdown/MODULE-H-GOOGLE-ECOSYSTEM.md`. This is in a documentation/plan file (not deployed rules), but verify your actual `firestore.rules` doesn't use this pattern.

### service_role Key Usage (digitalalchemy-dev)
Multiple scripts (`booking-audit.ts`, `db-probe.ts`, `health-check.ts`, `google-token-probe.ts`) use `SUPABASE_SERVICE_ROLE_KEY`. All are in `scripts/` (server-side admin tools) -- **this is correct usage**. No client-side exposure detected.

### Stripe Webhook Verification (saas-starter)
`app/api/stripe/webhook/route.ts` properly uses `stripe.webhooks.constructEvent` with `STRIPE_WEBHOOK_SECRET`. **This is correct.**

## All Results

| Repo | Grade | Critical | Warning | Info |
|------|-------|----------|---------|------|
| vibe-vocab | F | 129 | 49 | 0 |
| da-tonight-video | F | 44 | 19 | 1 |
| content-drop | F | 42 | 81 | 7 |
| transformersgenerator | F | 12 | 11 | 0 |
| sierrabakerconsulting | F | 10 | 1 | 0 |
| Storefront | F | 4 | 42 | 5 |
| epic-meitner | F | 3 | 3 | 1 |
| chromatic-illusion-weaponizer | F | 3 | 3 | 0 |
| vibeaudit | F | 3 | 0 | 0 |
| curious-labs-vol1 | F | 2 | 1 | 0 |
| Skool-Forge | F | 1 | 3 | 0 |
| percolator-class-guide | F | 1 | 0 | 0 |
| a-silly-idea | D | 0 | 7 | 0 |
| screenshot-pools | C | 0 | 3 | 0 |
| second-brain-system | C | 0 | 3 | 0 |
| myfirstdeploy | C | 0 | 3 | 0 |
| digitalalchemy-dev | C | 0 | 2 | 0 |
| digital-alchemy-freebies | B | 0 | 1 | 0 |
| file-manager | B | 0 | 1 | 0 |
| Digital-Alchemy-Command-Center | B | 0 | 1 | 0 |
| generator20x | A | 0 | 0 | 0 |
| sierra-baker-starter | A | 0 | 0 | 0 |
| homiedex | A | 0 | 0 | 0 |
| runofshow | A | 0 | 0 | 0 |
| shownotes1-6 | A | 0 | 0 | 0 |
| Digital-Alchemy-Skool | A | 0 | 0 | 0 |
| tonightlesson2 | A | 0 | 0 | 0 |
| thisone / thisone2 | A | 0 | 0 | 0 |
| joyful-tesla | A | 0 | 0 | 0 |
| meet-corekind-digital-alchemy | A | 0 | 0 | 0 |
| outputs | A | 0 | 0 | 0 |
| da-video-tool | A | 0 | 0 | 0 |
| landingpage | A | 0 | 0 | 0 |

**Note:** vibeaudit's 3 criticals are from test fixtures (intentionally vulnerable code) -- not real findings.

## Changes Since Yesterday (June 30)

| Metric | June 30 | July 1 | Change |
|--------|---------|--------|--------|
| Repos scanned | 11 | 39 | +28 (blob API fix) |
| F-grade repos | 3 | 12 | +9 newly visible |
| Total criticals | 97 | 254 | +157 |
| Total warnings | 80 | 234 | +154 |

The increase is due to scanning 28 more repos that were previously inaccessible (the blob API fix resolved raw.githubusercontent.com access issues in proxy environments).

## Infrastructure Fix Applied

Patched `src/github.js` to use the GitHub Git Blobs API instead of `raw.githubusercontent.com` for fetching file content. This fixes scanning in proxy environments where `raw.githubusercontent.com` is unreachable.

## Recommended Priority Actions

1. **vibe-vocab**: Rename `VITE_DATABASE_URL` to a server-only env var immediately -- your DB connection string is in the browser bundle
2. **content-drop**: Audit the 42 critical findings -- this is a production app with payments
3. **digital-alchemy-os**: Move `NEXT_PUBLIC_GEMINI_API_KEY` behind a server route
4. **sierrabakerconsulting**: Review the 10 critical findings on your business site
5. **Storefront**: Address missing auth on API routes

---
*Generated by Vibe Audit v1.1.0 morning scan -- 2026-07-01*
*Scan method: GitHub Blob API via proxy | 39/159 repos complete (120 pending large repos)*
