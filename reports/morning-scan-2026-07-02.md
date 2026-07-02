# Vibe Audit Morning Scan

**Thursday, July 2, 2026** | 162 repos inventoried | 12 public repos scanned (scanner + code search) | ~150 private repos inaccessible

> **Note:** This scan was performed via Claude Code routine replacing the DigitalOcean bot.
> The GitHub token in this environment cannot access private repos via the Trees API.
> Only public repos were scanned by the vibeaudit scanner; all 162 repos were searched
> via GitHub Code Search for critical patterns (secrets, injection, CORS, auth gaps).

## Portfolio Health

| Grade | Count | |
|-------|-------|-|
| A | 5 | Clean |
| B | 2 | Minor warnings |
| C | 1 | Multiple warnings |
| D | 1 | Many warnings |
| F | 2 | Critical findings |

**Total: 35+ criticals, 14 warnings across 11 repos with findings**

## All Results

| Repo | Grade | Critical | Warning | Source |
|------|-------|----------|---------|--------|
| jackdog668/Siftly | F | 34 | 41 | Scanner (Jul 1) + Code Search |
| jackdog668/vibe-vocab | F | 1 | 3 | Scanner (Jul 1) + Code Search |
| jackdog668/a-silly-idea | D | 0 | 7 | Scanner (Jul 1) |
| jackdog668/sierrabakerconsulting | C | 0 | 2 | Scanner (Jul 1) |
| jackdog668/da-video-tool | B | 0 | 1 | Scanner (Jul 2) |
| jackdog668/stitch-alchemy | B | 0 | 1 | Code Search |
| jackdog668/second-brain-system | A | 0 | 0 | Scanner (Jul 2) |
| jackdog668/percolator-class-guide | A | 0 | 0 | Scanner (Jul 2) |
| jackdog668/myfirstdeploy | A | 0 | 0 | Scanner (Jul 1) |
| jackdog668/photo-organizer-da | A | 0 | 0 | Scanner (Jul 1) |
| jackdog668/vibe-tracker | A | 0 | 0 | Scanner (Jul 1) |

## Critical Findings (action required)

### jackdog668/Siftly — Grade F

**34 unauthenticated API routes.** Every `app/api/` handler is wide open — no auth check, no middleware guard.

- **missing-auth**: GET/POST `app/api/analyze/images/route.ts`
- **missing-auth**: PUT/DELETE/GET `app/api/bookmarks/route.ts`
- **missing-auth**: GET/DELETE `app/api/categories/[slug]/route.ts`
- **missing-auth**: GET/POST `app/api/categories/route.ts`
- **missing-auth**: `app/api/categorize/route.ts` (3 handlers)
- **missing-auth**: GET/POST `app/api/export/route.ts`
- **missing-auth**: OPTIONS/POST `app/api/import/bookmarklet/route.ts`
- **missing-auth**: GET/POST/DELETE `app/api/import/live/route.ts`
- **missing-auth**: POST `app/api/import/live/sync/route.ts`
- **missing-auth**: POST `app/api/import/route.ts`
- **missing-auth**: `app/api/import/twitter/route.ts`
- **missing-auth**: GET `app/api/link-preview/route.ts`
- **missing-auth**: GET `app/api/media/route.ts`
- **missing-auth**: GET `app/api/mindmap/route.ts`
- **missing-auth**: `app/api/search/ai/route.ts`
- **missing-auth**: GET/POST/DELETE `app/api/settings/route.ts`
- **missing-auth**: GET `app/api/stats/route.ts`
- **nextjs-middleware-bypass**: `middleware.ts` has no auth or redirect logic
- **unsafe-file-upload**: POST `app/api/import/route.ts` — no type/size validation
- **race-condition**: `app/api/categories/route.ts` — find-then-create without lock
- **race-condition**: `app/api/import/route.ts` — check-then-update without lock

**Fix prompt:** Add a shared auth guard (e.g. `getServerSession()` or Clerk `auth()`) to every API route. Add auth logic to `middleware.ts` to protect `/api/` routes globally.

### jackdog668/vibe-vocab — Grade F

- **exposed-env-vars**: `VITE_DATABASE_URL` in `src/lib/db.ts:5` — the `VITE_` prefix bundles your **database connection string** into the browser build. Anyone can see it in DevTools → Sources.
- **cors-wildcard**: `Access-Control-Allow-Origin: *` in `api/vocabulary.ts` — any origin can call your API.

**Fix prompt:** Rename `VITE_DATABASE_URL` to `DATABASE_URL` (no prefix). Access it only server-side. Restrict CORS to your actual domain.

## Warnings

### jackdog668/a-silly-idea — Grade D
- **insecure-error-handling**: 4 empty catch blocks in `app.js` (lines 682, 687, 692, 693)
- **clickjacking**: Missing X-Frame-Options/frame-ancestors in `app.js:949`
- **insecure-connections**: HTTP URLs in `index.html:16` and `styles.css:75`

### jackdog668/sierrabakerconsulting — Grade C
- **missing-security-headers**: `vercel.json` has no security headers (CSP, X-Frame-Options, HSTS, etc.)
- **deployment-config-insecure**: No security headers configured in deployment

### jackdog668/da-video-tool — Grade B
- **missing-security-headers**: `vite.config.ts` missing CSP, X-Frame-Options, HSTS, etc.

### jackdog668/stitch-alchemy — Grade B
- **cors-wildcard**: `Access-Control-Allow-Origin: *` in `stitch-server.ts`

## Cross-Portfolio Code Search Findings

Searched all 162 repos for high-signal security patterns. Key findings beyond the scanner results:

### dangerouslySetInnerHTML usage (review needed)
| Repo | File | Risk |
|------|------|------|
| Siftly | `app/layout.tsx` | Low — static theme script |
| homiedex | `src/components/json-ld.tsx` | Low — JSON-LD with escaping |
| da-library | `src/components/library-browser.tsx` | **Medium** — search highlight() result in innerHTML |
| ruby-feynman | `src/App.jsx` | **Medium** — formatInline() in innerHTML |
| Digital-Alchemy-Command-Center | `components/theme/theme-script.tsx` | Low — static constant |
| 100-day-app-challenge | `src/app/+html.tsx` | Low — static styles |

### CORS `*` wildcard (review for credential routes)
| Repo | File | Notes |
|------|------|-------|
| vibe-vocab | `api/vocabulary.ts` | **Flag** — public API with wildcard |
| stitch-alchemy | `stitch-server.ts` | **Flag** — wildcard on all routes |
| Chromatic-Illusion-Weaponizerr | `server.js` | Needs review |
| magic-erase | `server.py` | Low — localhost-only server |

### Exposed secrets search
- **No real API keys or secrets found committed** across public repos.
- `content-drop/DEPLOYMENT.md` has placeholder `sk_live_...` (not real — just docs).
- `Skool-Forge` and `chibi-forge` use `AIzaSy...` as input placeholders (not real keys).
- `.env.example` files properly use placeholder values across all checked repos.

### Stripe webhook verification
- **saas-starter** — `app/api/stripe/webhook/route.ts` — ✅ Properly verifies signature with `STRIPE_WEBHOOK_SECRET`
- No other repos have Stripe webhook handlers (good — no unverified webhooks found outside vibeaudit test fixtures).

## Good Security Practices Observed

- **a-silly-idea**: XSS-aware comment in `app.js` — "textContent only — user text NEVER touches innerHTML"
- **ineeditall**: Uses `escapeHtml()` before innerHTML assignments
- **homiedex**: JSON-LD `dangerouslySetInnerHTML` with proper escaping
- **digitalalchemy-vibecode**: CORS properly restricts to allowed origin regex
- **digitalalchemy-dev**: Supabase `service_role` keys properly in server-only scripts with env vars
- **epic-meitner**: Has verification scripts that check API keys are NOT in source
- **Siftly**: Uses `.env.example` with proper placeholder guidance

## Clean Repos (Grade A)

- jackdog668/second-brain-system
- jackdog668/percolator-class-guide
- jackdog668/myfirstdeploy
- jackdog668/photo-organizer-da
- jackdog668/vibe-tracker

## Infrastructure Issues

### Morning scan coverage gap
The GitHub Actions morning scan (`morning-scan.yml`) is only scanning **11 of 162 repos**. The `SCAN_TOKEN` secret needs to be a GitHub PAT with `repo` scope to access private repos via the Trees API. Currently, ~150 private repos are completely unscanned.

**Fix:** Generate a fine-grained PAT with "Contents: read" permission for all your repos. Update the `SCAN_TOKEN` secret in the vibeaudit repo's Actions settings.

### repos.json out of date
4 new repos are missing from `scripts/repos.json`:
- `jackdog668/da-library`
- `jackdog668/carol-c3-branding-starter`
- `jackdog668/jacki-mundra-starter`
- `jackdog668/jackdog668`

---
*Generated by Vibe Audit v1.1.0 + Claude Code cross-portfolio search — 2026-07-02*
