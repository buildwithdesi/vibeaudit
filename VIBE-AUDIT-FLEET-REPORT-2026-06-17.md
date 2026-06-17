# Vibe Audit Fleet Scan — 2026-06-17

**Scanned:** 161 repositories under `jackdog668`
**Scanner:** vibe-audit pattern search via GitHub Code Search API
**Date:** June 17, 2026 (morning routine)

---

## Overall Grade: B+

Your fleet is in solid shape — no leaked secrets, good `.env.example` discipline across 30+ repos, and proper cookie handling where it matters most (saas-starter, content-drop, digitalalchemy-dev). The main issues are CORS wildcards in production code and a few `dangerouslySetInnerHTML` usages that bypass React's XSS protection with dynamic content.

---

## CRITICAL — Fix These First

### 1. Hardcoded fallback password in client-side code
**Repo:** `chromatic-illusion-weaponizer`
**File:** `components/LoginScreen.tsx`
```js
const CORRECT_PASSWORD = import.meta.env.VITE_LOGIN_PASSWORD || '$YULETIDE';
```
- The fallback `$YULETIDE` ships in the JS bundle — visible in DevTools Sources
- `VITE_` prefix means the real password is also in the bundle when set
- **Fix:** Move auth to a server-side check. Client-side password gates are always bypassable.

### 2. `dangerouslySetInnerHTML` with dynamic/user content (potential XSS)

| Repo | File | Risk |
|------|------|------|
| `ruby-feynman` | `src/App.jsx` | Renders content via `formatInline()` — no DOMPurify |
| `digital-alchemy-app` | `webapp/src/pages/Resources.tsx` | Regex-replaces markdown then injects as HTML |
| `digitalalchemy-dev` | `NewsletterCampaignComposer.tsx` | `compileLivePreview(bodyHtml)` rendered as raw HTML |
| `digitalalchemy-dev` | `CampaignCockpitClient.tsx` | Same `compileLivePreview(bodyHtml)` pattern |
| `da-library` | `src/components/library-browser.tsx` | Search highlight snippets rendered as HTML |
| `content-drop` | `src/app/library/library-browser.tsx` | Search highlight snippets rendered as HTML |
| `1code-main` | `agent-tool-call.tsx` (×2) | `subtitleStr` rendered without sanitization |

**Fix for all:** Install DOMPurify and wrap: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}`

---

## WARNING — Address Soon

### 3. CORS wildcard `Access-Control-Allow-Origin: *` (8 repos)

Any website can call these APIs:

| Repo | File(s) |
|------|---------|
| `vibe-vocab` | `api/vocabulary.ts` |
| `Siftly` | `app/api/media/route.ts` |
| `stitch-alchemy` | `stitch-server.ts` |
| `Chromatic-Illusion-Weaponizerr` | `server.js` |
| `crypto-101` | `netlify/edge-functions/prices.js` |
| `100-day-app-challenge` | `netlify/functions/reddit-trends.js`, `generate-idea.js` |
| `collab-connect` | 3 Supabase edge functions |
| `firecrawl-site-insight` | 2 Supabase edge functions |

**Risk:** If any of these APIs accept writes, mutate state, or expose private data, the wildcard lets any site exploit them.
**Fix:** Replace `*` with an allowlist of your actual domains. For read-only public APIs (crypto prices, static data), wildcard is acceptable.

### 4. Non-httpOnly auth cookie
**Repo:** `1code-main`
**File:** `1code-main/src/main/index.ts`
```js
httpOnly: false,
```
Auth cookies readable by JavaScript are vulnerable to XSS-based session theft.

### 5. No security middleware detected fleet-wide
Across all 161 repos, **zero** use `helmet`, `express-rate-limit`, or CSRF token libraries (outside vibeaudit's own recommendations). Most repos are:
- Vite/Next.js frontends (inherently less exposed)
- Serverless functions (platform handles some headers)

But `blazing-schrodinger`, `sref-scanner`, `ruby-magnetosphere`, and `Chromatic-Illusion-Weaponizerr` run Express servers with `app.use(cors())` and no helmet/rate-limiting.

---

## CLEAN — No Issues Found

| Check | Result |
|-------|--------|
| Leaked API keys/tokens in source | **None found** — all 161 repos clean |
| `.env` files committed | **None** — only `.env.example` / `.env.template` with placeholders |
| Firebase/Firestore open rules | **None committed** (only vibeaudit test fixtures) |
| `eval()` / `new Function()` in production | **None found** |
| `__proto__` pollution vectors | **None found** |
| Proper cookie security (where used) | `saas-starter`, `content-drop`, `digitalalchemy-dev` all use `httpOnly: true, secure: true, sameSite: "lax"` |
| `.gitignore` coverage | `.env*` files properly ignored across repos with env vars |

---

## Safe `dangerouslySetInnerHTML` Usages (no action needed)

These use static strings or properly sanitized content:
- `Siftly` — theme detection script (compile-time string, no user input)
- `content-drop` — theme script (static)
- `Digital-Alchemy-Command-Center` — theme script (explicitly documented as safe)
- `homiedex` — JSON-LD with `JSON.stringify()` escape
- `digitalalchemy-dev` — `JsonLd.tsx` uses children instead, `SchemaMarkup.tsx` uses `JSON.stringify`, `ChromeHider.tsx` uses text-node rendering
- `chibi-forge` — CSS injection via style tag (static)
- Multiple repos: `chart.tsx` from shadcn/ui (static theme CSS)

---

## Repo Activity Summary

| Metric | Count |
|--------|-------|
| Total repos | 161 |
| With code (language detected) | 131 |
| Updated in last 7 days | 6 (`content-drop`, `da-library`, `sierrabakerconsulting`, `a-silly-idea`, `screenshot-pools`, `carol-c3-branding-starter`) |
| Public repos | 33 |
| Private repos | 128 |

---

## Recommended Priority Actions

1. **Today:** Fix the `chromatic-illusion-weaponizer` hardcoded password — it's in the JS bundle
2. **This week:** Add DOMPurify to `ruby-feynman`, `digital-alchemy-app`, `digitalalchemy-dev`, `da-library`, `content-drop`, `1code-main`
3. **This week:** Set `httpOnly: true` on the `1code-main` auth cookie
4. **When deploying:** Replace CORS `*` with domain allowlists on any APIs that handle auth or mutations
5. **Nice to have:** Add `helmet` to the 4 Express servers

---

*Generated by Vibe Audit fleet scan routine — replacing DigitalOcean bot*
*Scanner: vibe-audit v1.1.0 × GitHub Code Search API*
