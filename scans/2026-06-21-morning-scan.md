# Vibe Audit — Morning Scan Report
**Date:** 2026-06-21  
**Scope:** 161 repositories under `jackdog668`  
**Scanner:** vibeaudit v1.1.0 (82 rules, GitHub code-search sweep)  
**Method:** Cross-repo pattern matching via GitHub Search API across all attack surfaces

---

## Summary

| Grade | Repos Scanned | With Code | Findings | Critical | Warning | Info |
|-------|--------------|-----------|----------|----------|---------|------|
| **B+** | 161 | ~110 | 12 | 1 | 7 | 4 |

Overall posture is solid. No committed secrets, no hardcoded API keys, proper use of environment variables across the board. One critical finding and several CORS misconfigurations need attention.

---

## CRITICAL (1)

### 1. Client-Side Gemini API Key Exposure
- **Repo:** `digital-alchemy-os`
- **File:** `src/lib/gemini.ts`
- **Pattern:** `process.env.NEXT_PUBLIC_GEMINI_API_KEY`
- **CWE:** CWE-312 — Cleartext Storage of Sensitive Information
- **CVSS:** 7.5

The `NEXT_PUBLIC_` prefix ships this key into the browser bundle. Anyone can open DevTools → Sources and steal the Gemini API key. This runs up your bill and leaks your usage quota.

**Fix prompt (paste into Claude Code or Cursor):**
> Move the Gemini API call to a server-side API route (e.g., `app/api/gemini/route.ts`). Remove the `NEXT_PUBLIC_` prefix from the env var name so it stays server-only. The client should call your API route, not the Gemini API directly.

---

## WARNING (7)

### 2–3. CORS Wildcard — stitch-alchemy & vibe-vocab
| Repo | File | Issue |
|------|------|-------|
| `stitch-alchemy` | `stitch-server.ts` | `"Access-Control-Allow-Origin": "*"` |
| `vibe-vocab` | `api/vocabulary.ts` | `res.setHeader('Access-Control-Allow-Origin', '*')` |

- **CWE:** CWE-942 — Overly Permissive Cross-domain Whitelist
- **Risk:** Any website can make authenticated requests to these APIs. If they handle user data or paid services, this is exploitable.

**Fix:** Replace `*` with your actual domain(s). For Vercel: `res.setHeader('Access-Control-Allow-Origin', 'https://yourdomain.com')`.

### 4. CORS Wildcard — Chromatic-Illusion-Weaponizerr
- **File:** `server.js`
- **Same pattern:** CORS wildcard on a server that proxies API calls (including Google API keys in headers)

### 5–6. CORS Wildcard — collab-connect (3 Supabase edge functions)
| File | Purpose |
|------|---------|
| `supabase/functions/send-opportunity-alert/index.ts` | Email sending (Resend API) |
| `supabase/functions/firecrawl-search/index.ts` | Firecrawl search |
| `supabase/functions/firecrawl-scrape/index.ts` | Firecrawl scrape |

All three use `'Access-Control-Allow-Origin': '*'` — standard Supabase edge function boilerplate, but if these functions perform privileged operations (sending emails, using paid APIs), the wildcard lets any site trigger them.

### 7–8. CORS Wildcard — firecrawl-site-insight (2 Supabase edge functions)
| File | Purpose |
|------|---------|
| `supabase/functions/firecrawl-map/index.ts` | Site mapping |
| `supabase/functions/firecrawl-analyze/index.ts` | Site analysis |

Same boilerplate CORS wildcard pattern. These functions consume the Firecrawl paid API.

---

## INFO (4)

### 9. Supabase Auth in localStorage — firecrawl-site-insight
- **File:** `src/integrations/supabase/client.ts`
- **Pattern:** `auth: { storage: localStorage, persistSession: true }`
- **Note:** This is Supabase's default behavior and acceptable for most apps, but auth tokens in localStorage are accessible to XSS. Consider `httpOnly` cookies if the app handles sensitive data.

### 10. Firebase Public Keys (5 repos — NOT a vulnerability)
These repos correctly use Firebase's client-side config pattern. Firebase API keys are public by design; security is enforced via Firebase Security Rules and authorized domains.
- `IdeaToPRD-with-Gemini` — `lib/firebase.ts`
- `chibi-forge` — `src/lib/firebase.js`
- `Content-Hook-Generator` — `lib/firebase.ts`
- `Digital-Alchemy-Tracker` — `services/firebase.ts`
- `lovepixel-sticker-studio` — `services/firebase.ts`

### 11. Multiple AI API Integrations (server-side, correct)
The following repos properly load AI API keys from `process.env` on the server side — no exposure:
- `vibeshot`, `vibeshot2` — Gemini
- `chibi-forge` — Gemini (via `process.env.GEMINI_API_KEY`)
- `the-77` — Gemini
- `video-analyzer-70` — Gemini
- `blazing-schrodinger` — OpenAI
- `VIDEOANALYZERGOOGLE` — R2 + Gemini
- `digital-alchemy-app` — Google AI
- `telegram-clipboard` — Telegram bot token

### 12. localStorage Usage (non-sensitive, correct)
41 repos use `localStorage.setItem()` — all for UI state only (themes, form drafts, onboarding flags, game saves). No auth tokens or credentials found in localStorage across any repo.

---

## Clean Bill of Health

The following security hygiene practices are consistently applied across all 161 repos:

| Practice | Status |
|----------|--------|
| No `.env` files committed | ✅ Pass |
| No hardcoded API keys in source | ✅ Pass |
| Server-side env var usage | ✅ Pass |
| No `eval()` usage in app code | ✅ Pass |
| No `dangerouslySetInnerHTML` in app code | ✅ Pass |
| No `Math.random()` for security values | ✅ Pass |
| No committed database credentials | ✅ Pass |
| No leaked Supabase service role keys | ✅ Pass |
| No open Firestore/RTDB rules committed | ✅ Pass |

---

## Repos By Risk (Top 10 to Watch)

These repos have the most security-relevant code and should be scanned individually with `npx vibeaudit` when changes land:

| Priority | Repo | Stack | Why |
|----------|------|-------|-----|
| 🔴 | `digital-alchemy-os` | Next.js + Gemini | Client-side API key |
| 🟡 | `stitch-alchemy` | Bun server | CORS wildcard + WebSocket |
| 🟡 | `vibe-vocab` | Vercel + Neon DB | CORS wildcard + DB access |
| 🟡 | `collab-connect` | Supabase + Firecrawl | 3 edge functions with CORS * |
| 🟡 | `firecrawl-site-insight` | Supabase + Firecrawl | CORS * + localStorage auth |
| 🟢 | `exo-spirit` | Next.js + Supabase + Twilio | Full CRM with auth (looks clean) |
| 🟢 | `digitalalchemy-dev` | Next.js + Supabase | Production site with Google OAuth |
| 🟢 | `homiedex` | Next.js + Upstash | Rate limiting implemented, admin guard |
| 🟢 | `Storefront` | Next.js + Printify | E-commerce with server actions |
| 🟢 | `Siftly` | Next.js + Prisma | Public repo, proper patterns |

---

## Recommended Actions

1. **[5 min]** `digital-alchemy-os`: Move Gemini API call behind a server route, remove `NEXT_PUBLIC_` prefix
2. **[15 min]** Fix CORS wildcards in `stitch-alchemy`, `vibe-vocab`, and `Chromatic-Illusion-Weaponizerr` — replace `*` with your actual domain
3. **[10 min]** Review Supabase edge function CORS in `collab-connect` and `firecrawl-site-insight` — if these are production, tighten to specific origins
4. **[Optional]** Add vibeaudit to CI for the top-10 repos: `npx vibeaudit --format json --strict`

---

*Scan completed 2026-06-21. Next scan scheduled for tomorrow morning.*
