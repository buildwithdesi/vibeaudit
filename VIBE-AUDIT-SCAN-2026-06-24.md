# Vibe Audit — Cross-Repo Security Scan

**Date:** 2026-06-24 (Morning Scan)
**Scope:** 161 repositories under jackdog668
**Method:** GitHub Code Search against VibeAudit rule patterns (static analysis via API — replaces DigitalOcean bot)

---

## Executive Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 2     | Action needed |
| WARNING  | 12    | Review recommended |
| INFO     | 8     | Acceptable / low-risk |

**No committed secrets found.** No `.env` files with real credentials, no hardcoded API keys (sk_live, AKIA, etc.) in source. Environment variable discipline is solid across the portfolio.

---

## CRITICAL Findings

### 1. Gemini API Key Exposed Client-Side — `digital-alchemy-os`

**File:** `src/lib/gemini.ts`
**Pattern:** `process.env.NEXT_PUBLIC_GEMINI_API_KEY`

The `NEXT_PUBLIC_` prefix bakes the key into the client-side JavaScript bundle. Anyone can open DevTools → Sources and extract the Gemini API key, then use it to run up your API bill or abuse your quota.

**Fix:** Rename to `GEMINI_API_KEY` (server-only). Create a `/api/gemini` route that proxies requests from the frontend. The key stays on the server, and you can add rate-limiting to the proxy route.

---

### 2. Auth Cookie Missing httpOnly — `1code-main`

**File:** `1code-main/src/main/index.ts`
**Pattern:** `httpOnly: false` on auth cookie

With `httpOnly: false`, any JavaScript on the page (including XSS payloads) can read the auth cookie via `document.cookie`. This enables session theft.

**Fix:** Set `httpOnly: true`. If the frontend needs to know auth state, use a separate non-sensitive indicator (e.g., a `logged_in=1` cookie or a `/api/me` endpoint).

---

## WARNING Findings

### 3. CORS Wildcard `Access-Control-Allow-Origin: *` — 10 repos

Any website can call these API endpoints. If they handle sensitive data or authenticated requests, this is exploitable.

| Repo | File | Notes |
|------|------|-------|
| **stitch-alchemy** | `stitch-server.ts` | Full wildcard CORS object |
| **vibe-vocab** | `api/vocabulary.ts` | Wildcard + `Allow-Credentials: true` (browsers reject this combo, but still risky) |
| **Chromatic-Illusion-Weaponizerr** | `server.js` | Wildcard on OPTIONS preflight |
| **firecrawl-site-insight** | `supabase/functions/firecrawl-analyze/index.ts` | Wildcard CORS |
| **firecrawl-site-insight** | `supabase/functions/firecrawl-map/index.ts` | Wildcard CORS |
| **collab-connect** | `supabase/functions/firecrawl-scrape/index.ts` | Wildcard CORS |
| **collab-connect** | `supabase/functions/firecrawl-search/index.ts` | Wildcard CORS |
| **collab-connect** | `supabase/functions/send-opportunity-alert/index.ts` | Wildcard CORS |
| **100-day-app-challenge** | `netlify/functions/generate-idea.js` | Wildcard CORS |
| **100-day-app-challenge** | `netlify/functions/reddit-trends.js` | Wildcard CORS |
| **crypto-101** | `netlify/edge-functions/prices.js` | Wildcard CORS |
| **Siftly** | `app/api/media/route.ts` | Wildcard on media proxy |

**Fix:** Replace `*` with your actual frontend domain(s). For Supabase edge functions, use the Supabase dashboard URL or your custom domain.

---

### 4. Open CORS with No Config — 2 repos

| Repo | File |
|------|------|
| **sref-scanner** | `backend/server.js` — `app.use(cors())` |
| **blazing-schrodinger** | `server/server.js` — `app.use(cors())` |

`cors()` with no arguments defaults to `origin: *`. Pass `{ origin: process.env.CORS_ORIGIN }`.

---

### 5. CSRF Protection Disabled — `digitalalchemy-vibecode`

**File:** `backend/src/auth.ts`
**Pattern:** `disableCSRFCheck: true`

Comment says "CORS origin validation + credential-based cookies" is sufficient. This is defensible if CORS is correctly configured (it appears to use an allowlist), but CSRF tokens provide defense-in-depth. Monitor the CORS config — if it ever opens to `*`, you lose both layers.

---

### 6. `dangerouslySetInnerHTML` with Dynamic Content — 4 repos

These use `dangerouslySetInnerHTML` with content that may include user-controlled data:

| Repo | File | Risk |
|------|------|------|
| **ruby-feynman** | `src/App.jsx` | `formatInline(content)` → XSS if content comes from user input |
| **da-library** | `src/components/library-browser.tsx` | `highlight(h.snippet)` — comment says HTML-escaped before mark swap |
| **1code-main** | `agent-tool-call.tsx` | `subtitleStr` rendered as HTML |
| **digital-alchemy-app** | `webapp/src/pages/Resources.tsx` | Paragraph with regex `**bold**` replacement |

**Fix:** Audit each `formatInline` / `highlight` function to confirm input is escaped before HTML insertion. Prefer `textContent` or a sanitizer like DOMPurify.

---

### 7. Missing Rate Limiting on API Routes — Most repos

Only **video-analyzer-70** uses `express-rate-limit`. The following repos have public API routes without rate limiting:

- **vibe-vocab** — `api/vocabulary.ts` (Vercel serverless)
- **100-day-app-challenge** — Netlify functions (`generate-idea.js`, `reddit-trends.js`)
- **stitch-alchemy** — `stitch-server.ts`
- **sref-scanner** — `backend/server.js`
- **blazing-schrodinger** — `server/server.js`
- **Chromatic-Illusion-Weaponizerr** — `server.js`
- **screenshot-pools** — `api/analyze-screenshot.js`

**Fix:** Add rate limiting (e.g., `express-rate-limit`, Vercel Edge Config, or Upstash `@upstash/ratelimit`). Especially critical for routes that call paid AI APIs (Gemini, OpenAI).

---

## INFO / Acceptable Findings

### 8. Supabase Service Role Key Usage — Properly Server-Side

The `SUPABASE_SERVICE_ROLE_KEY` is used in **digitalalchemy-dev** (scripts), **exo-spirit** (server.ts), and **collab-connect** (edge functions) — all server-side. No client-side exposure detected. This is correct usage.

### 9. No Committed Secrets

Searched for: `.env` files (non-example), `sk_live_`, `sk_test_`, `AKIA`, hardcoded API keys. **Zero real secrets found in any repo.** The only `.env` file is vibeaudit's own test fixture (intentional).

### 10. Good Security Patterns Observed

- **digitalalchemy-dev**: Zod env validation at startup, `.env.example` with placeholder values, service keys documented as server-only
- **content-drop**: Comprehensive env validation, `REQUIRED_IN_PROD` checklist, proper CLAUDE.md security guidelines
- **homiedex**: JSON-LD uses escaped content with explicit `biome-ignore` annotation
- **video-analyzer-70**: Uses `express-rate-limit` + configured CORS origin allowlist
- **epic-meitner**: CLAUDE.md includes detailed security guidelines (env discipline, webhook verification, RLS)
- **digitalalchemy-vibecode**: CORS uses regex allowlist, not wildcard
- **screenshot-pools**: CORS validates against `ALLOWED_ORIGINS` env var

### 11. Static HTML Repos — No Findings

~40 repos (shownotes1-6, landing pages, generators, show notes, etc.) are static HTML with no server-side code, API keys, or authentication. No security findings.

---

## Repos Not Scannable

The following repos had no language detected (empty or stub): `video2`, `chromtic-weaponizer`, `reminderapp`, `100DayAppChallenge`, `ai-agent-configs`, `AetherExWork`, `100-day-redo`, `alchemic-generator-v2`, `new-app`, `educational-resources`, `content-idea-generator34`, `notebooklm-mcp`, `awesome-nanobanana-pro`, `Super-Banana`, `Digital-Alchemy-Skool`, `fuzzy-octo-fishstick`, `literate-garbanzo`, `revenue-cat-contest`, `ansel`, `carol-c3-branding-starter`, `sierra-baker-starter`, `jacki-mundra-starter`.

---

## Priority Action Items

1. **[CRITICAL]** Move `NEXT_PUBLIC_GEMINI_API_KEY` to server-only in `digital-alchemy-os`
2. **[CRITICAL]** Set `httpOnly: true` on auth cookie in `1code-main`
3. **[HIGH]** Replace CORS `*` with domain allowlists in production-facing repos (especially `collab-connect`, `firecrawl-site-insight`, `stitch-alchemy`)
4. **[MEDIUM]** Add rate limiting to AI-proxying API routes (`screenshot-pools`, `100-day-app-challenge`)
5. **[MEDIUM]** Audit `dangerouslySetInnerHTML` usage in `ruby-feynman` and `1code-main` for XSS
6. **[LOW]** Re-enable CSRF protection in `digitalalchemy-vibecode` or document the risk acceptance

---

*Generated by VibeAudit cross-repo scan via GitHub Code Search API. Next scan scheduled for tomorrow morning.*
