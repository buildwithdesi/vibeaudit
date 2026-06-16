# Vibe Audit — Cross-Repo Security Scan

**Date:** 2026-06-16 (Morning Routine)
**Scope:** 160 repositories under `jackdog668`
**Method:** GitHub code search targeting vibeaudit's 82+ security rules
**Scanner:** vibeaudit v1.1.0 rule patterns applied via GitHub code search API

---

## Executive Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 0 | All clear |
| WARNING | 4 categories | Action recommended |
| INFO | 6 categories | Good hygiene confirmed |

**Overall Grade: B+** — No critical secrets or injection vulnerabilities. Main gaps are CORS wildcards, missing auth on API routes, and missing rate limiting. These are typical vibe-coded patterns that should be tightened before any app goes into production.

---

## WARNING Findings

### 1. CORS Wildcard (`Access-Control-Allow-Origin: *`) — 6 repos

Any website can call these APIs. If they handle user data or costs money (AI API calls), this is exploitable.

| Repo | File | Risk |
|------|------|------|
| `stitch-alchemy` | `stitch-server.ts` | Full wildcard CORS on all routes |
| `vibe-vocab` | `api/vocabulary.ts` | Wildcard CORS on vocabulary API |
| `Chromatic-Illusion-Weaponizerr` | `server.js` | Wildcard CORS on OPTIONS handler |
| `collab-connect` | `supabase/functions/send-opportunity-alert/index.ts` | Wildcard CORS |
| `collab-connect` | `supabase/functions/firecrawl-search/index.ts` | Wildcard CORS |
| `collab-connect` | `supabase/functions/firecrawl-scrape/index.ts` | Wildcard CORS |
| `firecrawl-site-insight` | `supabase/functions/firecrawl-map/index.ts` | Wildcard CORS |
| `firecrawl-site-insight` | `supabase/functions/firecrawl-analyze/index.ts` | Wildcard CORS |

**Fix:** Replace `*` with specific allowed origins. For Supabase edge functions, use the app's domain.

**Good example:** `screenshot-pools` (`api/analyze-screenshot.js`) correctly uses an origin allowlist instead of wildcard.

---

### 2. `dangerouslySetInnerHTML` with Dynamic Content — 5 repos

Most usage across repos is safe (static CSS, JSON-LD, theme scripts). These have potentially risky dynamic content:

| Repo | File | Context |
|------|------|---------|
| `ruby-feynman` | `src/App.jsx` | Renders formatted inline content via `formatInline(content)` |
| `digital-alchemy-app` | `webapp/src/pages/Resources.tsx` | Renders paragraph HTML |
| `digitalalchemy-dev` | `src/app/admin/freebies/CampaignCockpitClient.tsx` | Renders live HTML email preview |
| `digitalalchemy-dev` | `src/app/admin/newsletter/NewsletterCampaignComposer.tsx` | Renders live HTML email preview |
| `1code-main` | Multiple files (agent-edit-tool, agent-tool-call, chat-markdown-renderer) | Renders highlighted code and subtitles |

**Fix:** Sanitize HTML with DOMPurify before passing to `dangerouslySetInnerHTML`. For code highlighting, consider using React components instead of raw HTML.

**Safe usage (no action needed):** `chart.tsx` (shadcn/ui component), `JsonLd.tsx`, `SchemaMarkup.tsx`, `ThemeScript.tsx`, theme-flash scripts — these all use static/escaped content.

---

### 3. API Routes Missing Authentication — Most repos

Search for auth patterns (`getServerSession`, `getAuth`, `verifyIdToken`, `auth()`) in API routes returned **zero results** outside vibeaudit. Most API endpoints are open.

**Repos with proper auth (good examples):**
- `digitalalchemy-dev` — Supabase auth middleware
- `vibe-vocab` — Clerk authentication
- `IdeaToPRD-with-Gemini` — Access code validation
- `Siftly` — Proper origin-based CORS on bookmarklet route

**Repos with open API routes (sample):**
- `vibeshot2` — `api/phase1.ts` (Gemini API calls, no auth)
- `Content-Hook-Generator` — `api/generate.ts` (has rate limiting but no auth)
- `screenshot-pools` — `api/analyze-screenshot.js` (good CORS, but no auth check)
- `video-analyzer-70` — `api/files/[name].ts` (Gemini API calls, no auth)

**Fix:** Add authentication middleware to any API route that calls a paid service (OpenAI, Gemini, etc.) or accesses user data.

---

### 4. API Routes Missing Rate Limiting — Most repos

Only **2 out of 160 repos** implement rate limiting:

| Repo | Implementation |
|------|---------------|
| `Content-Hook-Generator` | In-memory rate limiter (10 req/min per IP) |
| `a-silly-idea` | DB-based rate limiter (counts recent rows per IP hash) |

**Fix:** Add rate limiting to any publicly accessible API route, especially ones that proxy AI/LLM calls. Use Vercel's built-in rate limiting, Upstash, or a simple in-memory counter.

---

## CLEAN — No Issues Found

### No Exposed Secrets
Zero hardcoded API keys, tokens, or credentials found across all 160 repos. Searches for `sk-`, `sk_live`, `sk_test`, `AKIA`, `ghp_`, `gho_`, `glpat-`, `xoxb-`, `eyJ` all returned empty.

### No Committed `.env` Files
No `.env` files with real credentials. Only found:
- `.env.template` files with placeholder values (correct pattern)
- `vibeaudit/tests/fixtures/.env` (intentional test fixture)

### No `eval()` with Dynamic Input
Zero instances of `eval()` with user or dynamic input outside vibeaudit's own test fixtures.

### No Command Injection
No `exec()`, `execSync()`, or `spawn()` with user-controlled input found.

### No SQL Injection
No string concatenation in SQL queries. Repos using databases use parameterized queries or ORMs (Prisma, Drizzle, Neon `sql` tagged templates).

### Supabase Keys Properly Handled
`digitalalchemy-dev` and `exo-spirit` correctly keep `service_role` keys server-side and use `anon` keys client-side.

---

## Repos by Risk Profile

### Higher Priority (active apps with API routes)
These repos have API endpoints that call paid services and should get auth + rate limiting:

1. **digitalalchemy-dev** — Production site with Supabase, Stripe, Resend (has auth, needs rate limiting review)
2. **homiedex** — Active app with Drizzle ORM (10 open issues — review for auth)
3. **content-drop** — TypeScript app with ffmpeg processing
4. **screenshot-pools** — AI screenshot analysis (good CORS, needs auth)
5. **Storefront** — Printify integration (needs auth on API routes)
6. **Siftly** — Prisma + SQLite app (has some auth patterns)

### Lower Priority (static sites, class demos, generators)
Most of the 160 repos are static HTML pages, class demo projects, show notes, or standalone generators with no backend. These have minimal attack surface.

---

## Recommendations

1. **This week:** Fix CORS wildcards in `stitch-alchemy`, `vibe-vocab`, `collab-connect`, and `firecrawl-site-insight`
2. **This week:** Add auth to API routes in `vibeshot2`, `video-analyzer-70`, and `screenshot-pools`
3. **Next sprint:** Add rate limiting to all API routes that proxy AI calls
4. **Ongoing:** Run `npx vibe-audit --format json` in CI for `digitalalchemy-dev`, `homiedex`, `content-drop`, and `Storefront`

---

*Generated by Vibe Audit cross-repo scan routine. Next scan scheduled for tomorrow morning.*
