# Vibe Audit Cross-Repo Security Scan

**Date:** 2026-06-18 (automated morning scan)
**Scanner:** vibeaudit v1.1.0 + GitHub code search (79 rules)
**Scope:** 161 repositories under `jackdog668`
**Method:** GitHub code search across all repos for vibeaudit rule patterns

---

## Executive Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 2 | Needs immediate fix |
| WARNING  | 12 | Should fix before shipping |
| INFO     | 3 | Low risk / expected patterns |
| CLEAN    | vibeaudit repo | 0 findings, 80 rules, 16 files |

---

## CRITICAL Findings

### 1. Client-Side API Key Exposure — `digital-alchemy-os`

**Rule:** `client-bundle-secrets` / `exposed-env-vars` / `ai-cost-exposure`
**File:** `src/lib/gemini.ts`

```typescript
const API_KEY = process.env.NEXT_PUBLIC_GEMINI_API_KEY || "";
```

`NEXT_PUBLIC_` vars are inlined into the client JS bundle at build time. Anyone opening DevTools > Sources can extract this Gemini API key and make calls on your account. This is a direct cost-exposure and credential-leak vulnerability.

**Fix:** Move the Gemini call behind a Next.js API route (`/api/gemini`) and use a server-only env var (`GEMINI_API_KEY` without the `NEXT_PUBLIC_` prefix). The client calls your API route; your server calls Gemini.

---

### 2. Client-Side API Key Exposure — `100-day-app-challenge`

**Rule:** `client-bundle-secrets` / `ai-cost-exposure`
**Files:** `src/app/index.tsx`, `src/components/IdeaChat.tsx`

```typescript
const apiKey = process.env.EXPO_PUBLIC_VIBECODE_ALPHA_VANTAGE_API_KEY;
// ...
Authorization: `Bearer ${process.env.EXPO_PUBLIC_VIBECODE_OPENAI_API_KEY}`,
```

Both an OpenAI API key and an Alpha Vantage key are exposed via `EXPO_PUBLIC_` env vars, which are bundled into the mobile app binary. Anyone who decompiles the app (or inspects network traffic) gets both keys.

**Fix:** Create a backend API proxy (Vercel serverless function, Supabase Edge Function, or Express server). The mobile app calls your proxy; the proxy calls OpenAI/Alpha Vantage with server-side keys.

---

## WARNING Findings

### 3. CORS Wildcard `Access-Control-Allow-Origin: *` — 7 repos

Any website can call these APIs. If they handle authenticated data, this is exploitable.

| Repo | File | Pattern |
|------|------|---------|
| **stitch-alchemy** | `stitch-server.ts` | `"Access-Control-Allow-Origin": "*"` |
| **vibe-vocab** | `api/vocabulary.ts` | `res.setHeader('Access-Control-Allow-Origin', '*')` |
| **Chromatic-Illusion-Weaponizerr** | `server.js` | `res.setHeader('Access-Control-Allow-Origin', '*')` |
| **collab-connect** | `supabase/functions/send-opportunity-alert/index.ts` | `"Access-Control-Allow-Origin": "*"` |
| **collab-connect** | `supabase/functions/firecrawl-scrape/index.ts` | `"Access-Control-Allow-Origin": "*"` |
| **collab-connect** | `supabase/functions/firecrawl-search/index.ts` | `"Access-Control-Allow-Origin": "*"` |
| **firecrawl-site-insight** | `supabase/functions/firecrawl-map/index.ts` | `"Access-Control-Allow-Origin": "*"` |
| **firecrawl-site-insight** | `supabase/functions/firecrawl-analyze/index.ts` | `"Access-Control-Allow-Origin": "*"` |
| **magic-erase** | `server.py` | `allow_origins=["*"]` |
| **sref-scanner** | `backend/server.js` | `app.use(cors())` (defaults to `*`) |

**Fix:** Replace `*` with your actual domain(s). For Supabase edge functions, check that these are only called from your frontend origin.

---

### 4. `dangerouslySetInnerHTML` with External/Dynamic Data — 5+ repos

Using `dangerouslySetInnerHTML` with content that isn't fully sanitized opens XSS vectors.

| Repo | File | Risk Level |
|------|------|------------|
| **ruby-feynman** | `src/App.jsx` | HIGH — renders `formatInline(content)` and `formatInline(line)` as raw HTML from parsed text |
| **da-library** | `src/components/library-browser.tsx` | MEDIUM — renders search `highlight(h.snippet)` as HTML |
| **1code-main** | `src/renderer/features/ui/agent-tool-call.tsx` | MEDIUM — renders `subtitleStr` as HTML |
| **1code-main** | `src/renderer/components/chat-markdown-renderer.tsx` | MEDIUM — renders `htmlContent` from markdown |
| **digital-alchemy-app** | `webapp/src/pages/Resources.tsx` | MEDIUM — regex-based markdown-to-HTML conversion |
| **digitalalchemy-dev** | `src/app/admin/freebies/CampaignCockpitClient.tsx` | LOW — admin-only email preview |
| **digitalalchemy-dev** | `src/app/admin/newsletter/NewsletterCampaignComposer.tsx` | LOW — admin-only email preview |

**Fix:** Use DOMPurify or a similar sanitizer: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}`. For JSON-LD and theme scripts with static strings, the existing usage is safe.

---

### 5. Supabase Edge Functions Missing Auth Checks

The Supabase edge functions in **collab-connect** and **firecrawl-site-insight** have CORS `*` and may lack per-request auth verification beyond the Supabase anon key. Verify that RLS policies are enforced on the underlying tables.

---

## INFO Findings

### 6. Firebase Client Config in `chibi-forge`

`src/lib/firebase.js` exposes Firebase config via `NEXT_PUBLIC_` vars. This is by design (Firebase client SDK requires it), but ensure Firestore Security Rules and Storage Rules restrict access properly.

### 7. Safe `dangerouslySetInnerHTML` Usage (no action needed)

Several repos use `dangerouslySetInnerHTML` safely for static/escaped content:
- Theme anti-flash scripts (Siftly, content-drop, Digital-Alchemy-Command-Center)
- JSON-LD structured data (homiedex, digitalalchemy-dev)
- Chart CSS injection (shadcn chart.tsx in multiple repos)

### 8. Well-Structured Security Patterns Observed

Several repos demonstrate good practices:
- **homiedex**: Rate limiting (`rate-limit.ts`), admin guard (`guard.ts`), URL allowlist, profanity filter, env validation
- **content-drop**: Clerk auth (`api-auth.ts`), token encryption (`crypto.ts`), env validation, job concurrency limits
- **digitalalchemy-dev**: Zod env parsing, Supabase service role kept server-side, PostHog key properly public

---

## Scan Limitations

| Limitation | Impact |
|-----------|--------|
| No `GITHUB_TOKEN` in environment | Could not run full vibeaudit scans via GitHub API (rate limited at 60 req/hr) |
| MCP tools restricted to `vibeaudit` repo | Could not fetch private repo file contents for deep analysis |
| GitHub code search used instead | Pattern matching across all repos; may miss context-dependent issues |
| ~150 private repos | Searched via code search (works across all repos) but could not run full 80-rule vibeaudit scans |

---

## Setup Recommendations for Full Automated Scanning

To run a complete vibeaudit scan across all 161 repos:

1. **Add `GITHUB_TOKEN`** to the routine environment (Settings > Environment Variables)
2. **Broaden repo scope** to include all `jackdog668/*` repos in the session
3. vibeaudit can then scan each repo directly: `npx vibe-audit jackdog668/repo-name --format json`
4. Consider adding vibeaudit to CI: `npx vibe-audit --format json --strict` in GitHub Actions

---

## Top 3 Action Items

1. **TODAY** — Remove `NEXT_PUBLIC_` prefix from Gemini API key in `digital-alchemy-os` and proxy through server route
2. **TODAY** — Move OpenAI/Alpha Vantage keys behind API proxy in `100-day-app-challenge`
3. **THIS WEEK** — Restrict CORS origins in production Supabase edge functions (collab-connect, firecrawl-site-insight)

---

*Generated by vibeaudit + GitHub code search. 161 repos scanned. 79 security rules evaluated via pattern matching.*
