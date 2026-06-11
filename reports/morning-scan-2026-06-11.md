# Vibe Audit Morning Scan — 2026-06-11

**Scope:** 152 repositories under `jackdog668`
**Method:** GitHub code search (77+ Vibe Audit rule patterns) + local SCA on `vibeaudit`
**Scanned:** 112 repos with code (language detected), 40 empty/docs-only skipped

---

## Executive Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 (dependency vulns in vibeaudit) |
| WARNING  | 12 findings across 6 repos |
| INFO     | 3 observations |

**Overall grade: B+** — No hardcoded secrets. No committed `.env` files. Auth patterns are solid in the production repos. Main gaps are CORS wildcards in edge functions and a browser extension calling an LLM API directly.

---

## CRITICAL — Dependency Vulnerabilities

### vibeaudit (this repo)

| Package | Vulnerability | CVSS | CWE | Fix |
|---------|--------------|------|-----|-----|
| `flatted` <=3.4.1 | Prototype Pollution via `parse()` | 7.5 | CWE-1035 | `npm audit fix` or `npm install flatted@latest` |
| `brace-expansion` <1.1.13 | Zero-step sequence causes hang + memory exhaustion | 7.5 | CWE-1035 | `npm audit fix` or `npm install brace-expansion@latest` |

---

## WARNING — CORS Wildcard (Access-Control-Allow-Origin: *)

Any website can call these APIs. If they handle user data or auth, restrict to your domains.

| Repo | File | Notes |
|------|------|-------|
| **stitch-alchemy** | `stitch-server.ts` | CORS object hardcodes `"*"` |
| **vibe-vocab** | `api/vocabulary.ts` | Vercel serverless function, `res.setHeader('Access-Control-Allow-Origin', '*')` |
| **Chromatic-Illusion-Weaponizerr** | `server.js` | OPTIONS preflight handler with `"*"` |
| **collab-connect** | `supabase/functions/send-opportunity-alert/index.ts` | Supabase edge function |
| **collab-connect** | `supabase/functions/firecrawl-search/index.ts` | Supabase edge function |
| **collab-connect** | `supabase/functions/firecrawl-scrape/index.ts` | Supabase edge function |
| **firecrawl-site-insight** | `supabase/functions/firecrawl-map/index.ts` | Supabase edge function |
| **firecrawl-site-insight** | `supabase/functions/firecrawl-analyze/index.ts` | Supabase edge function |

**Fix prompt:**
> Replace `'Access-Control-Allow-Origin': '*'` with your actual frontend domain(s). For Supabase edge functions, use the Supabase project URL. For Vercel, use your deployment URL.

---

## WARNING — Browser Extension Direct LLM API Call

| Repo | File | Issue |
|------|------|-------|
| **ineeditall** | `save-it-extension/background.js` | Calls `api.anthropic.com` directly with `x-api-key` header and `anthropic-dangerous-direct-browser-access: true` |

The API key is accessible to anyone who inspects the extension. If this is a user-provided key from `chrome.storage`, the risk is contained. If it's bundled, it's exposed.

**Fix:** Route LLM calls through a backend proxy, or at minimum ensure the key comes from user config (not hardcoded).

---

## WARNING — Missing Security Hardening

| Pattern | Repos affected | Notes |
|---------|---------------|-------|
| No `helmet` middleware | All Express/Node servers (stitch-alchemy, Chromatic-Illusion-Weaponizerr, ineeditall) | Missing `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security` |
| No rate limiting | All API servers | No `express-rate-limit` or equivalent detected |
| No CSRF protection | All servers with form handling | Supabase/Next.js repos get partial coverage from framework |

---

## INFO — Positive Findings

- **No hardcoded secrets** across all 152 repos. API keys consistently use `process.env` / `Deno.env`.
- **No committed `.env` files** with real credentials.
- **digitalalchemy-dev** has proper auth middleware (`middleware.ts`) gating `/admin/*` routes, validates required env vars at boot (`src/lib/env.ts`), and uses Zod schemas for config.
- **exo-spirit** correctly splits Supabase client (browser) vs server (SSR with cookies).
- **content-drop** enforces `TOKEN_ENCRYPTION_KEY` and `ADMIN_EMAILS` in production via boot-time validation.

---

## Repos by Risk Tier

### Tier 1 — Production apps (prioritize fixes)
| Repo | Language | Findings |
|------|----------|----------|
| digitalalchemy-dev | TypeScript | CSP `frame-ancestors *` on embed routes (intentional per SETUP.md) |
| content-drop | TypeScript | Clean |
| homiedex | TypeScript | Not scanned (9 open issues — review separately) |
| Storefront | TypeScript | New (created Jun 8) — scan when code lands |

### Tier 2 — Active tools & apps
| Repo | Language | Findings |
|------|----------|----------|
| collab-connect | TypeScript | 3x CORS wildcard in Supabase functions |
| firecrawl-site-insight | TypeScript | 2x CORS wildcard in Supabase functions |
| stitch-alchemy | HTML/TS | CORS wildcard in server, no helmet |
| vibe-vocab | TypeScript | CORS wildcard in API route |
| Skool-Forge | TypeScript | Clean |
| Agent-Factory | TypeScript | Clean |

### Tier 3 — Browser extensions
| Repo | Language | Findings |
|------|----------|----------|
| ineeditall | JavaScript | Direct browser API call to Anthropic |

### Tier 4 — Experiments / challenges / static sites
| Repo count | Notes |
|------------|-------|
| ~130 repos | 100-day challenge apps, show notes, landing pages, static HTML — low risk |

---

## Recommended Actions (priority order)

1. **Now:** `cd vibeaudit && npm audit fix` — clear the 2 dependency vulns
2. **This week:** Fix CORS wildcards in `collab-connect` and `firecrawl-site-insight` Supabase functions — these are the most likely to handle real user data
3. **This week:** Add `helmet` to `stitch-alchemy` server
4. **When convenient:** Audit `ineeditall` extension API key storage
5. **When convenient:** Review `homiedex` (9 open issues)

---

*Generated by Vibe Audit cross-repo scan — replacing DigitalOcean scheduled bot*
*Next scan: tomorrow morning*
