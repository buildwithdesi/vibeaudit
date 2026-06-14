# Vibe Audit — Full Portfolio Scan

**Date:** 2026-06-14 (Saturday morning)
**Scope:** All 160 repositories under `jackdog668`
**Scanner:** Vibe Audit rules via GitHub Code Search (replaces DigitalOcean bot)
**Rules checked:** exposed-secrets, client-bundle-secrets, vercel-env-leak, missing-security-headers, missing-rate-limiting, no-account-lockout, eval-injection, open-cors, disabled-rls, command-injection, sql-injection, unverified-webhooks, missing-auth, insecure-connections, debug-mode

---

## Executive Summary

| Grade | Repos Scanned | Critical | Warning | Info |
|-------|--------------|----------|---------|------|
| **A-** | 160 | 1 | 2 | 3 |

Your portfolio is **clean**. One critical finding in a prototype repo, two warnings worth addressing in production apps, and otherwise strong security posture across the board. Your production-grade repos (`digitalalchemy-dev`, `content-drop`, `homiedex`, `saas-starter`) demonstrate excellent security practices.

---

## Critical Findings

### 1. `NEXT_PUBLIC_GEMINI_API_KEY` — API key exposed to browser
- **Repo:** `digital-alchemy-os`
- **File:** `src/lib/gemini.ts`
- **Severity:** CRITICAL
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **OWASP:** A01:2021 — Broken Access Control
- **Evidence:**
  ```ts
  const API_KEY = process.env.NEXT_PUBLIC_GEMINI_API_KEY || "";
  ```
- **Risk:** The `NEXT_PUBLIC_` prefix ships this value into the client JS bundle. Gemini API keys are **billable secrets** — anyone who views your page source can extract the key and run up charges on your Google Cloud account.
- **Fix:** Rename to `GEMINI_API_KEY` (drop the `NEXT_PUBLIC_` prefix). Create a server-side API route (`/api/gemini`) that proxies requests. Client calls your API route instead of Gemini directly.

---

## Warnings

### 2. Prototype/educational repos without `.gitignore`
- **Repos affected:** ~30+ small repos created during 100-Day Challenge and earlier experiments
- **Severity:** WARNING
- **Risk:** If anyone ever runs `git add .` in these repos with a `.env` file present, secrets could get committed. No `.env` files with real secrets are committed today — this is preventive.
- **Fix:** Add a basic `.gitignore` with `.env*` to repos you still actively develop.

### 3. Bookmarklet endpoint bypasses auth in Siftly
- **Repo:** `Siftly`
- **File:** `middleware.ts`
- **Severity:** WARNING (by design, documented)
- **Evidence:** "Let the bookmarklet endpoint through — it's called cross-origin from x.com and can't include Basic Auth credentials."
- **Risk:** The bookmarklet endpoint is intentionally unauthenticated. If this endpoint mutates data, it could be abused. Currently appears low-risk since Siftly uses optional env-based auth (`SIFTLY_USERNAME` / `SIFTLY_PASSWORD`).
- **Fix:** If Siftly ever goes multi-user, add token-based auth to the bookmarklet endpoint.

---

## Info / Observations

### 4. Security headers properly configured (6 repos)
The following repos have security headers correctly set up:
- `digitalalchemy-dev` — next.config.ts with hardened headers
- `chibi-forge` — next.config.mjs with security headers
- `IdeaToPRD-with-Gemini` — vercel.json with security headers
- `homiedex` — next.config.ts with security headers
- `epic-meitner` — vercel.json with X-Content-Type-Options, etc.
- `qr-forge-pro` — vercel.json with security headers

### 5. Rate limiting properly implemented (6 repos)
- `content-drop` — Upstash Ratelimit with per-user and IP-based limits
- `homiedex` — Upstash Ratelimit with sliding window
- `digitalalchemy-dev` — Rate limiting on payment, booking, and subscribe endpoints
- `video-analyzer-70` — express-rate-limit
- `Chromatic-Illusion-Weaponizerr` — express-rate-limit
- `digitalalchemy-vibecode` — Custom rate limit middleware (Hono)

### 6. Auth middleware properly configured (8 repos)
- `content-drop` — Clerk middleware with public/private route matching
- `digitalalchemy-dev` — Supabase auth, admin email verification, fail-closed
- `exo-spirit` — Supabase SSR auth with cookie handling
- `saas-starter` — Session-based auth with protected routes
- `Agent-Factory` — Security middleware with security headers
- `Digital-Alchemy-Command-Center` — LanGuard evaluation middleware
- `Siftly` — Optional Basic Auth via env vars
- `digitalalchemy-vibecode` — Auth middleware

---

## Checks That Passed (All Clean)

| Check | Result | Details |
|-------|--------|---------|
| Hardcoded secret tokens | ✅ PASS | No `sk-proj-`, `sk-live`, `AKIA`, `ghp_`, `gho_`, `glpat-`, `dop_v1_`, `xoxb-`, `xoxp-` found |
| Committed `.env` files | ✅ PASS | Only test fixtures (`vibeaudit/tests/fixtures/.env`) and templates (`epic-meitner/.env.template`) |
| `SUPABASE_SERVICE_ROLE_KEY` in client code | ✅ PASS | All service role key usage is server-side only |
| `STRIPE_SECRET_KEY` in client code | ✅ PASS | All Stripe secret usage is server-side only |
| `eval()` / `innerHTML` / `document.write()` | ✅ PASS | No unsafe DOM manipulation in production code |
| Command injection (`exec`, `spawn`) | ✅ PASS | No unsanitized command execution |
| Raw SQL / NoSQL injection | ✅ PASS | No raw SQL queries with user input |
| Open CORS with credentials | ✅ PASS | No `Access-Control-Allow-Origin: *` with `credentials: true` |
| Disabled Firestore RLS | ✅ PASS | Only in vibeaudit test fixtures (intentional) |
| Firebase admin key exposure | ✅ PASS | `chibi-forge` uses `FIREBASE_CLIENT_EMAIL` server-side correctly |
| Unverified webhooks | ✅ PASS | Webhook routes use proper auth patterns |
| Insecure connections | ✅ PASS | `http://` refs are only XML namespace URIs and URL format checks |
| Client-side pricing logic | ✅ PASS | Stripe/PayPal handled server-side in `digitalalchemy-dev` and `saas-starter` |
| Gemini API key (server-side) | ✅ PASS | `the-77` correctly uses `GEMINI_API_KEY` (not `NEXT_PUBLIC_`) |

---

## Portfolio Breakdown

| Category | Count | Notes |
|----------|-------|-------|
| Total repos | 160 | 33 public, 127 private |
| Production apps | ~8 | `digitalalchemy-dev`, `content-drop`, `homiedex`, `saas-starter`, `Storefront`, `Digital-Alchemy-Command-Center`, `Agent-Factory`, `exo-spirit` |
| Prototypes / educational | ~90 | 100-Day Challenge apps, Skool content, experiments |
| Static sites / content | ~40 | Show notes, landing pages, generators |
| Tools / utilities | ~15 | `vibeaudit`, `Siftly`, `da-video-tool`, `vibe-tracker`, etc. |
| Config / docs only | ~7 | `ai-agent-configs`, `educational-resources`, etc. |

---

## Recommendations

1. **Fix now:** Rotate the Gemini API key for `digital-alchemy-os` and move it server-side
2. **Low effort:** Add `.gitignore` with `.env*` to any actively-developed prototype repos
3. **Consider:** Archive repos from the 100-Day Challenge that you're no longer developing — reduces attack surface and scan noise
4. **Keep doing:** Your production repos show mature security patterns (Clerk auth, Upstash rate limiting, Zod validation, fail-closed middleware, security headers). This is above-average for vibe-coded projects.

---

*Scan powered by Vibe Audit security rules — https://github.com/jackdog668/vibeaudit*
*Next scan: tomorrow morning*
