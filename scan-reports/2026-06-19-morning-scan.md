# Vibe Audit - Morning Scan Report
**Date:** 2026-06-19 (Morning)
**Scope:** 161 repositories under `jackdog668`
**Scanner:** vibeaudit cross-repo code search (82 rules)

---

## Overall Grade: B+

Your repos are cleaner than most vibe-coded projects. No leaked API keys, no committed `.env` files, and RLS is enabled on every Supabase project. The main issue is **CORS wildcards** in 5 repos.

---

## Findings Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | Clean |
| Warning  | 8 | Action needed |
| Info     | 3 | Awareness |

---

## WARNING Findings

### 1. CORS Wildcard - `Access-Control-Allow-Origin: *` (5 repos)

Any website can call these APIs. If they handle authenticated requests or sensitive data, this is exploitable.

| Repo | File | Fix |
|------|------|-----|
| `stitch-alchemy` | `stitch-server.ts` | Replace `*` with your app's domain |
| `vibe-vocab` | `api/vocabulary.ts` | Replace `*` with your Vercel domain |
| `Chromatic-Illusion-Weaponizerr` | `server.js` | Replace `*` with allowed origins |
| `collab-connect` | `supabase/functions/send-opportunity-alert/index.ts` | Restrict to app domain |
| `collab-connect` | `supabase/functions/firecrawl-search/index.ts` | Restrict to app domain |
| `collab-connect` | `supabase/functions/firecrawl-scrape/index.ts` | Restrict to app domain |
| `firecrawl-site-insight` | `supabase/functions/firecrawl-map/index.ts` | Restrict to app domain |
| `firecrawl-site-insight` | `supabase/functions/firecrawl-analyze/index.ts` | Restrict to app domain |

**Good example:** `screenshot-pools` does this right - it checks `allowed.includes(origin)` before setting the header.

**Fix prompt for Claude Code / Cursor:**
```
Replace Access-Control-Allow-Origin: * with an allowlist of specific origins.
Use: const ALLOWED = ['https://myapp.com']; if (ALLOWED.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
```

### 2. Hardcoded PII - Admin Email in Source Code (1 repo)

| Repo | File | Issue |
|------|------|-------|
| `digitalalchemy-dev` | `src/lib/env.ts` | `desibaker54@gmail.com` hardcoded as default |
| `digitalalchemy-dev` | `src/app/admin/auth/callback/route.ts` | Same email as fallback |
| `digitalalchemy-dev` | `scripts/google-token-probe.ts` | Same email as fallback |

**Risk:** Email address baked into source code is PII exposure. If this repo ever goes public, the email is exposed permanently in git history.

**Fix:** Move to `.env.local` as `ADMIN_EMAIL=desibaker54@gmail.com` and remove all default fallbacks from code. The env validation already requires it - just remove the `.default()`.

### 3. Console.log Sensitive Data (1 repo)

| Repo | File | Issue |
|------|------|-------|
| `digitalalchemy-dev` | `scripts/google-token-probe.ts` | Logs token scope, expiry, refresh token presence |

**Risk:** Low (script-only, not production code), but if logs are shipped to a service, token metadata leaks.

---

## CLEAN Checks (No Issues Found)

| Check | Result | Notes |
|-------|--------|-------|
| Hardcoded API Keys | Clean | No `sk_live_`, `sk_test_`, `AIza`, `AKIA` patterns |
| Committed `.env` Files | Clean | No real secrets in committed env files |
| `eval()` in App Code | Clean | Only in vibeaudit's own rule definitions |
| `dangerouslySetInnerHTML` | Clean | Only in vibeaudit's own rule definitions |
| `exec()` / Command Injection | Clean | No shell exec with user input |
| localStorage Token Storage | Clean | No auth tokens in browser storage |
| SQL Injection | Clean | No string-concatenated queries |
| Supabase RLS | Enabled | All Supabase projects have RLS enabled |
| Service Role Key Exposure | Clean | All loaded from `process.env`, never hardcoded |
| Stripe Webhook Verification | Proper | `saas-starter` uses `STRIPE_WEBHOOK_SECRET` |
| Firebase Rules | Clean | No open database rules |
| Exposed `.env` Values | Clean | `.env.example` files use placeholder values |
| Docker Root User | N/A | No Dockerfiles in application repos |
| Exposed Database Ports | N/A | No docker-compose with port mappings |

---

## Repo Activity Snapshot

| Metric | Count |
|--------|-------|
| Total repos | 161 |
| With code (language detected) | ~120 |
| Public repos | 12 |
| Private repos | 149 |
| Repos with open issues | 4 (`homiedex`: 10, `grainrad-bulk`: 1, `digital-alchemy-bot`: 1, `100-day-app-challenge`: 1) |
| Most active (last 7 days) | `sierrabakerconsulting`, `a-silly-idea`, `da-library`, `content-drop` |

---

## Repos Scanned by Category

**Full-Stack Apps (Supabase):** `digitalalchemy-dev`, `exo-spirit`, `collab-connect`, `new-genny`, `content-drop`, `homiedex`
**Frontend/Landing Pages:** `sierrabakerconsulting`, `shownotes1-6`, `myfirstdeploy`, `percolator-class-guide`, `video-alchemy`, `qr-forge-pro`
**Tools/Utilities:** `vibeaudit`, `screenshot-pools`, `Agent-Factory`, `Siftly`, `vibe-tracker`, `magic-erase`, `da-video-tool`
**AI/API Projects:** `reddit-analyzer`, `biz-agent`, `IdeaToPRD-with-Gemini`, `firecrawl-site-insight`, `VIDEOANALYZERGOOGLE`
**Creative/Fun:** `sticker-banner-lab`, `Jiggle-Room`, `chibi-forge`, `LovePixel-Final`, `Petty-Translator`
**Course/Education:** `Digital-Alchemy-Skool`, `sec-context`, `vibe-vocab`, `chatgpt-data-analysis`
**SaaS Starters:** `saas-starter`, `Storefront`, `Skool-Forge`, `Digital-Alchemy-Command-Center`

---

## Recommendations (Priority Order)

1. **Fix CORS wildcards** in `stitch-alchemy`, `vibe-vocab`, `Chromatic-Illusion-Weaponizerr`, `collab-connect`, `firecrawl-site-insight` - replace `*` with specific origins
2. **Remove hardcoded email** from `digitalalchemy-dev` source code - move to env-only
3. **Run `npx vibe-audit`** locally on `homiedex` (10 open issues, most active private app) and `digitalalchemy-dev` (most complex codebase) for deep per-file analysis
4. **Consider** adding a `.vibe-audit.json` config to your top repos so future scans auto-run

---

*Generated by vibeaudit cross-repo scan | jackdog668 | 2026-06-19*
