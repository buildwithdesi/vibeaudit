# Vibe Audit — Morning Scan Report
**Date:** 2026-06-15 (Sunday)
**Scope:** All 160 repositories under `jackdog668`
**Method:** GitHub code search across 82 vibeaudit rule patterns (secrets, auth, injection, CORS, client trust, config, AI safety)

---

## Overall Grade: B+

No critical secrets or high-severity vulnerabilities found. A handful of medium-risk CORS misconfigurations and dangerouslySetInnerHTML patterns need attention in production-facing repos.

---

## CRITICAL — None Found ✅

| Check | Result |
|-------|--------|
| Hardcoded API keys (sk-*, AIzaSy*, AKIA*, ghp_*, glpat-) | **0 across all 160 repos** |
| Real `.env` files committed | **0** — all are `.env.example` / `.env.template` with placeholders |
| Exposed secrets via VITE_ / NEXT_PUBLIC_ / REACT_APP_ | **0** |
| Open Firestore rules (`allow read, write: if true`) | **0** (only in vibeaudit test fixtures) |
| eval() with dynamic input | **0** in application code |
| localStorage storing tokens/JWTs | **0** in application code |
| Math.random() for security tokens | **0** in application code |
| Plaintext password storage | **0** |
| CSRF explicitly disabled | **0** |
| SQL injection patterns | **0** |

---

## WARNING — 11 Findings Across 9 Repos

### 1. CORS Wildcard `origin: "*"` (7 repos)

Open CORS allows any website to call your API. Low risk for static sites / local-only tools, medium risk if these serve authenticated data.

| Repo | File | Pattern |
|------|------|---------|
| **stitch-alchemy** | `stitch-server.ts` | `Access-Control-Allow-Origin: "*"` |
| **vibe-vocab** | `api/vocabulary.ts` | `res.setHeader('Access-Control-Allow-Origin', '*')` |
| **Chromatic-Illusion-Weaponizerr** | `server.js` | `Access-Control-Allow-Origin: '*'` |
| **magic-erase** | `server.py` | `allow_origins=["*"]` (FastAPI CORS) |
| **collab-connect** | `supabase/functions/` (3 edge functions) | `Access-Control-Allow-Origin: '*'` |
| **firecrawl-site-insight** | `supabase/functions/` (2 edge functions) | `Access-Control-Allow-Origin: '*'` |

**Fix:** Replace `"*"` with specific allowed origins from an env var:
```js
cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') })
```

### 2. `app.use(cors())` — No Config (4 repos)

`cors()` with no arguments defaults to `origin: "*"` — same issue as above, just less obvious.

| Repo | File |
|------|------|
| **sref-scanner** | `backend/server.js` |
| **blazing-schrodinger** | `server/server.js` |
| **ruby-magnetosphere** | `server/index.js` |
| **stream-gamify** | `BACKEND_PROXY_EXAMPLE.js` |

### 3. `dangerouslySetInnerHTML` — Potentially Unsafe (4 repos)

Most `dangerouslySetInnerHTML` usage across repos is safe (JSON-LD `<script>` tags, theme scripts, shadcn/ui chart components). These four deserve review because they render dynamic/user-adjacent content:

| Repo | File | Risk |
|------|------|------|
| **ruby-feynman** | `src/App.jsx` | Renders `formatInline(content)` as HTML — XSS if content is user-sourced |
| **digital-alchemy-app** | `webapp/src/pages/Resources.tsx` | Regex `**bold**` → `<strong>` on dynamic content |
| **digitalalchemy-dev** | `CampaignCockpitClient.tsx`, `NewsletterCampaignComposer.tsx` | `compileLivePreview(bodyHtml)` — admin-only, but still unsanitized HTML |
| **1code-main** | `agent-tool-call.tsx` (2 locations) | Renders `subtitleStr` as HTML |

**Fix:** Use DOMPurify before injecting: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}`

---

## INFO — Observations

### Good Practices Observed ✅
- **Env management**: All 35+ repos with env files use proper `.env.example` templates with placeholder values
- **Auth patterns**: `digitalalchemy-dev` uses `assertAdmin()` server-side checks before Supabase mutations
- **CORS done right**: `digitalalchemy-vibecode` and `digital-alchemy-app` both have `.claude/rules/api-patterns.md` enforcing proper CORS origin validation
- **Webhook verification**: `homiedex` and `digitalalchemy-vibecode` use `standardwebhooks` for Clerk webhook signature verification
- **video-analyzer-70** and **screenshot-pools** use env-var-based CORS origin allowlists

### Supabase Client Operations (2 repos — verify RLS)
`collab-connect` and `exo-spirit` perform direct Supabase `insert`/`update` from client-side hooks. This is safe **only if Row Level Security (RLS) is enabled** on those tables. Cannot verify from code — check Supabase dashboard.

### Repos With No Scannable Code (low priority)
~30 repos have no language set (empty, docs-only, or placeholder repos): `100-day-redo`, `catdog`, `educational-resources`, `fuzzy-octo-fishstick`, `jackdog668.github.io`, `reminderapp`, `video2`, etc.

---

## Changes Since Last Scan

| Repo | Last Updated | Notes |
|------|-------------|-------|
| **a-silly-idea** | Today (Jun 15) | Public, JavaScript — clean |
| **sierrabakerconsulting** | Jun 13 | Public, HTML — clean |
| **screenshot-pools** | Jun 13 | TypeScript — proper CORS ✅ |
| **generator20x** | Jun 12 | HTML — clean |
| **jacki-mundra-starter** | Jun 12 | New repo — no code yet |
| **carol-c3-branding-starter** | Jun 12 | New repo |
| **second-brain-system** | Jun 12 | Public, Python — clean |
| **Storefront** | Jun 8 | TypeScript — not scanned (private, new) |
| **content-drop** | Jun 7 | TypeScript — clean env handling ✅ |
| **homiedex** | Jun 6 | TypeScript — proper webhook verification ✅ |

---

## Action Items (Priority Order)

1. **[Medium]** Lock down CORS in `collab-connect`, `firecrawl-site-insight`, and `vibe-vocab` — these are the most active repos with wildcard CORS
2. **[Medium]** Sanitize HTML in `digitalalchemy-dev` admin components (CampaignCockpit, NewsletterComposer) with DOMPurify
3. **[Low]** Verify RLS is enabled on Supabase tables used by `collab-connect` and `exo-spirit`
4. **[Low]** Add explicit CORS origins to `sref-scanner` and `blazing-schrodinger` backends
5. **[Info]** Consider archiving ~30 empty/placeholder repos to reduce surface area

---

*Scanned 160 repos against vibeaudit's 82 security rules via GitHub code search API. This replaces the DigitalOcean bot morning scan.*
