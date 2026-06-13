# Vibe Audit — Morning Security Scan Report

**Date:** 2026-06-13 at 09:19 AM  
**Scanner:** Vibe Audit v1.1.0 (82 rules, 8 attack surfaces)  
**Scope:** 11 public repos | 149 private repos (skipped — no GITHUB_TOKEN)  
**Owner:** jackdog668 (Digital Alchemy)  

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Repos scanned | 11 |
| Total findings | 116 |
| Critical | 59 |
| Warnings | 56 |
| Clean repos | 3 |

## Repo Scorecard

| Repo | Grade | Critical | Warning | Total | Top Issue |
|------|-------|----------|---------|-------|-----------|
| Siftly | F | 37 | 42 | 80 | missing-auth |
| vibe-vocab | F | 8 | 3 | 11 | client-bundle-secrets |
| a-silly-idea | D | 4 | 4 | 8 | missing-gitignore |
| second-brain-system | D | 4 | 1 | 5 | missing-gitignore |
| sierrabakerconsulting | D | 4 | 4 | 8 | missing-gitignore |
| vibe-tracker | C | 2 | 0 | 2 | no-input-validation |
| da-video-tool | B | 0 | 1 | 1 | missing-security-headers |
| myfirstdeploy | B | 0 | 1 | 1 | missing-gitignore |
| percolator-class-guide | A | 0 | 0 | 0 | None |
| photo-organizer-da | A | 0 | 0 | 0 | None |
| vibeaudit | A | 0 | 0 | 0 | None |

---

## Detailed Findings

### Siftly — Grade F

**CRITICAL (37):**

- **missing-auth** (31 instances):
  - `images/route.ts:8` — Exported GET handler has no authentication check.
  - `images/route.ts:17` — Exported POST handler has no authentication check.
  - `categories/route.ts:5` — Exported PUT handler has no authentication check.
  - `bookmarks/route.ts:14` — Exported DELETE handler has no authentication check.
  - `bookmarks/route.ts:33` — Exported GET handler has no authentication check.
  - ...and 26 more
- **race-condition** (2 instances):
  - `categories/route.ts:84` — Find-then-create race condition (possible duplicate) — concurrent requests can cause inconsistency.
  - `import/route.ts:74` — Check-then-update on balance/inventory without lock — concurrent requests can cause inconsistency.
- **unsafe-file-upload** at `import/route.ts:5` — Function "POST" handles file uploads without type/size validation in scope.
- **no-input-validation** at `app/layout.tsx:27` — dangerouslySetInnerHTML — potential XSS vector
- **dangerously-set-inner-html** at `app/layout.tsx:27` — dangerouslySetInnerHTML used without sanitization — XSS vulnerability.
- **nextjs-middleware-bypass** at `middleware.ts:1` — Middleware file contains no authentication or redirect logic.

**WARNINGS (42):**

- **missing-gitignore**: 1 instance(s)
- **api-data-overfetch**: 12 instance(s)
- **missing-csrf**: 17 instance(s)
- **no-pagination**: 1 instance(s)
- **insecure-error-handling**: 7 instance(s)
- **console-data-leak**: 1 instance(s)
- **missing-security-headers**: 2 instance(s)
- **clickjacking**: 1 instance(s)

---

### vibe-vocab — Grade F

**CRITICAL (8):**

- **client-bundle-secrets** (7 instances):
  - `src/App.tsx:21` — Secret env var referenced in client code — visible in DevTools Sources: import.meta.env.VITE_CLERK_P
  - `src/App.tsx:40` — Secret env var referenced in client code — visible in DevTools Sources: import.meta.env.VITE_CLERK_P
  - `src/App.tsx:75` — Secret env var referenced in client code — visible in DevTools Sources: import.meta.env.VITE_CLERK_P
  - `components/AuthProvider.tsx:4` — Secret env var referenced in client code — visible in DevTools Sources: import.meta.env.VITE_CLERK_P
  - `components/Header.tsx:232` — Secret env var referenced in client code — visible in DevTools Sources: import.meta.env.VITE_CLERK_P
  - ...and 2 more
- **exposed-env-vars** at `lib/db.ts:5` — "VITE_DATABASE_URL" exposes a secret to the browser. The VITE_ prefix makes this variable public in your build output.

**WARNINGS (3):**

- **insecure-connections**: 1 instance(s)
- **no-pagination**: 1 instance(s)
- **missing-security-headers**: 1 instance(s)

---

### a-silly-idea — Grade D

**CRITICAL (4):**

- **missing-gitignore** (4 instances):
  - `.gitignore:1` — ".env" (Environment variables file) is not in .gitignore — will be committed to git.
  - `.gitignore:1` — ".env.local" (Local environment overrides) is not in .gitignore — will be committed to git.
  - `.gitignore:1` — ".env.production" (Production secrets) is not in .gitignore — will be committed to git.
  - `.gitignore:1` — ".env.development" (Development secrets) is not in .gitignore — will be committed to git.

**WARNINGS (4):**

- **insecure-error-handling**: 2 instance(s)
- **insecure-connections**: 2 instance(s)

---

### second-brain-system — Grade D

**CRITICAL (4):**

- **missing-gitignore** (4 instances):
  - `.gitignore:1` — ".env" (Environment variables file) is not in .gitignore — will be committed to git.
  - `.gitignore:1` — ".env.local" (Local environment overrides) is not in .gitignore — will be committed to git.
  - `.gitignore:1` — ".env.production" (Production secrets) is not in .gitignore — will be committed to git.
  - `.gitignore:1` — ".env.development" (Development secrets) is not in .gitignore — will be committed to git.

**WARNINGS (1):**

- **missing-gitignore**: 1 instance(s)

---

### sierrabakerconsulting — Grade D

**CRITICAL (4):**

- **missing-gitignore** (4 instances):
  - `.gitignore:1` — ".env" (Environment variables file) is not in .gitignore — will be committed to git.
  - `.gitignore:1` — ".env.local" (Local environment overrides) is not in .gitignore — will be committed to git.
  - `.gitignore:1` — ".env.production" (Production secrets) is not in .gitignore — will be committed to git.
  - `.gitignore:1` — ".env.development" (Development secrets) is not in .gitignore — will be committed to git.

**WARNINGS (4):**

- **missing-gitignore**: 2 instance(s)
- **missing-security-headers**: 1 instance(s)
- **deployment-config-insecure**: 1 instance(s)

---

### vibe-tracker — Grade C

**CRITICAL (2):**

- **no-input-validation** (2 instances):
  - `js/history.js:28` — Direct innerHTML assignment — potential XSS vector
  - `js/history.js:37` — Direct innerHTML assignment — potential XSS vector

---

### da-video-tool — Grade B

**WARNINGS (1):**

- **missing-security-headers**: 1 instance(s)

---

### myfirstdeploy — Grade B

**WARNINGS (1):**

- **missing-gitignore**: 1 instance(s)

---

## Priority Fix List

These are the highest-impact issues to address first:

1. **Siftly** — 37 API routes with NO authentication. Any endpoint is callable by anyone. Add auth middleware immediately.
2. **vibe-vocab** — Database URL exposed via `VITE_DATABASE_URL` prefix (ships to browser bundle). Move to server-side env var.
3. **vibe-tracker** — innerHTML XSS vectors in history.js. Use `textContent` or sanitize input.
4. **a-silly-idea / second-brain-system / sierrabakerconsulting** — Missing `.env` in `.gitignore`. Secrets will be committed.
5. **Siftly** — `dangerouslySetInnerHTML` in layout.tsx without sanitization.
6. **vibe-vocab** — CORS `Access-Control-Allow-Origin: *` on API with database access.
7. **Siftly** — Missing security headers (CSP, HSTS, X-Frame-Options) in both middleware and next.config.

## Private Repos (149 — Not Scanned)

To scan private repos, set the `GITHUB_TOKEN` environment variable:

```bash
export GITHUB_TOKEN=ghp_your_token_here
node bin/vibe-audit.js jackdog668/repo-name --format json
```

Key private repos that should be prioritized for scanning:

- **Storefront** (TypeScript, recent activity) — likely handles payments
- **homiedex** (TypeScript, 9 open issues) — active development
- **digitalalchemy-dev** (TypeScript, recent) — main platform
- **Agent-Factory** (TypeScript) — Claude Code management
- **content-drop** (TypeScript, recent) — active development
- **Digital-Alchemy-Command-Center** (TypeScript) — dashboard with analytics
- **saas-starter** (Next.js + Stripe) — payments/auth surface
- **digital-alchemy-bot** (JavaScript, 1 open issue) — bot with external access

---

*Generated by [Vibe Audit](https://github.com/jackdog668/vibeaudit) v1.1.0 — 82 rules across 8 attack surfaces.*
