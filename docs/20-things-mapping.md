# 20 Things That Get Your Vibe Coded App Hacked — Vibeaudit Coverage Map

> How Vibe Audit catches every item on the viral security checklist.
> Use this as a teaching reference or run the commands to audit your own app.

## Quick Start

```bash
# Scan everything
npx vibe-audit .

# Scan with fix prompts (copy-paste to your AI tool)
npx vibe-audit . --fix

# Scan only the rules from this checklist
npx vibe-audit . --rules exposed-secrets,exposed-env-vars,client-bundle-secrets,no-account-lockout,missing-rate-limiting,no-input-validation,insecure-connections,sensitive-browser-storage,insecure-jwt,client-only-auth,missing-auth,missing-gitignore,git-history-secrets,insecure-error-handling,unsafe-file-upload,plaintext-passwords,auth-token-no-expiry,idor-vulnerability,session-fixation,unsafe-redirect,docker-root-user,exposed-database-port
```

---

## The Full Mapping

| # | Vulnerability | Vibeaudit Rule(s) | Severity | CLI Command |
|---|---|---|---|---|
| 1 | API keys hardcoded in frontend JS | `exposed-secrets`, `client-bundle-secrets`, `exposed-env-vars` | Critical | `--rules exposed-secrets,client-bundle-secrets,exposed-env-vars` |
| 2 | No rate limiting on /login | `missing-rate-limiting`, `no-account-lockout` | Warning | `--rules missing-rate-limiting,no-account-lockout` |
| 3 | SQL injection (string concatenation) | `no-input-validation` | Critical | `--rules no-input-validation` |
| 4 | CORS set to wildcard (*) | `insecure-connections` | Warning | `--rules insecure-connections` |
| 5 | JWTs stored in localStorage | `sensitive-browser-storage` | Critical | `--rules sensitive-browser-storage` |
| 6 | JWT secret is "secret" or from tutorial | `insecure-jwt` | Critical | `--rules insecure-jwt` |
| 7 | Admin routes protected only in frontend | `client-only-auth`, `missing-auth` | Critical/Warning | `--rules client-only-auth,missing-auth` |
| 8 | .env committed to git | `missing-gitignore`, `git-history-secrets` | Critical | `--rules missing-gitignore,git-history-secrets --deep` |
| 9 | Error responses showing stack traces | `insecure-error-handling` | Warning | `--rules insecure-error-handling` |
| 10 | File uploads with no MIME validation | `unsafe-file-upload` | Critical | `--rules unsafe-file-upload` |
| 11 | Passwords hashed with MD5 or SHA1 | `plaintext-passwords` | Critical | `--rules plaintext-passwords` |
| 12 | Auth tokens that never expire | `auth-token-no-expiry`, `insecure-jwt` | Warning/Critical | `--rules auth-token-no-expiry,insecure-jwt` |
| 13 | Auth middleware missing on internal routes | `missing-auth` | Critical | `--rules missing-auth` |
| 14 | Server running as root | `docker-root-user` | Warning | `--rules docker-root-user` |
| 15 | Database port exposed to internet | `exposed-database-port` | Warning | `--rules exposed-database-port` |
| 16 | IDOR on resource endpoints | `idor-vulnerability` | Critical | `--rules idor-vulnerability` |
| 17 | No HTTPS enforcement | `insecure-connections` | Warning | `--rules insecure-connections` |
| 18 | Sessions not invalidated on logout | `session-fixation` | Critical | `--rules session-fixation` |
| 19 | npm packages not audited | SCA scanner (built-in) | Varies | Default scan (don't use `--skip-sca`) |
| 20 | Open redirects in callback URLs | `unsafe-redirect` | Warning | `--rules unsafe-redirect` |

---

## How Each Item Is Detected

### 1. API keys hardcoded in frontend JS

**Rules:** `exposed-secrets` | `client-bundle-secrets` | `exposed-env-vars`

Vibe Audit matches 20+ secret patterns (AWS keys, OpenAI keys, Stripe keys, Firebase keys, etc.) and flags them anywhere in source. The `client-bundle-secrets` rule specifically catches secrets in files that ship to the browser (React components, pages). The `exposed-env-vars` rule catches server secrets exposed via `NEXT_PUBLIC_` or `VITE_` prefixes.

**What to do:** Move all keys to `.env` and access via `process.env.KEY_NAME` on the server side only.

---

### 2. No rate limiting on /login

**Rules:** `missing-rate-limiting` | `no-account-lockout`

Detects API routes that call paid APIs or handle auth without rate limiting. The `no-account-lockout` rule specifically checks login endpoints for brute force protection.

**What to do:** Add rate limiting (e.g., `@upstash/ratelimit`) and lockout after 5 failed attempts.

---

### 3. SQL injection (string concatenation)

**Rule:** `no-input-validation`

Uses AST analysis to trace user input (`req.body`, `req.query`, `req.params`) flowing into dangerous functions including SQL queries and DOM manipulation.

**What to do:** Use parameterized queries. Never concatenate user input into SQL strings.

---

### 4. CORS set to wildcard (*)

**Rule:** `insecure-connections`

Detects `Access-Control-Allow-Origin: *` and `origin: '*'` in CORS configuration.

**What to do:** Whitelist specific origins. Use an allowlist, not a wildcard.

---

### 5. JWTs stored in localStorage

**Rule:** `sensitive-browser-storage`

Detects `localStorage.setItem` or `sessionStorage.setItem` with token/jwt/auth/session variable names.

**What to do:** Use `httpOnly` cookies instead. They can't be read by JavaScript.

---

### 6. JWT secret is "secret" or from tutorial

**Rule:** `insecure-jwt`

Detects weak JWT secrets (short strings, common words like "secret", "password"), missing algorithm pinning, and missing expiry.

**What to do:** Generate a 256-bit random secret. Use `RS256` or pin `HS256` explicitly.

---

### 7. Admin routes protected only in frontend

**Rules:** `client-only-auth` | `missing-auth`

`client-only-auth` catches frontend-only guards (`if (!user) redirect`). `missing-auth` uses AST to check every exported API handler for auth calls.

> **Name it right:** swapping `/dashboard` → `/admin` to reach a function you shouldn't is **Broken Function Level Authorization (BFLA)**, not IDOR. It's covered here by `missing-auth` and `nextjs-middleware-bypass`. IDOR/BOLA is the *object-reference* swap (`/invoice/1001` → `/1002`) — see item 16. Both are broken access control; different checks.

**What to do:** Every API route must verify auth server-side. Frontend guards are UX, not security.

---

### 8. .env committed to git

**Rules:** `missing-gitignore` | `git-history-secrets`

Checks that `.gitignore` includes `.env` patterns. With `--deep`, scans git history for previously committed secrets.

**What to do:** Add `.env*` to `.gitignore`. If it was ever committed, rotate every key in that file immediately.

---

### 9. Error responses showing stack traces

**Rule:** `insecure-error-handling`

Detects `err.stack`, `err.message`, or full error objects returned in API responses.

**What to do:** Log errors server-side. Return generic messages to clients.

---

### 10. File uploads with no MIME type validation

**Rule:** `unsafe-file-upload`

Detects `multer`, `formidable`, and similar upload handlers without MIME type or file size validation.

**What to do:** Validate MIME type server-side (allowlist). Set max file size. Use random filenames.

---

### 11. Passwords hashed with MD5 or SHA1

**Rule:** `plaintext-passwords`

Uses AST analysis to detect: (1) passwords stored without any hashing, (2) password `===` comparison (implies plaintext), and (3) `crypto.createHash('md5')` or `crypto.createHash('sha1')` used with password variables.

**What to do:** Use `bcrypt.hash(password, 12)` for storage and `bcrypt.compare()` for verification.

---

### 12. Auth tokens that never expire

**Rules:** `auth-token-no-expiry` | `insecure-jwt`

Detects `jwt.sign()` calls without `expiresIn` option.

**What to do:** Set expiry on every token. Implement refresh token rotation.

---

### 13. Auth middleware missing on internal API routes

**Rule:** `missing-auth`

AST-enhanced rule that examines each exported handler function individually. Checks if the function calls auth verification (session, JWT verify, middleware) before processing the request.

**What to do:** Audit every endpoint. Add auth middleware to all non-public routes.

---

### 14. Server running as root

**Rule:** `docker-root-user`

Checks Dockerfiles for missing `USER` directive or `USER root` as the final directive.

**What to do:** Add a non-root user: `RUN addgroup -S app && adduser -S app -G app` then `USER app`.

---

### 15. Database port exposed to internet

**Rule:** `exposed-database-port`

Scans `docker-compose.yml` for `ports:` mappings on known database ports (PostgreSQL 5432, MySQL 3306, MongoDB 27017, Redis 6379, etc.).

**What to do:** Remove `ports:` for database services. Use `expose:` for container-to-container only.

---

### 16. IDOR vulnerability on resource endpoints

**Rule:** `idor-vulnerability`

AST-enhanced rule that detects when `params.id` or `req.params.id` is used to query data without an ownership check (e.g., `WHERE userId = session.user.id`) in the same function scope.

> **IDOR ≠ BFLA:** IDOR/BOLA is swapping an *object reference* (`/invoice/1001` → `/1002`) to read someone else's record — what this rule checks. Swapping a *route/function* (`/dashboard` → `/admin`) is Broken Function Level Authorization (item 7). Both are broken access control; different checks.

**What to do:** Always verify ownership server-side. `findById(params.id)` must also check the resource belongs to the authenticated user.

---

### 17. No HTTPS enforcement

**Rule:** `insecure-connections`

Detects `http://` URLs (excluding localhost), disabled TLS verification, and missing HSTS configuration.

**What to do:** Enforce HTTPS at the server level. Redirect all HTTP traffic.

---

### 18. Sessions not invalidated on logout

**Rule:** `session-fixation`

Detects logout/signout handlers that don't call `session.destroy()`, `req.logout()`, or token invalidation. Also checks login handlers for session regeneration.

**What to do:** Always call `req.session.destroy()` on logout. For JWT, add tokens to a server-side revocation list.

---

### 19. npm packages not audited

**Detection:** Built-in SCA scanner

Vibe Audit automatically scans `package-lock.json` for known vulnerable dependencies using advisory data. Runs by default unless `--skip-sca` is used.

**What to do:** Run `npm audit` regularly. Schedule it as part of every deploy.

---

### 20. Open redirects in callback URLs

**Rule:** `unsafe-redirect`

Detects `res.redirect(req.query.*)` and similar patterns where redirect URLs come from user input without validation.

**What to do:** Validate and whitelist every redirect destination. Never trust user-supplied redirect URLs.

---

## Coverage Summary

- **20/20 items covered** by Vibe Audit
- **98 total rules** across 17 categories (these + 78 more, now including accessibility/WCAG, scale/performance, and observability packs)
- **Zero configuration** — just run `npx vibe-audit .`
- **Copy-paste fixes** — use `--fix` flag to get AI-ready fix prompts
- **Beyond the code** — every scan points you to the DA Pre-Flight Audit Prompt for the judgment layer a static scanner can't see (business logic, data model, threat model)

## Beyond the 20: v1.2 additions

The viral checklist is security-only. Two things that wreck vibe-coded apps aren't on it:

**Accessibility (the ADA-lawsuit lane).** An accessibility statement or an overlay widget does not stop a lawsuit — lawyers run automated scanners (PowerMapper, axe) against real WCAG conformance. Vibe Audit ships six Level A checks (`a11y-img-no-alt`, `a11y-form-no-label`, `a11y-no-lang`, `a11y-button-no-name`, `a11y-positive-tabindex`, `a11y-click-no-keyboard`) tuned to get you under the automated-scanner radar. Static analysis catches the low-hanging Level A misses; pair with axe-core for screen-reader depth.

**Scale (the "$50k server bill" lane).** "The AI made it sequential" is a fuzzy diagnosis. The real culprits are **N+1 queries**, **per-request DB connections**, **ephemeral-disk writes**, **missing indexes**, and **no caching**. Vibe Audit statically catches the ones that live in code — `perf-n-plus-one` (a query inside a loop or `.map`), `perf-no-await-parallel` (sequential `await` that should be `Promise.all`), `perf-db-client-per-request` (`new PrismaClient()` created per request → connection-pool exhaustion), and `serverless-fs-write` (writing to a serverless disk that gets wiped between requests). The rest — index design, cache strategy, sharding, load balancing — is architecture judgment, not static patterns, and belongs to the Pre-Flight Audit Prompt, not the scanner. We say so plainly.

## For Educators

This mapping is designed for teaching security to vibe coders. Each item can be turned into a hands-on exercise:

1. Create a vulnerable code snippet (the "before")
2. Run `npx vibe-audit . --rules [rule-id]` to detect it
3. Apply the fix
4. Run the scan again to verify it passes

This teaches the security concept AND the tool in the same lesson.
