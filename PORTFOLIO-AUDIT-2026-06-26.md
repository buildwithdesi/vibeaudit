# Vibe Audit Portfolio Scan — 2026-06-26

**Scanned:** 161 repos under `jackdog668/` via GitHub code search
**Method:** Pattern-based sweep across all repos for 20+ security anti-patterns (secrets, CORS, auth, injection, cookies, rate limiting, CSRF, AI prompt injection, infra)
**Grade: B+** — No critical findings. No exposed secrets. A handful of CORS misconfigurations to clean up.

---

## Findings Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0     | Clean  |
| High     | 2     | Action needed |
| Medium   | 4     | Should fix |
| Low      | 3     | Informational |

---

## HIGH

### 1. vibe-vocab — CORS credentials with wildcard origin
**File:** `api/vocabulary.ts`
**Issue:** Sets `Access-Control-Allow-Credentials: true` AND `Access-Control-Allow-Origin: *` simultaneously. Browsers block this combination today, but it signals a CORS misunderstanding. If "fixed" by reflecting the Origin header instead of using `*`, it becomes a real credential-stealing vulnerability.
**CWE:** CWE-942 | **OWASP:** A01:2021 Broken Access Control

**Fix:** Remove `Allow-Credentials: true` (this is a public vocabulary API — it doesn't need credentials), or restrict the origin to your actual frontend domain.

### 2. 1code-main — Auth cookies with httpOnly: false
**File:** `1code-main/src/main/index.ts` (2 occurrences)
**Issue:** Authentication cookies are set with `httpOnly: false`. Any XSS vulnerability anywhere in the app could steal the session cookie via `document.cookie`.
**CWE:** CWE-1004 | **OWASP:** A07:2021 Identification and Authentication Failures

**Fix:** Set `httpOnly: true` on all auth/session cookies.

---

## MEDIUM

### 3. sref-scanner — Open CORS (no origin restriction)
**File:** `backend/server.js`
**Issue:** `app.use(cors())` with default config allows any origin. If this server handles sensitive data or acts as a proxy, any website can make authenticated cross-origin requests.

### 4. blazing-schrodinger — Open CORS (no origin restriction)
**File:** `server/server.js`
**Issue:** Same pattern — `app.use(cors())` with no origin allowlist.

### 5. ruby-magnetosphere — Open CORS on a file system manager
**File:** `server/index.js`
**Issue:** `app.use(cors())` on a server that accesses the local Downloads directory. Any website could potentially read/list files from the user's filesystem via cross-origin requests.
**This is the most concerning MEDIUM** — file system access + open CORS is a dangerous combination.

### 6. stitch-alchemy — Wildcard CORS on AI API proxy
**File:** `stitch-server.ts`
**Issue:** `Access-Control-Allow-Origin: *` on a server that proxies Google Generative AI API calls using an API key. Any website could use this as a free AI proxy, burning your API credits.

**Fix for all MEDIUM:** Replace `cors()` or `"*"` with an explicit origin allowlist:
```js
app.use(cors({ origin: ['https://yourdomain.com'] }));
```

---

## LOW / INFORMATIONAL

### 7. digitalalchemy-vibecode — CSRF intentionally disabled
**File:** `backend/src/auth.ts`
**Detail:** `disableCSRFCheck: true` with `sameSite: "none"` cookies for cross-subdomain auth. Code comments explain the rationale. Risk is mitigated by CORS origin validation.

### 8. node-banana / node-banana-bear — Math.random() for IDs
**File:** `src/store/workflowStore.ts`
**Detail:** Uses `Math.random()` for workflow IDs. These are internal UI identifiers, not security tokens — low risk but could be upgraded to `crypto.randomUUID()`.

### 9. stream-gamify — Open CORS in example file
**File:** `BACKEND_PROXY_EXAMPLE.js`
**Detail:** `app.use(cors())` in an example/template file. Not production code, but users copying it will inherit the misconfiguration.

---

## Clean Highlights

These repos demonstrate good security practices:

| Repo | What's done right |
|------|-------------------|
| **saas-starter** | Stripe webhook signature verification, httpOnly+secure+sameSite cookies, bcrypt password hashing, proper session management |
| **content-drop** | OAuth state parameter, token encryption with timing-safe comparison, secure cookie flags |
| **digitalalchemy-dev** | OAuth state params, Supabase service key kept server-side, Zod env validation |
| **Siftly** | CORS locked to specific origins (x.com, twitter.com) |
| **video-analyzer-70** | express-rate-limit + env-configured CORS origins |
| **digital-alchemy-app** | CORS with regex-based origin validation + credentials |
| **screenshot-pools** | CORS allowlist from ALLOWED_ORIGINS env var |
| **Chromatic-Illusion-Weaponizerr** | Rate limiting on API endpoints (partially mitigates open CORS) |

## What Was NOT Found (Good News)

- **No hardcoded API keys or tokens** in any repo — all use `process.env`
- **No committed .env files** with secrets
- **No open Firebase/Firestore rules**
- **No SQL injection or command injection patterns**
- **No dangerouslySetInnerHTML or eval()** in application code
- **No exposed database ports** in Docker configs
- **No plaintext password storage** — repos using auth use proper hashing
- **No JWT with weak secrets** hardcoded in source

---

## Recommendations

1. **Fix the 2 HIGH findings** — both are quick one-line changes
2. **Add CORS origin allowlists** to the 4 MEDIUM repos
3. **Consider adding `helmet`** to Express servers for security headers (none of the Express apps use it currently)
4. **Add this scan to CI** — run `npx vibe-audit --strict --format json` in GitHub Actions on push

---

*Generated by Vibe Audit portfolio scan — replaces DigitalOcean bot*
*Scanner: vibe-audit v1.1.0 | Rules: 82 | Method: GitHub code search pattern sweep*
