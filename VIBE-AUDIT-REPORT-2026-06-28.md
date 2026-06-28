# Vibe Audit - Morning Scan Report
**Date:** 2026-06-28 | **Repos scanned:** 136 of 136 code-bearing repos (161 total)

## Executive Summary

| Metric | Count |
|--------|-------|
| Repos scanned | 136 |
| Repos with criticals | 123 (90%) |
| Repos with warnings | 128 (94%) |
| Clean repos (0 criticals) | 13 |
| Total criticals | 619 |
| Total warnings | 443 |

**Two systemic issues dominate:** `missing-gitignore` (CWE-538) accounts for ~4 criticals in most repos, and `missing-auth` (CWE-306) is severe in Siftly. One repo requires urgent attention.

---

## URGENT: Siftly (public repo)

**Siftly is publicly accessible and has 34 criticals + 40 warnings -- the worst non-test repo in the portfolio.**

| Rule | CWE | Count | Severity |
|------|-----|-------|----------|
| `missing-auth` | CWE-306 | 28 | CRITICAL -- 28 API routes have no authentication |
| `race-condition` | CWE-362 | 2 | CRITICAL |
| `unsafe-file-upload` | CWE-434 | 1 | CRITICAL |
| `no-input-validation` | CWE-20 | 1 | CRITICAL |
| `dangerously-set-inner-html` | CWE-79 | 1 | CRITICAL -- XSS vector |
| `nextjs-middleware-bypass` | CWE-863 | 1 | CRITICAL |
| `missing-csrf` | CWE-352 | 15 | WARNING |
| `api-data-overfetch` | CWE-200 | 13 | WARNING |
| `insecure-error-handling` | CWE-209 | 7 | WARNING |

**Recommended:** Make the repo private or add auth middleware immediately. The 28 unprotected API routes and XSS finding are exploitable as-is.

---

## Priority Repos (above baseline)

| Repo | Files | Crit | Warn | Key Issues |
|------|-------|------|------|------------|
| **Siftly** (PUBLIC) | 69 | 34 | 40 | `missing-auth` x28, `dangerously-set-inner-html`, `unsafe-file-upload` |
| **vibe-vocab** (PUBLIC) | 94 | 8 | 3 | `client-bundle-secrets` x7 (CWE-200) -- secrets bundled into client JS |
| **saas-starter** | 50 | 6 | 5 | `missing-gitignore` x6, `nextjs-middleware-bypass` x2 (CWE-863) |
| **Digital-Alchemy-Command-Center** | 131 | 5 | 7 | `missing-gitignore` x6, multiple warning-level gaps |
| **digitalalchemy-dev** | 173 | 5 | 6 | Above-baseline warnings across the main site |
| **content-drop** | 122 | 5 | 5 | `docker-root-user` (CWE-250), `missing-security-headers` |
| **Agent-Factory** | 314 | 5 | 4 | Large codebase with elevated findings |
| **exo-spirit** | 42 | 5 | 4 | Above-baseline criticals |
| **promptdatabasev3** | 93 | 4 | 7 | Highest warning count among standard repos |
| **a-silly-idea** (PUBLIC) | 11 | 0 | 7 | No criticals but high warning density |

## Clean Repos (0 criticals)

| Repo | Files | Warn | Notes |
|------|-------|------|-------|
| **node-banana** | 57 | 1 | Largest clean codebase -- good security template |
| **da-video-tool** (PUBLIC) | 20 | 1 | Clean public repo |
| **Chromatic-Illusion-Weaponizerr** | 6 | 0 | Fully clean |
| **photo-organizer-da** (PUBLIC) | 3 | 0 | Fully clean |
| **percolator-class-guide** (PUBLIC) | 2 | 0 | Fully clean |
| **myfirstdeploy** (PUBLIC) | 2 | 1 | |
| **vvprivacypolicy** | 3 | 2 | |
| + 6 single-file repos | 1 | 0 | Minimal codebases |

## Top Findings by Rule

### Critical

| Rule | CWE | Description | Prevalence |
|------|-----|-------------|------------|
| `missing-gitignore` | CWE-538 | Sensitive files not excluded from git | ~120 repos |
| `missing-auth` | CWE-306 | API routes without authentication | Siftly (28 routes) |
| `client-bundle-secrets` | CWE-200 | API keys/secrets in client bundles | vibe-vocab (7 instances) |
| `nextjs-middleware-bypass` | CWE-863 | Auth middleware can be bypassed | saas-starter, Siftly |
| `race-condition` | CWE-362 | Concurrent request vulnerabilities | Siftly |
| `unsafe-file-upload` | CWE-434 | No file type/size validation on upload | Siftly |
| `dangerously-set-inner-html` | CWE-79 | XSS via unescaped HTML injection | Siftly |
| `exposed-env-vars` | CWE-200 | Environment variables exposed | vibe-vocab |

### Warning

| Rule | CWE | Description | Prevalence |
|------|-----|-------------|------------|
| `missing-security-headers` | CWE-693 | No CSP, X-Frame-Options, etc. | ~50% of repos |
| `missing-csrf` | CWE-352 | No CSRF protection on mutations | Siftly (15 routes) |
| `api-data-overfetch` | CWE-200 | APIs return more data than needed | Siftly (13 endpoints) |
| `insecure-error-handling` | CWE-209 | Stack traces/internals in errors | Siftly (7 instances) |
| `no-pagination` | CWE-770 | Unbounded API result sets | Multiple repos |
| `insecure-connections` | CWE-319 | HTTP instead of HTTPS | Multiple repos |
| `docker-root-user` | CWE-250 | Container runs as root | content-drop |
| `clickjacking` | CWE-1021 | No frame protection | Siftly |

## Full Results (all 136 repos, sorted by severity)

```
Siftly .................... 69 files   34C 40W  ** PUBLIC - URGENT **
vibe-vocab ................ 94 files    8C  3W  ** PUBLIC **
saas-starter .............. 50 files    6C  5W
Digital-Alchemy-Command-Center 131 files  5C  7W
digitalalchemy-dev ........ 173 files   5C  6W
content-drop .............. 122 files   5C  5W
Agent-Factory ............. 314 files   5C  4W
exo-spirit ................ 42 files    5C  4W
promptdatabasev3 .......... 93 files    4C  7W
IdeaToPRD-with-Gemini ..... 24 files    4C  5W
Content-Hook-Generator .... 23 files    4C  5W
digital-alchemy-app ....... 116 files   4C  5W
video-analyzer-70 ......... 33 files    4C  5W
VIDEOANALYZERGOOGLE ....... 22 files    4C  5W
vibeshot2 ................. 20 files    4C  5W
chibi-forge ............... 30 files    4C  5W
qr-forge-pro .............. 20 files    4C  5W
homiedex .................. 207 files   4C  4W
screenshot-pools .......... 12 files    4C  4W
100-day-app-challenge ..... 65 files    4C  4W
the-77 .................... 37 files    4C  4W
sierrabakerconsulting ...... 4 files    4C  4W
collab-connect ............ 114 files   4C  3W
digitalalchemy-vibecode ... 107 files   4C  3W
digital-alchemy-lab ....... 93 files    4C  3W
groundwork-collective ..... 92 files    4C  3W
firecrawl-site-insight .... 92 files    4C  3W
jazz-roots-explorer ....... 83 files    4C  3W
carver-s-garden-companion . 82 files    4C  3W
echoos .................... 48 files    4C  3W
second-brain-system ....... 46 files    4C  3W
lovepixel-sticker-studio .. 38 files    4C  3W
LovePixel-Final ........... 34 files    4C  3W
node-banana-bear .......... 54 files    4C  3W
Storefront ................ 12 files    4C  3W
ShadowPlay ................ 12 files    4C  3W
sticker-banner-lab ........ 12 files    4C  3W
stream-gamify ............. 28 files    4C  3W
resonant-halley ........... 27 files    4C  3W
chromatic-illusion-weaponizer 25 files   4C  3W
prototype ................. 24 files    4C  3W
electric-plasma-portfolio . 24 files    4C  3W
chroma-flow ............... 23 files    4C  3W
digital-alchemy-os ........ 21 files    4C  3W
sref-scanner .............. 20 files    4C  3W
da-library ................ 19 files    4C  3W
video-analyzer ............ 19 files    4C  3W
Digital-Alchemy ........... 17 files    4C  3W
day-3-stackroller ......... 16 files    4C  3W
remotion-cinematic ........ 15 files    4C  2W
day-5-toothfairy-ai ....... 14 files    4C  3W
cursing-woman ............. 14 files    4C  3W
vibeshot .................. 14 files    4C  3W
new-genny ................. 13 files    4C  3W
Petty-Translator .......... 13 files    4C  3W
Digital-Alchemy-Tracker ... 13 files    4C  3W
DESI ...................... 9 files     4C  3W
Jiggle-Room ............... 9 files     4C  3W
1code-main ................ 325 files   4C  3W
234 ....................... 17 files    4C  3W
my-daily-yes .............. 12 files    4C  3W
brand-verticals-studio .... 73 files    4C  3W
This-Day-in-Black-Excellence 29 files   4C  3W
permission-to-play ........ 17 files    4C  3W
htmlchange ................ 8 files     4C  3W
panther-chicago-legacy .... 82 files    4C  3W
harriet-s-path ............ 83 files    4C  3W
lucky-leaf-finder ......... 82 files    4C  3W
CreatorColorLine .......... 22 files    4C  3W
Love-Pixel-Stickers ....... 14 files    4C  3W
day-6-bloodbank-charles-drew 13 files   4C  3W
new-folder-docs ........... 10 files    4C  3W
ineeditall ................ 10 files    4C  3W
melanin-patch-app ......... 6 files     4C  3W
ruby-magnetosphere ........ 7 files     4C  3W
ruby-feynman .............. 6 files     4C  3W
blazing-schrodinger ....... 5 files     4C  3W
app-replay-forge .......... 6 files     4C  3W
demo-carousel ............. 6 files     4C  3W
deep-radiation ............ 6 files     4C  3W
infrared-hypernova ........ 6 files     4C  3W
midjourney-agent .......... 4 files     4C  3W
alchemic-generator ........ 5 files     4C  3W
portfolio-website-v2 ...... 4 files     4C  3W
file-manager .............. 10 files    4C  3W
digital-alchemy-dashboard . 8 files     4C  3W
grainrad-bulk ............. 20 files    4C  3W
crypto-101 ................ 7 files     4C  3W
my-twitter-export ......... 4 files     4C  3W
digital-alchemy-bot ....... 14 files    4C  2W
reddit-analyzer ........... 7 files     4C  2W
telegram-clipboard ........ 4 files     4C  2W
biz-agent ................. 4 files     4C  2W
Digital-Alchemy-Skool ..... 2 files     4C  2W
Skool-Forge ............... 31 files    4C  2W
vibe-tracker .............. 18 files    4C  2W
chatgpt-data-analysis ..... 8 files     4C  2W
video-alchemy ............. 2 files     4C  2W
(+ 17 repos with 4C 2W from small/static codebases)

--- CLEAN ---
a-silly-idea .............. 11 files    0C  7W  (PUBLIC)
myfirstdeploy ............. 2 files     0C  1W  (PUBLIC)
vvprivacypolicy ........... 3 files     0C  2W
node-banana ............... 57 files    0C  1W
da-video-tool ............. 20 files    0C  1W  (PUBLIC)
Chromatic-Illusion-Weaponizerr 6 files  0C  0W
photo-organizer-da ........ 3 files     0C  0W  (PUBLIC)
percolator-class-guide .... 2 files     0C  0W  (PUBLIC)
+ 5 single-file repos      1 file      0C  0W
```

*Note: vibeaudit itself shows 92C/27W but these are from intentional test fixtures (insecure code samples used to test the scanner). Excluded from priority analysis.*

## Recommended Actions (Priority Order)

1. **URGENT: Secure Siftly or make it private** -- 28 unauthenticated API routes on a public repo. Add auth middleware to all `/api/` routes. Fix the XSS (`dangerouslySetInnerHTML`) and unsafe file upload immediately.

2. **Fix `missing-gitignore` across all repos** -- Add proper `.gitignore` with `node_modules/`, `.env*`, `dist/`, `.next/`, etc. This single fix eliminates ~4 criticals per repo (~480 criticals total).

3. **Audit `vibe-vocab` for client-bundle-secrets** -- 7 instances of potential secrets in client bundles. This is a public repo -- any exposed keys are already compromised.

4. **Review `saas-starter` Next.js middleware** -- The auth middleware bypass (CWE-863) could allow unauthenticated access to protected routes.

5. **Add security headers portfolio-wide** -- Deploy middleware adding CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers. Affects ~50% of repos.

6. **Fix `content-drop` Dockerfile** -- Add `USER node` to avoid running as root (CWE-250).

---

*Generated by vibeaudit v1.1.0 | Full scan: 136/136 repos, 619 criticals, 443 warnings | Replacing DigitalOcean bot*
