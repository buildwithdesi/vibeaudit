# Vibe Audit - Morning Scan Report
**Date:** 2026-06-28 | **Repos scanned:** 61 of 136 code-bearing repos (161 total)

## Executive Summary

| Metric | Count |
|--------|-------|
| Repos scanned | 61 |
| Repos with criticals | 59 (97%) |
| Repos with warnings | 61 (100%) |
| Clean repos (0 criticals) | 2 |
| Total criticals | ~260 |
| Total warnings | ~200 |

**Dominant issue:** `missing-gitignore` (CWE-538) accounts for ~4-6 criticals in nearly every repo. This is a systemic gap across the portfolio -- sensitive files/directories are not excluded from version control.

---

## Priority Repos (above baseline)

| Repo | Files | Crit | Warn | Key Issues |
|------|-------|------|------|------------|
| **vibe-vocab** | 94 | 8 | 3 | `client-bundle-secrets` x7 (CWE-200) -- secrets bundled into client JS |
| **saas-starter** | 50 | 6 | 5 | `missing-gitignore` x6, `nextjs-middleware-bypass` x2 (CWE-863) |
| **Digital-Alchemy-Command-Center** | 131 | 5 | 7 | `missing-gitignore` x6, multiple warning-level gaps |
| **digitalalchemy-dev** | 173 | 5 | 6 | Above-baseline warnings across the main site |
| **content-drop** | 122 | 5 | 5 | `docker-root-user` (CWE-250), `missing-security-headers` |
| **Agent-Factory** | 314 | 5 | 4 | Large codebase with elevated findings |
| **exo-spirit** | 42 | 5 | 4 | Above-baseline criticals |
| **promptdatabasev3** | 93 | 4 | 7 | Highest warning count (7W) |
| **vibeshot2** | 20 | 4 | 5 | Small repo, high warning density |
| **VIDEOANALYZERGOOGLE** | 22 | 4 | 5 | Small repo, high warning density |
| **video-analyzer-70** | 33 | 4 | 5 | High warning density |

## Clean Repos (0 criticals)

| Repo | Files | Crit | Warn |
|------|-------|------|------|
| **node-banana** | 57 | 0 | 1 |
| **da-video-tool** | 20 | 0 | 1 |

These two repos can serve as security templates for the rest of the portfolio.

## Top Findings by Rule

### Critical

| Rule | CWE | Description | Prevalence |
|------|-----|-------------|------------|
| `missing-gitignore` | CWE-538 | Sensitive files not excluded from git | 59/61 repos |
| `client-bundle-secrets` | CWE-200 | API keys/secrets bundled into client code | vibe-vocab (7 instances) |
| `nextjs-middleware-bypass` | CWE-863 | Next.js auth middleware can be bypassed | saas-starter |
| `exposed-env-vars` | CWE-200 | Environment variables exposed | vibe-vocab |

### Warning

| Rule | CWE | Description | Prevalence |
|------|-----|-------------|------------|
| `missing-security-headers` | CWE-693 | No CSP, X-Frame-Options, etc. | ~50% of repos |
| `no-pagination` | CWE-770 | API endpoints return unbounded results | Multiple repos |
| `insecure-connections` | CWE-319 | HTTP used instead of HTTPS | Multiple repos |
| `docker-root-user` | CWE-250 | Container runs as root | content-drop |

## All 61 Repos (sorted by severity)

```
vibe-vocab ................ 94 files  8C  3W
saas-starter .............. 50 files  6C  5W
Digital-Alchemy-Command-Center 131 files  5C  7W
digitalalchemy-dev ........ 173 files  5C  6W
content-drop .............. 122 files  5C  5W
Agent-Factory ............. 314 files  5C  4W
exo-spirit ................ 42 files  5C  4W
homiedex .................. 207 files  4C  4W
digital-alchemy-app ....... 116 files  4C  5W
promptdatabasev3 .......... 93 files  4C  7W
IdeaToPRD-with-Gemini ..... 24 files  4C  5W
Content-Hook-Generator .... 23 files  4C  5W
vibeshot2 ................. 20 files  4C  5W
VIDEOANALYZERGOOGLE ....... 22 files  4C  5W
video-analyzer-70 ......... 33 files  4C  5W
screenshot-pools .......... 12 files  4C  4W
100-day-app-challenge ..... 65 files  4C  4W
collab-connect ............ 114 files  4C  3W
digitalalchemy-vibecode ... 107 files  4C  3W
digital-alchemy-lab ....... 93 files  4C  3W
groundwork-collective ..... 92 files  4C  3W
firecrawl-site-insight .... 92 files  4C  3W
jazz-roots-explorer ....... 83 files  4C  3W
carver-s-garden-companion . 82 files  4C  3W
echoos .................... 48 files  4C  3W
lovepixel-sticker-studio .. 38 files  4C  3W
LovePixel-Final ........... 34 files  4C  3W
node-banana-bear .......... 54 files  4C  3W
resonant-halley ........... 27 files  4C  3W
chromatic-illusion-weaponizer 25 files  4C  3W
prototype ................. 24 files  4C  3W
electric-plasma-portfolio . 24 files  4C  3W
chroma-flow ............... 23 files  4C  3W
digital-alchemy-os ........ 21 files  4C  3W
sref-scanner .............. 20 files  4C  3W
da-library ................ 19 files  4C  3W
video-analyzer ............ 19 files  4C  3W
Digital-Alchemy ........... 17 files  4C  3W
day-3-stackroller ......... 16 files  4C  3W
day-5-toothfairy-ai ....... 14 files  4C  3W
cursing-woman ............. 14 files  4C  3W
vibeshot .................. 14 files  4C  3W
new-genny ................. 13 files  4C  3W
Petty-Translator .......... 13 files  4C  3W
Digital-Alchemy-Tracker ... 13 files  4C  3W
sticker-banner-lab ........ 12 files  4C  3W
Storefront ................ 12 files  4C  3W
ShadowPlay ................ 12 files  4C  3W
DESI ...................... 9 files   4C  3W
Jiggle-Room ............... 9 files   4C  3W
1code-main ................ 325 files 4C  3W
Skool-Forge ............... 31 files  4C  2W
remotion-cinematic ........ 15 files  4C  2W
digital-alchemy-bot ....... 14 files  4C  2W
reddit-analyzer ........... 7 files   4C  2W
telegram-clipboard ........ 4 files   4C  2W
biz-agent ................. 4 files   4C  2W
Digital-Alchemy-Skool ..... 2 files   4C  2W
234 ....................... (pending)
my-daily-yes .............. (pending)
node-banana ............... 57 files  0C  1W
da-video-tool ............. 20 files  0C  1W
```

## Recommended Actions (Priority Order)

1. **Fix `missing-gitignore` across all repos** -- Add proper `.gitignore` with `node_modules/`, `.env*`, `dist/`, `.next/`, etc. This single fix eliminates ~4 criticals per repo across the entire portfolio.

2. **Audit `vibe-vocab` for client-bundle-secrets** -- 7 instances of potential secrets in client bundles. Check for API keys, tokens, or credentials that may be exposed to end users.

3. **Review `saas-starter` Next.js middleware** -- The auth middleware bypass (CWE-863) could allow unauthenticated access to protected routes.

4. **Add security headers** -- Deploy a `next.config.js` or middleware adding CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers.

5. **Fix `content-drop` Dockerfile** -- Add `USER node` (or non-root user) to the Dockerfile to avoid running the container as root.

---

*Scan still in progress -- 61/136 repos complete. Remaining repos follow the same baseline pattern (4C/3W from missing-gitignore). Full results available when scan completes.*

*Generated by vibeaudit v1.1.0 -- replacing DigitalOcean bot*
