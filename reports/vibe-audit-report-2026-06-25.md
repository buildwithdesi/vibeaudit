# Vibe Audit Report — June 25, 2026

## Summary

| Metric | Count |
|--------|-------|
| Repos scanned | 119 |
| Files scanned | 4,610 |
| Total findings | 2,526 |
| Critical | 1,044 |
| Warning | 1,092 |
| Info | 390 |

## Top Critical Rule Types (across all repos)

| Rule | Hits | Description |
|------|------|-------------|
| no-input-validation | 312 | Missing sanitization, innerHTML/XSS vectors |
| missing-auth | 249 | API routes with no authentication check |
| missing-gitignore | 141 | .env and secrets not gitignored |
| nextjs-server-action-exposure | 113 | Server actions callable without auth |
| supabase-service-key-client | 77 | Service role key exposed in client code |
| dangerously-set-inner-html | 40 | Unsanitized innerHTML — XSS risk |
| session-fixation | 28 | Sessions not destroyed on logout |
| client-side-db-access | 19 | Direct DB queries from client |
| client-bundle-secrets | 13 | API keys in client bundles |
| secrets-in-urls | 9 | Secrets in URL query params |

## High-Priority Repos (need attention)

### 1. digitalalchemy-dev — 150 critical
The main website has the most findings. Key issues:
- **76 supabase-service-key-client**: Service role key referenced across admin pages — bypasses all RLS
- **24 nextjs-server-action-exposure**: Server actions with no auth checks
- **19 missing-auth**: Unauthenticated API routes (email, freebies, webhooks)
- **10 dangerously-set-inner-html**: XSS via unsanitized HTML
- **5 secrets-in-urls**: API keys in URL query params (logged everywhere)
- **3 client-bundle-secrets**: API keys visible in DevTools
- **2 session-fixation**: Logout doesn't destroy sessions

### 2. content-drop — 46 critical
- **40 missing-auth**: Admin API routes (disk, funnel, media, social) have no auth
- **1 race-condition**: Check-then-update on social publish balance without lock
- **2 dangerously-set-inner-html**: XSS vectors in layout and library browser

### 3. Storefront — 21 critical
- **20 nextjs-server-action-exposure**: All Printify server actions have no auth
- **1 sensitive-browser-storage**: Sensitive data in browser storage

### 4. homiedex — 32 critical (10 open issues)
- **22 nextjs-server-action-exposure**: Profile and admin actions exposed
- **1 exposed-secrets**: Database URL with credentials in source code
- **1 insecure-randomness**: Math.random() used in keyboard navigation
- **1 dangerously-set-inner-html**: XSS in JSON-LD component

### 5. stitch-alchemy — 74 critical
- **74 no-input-validation**: Massive innerHTML usage across HTML files — XSS everywhere

### 6. saas-starter — 18 critical
- **7 nextjs-server-action-exposure**: Login/payment actions unprotected
- **3 hardcoded-credentials**: Passwords in schema/seed/setup
- **1 exposed-secrets**: DB URL with credentials
- **1 stripe-webhook-no-verify**: Stripe webhook doesn't verify signature

### 7. Skool-Forge — 8 critical
- **4 missing-gitignore**: .env not gitignored
- **3 secrets-in-urls**: Gemini API key in URL params

### 8. second-brain-system / sierrabakerconsulting — 4 critical each
- **missing-gitignore**: .env files not in .gitignore

## Clean Repos (0 critical findings)
screenshot-pools, a-silly-idea, da-video-tool, photo-organizer-da, Jiggle-Room,
digital-alchemy-bot, vibeshot, vibeshot2, VIDEOANALYZERGOOGLE, 234, DESI, biz-agent,
magic-erase, sref-scanner, ShadowPlay, electric-plasma-portfolio, new-genny,
remotion-cinematic, telegram-clipboard, file-manager, new-folder-portfolio,
new-folder-docs, brand-verticals-studio, midjourney-agent, chatgpt-data-analysis,
da-tonight-video, Chromatic-Illusion-Weaponizerr, percolator-class-guide,
myfirstdeploy, vvprivacypolicy, landingpage

## Recommended Immediate Actions

1. **digitalalchemy-dev**: Remove supabase service_role key from all client-side code. Move to server-only module. Add auth middleware to server actions.
2. **content-drop**: Add authentication to all /api/admin/* routes immediately.
3. **Storefront**: Add auth checks to Printify server actions before going live.
4. **saas-starter**: Remove hardcoded credentials from schema/seed files. Verify Stripe webhook signature.
5. **Skool-Forge + second-brain-system + sierrabakerconsulting**: Add `.env` to `.gitignore` and rotate any committed secrets.
6. **All repos with dangerouslySetInnerHTML**: Add DOMPurify or equivalent sanitization.
