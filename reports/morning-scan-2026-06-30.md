# Vibe Audit Morning Scan
**Tuesday, June 30, 2026** | 11 repos scanned | 148 skipped | 305.5s

## Portfolio Health

| Grade | Count | |
|-------|-------|-|
| A | 5 | Clean |
| B | 1 | Minor warnings |
| C | 1 | Multiple warnings |
| D | 1 | Many warnings |
| F | 3 | Critical findings |

**Total: 97 criticals, 80 warnings across 11 repos**

## All Results

| Repo | Grade | Critical | Warning | Info |
|------|-------|----------|---------|------|
| jackdog668/vibeaudit | F | 62 | 26 | 0 |
| jackdog668/vibe-vocab | F | 1 | 3 | 0 |
| jackdog668/Siftly | F | 34 | 41 | 1 |
| jackdog668/a-silly-idea | D | 0 | 7 | 0 |
| jackdog668/sierrabakerconsulting | C | 0 | 2 | 0 |
| jackdog668/da-video-tool | B | 0 | 1 | 0 |
| jackdog668/second-brain-system | A | 0 | 0 | 0 |
| jackdog668/percolator-class-guide | A | 0 | 0 | 0 |
| jackdog668/myfirstdeploy | A | 0 | 0 | 0 |
| jackdog668/photo-organizer-da | A | 0 | 0 | 0 |
| jackdog668/vibe-tracker | A | 0 | 0 | 0 |

## Critical Findings (action required)

### jackdog668/vibeaudit — Grade F
- **nextjs-server-action-exposure**: Server action "hasDirective" has no authentication check. Anyone can call it. (src/context.js:33)
- **nextjs-server-action-exposure**: Server action "hasUseClient" has no authentication check. Anyone can call it. (src/context.js:50)
- **nextjs-server-action-exposure**: Server action "hasUseServer" has no authentication check. Anyone can call it. (src/context.js:55)
- **nextjs-server-action-exposure**: Server action "isServerOnly" has no authentication check. Anyone can call it. (src/context.js:63)
- **nextjs-server-action-exposure**: Server action "isClient" has no authentication check. Anyone can call it. (src/context.js:81)
- **nextjs-server-action-exposure**: Server action "escapersFor" has no authentication check. Anyone can call it. (src/context.js:112)
- **nextjs-server-action-exposure**: Server action "escaperRegex" has no authentication check. Anyone can call it. (src/context.js:122)
- **nextjs-server-action-exposure**: Server action "isDesignedPublicKey" has no authentication check. Anyone can call it. (src/context.js:143)
- **stripe-webhook-no-verify**: Stripe webhook handler does not verify the signature — anyone can send fake events. (src/data/cwe-map.js:1)
- **open-database-rules**: Storage rules allow unrestricted access. Anyone on the internet can read/write your data. (src/data/prompts.js:167)
- **insecure-connections**: TLS certificate verification disabled (src/data/prompts.js:182)
- **nextjs-server-action-exposure**: Server action "getFixPrompt" has no authentication check. Anyone can call it. (src/data/prompts.js:472)
- **exposed-secrets**: Stripe test secret key found in source code. (tests/fixtures/.env:2)
- **exposed-secrets**: Database URL with credentials found in source code. (tests/fixtures/.env:3)
- **exposed-env-vars**: "VITE_SECRET_KEY" exposes a secret to the browser. The VITE_ prefix makes this variable public in your build output. (tests/fixtures/.env:1)
- **exposed-env-vars**: "NEXT_PUBLIC_STRIPE_SECRET" exposes a secret to the browser. The NEXT_PUBLIC_ prefix makes this variable public in your build output. (tests/fixtures/.env:2)
- **exposed-env-vars**: "NEXT_PUBLIC_STRIPE_SECRET" exposes a secret to the browser. The NEXT_PUBLIC_ prefix makes this variable public in your build output. (tests/fixtures/.env:2)
- **exposed-env-vars**: "REACT_APP_DATABASE_URL" exposes a secret to the browser. The REACT_APP_ prefix makes this variable public in your build output. (tests/fixtures/.env:3)
- **vercel-env-leak**: NEXT_PUBLIC_STRIPE_SECRET exposes a server-only secret to the browser. (tests/fixtures/.env:2)
- **exposed-secrets**: Stripe test secret key found in source code. (tests/fixtures/api/realistic-ecommerce.js:9)
- **idor-vulnerability**: Function "GET" uses a user-supplied ID without verifying ownership in the same function scope. (tests/fixtures/api/realistic-ecommerce.js:14)
- **unsafe-file-upload**: Function "uploadHandler" handles file uploads without type/size validation in scope. (tests/fixtures/api/realistic-ecommerce.js:45)
- **mass-assignment**: Function "POST" passes raw request body to a database operation without destructuring or schema validation first. (tests/fixtures/api/realistic-ecommerce.js:24)
- **race-condition**: Find-then-create race condition (possible duplicate) — concurrent requests can cause inconsistency. (tests/fixtures/api/realistic-ecommerce.js:13)
- **unverified-webhook**: Webhook handler does not verify the request signature. Anyone who knows the URL can send fake events (e.g., fake "payment succeeded"). (tests/fixtures/api/webhooks/stripe.js:2)
- **stripe-webhook-no-verify**: Stripe webhook handler does not verify the signature — anyone can send fake events. (tests/fixtures/api/webhooks/stripe.js:5)
- **open-database-rules**: Rule allows unrestricted access (if true). Anyone on the internet can read/write your data. (tests/fixtures/firestore.rules:5)
- **open-database-rules**: Storage rules allow unrestricted access. Anyone on the internet can read/write your data. (tests/fixtures/firestore.rules:5)
- **sensitive-browser-storage**: Sensitive data stored in browser storage — visible in DevTools → Application tab (tests/fixtures/src/components/Dashboard.jsx:18)
- **exposed-secrets**: Google API key found in source code. (tests/fixtures/vulnerable.js:4)
- **exposed-secrets**: Database URL with credentials found in source code. (tests/fixtures/vulnerable.js:6)
- **no-input-validation**: Direct innerHTML assignment with dynamic, unescaped value — potential XSS vector (tests/fixtures/vulnerable.js:14)
- **no-input-validation**: eval() with dynamic input — code injection risk (tests/fixtures/vulnerable.js:16)
- **no-input-validation**: SQL query built with string interpolation — SQL injection risk (tests/fixtures/vulnerable.js:18)
- **client-bundle-secrets**: API key hardcoded in client-side code — visible in DevTools Sources (tests/fixtures/vulnerable.js:4)
- **eval-usage**: eval() with dynamic argument — arbitrary code execution. (tests/fixtures/vulnerable.js:16)
- **exposed-env-vars**: "NEXT_PUBLIC_SECRET_KEY" exposes a secret to the browser. The NEXT_PUBLIC_ prefix makes this variable public in your build output. (tests/rules/devtools.test.js:37)
- **exposed-env-vars**: "NEXT_PUBLIC_SECRET" exposes a secret to the browser. The NEXT_PUBLIC_ prefix makes this variable public in your build output. (tests/rules/devtools.test.js:39)
- **client-bundle-secrets**: API key hardcoded in client-side code — visible in DevTools Sources (tests/rules/devtools.test.js:25)
- **client-bundle-secrets**: API key hardcoded in client-side code — visible in DevTools Sources (tests/rules/devtools.test.js:31)
- **sensitive-browser-storage**: Sensitive data stored in browser storage — visible in DevTools → Application tab (tests/rules/devtools.test.js:69)
- **sensitive-browser-storage**: Sensitive data stored in browser storage — visible in DevTools → Application tab (tests/rules/devtools.test.js:76)
- **exposed-secrets**: Google API key found in source code. (tests/rules/edge-cases.test.js:56)
- **exposed-secrets**: OpenAI project API key found in source code. (tests/rules/edge-cases.test.js:124)
- **exposed-secrets**: Anthropic API key found in source code. (tests/rules/edge-cases.test.js:129)
- **exposed-secrets**: Private key found in source code. (tests/rules/edge-cases.test.js:134)
- **exposed-secrets**: Google API key found in source code. (tests/rules/edge-cases.test.js:208)
- **exposed-secrets**: Stripe test secret key found in source code. (tests/rules/edge-cases.test.js:215)
- **exposed-secrets**: Database URL with credentials found in source code. (tests/rules/regression-false-positives.test.js:198)
- **exposed-env-vars**: "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY" exposes a secret to the browser. The NEXT_PUBLIC_ prefix makes this variable public in your build output. (tests/rules/regression-false-positives.test.js:51)
- **exposed-env-vars**: "NEXT_PUBLIC_STRIPE_SECRET" exposes a secret to the browser. The NEXT_PUBLIC_ prefix makes this variable public in your build output. (tests/rules/regression-false-positives.test.js:198)
- **exposed-env-vars**: "NEXT_PUBLIC_STRIPE_SECRET" exposes a secret to the browser. The NEXT_PUBLIC_ prefix makes this variable public in your build output. (tests/rules/regression-false-positives.test.js:198)
- **exposed-env-vars**: "REACT_APP_DATABASE_URL" exposes a secret to the browser. The REACT_APP_ prefix makes this variable public in your build output. (tests/rules/regression-false-positives.test.js:198)
- **no-input-validation**: Direct innerHTML assignment with dynamic, unescaped value — potential XSS vector (tests/rules/regression-false-positives.test.js:112)
- **exposed-secrets**: Google API key found in source code. (tests/rules/rules.test.js:45)
- **exposed-secrets**: Google API key found in source code. (tests/rules/rules.test.js:46)
- **exposed-secrets**: Google API key found in source code. (tests/rules/rules.test.js:56)
- **exposed-secrets**: Google API key found in source code. (tests/rules/rules.test.js:57)
- **open-database-rules**: Storage rules allow unrestricted access. Anyone on the internet can read/write your data. (tests/rules/rules.test.js:130)
- **exposed-env-vars**: "NEXT_PUBLIC_SECRET_KEY" exposes a secret to the browser. The NEXT_PUBLIC_ prefix makes this variable public in your build output. (tests/rules/v2-rules.test.js:106)
- **no-input-validation**: eval() with dynamic input — code injection risk (tests/rules/v2-rules.test.js:324)
- **client-bundle-secrets**: API key hardcoded in client-side code — visible in DevTools Sources (tests/rules/v2-rules.test.js:347)

### jackdog668/vibe-vocab — Grade F
- **exposed-env-vars**: "VITE_DATABASE_URL" exposes a secret to the browser. The VITE_ prefix makes this variable public in your build output. (src/lib/db.ts:5)

### jackdog668/Siftly — Grade F
- **missing-auth**: Exported GET handler has no authentication check. (app/api/analyze/images/route.ts:8)
- **missing-auth**: Exported POST handler has no authentication check. (app/api/analyze/images/route.ts:17)
- **missing-auth**: Exported PUT handler has no authentication check. (app/api/bookmarks/[id]/categories/route.ts:5)
- **missing-auth**: Exported DELETE handler has no authentication check. (app/api/bookmarks/route.ts:14)
- **missing-auth**: Exported GET handler has no authentication check. (app/api/bookmarks/route.ts:33)
- **missing-auth**: Exported GET handler has no authentication check. (app/api/categories/[slug]/route.ts:17)
- **missing-auth**: Exported DELETE handler has no authentication check. (app/api/categories/[slug]/route.ts:116)
- **missing-auth**: Exported GET handler has no authentication check. (app/api/categories/route.ts:15)
- **missing-auth**: Exported POST handler has no authentication check. (app/api/categories/route.ts:51)
- **race-condition**: Find-then-create race condition (possible duplicate) — concurrent requests can cause inconsistency. (app/api/categories/route.ts:84)
- **missing-auth**: Next.js route handler found with no authentication check in file. (app/api/categorize/route.ts:72)
- **missing-auth**: Next.js route handler found with no authentication check in file. (app/api/categorize/route.ts:85)
- **missing-auth**: Next.js route handler found with no authentication check in file. (app/api/categorize/route.ts:98)
- **missing-auth**: Exported GET handler has no authentication check. (app/api/export/route.ts:4)
- **missing-auth**: Exported POST handler has no authentication check. (app/api/export/route.ts:99)
- **missing-auth**: Exported OPTIONS handler has no authentication check. (app/api/import/bookmarklet/route.ts:17)
- **missing-auth**: Exported POST handler has no authentication check. (app/api/import/bookmarklet/route.ts:92)
- **missing-auth**: Exported GET handler has no authentication check. (app/api/import/live/route.ts:6)
- **missing-auth**: Exported POST handler has no authentication check. (app/api/import/live/route.ts:30)
- **missing-auth**: Exported DELETE handler has no authentication check. (app/api/import/live/route.ts:97)
- **missing-auth**: Exported POST handler has no authentication check. (app/api/import/live/sync/route.ts:6)
- **missing-auth**: Exported POST handler has no authentication check. (app/api/import/route.ts:5)
- **unsafe-file-upload**: Function "POST" handles file uploads without type/size validation in scope. (app/api/import/route.ts:5)
- **race-condition**: Check-then-update on balance/inventory without lock — concurrent requests can cause inconsistency. (app/api/import/route.ts:74)
- **missing-auth**: Next.js route handler found with no authentication check in file. (app/api/import/twitter/route.ts:213)
- **missing-auth**: Exported GET handler has no authentication check. (app/api/link-preview/route.ts:69)
- **missing-auth**: Exported GET handler has no authentication check. (app/api/media/route.ts:34)
- **missing-auth**: Exported GET handler has no authentication check. (app/api/mindmap/route.ts:185)
- **missing-auth**: Next.js route handler found with no authentication check in file. (app/api/search/ai/route.ts:184)
- **missing-auth**: Exported GET handler has no authentication check. (app/api/settings/route.ts:15)
- **missing-auth**: Exported POST handler has no authentication check. (app/api/settings/route.ts:36)
- **missing-auth**: Exported DELETE handler has no authentication check. (app/api/settings/route.ts:87)
- **missing-auth**: Exported GET handler has no authentication check. (app/api/stats/route.ts:4)
- **nextjs-middleware-bypass**: Middleware file contains no authentication or redirect logic. (middleware.ts:1)

## Warnings

### jackdog668/a-silly-idea — Grade D
- **insecure-error-handling**: Empty catch block — errors silently swallowed (app.js:682)
- **insecure-error-handling**: Empty catch block — errors silently swallowed (app.js:687)
- **insecure-error-handling**: Empty catch block — errors silently swallowed (app.js:692)
- **insecure-error-handling**: Empty catch block — errors silently swallowed (app.js:693)
- **clickjacking**: Headers are configured but X-Frame-Options/frame-ancestors is missing — vulnerable to clickjacking. (app.js:949)
- **insecure-connections**: Non-localhost HTTP URL — data sent unencrypted (index.html:16)
- **insecure-connections**: Non-localhost HTTP URL — data sent unencrypted (styles.css:75)

### jackdog668/sierrabakerconsulting — Grade C
- **missing-security-headers**: Config file is missing security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy (vercel.json:1)
- **deployment-config-insecure**: vercel.json has no security headers configured. (vercel.json:1)

### jackdog668/da-video-tool — Grade B
- **missing-security-headers**: Config file is missing security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy (vite.config.ts:1)

## Clean Repos (Grade A)

- jackdog668/second-brain-system
- jackdog668/percolator-class-guide
- jackdog668/myfirstdeploy
- jackdog668/photo-organizer-da
- jackdog668/vibe-tracker

## Skipped Repos

- jackdog668/screenshot-pools: Not found / empty
- jackdog668/generator20x: Not found / empty
- jackdog668/sierra-baker-starter: Not found / empty
- jackdog668/digitalalchemy-dev: Not found / empty
- jackdog668/Storefront: Not found / empty
- jackdog668/epic-meitner: Not found / empty
- jackdog668/content-drop: Not found / empty
- jackdog668/homiedex: Not found / empty
- jackdog668/Skool-Forge: Not found / empty
- jackdog668/transformersgenerator: Not found / empty
- jackdog668/shownotes1: Not found / empty
- jackdog668/runofshow: Not found / empty
- jackdog668/shownotes2: Not found / empty
- jackdog668/shownotes4: Not found / empty
- jackdog668/shownotes5: Not found / empty
- jackdog668/shownotes3: Not found / empty
- jackdog668/Digital-Alchemy-Skool: Not found / empty
- jackdog668/tonightlesson2: Not found / empty
- jackdog668/shownotes6: Not found / empty
- jackdog668/thisone: Not found / empty
- jackdog668/thisone2: Not found / empty
- jackdog668/meet-corekind-digital-alchemy: Not found / empty
- jackdog668/joyful-tesla: Not found / empty
- jackdog668/curious-labs-vol1: Not found / empty
- jackdog668/chromatic-illusion-weaponizer: Not found / empty
- jackdog668/digital-alchemy-freebies: Not found / empty
- jackdog668/outputs: Not found / empty
- jackdog668/file-manager: Not found / empty
- jackdog668/Digital-Alchemy-Command-Center: Not found / empty
- jackdog668/landingpage: Not found / empty
- jackdog668/da-tonight-video: Not found / empty
- jackdog668/Agent-Factory: Not found / empty
- jackdog668/Digital-Alchemy: Not found / empty
- jackdog668/ericananton: Not found / empty
- jackdog668/prototype: Not found / empty
- jackdog668/magic-erase: Not found / empty
- jackdog668/content-idea-generator34: Not found / empty
- jackdog668/content-idea-generator342: Not found / empty
- jackdog668/lovepixel-sticker-studio: Not found / empty
- jackdog668/chatgpt-data-analysis: Not found / empty
- jackdog668/Digital-Alchemy-Tracker: Not found / empty
- jackdog668/stitch-alchemy: Not found / empty
- jackdog668/firecrawl-site-insight: Not found / empty
- jackdog668/blazing-schrodinger: Not found / empty
- jackdog668/digital-alchemy-bot: Not found / empty
- jackdog668/groundwork-collective: Not found / empty
- jackdog668/video-alchemy: Not found / empty
- jackdog668/234: Rate limited
- jackdog668/DESI: Rate limited
- jackdog668/qr-forge-pro: Rate limited
- jackdog668/digital-alchemy-lab: Not found / empty
- jackdog668/the-77: Not found / empty
- jackdog668/100-day-app-challenge: Not found / empty
- jackdog668/sticker-banner-lab: Not found / empty
- jackdog668/video-analyzer-70: Not found / empty
- jackdog668/brand-verticals-studio: Not found / empty
- jackdog668/jazz-roots-explorer: Not found / empty
- jackdog668/sec-context: Not found / empty
- jackdog668/collab-connect: Not found / empty
- jackdog668/IdeaToPRD-with-Gemini: Not found / empty
- jackdog668/Jiggle-Room: Not found / empty
- jackdog668/reddit-analyzer: Not found / empty
- jackdog668/VIDEOANALYZERGOOGLE: Not found / empty
- jackdog668/vibeshot2: Not found / empty
- jackdog668/vibeshot: Not found / empty
- jackdog668/video2: Not found / empty
- jackdog668/chibi-forge: Not found / empty
- jackdog668/carver-s-garden-companion: Not found / empty
- jackdog668/panther-chicago-legacy: Not found / empty
- jackdog668/lucky-leaf-finder: Not found / empty
- jackdog668/harriet-s-path: Not found / empty
- jackdog668/new-folder-portfolio: Not found / empty
- jackdog668/htmlchange: Not found / empty
- jackdog668/jackdog668.github.io: Not found / empty
- jackdog668/digitalalchemy-vibecode: Not found / empty
- jackdog668/my-twitter-export: Not found / empty
- jackdog668/Petty-Translator: Not found / empty
- jackdog668/ineeditall: Not found / empty
- jackdog668/catdog: Not found / empty
- jackdog668/literate-garbanzo: Not found / empty
- jackdog668/fuzzy-octo-fishstick: Not found / empty
- jackdog668/reimagined-octo-funicular: Not found / empty
- jackdog668/educational-resources: Not found / empty
- jackdog668/revenue-cat-contest: Not found / empty
- jackdog668/ansel: Not found / empty
- jackdog668/new-folder-docs: Not found / empty
- jackdog668/new-app: Not found / empty
- jackdog668/cursing-woman: Not found / empty
- jackdog668/alchemic-generator-v2: Not found / empty
- jackdog668/day-6-bloodbank-charles-drew: Not found / empty
- jackdog668/1code-main: Not found / empty
- jackdog668/100-day-redo: Not found / empty
- jackdog668/day-5-toothfairy-ai: Not found / empty
- jackdog668/day-3-stackroller: Not found / empty
- jackdog668/digital-alchemy-os: Not found / empty
- jackdog668/biz-agent: Not found / empty
- jackdog668/remotion-cinematic: Not found / empty
- jackdog668/permission-to-play: Not found / empty
- jackdog668/reminderapp: Not found / empty
- jackdog668/100DayAppChallenge: Not found / empty
- jackdog668/vvprivacypolicy: Not found / empty
- jackdog668/ai-agent-configs: Not found / empty
- jackdog668/This-Day-in-Black-Excellence: Not found / empty
- jackdog668/digital-alchemy-app: Not found / empty
- jackdog668/grainrad-bulk: Not found / empty
- jackdog668/Content-Hook-Generator: Not found / empty
- jackdog668/social-media-scraping-apis: Rate limited
- jackdog668/LovePixel-Final: Rate limited
- jackdog668/video-analyzer: Rate limited
- jackdog668/my-daily-yes: Rate limited
- jackdog668/Love-Pixel-Stickers: Rate limited
- jackdog668/chroma-flow: Rate limited
- jackdog668/da-forge-x7k9m2: Not found / empty
- jackdog668/melanin-patch-app: Not found / empty
- jackdog668/ui-forge-command-center: Not found / empty
- jackdog668/telegram-clipboard: Not found / empty
- jackdog668/node-banana: Not found / empty
- jackdog668/node-banana-bear: Not found / empty
- jackdog668/ruby-feynman: Not found / empty
- jackdog668/ruby-magnetosphere: Not found / empty
- jackdog668/resonant-halley: Not found / empty
- jackdog668/infrared-hypernova: Not found / empty
- jackdog668/demo-carousel: Not found / empty
- jackdog668/exo-spirit: Not found / empty
- jackdog668/promptdatabasev3: Not found / empty
- jackdog668/stream-gamify: Not found / empty
- jackdog668/deep-radiation: Not found / empty
- jackdog668/midjourney-agent: Not found / empty
- jackdog668/hackspark: Not found / empty
- jackdog668/portfolio-website-v2: Not found / empty
- jackdog668/app-replay-forge: Not found / empty
- jackdog668/alchemic-generator: Not found / empty
- jackdog668/echoos: Not found / empty
- jackdog668/sref-scanner: Not found / empty
- jackdog668/ShadowPlay: Not found / empty
- jackdog668/new-genny: Not found / empty
- jackdog668/electric-plasma-portfolio: Not found / empty
- jackdog668/digital-alchemy-dashboard: Not found / empty
- jackdog668/AetherExWork: Not found / empty
- jackdog668/CreatorColorLine: Not found / empty
- jackdog668/notebooklm-mcp: Not found / empty
- jackdog668/crypto-101: Not found / empty
- jackdog668/saas-starter: Not found / empty
- jackdog668/awesome-nanobanana-pro: Not found / empty
- jackdog668/Chromatic-Illusion-Weaponizerr: Not found / empty
- jackdog668/chromtic-weaponizer: Not found / empty
- jackdog668/Super-Banana: Not found / empty
- jackdog668/stitch-alchemy: Not found / empty

---
*Generated by Vibe Audit v1.1.0 — 2026-06-30T14:23:21.333Z*
