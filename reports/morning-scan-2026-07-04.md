# Vibe Audit Morning Scan
**Saturday, July 4, 2026** | 11 repos scanned | 152 skipped | 18.4s

## Portfolio Health

| Grade | Count | |
|-------|-------|-|
| A | 5 | Clean |
| B | 1 | Minor warnings |
| C | 1 | Multiple warnings |
| D | 2 | Many warnings |
| F | 2 | Critical findings |

**Total: 36 criticals, 170 warnings across 11 repos**

## All Results

| Repo | Grade | Critical | Warning | Info |
|------|-------|----------|---------|------|
| jackdog668/Siftly | F | 34 | 141 | 2 |
| jackdog668/vibe-vocab | F | 2 | 8 | 1 |
| jackdog668/sierrabakerconsulting | D | 0 | 5 | 0 |
| jackdog668/a-silly-idea | D | 0 | 13 | 0 |
| jackdog668/percolator-class-guide | C | 0 | 2 | 0 |
| jackdog668/myfirstdeploy | B | 0 | 1 | 0 |
| jackdog668/vibeaudit | A | 0 | 0 | 0 |
| jackdog668/vibe-tracker | A | 0 | 0 | 0 |
| jackdog668/jackdog668 | A | 0 | 0 | 0 |
| jackdog668/photo-organizer-da | A | 0 | 0 | 0 |
| jackdog668/second-brain-system | A | 0 | 0 | 0 |

## Critical Findings (action required)

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

### jackdog668/vibe-vocab — Grade F
- **exposed-env-vars**: "VITE_DATABASE_URL" exposes a secret to the browser. The VITE_ prefix makes this variable public in your build output. (src/lib/db.ts:5)
- **vercel-env-leak**: VITE_DATABASE_URL exposes a server-only secret to the browser. (src/lib/db.ts:5)

## Warnings

### jackdog668/sierrabakerconsulting — Grade D
- **missing-sri**: External stylesheet loaded from a CDN with no integrity hash — if that CDN is compromised, it runs arbitrary code in your users' browsers and you can't tell. (dealers.html:8)
- **insecure-connections**: Non-localhost HTTP URL — data sent unencrypted (index.html:7)
- **missing-sri**: External stylesheet loaded from a CDN with no integrity hash — if that CDN is compromised, it runs arbitrary code in your users' browsers and you can't tell. (index.html:8)
- **missing-security-headers**: Config file is missing security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy (vercel.json:1)
- **deployment-config-insecure**: vercel.json has no security headers configured. (vercel.json:1)

### jackdog668/a-silly-idea — Grade D
- **insecure-error-handling**: Empty catch block — errors silently swallowed (app.js:682)
- **insecure-error-handling**: Empty catch block — errors silently swallowed (app.js:687)
- **insecure-error-handling**: Empty catch block — errors silently swallowed (app.js:692)
- **insecure-error-handling**: Empty catch block — errors silently swallowed (app.js:693)
- **clickjacking**: Headers are configured but X-Frame-Options/frame-ancestors is missing — vulnerable to clickjacking. (app.js:949)
- **insecure-connections**: Non-localhost HTTP URL — data sent unencrypted (index.html:16)
- **missing-sri**: External stylesheet loaded from a CDN with no integrity hash — if that CDN is compromised, it runs arbitrary code in your users' browsers and you can't tell. (index.html:21)
- **perf-no-await-parallel**: await inside a loop runs each iteration one-at-a-time. If the iterations are independent, they should run in parallel. (scripts/backfill-embeddings.js:57)
- **perf-no-await-parallel**: await inside a loop runs each iteration one-at-a-time. If the iterations are independent, they should run in parallel. (scripts/backfill-embeddings.js:64)
- **perf-no-await-parallel**: await inside a loop runs each iteration one-at-a-time. If the iterations are independent, they should run in parallel. (scripts/backfill-embeddings.js:80)
- **perf-no-await-parallel**: await inside a loop runs each iteration one-at-a-time. If the iterations are independent, they should run in parallel. (scripts/backfill-embeddings.js:83)
- **perf-no-await-parallel**: await inside a loop runs each iteration one-at-a-time. If the iterations are independent, they should run in parallel. (scripts/backfill-embeddings.js:94)
- **insecure-connections**: Non-localhost HTTP URL — data sent unencrypted (styles.css:75)

### jackdog668/percolator-class-guide — Grade C
- **missing-sri**: External stylesheet loaded from a CDN with no integrity hash — if that CDN is compromised, it runs arbitrary code in your users' browsers and you can't tell. (index.html:7)
- **missing-sri**: External script loaded from a CDN with no integrity hash — if that CDN is compromised, it runs arbitrary code in your users' browsers and you can't tell. (index.html:620)

### jackdog668/myfirstdeploy — Grade B
- **missing-sri**: External stylesheet loaded from a CDN with no integrity hash — if that CDN is compromised, it runs arbitrary code in your users' browsers and you can't tell. (index.html:10)

## Clean Repos (Grade A)

- jackdog668/vibeaudit
- jackdog668/vibe-tracker
- jackdog668/jackdog668
- jackdog668/photo-organizer-da
- jackdog668/second-brain-system

## Skipped Repos

- jackdog668/Storefront: Auth required (private)
- jackdog668/Digital-Alchemy-Skool: Auth required (private)
- jackdog668/firecrawl-site-insight: Auth required (private)
- jackdog668/reddit-analyzer: Auth required (private)
- jackdog668/sticker-banner-lab: Auth required (private)
- jackdog668/100-day-redo: Auth required (private)
- jackdog668/carver-s-garden-companion: Auth required (private)
- jackdog668/literate-garbanzo: Auth required (private)
- jackdog668/fuzzy-octo-fishstick: Auth required (private)
- jackdog668/day-5-toothfairy-ai: Auth required (private)
- jackdog668/video-alchemy: Auth required (private)
- jackdog668/homiedex: Auth required (private)
- jackdog668/sref-scanner: Auth required (private)
- jackdog668/ineeditall: Auth required (private)
- jackdog668/shownotes5: Auth required (private)
- jackdog668/qr-forge-pro: Auth required (private)
- jackdog668/educational-resources: Auth required (private)
- jackdog668/echoos: Auth required (private)
- jackdog668/Petty-Translator: Auth required (private)
- jackdog668/meet-corekind-digital-alchemy: Auth required (private)
- jackdog668/curious-labs-vol1: Auth required (private)
- jackdog668/digitalalchemy-vibecode: Auth required (private)
- jackdog668/Jiggle-Room: Auth required (private)
- jackdog668/content-idea-generator34: Auth required (private)
- jackdog668/cursing-woman: Auth required (private)
- jackdog668/telegram-clipboard: Auth required (private)
- jackdog668/day-3-stackroller: Auth required (private)
- jackdog668/chromatic-illusion-weaponizer: Auth required (private)
- jackdog668/Skool-Forge: Auth required (private)
- jackdog668/shownotes6: Auth required (private)
- jackdog668/magic-erase: Auth required (private)
- jackdog668/prototype: Auth required (private)
- jackdog668/digital-alchemy-os: Auth required (private)
- jackdog668/new-folder-portfolio: Auth required (private)
- jackdog668/ruby-magnetosphere: Auth required (private)
- jackdog668/shownotes2: Auth required (private)
- jackdog668/chroma-flow: Auth required (private)
- jackdog668/100DayAppChallenge: Auth required (private)
- jackdog668/da-video-tool: Auth required (private)
- jackdog668/my-daily-yes: Auth required (private)
- jackdog668/generator20x: Auth required (private)
- jackdog668/jazz-roots-explorer: Auth required (private)
- jackdog668/LovePixel-Final: Auth required (private)
- jackdog668/seniornest-package: Auth required (private)
- jackdog668/da-forge-x7k9m2: Auth required (private)
- jackdog668/Agent-Factory: Auth required (private)
- jackdog668/file-manager: Auth required (private)
- jackdog668/melanin-patch-app: Auth required (private)
- jackdog668/remotion-cinematic: Auth required (private)
- jackdog668/collab-connect: Auth required (private)
- jackdog668/Digital-Alchemy: Auth required (private)
- jackdog668/outputs: Auth required (private)
- jackdog668/blazing-schrodinger: Auth required (private)
- jackdog668/sec-context: Auth required (private)
- jackdog668/video-analyzer: Auth required (private)
- jackdog668/vibeshot: Auth required (private)
- jackdog668/transformersgenerator: Auth required (private)
- jackdog668/app-replay-forge: Auth required (private)
- jackdog668/content-idea-generator342: Auth required (private)
- jackdog668/catdog: Auth required (private)
- jackdog668/da-tonight-video: Auth required (private)
- jackdog668/node-banana: Auth required (private)
- jackdog668/my-twitter-export: Auth required (private)
- jackdog668/joyful-tesla: Auth required (private)
- jackdog668/hackspark: Auth required (private)
- jackdog668/promptdatabasev3: Auth required (private)
- jackdog668/grainrad-bulk: Auth required (private)
- jackdog668/new-folder-docs: Auth required (private)
- jackdog668/exo-spirit: Auth required (private)
- jackdog668/biz-agent: Auth required (private)
- jackdog668/ai-agent-configs: Auth required (private)
- jackdog668/lucky-leaf-finder: Auth required (private)
- jackdog668/IdeaToPRD-with-Gemini: Auth required (private)
- jackdog668/awesome-nanobanana-pro: Auth required (private)
- jackdog668/AetherExWork: Auth required (private)
- jackdog668/jacki-mundra-starter: Auth required (private)
- jackdog668/tonightlesson2: Auth required (private)
- jackdog668/thisone2: Auth required (private)
- jackdog668/video2: Auth required (private)
- jackdog668/vibeshot2: Auth required (private)
- jackdog668/social-media-scraping-apis: Auth required (private)
- jackdog668/shownotes3: Auth required (private)
- jackdog668/electric-plasma-portfolio: Auth required (private)
- jackdog668/notebooklm-mcp: Auth required (private)
- jackdog668/Chromatic-Illusion-Weaponizerr: Auth required (private)
- jackdog668/demo-carousel: Auth required (private)
- jackdog668/new-app: Auth required (private)
- jackdog668/groundwork-collective: Auth required (private)
- jackdog668/234: Auth required (private)
- jackdog668/This-Day-in-Black-Excellence: Auth required (private)
- jackdog668/VIDEOANALYZERGOOGLE: Auth required (private)
- jackdog668/content-drop: Auth required (private)
- jackdog668/portfolio-website-v2: Auth required (private)
- jackdog668/100-day-app-challenge: Auth required (private)
- jackdog668/digital-alchemy-dashboard: Auth required (private)
- jackdog668/Super-Banana: Auth required (private)
- jackdog668/runofshow: Auth required (private)
- jackdog668/1code-main: Auth required (private)
- jackdog668/saas-starter: Auth required (private)
- jackdog668/lovepixel-sticker-studio: Auth required (private)
- jackdog668/reimagined-octo-funicular: Auth required (private)
- jackdog668/video-analyzer-70: Auth required (private)
- jackdog668/resonant-halley: Auth required (private)
- jackdog668/chatgpt-data-analysis: Auth required (private)
- jackdog668/ruby-feynman: Auth required (private)
- jackdog668/digital-alchemy-freebies: Auth required (private)
- jackdog668/shownotes4: Auth required (private)
- jackdog668/DESI: Auth required (private)
- jackdog668/new-genny: Auth required (private)
- jackdog668/stitch-alchemy: Auth required (private)
- jackdog668/Love-Pixel-Stickers: Auth required (private)
- jackdog668/crypto-101: Auth required (private)
- jackdog668/thisone: Auth required (private)
- jackdog668/ui-forge-command-center: Auth required (private)
- jackdog668/digital-alchemy-app: Auth required (private)
- jackdog668/harriet-s-path: Auth required (private)
- jackdog668/Digital-Alchemy-Command-Center: Auth required (private)
- jackdog668/digital-alchemy-bot: Auth required (private)
- jackdog668/carol-c3-branding-starter: Auth required (private)
- jackdog668/shownotes1: Auth required (private)
- jackdog668/the-77: Auth required (private)
- jackdog668/midjourney-agent: Auth required (private)
- jackdog668/ansel: Auth required (private)
- jackdog668/htmlchange: Auth required (private)
- jackdog668/jackdog668.github.io: Auth required (private)
- jackdog668/ericananton: Auth required (private)
- jackdog668/alchemic-generator: Auth required (private)
- jackdog668/panther-chicago-legacy: Auth required (private)
- jackdog668/digital-alchemy-lab: Auth required (private)
- jackdog668/Content-Hook-Generator: Auth required (private)
- jackdog668/landingpage: Auth required (private)
- jackdog668/alchemic-generator-v2: Auth required (private)
- jackdog668/revenue-cat-contest: Auth required (private)
- jackdog668/reminderapp: Auth required (private)
- jackdog668/epic-meitner: Auth required (private)
- jackdog668/Digital-Alchemy-Tracker: Auth required (private)
- jackdog668/sierra-baker-starter: Auth required (private)
- jackdog668/chibi-forge: Auth required (private)
- jackdog668/node-banana-bear: Auth required (private)
- jackdog668/infrared-hypernova: Auth required (private)
- jackdog668/day-6-bloodbank-charles-drew: Auth required (private)
- jackdog668/stream-gamify: Auth required (private)
- jackdog668/vvprivacypolicy: Auth required (private)
- jackdog668/chromtic-weaponizer: Auth required (private)
- jackdog668/ShadowPlay: Auth required (private)
- jackdog668/deep-radiation: Auth required (private)
- jackdog668/CreatorColorLine: Auth required (private)
- jackdog668/permission-to-play: Auth required (private)
- jackdog668/da-library: Auth required (private)
- jackdog668/screenshot-pools: Auth required (private)
- jackdog668/digitalalchemy-dev: Auth required (private)
- jackdog668/brand-verticals-studio: Auth required (private)

---
*Generated by Vibe Audit v1.1.0 — 2026-07-04T09:23:26.188Z*
