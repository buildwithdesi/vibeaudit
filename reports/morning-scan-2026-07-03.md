# Vibe Audit Morning Scan
**Friday, July 3, 2026** | 10 repos scanned | 149 skipped | 155.1s

## Portfolio Health

| Grade | Count | |
|-------|-------|-|
| A | 6 | Clean |
| B | 0 | Minor warnings |
| C | 1 | Multiple warnings |
| D | 1 | Many warnings |
| F | 2 | Critical findings |

**Total: 36 criticals, 55 warnings across 10 repos**

## All Results

| Repo | Grade | Critical | Warning | Info |
|------|-------|----------|---------|------|
| jackdog668/vibe-vocab | F | 2 | 3 | 0 |
| jackdog668/Siftly | F | 34 | 42 | 1 |
| jackdog668/a-silly-idea | D | 0 | 7 | 0 |
| jackdog668/sierrabakerconsulting | C | 0 | 3 | 0 |
| jackdog668/second-brain-system | A | 0 | 0 | 0 |
| jackdog668/vibeaudit | A | 0 | 0 | 0 |
| jackdog668/percolator-class-guide | A | 0 | 0 | 0 |
| jackdog668/myfirstdeploy | A | 0 | 0 | 0 |
| jackdog668/photo-organizer-da | A | 0 | 0 | 0 |
| jackdog668/vibe-tracker | A | 0 | 0 | 0 |

## Critical Findings (action required)

### jackdog668/vibe-vocab — Grade F
- **exposed-env-vars**: "VITE_DATABASE_URL" exposes a secret to the browser. The VITE_ prefix makes this variable public in your build output. (src/lib/db.ts:5)
- **vercel-env-leak**: VITE_DATABASE_URL exposes a server-only secret to the browser. (src/lib/db.ts:5)

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
- **insecure-connections**: Non-localhost HTTP URL — data sent unencrypted (index.html:7)
- **missing-security-headers**: Config file is missing security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy (vercel.json:1)
- **deployment-config-insecure**: vercel.json has no security headers configured. (vercel.json:1)

## Clean Repos (Grade A)

- jackdog668/second-brain-system
- jackdog668/vibeaudit
- jackdog668/percolator-class-guide
- jackdog668/myfirstdeploy
- jackdog668/photo-organizer-da
- jackdog668/vibe-tracker

## Skipped Repos

- jackdog668/generator20x: Not found / empty
- jackdog668/screenshot-pools: Not found / empty
- jackdog668/sierra-baker-starter: Not found / empty
- jackdog668/digitalalchemy-dev: Not found / empty
- jackdog668/Storefront: Not found / empty
- jackdog668/epic-meitner: Not found / empty
- jackdog668/homiedex: Not found / empty
- jackdog668/content-drop: Not found / empty
- jackdog668/Skool-Forge: Not found / empty
- jackdog668/transformersgenerator: Not found / empty
- jackdog668/runofshow: Not found / empty
- jackdog668/shownotes1: Not found / empty
- jackdog668/shownotes2: Not found / empty
- jackdog668/shownotes3: Not found / empty
- jackdog668/shownotes5: Not found / empty
- jackdog668/shownotes4: Not found / empty
- jackdog668/shownotes6: Not found / empty
- jackdog668/tonightlesson2: Not found / empty
- jackdog668/Digital-Alchemy-Skool: Not found / empty
- jackdog668/thisone2: Not found / empty
- jackdog668/thisone: Not found / empty
- jackdog668/curious-labs-vol1: Not found / empty
- jackdog668/meet-corekind-digital-alchemy: Not found / empty
- jackdog668/joyful-tesla: Not found / empty
- jackdog668/chromatic-illusion-weaponizer: Not found / empty
- jackdog668/outputs: Not found / empty
- jackdog668/digital-alchemy-freebies: Not found / empty
- jackdog668/da-video-tool: Not found / empty
- jackdog668/file-manager: Not found / empty
- jackdog668/Digital-Alchemy-Command-Center: Not found / empty
- jackdog668/da-tonight-video: Not found / empty
- jackdog668/landingpage: Not found / empty
- jackdog668/Digital-Alchemy: Not found / empty
- jackdog668/ericananton: Not found / empty
- jackdog668/Agent-Factory: Not found / empty
- jackdog668/magic-erase: Not found / empty
- jackdog668/prototype: Not found / empty
- jackdog668/content-idea-generator342: Not found / empty
- jackdog668/content-idea-generator34: Not found / empty
- jackdog668/Digital-Alchemy-Tracker: Not found / empty
- jackdog668/chatgpt-data-analysis: Not found / empty
- jackdog668/lovepixel-sticker-studio: Not found / empty
- jackdog668/firecrawl-site-insight: Not found / empty
- jackdog668/blazing-schrodinger: Not found / empty
- jackdog668/stitch-alchemy: Not found / empty
- jackdog668/groundwork-collective: Rate limited
- jackdog668/digital-alchemy-bot: Not found / empty
- jackdog668/video-alchemy: Not found / empty
- jackdog668/234: Not found / empty
- jackdog668/qr-forge-pro: Not found / empty
- jackdog668/DESI: Not found / empty
- jackdog668/the-77: Not found / empty
- jackdog668/digital-alchemy-lab: Not found / empty
- jackdog668/100-day-app-challenge: Not found / empty
- jackdog668/sticker-banner-lab: Not found / empty
- jackdog668/video-analyzer-70: Not found / empty
- jackdog668/brand-verticals-studio: Not found / empty
- jackdog668/jazz-roots-explorer: Not found / empty
- jackdog668/collab-connect: Not found / empty
- jackdog668/sec-context: Not found / empty
- jackdog668/Jiggle-Room: Not found / empty
- jackdog668/IdeaToPRD-with-Gemini: Not found / empty
- jackdog668/vibeshot2: Not found / empty
- jackdog668/reddit-analyzer: Not found / empty
- jackdog668/VIDEOANALYZERGOOGLE: Not found / empty
- jackdog668/video2: Not found / empty
- jackdog668/vibeshot: Not found / empty
- jackdog668/chibi-forge: Not found / empty
- jackdog668/lucky-leaf-finder: Not found / empty
- jackdog668/panther-chicago-legacy: Not found / empty
- jackdog668/carver-s-garden-companion: Not found / empty
- jackdog668/htmlchange: Not found / empty
- jackdog668/harriet-s-path: Not found / empty
- jackdog668/new-folder-portfolio: Not found / empty
- jackdog668/my-twitter-export: Not found / empty
- jackdog668/jackdog668.github.io: Not found / empty
- jackdog668/digitalalchemy-vibecode: Not found / empty
- jackdog668/ineeditall: Not found / empty
- jackdog668/catdog: Not found / empty
- jackdog668/Petty-Translator: Not found / empty
- jackdog668/reimagined-octo-funicular: Not found / empty
- jackdog668/literate-garbanzo: Not found / empty
- jackdog668/fuzzy-octo-fishstick: Not found / empty
- jackdog668/revenue-cat-contest: Not found / empty
- jackdog668/educational-resources: Not found / empty
- jackdog668/ansel: Not found / empty
- jackdog668/new-folder-docs: Not found / empty
- jackdog668/new-app: Not found / empty
- jackdog668/cursing-woman: Not found / empty
- jackdog668/alchemic-generator-v2: Not found / empty
- jackdog668/1code-main: Not found / empty
- jackdog668/day-6-bloodbank-charles-drew: Not found / empty
- jackdog668/day-3-stackroller: Not found / empty
- jackdog668/day-5-toothfairy-ai: Not found / empty
- jackdog668/100-day-redo: Not found / empty
- jackdog668/digital-alchemy-os: Not found / empty
- jackdog668/remotion-cinematic: Not found / empty
- jackdog668/biz-agent: Not found / empty
- jackdog668/permission-to-play: Not found / empty
- jackdog668/100DayAppChallenge: Not found / empty
- jackdog668/reminderapp: Not found / empty
- jackdog668/This-Day-in-Black-Excellence: Not found / empty
- jackdog668/ai-agent-configs: Not found / empty
- jackdog668/vvprivacypolicy: Not found / empty
- jackdog668/grainrad-bulk: Not found / empty
- jackdog668/digital-alchemy-app: Not found / empty
- jackdog668/Content-Hook-Generator: Not found / empty
- jackdog668/video-analyzer: Rate limited
- jackdog668/social-media-scraping-apis: Rate limited
- jackdog668/LovePixel-Final: Rate limited
- jackdog668/my-daily-yes: Not found / empty
- jackdog668/chroma-flow: Not found / empty
- jackdog668/Love-Pixel-Stickers: Not found / empty
- jackdog668/da-forge-x7k9m2: Not found / empty
- jackdog668/ui-forge-command-center: Not found / empty
- jackdog668/melanin-patch-app: Not found / empty
- jackdog668/telegram-clipboard: Not found / empty
- jackdog668/node-banana: Not found / empty
- jackdog668/node-banana-bear: Not found / empty
- jackdog668/ruby-feynman: Not found / empty
- jackdog668/ruby-magnetosphere: Not found / empty
- jackdog668/resonant-halley: Not found / empty
- jackdog668/demo-carousel: Not found / empty
- jackdog668/exo-spirit: Not found / empty
- jackdog668/infrared-hypernova: Not found / empty
- jackdog668/stream-gamify: Not found / empty
- jackdog668/deep-radiation: Not found / empty
- jackdog668/promptdatabasev3: Not found / empty
- jackdog668/portfolio-website-v2: Not found / empty
- jackdog668/midjourney-agent: Not found / empty
- jackdog668/hackspark: Not found / empty
- jackdog668/alchemic-generator: Not found / empty
- jackdog668/app-replay-forge: Not found / empty
- jackdog668/echoos: Not found / empty
- jackdog668/new-genny: Not found / empty
- jackdog668/ShadowPlay: Not found / empty
- jackdog668/sref-scanner: Not found / empty
- jackdog668/electric-plasma-portfolio: Not found / empty
- jackdog668/digital-alchemy-dashboard: Not found / empty
- jackdog668/AetherExWork: Not found / empty
- jackdog668/CreatorColorLine: Not found / empty
- jackdog668/crypto-101: Not found / empty
- jackdog668/notebooklm-mcp: Not found / empty
- jackdog668/saas-starter: Not found / empty
- jackdog668/awesome-nanobanana-pro: Not found / empty
- jackdog668/Chromatic-Illusion-Weaponizerr: Not found / empty
- jackdog668/stitch-alchemy: Not found / empty
- jackdog668/Super-Banana: Not found / empty
- jackdog668/chromtic-weaponizer: Not found / empty

---
*Generated by Vibe Audit v1.1.0 — 2026-07-03T14:05:42.584Z*
