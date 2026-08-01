/**
 * Fix Prompts — Copy-paste prompts for every Vibe Audit rule.
 *
 * These prompts work across AI coding platforms:
 * - Claude Code (terminal, full file access)
 * - Google AI Studio / Firebase Studio (full IDE, terminal)
 * - Lovable (chat-based, component generation, limited file access)
 * - Base44 (chat-based app builder)
 * - Replit (full IDE with terminal)
 * - Canva Code (frontend-only, design focused)
 * - Cursor / Windsurf / Bolt / v0
 *
 * Each prompt is designed to:
 * 1. Tell the AI exactly what's wrong
 * 2. Tell it exactly what to search for
 * 3. Tell it exactly what to change
 * 4. Work regardless of which AI tool you paste it into
 */

/**
 * @typedef {Object} FixPrompt
 * @property {string} prompt - Universal copy-paste prompt
 * @property {string} [platformNotes] - Limitations by platform
 */

/** @type {Record<string, FixPrompt>} */
export const FIX_PROMPTS = {

  // ─── SECRETS & CREDENTIALS ──────────────────────────────────────────────────

  'exposed-secrets': {
    prompt: `SECURITY FIX: I have API keys/tokens hardcoded in my source code. Find every instance of hardcoded API keys, tokens, and secrets in my codebase. For each one: (1) Create an environment variable in .env with the value. (2) Replace the hardcoded value with process.env.VARIABLE_NAME (or import.meta.env.VITE_VARIABLE_NAME for Vite). (3) Make sure .env is in .gitignore. (4) If this is a server-side secret, do NOT use a client-side prefix like VITE_ or NEXT_PUBLIC_. Show me every file you changed.`,
    platformNotes: `Lovable/Base44: These platforms manage env vars in their settings panel — don't hardcode in code. Replit: Use the Secrets tab. Canva Code: This is frontend-only — secrets should never be in frontend code at all, use a backend proxy.`,
  },

  'hardcoded-credentials': {
    prompt: `SECURITY FIX: I have passwords or database connection strings hardcoded in my code. Find all hardcoded passwords, database URLs with credentials, and auth tokens. Move each one to an environment variable. For database URLs, the format should be: DATABASE_URL=your_connection_string in .env, then reference process.env.DATABASE_URL in code. Make sure .env is in .gitignore.`,
    platformNotes: `Lovable/Base44: Use platform environment variable settings. Replit: Use the Secrets tab. Firebase Studio: Use .env or Secret Manager.`,
  },

  'exposed-env-vars': {
    prompt: `SECURITY FIX: I have server-side secrets using client-side environment variable prefixes (VITE_, NEXT_PUBLIC_, REACT_APP_). These get bundled into browser JavaScript and anyone can read them. Find every env var with these prefixes that contains SECRET, KEY, TOKEN, PASSWORD, or CREDENTIAL in the name. Remove the client prefix and move the logic that uses them to a server-side API route. The client should call your API route instead of accessing the secret directly.`,
    platformNotes: `Lovable: Server-side logic requires Lovable's backend functions feature. Base44: Use server-side functions. Canva Code: ALL code runs client-side — never put secrets in Canva Code, use an external API.`,
  },

  'client-bundle-secrets': {
    prompt: `SECURITY FIX: I have secrets in client-side code that get bundled into the browser JavaScript — anyone can see them in DevTools → Sources tab. Find all API keys, secret keys, and auth tokens referenced in client components or pages. Move each one to a server-side API route. The client should call fetch("/api/your-endpoint") and the server-side route should use the secret. Never reference secrets in any file that runs in the browser.`,
    platformNotes: `Lovable: Create a backend function to proxy the API call. Base44: Use server functions. Replit: Create an API route. Canva Code: Cannot handle secrets — use an external backend.`,
  },

  'sensitive-browser-storage': {
    prompt: `SECURITY FIX: I'm storing tokens/credentials in localStorage or sessionStorage where they're visible in DevTools → Application tab. Find every localStorage.setItem and sessionStorage.setItem that stores tokens, JWTs, passwords, or auth data. Replace with httpOnly cookies set by the server. Update the auth flow: server sets the cookie on login response with { httpOnly: true, secure: true, sameSite: 'lax' }, and client sends credentials via cookies automatically (no manual token handling needed).`,
    platformNotes: `Lovable/Base44: May need to use platform auth features instead of manual token storage. Canva Code: Should not handle auth at all.`,
  },

  'missing-gitignore': {
    prompt: `SECURITY FIX: My .env file is not in .gitignore, which means my secrets will be committed to git. Add .env, .env.local, .env.production, .env.development, and .env.staging to .gitignore. Also add node_modules/ and .DS_Store if missing. If .env was already committed, run: git rm --cached .env && git commit -m "Remove .env from tracking". If it was pushed to a public repo, ROTATE ALL SECRETS immediately — they are compromised.`,
    platformNotes: `Lovable/Base44/Canva Code: These platforms handle git internally — check platform settings for secret management. Replit: Use the Secrets tab instead of .env files.`,
  },

  'insecure-jwt': {
    prompt: `SECURITY FIX: My JWT implementation has security issues. Check my JWT code for: (1) Weak signing secret — replace any hardcoded string with a 64+ character random secret from an env var: process.env.JWT_SECRET. Generate with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))". (2) Missing algorithm pinning — add { algorithms: ['HS256'] } to jwt.verify(). (3) Missing expiry — add { expiresIn: '1h' } to jwt.sign(). Fix all three.`,
    platformNotes: `All platforms: JWT secret must be in environment variables. Lovable/Base44: JWT handling should be in server-side code only.`,
  },

  'secrets-in-urls': {
    prompt: `SECURITY FIX: I'm passing API keys in URL query parameters where they get logged everywhere. Find all instances of API keys, tokens, or secrets in URL query strings. Move them to the Authorization header instead: fetch(url, { headers: { 'Authorization': 'Bearer ' + token } }). URLs get logged in server access logs, browser history, proxy logs, and sent in Referer headers to external sites.`,
    platformNotes: `All platforms: This is a universal fix. Canva Code: If making API calls, use headers not URL params.`,
  },

  // ─── AUTH & AUTHORIZATION ───────────────────────────────────────────────────

  'missing-auth': {
    prompt: `SECURITY FIX: I have API routes with no authentication. Find every API route handler (GET, POST, PUT, DELETE) and add auth verification at the top of each one. For Next.js: const session = await getServerSession(); if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 }). For Express: add auth middleware. For Firebase: verify the ID token. No API route should process a request without first checking the user is authenticated.`,
    platformNotes: `Lovable: Use Lovable's built-in auth. Base44: Use platform auth. Replit: Add auth middleware. Firebase Studio: Use Firebase Auth verifyIdToken().`,
  },

  'idor-vulnerability': {
    prompt: `SECURITY FIX: My API routes use IDs from the URL/request without checking if the logged-in user owns that resource. This means any user can access other users' data by changing the ID. For every route that uses an ID from params/query/body: after fetching the resource, add an ownership check: if (resource.userId !== session.user.id) return Response.json({ error: 'Forbidden' }, { status: 403 }). Auth checks if you're logged in. Authorization checks if it's YOUR data.`,
    platformNotes: `All platforms: This is a server-side logic fix. Lovable/Base44: Add the ownership check in your backend function/endpoint.`,
  },

  'client-only-auth': {
    prompt: `SECURITY FIX: My auth checks only exist on the frontend — they hide UI elements but don't protect data. The server still returns everything to anyone who calls the API directly. For every client-side auth guard (if !user redirect, {isAdmin && <Component>}), ensure the SAME check exists server-side in the API route. A client-side redirect is a UX convenience, not security. Anyone can open DevTools Console and call fetch() to bypass frontend guards.`,
    platformNotes: `Lovable/Base44: Ensure backend functions also check auth — frontend guards alone are not security. Canva Code: Cannot implement server auth.`,
  },

  'plaintext-passwords': {
    prompt: `SECURITY FIX: Passwords are stored without hashing or use a weak hash algorithm. Find all code that saves passwords to the database. Add bcrypt: (1) Install: npm install bcrypt. (2) On registration: const hash = await bcrypt.hash(password, 12); save hash instead of password. (3) On login: const valid = await bcrypt.compare(inputPassword, storedHash); use this instead of === comparison. Never store plaintext passwords. Never compare with ===. Also check for weak hashing: crypto.createHash('md5') or crypto.createHash('sha1') are NOT suitable for passwords — they are fast hashes designed for integrity checks, not password storage. Replace with bcrypt.hash(password, 12).`,
    platformNotes: `Lovable/Base44: Use platform's built-in auth which handles hashing. Replit: Install bcrypt normally. Firebase Studio: Firebase Auth handles password hashing automatically — use it instead of custom auth.`,
  },

  'no-account-lockout': {
    prompt: `SECURITY FIX: My login endpoint accepts unlimited password attempts with no lockout. Add brute force protection: (1) Track failed login attempts per email/IP in your database or cache. (2) After 5 failures, lock the account for 15 minutes or require CAPTCHA. (3) Return the same error message for wrong email AND wrong password ("Invalid credentials") so attackers can't enumerate valid emails. (4) Consider adding rate limiting specifically to the login route.`,
    platformNotes: `Lovable/Base44: Use platform auth features. Firebase: Firebase Auth has built-in brute force protection. Replit: Implement in your auth route.`,
  },

  // ─── INJECTION & INPUT ──────────────────────────────────────────────────────

  'no-input-validation': {
    prompt: `SECURITY FIX: User input is used without sanitization — this creates XSS, SQL injection, and command injection vulnerabilities. Find all instances of: innerHTML (replace with textContent), eval() (remove entirely), SQL string concatenation (use parameterized queries), and shell exec with user input (use allowlists). For each one, sanitize the input before use. Never trust anything from the user — validate type, length, and format on the server side.`,
    platformNotes: `All platforms: React/JSX already prevents XSS by default (don't use dangerouslySetInnerHTML). Lovable/Base44: The framework handles most sanitization but check for raw HTML insertion.`,
  },

  'mass-assignment': {
    prompt: `SECURITY FIX: I'm passing the full request body directly to database operations. An attacker can add extra fields like "role: admin" to the request in DevTools. Fix by destructuring only the fields you expect: const { name, email } = req.body; then pass those explicitly to the database. Or use Zod/Yup to validate and strip unknown fields: const data = schema.parse(req.body). Never spread or pass raw req.body to create/update operations.`,
    platformNotes: `All platforms: This is a server-side logic fix. Lovable: Destructure in your backend function. Firebase Studio: Validate in Cloud Functions. Replit: Add validation middleware.`,
  },

  'unsafe-file-upload': {
    prompt: `SECURITY FIX: My file upload handler has no validation. Add: (1) MIME type check against an allowlist (don't trust file extensions). (2) File size limit (e.g., 5MB max). (3) For images, verify with a library like sharp. Example for multer: multer({ limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req, file, cb) => { const allowed = ['image/jpeg', 'image/png']; cb(null, allowed.includes(file.mimetype)); } }). The HTML accept="" attribute is NOT security — DevTools removes it in one click.`,
    platformNotes: `Lovable: File uploads go through platform storage — check platform docs for limits. Firebase Studio: Use Firebase Storage security rules + Cloud Functions for validation. Canva Code: Cannot handle file uploads server-side.`,
  },

  'path-traversal': {
    prompt: `SECURITY FIX: My file serve endpoint uses user input in file paths without sanitization. An attacker can use ../ to read any file on the server. Fix: (1) Use path.basename() to strip directory components from the filename. (2) Resolve the full path then verify it starts with your allowed directory: const resolved = path.resolve(UPLOADS_DIR, path.basename(userInput)); if (!resolved.startsWith(UPLOADS_DIR)) return 403. Never concatenate user input into file paths.`,
    platformNotes: `Lovable/Base44: These platforms handle file serving — use platform APIs. Firebase Studio: Use Firebase Storage URLs, not direct file system access. Replit: Implement path validation in your route.`,
  },

  'prototype-pollution': {
    prompt: `SECURITY FIX: I'm using deep merge (_.merge, Object.assign, etc.) with user input, which allows prototype pollution. An attacker can send {"__proto__": {"isAdmin": true}} and modify all objects in the app. Fix: (1) Never deep-merge raw user input. (2) Destructure only expected fields. (3) If you must merge, delete __proto__ and constructor.prototype keys first. (4) Use Zod/Yup schema validation to strip unknown keys before any merge operation.`,
    platformNotes: `All platforms: Avoid lodash _.merge with user data. Use schema validation (Zod works in all platforms).`,
  },

  // ─── SERVER-SIDE EXPLOITS ───────────────────────────────────────────────────

  'ssrf-vulnerability': {
    prompt: `SECURITY FIX: My server fetches URLs provided by users without validation — attackers can access internal services. Before fetching any user-provided URL: (1) Parse with new URL(userInput). (2) Verify protocol is https. (3) Block private IP ranges (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x). (4) Optionally allowlist specific domains. Without this, an attacker can read your cloud metadata, access internal APIs, and scan your private network.`,
    platformNotes: `Lovable/Base44: URL fetching in server functions needs validation. Firebase Studio: Cloud Functions can access internal Google services — validate URLs. Canva Code: Cannot make server-side requests.`,
  },

  'unverified-webhook': {
    prompt: `SECURITY FIX: My webhook handler accepts events without verifying the signature. Anyone who knows the URL can send fake events. Add verification: For Stripe: const event = stripe.webhooks.constructEvent(rawBody, sig, process.env.WEBHOOK_SECRET). For other providers: verify the HMAC signature using crypto.createHmac('sha256', secret).update(rawBody).digest('hex') and compare with crypto.timingSafeEqual. Never process webhook events without signature verification.`,
    platformNotes: `All platforms: This requires access to the raw request body. Lovable: Use backend functions for webhook handlers. Firebase Studio: Use Cloud Functions.`,
  },

  'insecure-randomness': {
    prompt: `SECURITY FIX: I'm using Math.random() for security-sensitive values like tokens, session IDs, or reset codes. Math.random() is predictable. Replace with: const token = crypto.randomBytes(32).toString('hex') for Node.js, or crypto.randomUUID() for UUIDs. For browser code: crypto.getRandomValues(new Uint8Array(32)). Never use Math.random() for anything security-related.`,
    platformNotes: `All platforms: crypto module is available in Node.js and browsers. Lovable/Base44: Use crypto in server functions. Canva Code: Use window.crypto.getRandomValues().`,
  },

  // ─── DATA EXPOSURE ──────────────────────────────────────────────────────────

  'api-data-overfetch': {
    prompt: `SECURITY FIX: My API returns full database objects with fields the client doesn't need — extra fields are visible in DevTools Network tab. For every API response: (1) Select only needed fields in your query (Prisma: use select, MongoDB: use projection). (2) Or map results to a DTO before sending: const { id, name, email } = user; return Response.json({ id, name, email }). Never return full objects — they may contain passwordHash, internal IDs, or PII.`,
    platformNotes: `All platforms: This is a universal pattern. Always select specific fields or map to a safe shape before returning.`,
  },

  'console-data-leak': {
    prompt: `SECURITY FIX: I have console.log statements that output sensitive data (tokens, passwords, user objects) — visible in DevTools Console. Find and remove all console.log/info/debug statements that log tokens, passwords, auth headers, request bodies, or user objects. In production, either strip all console statements or use a proper logging library with log levels that filters out debug/info in production.`,
    platformNotes: `All platforms: Remove sensitive console.log before deploying. Lovable/Base44: Console output is visible in browser DevTools.`,
  },

  'insecure-error-handling': {
    prompt: `SECURITY FIX: My error handling leaks internal details (stack traces, error messages, database info) to users. Find all catch blocks that send err.message or err.stack in responses. Replace with generic messages: catch (error) { console.error(error); return Response.json({ error: 'Something went wrong' }, { status: 500 }); }. Also find and fix any empty catch blocks — they silently swallow errors.`,
    platformNotes: `All platforms: Always log full errors server-side (console.error) but return generic messages to users.`,
  },

  'source-maps-exposed': {
    prompt: `SECURITY FIX: My production build ships source maps that expose my entire original source code in DevTools → Sources tab. In your build config: For Vite: set build.sourcemap to false or 'hidden'. For Next.js: set productionBrowserSourceMaps: false (or remove if true). For Webpack: use 'hidden-source-map' instead of 'source-map'. Source maps should be generated for error tracking services but never served to browsers.`,
    platformNotes: `Lovable/Base44: Platform handles build config. Replit: Check your build settings. Firebase Studio: Update firebase.json or build config.`,
  },

  // ─── TRANSPORT & CONFIG ─────────────────────────────────────────────────────

  'open-database-rules': {
    prompt: `SECURITY FIX: My Firebase/Firestore security rules allow public read/write access. Replace "allow read, write: if true" with proper rules. At minimum: "allow read, write: if request.auth != null" (requires login). Better: add per-collection rules that check request.auth.uid matches the document's userId field. Test rules in the Firebase Emulator before deploying. Never use "if true" in production.`,
    platformNotes: `Firebase Studio: Edit firestore.rules directly. All other platforms: Update the rules file and deploy with firebase deploy --only firestore:rules.`,
  },

  'missing-security-headers': {
    prompt: `SECURITY FIX: My deployment is missing security headers. Add these headers in your middleware or deployment config: Content-Security-Policy (controls what resources can load), X-Frame-Options: DENY (prevents clickjacking), X-Content-Type-Options: nosniff (prevents MIME sniffing), Strict-Transport-Security: max-age=31536000 (forces HTTPS), Referrer-Policy: strict-origin-when-cross-origin. For Next.js: add to next.config.js headers(). For Vercel: add to vercel.json. For Express: use helmet middleware.`,
    platformNotes: `Lovable/Base44: Platform may handle some headers. Replit: Add in your server config. Vercel/Netlify: Add to platform config files.`,
  },

  'missing-rate-limiting': {
    prompt: `SECURITY FIX: My API routes call paid services (OpenAI, Stripe, etc.) with no rate limiting. A bot can run up your bill. Add rate limiting: For serverless (Vercel/Netlify): use Upstash Ratelimit. For Express: use express-rate-limit. Set per-user limits (e.g., 10 requests/minute) and global limits. Also set spend alerts on your API provider dashboards as a safety net.`,
    platformNotes: `Lovable: Add rate limiting in backend functions. Firebase Studio: Use Firebase App Check + Cloud Functions rate limiting. Replit: Use express-rate-limit.`,
  },

  'insecure-connections': {
    prompt: `SECURITY FIX: I have insecure connection configurations. Find and fix: (1) HTTP URLs pointing to production servers — change to HTTPS. (2) rejectUnauthorized: false — remove it and fix the certificate issue instead. (3) CORS wildcard origin: "*" — replace with specific allowed domains. (4) cors() with no config — add { origin: process.env.CORS_ORIGIN, credentials: true } with your actual domain.`,
    platformNotes: `All platforms: Always use HTTPS in production. Platform-hosted apps typically get HTTPS automatically.`,
  },

  'missing-csrf': {
    prompt: `SECURITY FIX: My POST/PUT/DELETE routes have no CSRF protection. Add one of these: (1) SameSite=Lax or Strict on session cookies (simplest). (2) Double-submit cookie pattern. (3) CSRF token library like csrf-csrf. (4) Check the Origin header matches your domain. Next.js Server Actions have built-in CSRF protection. For API-only backends using token auth (not cookies), CSRF is not applicable.`,
    platformNotes: `Next.js/Firebase Studio: Server Actions have built-in protection. Lovable/Base44: Check platform CSRF handling. Replit: Add csrf-csrf middleware.`,
  },

  'insecure-cookies': {
    prompt: `SECURITY FIX: My cookies are missing security flags. Update every res.cookie() call to include all three flags: res.cookie("name", value, { httpOnly: true, secure: true, sameSite: "lax" }). httpOnly: prevents JavaScript access (blocks XSS token theft). secure: only sent over HTTPS. sameSite: prevents cross-site sending (blocks CSRF). Check DevTools → Application → Cookies to verify.`,
    platformNotes: `All platforms: These flags work everywhere. In development, secure:false is ok for localhost but must be true in production.`,
  },

  'cors-credentials': {
    prompt: `SECURITY FIX: My CORS configuration has credentials:true with a hardcoded localhost origin or reflected origin. Fix: (1) Use an environment variable for the origin: origin: process.env.CORS_ORIGIN. (2) In production, set CORS_ORIGIN to your actual domain (https://yourdomain.com). (3) Never reflect the request's Origin header without validation. (4) Never use origin: true or origin: "*" with credentials.`,
    platformNotes: `All platforms: Set CORS origin via environment variable. Platform-hosted apps may handle CORS in platform settings.`,
  },

  // ─── CLIENT-SIDE TRUST ──────────────────────────────────────────────────────

  'client-side-trust': {
    prompt: `SECURITY FIX: I have business logic (pricing, permissions, validation) running only on the client side — it can be edited via DevTools. For every client-side calculation that affects money, access, or data integrity: (1) Keep the client-side logic for UX. (2) ALSO validate/recalculate server-side before processing. The server is the source of truth. Price comes from your database, not from what the client sends. Permissions come from the session, not from a client-side boolean.`,
    platformNotes: `Lovable/Base44: Add server-side validation in backend functions. Canva Code: Cannot add server validation — use an external API. Firebase Studio: Validate in Firestore security rules + Cloud Functions.`,
  },

  'no-pagination': {
    prompt: `SECURITY FIX: My list endpoints return all records with no limit. Add pagination: (1) Accept page/limit params: const page = parseInt(req.query.page) || 1; const limit = Math.min(parseInt(req.query.limit) || 20, 100). (2) Apply to query: .skip((page-1)*limit).limit(limit) for Mongoose, { take: limit, skip: offset } for Prisma. (3) Return metadata: { data: results, page, limit, total }. Hard-cap at 100 items per request even if the client asks for more.`,
    platformNotes: `All platforms: This is a universal database query pattern. Firestore: Use .limit() and startAfter() for cursor-based pagination.`,
  },

  // ─── AUTH FLOW ATTACKS ──────────────────────────────────────────────────────

  'timing-attack': {
    prompt: `SECURITY FIX: I'm comparing tokens/secrets with === which is vulnerable to timing attacks. Replace: if (token === expected) with: if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))). The === operator short-circuits on first mismatch, leaking timing info. timingSafeEqual takes constant time regardless of how many characters match. Apply this to ALL secret/token/signature comparisons.`,
    platformNotes: `All platforms with Node.js: crypto.timingSafeEqual is built-in. Lovable/Base44: Apply in backend functions. Canva Code: Not applicable (frontend-only).`,
  },

  'unsafe-redirect': {
    prompt: `SECURITY FIX: My auth flow uses unvalidated redirect URLs from query params. An attacker can set redirect=https://evil.com to phish users after login. Fix: (1) Only allow relative paths: if (!url.startsWith('/')) reject. (2) If absolute URLs needed, check against an allowlist of your domains. (3) Never redirect to user-provided external URLs. Add this validation before every res.redirect() or router.push() that uses a query/body parameter.`,
    platformNotes: `All platforms: This is a universal validation pattern. Apply in your auth callback handler.`,
  },

  // ─── BOT/AGENT ATTACKS ──────────────────────────────────────────────────────

  'no-bot-protection': {
    prompt: `SECURITY FIX: My signup/registration endpoint has no bot protection — bots can create unlimited fake accounts. Add one or more: (1) Google reCAPTCHA v3 (invisible, score-based). (2) Cloudflare Turnstile (privacy-friendly). (3) Honeypot field (hidden field that bots fill but humans don't). (4) Email verification before account activation. (5) Rate limiting on the signup endpoint. At minimum, require email verification so fake accounts can't be activated.`,
    platformNotes: `Lovable/Base44: Use platform auth features. Firebase: Firebase App Check provides bot protection. Replit: Add reCAPTCHA or Turnstile to your form.`,
  },

  'predictable-ids': {
    prompt: `SECURITY FIX: I'm using auto-incrementing integer IDs that let attackers enumerate all records. For public-facing IDs (URLs, API responses): use crypto.randomUUID() or a CUID library instead. Keep auto-increment IDs for internal database use but add a public_id column with a random UUID. Update your API routes to look up by public_id instead of the sequential id. This prevents attackers from guessing valid IDs and knowing your total record count.`,
    platformNotes: `Prisma: Use @default(uuid()) or @default(cuid()). Firebase: Firestore already uses random document IDs by default. All platforms: Add a random public ID field.`,
  },

  'debug-mode-exposed': {
    prompt: `SECURITY FIX: Debug/development mode is enabled in my production config. Find and fix: (1) debug: true → debug: process.env.NODE_ENV === 'development'. (2) Hardcoded NODE_ENV=development → remove, let the platform set it. (3) GraphQL introspection/playground: true → only enable in development. (4) Verbose log levels → use 'error' or 'warn' in production. Debug mode exposes stack traces, internal routes, environment variables, and database queries to anyone.`,
    platformNotes: `Vercel/Netlify: NODE_ENV is set to production automatically. Replit: Set NODE_ENV=production in environment. Lovable/Base44: Platform handles this. Firebase Studio: Set in Cloud Function config.`,
  },

  'missing-rate-limiting': {
    prompt: `SECURITY FIX: My API routes call paid services with no rate limiting — a bot could run up a massive bill. Add rate limiting before every paid API call. For serverless: use @upstash/ratelimit. For Express: use express-rate-limit. Set per-user AND per-IP limits. Also configure spend alerts and hard spending caps on your API provider dashboards (OpenAI, Anthropic, Stripe, etc.) as a safety net.`,
    platformNotes: `Lovable: Add in backend functions. Firebase: Use App Check + rate limiting in Cloud Functions. Replit: Use express-rate-limit. All platforms: Also set spend alerts on your API provider.`,
  },

  // ─── FRAMEWORK-SPECIFIC (v2) ──────────────────────────────────────────────

  'nextjs-server-action-exposure': {
    prompt: `SECURITY FIX: My Next.js server actions (files with "use server") have no authentication checks. Server actions are directly callable from the client — anyone can invoke them without being logged in. Add auth verification at the top of EVERY server action: const session = await getServerSession(); if (!session) throw new Error("Unauthorized"). Never assume server actions are protected by the UI.`,
    platformNotes: `Next.js specific. Use next-auth getServerSession() or clerk auth() at the top of each action.`,
  },

  'nextjs-middleware-bypass': {
    prompt: `SECURITY FIX: My Next.js middleware doesn't cover all routes or has no auth logic. Check your middleware.ts matcher config — ensure it covers /api routes. Add authentication checking: verify the session/token and redirect unauthenticated users. Example matcher: matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"].`,
    platformNotes: `Next.js specific. Works with next-auth, Clerk, or custom JWT verification.`,
  },

  'nextjs-api-route-no-method-check': {
    prompt: `SECURITY FIX: My Next.js Pages Router API route accepts all HTTP methods. A DELETE handler responds to GET requests too. Add a method check at the top: if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" }). Better yet, migrate to App Router which uses named exports (GET, POST, etc.) for automatic method routing.`,
    platformNotes: `Next.js Pages Router specific. App Router handles this automatically via named exports.`,
  },

  'supabase-missing-rls': {
    prompt: `SECURITY FIX: My Supabase tables don't have Row Level Security (RLS) enabled. Without RLS, anyone with the anon key can read/write ALL data. For every table: (1) ALTER TABLE your_table ENABLE ROW LEVEL SECURITY; (2) CREATE POLICY "Users can read own data" ON your_table FOR SELECT USING (auth.uid() = user_id); (3) Create similar policies for INSERT, UPDATE, DELETE. Test in the Supabase Dashboard SQL editor.`,
    platformNotes: `Supabase specific. Go to Authentication > Policies in the Supabase Dashboard to manage RLS visually.`,
  },

  'supabase-service-key-client': {
    prompt: `SECURITY FIX: The Supabase service_role key is referenced in client-side code. This key bypasses ALL Row Level Security and gives full admin access to your database. Remove it from client code immediately. Use the anon key for client-side Supabase. Move any operation that needs the service_role key to a server-side API route.`,
    platformNotes: `Supabase specific. The service_role key should only exist in server-side environment variables.`,
  },

  'supabase-anon-key-abuse': {
    prompt: `SECURITY FIX: My code calls Supabase admin operations (auth.admin, direct auth.users access) with the anon key. These operations require the service_role key and will fail or be restricted with the anon key. Move admin operations to a server-side API route that uses the service_role key.`,
    platformNotes: `Supabase specific. Admin operations must run server-side with the service_role key.`,
  },

  'firebase-admin-client': {
    prompt: `SECURITY FIX: Firebase Admin SDK is imported in client-side code. The Admin SDK has FULL access to your database and auth — it must only run on the server. Remove firebase-admin imports from client code. Use the regular Firebase client SDK (firebase/app, firebase/firestore) for client-side code. Move admin operations to Cloud Functions or API routes.`,
    platformNotes: `Firebase specific. Admin SDK = server only. Client SDK = browser safe.`,
  },

  'vercel-env-leak': {
    prompt: `SECURITY FIX: Server-only secrets are exposed via the NEXT_PUBLIC_ prefix. Variables with NEXT_PUBLIC_ are bundled into browser JavaScript. Remove the NEXT_PUBLIC_ prefix from any variable containing SECRET, KEY, TOKEN, PASSWORD, or CREDENTIAL. Access these only in server-side code (API routes, Server Components, server actions) via process.env.VARIABLE_NAME.`,
    platformNotes: `Vercel/Next.js specific. NEXT_PUBLIC_ = visible to everyone. No prefix = server-only.`,
  },

  'netlify-redirect-open': {
    prompt: `SECURITY FIX: My Netlify _redirects or netlify.toml has wildcard proxy/redirect rules pointing to external URLs. An attacker could use these as an open proxy or for phishing. Narrow wildcard rules to specific paths. Verify target domains are trusted. Remove unused redirect rules.`,
    platformNotes: `Netlify specific. Check both _redirects file and netlify.toml [[redirects]] sections.`,
  },

  'deployment-config-insecure': {
    prompt: `SECURITY FIX: My deployment config (vercel.json/netlify.toml) is missing security headers or has insecure CORS settings. Add security headers: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin, Content-Security-Policy. Replace CORS wildcard (*) with your specific domain.`,
    platformNotes: `Check your platform's config file format for header configuration.`,
  },

  // ─── AI & API SECURITY (v2) ───────────────────────────────────────────────

  'ai-prompt-injection': {
    prompt: `SECURITY FIX: User input is being interpolated directly into AI/LLM prompts. An attacker can inject instructions that override your system prompt. Fix: (1) Never put user input in the system message. (2) Use the "user" role for user content. (3) Add input validation and length limits. (4) Consider using structured outputs to constrain AI responses. Example: messages: [{ role: "system", content: YOUR_INSTRUCTIONS }, { role: "user", content: sanitizedUserInput }].`,
    platformNotes: `All platforms using OpenAI, Anthropic, or other AI APIs. This applies to any AI feature in your app.`,
  },

  'ai-response-trusted': {
    prompt: `SECURITY FIX: AI/LLM responses are being passed directly to dangerous sinks (eval, innerHTML, SQL queries). AI output can contain anything — including malicious code. Never use AI output in: eval(), innerHTML, dangerouslySetInnerHTML, SQL string concatenation, or Function constructors. Always sanitize and validate AI responses before use.`,
    platformNotes: `All platforms. Treat AI output as untrusted user input.`,
  },

  'ai-cost-exposure': {
    prompt: `SECURITY FIX: My AI API calls have no max_tokens limit. A single request could generate an expensive response. Add max_tokens to every AI API call: { max_tokens: 1000 } (adjust based on your needs). Also add rate limiting to the API route and set spend alerts on your AI provider dashboard.`,
    platformNotes: `All platforms using AI APIs. Also set hard spending caps on OpenAI/Anthropic dashboards.`,
  },

  'stripe-webhook-no-verify': {
    prompt: `SECURITY FIX: My Stripe webhook handler doesn't verify the webhook signature. Anyone who knows the URL can send fake payment events. Add: const event = stripe.webhooks.constructEvent(rawBody, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET). Important: use the RAW request body, not parsed JSON.`,
    platformNotes: `All platforms. Requires access to raw request body. For Next.js, disable body parsing in the route config.`,
  },

  'payment-amount-client': {
    prompt: `SECURITY FIX: Payment amounts are coming from client-side request data. An attacker can change the amount in DevTools to pay $0.01. Always calculate amounts server-side from your database: look up the product price, multiply by quantity, and use that as the payment amount. Never accept an amount from the client.`,
    platformNotes: `All platforms with Stripe/payment integration. Price must come from your database, not the client.`,
  },

  // ─── DATA & PRIVACY (v2) ──────────────────────────────────────────────────

  'pii-logging': {
    prompt: `SECURITY FIX: My logging statements contain PII (email, phone, SSN, credit card, etc.). Remove PII from all console.log/logger calls. If you need to log user actions, log user IDs or anonymized data only. Use structured logging with field allowlists to prevent accidental PII exposure.`,
    platformNotes: `All platforms. PII in logs creates GDPR/CCPA compliance issues.`,
  },

  'missing-data-encryption': {
    prompt: `SECURITY FIX: Sensitive data (SSN, credit card, etc.) is stored in the database without encryption. Encrypt sensitive fields before storing: use crypto.createCipheriv("aes-256-gcm", key, iv). Store: encrypted text + IV + auth tag. Decrypt on read. Better yet, avoid storing sensitive data if possible — use a payment processor for credit cards.`,
    platformNotes: `All platforms. For credit cards, use Stripe/payment processor instead of storing directly.`,
  },

  'graphql-introspection': {
    prompt: `SECURITY FIX: GraphQL introspection is unconditionally enabled. Attackers can query your entire API schema. Set: introspection: process.env.NODE_ENV !== "production". Also disable playground/GraphiQL in production. This hides your API structure from attackers.`,
    platformNotes: `Apollo Server, Yoga, Mercurius — all have introspection config options.`,
  },

  'graphql-depth-limit': {
    prompt: `SECURITY FIX: My GraphQL server has no query depth or complexity limits. An attacker can craft deeply nested queries that crash your server (DoS). Install graphql-depth-limit: npm install graphql-depth-limit. Add: validationRules: [depthLimit(10)] to your server config. Consider also adding query complexity analysis.`,
    platformNotes: `All GraphQL servers. Apollo, Yoga, and Mercurius all support validation rules.`,
  },

  'graphql-no-auth': {
    prompt: `SECURITY FIX: My GraphQL resolvers have no authentication checks. Any user can call any query or mutation. Add auth to resolvers: check context.user at the top of each resolver. For a global solution, use a middleware/plugin that checks auth before resolvers execute.`,
    platformNotes: `All GraphQL servers. Use context to pass the authenticated user to resolvers.`,
  },

  // ─── SESSION & AUTH HARDENING (v2) ────────────────────────────────────────

  'session-fixation': {
    prompt: `SECURITY FIX: My login handler sets session data without regenerating the session ID, or my logout handler doesn't destroy the server-side session. For login: After successful authentication, call req.session.regenerate((err) => { req.session.userId = user.id; req.session.save(); }). This creates a new session ID, invalidating any pre-set session. For logout: Always call req.session.destroy() or req.logout() before clearing cookies. Do NOT just clearCookie() and redirect — the session is still valid server-side. For JWT auth, add the token to a server-side blacklist/revocation list on logout.`,
    platformNotes: `Express/Node.js with express-session. Next-auth and Clerk handle this automatically.`,
  },

  'oauth-state-missing': {
    prompt: `SECURITY FIX: My OAuth flow doesn't use a state parameter. This is vulnerable to CSRF — an attacker can trick a user into logging in with the attacker's account. Fix: (1) Generate a random state: crypto.randomUUID(). (2) Store it in the session. (3) Add &state=... to the OAuth authorization URL. (4) In the callback, verify the returned state matches the session state.`,
    platformNotes: `All OAuth implementations. Libraries like next-auth, passport handle state automatically.`,
  },

  'password-reset-weak': {
    prompt: `SECURITY FIX: My password reset tokens are predictable or don't expire. Fix: (1) Generate tokens with crypto.randomBytes(32).toString("hex"). (2) Hash the token before storing in DB (like a password). (3) Set expiry: Date.now() + 3600000 (1 hour). (4) Invalidate the token after use. (5) Rate limit the reset request endpoint.`,
    platformNotes: `All platforms with custom auth. Firebase/Supabase/Clerk handle password reset securely.`,
  },

  'mfa-bypass': {
    prompt: `SECURITY FIX: My MFA implementation can be bypassed. Ensure: (1) After password auth, issue a "pending MFA" temporary token — NOT a full session. (2) The MFA verify endpoint requires this temporary token. (3) Only issue a full session after BOTH password AND MFA pass. (4) Don't allow skipping MFA with an else branch.`,
    platformNotes: `All platforms with custom MFA. Use a proper auth library that handles MFA flow correctly.`,
  },

  'auth-token-no-expiry': {
    prompt: `SECURITY FIX: My JWTs are issued without an expiration time. If a token is stolen, it's valid forever. Add: jwt.sign(payload, secret, { expiresIn: "1h" }). Use short-lived access tokens (15 min to 1 hour) with longer-lived refresh tokens. Always verify expiry on the server.`,
    platformNotes: `All platforms using JWT. Express, Next.js, and all Node.js frameworks.`,
  },

  // ─── EXPANDED CATEGORIES (v2) ─────────────────────────────────────────────

  'race-condition': {
    prompt: `SECURITY FIX: My code has check-then-act patterns without atomic operations. Example: checking balance then deducting — two concurrent requests could both pass the check. Fix: Use database transactions: prisma.$transaction() for Prisma, or SELECT ... FOR UPDATE in SQL. For MongoDB, use $inc for atomic counter updates. Never read-check-write without a lock.`,
    platformNotes: `All platforms with databases. This is especially common in payment/inventory/booking code.`,
  },

  'nosql-injection': {
    prompt: `SECURITY FIX: My MongoDB queries use raw request data, allowing NoSQL operator injection. An attacker can send {"$gt": ""} to bypass filters. Fix: (1) Never pass req.body directly to MongoDB queries. (2) Extract specific fields: const { email } = req.body. (3) Cast types explicitly. (4) Strip keys starting with "$" from user input. (5) Use mongoose with schema validation.`,
    platformNotes: `All platforms using MongoDB/Mongoose. Prisma and other ORMs are not vulnerable to this.`,
  },

  'xml-xxe': {
    prompt: `SECURITY FIX: My XML parser has external entity processing enabled. An attacker can read files from your server or make SSRF requests. Fix: Disable external entities in your XML parser config. Better yet, use JSON instead of XML. If you must parse XML, use a parser with secure defaults like fast-xml-parser.`,
    platformNotes: `All platforms processing XML. Modern JSON APIs are not affected.`,
  },

  'ldap-injection': {
    prompt: `SECURITY FIX: User input is concatenated into LDAP queries. An attacker can modify the query to bypass authentication or access unauthorized data. Fix: Escape LDAP special characters: * ( ) \\ NUL / in user input. Use parameterized LDAP filters when your library supports them.`,
    platformNotes: `Enterprise apps using LDAP/Active Directory for authentication.`,
  },

  'header-injection': {
    prompt: `SECURITY FIX: User input is placed in HTTP response headers. An attacker can inject \\r\\n to add arbitrary headers (CRLF injection). Fix: Strip \\r and \\n characters from any user input before placing in headers: value.replace(/[\\r\\n]/g, ""). Better: validate against an allowlist of expected values.`,
    platformNotes: `All server frameworks. Most modern frameworks sanitize headers automatically.`,
  },

  'subdomain-takeover': {
    prompt: `SECURITY FIX: CNAME records or references point to external services that may be deprovisioned. If the service is no longer active, an attacker can claim the subdomain. Verify that all referenced services are still active and provisioned. Remove DNS records for decommissioned services.`,
    platformNotes: `Infrastructure concern. Check your DNS provider for dangling CNAME records.`,
  },

  'clickjacking': {
    prompt: `SECURITY FIX: My app is missing clickjacking protection. An attacker can embed your site in an iframe on their page and trick users into clicking hidden buttons. Add X-Frame-Options: DENY header, or use CSP: frame-ancestors 'none'. If using Express, install helmet — it sets this by default.`,
    platformNotes: `All web apps. Add headers in your server config, middleware, or deployment config.`,
  },

  'dangerously-set-inner-html': {
    prompt: `SECURITY FIX: My React code uses dangerouslySetInnerHTML without sanitization. This is a direct XSS vulnerability. Fix: (1) Best: avoid dangerouslySetInnerHTML entirely — use React's built-in escaping. (2) If HTML rendering is needed, install DOMPurify: npm install dompurify. (3) Use: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}.`,
    platformNotes: `React/Next.js/Remix. React normally prevents XSS — dangerouslySetInnerHTML opts out of that protection.`,
  },

  'eval-usage': {
    prompt: `SECURITY FIX: My code uses eval() or new Function() with dynamic arguments. This allows arbitrary code execution. Remove eval(). Alternatives: JSON.parse() for data, a math expression parser for calculations, a proper template engine for templates. eval() is almost never the right tool.`,
    platformNotes: `All JavaScript platforms. CSP headers can also block eval() as an extra layer.`,
  },

  'regex-dos': {
    prompt: `SECURITY FIX: My code has regex patterns with nested quantifiers that could cause catastrophic backtracking (ReDoS). A malicious input string could freeze your server. Fix: (1) Simplify the regex — avoid patterns like (a+)+ or (a|b)*. (2) Add input length limits before regex matching. (3) Use the safe-regex library to validate regex patterns. (4) Consider using string methods instead of regex.`,
    platformNotes: `All JavaScript platforms. Test regex with long strings to check for backtracking.`,
  },

  'hardcoded-ip': {
    prompt: `SECURITY FIX: Hardcoded IP addresses should be in environment variables. Move the IP to: process.env.SERVICE_HOST. This makes deployment flexible and avoids exposing infrastructure details in source code.`,
    platformNotes: `All platforms. Use environment variables for any host/IP configuration.`,
  },

  // ─── EXTENDED SECRETS (v2) ────────────────────────────────────────────────

  'high-entropy-strings': {
    prompt: `SECURITY FIX: A high-entropy string in a variable named like a secret was detected. This may be a hardcoded API key, token, or password. Move it to an environment variable in .env (git-ignored) and reference via process.env.VARIABLE_NAME.`,
    platformNotes: `All platforms. If it's not a secret, rename the variable to avoid false positives.`,
  },

  'git-history-secrets': {
    prompt: `SECURITY FIX: Secrets were found in git history. Even deleted files remain in git history forever. (1) ROTATE the compromised secret immediately — generate a new one. (2) Remove from history: use git-filter-repo or BFG Repo-Cleaner. (3) Force push the cleaned history. (4) If it was ever on a public repo, assume it has been compromised.`,
    platformNotes: `All platforms. Rotating the secret is more important than cleaning history — do that first.`,
  },

  // ─── INFRASTRUCTURE (v3) ──────────────────────────────────────────────────

  'docker-root-user': {
    prompt: `SECURITY FIX: My Dockerfile runs the container as root. This means if an attacker exploits a vulnerability in my app, they have full root access to the container and potentially the host. Fix: (1) Create a non-root user: RUN addgroup -S appgroup && adduser -S appuser -G appgroup. (2) Copy files with correct ownership: COPY --chown=appuser:appgroup . . (3) Switch to that user before CMD: USER appuser. (4) Make sure the app doesn't need root — if it does, fix the app, not the Dockerfile.`,
    platformNotes: `Docker/Kubernetes deployments. Lovable/Vercel/Netlify: Not applicable — these platforms manage containers for you.`,
  },

  'exposed-database-port': {
    prompt: `SECURITY FIX: My docker-compose.yml exposes database ports to the host machine. Anyone on the network can connect to my database directly. Fix: (1) Remove the "ports:" section from your database service. (2) Use "expose:" instead if other containers need to connect. (3) Your app connects to the database via the Docker network using the service name (e.g., postgres:5432), not localhost. (4) If you need database access for development, use "docker exec" to connect through the container.`,
    platformNotes: `Docker Compose deployments. For production, never expose database ports. Use a VPN or SSH tunnel for remote database access.`,
  },

  'client-side-db-access': {
    prompt: `SECURITY FIX: Direct database access (Supabase, Firebase, or query builders like Drizzle/Prisma) was detected in client-side code. This exposes database credentials, table structures, and allows clients to bypass backend security constraints. Fix: Move database queries into server-side functions (Server Actions, API routes, or server controllers). Call those server endpoints from the client. Never query the database directly from files that run in the browser.`,
    platformNotes: `All platforms. Supabase/Firebase anon queries must be secured with RLS if used, but direct query builder connections (like Drizzle/Prisma) must never be client-side.`,
  },

  // ─── INJECTION & CRYPTOGRAPHY (v1.3) ─────────────────────────────────────────

  'sql-injection': {
    prompt: `SECURITY FIX: I'm building SQL queries by concatenating strings or interpolating variables with template literals — this is SQL injection. Find every query that uses "+" or \${} to insert a value into the SQL text. Rewrite each one to use parameterized queries / prepared statements: pass the SQL string with placeholders and the values as a separate array. Examples: pg — client.query("SELECT * FROM users WHERE id = $1", [id]); mysql2 — conn.execute("... WHERE email = ?", [email]); Prisma — use the query builder or the sql\`\` tagged template. Never build a query string from user input.`,
    platformNotes: `All platforms. If you use an ORM (Prisma, Drizzle, Sequelize), prefer its query builder — it parameterizes automatically. Only drop to raw SQL with bound parameters.`,
  },

  'weak-hashing': {
    prompt: `SECURITY FIX: I'm using a broken hash algorithm (MD5 or SHA-1). Find every crypto.createHash('md5') / createHash('sha1') call. If it's for data integrity or fingerprints, switch to 'sha256' or stronger. If it's for passwords, replace the hash entirely with bcrypt, scrypt, or argon2 (with a per-user salt). MD5 and SHA-1 are collision-broken and unfit for any security use.`,
    platformNotes: `All platforms. For password hashing prefer a maintained library (bcryptjs, @node-rs/argon2) over hand-rolled crypto.`,
  },

  'insecure-cipher': {
    prompt: `SECURITY FIX: I'm using insecure encryption. Find every crypto.createCipher/createDecipher call (the deprecated no-IV API) and every cipher using DES, 3DES, RC4, Blowfish, or ECB mode. Replace them with crypto.createCipheriv('aes-256-gcm', key, iv) using a random 12-byte IV from crypto.randomBytes(12); store the IV (and GCM auth tag) alongside the ciphertext so you can decrypt. Never reuse an IV and never use ECB mode.`,
    platformNotes: `All platforms. AES-256-GCM is authenticated encryption — prefer it over CBC so tampering is detected.`,
  },
};

/**
 * Get the fix prompt for a rule.
 * @param {string} ruleId
 * @returns {FixPrompt | null}
 */
export function getFixPrompt(ruleId) {
  return FIX_PROMPTS[ruleId] || null;
}
