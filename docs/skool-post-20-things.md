# Skool Post: Your Vibe Coded App Has 20 Security Holes (Here's How to Find All of Them in 10 Seconds)

---

**POST TITLE:** Your Vibe Coded App Has 20 Security Holes (Here's How to Find All of Them in 10 Seconds)

**CATEGORY:** Vibe Coding

---

You've seen that viral post going around — "20 things that will get your vibe coded app hacked in 24 hours."

Hardcoded API keys. No rate limiting. SQL injection. CORS wildcards. The whole list reads like a horror movie for anyone who's shipped a vibe coded app.

Here's the thing — **that list is real.** I've seen every single one of those vulnerabilities in apps built with Cursor, Bolt, Replit, and Lovable. AI tools are amazing at generating code fast. They're terrible at generating code *safely.*

So I built something to fix that.

**Vibe Audit scans your entire codebase and catches all 20 of those vulnerabilities automatically.**

One command. Zero setup. Takes about 2 seconds.

```
npx vibe-audit .
```

That's it. It reads every file in your project, runs 90 checks, and tells you exactly what's broken and how to fix it.

---

**Here's the full breakdown — every item from the "20 things" list mapped to how Vibe Audit catches it:**

**1. API keys hardcoded in frontend JS**
Vibe Audit matches 20+ secret patterns — AWS keys, OpenAI keys, Stripe keys, Firebase keys. It knows the difference between server-side and client-side files, so it catches keys that ship to the browser specifically.

**2. No rate limiting on /login**
Detects login endpoints without brute force protection. If a bot can try 10,000 passwords while you sleep, Vibe Audit will flag it.

**3. SQL injection**
Uses AST analysis (it actually *reads your code structure*, not just text matching) to trace user input flowing into database queries.

**4. CORS set to wildcard**
Catches `Access-Control-Allow-Origin: *` — the "let anyone in" setting that most AI tools default to.

**5. JWTs stored in localStorage**
Detects tokens being stored where any script on the page can steal them.

**6. JWT secret is "secret"**
Catches weak secrets, missing algorithm pinning, and tokens with no expiry.

**7. Admin routes protected only in frontend**
This is a big one. AI tools love to add `if (!user) redirect('/login')` in the frontend and call it security. Vibe Audit checks every API route for *server-side* auth verification. (Swapping `/dashboard` for `/admin` to reach something you shouldn't is Broken Function Level Authorization — a cousin of the IDOR in #16, same root problem: broken access control.)

**8. .env committed to git**
Checks your .gitignore AND can scan your git history (with `--deep`) for secrets that were committed and "deleted."

**9. Error responses showing stack traces**
You're giving attackers a map of your infrastructure. Vibe Audit catches error objects being returned to clients.

**10. File uploads with no MIME validation**
Upload a malicious script disguised as an image? Vibe Audit flags upload handlers missing type and size checks.

**11. Passwords hashed with MD5 or SHA1**
MD5 cracks in seconds. Vibe Audit now detects `crypto.createHash('md5')` and `crypto.createHash('sha1')` used anywhere near password variables. It knows the difference between hashing a password (bad) and hashing an email for Gravatar (fine).

**12. Auth tokens that never expire**
Stolen session = permanent access. Vibe Audit flags `jwt.sign()` calls missing `expiresIn`.

**13. Auth middleware missing on internal API routes**
AI adds auth to the obvious routes and skips the rest. Vibe Audit checks *every single exported handler function* individually using code analysis.

**14. Server running as root**
Scans your Dockerfile. No `USER` directive = running as root = one exploit gives full system access.

**15. Database port exposed to internet**
Scans your docker-compose.yml for PostgreSQL, MySQL, MongoDB, and Redis ports mapped to the host. Your database should never have a public IP.

**16. IDOR vulnerability**
Change the ID in the URL, access someone else's data. Vibe Audit's AST engine checks that every function using `params.id` also verifies ownership in the same scope.

**17. No HTTPS enforcement**
Detects `http://` URLs and missing HSTS configuration.

**18. Sessions not invalidated on logout**
The user clicks "logout" but the old session token still works. Vibe Audit now checks that logout handlers actually call `session.destroy()` or `req.logout()` — not just clear a cookie.

**19. npm packages not audited**
Built-in dependency scanner checks your `package-lock.json` for known vulnerabilities automatically.

**20. Open redirects**
Detects `res.redirect(req.query.returnUrl)` — where attackers use your trusted domain to redirect users to phishing sites.

---

**20 out of 20. Full coverage.**

And Vibe Audit has **70 more rules** beyond this list — AI prompt injection, payment amount manipulation, GraphQL introspection, Supabase RLS, Firebase admin key exposure, plus two new packs: **accessibility/WCAG** (the Level A checks that trip ADA-lawsuit scanners) and **scale/performance** (the N+1 queries behind surprise server bills). Every scan also points you to the Pre-Flight Audit Prompt for the judgment calls a scanner can't make.

---

**The best part? The fix prompts.**

Run with the `--fix` flag:

```
npx vibe-audit . --fix
```

For every vulnerability it finds, you get a plain-English fix prompt you can copy-paste directly into Cursor, Claude, Bolt, or whatever AI tool you're using. It literally tells your AI assistant exactly how to fix the security hole.

**Security scanning that speaks vibe coder.**

---

**Try it right now:**

1. Open your terminal in any project folder
2. Run `npx vibe-audit .`
3. Read the report
4. Run `npx vibe-audit . --fix` to get the fix prompts
5. **Drop your grade in the comments!** (A through F — let's see where everyone lands)

Your AI toolkit just leveled up. Time to build AND build *safely.*

---

**Tags:** #vibeaudit #security #vibecoding #buildsafe
