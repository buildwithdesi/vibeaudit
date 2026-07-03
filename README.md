# ⚗️ Vibe Audit

**Security scanner for AI-generated codebases.**

Vibe coding is fast. Shipping insecure code is faster. Vibe Audit catches the security time bombs that AI tools leave behind — exposed API keys, open database rules, missing auth, XSS vectors, prompt injection, unverified payment webhooks, and more — before they blow up in production.

```bash
npx @jackdog668/vibeaudit
```

No config required. **90 rules** across 16 attack surfaces (now including accessibility/WCAG and scale/performance). Two production dependencies. Runs in seconds.

> Every finding ships with a CWE ID, a CVSS v3.1 score, an OWASP Top 10 mapping, a plain-English explanation, **and** a copy-paste fix prompt for your AI coding tool.

---

## Why This Exists

AI coding tools generate working code. But "working" and "secure" aren't the same thing. Every day, developers ship vibe-coded apps with:

- API keys hardcoded in source files
- `service_role` keys and Firebase Admin SDK shipped to the browser
- Supabase tables with Row Level Security turned off
- Firestore rules set to `allow read, write: if true`
- API routes and Server Actions with zero authentication
- User input piped straight into `innerHTML`, SQL, NoSQL, or an LLM prompt
- Stripe webhooks accepted without signature verification
- Paid AI calls with no spend limit (hello, surprise $10K bill)

Vibe Audit finds these in seconds and tells you exactly how to fix them — with explanations AND copy-paste prompts that work in any AI coding tool (Claude Code, Cursor, Lovable, Replit, Firebase Studio, and more).

---

## Quick Start

```bash
# Audit the current directory
npx @jackdog668/vibeaudit

# Audit a specific local project
npx @jackdog668/vibeaudit ./my-app

# Audit a GitHub repo directly — no clone needed (scanned via the GitHub API)
npx @jackdog668/vibeaudit owner/repo
npx @jackdog668/vibeaudit https://github.com/owner/repo

# Deep scan — also check git history for committed secrets
npx @jackdog668/vibeaudit --deep

# Interactive HTML report (security grade A–F, CVSS charts, OWASP grid)
npx @jackdog668/vibeaudit --format html > audit-report.html

# Copy-paste fix prompts for your AI coding tool
npx @jackdog668/vibeaudit --fix

# JSON output for CI
npx @jackdog668/vibeaudit --format json --strict
```

**Install globally** if you run it a lot:

```bash
npm install -g @jackdog668/vibeaudit
vibeaudit            # then just call it directly
```

Requires Node `>=18.3.0`.

---

## Output Formats

| Format | Flag | Best for |
| --- | --- | --- |
| **Terminal** | *(default)* | Quick local checks — security grade, per-file counts, CVSS scores, colored severity bar |
| **HTML** | `--format html` | Sharing/reporting — self-contained interactive report: A–F grade, CVSS distribution, OWASP Top 10 coverage grid, searchable findings, one-click fix-prompt copy, dark mode, PDF-exportable |
| **Markdown** | `--format markdown` | Dropping into a doc/PR with copy-paste fix prompts |
| **JSON** | `--format json` | CI pipelines and automation |

Every **security** finding carries its **CWE ID, CVSS v3.1 score, and OWASP Top 10 (2021) category.** Accessibility findings carry a **WCAG success criterion** instead; scale/performance findings are quality checks with no security taxonomy.

---

## What It Checks

**90 rules** across 16 categories, plus dependency scanning (SCA). Severity is as reported by Vibe Audit: 🔴 **CRIT** · 🟡 **WARN** · ⚪ **INFO**. CVSS is the v3.1 base score.

### 🔑 Secrets & Credentials

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `exposed-secrets` | 🔴 | 7.5 | CWE-798 | API keys, tokens, private keys in source code |
| `hardcoded-credentials` | 🔴 | 7.5 | CWE-798 | Passwords, connection strings, bearer tokens |
| `exposed-env-vars` | 🔴 | 7.5 | CWE-200 | Secrets leaked via `VITE_` / `NEXT_PUBLIC_` / `REACT_APP_` prefixes |
| `client-bundle-secrets` | 🔴 | 7.5 | CWE-200 | Secrets in client code, visible in DevTools → Sources |
| `insecure-jwt` | 🔴 | 7.5 | CWE-347 | Weak JWT secrets, missing algorithm pinning, no expiry |
| `git-history-secrets` | 🔴 | 7.5 | CWE-798 | Secrets committed in past git history (`--deep`) |
| `sensitive-browser-storage` | 🔴 | 6.5 | CWE-922 | Tokens / PII in `localStorage` / `sessionStorage` |
| `missing-gitignore` | 🔴 | 5.3 | CWE-538 | `.env` not in `.gitignore` — one push leaks everything |
| `secrets-in-urls` | 🔴 | 5.3 | CWE-598 | API keys in URL query params — logged everywhere |
| `high-entropy-strings` | 🟡 | 5.0 | CWE-798 | Entropy-based detection of secret-looking strings |

### 🔐 Auth & Authorization

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `missing-auth` | 🔴 | 9.8 | CWE-306 | API routes / endpoints with no authentication checks |
| `idor-vulnerability` | 🔴 | 8.6 | CWE-639 | Routes using IDs without ownership verification |
| `plaintext-passwords` | 🔴 | 7.5 | CWE-256 | Passwords stored/compared without hashing (or MD5/SHA1) |
| `client-only-auth` | 🟡 | 6.5 | CWE-602 | Auth only on the frontend — bypassable via DevTools |
| `no-account-lockout` | 🟡 | 5.3 | CWE-307 | Login endpoints with no brute-force protection |

### 💉 Injection & Input

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `no-input-validation` | 🔴 | 8.6 | CWE-20 | User input used unsafely without validation/sanitization |
| `path-traversal` | 🔴 | 8.6 | CWE-22 | File ops with user input — read any file via `../` |
| `mass-assignment` | 🔴 | 8.1 | CWE-915 | Raw request body to DB — inject `role` / `isAdmin` |
| `unsafe-file-upload` | 🔴 | 8.1 | CWE-434 | Uploads with no type validation or size limits |
| `prototype-pollution` | 🔴 | 8.1 | CWE-1321 | Deep merge with user input — inject `__proto__` |

### 🖥️ Server-Side Exploits

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `ssrf-vulnerability` | 🔴 | 8.6 | CWE-918 | Server fetches user-provided URLs — reach internal network |
| `unverified-webhook` | 🔴 | 7.5 | CWE-345 | Webhook handlers accepting events without signature checks |
| `insecure-randomness` | 🔴 | 5.3 | CWE-330 | `Math.random()` for tokens/keys — predictable output |

### 📤 Data Exposure

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `api-data-overfetch` | 🟡 | 4.3 | CWE-200 | API returning full objects — extra fields in Network tab |
| `console-data-leak` | 🟡 | 4.3 | CWE-532 | Sensitive data in `console.log` |
| `insecure-error-handling` | 🟡 | 4.3 | CWE-209 | Stack traces leaked to users, silently swallowed errors |
| `source-maps-exposed` | 🟡 | 3.7 | CWE-540 | Source maps shipping full source to production |

### 🚦 Transport & Config

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `open-database-rules` | 🔴 | 9.8 | CWE-284 | Firebase/Firestore/Storage rules allowing public access |
| `missing-csrf` | 🟡 | 6.5 | CWE-352 | State-changing routes with no CSRF protection |
| `missing-rate-limiting` | 🟡 | 5.3 | CWE-770 | Paid API calls with no rate limiting |
| `insecure-connections` | 🟡 | 5.3 | CWE-319 | HTTP URLs, disabled TLS, CORS wildcards |
| `missing-security-headers` | 🟡 | 4.3 | CWE-693 | Missing CSP, HSTS, X-Frame-Options |
| `insecure-cookies` | 🟡 | 4.3 | CWE-614 | Cookies missing `httpOnly`, `secure`, `sameSite` |

### 🧩 Client-Side Trust

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `client-side-trust` | 🟡 | 5.3 | CWE-602 | Pricing / permission / validation logic only on the client |
| `cors-credentials` | 🟡 | 5.3 | CWE-942 | `credentials:true` with reflected or permissive origin |
| `no-pagination` | 🟡 | 4.3 | CWE-770 | List endpoints returning all records — scraping / DoS |
| `debug-mode-exposed` | 🟡 | 3.7 | CWE-489 | Debug/dev mode exposing internal state in production |

### 🤖 Bot & Auth Flow

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `unsafe-redirect` | 🟡 | 5.3 | CWE-601 | Unvalidated redirect URLs — phishing via auth flows |
| `no-bot-protection` | 🟡 | 3.7 | CWE-799 | Signup with no CAPTCHA or bot detection |
| `timing-attack` | 🟡 | 3.7 | CWE-208 | Token `===` comparison leaks timing info |
| `predictable-ids` | ⚪ | 3.7 | CWE-340 | Auto-incrementing IDs enable enumeration |

### ⚡ Framework-Specific — Next.js · Supabase · Firebase · Vercel · Netlify

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `supabase-missing-rls` | 🔴 | 9.8 | CWE-284 | Supabase tables that may lack Row Level Security |
| `supabase-service-key-client` | 🔴 | 9.8 | CWE-798 | `service_role` key used in client code |
| `firebase-admin-client` | 🔴 | 9.8 | CWE-798 | Firebase Admin SDK imported into the browser bundle |
| `nextjs-server-action-exposure` | 🔴 | 8.6 | CWE-306 | Server Actions with no auth check |
| `nextjs-middleware-bypass` | 🔴 | 7.5 | CWE-863 | Middleware matchers that leave routes unprotected |
| `vercel-env-leak` | 🔴 | 7.5 | CWE-200 | Server-only secrets exposed via `NEXT_PUBLIC_` |
| `supabase-anon-key-abuse` | 🟡 | 5.3 | CWE-269 | Anon key used for ops that need `service_role` |
| `netlify-redirect-open` | 🟡 | 5.3 | CWE-601 | Open redirect / proxy patterns in Netlify config |
| `nextjs-api-route-no-method-check` | 🟡 | 4.3 | CWE-749 | Pages Router API routes accepting all HTTP methods |
| `deployment-config-insecure` | 🟡 | 4.3 | CWE-16 | Insecure settings in deployment config files |

### 🧠 AI & API Security

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `ai-prompt-injection` | 🔴 | 8.6 | CWE-77 | User input passed into LLM prompts without sanitization |
| `payment-amount-client` | 🔴 | 8.6 | CWE-602 | Payment amount taken from client instead of server |
| `stripe-webhook-no-verify` | 🔴 | 8.1 | CWE-345 | Stripe webhooks without signature verification |
| `ai-response-trusted` | 🟡 | 6.5 | CWE-20 | LLM output used in `eval`/`innerHTML`/SQL unsanitized |
| `ai-cost-exposure` | 🟡 | 5.3 | CWE-770 | AI API calls with no token/spend limit |

### 🔏 Data & Privacy

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `graphql-no-auth` | 🔴 | 8.6 | CWE-306 | GraphQL resolvers with no auth checks |
| `missing-data-encryption` | 🟡 | 5.3 | CWE-311 | Sensitive data (SSN, card, etc.) stored unencrypted |
| `graphql-depth-limit` | 🟡 | 5.3 | CWE-770 | GraphQL with no query depth/complexity limit |
| `pii-logging` | 🟡 | 4.3 | CWE-532 | Personally identifiable info in logging statements |
| `graphql-introspection` | 🟡 | 3.7 | CWE-200 | GraphQL introspection enabled in production |

### 🪪 Session & Auth Hardening

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `oauth-state-missing` | 🔴 | 8.1 | CWE-352 | OAuth flow with no `state` param — login CSRF |
| `session-fixation` | 🔴 | 7.5 | CWE-384 | Session ID not regenerated after login |
| `mfa-bypass` | 🟡 | 6.5 | CWE-287 | MFA implementations that may be skippable |
| `password-reset-weak` | 🟡 | 5.3 | CWE-640 | Predictable reset tokens or tokens without expiry |
| `auth-token-no-expiry` | 🟡 | 5.3 | CWE-613 | JWT / auth tokens issued with no expiration |

### 🧪 Expanded Coverage

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `nosql-injection` | 🔴 | 8.6 | CWE-943 | MongoDB query-operator injection / `$where` |
| `xml-xxe` | 🔴 | 8.6 | CWE-611 | XML parsing vulnerable to XXE |
| `ldap-injection` | 🔴 | 8.6 | CWE-90 | LDAP queries with unsanitized input |
| `eval-usage` | 🔴 | 8.6 | CWE-95 | `eval()` / `new Function()` with dynamic args |
| `race-condition` | 🔴 | 8.1 | CWE-362 | Check-then-act without atomicity (TOCTOU) |
| `dangerously-set-inner-html` | 🔴 | 6.1 | CWE-79 | React `dangerouslySetInnerHTML` with user content |
| `header-injection` | 🟡 | 5.3 | CWE-113 | User input in HTTP response headers (CRLF) |
| `subdomain-takeover` | 🟡 | 5.3 | CWE-284 | CNAME/subdomain refs vulnerable to takeover |
| `regex-dos` | 🟡 | 5.3 | CWE-1333 | Regex vulnerable to catastrophic backtracking |
| `clickjacking` | 🟡 | 4.3 | CWE-1021 | Missing `X-Frame-Options` / CSP `frame-ancestors` |
| `hardcoded-ip` | ⚪ | 2.0 | CWE-547 | Hardcoded IPs that belong in env vars |

### 🏗️ Infrastructure

| Rule | Sev | CVSS | CWE | What it catches |
| --- | --- | --- | --- | --- |
| `docker-root-user` | 🟡 | 6.5 | CWE-250 | Dockerfiles running containers as `root` |
| `exposed-database-port` | 🟡 | 5.3 | CWE-284 | Database ports exposed to the host in compose files |
| `serverless-fs-write` | 🟡 | — | — | Filesystem writes / SQLite in serverless routes — ephemeral disk, data silently lost |

### ♿ Accessibility / WCAG

Level A checks that the automated scanners lawyers run (PowerMapper, axe, WAVE) flag. These carry a **WCAG success criterion**, not a CWE — accessibility is conformance, not a security weakness. An accessibility statement or overlay widget does **not** stop those scanners; real conformance does. Static analysis catches the low-hanging misses — pair with axe-core to verify screen-reader UX.

| Rule | Sev | WCAG | What it catches |
| --- | --- | --- | --- |
| `a11y-img-no-alt` | 🟡 | 1.1.1 (A) | `<img>` / `next/image` with no `alt` |
| `a11y-form-no-label` | 🟡 | 1.3.1 (A) | Inputs with no associated label or `aria-label` |
| `a11y-no-lang` | 🟡 | 3.1.1 (A) | `<html>` with no `lang` attribute |
| `a11y-button-no-name` | 🟡 | 4.1.2 (A) | Buttons with no text and no `aria-label` |
| `a11y-positive-tabindex` | 🟡 | 2.4.3 (A) | `tabindex` > 0 — breaks the keyboard tab order |
| `a11y-click-no-keyboard` | 🟡 | 2.1.1 (A) | `onClick` on a non-interactive element with no keyboard handler |

### ⚡ Scale / Performance

The real culprits behind the "$50k server bill" — named, not vibed. Quality/scale checks, not security findings, so they carry no CWE/OWASP. Missing DB indexes, caching, and connection pooling are **not** statically detectable — that judgment lives in the DA Pre-Flight Audit Prompt, not the scanner.

| Rule | Sev | What it catches |
| --- | --- | --- |
| `perf-n-plus-one` | 🟡 | A DB query inside a loop or `.map`/`.forEach` (the N+1 pattern) |
| `perf-no-await-parallel` | 🟡 | Sequential `await` in a loop that should run in parallel with `Promise.all` |
| `perf-db-client-per-request` | 🟡 | Pooled DB client (`new PrismaClient()`, pg `Pool`) created per-request — exhausts the connection pool |

### 📦 Dependencies (SCA)

Beyond the 90 rules above, Vibe Audit runs **software composition analysis** via `npm audit` to flag **known-vulnerable dependencies** (`vulnerable-dependency`, CWE-1035). Skip it with `--skip-sca`.

> Run `vibeaudit --list-rules` for the complete, always-current list.

---

## Copy-Paste Fix Prompts

Every finding includes a **copy-paste prompt** you can drop directly into your AI coding tool. Prompts include platform-specific notes for each tool's capabilities and limitations.

```bash
# Markdown report with fix prompts
npx @jackdog668/vibeaudit --format markdown > audit-report.md

# Show prompts in terminal + save VIBE-AUDIT-FIXES.md
npx @jackdog668/vibeaudit --fix
```

### Supported Platforms

| Platform | Type | Strengths | Limitations |
| --- | --- | --- | --- |
| **Claude Code** | Terminal IDE | Full file access, terminal, multi-file edits | — |
| **Firebase Studio** | Cloud IDE | Full IDE, terminal, Firebase integration | — |
| **Cursor / Windsurf** | Desktop IDE | Full file access, terminal, AI editing | — |
| **Replit** | Cloud IDE | Full IDE, terminal, package management | — |
| **Google AI Studio** | Chat | Code generation, prototyping | No direct file editing |
| **Lovable** | Chat builder | Component gen, backend functions | Limited file access |
| **Base44** | Chat builder | App builder, server functions | Limited infra control |
| **Bolt / v0** | Chat builder | Component generation, deployment | Limited server-side |
| **Canva Code** | Design tool | Frontend/design focused | No server-side, no secrets |

---

## Configuration

Drop a `.vibe-audit.json` in your project root:

```json
{
  "ignore": ["legacy/", "vendor/"],
  "exclude": ["predictable-ids"],
  "format": "terminal",
  "strict": false,
  "customEscapers": ["myEscapeHtml"],
  "customAuthGuards": ["requireAuthedApiFromReq"],
  "disableForPaths": { "missing-auth": ["^public/"] }
}
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `ignore` | string[] | `[]` | Extra directories to skip |
| `rules` | string[] | `[]` | Only run these rules (empty = all) |
| `exclude` | string[] | `[]` | Skip these rules |
| `format` | string | `"terminal"` | `terminal`, `json`, `markdown`, or `html` |
| `strict` | boolean | `false` | Exit 1 on warnings too |
| `customEscapers` | string[] | `[]` | Extra HTML escaper/sanitizer names that make `innerHTML` / `dangerouslySetInnerHTML` safe |
| `customAuthGuards` | string[] | `[]` | Extra auth-guard function names that satisfy `missing-auth` / server-action checks |
| `disableForPaths` | object | `{}` | Per-rule path patterns to skip, e.g. `{ "rule-id": ["^public/"] }` |

CLI flags override config file values.

### Suppressing a finding

When a finding is a false positive, silence it inline with a comment — no config needed:

```js
// vibe-audit-ignore-next-line missing-auth
export async function GET(req) { /* intentionally public */ }

const admin = createServiceRoleClient(); // vibe-audit-ignore supabase-service-key-client
```

A bare `// vibe-audit-ignore` (no rule id) suppresses every rule on that line; comma-separate ids to silence several.

> **Note on framework awareness:** Vibe Audit understands Next.js App Router context. A file is treated as **server** by default — importing React does not make it "client." Server-only code (`import 'server-only'`, route handlers, `'use server'`) is exempt from client-exposure rules, and auth guards imported from your own libs are recognized automatically.

---

## CI / Pre-commit

### GitHub Actions

```yaml
- name: Security Audit
  run: npx @jackdog668/vibeaudit --format json --strict
```

### Pre-commit Hook

```bash
# .husky/pre-commit
npx @jackdog668/vibeaudit --strict
```

### Package Script

```json
{
  "scripts": {
    "security": "vibeaudit --strict"
  }
}
```

---

## CLI Reference

```
npx @jackdog668/vibeaudit [target] [options]

target   A local directory, OR a GitHub repo (owner/repo or full URL)

Options:
  -f, --format <terminal|json|markdown|html>  Output format
  -r, --rules   <id,id,...>                   Only run these rules
  -e, --exclude <id,id,...>                   Skip these rules
  -s, --strict                                Exit 1 on warnings too
      --deep                                  Also scan git history for secrets
      --skip-sca                              Skip dependency vulnerability scanning
      --fix                                   Show fix prompts + save VIBE-AUDIT-FIXES.md
      --fix-file                              Only save fix file (no terminal prompts)
      --list-rules                            Show all available rules
  -h, --help                                  Show help
  -v, --version                               Show version
```

---

## Programmatic API

```js
import { audit } from '@jackdog668/vibeaudit';

const { findings, exitCode } = await audit('/path/to/project', {
  format: 'json',
  strict: true,
});

console.log(`Found ${findings.length} issues`);
```

---

## Design Principles

**AST-powered analysis.** The highest-impact rules (IDOR, mass assignment, missing auth, N+1 queries) use [acorn](https://github.com/acornjs/acorn) to parse your code into an Abstract Syntax Tree and analyze it per-function. This means we can tell the difference between "this function checks ownership" and "some other function in the file does" — a distinction regex alone can't make.

**Minimal dependencies.** Two production dependencies: `acorn` (the parser behind ESLint and webpack) and `acorn-loose` (tolerant parsing for AI-generated code that may have syntax quirks). No bloated dependency tree.

**Industry-standard metadata.** Every **security** rule is mapped to a CWE ID, a CVSS v3.1 base score, and an OWASP Top 10 (2021) category. Accessibility rules carry a WCAG success criterion, and scale/performance rules are quality checks — all surfaced in every output format.

**Zero false positives over catching everything.** A rule that cries wolf gets disabled. Every pattern is tuned to minimize noise. Clean code triggers zero findings (verified by regression tests on a fully-secured fixture).

**Every finding includes a fix AND a prompt.** Plain-English explanation for understanding PLUS a copy-paste prompt for action. No "go read the OWASP docs."

**It audits itself.** `npm run audit:self` — Vibe Audit passes its own checks in strict mode. 174+ tests, all passing.

---

## Roadmap

- **DAST (Phase 2)** — dynamic scanning stubs for ZAP + Nuclei are in place for live-endpoint testing.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Adding a new rule is straightforward — each one is a self-contained module with a simple interface.

---

## License

MIT — [Digital Alchemy Academy](https://digitalalchemy.dev/)

Built by [Digital Alchemy Academy](https://digitalalchemy.dev/). Teaching the security-first approach to vibe coding.
