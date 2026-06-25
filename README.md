# ⚗️ Vibe Audit

**Security scanner for AI-generated codebases.**

Vibe coding is fast. Shipping insecure code is faster. Vibe Audit catches the security time bombs that AI tools leave behind — exposed API keys, open database rules, missing auth, XSS vectors, and more — before they blow up in production.

```
npx vibe-audit
```

No config required. Zero production dependencies. 39 rules. Runs in under a second.

---

## Why This Exists

AI coding tools generate working code. But "working" and "secure" aren't the same thing. Every day, developers ship vibe-coded apps with:

- API keys hardcoded in source files
- Firestore rules set to `allow read, write: if true`
- API routes with zero authentication
- User input piped straight into `innerHTML` or SQL queries
- Paid API calls with no rate limiting (hello, surprise $10K bill)
- Passwords stored in plaintext
- Webhook handlers that accept fake events without verification

Vibe Audit finds these issues in seconds and tells you exactly how to fix them — with plain-English explanations AND copy-paste prompts that work in any AI coding tool (Claude Code, Cursor, Lovable, Replit, Firebase Studio, and more).

---

## Quick Start

```bash
# Audit current directory
npx vibe-audit

# Audit a specific project
npx vibe-audit ./my-app

# Get fix prompts for your AI coding tool
npx vibe-audit --fix

# Save fix guide only (no terminal output)
npx vibe-audit --fix-file

# JSON output for CI
npx vibe-audit --format json --strict

# Markdown report with copy-paste fix prompts
npx vibe-audit --format markdown > audit-report.md
```

---

## What It Checks

### 39 Rules Across 8 Attack Surfaces

**Secrets & Credentials (8 rules)**

| Rule | Sev | What It Catches |
|------|-----|-----------------|
| `exposed-secrets` | 🔴 | API keys, tokens, private keys in source code |
| `hardcoded-credentials` | 🔴 | Passwords, connection strings, bearer tokens |
| `exposed-env-vars` | 🔴 | Secrets leaked via VITE_, NEXT_PUBLIC_, REACT_APP_ prefixes |
| `client-bundle-secrets` | 🔴 | Secrets in client code visible in DevTools Sources |
| `sensitive-browser-storage` | 🔴 | Tokens/PII in localStorage visible in DevTools Application |
| `missing-gitignore` | 🔴 | .env not in .gitignore — one push leaks all secrets |
| `insecure-jwt` | 🔴 | Weak JWT secrets, missing algorithm pinning, no expiry |
| `secrets-in-urls` | 🔴 | API keys in URL query params — logged everywhere |

**Auth & Authorization (5 rules)**

| Rule | Sev | What It Catches |
|------|-----|-----------------|
| `missing-auth` | 🔴 | API routes with no authentication checks |
| `idor-vulnerability` | 🔴 | Routes using IDs without ownership verification |
| `client-only-auth` | 🟡 | Auth only on frontend — bypassable via DevTools Console |
| `plaintext-passwords` | 🔴 | Passwords stored or compared without hashing |
| `no-account-lockout` | 🟡 | Login endpoints with no brute force protection |

**Injection & Input (5 rules)**

| Rule | Sev | What It Catches |
|------|-----|-----------------|
| `no-input-validation` | 🔴 | XSS, SQL injection, command injection, eval() |
| `mass-assignment` | 🔴 | Raw request body to DB — inject role:admin via DevTools |
| `unsafe-file-upload` | 🔴 | File uploads with no type validation or size limits |
| `path-traversal` | 🔴 | File ops with user input — read any file via ../ |
| `prototype-pollution` | 🔴 | Deep merge with user input — inject __proto__ |

**Server-Side Exploits (3 rules)**

| Rule | Sev | What It Catches |
|------|-----|-----------------|
| `ssrf-vulnerability` | 🔴 | Server fetches user-provided URLs — access internal network |
| `unverified-webhook` | 🔴 | Webhook handlers accepting events without signature check |
| `insecure-randomness` | 🔴 | Math.random() for tokens/keys — predictable output |

**Data Exposure (4 rules)**

| Rule | Sev | What It Catches |
|------|-----|-----------------|
| `api-data-overfetch` | 🟡 | API returning full objects — extra fields in Network tab |
| `console-data-leak` | 🟡 | Sensitive data in console.log — visible in Console tab |
| `insecure-error-handling` | 🟡 | Stack traces leaked to users, empty catch blocks |
| `source-maps-exposed` | 🟡 | Source maps shipping full source code to production |

**Transport & Config (6 rules)**

| Rule | Sev | What It Catches |
|------|-----|-----------------|
| `open-database-rules` | 🔴 | Firestore/RTDB rules allowing public access |
| `missing-security-headers` | 🟡 | Missing CSP, HSTS, X-Frame-Options |
| `missing-rate-limiting` | 🟡 | Paid API calls with no rate limiting |
| `insecure-connections` | 🟡 | HTTP URLs, disabled TLS, CORS wildcards |
| `missing-csrf` | 🟡 | State-changing routes with no CSRF protection |
| `insecure-cookies` | 🟡 | Cookies missing httpOnly, secure, sameSite flags |

**Client-Side Trust (4 rules)**

| Rule | Sev | What It Catches |
|------|-----|-----------------|
| `client-side-trust` | 🟡 | Pricing/permission logic only on client |
| `no-pagination` | 🟡 | List endpoints returning all records |
| `cors-credentials` | 🟡 | CORS credentials:true with localhost or reflected origin |
| `debug-mode-exposed` | 🟡 | Debug/dev mode exposing internal state in production |

**Bot, Agent & Auth Flow Attacks (4 rules)**

| Rule | Sev | What It Catches |
|------|-----|-----------------|
| `no-bot-protection` | 🟡 | Signup with no CAPTCHA or bot detection |
| `predictable-ids` | ℹ️ | Auto-incrementing IDs enable enumeration |
| `unsafe-redirect` | 🟡 | Unvalidated redirect URLs — phishing via auth flows |
| `timing-attack` | 🟡 | Token === comparison leaks timing info |

---

## Copy-Paste Fix Prompts

Every finding includes a **copy-paste prompt** you can drop directly into your AI coding tool. Prompts include platform-specific notes for each tool's capabilities and limitations.

**Get them with markdown or JSON output:**

```bash
# Markdown report with fix prompts
npx vibe-audit --format markdown > audit-report.md

# JSON with prompts (for automation)
npx vibe-audit --format json
```

### Supported Platforms

| Platform | Type | Strengths | Limitations |
|----------|------|-----------|-------------|
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
|--------|------|---------|-------------|
| `ignore` | string[] | `[]` | Extra directories to skip |
| `rules` | string[] | `[]` | Only run these rules (empty = all) |
| `exclude` | string[] | `[]` | Skip these rules |
| `format` | string | `"terminal"` | `terminal`, `json`, or `markdown` |
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
  run: npx vibe-audit --format json --strict
```

### Pre-commit Hook

```bash
# .husky/pre-commit
npx vibe-audit --strict
```

### Package Script

```json
{
  "scripts": {
    "security": "vibe-audit --strict"
  }
}
```

---

## CLI Reference

```
npx vibe-audit [directory] [options]

Options:
  -f, --format <terminal|json|markdown>  Output format
  -r, --rules  <id,id,...>               Only run these rules
  -e, --exclude <id,id,...>              Skip these rules
  -s, --strict                           Exit 1 on warnings too
  --fix                                  Show fix prompts + save VIBE-AUDIT-FIXES.md
  --fix-file                             Only save fix file (no terminal prompts)
  --list-rules                           Show all available rules
  -h, --help                             Show help
  -v, --version                          Show version
```

---

## Programmatic API

```js
import { audit } from 'vibe-audit';

const { findings, exitCode } = await audit('/path/to/project', {
  format: 'json',
  strict: true,
});

console.log(`Found ${findings.length} issues`);
```

---

## Design Principles

**AST-powered analysis.** The highest-impact rules (IDOR, mass assignment, missing auth) use acorn to parse your code into an Abstract Syntax Tree and analyze it per-function. This means we can tell the difference between "this function checks ownership" and "some other function in the file checks ownership" — a distinction regex alone can't make.

**Minimal dependencies.** Two production dependencies: `acorn` (the parser behind ESLint and webpack) and `acorn-loose` (tolerant parsing for AI-generated code that may have syntax quirks). No bloated dependency tree.

**Zero false positives over catching everything.** A rule that cries wolf gets disabled. Every pattern is tuned to minimize noise. Clean code triggers zero findings (verified by regression tests on a fully-secured fixture).

**Every finding includes a fix AND a prompt.** Plain English explanation for understanding PLUS a copy-paste prompt for action. No "go read the OWASP docs."

**It audits itself.** `npm run audit:self` — Vibe Audit passes its own checks in strict mode.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Adding a new rule is straightforward — each one is a self-contained module with a simple interface.

---

## License

MIT — [Digital Alchemy Academy](https://digitalalchemy.dev)

Built by [Digital Alchemy Academy](https://digitalalchemy.dev). Teaching the security-first approach to vibe coding.
