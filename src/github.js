import { execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, extname } from 'node:path';
import { normalizeConfig } from './config.js';

/**
 * Patterns that indicate a GitHub target rather than a local path.
 *
 * Matches:
 *   - https://github.com/owner/repo
 *   - git@github.com:owner/repo.git
 *   - github.com/owner/repo
 *   - owner/repo  (exactly one slash, no dots/spaces/backslashes)
 */
const GITHUB_URL_RE =
  /^(?:https?:\/\/)?github\.com[/:](?<owner>[^/\s]+)\/(?<repo>[^/\s#?.]+?)(?:\.git)?(?:[/#?].*)?$/;
const SHORTHAND_RE = /^(?<owner>[a-zA-Z0-9_.-]+)\/(?<repo>[a-zA-Z0-9_.-]+)$/;

/** File extensions we scan (mirrors scanner.js). */
const SCAN_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte',
  '.json', '.env', '.yaml', '.yml', '.toml', '.html', '.htm', '.css',
  '.py', '.rb', '.go', '.rs', '.php', '.java', '.kt', '.swift', '.dart',
  '.rules', '.lock',
]);

/** Files we always scan regardless of extension. */
const ALWAYS_SCAN = new Set([
  '.env', '.env.local', '.env.production', '.env.development', '.env.staging',
  '.env.test', '.gitignore', '.dockerignore', 'firestore.rules', 'storage.rules',
  'database.rules.json', 'firebase.json', 'vercel.json', 'netlify.toml',
  'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile', '.htaccess', 'nginx.conf',
]);

/** Directories to skip when walking the tree via API. */
const IGNORE_DIRS = new Set([
  'node_modules', '.git', '.next', '.nuxt', 'dist', 'build', '.output',
  '.vercel', '.netlify', 'coverage', '__pycache__', '.venv', 'venv', '.svelte-kit',
]);

/**
 * Build an error from a failed GitHub API response, tagging whether it's a real
 * rate-limit (primary or secondary) vs. a plain auth/not-found failure. A bare
 * `status === 403` is ambiguous — GitHub returns 403 for both "rate limited" and
 * "token lacks access" — so we disambiguate off the X-RateLimit-Remaining header
 * and the "secondary rate limit" message text, since callers need to retry one
 * and skip the other.
 *
 * Body is truncated to 500 chars to avoid leaking HTML/JSON from error pages
 * into terminal scrollback or error logs.
 * @param {Response} res
 * @param {string} body
 * @returns {Error & { status: number, rateLimited: boolean, retryAfterMs: number|null }}
 */
export function makeApiError(res, body) {
  const truncated = String(body ?? '').slice(0, 500);
  const err = new Error(`GitHub API error (${res.status}): ${truncated}`);
  err.status = res.status;

  const remaining = res.headers.get('x-ratelimit-remaining');
  const retryAfterHeader = res.headers.get('retry-after');
  const resetHeader = res.headers.get('x-ratelimit-reset');

  err.rateLimited =
    res.status === 429 ||
    (res.status === 403 &&
      (remaining === '0' || /rate limit|secondary rate limit/i.test(body)));

  err.retryAfterMs = retryAfterHeader
    ? parseInt(retryAfterHeader, 10) * 1000
    : resetHeader
      ? Math.max(0, parseInt(resetHeader, 10) * 1000 - Date.now())
      : null;

  return err;
}

/**
 * Verify a token actually works and report remaining quota before a bulk scan starts,
 * so a bad/expired/under-scoped token fails loud with one clear message instead of
 * silently producing 150+ "Not found" rows that all look like deleted repos.
 * @returns {Promise<{ ok: boolean, authenticated: boolean, remaining: number, limit: number, login?: string, message: string }>}
 */
export async function verifyToken() {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = { Accept: 'application/vnd.github.v3+json', 'User-Agent': 'vibe-audit' };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch('https://api.github.com/rate_limit', { headers });
  const data = await res.json().catch(() => ({}));
  const core = data.resources?.core ?? { remaining: 0, limit: 0 };

  if (!token) {
    return {
      ok: false,
      authenticated: false,
      remaining: core.remaining,
      limit: core.limit,
      message: 'No GITHUB_TOKEN/GH_TOKEN set — running unauthenticated (60 req/hr, public repos only).',
    };
  }
  if (!res.ok) {
    return {
      ok: false,
      authenticated: false,
      remaining: 0,
      limit: 0,
      message: `Token rejected by GitHub API (${res.status}) — it's expired, revoked, or malformed.`,
    };
  }

  let login;
  try {
    const userRes = await fetch('https://api.github.com/user', { headers });
    if (userRes.ok) login = (await userRes.json()).login;
  } catch {
    // Non-fatal — quota check above already confirmed the token works.
  }

  return {
    ok: true,
    authenticated: true,
    remaining: core.remaining,
    limit: core.limit,
    login,
    message: `Token OK${login ? ` (${login})` : ''} — ${core.remaining}/${core.limit} API requests remaining this hour.`,
  };
}

/**
 * Check whether a target string looks like a GitHub repo reference.
 * @param {string} target
 * @returns {{ owner: string, repo: string } | null}
 */
export function parseGitHubTarget(target) {
  // Full URL (https or git@)
  let m = GITHUB_URL_RE.exec(target);
  if (m) {
    const { owner, repo } = m.groups;
    return { owner, repo };
  }

  // Shorthand owner/repo — but NOT a local path.
  m = SHORTHAND_RE.exec(target);
  if (m) {
    const { owner, repo } = m.groups;
    if (owner.startsWith('.') || owner.includes('\\') || repo.includes('\\')) {
      return null;
    }
    return { owner, repo };
  }

  return null;
}

/**
 * Fetch the full file tree of a GitHub repo using the Git Trees API (single request).
 * Falls back to the Contents API if the tree is too large.
 *
 * Requires GITHUB_TOKEN env var for private repos (optional for public).
 *
 * @param {string} owner
 * @param {string} repo
 * @param {{ branch?: string }} options
 * @returns {AsyncGenerator<{ path: string, relativePath: string, content: string, lines: string[] }>}
 */
export async function* fetchRepoFiles(owner, repo, { branch = 'HEAD' } = {}) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'vibe-audit',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  // 1. Get the recursive tree in a single API call.
  const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
  const treeRes = await fetch(treeUrl, { headers });
  if (!treeRes.ok) {
    const body = await treeRes.text();
    throw makeApiError(treeRes, body);
  }
  const treeData = await treeRes.json();

  // Filter to scannable files.
  const files = (treeData.tree || []).filter((item) => {
    if (item.type !== 'blob') return false;
    // Skip ignored directories.
    const parts = item.path.split('/');
    if (parts.some((p) => IGNORE_DIRS.has(p))) return false;
    // Check extension / name.
    const name = parts[parts.length - 1];
    const ext = extname(name).toLowerCase();
    return SCAN_EXTENSIONS.has(ext) || ALWAYS_SCAN.has(name);
  });

  // 2. Fetch each file's content (using blob API for efficiency).
  for (const file of files) {
    try {
      // Use the raw content endpoint for simplicity.
      // Note: the Authorization header (GITHUB_TOKEN) is sent to
      // raw.githubusercontent.com as well, since private repos require it.
      // For public repos this is harmless; for private ones it's necessary.
      // Node's undici (since 5.28.3) strips Authorization on cross-origin
      // redirect, but engines >= 18.19 is recommended.
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${file.path}`;
      const fileRes = await fetch(rawUrl, { headers }); // vibe-audit-ignore perf-no-await-parallel  (sequential fetch avoids GitHub secondary rate limits)
      if (!fileRes.ok) {
        // raw.githubusercontent.com rate-limits separately from api.github.com — surface it
        // instead of silently dropping the file, so a mid-repo throttle doesn't masquerade
        // as "file just didn't exist."
        if (fileRes.status === 429 || fileRes.status === 403) {
          throw makeApiError(fileRes, await fileRes.text()); // vibe-audit-ignore perf-no-await-parallel  (sequential fetch avoids GitHub secondary rate limits)
        }
        continue;
      }

      const content = await fileRes.text(); // vibe-audit-ignore perf-no-await-parallel  (part of the same intentional sequential fetch)
      // Skip huge files (> 2 MB).
      if (content.length > 2 * 1024 * 1024) continue;

      const lines = content.split('\n');
      yield {
        path: `github://${owner}/${repo}/${file.path}`,
        relativePath: file.path,
        content,
        lines,
      };
    } catch (err) {
      // Rate limits abort the whole repo scan so the caller can back off and retry;
      // everything else (network blip, one bad file) just skips that file.
      if (err.rateLimited) throw err;
      continue;
    }
  }
}

/**
 * Fetch and validate a target repo's own .vibe-audit.json via the GitHub raw content API.
 * Lets remote scans (morning-scan, GitHub-target CLI runs) respect the same project-level
 * ignore/rules/exclude config that a local `vibeaudit .` run would honor.
 *
 * @param {string} owner
 * @param {string} repo
 * @param {{ branch?: string }} [options]
 * @returns {Promise<import('./config.js').VibeAuditConfig | null>} null if no config file exists or it's invalid.
 */
export async function fetchRemoteConfig(owner, repo, { branch = 'HEAD' } = {}) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = { Accept: 'application/vnd.github.v3+json', 'User-Agent': 'vibe-audit' };
  if (token) headers.Authorization = `Bearer ${token}`;

  try {
    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/.vibe-audit.json`;
    const res = await fetch(rawUrl, { headers });
    if (!res.ok) return null;
    const text = await res.text();
    return normalizeConfig(JSON.parse(text));
  } catch {
    // No config file, invalid JSON, or network failure — caller falls back to defaults.
    return null;
  }
}

/**
 * Shallow-clone a GitHub repo into a temporary directory.
 * Use this as a fallback when API access isn't available.
 *
 * @param {string} owner
 * @param {string} repo
 * @param {{ branch?: string }} options
 * @returns {Promise<string>} Path to the cloned directory
 */
export async function cloneRepo(owner, repo, { branch } = {}) {
  const cloneUrl = `https://github.com/${owner}/${repo}.git`;
  const tmp = await mkdtemp(join(tmpdir(), 'vibe-audit-'));

  const args = ['clone', '--depth', '1'];
  if (branch) args.push('--branch', branch);
  args.push(cloneUrl, tmp);

  await new Promise((resolve, reject) => {
    execFile('git', args, { timeout: 60_000 }, (err, _stdout, stderr) => {
      if (err) {
        reject(new Error(`git clone failed: ${stderr || err.message}`));
      } else {
        resolve();
      }
    });
  });

  return tmp;
}

/**
 * Remove a temporary clone directory.
 * @param {string} dir
 */
export async function cleanupClone(dir) {
  try {
    await rm(dir, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup.
  }
}
