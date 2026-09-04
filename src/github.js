import { execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, extname, resolve, sep } from 'node:path';
import { normalizeConfig } from './config.js';
import { isAgentControlPath } from './guard/agent-files.js';
import { findTrustedExecutable } from './trusted-tools.js';

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
  '.ps1', '.psm1', '.sh', '.bash', '.zsh', '.fish', '.bat', '.cmd', '.mdx',
]);

/** Files we always scan regardless of extension. */
const ALWAYS_SCAN = new Set([
  '.env', '.env.local', '.env.production', '.env.development', '.env.staging',
  '.env.test', '.gitignore', '.dockerignore', 'firestore.rules', 'storage.rules',
  'database.rules.json', 'firebase.json', 'vercel.json', 'netlify.toml',
  'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile', '.htaccess', 'nginx.conf',
  '.npmrc', '.yarnrc', '.yarnrc.yml',
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

function repoApiBase(owner, repo) {
  return `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
}

function githubHeaders() {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = { Accept: 'application/vnd.github.v3+json', 'User-Agent': 'vibe-audit' };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

/** Resolve a mutable branch name once so every file comes from one commit. */
export async function resolveGitHubCommit(owner, repo, branch = 'HEAD') {
  const url = `${repoApiBase(owner, repo)}/commits/${encodeURIComponent(branch)}`;
  const res = await fetch(url, { headers: githubHeaders() });
  if (!res.ok) throw makeApiError(res, await res.text());
  const data = await res.json();
  if (!/^[0-9a-f]{40}$/i.test(data.sha || '')) {
    throw new Error('GitHub returned an invalid commit identifier. Remote scan stopped.');
  }
  return data.sha;
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
export async function* fetchRepoFiles(owner, repo, { branch = 'HEAD', commitSha } = {}) {
  const headers = githubHeaders();
  const snapshot = commitSha || await resolveGitHubCommit(owner, repo, branch);

  // 1. Get the recursive tree in a single API call.
  const treeUrl = `${repoApiBase(owner, repo)}/git/trees/${snapshot}?recursive=1`;
  const treeRes = await fetch(treeUrl, { headers });
  if (!treeRes.ok) {
    const body = await treeRes.text();
    throw makeApiError(treeRes, body);
  }
  const treeData = await treeRes.json();
  if (treeData.truncated) {
    throw new Error('GitHub truncated the repository tree. Remote scan stopped instead of reporting partial coverage.');
  }

  // Filter to scannable files.
  const files = (treeData.tree || []).filter((item) => {
    if (item.type !== 'blob') return false;
    // Skip ignored directories.
    const parts = item.path.split('/');
    if (parts.some((p) => IGNORE_DIRS.has(p))) return false;
    // Check extension / name.
    const name = parts[parts.length - 1];
    const ext = extname(name).toLowerCase();
    return SCAN_EXTENSIONS.has(ext) || ALWAYS_SCAN.has(name) || isAgentControlPath(item.path);
  });

  // 2. Fetch each file's content (using blob API for efficiency).
  for (const file of files) {
    if (file.size > 2 * 1024 * 1024) {
      throw new Error(`Scannable file exceeds the 2 MB safety limit: ${file.path}. Remote scan stopped instead of reporting partial coverage.`);
    }
    const blobUrl = `${repoApiBase(owner, repo)}/git/blobs/${encodeURIComponent(file.sha)}`;
    const fileRes = await fetch(blobUrl, { headers }); // vibe-audit-ignore perf-no-await-parallel  (sequential fetch avoids GitHub secondary rate limits)
    if (!fileRes.ok) throw makeApiError(fileRes, await fileRes.text()); // vibe-audit-ignore perf-no-await-parallel
    const blob = await fileRes.json(); // vibe-audit-ignore perf-no-await-parallel
    if (blob.encoding !== 'base64' || typeof blob.content !== 'string') {
      throw new Error(`GitHub returned unsupported blob data for ${file.path}. Remote scan stopped.`);
    }
    const bytes = Buffer.from(blob.content.replace(/\s/g, ''), 'base64');
    if (bytes.length > 2 * 1024 * 1024) {
      throw new Error(`Scannable file exceeds the 2 MB safety limit: ${file.path}. Remote scan stopped instead of reporting partial coverage.`);
    }
    const content = bytes.toString('utf8');
    yield {
      path: `github://${owner}/${repo}@${snapshot}/${file.path}`,
      relativePath: file.path,
      content,
      lines: content.split('\n'),
      _agentControl: isAgentControlPath(file.path),
      _snapshot: snapshot,
    };
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
  const url = `${repoApiBase(owner, repo)}/contents/.vibe-audit.json?ref=${encodeURIComponent(branch)}`;
  const res = await fetch(url, { headers: githubHeaders() });
  if (res.status === 404) return null;
  if (!res.ok) throw makeApiError(res, await res.text());
  const data = await res.json();
  if (data.encoding !== 'base64' || typeof data.content !== 'string') {
    throw new Error('Remote .vibe-audit.json used an unsupported encoding.');
  }
  const text = Buffer.from(data.content.replace(/\s/g, ''), 'base64').toString('utf8');
  return normalizeConfig(JSON.parse(text));
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

  const git = findTrustedExecutable('git', process.cwd());
  if (!git) throw new Error('A trusted Git executable was not found. Refusing a PATH-resolved clone.');
  await new Promise((done, reject) => {
    execFile(git, args, { timeout: 60_000 }, (err, _stdout, stderr) => {
      if (err) {
        reject(new Error(`git clone failed: ${stderr || err.message}`));
      } else {
        done();
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
  const absolute = resolve(dir);
  const expectedPrefix = `${resolve(tmpdir())}${sep}vibe-audit-`;
  if (!absolute.startsWith(expectedPrefix)) return;
  try {
    await rm(absolute, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup.
  }
}
