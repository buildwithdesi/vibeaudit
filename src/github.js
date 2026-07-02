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
    throw new Error(`GitHub API error (${treeRes.status}): ${body}`);
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
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${file.path}`;
      const fileRes = await fetch(rawUrl, { headers });
      if (!fileRes.ok) continue;

      const content = await fileRes.text();
      // Skip huge files (> 2 MB).
      if (content.length > 2 * 1024 * 1024) continue;

      const lines = content.split('\n');
      yield {
        path: `github://${owner}/${repo}/${file.path}`,
        relativePath: file.path,
        content,
        lines,
      };
    } catch {
      // Skip files we can't fetch.
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
