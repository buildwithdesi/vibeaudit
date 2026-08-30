import { readdir, readFile, stat } from 'node:fs/promises';
import { join, extname, relative } from 'node:path';
import { isAgentControlPath } from './guard/agent-files.js';

/** Directories that are never worth scanning. */
const ALWAYS_IGNORE = new Set([
  'node_modules',
  '.git',
  '.next',
  '.nuxt',
  'dist',
  'build',
  '.output',
  '.vercel',
  '.netlify',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
  '.svelte-kit',
]);

/** File extensions we actually care about. */
const SCAN_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.vue',
  '.svelte',
  '.json',
  '.env',
  '.yaml',
  '.yml',
  '.toml',
  '.html',
  '.htm',
  '.css',
  '.py',
  '.rb',
  '.go',
  '.rs',
  '.php',
  '.java',
  '.kt',
  '.swift',
  '.dart',
  '.rules',       // Firestore rules
  '.lock',        // Lock files can leak registry info
  '.ps1',
  '.psm1',
  '.sh',
  '.bash',
  '.zsh',
  '.fish',
  '.bat',
  '.cmd',
  '.mdx',
]);

/** Files we always scan regardless of extension. */
const ALWAYS_SCAN = new Set([
  '.env',
  '.env.local',
  '.env.production',
  '.env.development',
  '.env.staging',
  '.env.test',
  '.gitignore',
  '.dockerignore',
  'firestore.rules',
  'storage.rules',
  'database.rules.json',
  'firebase.json',
  'vercel.json',
  'netlify.toml',
  'docker-compose.yml',
  'docker-compose.yaml',
  'Dockerfile',
  '.htaccess',
  'nginx.conf',
  '.npmrc',
  '.yarnrc',
  '.yarnrc.yml',
]);

/** Max file size to read (2 MB). Anything bigger is not source code. */
const MAX_FILE_SIZE = 2 * 1024 * 1024;

/**
 * Walk a directory tree and yield scannable files.
 *
 * @param {string} root  - Absolute path to project root
 * @param {string[]} extraIgnore - Additional patterns from config
 * @returns {AsyncGenerator<{path: string, relativePath: string, content: string, lines: string[]}>}
 */
export async function* discoverFiles(root, extraIgnore = []) {
  const ignorePatterns = [...ALWAYS_IGNORE, ...extraIgnore]
    .map((pattern) => String(pattern).replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/$/, ''))
    .filter(Boolean);

  function ignored(relativePath) {
    const normalized = relativePath.replace(/\\/g, '/').replace(/\/$/, '');
    const segments = normalized.split('/');
    return ignorePatterns.some((pattern) => {
      if (pattern.includes('/')) return normalized === pattern || normalized.startsWith(`${pattern}/`);
      return segments.includes(pattern);
    });
  }

  async function* walk(dir) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (error) {
      throw new Error(`Scan incomplete. Could not read directory ${dir}: ${error.code || error.message}`);
    }

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      const relativePath = relative(root, fullPath).replace(/\\/g, '/');

      if (entry.isDirectory()) {
        if (ignored(relativePath)) continue;
        yield* walk(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;

      // Check if it's a file we should scan.
      const ext = extname(entry.name).toLowerCase();
      const agentControl = isAgentControlPath(relativePath);
      if (!SCAN_EXTENSIONS.has(ext) && !ALWAYS_SCAN.has(entry.name) && !agentControl) continue;

      // Check file size.
      try {
        const stats = await stat(fullPath); // vibe-audit-ignore perf-no-await-parallel  (streaming walker reads one entry at a time)
        if (stats.size > MAX_FILE_SIZE) {
          throw new Error(`Scan incomplete. Scannable file exceeds the 2 MB limit: ${relativePath}`);
        }
        if (stats.size === 0) continue;
      } catch (error) {
        if (/^Scan incomplete\./.test(error.message)) throw error;
        throw new Error(`Scan incomplete. Could not inspect ${relativePath}: ${error.code || error.message}`);
      }

      // Read content.
      let content;
      try {
        content = await readFile(fullPath, 'utf-8'); // vibe-audit-ignore perf-no-await-parallel  (streaming walker reads one entry at a time)
      } catch (error) {
        throw new Error(`Scan incomplete. Could not read ${relativePath}: ${error.code || error.message}`);
      }

      const lines = content.split('\n');

      yield { path: fullPath, relativePath, content, lines, _agentControl: agentControl };
    }
  }

  yield* walk(root);
}
