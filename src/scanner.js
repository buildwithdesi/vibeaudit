import { readdir, readFile, stat } from 'node:fs/promises';
import { join, extname, relative } from 'node:path';

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
  const ignoreSet = new Set([...ALWAYS_IGNORE, ...extraIgnore]);

  async function* walk(dir) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      // Permission denied or broken symlink — skip silently.
      return;
    }

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (ignoreSet.has(entry.name)) continue;
        yield* walk(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;

      // Check if it's a file we should scan.
      const ext = extname(entry.name).toLowerCase();
      if (!SCAN_EXTENSIONS.has(ext) && !ALWAYS_SCAN.has(entry.name)) continue;

      // Check file size.
      try {
        const stats = await stat(fullPath);
        if (stats.size > MAX_FILE_SIZE || stats.size === 0) continue;
      } catch {
        continue;
      }

      // Read content.
      let content;
      try {
        content = await readFile(fullPath, 'utf-8');
      } catch {
        continue;
      }

      const relativePath = relative(root, fullPath).replace(/\\/g, '/');
      const lines = content.split('\n');

      yield { path: fullPath, relativePath, content, lines };
    }
  }

  yield* walk(root);
}
