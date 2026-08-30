import { lstat, writeFile } from 'node:fs/promises';
import { basename, dirname, extname, join } from 'node:path';

async function exists(filePath) {
  try {
    await lstat(filePath);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}
/**
 * Write a new report without following or replacing an attacker-created link.
 * If the usual filename exists, use a timestamped sibling instead.
 *
 * @param {string} preferredPath
 * @param {string} content
 * @returns {Promise<string>}
 */
export async function writeNewOutput(preferredPath, content) {
  let filePath = preferredPath;
  if (await exists(filePath)) {
    const extension = extname(filePath);
    const stem = basename(filePath, extension);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    filePath = join(dirname(filePath), `${stem}-${stamp}-${process.pid}${extension}`);
  }
  await writeFile(filePath, content, { encoding: 'utf8', flag: 'wx' });
  return filePath;
}
