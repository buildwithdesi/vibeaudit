/**
 * Exit with `code` once everything already written to stdout and stderr
 * has been handed to the operating system.
 *
 * process.exit() drops output that is still queued. A parent process that
 * spawns this CLI with stdio "pipe" reads through a socket pair, and socket
 * writes are asynchronous, so `--list-rules` or `--format json` output was
 * cut short under load while the exit status still said success.
 *
 * The returned promise never settles: `await exitAfterFlush(code)` stops the
 * caller the same way process.exit() did.
 *
 * @param {number} code
 * @returns {Promise<never>}
 */
export function exitAfterFlush(code) {
  process.exitCode = code;
  let pending = 2;
  const done = () => {
    pending -= 1;
    if (pending === 0) process.exit(code);
  };
  // An empty write completes only after every earlier write on the stream.
  process.stdout.write('', done);
  process.stderr.write('', done);
  return new Promise(() => {});
}
