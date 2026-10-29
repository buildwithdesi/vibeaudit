/**
 * Close undici keep-alive sockets, then set process.exitCode.
 * process.exit() while a fetch handle is still open is the Windows
 * libuv crash on `vibeaudit --precheck`.
 *
 * @param {number} code
 * @returns {Promise<void>}
 */
export async function closeAndSetExitCode(code) {
  try {
    const undici = await import("node:undici");
    const dispatcher = undici.getGlobalDispatcher?.();
    if (dispatcher && typeof dispatcher.close === "function") {
      await dispatcher.close();
    }
  } catch {
    // Older Node without node:undici: skip. exitCode still lets the process end.
  }
  process.exitCode = code;
}
