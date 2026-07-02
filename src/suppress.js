/**
 * Finding suppression + per-path rule disabling.
 *
 * Applied once in the scanner core so every rule supports the same escape
 * hatch without each rule re-implementing it:
 *
 *   const x = something();        // vibe-audit-ignore missing-auth
 *   // vibe-audit-ignore-next-line supabase-service-key-client
 *   const admin = createServiceRoleClient();
 *
 * A bare `vibe-audit-ignore` (no rule id) suppresses every rule on that line.
 * Multiple ids can be comma-separated.
 */

const SUPPRESS = /vibe-audit-ignore(-next-line)?(?:\s*[:=]?\s*([\w-]+(?:\s*,\s*[\w-]+)*))?/i;

function matchSuppression(text, ruleId, requireNextLine) {
  if (!text) return false;
  const m = SUPPRESS.exec(text);
  if (!m) return false;
  const isNextLine = Boolean(m[1]);
  // A `-next-line` directive only suppresses the line below it; a plain
  // directive only suppresses its own line.
  if (requireNextLine && !isNextLine) return false;
  if (!requireNextLine && isNextLine) return false;
  const ids = m[2]
    ? m[2].split(',').map((s) => s.trim()).filter(Boolean)
    : null;
  return !ids || ids.includes(ruleId);
}

/**
 * Is this finding suppressed by an inline comment on its line or the line above?
 *
 * @param {{lines: string[]}} file
 * @param {{line?: number, ruleId: string}} finding
 * @returns {boolean}
 */
export function isSuppressed(file, finding) {
  const ln = finding.line;
  if (!ln || !Array.isArray(file.lines)) return false;
  if (matchSuppression(file.lines[ln - 1], finding.ruleId, false)) return true;
  if (matchSuppression(file.lines[ln - 2], finding.ruleId, true)) return true;
  return false;
}

/**
 * Is a rule disabled for this path via `.vibe-audit.json` `disableForPaths`?
 * Shape: { "rule-id": ["regex-or-substring", ...] }
 *
 * @param {{disableForPaths?: Record<string, string[]>}} config
 * @param {string} ruleId
 * @param {string} relativePath
 * @returns {boolean}
 */
export function pathDisabledFor(config, ruleId, relativePath) {
  const map = config?.disableForPaths;
  if (!map || typeof map !== 'object') return false;
  const patterns = map[ruleId];
  if (!Array.isArray(patterns)) return false;
  return patterns.some((p) => {
    try {
      return new RegExp(p).test(relativePath);
    } catch {
      return relativePath.includes(p);
    }
  });
}
