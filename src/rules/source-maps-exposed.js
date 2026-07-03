/**
 * Rule: source-maps-exposed
 * Detects source map configuration that ships .map files to production.
 *
 * Framing matters: this is NOT a "hide your code" control. Minification is hygiene,
 * not security — minified JS is still reversible, and obscurity is not a boundary.
 * The reason to drop prod source maps is to stop shipping dev artifacts that hand
 * over original comments, variable names, and file structure for free reconnaissance.
 */

/** @typedef {import('./types.js').Rule} Rule */

/** Config patterns that enable source maps in production. */
const SOURCE_MAP_PATTERNS = [
  // Webpack/Vite: devtool or sourcemap set to a non-hidden value
  {
    regex: /(?:devtool|sourcemap)\s*[:=]\s*['"`](?:source-map|eval-source-map|inline-source-map|cheap-source-map|cheap-module-source-map|eval)['"`]/gi,
    label: 'Source maps enabled — full source code visible in DevTools Sources tab',
    context: 'build-config',
  },
  // Vite config: sourcemap: true
  {
    regex: /sourcemap\s*:\s*true/gi,
    label: 'Source maps enabled in build config — full source visible in DevTools',
    context: 'build-config',
  },
  // Next.js: productionBrowserSourceMaps: true
  {
    regex: /productionBrowserSourceMaps\s*:\s*true/gi,
    label: 'Production source maps enabled in Next.js — full source code exposed',
    context: 'build-config',
  },
  // Nuxt: sourcemap in nuxt.config
  {
    regex: /sourcemap\s*:\s*(?:true|\{[^}]*client\s*:\s*true)/gi,
    label: 'Client-side source maps enabled — full source visible in DevTools',
    context: 'build-config',
  },
];

/** Only check build/framework config files. */
const CONFIG_FILES = /(?:webpack\.config|vite\.config|next\.config|nuxt\.config|rollup\.config|esbuild|tsconfig)/i;

/** Source map reference in compiled files. */
const SOURCEMAP_COMMENT = /\/\/[#@]\s*sourceMappingURL\s*=\s*(?!data:)/g;

/** @type {Rule} */
export const sourceMapsExposed = {
  id: 'source-maps-exposed',
  name: 'Source Maps Exposed',
  severity: 'warning',
  description: 'Detects source map configs that expose your full source code in production via DevTools Sources tab.',

  check(file) {
    const findings = [];
    const isConfig = CONFIG_FILES.test(file.relativePath);

    if (isConfig) {
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

        for (const { regex, label } of SOURCE_MAP_PATTERNS) {
          regex.lastIndex = 0;
          if (regex.test(line)) {
            findings.push({
              ruleId: 'source-maps-exposed',
              ruleName: 'Source Maps Exposed',
              severity: 'warning',
              message: label,
              file: file.relativePath,
              line: i + 1,
              evidence: trimmed.slice(0, 120),
              fix: `Drop source maps from production builds, or use "hidden-source-map" (maps are generated for error tools but not referenced in the bundle). Framing matters: minification is hygiene, not a security control — a determined attacker can still read minified JS, so this isn't about "hiding" logic. The point is to stop shipping dev artifacts that expose original comments, names, and structure for free reconnaissance. Never rely on minification to protect a secret — keep secrets server-side.`,
            });
          }
        }
      }
    }

    return findings;
  },
};
