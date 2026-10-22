/**
 * Rule: php-stack
 * Flags a PHP stack: composer.json manifests, .php source files, and PHP base
 * images or services in Docker configuration.
 *
 * This is a stack-policy rule, not a vulnerability rule. The standing doctrine
 * is: no PHP; choose the optimal stack even when that means a rewrite (Linux +
 * Rust backends, strict TypeScript frontends). PHP also carries fresh, concrete
 * risk: the October 2026 PHP releases (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) fixed
 * unauthenticated remote-code-execution bugs, and 8.1 and older got no fix —
 * which is why the fix text says to patch first and plan the migration second.
 */

/** @typedef {import('./types.js').Rule} Rule */
/** @typedef {import('./types.js').Finding} Finding */

const COMPOSER = /(?:^|\/)composer\.json$/;
const PHP_FILE = /\.php$/i;
const DOCKERFILE = /(?:^|\/)(?:Dockerfile|.*\.dockerfile)$/i;
const COMPOSE = /(?:^|\/)docker-compose\.ya?ml$/i;

const PATCHED = '8.5.12 / 8.4.27 / 8.3.36 / 8.2.35';

function finding(file, line, evidence, severity, message, fix) {
  return {
    ruleId: 'php-stack',
    ruleName: 'PHP Stack',
    severity,
    message,
    file: file.relativePath,
    line,
    evidence,
    fix,
  };
}

function lineOf(file, needle) {
  const idx = file.lines.findIndex((l) => l.includes(needle));
  return { line: idx >= 0 ? idx + 1 : 1, evidence: idx >= 0 ? file.lines[idx].trim().slice(0, 120) : undefined };
}

const MIGRATION_FIX = 'Plan the move off PHP to the standard stack (Linux + Rust services, strict TypeScript frontends) rather than growing this codebase. Until it is migrated, keep PHP on a patched release — as of October 2026 that is 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or newer; 8.1 and older received no fix for the October 2026 RCE bugs.';

/** @type {Rule} */
export const phpStack = {
  id: 'php-stack',
  name: 'PHP Stack',
  severity: 'warning',
  description: 'Flags PHP in the stack: composer.json manifests, .php source files, and PHP images in Docker configuration. Standing doctrine is no PHP; choose the optimal stack even if it means a rewrite.',

  check(file) {
    const p = file.relativePath;

    if (COMPOSER.test(p)) {
      const at = lineOf(file, '"name"');
      return [finding(file, at.line, at.evidence, 'warning',
        'composer.json: this project is a PHP application. The standing stack doctrine is no PHP.',
        MIGRATION_FIX)];
    }

    if (PHP_FILE.test(p)) {
      return [finding(file, 1, file.lines[0]?.trim().slice(0, 120), 'info',
        'PHP source file. The standing stack doctrine is no PHP; this file belongs to the migration inventory.',
        MIGRATION_FIX)];
    }

    if (DOCKERFILE.test(p)) {
      const out = [];
      file.lines.forEach((line, i) => {
        if (!/^\s*FROM\s+\S*php(?=[:\s-]|$)/i.test(line)) return;
        out.push(finding(file, i + 1, line.trim().slice(0, 120), 'warning',
          `Dockerfile builds on a PHP image ("${line.trim().slice(0, 80)}"). The standing stack doctrine is no PHP, and the container is what ships.`,
          `Rebuild the service on the standard stack. Until then, pin a patched PHP release (${PATCHED} or newer, as of October 2026), rebuild without cache, and redeploy.`));
      });
      return out;
    }

    if (COMPOSE.test(p)) {
      const out = [];
      file.lines.forEach((line, i) => {
        if (!/^\s*image:\s*["']?\S*php/i.test(line)) return;
        out.push(finding(file, i + 1, line.trim().slice(0, 120), 'warning',
          'docker-compose runs a PHP image. The standing stack doctrine is no PHP.',
          `Replace the service with the standard stack. Until then, pin a patched PHP release (${PATCHED} or newer, as of October 2026) and redeploy.`));
      });
      return out;
    }

    return [];
  },
};
