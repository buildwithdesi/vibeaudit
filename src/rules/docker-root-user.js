/**
 * Rule: docker-root-user
 * Detects Dockerfiles that run containers as root.
 */

/** @typedef {import('./types.js').Rule} Rule */

const DOCKERFILE = /(?:^|\/)Dockerfile(?:\.\w+)?$/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

/** @type {Rule} */
export const dockerRootUser = {
  id: 'docker-root-user',
  name: 'Docker Root User',
  severity: 'warning',
  description: 'Detects Dockerfiles that run containers as root.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!DOCKERFILE.test(file.relativePath)) return [];

    const findings = [];
    const userDirectives = [];

    for (let i = 0; i < file.lines.length; i++) {
      const trimmed = file.lines[i].trim();
      if (/^USER\s+/i.test(trimmed)) {
        userDirectives.push({ line: i + 1, value: trimmed });
      }
    }

    if (userDirectives.length === 0) {
      findings.push({
        ruleId: 'docker-root-user',
        ruleName: 'Docker Root User',
        severity: 'warning',
        message: 'Dockerfile has no USER directive — container runs as root by default.',
        file: file.relativePath,
        line: 1,
        evidence: file.lines[0]?.trim().slice(0, 120),
        fix: 'Add a non-root user before CMD/ENTRYPOINT: "RUN addgroup -S app && adduser -S app -G app" then "USER app". One exploit as root = full system access.',
      });
    } else {
      const last = userDirectives[userDirectives.length - 1];
      if (/^USER\s+root\s*$/i.test(last.value)) {
        findings.push({
          ruleId: 'docker-root-user',
          ruleName: 'Docker Root User',
          severity: 'warning',
          message: 'Dockerfile sets USER root without switching back to a non-root user.',
          file: file.relativePath,
          line: last.line,
          evidence: last.value.slice(0, 120),
          fix: 'Switch to a non-root user after root operations: "USER app" before CMD/ENTRYPOINT.',
        });
      }
    }

    return findings;
  },
};
