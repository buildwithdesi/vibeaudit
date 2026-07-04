/**
 * @typedef {'critical' | 'warning' | 'info'} Severity
 */

/**
 * @typedef {Object} FileContext
 * @property {string} path - Absolute path
 * @property {string} relativePath - Path relative to project root
 * @property {string} content - Full file content
 * @property {string[]} lines - Content split by newline
 */

/**
 * @typedef {Object} Finding
 * @property {string} ruleId
 * @property {string} ruleName
 * @property {Severity} severity
 * @property {string} message - What's wrong
 * @property {string} file - Relative file path
 * @property {number} [line] - 1-indexed line number
 * @property {string} [evidence] - Sanitized snippet (secrets redacted)
 * @property {string} fix - How to fix it (plain English or copy-paste prompt)
 * @property {string} [cweId] - CWE identifier (e.g., "CWE-89")
 * @property {number} [cvssScore] - CVSS v3.1 base score (0-10)
 * @property {string} [owaspCategory] - OWASP Top 10 2021 category (e.g., "A03:2021")
 * @property {string} [wcag] - WCAG success criterion for accessibility findings (e.g., "WCAG 1.1.1 (Level A)"). Set instead of cweId/owaspCategory for a11y rules.
 */

/**
 * @typedef {Object} Rule
 * @property {string} id - Unique kebab-case identifier
 * @property {string} name - Human-readable name
 * @property {Severity} severity - Default severity
 * @property {string} description - What this rule checks
 * @property {(file: FileContext) => Finding[]} check - The check function
 */

export {};
