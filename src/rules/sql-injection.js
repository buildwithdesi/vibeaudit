/**
 * Rule: sql-injection
 * Detects SQL queries built with string concatenation or template-literal
 * interpolation of variables — the classic SQL injection pattern (CWE-89).
 *
 * The attack: any value glued directly into the query text can break out of
 * the intended query and run attacker-controlled SQL — dump the whole table,
 * drop it, or auth-bypass with `' OR '1'='1`.
 *
 * Safe code uses parameterized queries / prepared statements (`?`, `$1`,
 * named bindings) and passes user values as a separate argument, so this rule
 * only fires when a variable is interpolated INTO the SQL string itself.
 */

/** @typedef {import('./types.js').Rule} Rule */

const SKIP_PATTERN = /(?:\.test\.|\.spec\.|__tests__|\.d\.ts$)/i;
const SKIP_RULES = /src\/rules\//i;

// A SQL DML/DDL verb — the statement type.
const VERB = 'SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE|DROP|TRUNCATE|ALTER|CREATE';
// A SQL clause word — proves the string is really SQL, not English prose.
const CLAUSE = 'FROM|INTO|WHERE|SET|VALUES|TABLE|JOIN|COLUMN|DATABASE';

// Template literal that contains a real SQL statement AND an interpolation.
const DYNAMIC_TEMPLATE = new RegExp(
  '`[^`]*\\b(?:' + VERB + ')\\b[^`]*\\b(?:' + CLAUSE + ')\\b[^`]*\\$\\{[^}]+\\}',
  'i',
);

// Quoted SQL string immediately concatenated with a variable (not another literal).
const DYNAMIC_CONCAT = new RegExp(
  '[\'"][^\'"]*\\b(?:' + VERB + ')\\b[^\'"]*\\b(?:' + CLAUSE + ')\\b[^\'"]*[\'"]\\s*\\+\\s*[A-Za-z_$]',
  'i',
);

/** @type {Rule} */
export const sqlInjection = {
  id: 'sql-injection',
  name: 'SQL Injection',
  severity: 'critical',
  description:
    'Detects SQL queries built via string concatenation or template-literal interpolation instead of parameterized queries.',

  check(file) {
    if (SKIP_PATTERN.test(file.relativePath)) return [];
    if (SKIP_RULES.test(file.relativePath)) return [];

    const upper = file.content.toUpperCase();
    // Cheap pre-filter: bail unless the file mentions a SQL verb at all.
    if (!/SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE|DROP|TRUNCATE|ALTER|CREATE/.test(upper)) {
      return [];
    }

    const findings = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;

      DYNAMIC_TEMPLATE.lastIndex = 0;
      DYNAMIC_CONCAT.lastIndex = 0;

      const isTemplate = DYNAMIC_TEMPLATE.test(line);
      const isConcat = !isTemplate && DYNAMIC_CONCAT.test(line);
      if (!isTemplate && !isConcat) continue;

      findings.push({
        ruleId: 'sql-injection',
        ruleName: 'SQL Injection',
        severity: 'critical',
        message: isTemplate
          ? 'SQL query built with template-literal interpolation — user input can rewrite the query.'
          : 'SQL query built with string concatenation — user input can rewrite the query.',
        file: file.relativePath,
        line: i + 1,
        evidence: trimmed.slice(0, 120),
        fix: 'Use parameterized queries / prepared statements. Pass values as a separate argument, never build the SQL string with `+` or `${}`. Examples: pg — client.query("SELECT * FROM users WHERE id = $1", [id]); mysql2 — conn.execute("SELECT * FROM users WHERE id = ?", [id]); Prisma/Drizzle — use the query builder or sql`...${id}` tagged templates that bind safely.',
      });
    }

    return findings;
  },
};
