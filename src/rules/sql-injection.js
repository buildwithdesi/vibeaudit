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

const TEMPLATE_BODY = '[^`]*\\b(?:' + VERB + ')\\b[^`]*\\b(?:' + CLAUSE + ')\\b[^`]*\\$\\{[^}]+\\}';
const CONCAT_BODY =
  '[\'"][^\'"]*\\b(?:' + VERB + ')\\b[^\'"]*\\b(?:' + CLAUSE + ')\\b[^\'"]*[\'"]\\s*\\+\\s*[A-Za-z_$]';

// Two tiers, because casing is the only cheap signal that separates real SQL
// from English prose that happens to contain "drop ... from ... ${n}".
// Tier A (uppercase) is conventional in code and fires on its own.
// Tier B (any case) is ambiguous, so it additionally requires a query sink
// nearby — otherwise a sentence in an LLM prompt reads as an injection.
const TEMPLATE_UPPER = new RegExp(TEMPLATE_BODY);
const TEMPLATE_ANY = new RegExp(TEMPLATE_BODY, 'i');
const CONCAT_UPPER = new RegExp(CONCAT_BODY);
const CONCAT_ANY = new RegExp(CONCAT_BODY, 'i');

// Something that actually executes SQL, near the suspect line.
const SINK =
  /\b(?:query|execute|exec|executemany|queryRaw|executeRaw|prepare|raw)\s*\(|\b(?:knex|pool|conn|connection|client|cursor|db|database|sequelize)\s*\.|(?:const|let|var)\s+\w*(?:sql|query|stmt)\w*\s*=/i;
const SINK_RADIUS = 3;

// Places a SQL-shaped string is written, not run. Logging a query is not
// injection; the injection lives at the sink.
const NON_SINK =
  /\b(?:console|logger|prompt|systemPrompt|instructions)\b|\blog\.(?:info|warn|debug|error)\b|\b(?:process\.)?std(?:out|err)\.write\b|throw\s+new\s+\w*Error/i;

// A tagged template (sql`...`, db.sql`...`, prisma.$queryRaw`...`) binds its
// interpolations as parameters — that is the SAFE pattern this rule's own fix
// text recommends. Only the explicitly-unsafe escape hatches still count.
const TAG_BEFORE_BACKTICK = /([A-Za-z0-9_$.[\]]+)$/;
const UNSAFE_TAG = /(?:unsafe$|\.raw$|^raw$)/i;

/**
 * Find a dynamic-SQL template literal on this line that is NOT a safely-bound
 * tagged template.
 *
 * @param {string} line
 * @param {boolean} sinkNearby whether a query sink sits within SINK_RADIUS lines
 * @returns {boolean} true when the line should be reported
 */
function hasUnsafeTemplate(line, sinkNearby) {
  let from = 0;
  for (;;) {
    const open = line.indexOf('`', from);
    if (open === -1) return false;
    const close = line.indexOf('`', open + 1);
    if (close === -1) return false;

    const span = line.slice(open, close + 1);
    const matches = TEMPLATE_UPPER.test(span) || (sinkNearby && TEMPLATE_ANY.test(span));

    if (matches) {
      const tag = TAG_BEFORE_BACKTICK.exec(line.slice(0, open))?.[1] || '';
      // No tag → a bare template being glued into a query. Tagged → bound,
      // unless it is one of the documented raw/unsafe escape hatches.
      if (!tag || UNSAFE_TAG.test(tag)) return true;
    }

    from = close + 1;
  }
}

/**
 * Is there something that executes SQL within SINK_RADIUS lines of `index`?
 * Multi-line query builds are common, so the sink is rarely on the same line
 * as the interpolation.
 *
 * @param {string[]} lines
 * @param {number} index
 */
function hasSinkNear(lines, index) {
  const start = Math.max(0, index - SINK_RADIUS);
  const end = Math.min(lines.length - 1, index + SINK_RADIUS);
  for (let i = start; i <= end; i++) {
    if (SINK.test(lines[i])) return true;
  }
  return false;
}

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

      const sinkNearby = hasSinkNear(file.lines, i);
      // A logging/prompt line with no sink on it is writing SQL, not running it.
      if (!SINK.test(line) && NON_SINK.test(line)) continue;

      const isTemplate = hasUnsafeTemplate(line, sinkNearby);
      const isConcat =
        !isTemplate && (CONCAT_UPPER.test(line) || (sinkNearby && CONCAT_ANY.test(line)));
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
