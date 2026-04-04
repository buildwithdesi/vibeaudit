/**
 * Rule: exposed-database-port
 * Detects database ports exposed to the host in docker-compose files.
 */

/** @typedef {import('./types.js').Rule} Rule */

const COMPOSE_FILE = /(?:^|\/)docker-compose(?:\.\w+)?\.ya?ml$/i;
const SKIP = /(?:\.test\.|\.spec\.|__tests__|node_modules)/i;

const DB_PORTS = {
  5432: 'PostgreSQL',
  3306: 'MySQL',
  27017: 'MongoDB',
  6379: 'Redis',
  1433: 'MSSQL',
  9200: 'Elasticsearch',
  5984: 'CouchDB',
};

/** @type {Rule} */
export const exposedDatabasePort = {
  id: 'exposed-database-port',
  name: 'Exposed Database Port',
  severity: 'warning',
  description: 'Detects database ports exposed to the host in docker-compose files.',

  check(file) {
    if (SKIP.test(file.relativePath)) return [];
    if (!COMPOSE_FILE.test(file.relativePath)) return [];

    const findings = [];
    let inPorts = false;

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const trimmed = line.trim();

      // Detect start of "ports:" section
      if (/^ports\s*:/i.test(trimmed)) {
        inPorts = true;
        continue;
      }

      // Exit ports section on a new top-level or same-level key
      if (inPorts && /^\S/.test(line) && !/^\s*-/.test(line)) {
        inPorts = false;
      }

      if (inPorts && trimmed.startsWith('-')) {
        // Match port mappings: "5432:5432", 5432:5432, "0.0.0.0:5432:5432"
        const match = trimmed.match(/['"]?(?:[\d.]+:)?(\d+):\d+['"]?/);
        if (match) {
          const hostPort = match[1];
          const dbName = DB_PORTS[hostPort];
          if (dbName) {
            findings.push({
              ruleId: 'exposed-database-port',
              ruleName: 'Exposed Database Port',
              severity: 'warning',
              message: `${dbName} port ${hostPort} is exposed to the host. In production, databases should not be directly accessible.`,
              file: file.relativePath,
              line: i + 1,
              evidence: trimmed.slice(0, 120),
              fix: `Remove the ports mapping for ${dbName} or use "expose:" instead of "ports:" for container-to-container communication only. Never expose database ports in production.`,
            });
          }
        }
      }
    }

    return findings;
  },
};
