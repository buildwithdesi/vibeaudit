import { runGitleaksAdapter } from './gitleaks.js';
import { runSemgrepAdapter } from './semgrep.js';

const DEFAULT_ADAPTERS = { gitleaks: runGitleaksAdapter, semgrep: runSemgrepAdapter };

/** Keep optional external scanners behind one explicit, testable seam. */
export function runSecurityAdapters(files, { enabled = [], adapters = DEFAULT_ADAPTERS, adapterOptions = {} } = {}) {
  const results = [];
  for (const name of enabled) {
    const adapter = adapters[name];
    if (!adapter) {
      results.push({ tool: name, status: 'unavailable', coverage: { complete: false, reason: `Unknown adapter: ${name}` }, findings: [] });
      continue;
    }
    try {
      results.push(adapter(files, adapterOptions[name] || {}));
    } catch {
      results.push({ tool: name, status: 'failed', coverage: { complete: false, reason: `${name} adapter failed before producing a report.` }, findings: [] });
    }
  }
  return { complete: results.every((result) => result.coverage?.complete === true), results };
}
