/**
 * Fleet JSON reporter — machine-readable output for CI pipelines and dashboards.
 * @param {import('../fleet.js').FleetResult} fleet
 */
export function reportFleetJSON(fleet) {
  const output = {
    summary: {
      totalRepos: fleet.totalRepos,
      scannedRepos: fleet.scannedRepos,
      failedRepos: fleet.failedRepos,
      totalFindings: fleet.totalFindings,
      critical: fleet.totalCritical,
      warning: fleet.totalWarning,
      info: fleet.totalInfo,
      durationMs: fleet.durationMs,
      timestamp: new Date().toISOString(),
    },
    repos: fleet.repos.map(r => ({
      repo: r.repo,
      grade: r.grade,
      critical: r.critical,
      warning: r.warning,
      info: r.info,
      total: r.total,
      filesScanned: r.filesScanned,
      durationMs: r.durationMs,
      error: r.error,
      findings: r.findings.map(f => ({
        ruleId: f.ruleId,
        severity: f.severity,
        message: f.message,
        file: f.file,
        line: f.line || null,
        cweId: f.cweId || null,
        cvssScore: f.cvssScore || null,
        owaspCategory: f.owaspCategory || null,
        evidence: f.evidence || null,
        fix: f.fix,
      })),
    })),
  };

  console.log(JSON.stringify(output, null, 2));
}
