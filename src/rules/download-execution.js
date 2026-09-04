import { analyzeCommand } from '../guard/command.js';

const SCRIPT_EXTENSIONS = /\.(?:ps1|psm1|sh|bash|zsh|fish|bat|cmd)$/i;

export const downloadExecution = {
  id: 'download-execution',
  name: 'Download and Execute',
  severity: 'critical',
  description: 'Detects commands that download unverified content and immediately execute it.',
  controlPlane: true,

  check(file) {
    if (!SCRIPT_EXTENSIONS.test(file.relativePath) && !file._agentControl) return [];
    const analysis = analyzeCommand(file.content);
    if (analysis.decision === 'allow') return [];
    return analysis.findings
      .filter((issue) => {
        if (issue.id === 'package-install') return Boolean(file._agentControl);
        if (['high-impact-action', 'destructive-file-operation', 'agent-control-tampering'].includes(issue.id)) {
          return Boolean(file._agentControl);
        }
        return true;
      })
      .map((issue) => ({
      ruleId: 'download-execution',
      ruleName: 'Download and Execute',
      severity: analysis.decision === 'deny' ? 'critical' : 'warning',
      message: issue.message,
      file: file.relativePath,
      line: 1,
      evidence: issue.id,
      fix: 'Separate download from execution. Verify the publisher, final domain, checksum, and signature before running the artifact.',
      }));
  },
};
