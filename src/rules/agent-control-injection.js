import { analyzeAgentControlContent, isAgentControlPath } from '../guard/agent-files.js';

export const agentControlInjection = {
  id: 'agent-control-injection',
  name: 'Poisoned Agent Control File',
  severity: 'critical',
  description: 'Detects concealed download, credential theft, persistence, or guard bypass instructions in AI control files.',
  controlPlane: true,

  check(file) {
    if (!isAgentControlPath(file.relativePath)) return [];
    return analyzeAgentControlContent(file.content, file.relativePath).map((issue) => ({
      ruleId: 'agent-control-injection',
      ruleName: 'Poisoned Agent Control File',
      severity: issue.severity,
      message: issue.message,
      file: file.relativePath,
      line: issue.line,
      evidence: issue.id,
      fix: 'Quarantine this file. Review every instruction manually, then rebuild it from a trusted source. Rotate credentials if the instruction may have run.',
    }));
  },
};
