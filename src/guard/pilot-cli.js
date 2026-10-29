import { parseArgs } from 'node:util';
import { approvePilot, doctorPilot, recoverPilot, reviewPilot, revokePilot, runPilot, statusPilot } from './pilot.js';

const HELP = `VibeGuard protection pilot (offline Node skills, local Linux Docker)

  pilot doctor --image node@sha256:<digest> [--json]
  pilot review <skill-dir> --input <dir> --image node@sha256:<digest>
    [--entry run.mjs] [--seconds 30] [--store <external-dir>] [--json]
  pilot approve <review-id> --accept <review-id> [--store <dir>]
  pilot run <review-id> [--store <dir>] [--json]
  pilot revoke <review-id> [--store <dir>]
  pilot status [--store <dir>]
  pilot recover <run-id> [--store <dir>]

Run doctor before review and approval; readiness does not verify active isolation.
Review the manifest, files, findings, and policy before approving the digest.
Approvals expire after 10 minutes and permit one attempt. Run never pulls images.
No network or host credentials. Output is untrusted and stays in a JSON receipt.
Guide: docs/protection-pilot.md
`;

export async function pilotCli(args) {
  let machine = false;
  try {
    const { values, positionals } = parseArgs({ args, allowPositionals: true, strict: true, options: {
      input: { type: 'string' }, entry: { type: 'string' }, image: { type: 'string' },
      store: { type: 'string' }, seconds: { type: 'string' }, accept: { type: 'string' },
      json: { type: 'boolean' }, help: { type: 'boolean' },
    } });
    machine = Boolean(values.json);
    const [action, id] = positionals;
    if (!action || values.help) { console.log(HELP); return 0; }
    let result;
    switch (action) {
      case 'doctor':
        if (positionals.length !== 1 || Object.keys(values).some((key) => !['image', 'json'].includes(key))) {
          throw new Error('Use pilot doctor --image node@sha256:<digest> [--json]. Doctor does not read or change a pilot store.');
        }
        result = await doctorPilot(values);
        break;
      case 'review': result = await reviewPilot({ ...values, skill: id, seconds: values.seconds === undefined ? 30 : Number(values.seconds) }); break;
      case 'approve': result = approvePilot(id, values); break;
      case 'run': result = await runPilot(id, values); break;
      case 'revoke': result = revokePilot(id, values); break;
      case 'status': result = statusPilot(values); break;
      case 'recover': result = await recoverPilot(id, values); break;
      default: throw new Error('Unknown pilot command. Use pilot --help.');
    }
    // JSON escaping prevents terminal escapes in skill-supplied paths or output.
    if (action === 'doctor' && !machine) console.log([
      `${result.status.toUpperCase()}: ${result.message} (${result.reasonCode})`,
      ...result.checks.map((check) => `  ${check.name}: ${check.status} (${check.reasonCode}) — ${check.message}`),
      `Next step: ${result.nextStep}`, result.note,
    ].join('\n'));
    else if (machine || action === 'review' || action === 'status') console.log(JSON.stringify(result, null, 2));
    else console.log(JSON.stringify({ status: result.status || 'approved', id: result.id,
      runId: result.runId, receiptPath: result.receiptPath, error: result.error,
      reasonCode: result.reasonCode, nextStep: result.nextStep, expiresAt: result.expiresAt }, null, 2));
    return ['blocked', 'failed', 'unavailable', 'interrupted'].includes(result.status) ? 4 : 0;
  } catch (error) {
    console.error(JSON.stringify({ status: 'blocked', error: error.message }));
    return 4;
  }
}
