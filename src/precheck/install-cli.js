import { parseArgs } from 'node:util';
import { installReviewed, installStatus, reviewInstall, rollbackInstall } from './protected-install.js';

const HELP = `VibeGuard protected npm installation (public registry, single project)

  npm review <package> --project <directory> [--dev] [--store <directory>]
  npm install <review-id> --accept <review-id> [--store <directory>]
  npm status <review-id> [--store <directory>]
  npm rollback <review-id> [--store <directory>]

Review prints the exact package checks and a review ID. Inspect warnings before
accepting that ID. Reviews expire after 10 minutes and allow one install attempt.
Install uses only reviewed archives, offline, with all installation scripts off.
Backups support rollback; changed user files are preserved and reported.
This does not sandbox later imports, builds, or application execution.
All results are JSON for both people and coding agents. --json is also accepted.
Guide: docs/protected-npm-install.md
`;

export async function installCli(args) {
  try {
    const { values, positionals } = parseArgs({ args, strict: true, allowPositionals: true, options: {
      project: { type: 'string' }, dev: { type: 'boolean' }, store: { type: 'string' },
      accept: { type: 'string' }, json: { type: 'boolean' }, help: { type: 'boolean' },
    } });
    if (values.help || !positionals.length) { console.log(HELP); return 0; }
    const [action, subject] = positionals;
    const allowed = { review: ['project', 'dev', 'store', 'json'], install: ['accept', 'store', 'json'], status: ['store', 'json'], rollback: ['store', 'json'] };
    if (!allowed[action] || positionals.length !== 2 || Object.keys(values).some((key) => !allowed[action].includes(key))) throw new Error('Invalid npm workflow arguments. Use vibeguard npm --help.');
    let result;
    if (action === 'review') result = await reviewInstall({ ...values, spec: subject });
    else if (action === 'install') result = await installReviewed(subject, values);
    else if (action === 'status') result = installStatus(subject, values);
    else result = rollbackInstall(subject, values);
    console.log(JSON.stringify(result, null, 2));
    return ['blocked', 'failed', 'recovery-required'].includes(result.attempt?.status || result.status) ? 4 : 0;
  } catch (error) {
    console.error(JSON.stringify({ status: 'blocked', error: error.message }));
    return 4;
  }
}
