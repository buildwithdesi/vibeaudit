// Trusted container PID 1. The workload cannot signal this root-owned deadline.
import { spawn } from 'node:child_process';
import { setTimeout } from 'node:timers';

const [entry, secondsText] = process.argv.slice(2);
const seconds = Number(secondsText);
if (process.getuid() !== 0 || !/^\/skill\/[A-Za-z0-9_./-]+\.mjs$/.test(entry || '') ||
    !Number.isInteger(seconds) || seconds < 1 || seconds > 60) process.exit(125);

const child = spawn('/usr/local/bin/node', [entry], {
  uid: 65534, gid: 65534, cwd: '/tmp', stdio: ['ignore', 'inherit', 'inherit'],
  env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', TMPDIR: '/tmp' },
});
// Exiting PID 1 also terminates descendants in this PID namespace. This deadline
// survives loss of the host CLI and cannot be cancelled by the unprivileged child.
setTimeout(() => process.exit(124), seconds * 1000);
child.on('error', () => process.exit(125));
child.on('exit', (code) => process.exit(Number.isInteger(code) ? code : 125));
