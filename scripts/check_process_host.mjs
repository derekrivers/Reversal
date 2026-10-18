// Diagnose the hosted Node/ps failure without printing process command lines.
import { execFile } from 'node:child_process';
execFile('ps', ['-axo', 'pid=,ppid=,pgid=,uid=,stat=,command='], (error, stdout, stderr) => {
  const ownProcessPresent = stdout.split('\n').some(line => Number(line.trim().split(/\s+/)[0]) === process.pid);
  console.log(JSON.stringify({ node: process.version, exitCode: error?.code ?? 0, ownProcessPresent, stderr: stderr.trim() }, null, 2));
  process.exitCode = error || !ownProcessPresent ? 1 : 0;
});
