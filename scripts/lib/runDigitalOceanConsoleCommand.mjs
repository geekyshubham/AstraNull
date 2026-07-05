import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  resolveDigitalOceanAppId,
  resolveDigitalOceanWebInstanceName,
} from './doAppDatabase.mjs';

/**
 * @param {string} command
 * @param {{ appId?: string, instanceName?: string, timeoutSec?: number }} [options]
 */
export function runDigitalOceanConsoleCommand(command, options = {}) {
  const appId = options.appId ?? resolveDigitalOceanAppId();
  const instanceName = options.instanceName ?? resolveDigitalOceanWebInstanceName(appId);
  const timeoutSec = options.timeoutSec ?? 180;

  const workDir = mkdtempSync(path.join(tmpdir(), 'astranull-do-console-'));
  const payloadPath = path.join(workDir, 'payload.b64');
  const expectPath = path.join(workDir, 'console.expect');
  const payload = Buffer.from(command, 'utf8').toString('base64');
  writeFileSync(payloadPath, payload, 'utf8');

  const expectScript = `set timeout ${timeoutSec}
set fp [open "${payloadPath}" r]
set payload [read $fp]
close $fp
spawn doctl apps console ${appId} web --instance-name ${instanceName}
expect -re {[#$%>] }
send "cd /app && printf '%s' $payload | base64 -d > /tmp/astranull-console.cmd && sh /tmp/astranull-console.cmd\\r"
expect {
  -re {truncated [0-9]+|seed-local-staging-tenant:|__DONE__} {}
  -re {[#$%>] } {}
  timeout {}
}
send "exit\r"
expect eof
`;

  writeFileSync(expectPath, expectScript, 'utf8');
  const result = spawnSync('expect', [expectPath], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  if (result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
    throw new Error(`DigitalOcean console command failed${detail ? `: ${detail}` : ''}`);
  }

  return [result.stdout, result.stderr].filter(Boolean).join('\n');
}

/**
 * @param {string[]} commands
 * @param {{ appId?: string, instanceName?: string, timeoutSec?: number }} [options]
 */
export function runDigitalOceanConsoleCommands(commands, options = {}) {
  let combined = '';
  for (const command of commands) {
    combined += runDigitalOceanConsoleCommand(command, options);
  }
  return combined;
}