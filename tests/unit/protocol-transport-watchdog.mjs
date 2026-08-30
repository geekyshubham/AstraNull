import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const fixturePath = fileURLToPath(new URL('./protocol-transport-socket.fixture.mjs', import.meta.url));

function killProcessGroup(child) {
  if (!child.pid) return;
  try {
    if (process.platform === 'win32') child.kill('SIGKILL');
    else process.kill(-child.pid, 'SIGKILL');
  } catch {
    child.kill('SIGKILL');
  }
}

export function runProtocolTransportFixture(mode, { timeoutMs = 4000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fixturePath, mode], {
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    let timedOut = false;

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });

    const timer = setTimeout(() => {
      timedOut = true;
      killProcessGroup(child);
    }, timeoutMs);

    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve({ stdout, stderr });
    };

    child.once('error', (error) => finish(error));
    child.once('close', (code, signal) => {
      if (timedOut) {
        finish(new Error(`protocol fixture ${mode} exceeded ${timeoutMs}ms; process group killed\n${stderr}`));
      } else if (code !== 0) {
        finish(new Error(`protocol fixture ${mode} failed (${code ?? signal})\n${stdout}${stderr}`));
      } else {
        finish(null);
      }
    });
  });
}
