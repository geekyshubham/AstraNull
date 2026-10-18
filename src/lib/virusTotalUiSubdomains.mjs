import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(new URL('../../scripts/virustotal-subdomains.py', import.meta.url));
const LOCAL_PYTHON = fileURLToPath(new URL('../../.data/subdomains-venv/bin/python', import.meta.url));

/** No shell or secret arguments. Full enumeration has per-request timeouts in the helper. */
export function runVirusTotalUiSubdomains(input, { pythonExecutable } = {}) {
  return new Promise((resolve) => {
    const child = spawn(pythonExecutable || (existsSync(LOCAL_PYTHON) ? LOCAL_PYTHON : 'python3'), [SCRIPT], {
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    const chunks = [];
    child.stdout.on('data', (chunk) => chunks.push(chunk));
    child.on('error', (error) => resolve({
      error: error.code === 'ENOENT' ? 'subdomain_source_not_configured' : 'subdomain_source_unreachable',
    }));
    child.on('close', (code) => {
      if (code !== 0) {
        resolve({ error: 'subdomain_source_unreachable' });
        return;
      }
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { resolve({ error: 'subdomain_source_failed' }); }
    });
    child.stdin.on('error', () => {}); // A missing interpreter can close stdin before the write.
    child.stdin.end(JSON.stringify(input));
  });
}
