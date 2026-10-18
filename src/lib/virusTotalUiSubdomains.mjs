import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(new URL('../../scripts/virustotal-subdomains.py', import.meta.url));
const LOCAL_PYTHON = fileURLToPath(new URL('../../.data/subdomains-venv/bin/python', import.meta.url));

/** No shell or secret arguments. The bounded helper receives private configuration on stdin. */
export function runVirusTotalUiSubdomains(input, { pythonExecutable } = {}) {
  return new Promise((resolve) => {
    const child = execFile(pythonExecutable || (existsSync(LOCAL_PYTHON) ? LOCAL_PYTHON : 'python3'), [SCRIPT], {
      timeout: 47_000,
      killSignal: 'SIGKILL',
      maxBuffer: 2 * 1024 * 1024,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
    }, (error, stdout) => {
      if (error) {
        resolve({ error: error.code === 'ENOENT' ? 'subdomain_source_not_configured' : 'subdomain_source_unreachable' });
        return;
      }
      try { resolve(JSON.parse(stdout)); }
      catch { resolve({ error: 'subdomain_source_failed' }); }
    });
    child.stdin.on('error', () => {}); // A missing interpreter can close stdin before the write.
    child.stdin.end(JSON.stringify(input));
  });
}
