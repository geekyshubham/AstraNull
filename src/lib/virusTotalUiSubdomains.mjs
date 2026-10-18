import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

const SCRIPT = fileURLToPath(new URL('../../scripts/virustotal-subdomains.py', import.meta.url));
const LOCAL_PYTHON = fileURLToPath(new URL('../../.data/subdomains-venv/bin/python', import.meta.url));

/** No shell or secret arguments. Full enumeration has per-request timeouts in the helper. */
export function runVirusTotalUiSubdomains(input, { pythonExecutable, signal, onProgress, idleTimeoutMs = 45_000 } = {}) {
  return new Promise((resolve) => {
    if (signal?.aborted) { resolve({ error: 'subdomain_discovery_cancelled' }); return; }
    const child = spawn(pythonExecutable || (existsSync(LOCAL_PYTHON) ? LOCAL_PYTHON : 'python3'), [SCRIPT], {
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    let result;
    let idleTimer;
    let idleExpired = false;
    const abort = () => child.kill('SIGTERM');
    const resetIdle = () => {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => { idleExpired = true; abort(); }, idleTimeoutMs);
      idleTimer.unref();
    };
    signal?.addEventListener('abort', abort, { once: true });
    resetIdle();
    const lines = createInterface({ input: child.stdout });
    lines.on('line', (line) => {
      resetIdle();
      try {
        const item = JSON.parse(line);
        if (item?.type === 'progress') onProgress?.(item.progress);
        else result = item;
      } catch { result = { error: 'subdomain_source_failed' }; }
    });
    child.on('error', (error) => resolve({
      error: error.code === 'ENOENT' ? 'subdomain_source_not_configured' : 'subdomain_source_unreachable',
    }));
    child.on('close', (code) => {
      clearTimeout(idleTimer);
      signal?.removeEventListener('abort', abort);
      lines.close();
      if (signal?.aborted) { resolve({ error: 'subdomain_discovery_cancelled' }); return; }
      if (code !== 0 || idleExpired) {
        resolve({ error: 'subdomain_source_unreachable' });
        return;
      }
      resolve(result ?? { error: 'subdomain_source_failed' });
    });
    child.stdin.on('error', () => {}); // A missing interpreter can close stdin before the write.
    child.stdin.end(JSON.stringify({ ...input, progress: true, retries: 3, baseDelay: 1, requestTimeoutMs: 10_000 }));
  });
}
