import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const WATCHDOG = path.join(ROOT, 'scripts/worker-heartbeat-health.mjs');
const runWatchdog = (...args) => spawnSync(process.execPath, [WATCHDOG, ...args], {
  cwd: ROOT,
  encoding: 'utf8',
  timeout: 2_000,
});

describe('worker heartbeat health watchdog', () => {
  it('accepts only a present heartbeat inside the configured freshness window', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'astranull-worker-heartbeat-'));
    const heartbeat = path.join(directory, 'worker.heartbeat');
    try {
      writeFileSync(heartbeat, 'ok\n');
      assert.equal(runWatchdog(heartbeat, '180').status, 0);

      const stale = new Date(Date.now() - 181_000);
      utimesSync(heartbeat, stale, stale);
      assert.equal(runWatchdog(heartbeat, '180').status, 1);

      const future = new Date(Date.now() + 60_000);
      utimesSync(heartbeat, future, future);
      assert.equal(runWatchdog(heartbeat, '180').status, 1);
      assert.equal(runWatchdog(path.join(directory, 'missing'), '180').status, 1);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('fails closed on an invalid path or freshness argument', () => {
    assert.equal(runWatchdog().status, 2);
    assert.equal(runWatchdog('/tmp/not-used', '0').status, 2);
    assert.equal(runWatchdog('/tmp/not-used', 'not-a-number').status, 2);
  });
});
