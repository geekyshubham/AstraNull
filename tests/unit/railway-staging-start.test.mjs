import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const START_SCRIPT = path.join(REPO_ROOT, 'scripts/railway-staging-start.mjs');

describe('railway-staging-start probe worker URL', () => {
  it('prefers loopback for in-container polling unless overridden', async () => {
    const mod = await import('../../scripts/railway-staging-start.mjs');
    assert.equal(
      mod.resolveProbeWorkerApiUrl(
        { ASTRANULL_PUBLIC_BASE_URL: 'https://astranull-qteog.ondigitalocean.app', PORT: '8080' },
        '8080',
      ),
      'http://127.0.0.1:8080',
    );
    assert.equal(
      mod.resolveProbeWorkerApiUrl(
        { ASTRANULL_PROBE_WORKER_API_URL: 'http://127.0.0.1:9090' },
        '8080',
      ),
      'http://127.0.0.1:9090',
    );
  });
});

/**
 * Signal forwarding from the container's PID 1.
 *
 * The wrapper is PID 1 in the deployed container. It used to register no signal handler, so Node
 * applied the default disposition and PID 1 died the instant SIGTERM arrived — the API child was
 * never signalled, and the drain in src/startup.mjs (flip /ready to 503, finish in-flight requests,
 * then close) never ran in production at all. It only executed when src/index.mjs was launched
 * directly, which is why local runs and tests exercised it while the container did not.
 *
 * Measured before writing this: a parent with no handler logs only the child's startup line and
 * dies; with a handler the child receives SIGTERM, drains, and exits 0. These tests pin the
 * forwarding behaviour itself rather than the presence of some text in the source.
 */
describe('railway-staging-start shutdown forwarding', () => {
  /** Minimal stand-in for a ChildProcess: records the signals it was sent. */
  function fakeChild(pid, { exitCode = null, signalCode = null, throwOnKill = false } = {}) {
    return {
      pid,
      exitCode,
      signalCode,
      killed: [],
      kill(signal) {
        if (throwOnKill) throw new Error('ESRCH');
        this.killed.push(signal);
        return true;
      },
    };
  }

  function harness(children) {
    const exits = [];
    const logs = [];
    let shuttingDown = false;
    const mod = () => import('../../scripts/railway-staging-start.mjs');
    return {
      exits,
      logs,
      get shuttingDown() { return shuttingDown; },
      async forwarder() {
        const { createShutdownForwarder } = await mod();
        return createShutdownForwarder(children, {
          onShuttingDown: () => { shuttingDown = true; },
          exit: (code) => exits.push(code),
          log: (line) => logs.push(line),
          logError: (line) => logs.push(line),
        });
      },
    };
  }

  it('forwards the signal to every running child', async () => {
    const children = { api: fakeChild(101), worker: fakeChild(102) };
    const h = harness(children);
    (await h.forwarder())('SIGTERM');

    assert.deepEqual(children.api.killed, ['SIGTERM'], 'API child must receive the stop signal');
    assert.deepEqual(children.worker.killed, ['SIGTERM'], 'probe worker must receive it too');
    assert.equal(h.shuttingDown, true, 'shutdown state must be set so the supervisor stops relaunching');
    assert.deepEqual(h.exits, [], 'PID 1 must stay alive while the children drain');
  });

  it('reads the child refs at signal time, so a relaunched worker is not missed', async () => {
    // The supervisor creates a NEW child object on every restart. A forwarder that captured the
    // first one would signal a pid that no longer exists and leak the live worker.
    const children = { api: fakeChild(201), worker: fakeChild(202) };
    const forward = await harness(children).forwarder();

    children.worker.exitCode = 1;            // original worker died
    const relaunched = fakeChild(203);       // supervisor replaced it
    children.worker = relaunched;

    forward('SIGTERM');
    assert.deepEqual(relaunched.killed, ['SIGTERM'], 'the current worker must be signalled');
  });

  it('skips children that have already exited or been signalled', async () => {
    const children = {
      api: fakeChild(301, { exitCode: 0 }),
      worker: fakeChild(302, { signalCode: 'SIGKILL' }),
    };
    const h = harness(children);
    (await h.forwarder())('SIGTERM');

    assert.deepEqual(children.api.killed, [], 'must not signal a reaped child');
    assert.deepEqual(children.worker.killed, [], 'must not re-signal a killed child');
    // Nothing left to drain, and the handler suppressed the default disposition, so PID 1 has to
    // exit explicitly or the container hangs until the platform's kill timeout.
    assert.deepEqual(h.exits, [0], 'PID 1 must exit rather than hang with no children');
  });

  it('forwards only once when a stop signal is repeated', async () => {
    const children = { api: fakeChild(401), worker: null };
    const forward = await harness(children).forwarder();

    forward('SIGTERM');
    forward('SIGTERM');
    forward('SIGINT');

    assert.deepEqual(
      children.api.killed,
      ['SIGTERM'],
      'an impatient orchestrator must not restart the drain',
    );
  });

  it('keeps draining the other children when one cannot be signalled', async () => {
    const children = { api: fakeChild(501, { throwOnKill: true }), worker: fakeChild(502) };
    const h = harness(children);
    (await h.forwarder())('SIGTERM');

    assert.deepEqual(children.worker.killed, ['SIGTERM'], 'one bad pid must not abort the rest');
    assert.ok(
      h.logs.some((line) => line.includes('501')),
      'the failure must be reported against its pid',
    );
  });

  it('passes SIGINT through as SIGINT', async () => {
    const children = { api: fakeChild(601), worker: null };
    await (await harness(children).forwarder())('SIGINT');
    assert.deepEqual(children.api.killed, ['SIGINT']);
  });
});

describe('railway-staging-start', () => {
  it('refuses to start without ASTRANULL_DATABASE_URL', async () => {
    const child = spawn(process.execPath, [START_SCRIPT], {
      cwd: REPO_ROOT,
      env: { ...process.env, ASTRANULL_DATABASE_URL: '' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const [code, stderr] = await new Promise((resolve, reject) => {
      let err = '';
      child.stderr.on('data', (chunk) => { err += chunk; });
      child.on('error', reject);
      child.on('exit', (exitCode) => resolve([exitCode, err]));
    });

    assert.equal(code, 1);
    assert.match(stderr, /ASTRANULL_DATABASE_URL is required|managed Postgres/);
  });
});