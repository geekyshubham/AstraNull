import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { describe, it } from 'node:test';
import { createPostgresValidationScanRepository } from '../../src/persistence/postgres/validationScanRepository.mjs';

// A fake pg client: emits 'error' like a real socket, records how it was released.
class FakeClient extends EventEmitter {
  constructor(responses) {
    super();
    this.responses = responses;
    this.released = { called: false, err: undefined };
  }

  async query(sql) {
    if (/pg_try_advisory_lock/.test(sql)) return { rows: [{ acquired: this.responses.acquired !== false }] };
    if (/pg_advisory_unlock/.test(sql)) {
      if (this.responses.unlockThrows) throw new Error('unlock failed');
      return { rows: [{}] };
    }
    return { rows: [] };
  }

  release(err) {
    this.released = { called: true, err };
  }
}

class FakeLockPool {
  constructor(client) {
    this.client = client;
    this.connectCount = 0;
    this.ended = false;
  }

  async connect() {
    this.connectCount += 1;
    return this.client;
  }

  async end() { this.ended = true; }
}

// Minimal audit repo so the factory does not build a real one against a null pool.
const auditRepository = { appendAuditEvent: async () => ({}) };
const CTX = { tenantId: 'ten_demo' };

describe('withScanLock (findings 3 and 4)', () => {
  it('acquires on the dedicated lock pool, runs the callback, and releases a healthy client', async () => {
    const client = new FakeClient({ acquired: true });
    const lockPool = new FakeLockPool(client);
    const repo = createPostgresValidationScanRepository(null, { auditRepository, lockPool });

    let ran = false;
    const result = await repo.withScanLock(CTX, 'scan_1', async () => { ran = true; return 'done'; });

    assert.equal(ran, true);
    assert.deepEqual(result, { acquired: true, result: 'done' });
    // The lock came from the dedicated pool, not the (null) main pool.
    assert.equal(lockPool.connectCount, 1);
    // Healthy client: released without an error so the pool can reuse it.
    assert.equal(client.released.called, true);
    assert.equal(client.released.err, undefined);
  });

  it('does not run the callback when the advisory lock is not acquired', async () => {
    const client = new FakeClient({ acquired: false });
    const lockPool = new FakeLockPool(client);
    const repo = createPostgresValidationScanRepository(null, { auditRepository, lockPool });

    let ran = false;
    const result = await repo.withScanLock(CTX, 'scan_1', async () => { ran = true; return 'x'; });
    assert.equal(ran, false);
    assert.deepEqual(result, { acquired: false, result: null });
  });

  it('does not crash when a busy client errors, and discards the broken client (finding 3)', async () => {
    const client = new FakeClient({ acquired: true });
    const lockPool = new FakeLockPool(client);
    const repo = createPostgresValidationScanRepository(null, { auditRepository, lockPool });

    // Simulate Postgres dropping the busy connection mid-callback. With no handler this would be an
    // uncaught 'error' event that kills the process; the handler must absorb it.
    const result = await repo.withScanLock(CTX, 'scan_1', async () => {
      client.emit('error', Object.assign(new Error('connection terminated'), { code: '57P01' }));
      return 'still-returns';
    });

    assert.deepEqual(result, { acquired: true, result: 'still-returns' });
    // Broken client must be discarded (released WITH an error), not returned to the pool.
    assert.equal(client.released.called, true);
    assert.ok(client.released.err instanceof Error);
  });

  it('discards the client when the unlock query fails', async () => {
    const client = new FakeClient({ acquired: true, unlockThrows: true });
    const lockPool = new FakeLockPool(client);
    const repo = createPostgresValidationScanRepository(null, { auditRepository, lockPool });

    await repo.withScanLock(CTX, 'scan_1', async () => 'ok');
    assert.equal(client.released.called, true);
    assert.ok(client.released.err instanceof Error);
  });

  it('close() ends an owned lock pool but leaves an injected one alone', async () => {
    // Injected lock pool is caller-owned: close() must not end it.
    const injected = new FakeLockPool(new FakeClient({ acquired: true }));
    const repo = createPostgresValidationScanRepository(null, { auditRepository, lockPool: injected });
    await repo.close();
    assert.equal(injected.ended, false);
  });
});
