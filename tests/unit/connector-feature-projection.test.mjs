import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { reconcileConnectorFeatureProjection } from '../../src/server.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr', role: 'admin' };
const POSTGRES_CONFIG = {
  persistenceMode: 'postgres',
  featureFlags: { connectorsEnabledDefault: true },
};

describe('connector feature projection resilience (finding 7)', () => {
  it('does not throw when reading the connector flag hits a database error', async () => {
    const warnings = [];
    const originalWarn = console.warn;
    console.warn = (msg) => warnings.push(String(msg));
    try {
      const waf = {
        async isConnectorFeatureEnabled() { throw new Error('connection terminated for postgres://user:secret@db'); },
        async setConnectorFeatureState() { throw new Error('should not be called'); },
      };
      // Must resolve, not reject: a transient DB failure cannot 500 the connector request. The
      // authoritative gate is the in-memory runtimeConfig, not this projection.
      await assert.doesNotReject(() => reconcileConnectorFeatureProjection(POSTGRES_CONFIG, { wafPosture: waf }, CTX));
    } finally {
      console.warn = originalWarn;
    }
    // The DB credentials must not leak into logs.
    assert.equal(warnings.join('\n').includes('user:secret'), false);
  });

  it('does not throw when persisting the projection hits a database error', async () => {
    const waf = {
      // Persisted state disagrees with desired (true), so it will try to write and fail.
      async isConnectorFeatureEnabled() { return false; },
      async setConnectorFeatureState() { throw new Error('write failed'); },
    };
    await assert.doesNotReject(() => reconcileConnectorFeatureProjection(POSTGRES_CONFIG, { wafPosture: waf }, CTX));
  });

  it('writes the projection when it is out of sync and the database is healthy', async () => {
    let wrote = null;
    const waf = {
      async isConnectorFeatureEnabled() { return false; },
      async setConnectorFeatureState(_ctx, desired) { wrote = desired; },
    };
    await reconcileConnectorFeatureProjection(POSTGRES_CONFIG, { wafPosture: waf }, CTX);
    assert.equal(wrote, true);
  });

  it('is a no-op outside postgres mode', async () => {
    let touched = false;
    const waf = {
      async isConnectorFeatureEnabled() { touched = true; return false; },
      async setConnectorFeatureState() { touched = true; },
    };
    await reconcileConnectorFeatureProjection({ ...POSTGRES_CONFIG, persistenceMode: 'dev-json' }, { wafPosture: waf }, CTX);
    assert.equal(touched, false);
  });
});
