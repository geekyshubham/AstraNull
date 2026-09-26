import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import {
  DEV_SECRET_KEY_FILENAME,
  ensureDeveloperSecretEncryptionKey,
} from '../../src/lib/devSecretEncryptionKey.mjs';

function tempDir() {
  return mkdtempSync(path.join(os.tmpdir(), 'astranull-dev-key-'));
}

describe('developer secret encryption key', () => {
  it('generates a 0600 key under the dev data dir once and reuses it', () => {
    const dir = tempDir();
    const warnings = [];
    const env = { NODE_ENV: 'development', ASTRANULL_DEV_DATA_DIR: dir };
    const first = ensureDeveloperSecretEncryptionKey(env, { warn: (m) => warnings.push(m) });
    assert.equal(first.applied, true);
    assert.equal(first.source, 'generated');
    const keyPath = path.join(dir, DEV_SECRET_KEY_FILENAME);
    assert.equal(first.keyPath, keyPath);
    assert.equal(statSync(keyPath).mode & 0o777, 0o600);
    assert.match(env.ASTRANULL_SECRET_ENCRYPTION_KEY, /^[0-9a-f]{64}$/);
    assert.equal(readFileSync(keyPath, 'utf8').trim(), env.ASTRANULL_SECRET_ENCRYPTION_KEY);
    assert.match(warnings[0], /local development only/);
    assert.doesNotMatch(warnings[0], new RegExp(env.ASTRANULL_SECRET_ENCRYPTION_KEY));

    const nextEnv = { NODE_ENV: 'development', ASTRANULL_DEV_DATA_DIR: dir };
    const second = ensureDeveloperSecretEncryptionKey(nextEnv, { warn: () => {} });
    assert.equal(second.source, 'file');
    assert.equal(nextEnv.ASTRANULL_SECRET_ENCRYPTION_KEY, env.ASTRANULL_SECRET_ENCRYPTION_KEY);
    assert.equal(loadRuntimeConfig(nextEnv).secretEncryptionConfigured, true);
  });

  it('uses an ephemeral key without touching disk when persistence is disabled', () => {
    const dir = tempDir();
    const env = { NODE_ENV: 'development', ASTRANULL_NO_PERSIST: '1', ASTRANULL_DEV_DATA_DIR: dir };
    const result = ensureDeveloperSecretEncryptionKey(env, { warn: () => {} });
    assert.equal(result.source, 'ephemeral');
    assert.match(env.ASTRANULL_SECRET_ENCRYPTION_KEY, /^[0-9a-f]{64}$/);
    assert.throws(() => statSync(path.join(dir, DEV_SECRET_KEY_FILENAME)));
  });

  it('never applies to production, deployment profiles, postgres, or an explicit key', () => {
    const cases = [
      [{ NODE_ENV: 'production' }, 'production'],
      [{ NODE_ENV: 'development', ASTRANULL_DEPLOYMENT_PROFILE: 'local-staging' }, 'deployment_profile'],
      [{ NODE_ENV: 'development', ASTRANULL_PERSISTENCE_MODE: 'postgres' }, 'postgres'],
      [{ NODE_ENV: 'development', ASTRANULL_SECRET_ENCRYPTION_KEY: 'x' }, 'configured'],
    ];
    for (const [env, reason] of cases) {
      const snapshot = { ...env };
      const result = ensureDeveloperSecretEncryptionKey(env, { warn: () => assert.fail('must not warn') });
      assert.deepEqual(result, { applied: false, reason });
      assert.deepEqual(env, snapshot);
    }
  });
});
