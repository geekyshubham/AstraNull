import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPostgresSecretVaultServices } from '../../src/persistence/postgres/secretVaultServiceAdapters.mjs';
import { warnIfConnectorVaultUnavailable } from '../../src/startup.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

function vaultServices(options = {}) {
  return createPostgresSecretVaultServices({
    secretVault: {
      async createEncryptedSecret() { throw new Error('must not write without a key'); },
      async listEncryptedSecrets() { return []; },
      async getEncryptedSecretById() { return null; },
      async updateEncryptedSecret() { throw new Error('must not write without a key'); },
    },
    audit: { async appendAuditEvent() {} },
  }, options);
}

describe('connector vault configuration', () => {
  it('names the connector key when a connector secret cannot be encrypted', async () => {
    const services = vaultServices({ encryptionKey: Buffer.alloc(32, 1) });
    const denied = await services.storeEncryptedSecret(ctx, {
      purpose: 'connector',
      name: 'cloudflare:prod',
      plaintext: 'placeholder-value',
    });
    assert.equal(denied.error, 'connector_encryption_not_configured');
    assert.equal(denied.status, 503);
  });

  it('keeps the general code for non-connector purposes', async () => {
    const denied = await vaultServices().storeEncryptedSecret(ctx, {
      purpose: 'notification',
      name: 'webhook',
      plaintext: 'placeholder-value',
    });
    assert.equal(denied.error, 'encryption_not_configured');
  });

  it('warns at startup only when connectors are enabled without a connector key', () => {
    const messages = [];
    const warn = (message) => messages.push(message);
    assert.equal(warnIfConnectorVaultUnavailable({ ASTRANULL_CONNECTORS_ENABLED: '1' }, warn), true);
    assert.match(messages[0], /ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY/);
    assert.equal(warnIfConnectorVaultUnavailable({}, warn), false);
    assert.equal(warnIfConnectorVaultUnavailable({
      ASTRANULL_CONNECTORS_ENABLED: 'true',
      ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY: 'configured',
    }, warn), false);
    assert.equal(messages.length, 1);
  });
});
