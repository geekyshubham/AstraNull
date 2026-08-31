import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { targetDedupeKey } from '../../src/contracts/targetManagement.mjs';
import { createPostgresPortalRevampServices } from '../../src/persistence/postgres/portalRevampServiceAdapters.mjs';
import { PORTAL_REVAMP_REPOSITORY_METHODS } from '../../src/persistence/postgres/portalRevampRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

// Snapshots must read as a recent successful poll (within PROVIDER_OWNERSHIP_MAX_AGE_MS).
const lastSuccessAt = new Date(Date.now() - 60_000).toISOString();

function portalRepositoryDouble() {
  return Object.fromEntries(PORTAL_REVAMP_REPOSITORY_METHODS.map((method) => [method, async () => null]));
}

function createServices(overrides = {}) {
  const calls = [];
  const connector = overrides.connector ?? {
    id: 'conn_1', tenant_id: CTX.tenantId, provider: 'cloudflare', name: 'Production DNS',
    status: 'active', secret_id: 'secret_must_not_leak', config: { api_token: 'must_not_leak' },
    last_success_at: lastSuccessAt, last_success_revision: 7,
  };
  const snapshots = overrides.snapshots ?? [{
    id: 'snap_1', tenant_id: CTX.tenantId, connector_id: 'conn_1', provider: 'cloudflare',
    snapshot_kind: 'dns_zone', resource_ref_hash: 'sha256:zone-1', display_ref: 'Example.COM.',
    summary: {
      result: [{ id: 'zone-secret-provider-ref', name: 'Example.COM.', status: 'active' }],
      hostnames: ['Example.COM.'],
      tags: ['ownership_eligible:true', 'resource_status:active'],
    },
    evidence_source: 'provider_api', inventory_complete: true, inventory_truncated: false,
    poll_revision: 7, observed_at: lastSuccessAt,
  }];
  const coreCatalog = {
    async restoreTargetGroup() { return { restored: true, id: 'tg_1', audit_entry_id: 'audit_1' }; },
    async getTargetGroup() { return { id: 'tg_1', targets: [] }; },
    async bulkImportTargets(ctx, groupId, body, options) {
      calls.push({ ctx, groupId, body, options });
      return { imported: body.items, skipped: [], count: body.items.length };
    },
  };
  const repositories = {
    portalRevamp: portalRepositoryDouble(),
    coreCatalog,
    audit: {},
    validationEvidence: {},
    wafPosture: {
      async isConnectorFeatureEnabled() { return true; },
      async getConnector(ctx, id) {
        return id === connector.id && ctx.tenantId === connector.tenant_id ? connector : null;
      },
      async listConnectorSnapshots() { return snapshots; },
    },
  };
  return { services: createPostgresPortalRevampServices({ repositories }), calls };
}

describe('Postgres connector target inventory', () => {
  it('maps latest tenant connector snapshots to canonical, credential-free paginated inventory', async () => {
    const { services } = createServices();
    const result = await services.portalWaf.getConnectorInventory(CTX, 'conn_1', { limit: 1 });

    assert.equal(result.provider, 'cloudflare');
    assert.equal(result.scope, 'read_only');
    assert.deepEqual(result.items.map(({ kind, value }) => ({ kind, value })), [
      { kind: 'fqdn', value: 'example.com' },
    ]);
    assert.equal(result.count, 1);
    const serialized = JSON.stringify(result);
    assert.doesNotMatch(serialized, /api_token|must_not_leak|secret_id|poll_revision/i);
  });

  it('passes a verified connector and exact canonical inventory set into transactional bulk import', async () => {
    const { services, calls } = createServices();
    const body = {
      connector_id: 'conn_1',
      items: [{ kind: 'fqdn', value: 'EXAMPLE.com.' }],
    };
    const result = await services.portalTargetGroups.bulkImportTargets(CTX, 'tg_1', body);

    assert.equal(result.count, 1);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].options.trustedConnector.id, 'conn_1');
    assert.equal(calls[0].options.trustedConnector.last_success_revision, 7);
    assert.equal(
      calls[0].options.connectorInventoryEvidence.get(targetDedupeKey(body.items[0])).poll_revision,
      7,
    );
    assert.ok(calls[0].options.connectorInventoryKeys.has(targetDedupeKey(body.items[0])));
  });

  it('fails closed for disabled or cross-tenant/missing connectors', async () => {
    const disabled = createServices({ connector: {
      id: 'conn_disabled', tenant_id: CTX.tenantId, provider: 'cloudflare', name: 'Disabled', status: 'disabled',
    } }).services;
    assert.deepEqual(
      await disabled.portalWaf.getConnectorInventory(CTX, 'conn_disabled'),
      { error: 'connector_disabled', status: 409 },
    );

    const { services } = createServices();
    assert.deepEqual(
      await services.portalTargetGroups.bulkImportTargets(CTX, 'tg_1', { connector_id: 'missing', items: [] }),
      { error: 'connector_not_found', status: 404 },
    );
  });
});
