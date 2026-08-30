import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mapProviderInventory } from '../../src/lib/connectorInventory.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import {
  CORE_CATALOG_SERVICE_METHODS,
  CORE_CATALOG_TARGET_GROUP_SERVICE_METHODS,
  createPostgresCatalogServices,
} from '../../src/persistence/postgres/serviceAdapters.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';

const CREATED_AT = '2026-08-28T20:00:00.000Z';
const VERIFIED_AT = '2026-08-28T20:05:00.000Z';

async function listen(server) {
  await new Promise((resolve) => server.listen(0, resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

function seedInventoryTenants() {
  const store = freshStore();
  store.targetGroups[0].ownership_status = 'unverified';
  store.targets.push({
    id: 'tgt_imported',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    kind: 'fqdn',
    value: 'Api.Example.COM',
    expected_behavior: null,
    metadata: {
      eligibility: 'not_eligible',
      eligibility_reason: 'maintenance_window',
      import_source: 'hetzner_dns',
    },
    created_at: CREATED_AT,
  });
  store.targetVerifications = [
    {
      id: 'tv_pending',
      tenant_id: 'ten_demo',
      target_id: 'tgt_imported',
      state: 'pending',
      source_kind: 'manual_override',
      source_ref: { source: 'hetzner_dns', bulk_import: true },
      transitioned_at: CREATED_AT,
    },
    {
      id: 'tv_dns',
      tenant_id: 'ten_demo',
      target_id: 'tgt_imported',
      state: 'dns_verified',
      source_kind: 'dns_txt',
      source_ref: { dns_challenge_id: 'dns_imported' },
      transitioned_at: VERIFIED_AT,
    },
  ];

  store.tenants.push({ id: 'ten_other', name: 'Other tenant' });
  store.environments.push({
    id: 'env_other',
    tenant_id: 'ten_other',
    name: 'Other production',
  });
  store.targetGroups.push({
    id: 'tg_other',
    tenant_id: 'ten_other',
    environment_id: 'env_other',
    name: 'Other group',
    ownership_status: 'dns_verified',
  });
  store.targets.push({
    id: 'tgt_other',
    tenant_id: 'ten_other',
    target_group_id: 'tg_other',
    kind: 'fqdn',
    value: 'other.example.com',
    created_at: '2026-08-28T21:00:00.000Z',
  });

  store.targetGroups.push({
    id: 'tg_archived',
    tenant_id: 'ten_demo',
    environment_id: 'env_demo',
    name: 'Archived group',
    archived_at: '2026-08-27T00:00:00.000Z',
  });
  store.targets.push({
    id: 'tgt_archived',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_archived',
    kind: 'fqdn',
    value: 'archived.example.com',
    created_at: '2026-08-28T22:00:00.000Z',
  });
}

function createRecordingPool(row) {
  const queries = [];
  const client = {
    async query(text, params = []) {
      queries.push({ text, params });
      if (text.includes('FROM targets t')) return { rows: [row] };
      return { rows: [] };
    },
    release() {},
  };
  return {
    queries,
    async connect() {
      return client;
    },
  };
}

describe('GET /v1/targets inventory', () => {
  it('returns only the authenticated tenant’s active targets with page-ready enrichment', async (t) => {
    seedInventoryTenants();
    const server = createServer();
    t.after(() => closeServer(server));
    const baseUrl = await listen(server);

    const response = await request(baseUrl, 'GET', '/v1/targets', {
      headers: demoHeaders('engineer', 'ten_demo', 'usr_demo'),
    });

    assert.equal(response.status, 200);
    assert.equal(response.json.count, 2);
    assert.equal(response.json.meta.empty_reason, null);
    assert.equal(response.json.items.some((item) => item.id === 'tgt_other'), false);
    assert.equal(response.json.items.some((item) => item.id === 'tgt_archived'), false);

    const item = response.json.items.find((candidate) => candidate.id === 'tgt_imported');
    assert.deepEqual(item, {
      id: 'tgt_imported',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_group_name: 'TG',
      environment_id: 'env_demo',
      environment_name: 'Prod',
      kind: 'fqdn',
      value: 'Api.Example.COM',
      expected_behavior: 'must_block_before_origin',
      metadata: {
        eligibility: 'not_eligible',
        eligibility_reason: 'maintenance_window',
        import_source: 'hetzner_dns',
      },
      verification_state: 'dns_verified',
      verification: {
        state: 'dns_verified',
        source_kind: 'dns_txt',
        source_ref: { dns_challenge_id: 'dns_imported' },
        transitioned_at: VERIFIED_AT,
      },
      eligibility: 'eligible',
      eligibility_reason: null,
      source: 'manual',
      import_source: null,
      import_integration: null,
      created_at: CREATED_AT,
    });

    const otherTenant = await request(baseUrl, 'GET', '/v1/targets', {
      headers: demoHeaders('engineer', 'ten_other', 'usr_other'),
    });
    assert.equal(otherTenant.status, 200);
    assert.deepEqual(otherTenant.json.items.map((target) => target.id), ['tgt_other']);
    assert.equal(otherTenant.json.items[0].environment_name, 'Other production');
  });

  it('keeps the Postgres query tenant-bound and maps the same inventory contract', async () => {
    const row = {
      id: 'tgt_pg',
      tenant_id: 'ten_pg',
      target_group_id: 'tg_pg',
      target_group_name: 'Payments',
      environment_id: 'env_pg',
      environment_name: 'Production',
      ownership_status: 'unverified',
      expected_behavior_default: 'block_at_edge',
      kind: 'fqdn',
      value: 'pay.example.com',
      expected_behavior: null,
      metadata_json: {
        import_source: 'hetzner_dns',
        eligibility: 'not_eligible',
        eligibility_reason: 'maintenance_window',
      },
      verification_state: 'dns_verified',
      verification_source_kind: 'dns_txt',
      verification_source_ref: { dns_challenge_id: 'dns_pg' },
      verification_transitioned_at: new Date(VERIFIED_AT),
      created_at: new Date(CREATED_AT),
    };
    const pool = createRecordingPool(row);
    const repository = createCoreCatalogRepository(pool);

    const items = await repository.listTargets({ tenantId: 'ten_pg' });

    assert.equal(items.length, 1);
    assert.equal(items[0].target_group_name, 'Payments');
    assert.equal(items[0].environment_name, 'Production');
    assert.equal(items[0].verification_state, 'dns_verified');
    assert.deepEqual(items[0].verification.source_ref, { dns_challenge_id: 'dns_pg' });
    assert.equal(items[0].eligibility, 'eligible');
    assert.equal(items[0].eligibility_reason, null);
    assert.equal(items[0].source, 'manual');
    assert.equal(items[0].import_integration, null);
    assert.equal(items[0].created_at, CREATED_AT);

    const inventoryQuery = pool.queries.find((query) => query.text.includes('FROM targets t'));
    assert.deepEqual(inventoryQuery.params, ['ten_pg']);
    assert.match(inventoryQuery.text, /WHERE t\.tenant_id = \$1/);
    assert.match(inventoryQuery.text, /tg\.tenant_id = \$1/);
    assert.match(inventoryQuery.text, /tv\.tenant_id = \$1/);
    assert.match(inventoryQuery.text, /environment\.tenant_id = t\.tenant_id/);
  });

  it('requires and forwards listTargets through the Postgres catalog adapter', async () => {
    assert.equal(CORE_CATALOG_TARGET_GROUP_SERVICE_METHODS.includes('listTargets'), true);
    const calls = [];
    const coreCatalog = Object.fromEntries(
      CORE_CATALOG_SERVICE_METHODS.map((method) => [
        method,
        async (...args) => {
          calls.push({ method, args });
          return method === 'listTargets' ? [{ id: 'tgt_adapter' }] : null;
        },
      ]),
    );
    const { targetGroups } = createPostgresCatalogServices({ coreCatalog });
    const ctx = { tenantId: 'ten_adapter' };

    const result = await targetGroups.listTargets(ctx);

    assert.deepEqual(result, [{ id: 'tgt_adapter' }]);
    assert.deepEqual(calls, [{ method: 'listTargets', args: [ctx] }]);
  });
});

describe('Hetzner DNS connector inventory mapping', () => {
  it('accepts hetzner aliases, normalizes FQDNs, and omits raw secrets', () => {
    const raw = {
      api_token: 'must-not-leak',
      zones: [
        {
          id: 'zone-1',
          name: '  API.Example.COM.  ',
          status: 'verified',
          api_token: 'also-must-not-leak',
        },
        {
          id: 'zone-2',
          zone: 'FAILED.Example.COM...',
          status: 'failed',
          secret_access_key: 'not-an-inventory-field',
        },
      ],
    };

    const expected = [
      {
        kind: 'fqdn',
        value: 'api.example.com',
        label: 'api.example.com',
        resource_ref: 'zone-1',
        importable: true,
      },
      {
        kind: 'fqdn',
        value: 'failed.example.com',
        label: 'failed.example.com',
        resource_ref: 'zone-2',
        importable: false,
      },
    ];

    assert.deepEqual(mapProviderInventory('hetzner', raw), expected);
    assert.deepEqual(mapProviderInventory(' HETZNER_DNS ', raw), expected);
    const serialized = JSON.stringify(mapProviderInventory('hetzner_dns', raw));
    assert.equal(serialized.includes('must-not-leak'), false);
    assert.equal(serialized.includes('secret_access_key'), false);
    assert.equal(serialized.includes('api_token'), false);
  });
});
