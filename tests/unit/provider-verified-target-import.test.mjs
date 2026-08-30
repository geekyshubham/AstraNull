import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { ownershipProofFromStates } from '../../src/lib/ownershipPolicy.mjs';
import { createPostgresPortalRevampServices } from '../../src/persistence/postgres/portalRevampServiceAdapters.mjs';
import { PORTAL_REVAMP_REPOSITORY_METHODS } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { bulkImportTargets } from '../../src/services/targetGroups.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';


function portalRepositoryDouble() {
  return Object.fromEntries(
    PORTAL_REVAMP_REPOSITORY_METHODS.map((method) => [method, async () => null]),
  );
}
const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

function seedSnapshot({
  connectorId,
  provider = 'cloudflare',
  source = 'provider_api',
  snapshotKind = 'dns_zone',
  displayRef = 'owned.example.com',
  hostnames = ['owned.example.com'],
  observedAt = '2026-08-30T12:00:00.000Z',
  suffix = connectorId,
}) {
  getStore().wafConnectorSnapshots.push({
    id: `snap_${suffix}`,
    tenant_id: CTX.tenantId,
    connector_id: connectorId,
    provider,
    snapshot_kind: snapshotKind,
    resource_ref_hash: `hash_${suffix}`,
    display_ref: displayRef,
    summary_json: { hostnames },
    config_hash: `cfg_${suffix}`,
    evidence_source: source,
    inventory_complete: true,
    inventory_truncated: false,
    observed_at: observedAt,
    created_at: observedAt,
  });
}

function seedConnector({
  id,
  provider = 'cloudflare',
  source = 'provider_api',
  secretId = 'sec_dns_1',
  status = 'active',
  snapshotKind = 'dns_zone',
  displayRef = 'owned.example.com',
  hostnames = ['owned.example.com'],
  observedAt = '2026-08-30T12:00:00.000Z',
  lastSuccessAt = observedAt,
}) {
  const store = getStore();
  if (!Array.isArray(store.wafConnectors)) store.wafConnectors = [];
  if (!Array.isArray(store.wafConnectorSnapshots)) store.wafConnectorSnapshots = [];
  store.wafConnectors.push({
    id,
    tenant_id: CTX.tenantId,
    provider,
    name: id,
    secret_id: secretId,
    config_json: { read_only: true },
    status,
    last_success_at: lastSuccessAt,
    created_at: '2026-08-30T00:00:00.000Z',
    updated_at: '2026-08-30T00:00:00.000Z',
  });
  seedSnapshot({
    connectorId: id,
    provider,
    source,
    snapshotKind,
    displayRef,
    hostnames,
    observedAt,
  });
}

beforeEach(() => freshStore());

describe('provider-verified target imports', () => {
  it('grants exact-target proof from a vault-backed live provider snapshot', () => {
    seedConnector({ id: 'conn_live' });
    const result = bulkImportTargets(CTX, 'tg_1', {
      connector_id: 'conn_live',
      items: [{ kind: 'fqdn', value: 'owned.example.com' }],
    });

    assert.equal(result.count, 1);
    assert.equal(result.imported[0].verify_state, 'provider_verified');
    const verification = getStore().targetVerifications.find(
      (row) => row.target_id === result.imported[0].id,
    );
    assert.equal(verification.state, 'provider_verified');
    assert.equal(verification.source_kind, 'provider_account');
    assert.equal(verification.source_ref.snapshot_id, 'snap_conn_live');
    assert.equal(verification.source_ref.resource_ref_hash, 'hash_conn_live');
    assert.equal(verification.source_ref.provider, 'cloudflare');
    assert.equal(verification.source_ref.snapshot_kind, 'dns_zone');
    assert.equal(verification.source_ref.poll_generation, '2026-08-30T12:00:00.000Z');
    assert.equal(ownershipProofFromStates({ targetState: verification.state }).verified, true);
  });

  it('keeps manual metadata pending and rejects a client-selected row absent from inventory', () => {
    seedConnector({ id: 'conn_manual', source: 'manual_metadata' });
    const manual = bulkImportTargets(CTX, 'tg_1', {
      connector_id: 'conn_manual',
      items: [{
        kind: 'fqdn',
        value: 'owned.example.com',
        provider: 'cloudflare',
        snapshot_kind: 'dns_zone',
        evidence_source: 'provider_api',
        current_successful_poll: true,
      }],
    });
    assert.equal(manual.imported[0].verify_state, 'pending');
    const verification = getStore().targetVerifications.find(
      (row) => row.target_id === manual.imported[0].id,
    );
    assert.equal(verification.source_kind, 'connector_inventory');
    assert.equal(ownershipProofFromStates({ targetState: verification.state }).verified, false);

    const missing = bulkImportTargets(CTX, 'tg_1', {
      connector_id: 'conn_manual',
      items: [{ kind: 'fqdn', value: 'not-in-provider.example.com' }],
    });
    assert.equal(missing.count, 0);
    assert.equal(missing.skipped[0].reason, 'connector_item_not_found');
  });

  it('keeps WAF snapshots and generic display refs pending', () => {
    seedConnector({
      id: 'conn_waf',
      provider: 'aws_waf',
      snapshotKind: 'waf_policy',
      displayRef: 'waf.example.com',
      hostnames: ['waf.example.com'],
    });
    const waf = bulkImportTargets(CTX, 'tg_1', {
      connector_id: 'conn_waf',
      items: [{ kind: 'fqdn', value: 'waf.example.com' }],
    });
    assert.equal(waf.count, 1);
    assert.equal(waf.imported[0].verify_state, 'pending');

    seedConnector({
      id: 'conn_display',
      displayRef: 'display-only.example.com',
      hostnames: [],
    });
    const displayOnly = bulkImportTargets(CTX, 'tg_1', {
      connector_id: 'conn_display',
      items: [{ kind: 'fqdn', value: 'display-only.example.com' }],
    });
    assert.equal(displayOnly.count, 1);
    assert.equal(displayOnly.imported[0].verify_state, 'pending');
  });

  it('drops resources absent from the connector latest successful poll generation', () => {
    const oldPoll = '2026-08-30T12:00:00.000Z';
    const latestPoll = '2026-08-30T13:00:00.000Z';
    seedConnector({
      id: 'conn_rotated',
      displayRef: 'removed.example.com',
      hostnames: ['removed.example.com'],
      observedAt: oldPoll,
      lastSuccessAt: latestPoll,
    });
    seedSnapshot({
      connectorId: 'conn_rotated',
      displayRef: 'current.example.com',
      hostnames: ['current.example.com'],
      observedAt: latestPoll,
      suffix: 'conn_rotated_current',
    });

    const removed = bulkImportTargets(CTX, 'tg_1', {
      connector_id: 'conn_rotated',
      items: [{ kind: 'fqdn', value: 'removed.example.com' }],
    });
    assert.equal(removed.count, 0);
    assert.equal(removed.skipped[0].reason, 'connector_item_not_found');

    const current = bulkImportTargets(CTX, 'tg_1', {
      connector_id: 'conn_rotated',
      items: [{ kind: 'fqdn', value: 'current.example.com' }],
    });
    assert.equal(current.count, 1);
    assert.equal(current.imported[0].verify_state, 'provider_verified');
    assert.equal(current.imported[0].metadata.managed_provenance.snapshot_kind, 'dns_zone');
    assert.equal(current.imported[0].metadata.managed_provenance.poll_generation, latestPoll);
  });

  it('preserves server-loaded provider evidence and ignores client evidence fields in Postgres mode', async () => {
    const latestPoll = '2026-08-30T14:00:00.000Z';
    let importOptions;
    const connector = {
      id: 'conn_pg',
      tenant_id: CTX.tenantId,
      provider: 'cloudflare',
      name: 'Cloudflare DNS',
      status: 'active',
      secret_id: 'sec_pg',
      last_success_at: latestPoll,
    };
    const snapshot = {
      id: 'snap_pg_current',
      tenant_id: CTX.tenantId,
      connector_id: connector.id,
      provider: 'cloudflare',
      snapshot_kind: 'dns_zone',
      resource_ref_hash: 'hash_pg_current',
      display_ref: 'postgres.example.com',
      summary: { hostnames: ['postgres.example.com'] },
      evidence_source: 'provider_api',
      inventory_complete: true,
      inventory_truncated: false,
      observed_at: latestPoll,
    };
    const services = createPostgresPortalRevampServices({
      repositories: {
        portalRevamp: portalRepositoryDouble(),
        coreCatalog: {
          async bulkImportTargets(_ctx, _groupId, body, options) {
            importOptions = options;
            return { imported: body.items, skipped: [], count: body.items.length };
          },
        },
        wafPosture: {
          async getConnector() { return connector; },
          async listConnectorSnapshots() { return [snapshot]; },
        },
      },
    });

    const inventory = await services.portalWaf.getConnectorInventory(CTX, connector.id);
    assert.equal(inventory.items[0].provider, 'cloudflare');
    assert.equal(inventory.items[0].snapshot_kind, 'dns_zone');
    assert.equal(inventory.items[0].snapshot_id, 'snap_pg_current');
    assert.equal(inventory.items[0].poll_generation, latestPoll);

    await services.portalTargetGroups.bulkImportTargets(CTX, 'tg_1', {
      connector_id: connector.id,
      items: [{
        kind: 'fqdn',
        value: 'postgres.example.com',
        provider: 'aws_waf',
        snapshot_kind: 'waf_policy',
        evidence_source: 'manual_metadata',
      }],
    });
    const serverEvidence = [...importOptions.connectorInventoryEvidence.values()][0];
    assert.equal(serverEvidence.provider, 'cloudflare');
    assert.equal(serverEvidence.snapshot_kind, 'dns_zone');
    assert.equal(serverEvidence.evidence_source, 'provider_api');
  });
});
