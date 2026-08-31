import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { ownershipProofFromStates } from '../../src/lib/ownershipPolicy.mjs';
import { createPostgresPortalRevampServices } from '../../src/persistence/postgres/portalRevampServiceAdapters.mjs';
import { PORTAL_REVAMP_REPOSITORY_METHODS } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { bulkImportTargets, listTargets } from '../../src/services/targetGroups.mjs';
import { getTargetDetail } from '../../src/services/targetDetail.mjs';
import { getLadder, targetOwnershipProof } from '../../src/services/ownershipVerification.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';


function portalRepositoryDouble() {
  return Object.fromEntries(
    PORTAL_REVAMP_REPOSITORY_METHODS.map((method) => [method, async () => null]),
  );
}
const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

// Authority-success instants must stay within the 24h provider-ownership freshness window
// (PROVIDER_OWNERSHIP_MAX_AGE_MS) and never in the future, so compute them relative to now.
function hoursAgoIso(hours) {
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
}

function seedSnapshot({
  connectorId,
  provider = 'cloudflare',
  source = 'provider_api',
  snapshotKind = 'dns_zone',
  displayRef = 'owned.example.com',
  hostnames = ['owned.example.com'],
  observedAt = hoursAgoIso(2),
  resourceStatus = 'active',
  ownershipEligible = true,
  providerEnvironment = provider === 'namecheap' ? 'production' : null,
  suffix = connectorId,
  resourceRefHash = `hash_${suffix}`,
  pollRevision = 1,
}) {
  getStore().wafConnectorSnapshots.push({
    id: `snap_${suffix}`,
    tenant_id: CTX.tenantId,
    connector_id: connectorId,
    provider,
    snapshot_kind: snapshotKind,
    resource_ref_hash: resourceRefHash,
    display_ref: displayRef,
    summary_json: {
      hostnames,
      tags: [
        `resource_status:${resourceStatus}`,
        `ownership_eligible:${ownershipEligible ? 'true' : 'false'}`,
        ...(providerEnvironment ? [`provider_environment:${providerEnvironment}`] : []),
      ],
    },
    config_hash: `cfg_${suffix}`,
    evidence_source: source,
    inventory_complete: true,
    inventory_truncated: false,
    poll_revision: pollRevision,
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
  observedAt = hoursAgoIso(2),
  lastSuccessAt = observedAt,
  pollRevision = 1,
  lastSuccessRevision = pollRevision,
  resourceStatus = 'active',
  ownershipEligible = true,
  providerEnvironment = provider === 'namecheap' ? 'production' : null,
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
    poll_revision: pollRevision,
    last_success_at: lastSuccessAt,
    last_success_revision: lastSuccessRevision,
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
    resourceStatus,
    ownershipEligible,
    providerEnvironment,
    pollRevision,
  });
}

beforeEach(() => freshStore());

describe('provider-verified target imports', () => {
  it('grants exact-target proof from a vault-backed live provider snapshot', () => {
    const pollOne = hoursAgoIso(2);
    seedConnector({ id: 'conn_live', observedAt: pollOne });
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
    assert.equal(verification.source_ref.poll_generation, pollOne);
    assert.equal(ownershipProofFromStates({ targetState: verification.state }).verified, true);
    assert.deepEqual(targetOwnershipProof(CTX, getStore().targetGroups[0], result.imported[0].id), {
      verified: true,
      state: 'provider_verified',
      source: 'target',
    });
  });

  it('revalidates provider authorization against the current exact resource snapshot', () => {
    const pollOne = hoursAgoIso(2);
    const pollTwo = hoursAgoIso(1);
    seedConnector({ id: 'conn_revalidate', observedAt: pollOne });
    const imported = bulkImportTargets(CTX, 'tg_1', {
      connector_id: 'conn_revalidate',
      items: [{ kind: 'fqdn', value: 'owned.example.com' }],
    }).imported[0];
    const store = getStore();
    const group = store.targetGroups[0];
    const connector = store.wafConnectors[0];
    const proof = () => targetOwnershipProof(CTX, group, imported.id);

    connector.status = 'degraded';
    connector.last_error_at = hoursAgoIso(1.5);
    assert.equal(proof().verified, true, 'failed/degraded poll retaining last_success stays valid');

    connector.status = 'active';
    connector.last_success_at = pollTwo;
    assert.deepEqual(proof(), { verified: false, state: 'pending', source: null });

    seedSnapshot({
      connectorId: connector.id,
      observedAt: pollTwo,
      suffix: 'conn_revalidate_poll_two',
      resourceRefHash: 'hash_conn_revalidate',
    });
    assert.equal(proof().verified, true, 'a later active snapshot for the same resource refreshes proof');

    const current = store.wafConnectorSnapshots.at(-1);
    current.resource_ref_hash = 'hash_different_resource';
    assert.equal(proof().verified, false);
    current.resource_ref_hash = 'hash_conn_revalidate';

    current.summary_json.tags = ['resource_status:pending', 'ownership_eligible:false'];
    assert.equal(proof().verified, false);

    current.summary_json.tags = ['resource_status:active', 'ownership_eligible:true'];
    current.summary_json.hostnames = ['different.example.com'];
    assert.equal(proof().verified, false);

    current.summary_json.hostnames = ['owned.example.com'];
    connector.status = 'disabled';
    assert.equal(proof().verified, false);

    connector.status = 'active';
    connector.secret_id = null;
    assert.equal(proof().verified, false);
  });

  it('projects historical provider proof as pending after a complete empty provider generation', () => {
    const firstPoll = hoursAgoIso(2);
    const emptyPoll = hoursAgoIso(1);
    seedConnector({ id: 'conn_empty_revoke', observedAt: firstPoll, pollRevision: 1 });
    const imported = bulkImportTargets(CTX, 'tg_1', {
      connector_id: 'conn_empty_revoke',
      items: [{ kind: 'fqdn', value: 'owned.example.com' }],
    }).imported[0];
    const connector = getStore().wafConnectors[0];

    assert.equal(listTargets(CTX).find((target) => target.id === imported.id).verification_state, 'provider_verified');
    assert.equal(getTargetDetail(CTX, imported.id).verification.state, 'provider_verified');
    assert.equal(getLadder(CTX, 'tg_1').steps.find((step) => step.id === 'dns_verified').count, 1);

    connector.poll_revision = 2;
    connector.last_success_revision = 2;
    connector.last_success_at = emptyPoll;
    connector.updated_at = emptyPoll;

    assert.equal(listTargets(CTX).find((target) => target.id === imported.id).verification_state, 'pending');
    assert.equal(getTargetDetail(CTX, imported.id).verification.state, 'pending');
    assert.equal(getLadder(CTX, 'tg_1').steps.find((step) => step.id === 'dns_verified').count, 0);
    assert.deepEqual(
      targetOwnershipProof(CTX, getStore().targetGroups[0], imported.id),
      { verified: false, state: 'pending', source: null },
    );
  });

  it('never grants provider verification to sandbox, pending, or status-absent zones', () => {
    seedConnector({
      id: 'conn_namecheap_sandbox',
      provider: 'namecheap',
      displayRef: 'sandbox.example.com',
      hostnames: ['sandbox.example.com'],
      providerEnvironment: 'sandbox',
      resourceStatus: 'sandbox',
      ownershipEligible: false,
    });
    seedConnector({
      id: 'conn_cloudflare_pending',
      displayRef: 'pending.example.com',
      hostnames: ['pending.example.com'],
      resourceStatus: 'pending',
      ownershipEligible: false,
    });
    seedConnector({
      id: 'conn_cloudflare_unknown',
      displayRef: 'unknown.example.com',
      hostnames: ['unknown.example.com'],
      resourceStatus: 'unknown',
      ownershipEligible: false,
    });

    for (const [connectorId, hostname] of [
      ['conn_namecheap_sandbox', 'sandbox.example.com'],
      ['conn_cloudflare_pending', 'pending.example.com'],
      ['conn_cloudflare_unknown', 'unknown.example.com'],
    ]) {
      const result = bulkImportTargets(CTX, 'tg_1', {
        connector_id: connectorId,
        items: [{ kind: 'fqdn', value: hostname }],
      });
      assert.equal(result.count, 1);
      assert.equal(result.imported[0].verify_state, 'pending');
      assert.equal(targetOwnershipProof(CTX, getStore().targetGroups[0], result.imported[0].id).verified, false);
    }
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
        ownership_eligible: true,
        resource_status: 'active',
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
    const oldPoll = hoursAgoIso(2);
    const latestPoll = hoursAgoIso(1);
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
    const latestPoll = hoursAgoIso(1);
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
      summary: {
        hostnames: ['postgres.example.com'],
        tags: ['resource_status:active', 'ownership_eligible:true'],
      },
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
          async isConnectorFeatureEnabled() { return true; },
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
    assert.equal(inventory.items[0].ownership_eligible, true);
    assert.equal(inventory.items[0].resource_status, 'active');

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
