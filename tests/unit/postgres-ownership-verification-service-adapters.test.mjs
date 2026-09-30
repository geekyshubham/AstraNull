import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createOwnershipVerificationRepository } from '../../src/persistence/postgres/ownershipVerificationRepository.mjs';
import { createPostgresOwnershipVerificationServices } from '../../src/persistence/postgres/ownershipVerificationServiceAdapters.mjs';
import { runWithTenantClient } from '../../src/persistence/postgres/tenantContext.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return handler(text, params, this.queries);
    },
    release() {
      this.released = true;
    },
  };
  return {
    client,
    async connect() {
      return client;
    },
  };
}

function dataQueries(client) {
  return client.queries.filter((q) => {
    const t = q.text.trim();
    return t !== 'BEGIN' && t !== 'COMMIT' && t !== 'ROLLBACK' && !t.startsWith("SELECT set_config('app.tenant_id'");
  });
}

function dbRow(overrides = {}) {
  return {
    id: 'own_1',
    tenant_id: CTX.tenantId,
    target_group_id: 'tg_1',
    agent_id: null,
    declared_fqdn: 'app.example.com',
    status: 'challenge_sent',
    challenge_nonce_hash: 'nonce_hash_1',
    probe_observed: true,
    agent_observed: false,
    verified_at: null,
    confirmed_by_user_id: null,
    confirmed_at: null,
    probe_job_id: null,
    created_at: new Date('2026-06-01T12:00:00.000Z'),
    created_by: CTX.userId,
    ...overrides,
  };
}

// Anchored 2 hours in the past so connector.last_success_at always satisfies the
// production freshness window (<= now, within PROVIDER_OWNERSHIP_MAX_AGE_MS = 24h).
function providerProofInstant(offsetMs = 0) {
  return new Date(Date.now() - 2 * 60 * 60 * 1000 + offsetMs).toISOString();
}

function providerVerificationRow({
  provider = 'cloudflare',
  connectorStatus = 'active',
  secretId = 'sec_provider_1',
  lastSuccessAt = providerProofInstant(),
  snapshotObservedAt = lastSuccessAt,
  sourceResourceRef = 'hash_zone_1',
  snapshotResourceRef = sourceResourceRef,
  targetHostname = 'app.example.com',
  snapshotHostnames = [targetHostname],
  tags = ['resource_status:active', 'ownership_eligible:true'],
  snapshotId = 'snap_current',
  snapshotKind = 'dns_zone',
  evidenceSource = 'provider_api',
  sourceKind = 'provider_account',
  featureEnabled = true,
  featureRevision = 2,
  connectorRevision = 7,
  snapshotRevision = connectorRevision,
} = {}) {
  const originalPoll = providerProofInstant(-60 * 60 * 1000);
  return {
    id: 'tv_provider_1',
    tenant_id: CTX.tenantId,
    target_id: 'tgt_1',
    state: 'provider_verified',
    source_kind: sourceKind,
    source_ref: {
      connector_id: 'conn_provider_1',
      provider,
      snapshot_kind: 'dns_zone',
      evidence_source: 'provider_api',
      resource_ref_hash: sourceResourceRef,
      snapshot_id: 'snap_original',
      observed_at: originalPoll,
      poll_generation: originalPoll,
    },
    transitioned_at: new Date(originalPoll),
    transitioned_by: CTX.userId,
    audit_entry_id: 'audit_provider_1',
    proof_target_kind: 'fqdn',
    proof_target_value: targetHostname,
    proof_target_normalized_value: targetHostname,
    proof_connector_feature_enabled: featureEnabled,
    proof_connector_feature_revision: featureRevision,
    proof_connector_id: 'conn_provider_1',
    proof_connector_provider: provider,
    proof_connector_status: connectorStatus,
    proof_connector_secret_id: secretId,
    proof_connector_last_success_at: new Date(lastSuccessAt),
    proof_connector_last_success_revision: connectorRevision,
    proof_snapshot_id: snapshotId,
    proof_snapshot_connector_id: snapshotId ? 'conn_provider_1' : null,
    proof_snapshot_provider: snapshotId ? provider : null,
    proof_snapshot_kind: snapshotId ? snapshotKind : null,
    proof_snapshot_resource_ref_hash: snapshotId ? snapshotResourceRef : null,
    proof_snapshot_summary_json: snapshotId ? { hostnames: snapshotHostnames, tags } : null,
    proof_snapshot_evidence_source: snapshotId ? evidenceSource : null,
    proof_snapshot_poll_revision: snapshotId ? snapshotRevision : null,
    proof_snapshot_observed_at: snapshotId ? new Date(snapshotObservedAt) : null,
  };
}

function buildServices(pool, audit = { appendAuditEvent: async () => ({ id: 'audit_1' }) }) {
  const ownershipVerifications = createOwnershipVerificationRepository(pool);
  const transactionalAudit = {
    ...audit,
    withTenantAuditLock: audit.withTenantAuditLock
      ?? ((tenantId, callback) => runWithTenantClient(
        pool,
        tenantId,
        undefined,
        (client) => callback({ client, prior: null }),
      )),
  };
  return createPostgresOwnershipVerificationServices({
    repositories: { ownershipVerifications },
    audit: transactionalAudit,
  });
}

describe('postgres ownership verification service adapters (outside-in)', () => {
  it('listOwnershipVerifications queries with tenant_id predicate', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM ownership_verifications/i.test(text)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const services = buildServices(pool);
    await services.listOwnershipVerifications(CTX);
    const listQuery = dataQueries(pool.client).find((q) =>
      /FROM ownership_verifications/i.test(q.text),
    );
    assert.ok(listQuery);
    assert.match(listQuery.text, /tenant_id/i);
    assert.deepEqual(listQuery.params, [CTX.tenantId]);
  });

  it('getOwnershipVerification filters by id and tenant_id', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM ownership_verifications/i.test(text) && /WHERE id = \$1 AND tenant_id = \$2/.test(text)) {
        return { rows: [dbRow()] };
      }
      return { rows: [] };
    });
    const services = buildServices(pool);
    const record = await services.getOwnershipVerification(CTX, 'own_1');
    assert.equal(record.id, 'own_1');
    const getQuery = dataQueries(pool.client).find((q) =>
      /WHERE id = \$1 AND tenant_id = \$2/.test(q.text),
    );
    assert.ok(getQuery);
    assert.deepEqual(getQuery.params, ['own_1', CTX.tenantId]);
  });

  // ADR-0008: the agent-observed challenge flow is removed. These endpoints fail closed.
  it('createOwnershipChallenge fails closed without touching the store', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const services = buildServices(pool);
    const result = await services.createOwnershipChallenge(CTX, { target_group_id: 'tg_1' }, {});
    assert.equal(result.error, 'ownership_agent_flow_removed');
    assert.equal(result.status, 410);
    assert.equal(dataQueries(pool.client).length, 0);
  });

  it('verifyOwnershipSetup fails closed', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const services = buildServices(pool);
    const result = await services.verifyOwnershipSetup(CTX, { target_group_id: 'tg_1' });
    assert.equal(result.ready, false);
    assert.equal(result.error, 'ownership_agent_flow_removed');
    assert.equal(result.status, 410);
    assert.equal(dataQueries(pool.client).length, 0);
  });

  it('recordOwnershipSignal and recordOwnershipSignalByNonce fail closed', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const services = buildServices(pool);
    const bySignal = await services.recordOwnershipSignal(CTX, 'own_1', {
      source: 'probe', nonce_hash: 'n',
    });
    assert.equal(bySignal.error, 'ownership_agent_flow_removed');
    const byNonce = await services.recordOwnershipSignalByNonce(
      { tenantId: CTX.tenantId },
      { source: 'probe', nonce_hash: 'n' },
    );
    assert.equal(byNonce.error, 'ownership_agent_flow_removed');
    assert.equal(dataQueries(pool.client).length, 0);
  });

  it('reads current ownership proof by tenant, group, and target', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM target_groups tg/i.test(text) && /JOIN LATERAL/i.test(text)) {
        return { rows: [{
          id: 'tv_1', tenant_id: CTX.tenantId, target_id: 'tgt_1',
          state: 'dns_verified', source_kind: 'dns_txt', source_ref: {},
          transitioned_at: new Date('2026-06-01T12:00:00.000Z'),
          transitioned_by: 'system', audit_entry_id: 'audit_1',
        }] };
      }
      return { rows: [] };
    });
    const repo = createOwnershipVerificationRepository(pool);

    const current = await repo.getCurrentTargetVerification(CTX, 'tg_1', 'tgt_1');

    assert.equal(current.target_id, 'tgt_1');
    assert.equal(current.state, 'dns_verified');
    const query = dataQueries(pool.client).find((entry) => /JOIN LATERAL/i.test(entry.text));
    assert.deepEqual(query.params, [CTX.tenantId, 'tg_1', 'tgt_1']);
    assert.match(query.text, /tg\.tenant_id = \$1 AND tg\.id = \$2 AND t\.id = \$3/);
    assert.match(query.text, /t\.deleted_at IS NULL/);
    assert.match(query.text, /WHEN 'user_confirmed' THEN 4/);
    // Legacy agent_verified rank is no longer part of the ordering (fails closed).
    assert.doesNotMatch(query.text, /WHEN 'agent_verified'/);
  });

  it('keeps current provider proof valid after a degraded failed poll retains last_success', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM target_groups tg/i.test(text) && /JOIN LATERAL/i.test(text)) {
        return { rows: [providerVerificationRow({ connectorStatus: 'degraded' })] };
      }
      return { rows: [] };
    });
    const repo = createOwnershipVerificationRepository(pool);

    const current = await repo.getCurrentTargetVerification(CTX, 'tg_1', 'tgt_1');

    assert.equal(current.state, 'provider_verified');
    const query = dataQueries(pool.client).find((entry) => /JOIN LATERAL/i.test(entry.text));
    assert.match(query.text, /connector_feature\.enabled AS proof_connector_feature_enabled/);
    assert.match(query.text, /LEFT JOIN tenant_connector_features connector_feature/);
    assert.match(query.text, /candidate_snapshot\.evidence_source = 'provider_api'/);
    assert.match(query.text, /candidate_snapshot\.snapshot_kind = 'dns_zone'/);
    assert.match(query.text, /candidate_snapshot\.observed_at = ownership_connector\.last_success_at/);
    assert.match(query.text, /candidate_snapshot\.poll_revision = ownership_connector\.last_success_revision/);
    assert.match(query.text, /candidate_snapshot\.resource_ref_hash = tv\.source_ref->>'resource_ref_hash'/);
  });

  for (const [label, overrides] of [
    ['disabled tenant connector feature', { featureEnabled: false }],
    ['successful empty poll', { snapshotId: null, lastSuccessAt: providerProofInstant(60 * 60 * 1000) }],
    ['disabled connector', { connectorStatus: 'disabled' }],
    ['removed vault secret', { secretId: null }],
    ['pending Cloudflare zone', { tags: ['resource_status:pending', 'ownership_eligible:false'] }],
    ['status-absent Cloudflare zone', { tags: ['ownership_eligible:true'] }],
    ['Namecheap sandbox', {
      provider: 'namecheap',
      tags: ['resource_status:sandbox', 'provider_environment:sandbox', 'ownership_eligible:false'],
    }],
    ['manual snapshot', { evidenceSource: 'manual_metadata' }],
    ['stale snapshot generation', { snapshotObservedAt: providerProofInstant(-1000) }],
    ['same-timestamp stale poll revision', { connectorRevision: 8, snapshotRevision: 7 }],
    ['different provider resource', { snapshotResourceRef: 'hash_other_zone' }],
    ['different hostname', { snapshotHostnames: ['victim.example.com'] }],
    ['non-provider source kind', { sourceKind: 'connector_inventory' }],
  ]) {
    it(`downgrades provider_verified for ${label}`, async () => {
      const pool = createRecordingPool((text) => {
        if (/FROM target_groups tg/i.test(text) && /JOIN LATERAL/i.test(text)) {
          return { rows: [providerVerificationRow(overrides)] };
        }
        return { rows: [] };
      });
      const repo = createOwnershipVerificationRepository(pool);

      const current = await repo.getCurrentTargetVerification(CTX, 'tg_1', 'tgt_1');

      assert.equal(current.state, 'pending');
      assert.equal(current.target_id, 'tgt_1');
    });
  }

  it('atomically confirms only A from a verified record, keeps unverified B, and is idempotent', async () => {
    const auditCalls = [];
    let ownership = dbRow({
      status: 'verified',
      verified_at: '2026-06-01T12:05:00.000Z',
    });
    let current = {
      id: 'tv_dns',
      tenant_id: CTX.tenantId,
      target_id: 'tgt_1',
      state: 'dns_verified',
      source_kind: 'dns_txt',
      source_ref: { dns_challenge_id: 'dns_1' },
      transitioned_at: new Date('2026-06-01T12:05:00.000Z'),
      transitioned_by: 'system',
      audit_entry_id: 'audit_dns',
    };
    const pool = createRecordingPool((text, params) => {
      if (/FROM ownership_verifications/i.test(text) && /FOR UPDATE/i.test(text)) {
        return { rows: [ownership] };
      }
      if (/FROM target_groups tg/i.test(text) && /JOIN targets t/i.test(text)) {
        return { rows: [{
          id: 'tgt_1', tenant_id: CTX.tenantId, target_group_id: 'tg_1',
          kind: 'fqdn', value: 'app.example.com', normalized_value: 'app.example.com',
        }] };
      }
      if (/FROM target_verifications/i.test(text) && /FOR UPDATE/i.test(text)) {
        return { rows: [current] };
      }
      if (/INSERT INTO target_verifications/i.test(text) && /user_confirmed/i.test(text)) {
        current = {
          id: params[0], tenant_id: params[1], target_id: params[2],
          state: 'user_confirmed', source_kind: 'user_attestation',
          source_ref: JSON.parse(params[3]), transitioned_at: new Date(params[4]),
          transitioned_by: params[5], audit_entry_id: params[6],
        };
        return { rows: [current] };
      }
      if (/UPDATE ownership_verifications/i.test(text) && /confirmed_at = COALESCE/i.test(text)) {
        ownership = {
          ...ownership,
          confirmed_by_user_id: ownership.confirmed_by_user_id ?? params[2],
          confirmed_at: ownership.confirmed_at ?? params[3],
        };
        return { rows: [ownership] };
      }
      if (/SELECT t\.id AS target_id/i.test(text)) {
        return { rows: [
          { target_id: 'tgt_1', state: current.state },
          { target_id: 'tgt_2', state: null },
        ] };
      }
      if (/UPDATE target_groups/i.test(text) && /ownership_status/.test(text)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const audit = {
      async appendAuditEvent(entry, options) {
        auditCalls.push({ entry, options });
        return { id: `audit_confirm_${auditCalls.length}` };
      },
    };
    const services = buildServices(pool, audit);

    const first = await services.confirmOwnership(CTX, 'own_1');
    const second = await services.confirmOwnership(CTX, 'own_1');

    assert.equal(first.target_id, 'tgt_1');
    assert.equal(first.target_verification.state, 'user_confirmed');
    assert.equal(first.target_verification.source_kind, 'user_attestation');
    // No agent_id in the user-confirmed source_ref (ADR-0008).
    assert.deepEqual(first.target_verification.source_ref, {
      ownership_verification_id: 'own_1',
      declared_fqdn: 'app.example.com',
      confirmed_by_user_id: CTX.userId,
    });
    assert.equal(first.verification.confirmed_by_user_id, CTX.userId);
    assert.ok(first.verification.confirmed_at);
    assert.equal(first.ownership_status, 'unverified');
    assert.equal(second.target_verification.id, first.target_verification.id);
    assert.equal(second.verification.confirmed_at, first.verification.confirmed_at);
    assert.equal(second.ownership_status, 'unverified');

    const queries = dataQueries(pool.client);
    assert.equal(
      queries.filter((query) => /INSERT INTO target_verifications/i.test(query.text)).length,
      1,
    );
    const groupUpdates = queries.filter((query) => /UPDATE target_groups/i.test(query.text));
    assert.equal(groupUpdates.length, 2);
    assert.ok(groupUpdates.every((query) => query.params[2] === 'unverified'));
    assert.deepEqual(auditCalls.map(({ entry }) => entry.action), [
      'target_verification.user_confirmed',
      'ownership_verification.user_confirmed',
    ]);
    assert.ok(auditCalls.every(({ options }) => options.client === pool.client));
    assert.equal(pool.client.queries.filter((query) => query.text === 'BEGIN').length, 2);
    assert.equal(pool.client.queries.filter((query) => query.text === 'COMMIT').length, 2);
  });

  it('fails closed when the challenge-bound target was deleted or replaced', async () => {
    const auditCalls = [];
    const pool = createRecordingPool((text) => {
      if (/FROM ownership_verifications/i.test(text) && /FOR UPDATE/i.test(text)) {
        return { rows: [dbRow({
          status: 'verified',
          verified_at: '2026-06-01T12:05:00.000Z',
        })] };
      }
      if (/FROM target_groups tg/i.test(text) && /JOIN targets t/i.test(text)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const services = buildServices(pool, {
      async appendAuditEvent(entry) {
        auditCalls.push(entry);
        return { id: 'unexpected_audit' };
      },
    });

    const result = await services.confirmOwnership(CTX, 'own_1');

    assert.deepEqual(result, { error: 'ownership_target_not_active', status: 409 });
    const queries = dataQueries(pool.client);
    const binding = queries.find(
      (query) => /FROM target_groups tg/i.test(query.text) && /JOIN targets t/i.test(query.text),
    );
    assert.ok(binding);
    assert.match(binding.text, /t\.deleted_at IS NULL/);
    assert.match(binding.text, /t\.created_at <= \$4::timestamptz/);
    assert.equal(queries.some((query) => /^\s*(INSERT|UPDATE)/i.test(query.text)), false);
    assert.deepEqual(auditCalls, []);
  });

  it('confirmOwnership rejects non-verified rows', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM ownership_verifications/i.test(text)) {
        return { rows: [dbRow({ status: 'challenge_sent' })] };
      }
      return { rows: [] };
    });
    const services = buildServices(pool);
    const result = await services.confirmOwnership(CTX, 'own_1');
    assert.deepEqual(result, { error: 'ownership_not_verified', status: 409 });
  });
});
