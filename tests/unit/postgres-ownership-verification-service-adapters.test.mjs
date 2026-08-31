import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createOwnershipVerificationRepository } from '../../src/persistence/postgres/ownershipVerificationRepository.mjs';
import { createPostgresOwnershipVerificationServices } from '../../src/persistence/postgres/ownershipVerificationServiceAdapters.mjs';

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
    agent_id: 'agt_1',
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
  return createPostgresOwnershipVerificationServices({
    repositories: { ownershipVerifications },
    audit,
  });
}

function onlineAgent(overrides = {}) {
  return {
    id: 'agt_1',
    target_group_id: 'tg_1',
    status: 'online',
    last_token_validation_status: 'valid',
    probe_endpoint: { declared_fqdn: 'app.example.com' },
    ...overrides,
  };
}

function ownershipSetupPoolHandler(overrides = {}) {
  return (text) => {
    if (/FROM target_groups/i.test(text)) {
      return {
        rows: [
          {
            id: 'tg_1',
            tenant_id: CTX.tenantId,
            validation_mode: 'agent_assisted',
            ownership_status: 'unverified',
            dns_ownership: null,
            archived_at: null,
          },
        ],
      };
    }
    if (/FROM targets/i.test(text) && /kind = 'fqdn'/i.test(text)) {
      return { rows: [{ value: 'app.example.com' }] };
    }
    return overrides.fallback?.(text) ?? { rows: [] };
  };
}

function buildServicesWithAgent(pool, agent) {
  const ownershipVerifications = createOwnershipVerificationRepository(pool);
  return createPostgresOwnershipVerificationServices({
    repositories: { ownershipVerifications },
    agentControl: { getAgentById: async () => agent },
    audit: { appendAuditEvent: async () => ({ id: 'audit_1' }) },
  });
}

function assertSelectOnlyDataQueries(client) {
  for (const q of dataQueries(client)) {
    const t = q.text.trim();
    assert.match(t, /^SELECT/i, `expected SELECT only, got: ${t.slice(0, 120)}`);
    assert.doesNotMatch(t, /INSERT INTO ownership_verifications/i);
    assert.doesNotMatch(t, /^UPDATE\b/i);
  }
}

describe('postgres ownership verification service adapters', () => {
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
    const pool = createRecordingPool((text, params) => {
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

  it('atomically completes against the exact active target and writes target-bound evidence', async () => {
    const auditCalls = [];
    const verifiedAt = '2026-06-01T12:05:00.000Z';
    const pool = createRecordingPool((text, params) => {
      if (/FROM ownership_verifications/i.test(text) && /challenge_nonce_hash/.test(text)) {
        return { rows: [dbRow({ probe_observed: true, agent_observed: false })] };
      }
      if (/FROM target_groups tg/i.test(text) && /JOIN targets t/i.test(text)) {
        return { rows: [{
          id: 'tgt_1', tenant_id: CTX.tenantId, target_group_id: 'tg_1',
          kind: 'fqdn', value: 'app.example.com', normalized_value: 'app.example.com',
        }] };
      }
      if (/FROM target_verifications/i.test(text) && /FOR UPDATE/i.test(text)) {
        return { rows: [] };
      }
      if (/INSERT INTO target_verifications/i.test(text)) {
        return { rows: [{
          id: params[0], tenant_id: params[1], target_id: params[2],
          state: 'agent_verified', source_kind: 'agent_observation',
          source_ref: JSON.parse(params[3]), transitioned_at: new Date(params[4]),
          transitioned_by: params[5], audit_entry_id: params[6],
        }] };
      }
      if (/UPDATE ownership_verifications/i.test(text) && /status = 'verified'/i.test(text)) {
        return { rows: [dbRow({
          probe_observed: true,
          agent_observed: true,
          status: 'verified',
          verified_at: verifiedAt,
        })] };
      }
      if (/SELECT t\.id AS target_id/i.test(text)) {
        return { rows: [{ target_id: 'tgt_1', state: 'agent_verified' }] };
      }
      if (/UPDATE target_groups/i.test(text) && /ownership_status/.test(text)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const audit = {
      async appendAuditEvent(entry, options) {
        auditCalls.push({ entry, options });
        return { id: `audit_${auditCalls.length}` };
      },
    };
    const services = buildServices(pool, audit);

    const result = await services.recordOwnershipSignalByNonce(
      { tenantId: CTX.tenantId },
      { source: 'agent', nonce_hash: 'nonce_hash_1' },
    );

    assert.equal(result.verification.status, 'verified');
    assert.equal(result.target_id, 'tgt_1');
    assert.equal(result.target_verification.target_id, 'tgt_1');
    assert.equal(result.target_verification.state, 'agent_verified');
    assert.equal(result.ownership_status, 'agent_verified');
    const queries = dataQueries(pool.client);
    const targetInsert = queries.find((q) => /INSERT INTO target_verifications/i.test(q.text));
    assert.ok(targetInsert);
    assert.equal(targetInsert.params[2], 'tgt_1');
    assert.deepEqual(JSON.parse(targetInsert.params[3]), {
      ownership_verification_id: 'own_1',
      agent_id: 'agt_1',
      declared_fqdn: 'app.example.com',
    });
    const groupUpdate = queries.find((q) => /UPDATE target_groups/i.test(q.text));
    assert.deepEqual(groupUpdate.params, [CTX.tenantId, 'tg_1', 'agent_verified']);
    assert.deepEqual(auditCalls.map(({ entry }) => entry.action), [
      'target_verification.agent_verified',
      'ownership_verification.agent_verified',
    ]);
    assert.ok(auditCalls.every(({ options }) => options.client === pool.client));
    assert.equal(pool.client.queries[0].text, 'BEGIN');
    assert.equal(pool.client.queries.at(-1).text, 'COMMIT');
  });

  it('rolls back challenge completion when target evidence cannot be inserted', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM ownership_verifications/i.test(text) && /WHERE tenant_id = \$1 AND id = \$2/.test(text)) {
        return { rows: [dbRow({ probe_observed: true, agent_observed: false })] };
      }
      if (/FROM target_groups tg/i.test(text) && /JOIN targets t/i.test(text)) {
        return { rows: [{
          id: 'tgt_1', tenant_id: CTX.tenantId, target_group_id: 'tg_1',
          kind: 'fqdn', value: 'app.example.com', normalized_value: 'app.example.com',
        }] };
      }
      if (/FROM target_verifications/i.test(text) && /FOR UPDATE/i.test(text)) return { rows: [] };
      if (/INSERT INTO target_verifications/i.test(text)) throw new Error('target evidence failed');
      return { rows: [] };
    });
    const services = buildServices(pool);

    await assert.rejects(
      services.recordOwnershipSignal(CTX, 'own_1', {
        source: 'agent', nonce_hash: 'nonce_hash_1',
      }),
      /target evidence failed/,
    );

    assert.equal(pool.client.queries.at(-1).text, 'ROLLBACK');
    assert.equal(pool.client.queries.some((query) => query.text === 'COMMIT'), false);
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
    assert.match(query.text, /connector_feature\.revision AS proof_connector_feature_revision/);
    assert.match(query.text, /LEFT JOIN tenant_connector_features connector_feature/);
    assert.match(query.text, /ownership_connector\.status AS proof_connector_status/);
    assert.match(query.text, /ownership_connector\.secret_id AS proof_connector_secret_id/);
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

  it('verifyOwnershipSetup returns ready without INSERT or UPDATE', async () => {
    const pool = createRecordingPool(ownershipSetupPoolHandler());
    const services = buildServicesWithAgent(pool, onlineAgent());
    const result = await services.verifyOwnershipSetup(CTX, {
      target_group_id: 'tg_1',
      agent_id: 'agt_1',
    });

    assert.equal(result.dry_run, true);
    assert.equal(result.ready, true);
    assert.equal(result.target_group_id, 'tg_1');
    assert.equal(result.agent_id, 'agt_1');
    assert.equal(result.declared_fqdn, 'app.example.com');
    assert.deepEqual(result.checks, {
      agent_online: true,
      agent_bound: true,
      token_valid: true,
      fqdn_declared: true,
    });
    assertSelectOnlyDataQueries(pool.client);
  });

  it('verifyOwnershipSetup returns agent_not_online when agent is offline', async () => {
    const pool = createRecordingPool(ownershipSetupPoolHandler());
    const services = buildServicesWithAgent(pool, onlineAgent({ status: 'offline' }));
    const result = await services.verifyOwnershipSetup(CTX, {
      target_group_id: 'tg_1',
      agent_id: 'agt_1',
    });

    assert.equal(result.dry_run, true);
    assert.equal(result.ready, false);
    assert.equal(result.error, 'agent_not_online');
    assert.equal(result.status, 409);
    assertSelectOnlyDataQueries(pool.client);
  });

  it('creates signed ownership verification and probe job in one transaction', async () => {
    const pool = createRecordingPool((text, params) => {
      if (/FROM target_groups/i.test(text)) {
        return { rows: [{
          id: 'tg_1', tenant_id: CTX.tenantId, validation_mode: 'agent_assisted',
          ownership_status: 'unverified', dns_ownership: null, archived_at: null,
        }] };
      }
      if (/FROM targets/i.test(text) && /kind = 'fqdn'/i.test(text)) {
        return { rows: [{ value: 'app.example.com' }] };
      }
      if (/INSERT INTO ownership_verifications/i.test(text)) {
        assert.match(text, /CURRENT_TIMESTAMP/);
        return { rows: [dbRow({
          id: params[0],
          challenge_nonce_hash: params[6],
          probe_job_id: params[12],
          created_at: new Date(),
        })] };
      }
      return { rows: [] };
    });
    let probeInsert;
    const ownershipVerifications = createOwnershipVerificationRepository(pool);
    const services = createPostgresOwnershipVerificationServices({
      repositories: { ownershipVerifications },
      agentControl: { getAgentById: async () => onlineAgent() },
      probeJobs: {
        async createProbeJob(ctx, job, options) {
          probeInsert = { ctx, job, options };
          return job;
        },
      },
      audit: { appendAuditEvent: async () => ({ id: 'audit_1' }) },
    });

    const result = await services.createOwnershipChallenge(CTX, {
      target_group_id: 'tg_1',
      agent_id: 'agt_1',
    }, {
      probeMode: 'signed-worker',
      probeWorkerSecret: 'probe-worker-secret-at-least-32-chars',
    });

    assert.ok(result.verification.probe_job_id);
    assert.equal(probeInsert.options.client, pool.client);
    assert.equal(probeInsert.job.ownership_verification_id, result.verification.id);
    assert.equal(probeInsert.job.test_run_id, result.verification.id);
    assert.equal(probeInsert.job.target_id, 'agt_1');
    assert.equal(pool.client.queries[0].text, 'BEGIN');
    assert.equal(pool.client.queries.at(-1).text, 'COMMIT');
  });

  it('rolls back signed ownership verification when probe job insertion fails', async () => {
    const pool = createRecordingPool((text, params) => {
      if (/FROM target_groups/i.test(text)) {
        return { rows: [{ id: 'tg_1', tenant_id: CTX.tenantId, archived_at: null }] };
      }
      if (/FROM targets/i.test(text) && /kind = 'fqdn'/i.test(text)) {
        return { rows: [{ value: 'app.example.com' }] };
      }
      if (/INSERT INTO ownership_verifications/i.test(text)) {
        return { rows: [dbRow({ id: params[0], challenge_nonce_hash: params[6] })] };
      }
      return { rows: [] };
    });
    const ownershipVerifications = createOwnershipVerificationRepository(pool);
    const services = createPostgresOwnershipVerificationServices({
      repositories: { ownershipVerifications },
      agentControl: { getAgentById: async () => onlineAgent() },
      probeJobs: { createProbeJob: async () => { throw new Error('probe insert failed'); } },
      audit: { appendAuditEvent: async () => ({ id: 'audit_1' }) },
    });

    await assert.rejects(
      services.createOwnershipChallenge(CTX, {
        target_group_id: 'tg_1',
        agent_id: 'agt_1',
      }, {
        probeMode: 'signed-worker',
        probeWorkerSecret: 'probe-worker-secret-at-least-32-chars',
      }),
      /probe insert failed/,
    );
    assert.equal(pool.client.queries.at(-1).text, 'ROLLBACK');
    const lastBegin = pool.client.queries.findLastIndex((query) => query.text === 'BEGIN');
    assert.equal(
      pool.client.queries.slice(lastBegin + 1).some((query) => query.text === 'COMMIT'),
      false,
    );
  });

  it('atomically confirms only A, keeps unverified B in the summary, and is idempotent', async () => {
    const auditCalls = [];
    let ownership = dbRow({
      status: 'verified',
      agent_observed: true,
      verified_at: '2026-06-01T12:05:00.000Z',
    });
    let current = {
      id: 'tv_agent',
      tenant_id: CTX.tenantId,
      target_id: 'tgt_1',
      state: 'agent_verified',
      source_kind: 'agent_observation',
      source_ref: { ownership_verification_id: 'own_1' },
      transitioned_at: new Date('2026-06-01T12:05:00.000Z'),
      transitioned_by: 'system',
      audit_entry_id: 'audit_agent',
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
    assert.deepEqual(first.target_verification.source_ref, {
      ownership_verification_id: 'own_1',
      agent_id: 'agt_1',
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
    const bindingQueries = queries.filter(
      (query) => /FROM target_groups tg/i.test(query.text) && /JOIN targets t/i.test(query.text),
    );
    assert.equal(bindingQueries.length, 2);
    assert.ok(bindingQueries.every((query) => /t\.created_at <= \$4::timestamptz/.test(query.text)));
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
          agent_observed: true,
          verified_at: '2026-06-01T12:05:00.000Z',
        })] };
      }
      if (/FROM target_groups tg/i.test(text) && /JOIN targets t/i.test(text)) {
        // A same-FQDN replacement is newer than the challenge and therefore excluded by SQL.
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