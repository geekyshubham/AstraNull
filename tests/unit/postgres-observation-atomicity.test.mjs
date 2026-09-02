import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAgentControlRepository } from '../../src/persistence/postgres/agentControlRepository.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';

const TENANT_ID = 'ten_demo';
const AGENT_ID = 'agent_1';
const JOB_ID = 'job_1';
const RUN_ID = 'run_1';
const NOW = '2026-06-01T12:00:00.000Z';
const CTX = { tenantId: TENANT_ID, userId: AGENT_ID, role: 'agent' };

function createAtomicityPool({ failAudit = false } = {}) {
  let connectCount = 0;
  let active = false;
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      if (text.includes('pg_try_advisory_xact_lock')) {
        return { rows: [{ acquired: true }] };
      }
      if (text.includes('FROM soc_kill_switch')) {
        return { rows: [{ active: false }] };
      }
      if (text.startsWith('UPDATE agent_jobs')) {
        return {
          rows: [{
            id: JOB_ID,
            tenant_id: TENANT_ID,
            agent_id: AGENT_ID,
            test_run_id: RUN_ID,
            check_id: 'origin.direct_bypass.safe',
            target_id: 'target_1',
            type: 'observe_window',
            status: 'observed',
            nonce_hash: 'nonce_hash_1',
            payload_json: {},
            created_at: NOW,
            acked_at: NOW,
            observed_at: NOW,
          }],
        };
      }
      if (text.startsWith('INSERT INTO events')) {
        return {
          rows: [{
            id: 'event_1',
            tenant_id: TENANT_ID,
            event_id: null,
            test_run_id: RUN_ID,
            target_id: 'target_1',
            check_id: 'origin.direct_bypass.safe',
            agent_id: AGENT_ID,
            source: 'agent',
            signal_type: 'agent_observation',
            producer_kind: 'authenticated_agent',
            nonce_hash: 'nonce_hash_1',
            timestamp: NOW,
            metadata_json: { mode: 'canary' },
          }],
        };
      }
      if (text.includes('FROM audit_logs')) return { rows: [] };
      if (text.startsWith('INSERT INTO audit_logs') && failAudit) {
        throw new Error('audit insert failed');
      }
      return { rows: [] };
    },
    release() {
      this.released = true;
      active = false;
    },
  };
  return {
    client,
    get connectCount() {
      return connectCount;
    },
    async connect() {
      if (active) throw new Error('pool-size-1 second client requested');
      active = true;
      connectCount += 1;
      return client;
    },
  };
}

async function writeConfirmedObservation(pool) {
  const agentControl = createAgentControlRepository(pool);
  const validationEvidence = createValidationEvidenceRepository(pool);
  const audit = createAuditRepository(pool);
  const killSwitch = createKillSwitchRepository(pool);

  return audit.withTenantAuditLock(TENANT_ID, ({ client: auditClient }) =>
    validationEvidence.withRunMutationLock(CTX, RUN_ID, async (client) => {
      assert.equal(await killSwitch.isKillSwitchActiveForTenant(CTX, { client }), false);
      const job = await agentControl.markAgentJobObserved(
        { tenantId: TENANT_ID, agentId: AGENT_ID, jobId: JOB_ID },
        NOW,
        { client },
      );
      const event = await validationEvidence.appendEvent(
        CTX,
        {
          id: 'event_1',
          tenant_id: TENANT_ID,
          test_run_id: RUN_ID,
          target_id: 'target_1',
          check_id: 'origin.direct_bypass.safe',
          agent_id: AGENT_ID,
          source: 'agent',
          signal_type: 'agent_observation',
          producer_kind: 'authenticated_agent',
          nonce_hash: 'nonce_hash_1',
          timestamp: NOW,
          metadata: { mode: 'canary', agent_job_id: JOB_ID },
        },
        { client },
      );
      const auditEntry = await audit.appendAuditEvent(
        {
          tenant_id: TENANT_ID,
          actor_user_id: AGENT_ID,
          actor_role: 'agent',
          action: 'observation.ingested',
          resource_type: 'test_run',
          resource_id: RUN_ID,
          metadata: { agent_id: AGENT_ID, agent_job_id: JOB_ID },
        },
        {
          client,
          now: new Date(NOW),
          idempotency: {
            actions: ['observation.ingested', 'observation.recovered'],
            resourceType: 'test_run',
            resourceId: RUN_ID,
            metadata: { agent_job_id: JOB_ID },
          },
        },
      );
      return { job, event, auditEntry };
    }, { client: auditClient }));
}

function countQuery(client, sql) {
  return client.queries.filter(({ text }) => text.trim() === sql).length;
}

describe('postgres confirmed observation atomicity', () => {
  it('uses one pool-size-1 audit/run transaction in global lock order', async () => {
    const pool = createAtomicityPool();
    const mutation = await writeConfirmedObservation(pool);

    assert.equal(mutation.acquired, true);
    assert.equal(mutation.result.job.status, 'observed');
    assert.equal(mutation.result.event.signal_type, 'agent_observation');
    assert.equal(mutation.result.auditEntry.action, 'observation.ingested');
    assert.equal(pool.connectCount, 1);
    assert.equal(countQuery(pool.client, 'BEGIN'), 1);
    assert.equal(countQuery(pool.client, 'COMMIT'), 1);
    assert.equal(countQuery(pool.client, 'ROLLBACK'), 0);
    assert.equal(pool.client.released, true);

    const statements = pool.client.queries.map(({ text }) => text.trim());
    const tenantAuditLockIndex = pool.client.queries.findIndex(
      ({ text, params }) => text.includes('pg_advisory_xact_lock(hashtext($1))')
        && params?.[0] === TENANT_ID,
    );
    const runLockIndex = statements.findIndex((text) =>
      text.includes('pg_try_advisory_xact_lock'));
    const killSwitchReadIndex = statements.findIndex((text) =>
      text.includes('FROM soc_kill_switch'));
    const transitionIndex = statements.findIndex((text) => text.startsWith('UPDATE agent_jobs'));
    const eventIndex = statements.findIndex((text) => text.startsWith('INSERT INTO events'));
    const auditIndex = statements.findIndex((text) => text.startsWith('INSERT INTO audit_logs'));
    const commitIndex = statements.indexOf('COMMIT');
    assert.ok(transitionIndex > statements.indexOf('BEGIN'));
    assert.ok(
      tenantAuditLockIndex >= 0
        && tenantAuditLockIndex < runLockIndex
        && runLockIndex < killSwitchReadIndex
        && killSwitchReadIndex < transitionIndex,
    );
    assert.ok(transitionIndex < eventIndex && eventIndex < auditIndex && auditIndex < commitIndex);
    assert.ok(statements.some((text) => text.includes('pg_try_advisory_xact_lock')));
  });

  it('rolls back the job transition and event when audit persistence fails', async () => {
    const pool = createAtomicityPool({ failAudit: true });

    await assert.rejects(() => writeConfirmedObservation(pool), /audit insert failed/);
    assert.equal(pool.connectCount, 1);
    assert.equal(countQuery(pool.client, 'BEGIN'), 1);
    assert.equal(countQuery(pool.client, 'COMMIT'), 0);
    assert.equal(countQuery(pool.client, 'ROLLBACK'), 1);
    assert.equal(pool.client.released, true);
  });
});
