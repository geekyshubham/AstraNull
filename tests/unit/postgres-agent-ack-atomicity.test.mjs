import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAgentControlRepository } from '../../src/persistence/postgres/agentControlRepository.mjs';
import { createPostgresAgentServices } from '../../src/persistence/postgres/agentServiceAdapters.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';

const TENANT_ID = 'ten_demo';
const AGENT_ID = 'agent_1';
const JOB_ID = 'job_1';
const RUN_ID = 'run_1';
const NOW = '2026-06-01T12:00:00.000Z';

function rawJob(overrides = {}) {
  return {
    id: JOB_ID,
    tenant_id: TENANT_ID,
    agent_id: AGENT_ID,
    test_run_id: RUN_ID,
    check_id: 'origin.direct_bypass.safe',
    target_id: 'target_1',
    type: 'observe_window',
    status: 'pending',
    nonce_hash: 'nonce_hash_1',
    nonce_for_agent: null,
    payload_json: {},
    created_at: NOW,
    acked_at: null,
    observed_at: null,
    ...overrides,
  };
}

function createAtomicAckPool({ failAudit = false } = {}) {
  let connectCount = 0;
  let active = false;
  let durable = { job: rawJob(), audits: [] };
  let transaction = null;

  const state = () => transaction ?? durable;
  const client = {
    queries: [],
    async query(text, params = []) {
      this.queries.push({ text, params });
      const sql = text.trim();
      if (sql === 'BEGIN') {
        transaction = structuredClone(durable);
        return { rows: [] };
      }
      if (sql === 'COMMIT') {
        durable = transaction;
        transaction = null;
        return { rows: [] };
      }
      if (sql === 'ROLLBACK') {
        transaction = null;
        return { rows: [] };
      }
      if (text.includes('FROM agent_jobs') && text.includes('FOR UPDATE')) {
        return { rows: [structuredClone(state().job)] };
      }
      if (sql.startsWith('UPDATE agent_jobs')) {
        if (state().job.status !== 'pending') return { rows: [] };
        state().job = rawJob({
          ...state().job,
          status: 'acked',
          acked_at: params[0],
        });
        return { rows: [structuredClone(state().job)] };
      }
      if (text.includes('FROM audit_logs')) {
        const rows = text.includes('action = ANY')
          ? state().audits.filter((row) => (
            params[1].includes(row.action)
            && row.resource_type === params[2]
            && row.resource_id === params[3]
          ))
          : state().audits.slice(-1);
        return { rows: structuredClone(rows) };
      }
      if (sql.startsWith('INSERT INTO audit_logs')) {
        if (failAudit) throw new Error('audit insert failed');
        state().audits.push({
          id: params[0],
          tenant_id: params[1],
          timestamp: params[2],
          sequence: params[3],
          prev_hash: params[4],
          entry_hash: params[5],
          actor_user_id: params[6],
          actor_role: params[7],
          action: params[8],
          resource_type: params[9],
          resource_id: params[10],
          metadata_json: JSON.parse(params[11]),
        });
        return { rows: [] };
      }
      return { rows: [] };
    },
    release() {
      active = false;
    },
  };

  return {
    client,
    get connectCount() {
      return connectCount;
    },
    snapshot() {
      return structuredClone(durable);
    },
    async connect() {
      if (active) throw new Error('pool-size-1 second client requested');
      active = true;
      connectCount += 1;
      return client;
    },
  };
}

function createAckService(pool) {
  return createPostgresAgentServices(
    {
      agentControl: createAgentControlRepository(pool),
      audit: createAuditRepository(pool),
    },
    {
      now: () => new Date(NOW),
      tokens: { consumeBootstrapToken: async () => null },
    },
  ).agents;
}

function queryCount(client, predicate) {
  return client.queries.filter(({ text }) => predicate(text.trim())).length;
}

describe('postgres agent ACK atomicity', () => {
  it('uses one audit-first client and persists only one audit across ACK replay', async () => {
    const pool = createAtomicAckPool();
    const agents = createAckService(pool);
    const agent = { id: AGENT_ID, tenant_id: TENANT_ID };

    assert.equal((await agents.ackJob(agent, JOB_ID)).status, 'acked');
    assert.equal((await agents.ackJob(agent, JOB_ID)).status, 'acked');

    const snapshot = pool.snapshot();
    assert.equal(snapshot.job.status, 'acked');
    assert.equal(snapshot.audits.length, 1);
    assert.equal(snapshot.audits[0].action, 'agent.job_acked');
    assert.equal(pool.connectCount, 2);
    assert.equal(
      queryCount(pool.client, (text) => text.startsWith('UPDATE agent_jobs')),
      1,
    );
    assert.equal(
      queryCount(pool.client, (text) => text.startsWith('INSERT INTO audit_logs')),
      1,
    );

    const statements = pool.client.queries.map(({ text }) => text.trim());
    const auditLock = statements.findIndex((text) =>
      text.includes('pg_advisory_xact_lock(hashtext($1))'));
    const jobLock = statements.findIndex((text) =>
      text.includes('FROM agent_jobs') && text.includes('FOR UPDATE'));
    const transition = statements.findIndex((text) => text.startsWith('UPDATE agent_jobs'));
    const auditInsert = statements.findIndex((text) => text.startsWith('INSERT INTO audit_logs'));
    const commit = statements.indexOf('COMMIT');
    assert.ok(auditLock >= 0 && auditLock < jobLock);
    assert.ok(jobLock < transition && transition < auditInsert && auditInsert < commit);
  });

  it('rolls the ACK transition back when final audit persistence fails', async () => {
    const pool = createAtomicAckPool({ failAudit: true });
    const agents = createAckService(pool);

    await assert.rejects(
      () => agents.ackJob({ id: AGENT_ID, tenant_id: TENANT_ID }, JOB_ID),
      /audit insert failed/,
    );

    const snapshot = pool.snapshot();
    assert.equal(snapshot.job.status, 'pending');
    assert.equal(snapshot.job.acked_at, null);
    assert.equal(snapshot.audits.length, 0);
    assert.equal(pool.connectCount, 1);
    assert.equal(queryCount(pool.client, (text) => text === 'COMMIT'), 0);
    assert.equal(queryCount(pool.client, (text) => text === 'ROLLBACK'), 1);
  });
});
