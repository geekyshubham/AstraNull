import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createValidationEvidenceRepository,
  mapEventRow,
  mapEvidenceRow,
  mapFindingRow,
  mapTestRunRow,
  mapVerdictRow,
} from '../../src/persistence/postgres/validationEvidenceRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const RUN_ID = 'run_abc';
const EVENT_EXT_ID = 'evt_external_1';
const EVIDENCE_ID = 'evidence_1';
const VERDICT_ID = 'verdict_1';
const FINDING_ID = 'finding_1';

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

function assertTenantWrapped(client, tenantId) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

function assertUsesTenantPredicate(sql, params, tenantId) {
  const hasWherePredicate = /tenant_id\s*=\s*\$\d+/i.test(sql);
  const hasInsertColumn = /INSERT\s+INTO\s+\w+\s*\([^)]*tenant_id/i.test(sql);
  assert.ok(
    hasWherePredicate || hasInsertColumn,
    `expected tenant_id predicate or INSERT column in: ${sql}`,
  );
  assert.ok(params.includes(tenantId), `expected tenant id in params for: ${sql}`);
}

function assertNoInterpolatedValue(sql, value) {
  if (value == null || value === '') return;
  assert.ok(!sql.includes(String(value)), `value must not be interpolated into SQL: ${value}`);
}

const testRunRow = {
  id: RUN_ID,
  tenant_id: CTX.tenantId,
  target_group_id: 'tg_1',
  target_id: 'tgt_1',
  check_id: 'chk_1',
  status: 'running',
  awaiting_external_probe: false,
  safety_constraints: { max_events: 10 },
  correlation_json: { nonce_hash: 'nh', window_ms: 120000 },
  summary_json: { ok: true },
  collection_deadline_at: new Date(FIXED_NOW),
  created_at: new Date(FIXED_NOW),
};

describe('postgres validation evidence repository', () => {
  it('maps rows with JSON aliases, ISO dates, and default arrays', () => {
    const run = mapTestRunRow(testRunRow);
    assert.equal(run.collection_deadline_at, FIXED_NOW);
    assert.deepEqual(run.correlation, { nonce_hash: 'nh', window_ms: 120000 });
    assert.deepEqual(run.summary, { ok: true });
    assert.deepEqual(run.safety_constraints, { max_events: 10 });

    const event = mapEventRow({
      id: 'event_1',
      tenant_id: CTX.tenantId,
      event_id: EVENT_EXT_ID,
      timestamp: new Date(FIXED_NOW),
      metadata_json: { probe: 'blocked' },
    });
    assert.equal(event.timestamp, FIXED_NOW);
    assert.deepEqual(event.metadata, { probe: 'blocked' });

    const evidence = mapEvidenceRow({
      id: EVIDENCE_ID,
      tenant_id: CTX.tenantId,
      metadata_json: null,
      created_at: FIXED_NOW,
    });
    assert.deepEqual(evidence.metadata, {});

    const verdict = mapVerdictRow({
      id: VERDICT_ID,
      tenant_id: CTX.tenantId,
      test_run_id: RUN_ID,
      verdict: 'pass',
      evidence_ids: null,
      placement_confidence_json: { level: 'High', status: 'observed_this_run' },
      created_at: FIXED_NOW,
    });
    assert.deepEqual(verdict.evidence_ids, []);
    assert.deepEqual(verdict.placement_confidence, {
      level: 'High',
      status: 'observed_this_run',
    });

    const finding = mapFindingRow({
      id: FINDING_ID,
      tenant_id: CTX.tenantId,
      title: 'T',
      severity: 'high',
      status: 'open',
      evidence_ids: ['ev_1'],
      created_at: FIXED_NOW,
      updated_at: null,
    });
    assert.deepEqual(finding.evidence_ids, ['ev_1']);
    assert.equal(finding.updated_at, null);
  });

  it('listTestRuns and getTestRun use tenant context and predicates', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM test_runs')) {
        return { rows: [testRunRow] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const items = await repo.listTestRuns(CTX);
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const listQ = dataQueries(pool.client)[0];
    assertUsesTenantPredicate(listQ.text, listQ.params, CTX.tenantId);

    pool.client.queries.length = 0;
    pool.client.released = false;
    const run = await repo.getTestRun(CTX, RUN_ID);
    assert.equal(run.id, RUN_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const getQ = dataQueries(pool.client)[0];
    assert.match(getQ.text, /WHERE tenant_id = \$1 AND id = \$2/);
    assert.deepEqual(getQ.params, [CTX.tenantId, RUN_ID]);
  });

  it('createTestRun inserts tenant_id column with parameterized values', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO test_runs')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, RUN_ID);
        return { rows: [testRunRow] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const row = await repo.createTestRun(CTX, {
      id: RUN_ID,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'chk_1',
      status: 'running',
      created_at: FIXED_NOW,
    });
    assert.equal(row.id, RUN_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('updateTestRun patches runtime fields with tenant-scoped UPDATE', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE test_runs')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.match(text, /status = \$1/);
        assert.match(text, /correlation_json = \$2::jsonb/);
        assertNoInterpolatedValue(text, 'verdicted');
        return {
          rows: [
            {
              ...testRunRow,
              status: 'verdicted',
              correlation_json: { nonce_hash: 'x', window_ms: 1 },
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const row = await repo.updateTestRun(CTX, RUN_ID, {
      status: 'verdicted',
      correlation: { nonce_hash: 'x', window_ms: 1 },
    });
    assert.equal(row.status, 'verdicted');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('cancelTestRunAtomic transitions the run and open probe jobs in one tenant transaction', async () => {
    const pool = createRecordingPool((text) => {
      if (/FROM test_runs[\s\S]*FOR UPDATE/i.test(text)) return { rows: [testRunRow] };
      if (/UPDATE test_runs/i.test(text)) {
        return { rows: [{ ...testRunRow, status: 'cancelled', completed_at: FIXED_NOW }] };
      }
      if (/UPDATE probe_jobs/i.test(text)) {
        return { rows: [
          { id: 'pjob_pending', test_run_id: RUN_ID },
          { id: 'pjob_leased', test_run_id: RUN_ID },
        ] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const result = await repo.cancelTestRunAtomic(CTX, RUN_ID, { completed_at: FIXED_NOW });

    assert.equal(result.cancelled, true);
    assert.equal(result.run.status, 'cancelled');
    assert.deepEqual(result.cancelled_jobs.map((job) => job.id), [
      'pjob_pending',
      'pjob_leased',
    ]);
    const queries = dataQueries(pool.client);
    assert.match(queries[0].text, /pg_advisory_xact_lock/);
    assert.match(queries[1].text, /FOR UPDATE/);
    assert.match(queries[3].text, /status IN \('pending', 'leased'\)/);
    assert.match(queries[3].text, /ownership_verification_id IS NULL/);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('findEventByTenantEventId uses tenant_id and event_id only', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM events')) {
        return {
          rows: [
            {
              id: 'event_1',
              tenant_id: CTX.tenantId,
              event_id: EVENT_EXT_ID,
              timestamp: FIXED_NOW,
              metadata_json: {},
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const event = await repo.findEventByTenantEventId(CTX, EVENT_EXT_ID);
    assert.equal(event.event_id, EVENT_EXT_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /WHERE tenant_id = \$1 AND event_id = \$2/);
    assert.deepEqual(q.params, [CTX.tenantId, EVENT_EXT_ID]);
    assert.doesNotMatch(q.text, /event_id = \$1 AND tenant_id = \$2/);
  });

  it('appendEvent and listRunEvents scope events by tenant and run', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO events')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return {
          rows: [
            {
              id: 'event_1',
              tenant_id: CTX.tenantId,
              event_id: EVENT_EXT_ID,
              test_run_id: RUN_ID,
              timestamp: FIXED_NOW,
              metadata_json: {},
            },
          ],
        };
      }
      if (text.includes('FROM events') && text.includes('test_run_id')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.appendEvent(CTX, {
      id: 'event_1',
      event_id: EVENT_EXT_ID,
      test_run_id: RUN_ID,
      timestamp: FIXED_NOW,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);

    pool.client.queries.length = 0;
    pool.client.released = false;
    await repo.listRunEvents(CTX, RUN_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /tenant_id = \$1 AND test_run_id = \$2/);
    assert.match(q.text, /ORDER BY timestamp/);
    assert.match(q.text, /LIMIT \$\d+/);
    assert.deepEqual(q.params, [CTX.tenantId, RUN_ID, 200]);
  });

  it('loads 500 runs with two parameterized data queries on one tenant transaction', async () => {
    const runIds = Array.from({ length: 500 }, (_, index) => `run_batch_${index}`);
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('JOIN LATERAL')) {
        assert.deepEqual(params, [CTX.tenantId, runIds]);
        return {
          rows: [{
            id: 'verdict_batch_499',
            tenant_id: CTX.tenantId,
            test_run_id: runIds[499],
            verdict: 'protected',
            evidence_ids: ['event_batch_499'],
            created_at: FIXED_NOW,
          }],
        };
      }
      if (sql.includes('ROW_NUMBER() OVER')) {
        assert.deepEqual(params, [CTX.tenantId, [runIds[0], runIds[499]], 1000]);
        return {
          rows: [{
            id: 'event_batch_499',
            tenant_id: CTX.tenantId,
            test_run_id: runIds[499],
            signal_type: 'probe_result',
            producer_kind: 'signed_probe',
            timestamp: FIXED_NOW,
            metadata_json: {},
          }],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);

    const result = await repo.loadRunEvidenceBatch(CTX, {
      runIds,
      eventRunIds: [runIds[0]],
      eventLimitPerRun: 50_000,
    });

    assert.equal(result.verdicts.length, 1);
    assert.equal(result.events.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const queries = dataQueries(pool.client);
    assert.equal(queries.length, 2, '500 runs must remain O(1) SQL calls');
    assert.match(queries[0].text, /unnest\(\$2::text\[\]\) WITH ORDINALITY/);
    assert.match(queries[0].text, /ORDER BY created_at DESC, id DESC\s+LIMIT 1/);
    assert.match(queries[0].text, /ORDER BY selected\.ordinal\s*$/);
    assert.match(queries[1].text, /PARTITION BY events\.test_run_id\s+ORDER BY events\.timestamp/);
    assert.match(queries[1].text, /WHERE per_run_position <= \$3/);
    assert.ok(queries.every(({ text: sql }) => !sql.includes(runIds[499])));
  });

  it('rejects oversized run batches before opening a transaction', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createValidationEvidenceRepository(pool);

    await assert.rejects(
      () => repo.loadRunEvidenceBatch(CTX, {
        runIds: Array.from({ length: 501 }, (_, index) => `run_${index}`),
      }),
      /at most 500 run ids/,
    );
    assert.equal(pool.client.queries.length, 0);
  });

  it('appendEvidence and getEvidence use tenant-scoped vault access', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO evidence_vault')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return {
          rows: [
            {
              id: EVIDENCE_ID,
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              metadata_json: { label: 'x' },
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.includes('FROM evidence_vault') && text.includes('AND id')) {
        return {
          rows: [
            {
              id: EVIDENCE_ID,
              tenant_id: CTX.tenantId,
              metadata_json: {},
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.appendEvidence(CTX, {
      id: EVIDENCE_ID,
      test_run_id: RUN_ID,
      created_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);

    pool.client.queries.length = 0;
    pool.client.released = false;
    await repo.getEvidence(CTX, EVIDENCE_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /WHERE tenant_id = \$1 AND id = \$2/);
  });

  it('derives edge provenance from the authoritative run and cannot retarget on conflict', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (!sql.startsWith('INSERT INTO target_edge_detections')) return { rows: [] };
      assert.match(sql, /FROM test_runs authoritative_run/);
      assert.match(
        sql,
        /JOIN targets authoritative_target[\s\S]*authoritative_target\.target_group_id = authoritative_run\.target_group_id[\s\S]*authoritative_target\.id = authoritative_run\.target_id/,
      );
      assert.match(sql, /authoritative_run\.id = \$5/);
      assert.match(sql, /authoritative_run\.target_group_id = \$3/);
      assert.match(sql, /authoritative_run\.target_id = \$4/);
      const conflictUpdate = sql.match(
        /ON CONFLICT \(tenant_id, target_id\) DO UPDATE SET([\s\S]*?)WHERE target_edge_detections/,
      )?.[1] ?? '';
      assert.match(conflictUpdate, /test_run_id = EXCLUDED\.test_run_id/);
      assert.doesNotMatch(
        conflictUpdate,
        /^\s*(?:id|tenant_id|target_group_id|target_id)\s*=/m,
        'conflict refresh must not rewrite identity provenance',
      );
      assert.match(
        sql,
        /WHERE target_edge_detections\.target_group_id = EXCLUDED\.target_group_id\s+AND target_edge_detections\.target_id = EXCLUDED\.target_id\s+RETURNING/,
      );
      assert.deepEqual(params.slice(0, 5), [
        'edge_1',
        CTX.tenantId,
        'tg_1',
        'tgt_1',
        RUN_ID,
      ]);
      return {
        rows: [{
          id: 'edge_1',
          target_id: 'tgt_1',
          target_group_id: 'tg_1',
          status: 'detected',
          updated_at: FIXED_NOW,
        }],
      };
    });
    const repo = createValidationEvidenceRepository(pool);

    const result = await repo.upsertTargetEdgeDetection(CTX, {
      id: 'edge_1',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      test_run_id: RUN_ID,
      status: 'detected',
      evidence_json: {},
      observed_at: FIXED_NOW,
    }, { client: pool.client });

    assert.equal(result.id, 'edge_1');
    assert.equal(pool.client.queries.length, 1, 'caller transaction client must be reused');
    assert.equal(pool.client.released, false);
  });

  it('appendEvidence can idempotently reuse evidence for the same related event', async () => {
    const relatedEventId = 'event_probe_1';
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM evidence_vault') && text.includes('related_event_id = $4')) {
        assert.deepEqual(params, [
          CTX.tenantId,
          RUN_ID,
          'probe_worker_evidence',
          relatedEventId,
        ]);
        return {
          rows: [{
            id: EVIDENCE_ID,
            tenant_id: CTX.tenantId,
            test_run_id: RUN_ID,
            label: 'probe_worker_evidence',
            metadata_json: { external_result: 'blocked' },
            related_event_id: relatedEventId,
            created_at: FIXED_NOW,
          }],
        };
      }
      if (text.startsWith('INSERT INTO evidence_vault')) {
        throw new Error('idempotent replay must not insert evidence');
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);

    const result = await repo.appendEvidence(
      CTX,
      {
        id: 'evidence_replay',
        test_run_id: RUN_ID,
        label: 'probe_worker_evidence',
        related_event_id: relatedEventId,
        created_at: FIXED_NOW,
      },
      { idempotentByRelatedEvent: true },
    );

    assert.equal(result.id, EVIDENCE_ID);
    assert.deepEqual(result.metadata, { external_result: 'blocked' });
    assert.ok(
      pool.client.queries.some(({ text }) => text.includes('hashtextextended($1, 0)')),
    );
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createVerdict and getVerdictForRun are tenant-scoped', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO verdicts')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return {
          rows: [
            {
              id: VERDICT_ID,
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              verdict: 'pass',
              evidence_ids: [],
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.includes('FROM verdicts')) {
        return {
          rows: [
            {
              id: VERDICT_ID,
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              verdict: 'pass',
              evidence_ids: ['event_1'],
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.createVerdict(CTX, {
      id: VERDICT_ID,
      test_run_id: RUN_ID,
      verdict: 'pass',
      created_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);

    pool.client.queries.length = 0;
    pool.client.released = false;
    const verdict = await repo.getVerdictForRun(CTX, RUN_ID);
    assert.equal(verdict.verdict, 'pass');
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /WHERE tenant_id = \$1 AND test_run_id = \$2/);
  });

  it('findOpenFinding filters by tenant, target tuple, and open status', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM findings')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.findOpenFinding(CTX, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'chk_1',
    });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /tenant_id = \$1/);
    assert.match(q.text, /target_group_id = \$2/);
    assert.match(q.text, /target_id = \$3/);
    assert.match(q.text, /check_id = \$4/);
    assert.match(q.text, /status = 'open'/);
    assert.deepEqual(q.params, [CTX.tenantId, 'tg_1', 'tgt_1', 'chk_1']);
  });

  it('patchFinding updates only allowed fields with placeholders', async () => {
    const sensitiveNote = 'do-not-interpolate-me';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE findings')) {
        assert.match(text, /status = \$1/);
        assert.match(text, /notes = \$2/);
        assert.match(text, /last_verdict_id = \$3/);
        assert.match(text, /evidence_ids = \$4/);
        assert.match(text, /updated_at = \$5::timestamptz/);
        assertNoInterpolatedValue(text, sensitiveNote);
        assertNoInterpolatedValue(text, 'resolved');
        assertNoInterpolatedValue(text, VERDICT_ID);
        assert.doesNotMatch(text, /SET status = resolved/);
        return {
          rows: [
            {
              id: FINDING_ID,
              tenant_id: CTX.tenantId,
              title: 'F',
              severity: 'medium',
              status: 'resolved',
              evidence_ids: ['ev_2'],
              notes: sensitiveNote,
              last_verdict_id: VERDICT_ID,
              created_at: FIXED_NOW,
              updated_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const row = await repo.patchFinding(CTX, FINDING_ID, {
      status: 'resolved',
      notes: sensitiveNote,
      last_verdict_id: VERDICT_ID,
      evidence_ids: ['ev_2'],
      updated_at: FIXED_NOW,
    });
    assert.equal(row.status, 'resolved');
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.ok(q.params.includes(sensitiveNote));
    assert.ok(q.params.includes('resolved'));
  });

  it('createFinding and listFindings use tenant context', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO findings')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return {
          rows: [
            {
              id: FINDING_ID,
              tenant_id: CTX.tenantId,
              title: 'Finding',
              severity: 'low',
              status: 'open',
              evidence_ids: [],
              created_at: FIXED_NOW,
              updated_at: null,
            },
          ],
        };
      }
      if (text.includes('FROM findings') && text.includes('ORDER BY')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.createFinding(CTX, {
      id: FINDING_ID,
      title: 'Finding',
      severity: 'low',
      created_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);

    pool.client.queries.length = 0;
    pool.client.released = false;
    await repo.listFindings(CTX);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
  });

  it('countOpenFindings uses a tenant-scoped aggregate without materializing rows', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('COUNT(*)::int AS open_count')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return { rows: [{ open_count: 33_334 }] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);

    const count = await repo.countOpenFindings(CTX);

    assert.equal(count, 33_334);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [query] = dataQueries(pool.client);
    assert.match(query.text, /COUNT\(\*\)::int AS open_count/);
    assert.match(query.text, /WHERE tenant_id = \$1 AND status = 'open'/);
    assert.doesNotMatch(query.text, /ORDER BY|LIMIT/);
    assert.deepEqual(query.params, [CTX.tenantId]);
  });

  it('listFindings applies test_run_id, target, and bounded limit filters', async () => {
    let captured;
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM findings') && text.includes('ORDER BY')) {
        captured = { text, params };
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.listFindings(CTX, {
      test_run_id: 'run_1',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      limit: 25,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.match(captured.text, /test_run_id = \$\d+/);
    assert.match(captured.text, /target_group_id = \$\d+/);
    assert.match(captured.text, /target_id = \$\d+/);
    assert.match(captured.text, /LIMIT \$\d+/);
    assert.ok(captured.params.includes('run_1'));
    assert.ok(captured.params.includes('tg_1'));
    assert.ok(captured.params.includes('tgt_1'));
    assert.ok(captured.params.includes(25));
  });

  it('listFindings locks all statuses for a full tuple on the provided transaction client', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM findings')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);

    await repo.listFindings(CTX, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'chk_1',
      forUpdate: true,
      client: pool.client,
    });

    assert.equal(pool.client.queries.length, 1, 'provided client must not open a nested transaction');
    assert.equal(pool.client.released, false);
    const [query] = pool.client.queries;
    assert.match(query.text, /target_group_id = \$2/);
    assert.match(query.text, /target_id = \$3/);
    assert.match(query.text, /check_id = \$4/);
    assert.match(query.text, /ORDER BY created_at DESC, id DESC FOR UPDATE\s*$/);
    assert.doesNotMatch(query.text, /status = 'open'/);
    assert.deepEqual(query.params, [CTX.tenantId, 'tg_1', 'tgt_1', 'chk_1']);
  });

  it('listTestRuns applies bounded LIMIT and optional filters with parameterized tenant', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM test_runs')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.listTestRuns(CTX, {
      targetGroupId: 'tg_1',
      statuses: ['running', 'verdicted'],
      beforeCreatedAt: FIXED_NOW,
      limit: 9999,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /tenant_id = \$1/);
    assert.match(q.text, /target_group_id = \$2/);
    assert.match(q.text, /status = ANY\(\$3\)/);
    assert.match(q.text, /created_at < \$4::timestamptz/);
    assert.match(q.text, /ORDER BY COALESCE\(started_at, created_at\) DESC, id DESC/);
    assert.match(q.text, /LIMIT \$5/);
    assert.deepEqual(q.params, [CTX.tenantId, 'tg_1', ['running', 'verdicted'], FIXED_NOW, 500]);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
  });

  it('listRunEvents applies signal type, before timestamp, and bounded LIMIT', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM events')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.listRunEvents(CTX, RUN_ID, {
      signalType: 'probe_result',
      beforeTimestamp: FIXED_NOW,
      limit: 50,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /tenant_id = \$1/);
    assert.match(q.text, /test_run_id = \$2/);
    assert.match(q.text, /signal_type = \$3/);
    assert.match(q.text, /timestamp < \$4::timestamptz/);
    assert.match(q.text, /LIMIT \$5/);
    assert.deepEqual(q.params, [CTX.tenantId, RUN_ID, 'probe_result', FIXED_NOW, 50]);
  });

  it('listEvidenceForRun scopes by tenant and run with ORDER BY and LIMIT', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM evidence_vault')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.listEvidenceForRun(CTX, RUN_ID, { limit: 25 });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /tenant_id = \$1/);
    assert.match(q.text, /test_run_id = \$2/);
    assert.match(q.text, /ORDER BY created_at DESC/);
    assert.match(q.text, /LIMIT \$3/);
    assert.deepEqual(q.params, [CTX.tenantId, RUN_ID, 25]);
  });

  it('appendEventIdempotent rejects missing event_id', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createValidationEvidenceRepository(pool);
    await assert.rejects(
      () =>
        repo.appendEventIdempotent(CTX, {
          id: 'event_1',
          test_run_id: RUN_ID,
          timestamp: FIXED_NOW,
        }),
      /requires record\.event_id/,
    );
    assert.equal(pool.client.queries.length, 0);
  });

  it('appendEventIdempotent uses partial conflict target and parameterized values', async () => {
    const sensitiveMeta = 'secret-probe-token';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO events')) {
        assert.match(
          text,
          /ON CONFLICT \(tenant_id, event_id\) WHERE event_id IS NOT NULL/,
        );
        assert.match(text, /DO UPDATE SET/);
        assertNoInterpolatedValue(text, sensitiveMeta);
        assertNoInterpolatedValue(text, EVENT_EXT_ID);
        assert.ok(params.includes(EVENT_EXT_ID));
        assert.ok(
          params.some(
            (p) => typeof p === 'string' && p.includes(sensitiveMeta),
          ),
          'metadata must be passed as a parameterized JSON value',
        );
        return {
          rows: [
            {
              id: 'event_1',
              tenant_id: CTX.tenantId,
              event_id: EVENT_EXT_ID,
              test_run_id: RUN_ID,
              timestamp: FIXED_NOW,
              metadata_json: { token: sensitiveMeta },
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const event = await repo.appendEventIdempotent(CTX, {
      id: 'event_1',
      event_id: EVENT_EXT_ID,
      test_run_id: RUN_ID,
      timestamp: FIXED_NOW,
      metadata: { token: sensitiveMeta },
    });
    assert.equal(event.event_id, EVENT_EXT_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('appendProbeResultEventIdempotent validates required fields and signal_type', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createValidationEvidenceRepository(pool);
    const base = {
      id: 'event_probe',
      timestamp: FIXED_NOW,
      nonce_hash: 'nh_1',
    };

    await assert.rejects(
      () => repo.appendProbeResultEventIdempotent(CTX, { ...base, test_run_id: RUN_ID, nonce_hash: '' }),
      /nonce_hash/,
    );
    await assert.rejects(
      () => repo.appendProbeResultEventIdempotent(CTX, { ...base, test_run_id: '', nonce_hash: 'nh_1' }),
      /test_run_id/,
    );
    await assert.rejects(
      () =>
        repo.appendProbeResultEventIdempotent(CTX, {
          ...base,
          test_run_id: RUN_ID,
          signal_type: 'health_ping',
        }),
      /probe_result/,
    );
    assert.equal(pool.client.queries.length, 0);
  });

  it('appendProbeResultEventIdempotent uses probe-result partial conflict and DO UPDATE', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO events')) {
        assert.match(
          text,
          /ON CONFLICT \(tenant_id, test_run_id, signal_type, nonce_hash\)\s+WHERE signal_type = 'probe_result' AND nonce_hash IS NOT NULL/,
        );
        assert.match(text, /DO UPDATE SET/);
        assert.match(text, /event_id = COALESCE\(EXCLUDED\.event_id, events\.event_id\)/);
        assert.match(
          text,
          /WHERE events\.target_id IS NOT DISTINCT FROM EXCLUDED\.target_id[\s\S]*events\.check_id IS NOT DISTINCT FROM EXCLUDED\.check_id/,
        );
        assert.match(
          text,
          /events\.metadata_json->>'probe_job_id' IS NULL[\s\S]*events\.metadata_json->>'probe_job_id'[\s\S]*= EXCLUDED\.metadata_json->>'probe_job_id'/,
        );
        assert.ok(params.includes('probe_result'));
        assert.ok(params.includes('nh_probe'));
        return {
          rows: [
            {
              id: 'event_probe',
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              signal_type: 'probe_result',
              nonce_hash: 'nh_probe',
              timestamp: FIXED_NOW,
              metadata_json: {},
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const event = await repo.appendProbeResultEventIdempotent(CTX, {
      id: 'event_probe',
      test_run_id: RUN_ID,
      nonce_hash: 'nh_probe',
      timestamp: FIXED_NOW,
    });
    assert.equal(event.signal_type, 'probe_result');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createVerdict persists placement_confidence as parameterized JSONB', async () => {
    const placement = { level: 'High', observation_mode: 'canary', status: 'observed_this_run' };
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO verdicts') && !text.includes('ON CONFLICT')) {
        assert.match(text, /placement_confidence_json/);
        assert.match(text, /\$10::jsonb/);
        assertNoInterpolatedValue(text, 'canary');
        const jsonParam = params[9];
        assert.equal(typeof jsonParam, 'string');
        assert.deepEqual(JSON.parse(jsonParam), placement);
        return {
          rows: [
            {
              id: VERDICT_ID,
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              verdict: 'pass',
              evidence_ids: [],
              placement_confidence_json: placement,
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const verdict = await repo.createVerdict(CTX, {
      id: VERDICT_ID,
      test_run_id: RUN_ID,
      verdict: 'pass',
      placement_confidence: placement,
      created_at: FIXED_NOW,
    });
    assert.deepEqual(verdict.placement_confidence, placement);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createVerdictIfAbsent preserves an existing verdict and parameterizes evidence_ids', async () => {
    const evidenceIds = ['ev_a', 'ev_b'];
    const pool = createRecordingPool((text, params) => {
      if (/SELECT status[\s\S]*FROM test_runs/i.test(text)) {
        return { rows: [{ status: 'running' }] };
      }
      if (text.startsWith('INSERT INTO verdicts')) {
        assert.match(text, /ON CONFLICT \(test_run_id\)/);
        // A published verdict is immutable: the conflict path must never rewrite it.
        assert.match(text, /DO NOTHING/);
        assert.doesNotMatch(text, /DO UPDATE/);
        assert.match(text, /\$10::jsonb/);
        assertNoInterpolatedValue(text, evidenceIds[0]);
        assert.deepEqual(params[8], evidenceIds);
        assert.equal(params[9], '{}');
        return {
          rows: [
            {
              id: VERDICT_ID,
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              verdict: 'fail',
              evidence_ids: evidenceIds,
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const verdict = await repo.createVerdictIfAbsent(CTX, {
      id: VERDICT_ID,
      test_run_id: RUN_ID,
      verdict: 'fail',
      evidence_ids: evidenceIds,
      created_at: FIXED_NOW,
    });
    assert.equal(verdict.verdict, 'fail');
    assert.deepEqual(verdict.evidence_ids, evidenceIds);
    const verdictQueries = dataQueries(pool.client);
    assert.match(verdictQueries[0].text, /pg_advisory_xact_lock/);
    assert.deepEqual(verdictQueries[0].params, [`test_run_mutation:${RUN_ID}`]);
    assert.match(verdictQueries[1].text, /pg_advisory_xact_lock/);
    assert.deepEqual(verdictQueries[1].params, [`kill_switch_state:${CTX.tenantId}`]);
    assert.match(verdictQueries[2].text, /FROM soc_kill_switch/);
    assert.match(verdictQueries[2].text, /tenant_id = \$1/);
    assert.deepEqual(verdictQueries[2].params, [CTX.tenantId]);
    assert.match(verdictQueries[3].text, /FROM test_runs[\s\S]*FOR UPDATE/);
    assert.match(verdictQueries[3].text, /tenant_id = \$1 AND id = \$2/);
    assert.deepEqual(verdictQueries[3].params, [CTX.tenantId, RUN_ID]);
    assert.match(verdictQueries.at(-1).text, /UPDATE test_runs/);
    assert.match(verdictQueries.at(-1).text, /status = 'verdicted'/);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createVerdictIfAbsent rejects a canceled run before inserting evidence', async () => {
    const pool = createRecordingPool((text) => {
      if (/SELECT status[\s\S]*FROM test_runs/i.test(text)) {
        return { rows: [{ status: 'cancelled' }] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const verdict = await repo.createVerdictIfAbsent(CTX, {
      id: 'verdict_cancelled',
      test_run_id: RUN_ID,
      verdict: 'protected',
      evidence_ids: ['event_1'],
      created_at: FIXED_NOW,
    });

    assert.equal(verdict, null);
    const guardQueries = dataQueries(pool.client);
    assert.match(guardQueries[0].text, /pg_advisory_xact_lock/);
    assert.deepEqual(guardQueries[0].params, [`test_run_mutation:${RUN_ID}`]);
    assert.match(guardQueries[1].text, /pg_advisory_xact_lock/);
    assert.deepEqual(guardQueries[1].params, [`kill_switch_state:${CTX.tenantId}`]);
    assert.match(guardQueries[2].text, /FROM soc_kill_switch/);
    assert.match(guardQueries[2].text, /tenant_id = \$1/);
    assert.deepEqual(guardQueries[2].params, [CTX.tenantId]);
    assert.match(guardQueries[3].text, /FROM test_runs[\s\S]*FOR UPDATE/);
    assert.deepEqual(guardQueries[3].params, [CTX.tenantId, RUN_ID]);
    assert.equal(guardQueries.length, 4);
    assert.equal(
      guardQueries.some((query) => /INSERT INTO verdicts/i.test(query.text)),
      false,
    );
  });

  it('upsertOpenFindingFromVerdict atomically enforces durable tuple and strict chronology', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO findings')) {
        assert.match(text, /FROM verdicts incoming/);
        assert.match(text, /incoming\.tenant_id = \$2/);
        assert.match(text, /incoming\.id = \$14/);
        assert.match(text, /incoming\.test_run_id = \$5/);
        assert.match(text, /incoming\.target_id IS NOT DISTINCT FROM \$4/);
        assert.match(text, /incoming\.check_id IS NOT DISTINCT FROM \$6/);
        assert.match(text, /NOT EXISTS \([\s\S]*FROM findings prior/);
        assert.match(text, /prior\.verdict_id = \$14[\s\S]*prior\.last_verdict_id = \$14/);
        assert.match(text, /prior_verdict\.created_at > incoming\.created_at/);
        assert.match(text, /prior_verdict\.created_at = incoming\.created_at[\s\S]*prior_verdict\.id >= incoming\.id/);
        assert.match(
          text,
          /ON CONFLICT \(tenant_id, target_group_id, target_id, check_id\) WHERE status = 'open'/,
        );
        assert.match(text, /last_verdict_id = EXCLUDED\.last_verdict_id/);
        assert.match(text, /DO UPDATE SET/);
        assert.match(text, /WHERE EXISTS \([\s\S]*FROM verdicts incoming[\s\S]*LEFT JOIN verdicts incumbent/);
        assert.match(text, /incoming\.created_at > incumbent\.created_at/);
        assert.match(text, /incoming\.created_at = incumbent\.created_at[\s\S]*incoming\.id > incumbent\.id/);
        assert.equal(params[8], 'open');
        assert.ok(params.includes(VERDICT_ID));
        return {
          rows: [
            {
              id: FINDING_ID,
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: 'tgt_1',
              check_id: 'chk_1',
              title: 'Open issue',
              severity: 'high',
              status: 'open',
              evidence_ids: ['ev_1'],
              last_verdict_id: VERDICT_ID,
              created_at: FIXED_NOW,
              updated_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const finding = await repo.upsertOpenFindingFromVerdict(CTX, {
      id: FINDING_ID,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'chk_1',
      title: 'Open issue',
      severity: 'high',
      last_verdict_id: VERDICT_ID,
      evidence_ids: ['ev_1'],
      created_at: FIXED_NOW,
    });
    assert.equal(finding.last_verdict_id, VERDICT_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('returns null without a nested transaction when chronology blocks finding publication', async () => {
    const pool = createRecordingPool((text) => {
      if (text.startsWith('INSERT INTO findings')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);

    const finding = await repo.upsertOpenFindingFromVerdict(CTX, {
      id: FINDING_ID,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      test_run_id: RUN_ID,
      check_id: 'chk_1',
      title: 'Older publication',
      severity: 'high',
      verdict_id: VERDICT_ID,
      last_verdict_id: VERDICT_ID,
      evidence_ids: ['ev_1'],
      created_at: FIXED_NOW,
    }, { client: pool.client });

    assert.equal(finding, null);
    assert.equal(pool.client.queries.length, 1);
    assert.equal(pool.client.released, false);
  });

  it('upsertOpenFindingFromVerdict rejects non-open status before any DB access', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createValidationEvidenceRepository(pool);

    await assert.rejects(
      () =>
        repo.upsertOpenFindingFromVerdict(CTX, {
          id: FINDING_ID,
          target_group_id: 'tg_1',
          target_id: 'tgt_1',
          check_id: 'chk_1',
          title: 'Closed issue',
          severity: 'high',
          status: 'resolved',
          created_at: FIXED_NOW,
        }),
      /only accepts open findings/,
    );
    assert.equal(pool.client.queries.length, 0);
  });
});


describe('postgres validation finalization transaction ownership', () => {
  it('requires the audit transaction client and never performs a second checkout', async () => {
    let checkouts = 0;
    const queries = [];
    const transactionClient = {
      async query(text, params) {
        queries.push({ text, params });
        return { rows: [] };
      },
    };
    const pool = {
      async connect() {
        checkouts += 1;
        throw new Error('finalization attempted a second checkout');
      },
    };
    const repo = createValidationEvidenceRepository(pool);
    let callbackClient;

    const result = await repo.withRunFinalizationLock(
      CTX,
      RUN_ID,
      async (client) => {
        callbackClient = client;
        return 'done';
      },
      { client: transactionClient },
    );

    assert.deepEqual(result, { acquired: true, result: 'done' });
    assert.equal(callbackClient, transactionClient);
    assert.equal(checkouts, 0);
    assert.equal(queries.length, 2);
    assert.match(queries[0].text, /pg_advisory_xact_lock/);
    assert.deepEqual(queries[0].params, [`test_run_mutation:${RUN_ID}`]);
    assert.match(queries[1].text, /pg_advisory_xact_lock/);
    assert.deepEqual(queries[1].params, [`kill_switch_state:${CTX.tenantId}`]);

    await assert.rejects(
      () => repo.withRunFinalizationLock(CTX, RUN_ID, async () => null),
      /requires the tenant audit transaction client/,
    );
    assert.equal(checkouts, 0, 'missing-client failure must not silently fall back to the pool');
  });
});
