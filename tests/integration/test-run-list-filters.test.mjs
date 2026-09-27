import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { getStore } from '../../src/store.mjs';
import { listTestRuns, listTestRunsEnvelope } from '../../src/services/testRuns.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

function seedRun(id, fields) {
  getStore().testRuns.push({
    id, tenant_id: 'ten_demo', target_group_id: 'tg_1', target_id: 'tgt_1', check_id: 'origin.leak_scan.safe',
    status: 'verdicted', created_at: '2026-01-01T00:00:00.000Z', ...fields,
  });
}

describe('dev-json test-run list filters', () => {
  afterEach(() => freshStore());

  it('filters by check_id / target_id and attaches the published verdict', () => {
    freshStore();
    seedRun('run_f1', { created_at: '2026-01-01T00:00:01.000Z' });
    seedRun('run_f2', { check_id: 'waf.fingerprint.safe', target_id: 'tgt_2', created_at: '2026-01-01T00:00:02.000Z' });
    getStore().verdicts.push({ id: 'vrd_f1', tenant_id: 'ten_demo', test_run_id: 'run_f1', verdict: 'edge_protected', evidence_ids: ['evt_1'] });

    const byCheck = listTestRuns(ctx, { check_id: 'origin.leak_scan.safe' });
    assert.ok(byCheck.every((run) => run.check_id === 'origin.leak_scan.safe'));
    assert.equal(byCheck.find((run) => run.id === 'run_f1').verdict.verdict, 'edge_protected');
    assert.ok(listTestRuns(ctx, { target_id: 'tgt_2' }).every((run) => run.target_id === 'tgt_2'));
    const empty = listTestRunsEnvelope(ctx, { check_id: 'no.such.check' });
    assert.equal(empty.count, 0);
    assert.equal(empty.meta.empty_reason, 'No test runs have been recorded for this check yet.');
  });
});
