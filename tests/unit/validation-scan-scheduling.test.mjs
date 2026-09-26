import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  cancelValidationScan,
  createValidationScan,
  dispatchDueValidationScans,
  getValidationScan,
  listDueValidationScans,
  listValidationScans,
  patchValidationScan,
} from '../../src/services/validationScans.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_engineer', role: 'engineer' };
const RUNTIME = { probeMode: 'simulation' };
const NOW = new Date('2026-06-01T12:00:00.000Z');
const SCHEDULED_FOR = '2026-06-01T13:00:00.000Z';

function scheduledScan(extra = {}) {
  return createValidationScan(CTX, {
    target_group_id: 'tg_1',
    target_id: 'tgt_1',
    check_ids: ['dns.authoritative_response.safe', 'origin.leak_scan.safe'],
    scheduled_for: SCHEDULED_FOR,
    ...extra,
  }, RUNTIME, { now: NOW });
}

function actions() {
  return getStore().auditLog.map((entry) => entry.action);
}

describe('validation scan scheduling (dev-json)', () => {
  beforeEach(() => freshStore());

  it('creates a scheduled scan without starting any run and dispatches it only when due', () => {
    const scan = scheduledScan();
    assert.equal(scan.status, 'scheduled');
    assert.equal(scan.scheduled_for, SCHEDULED_FOR);
    assert.equal(getStore().testRuns.length, 0);
    assert.equal(actions().at(-1), 'validation_scan.scheduled');

    assert.equal(listDueValidationScans(CTX, { now: NOW }).length, 0);
    assert.deepEqual(dispatchDueValidationScans(CTX, { now: NOW, runtimeConfig: RUNTIME }), []);

    const due = new Date('2026-06-01T13:00:01.000Z');
    assert.equal(listDueValidationScans(CTX, { now: due }).length, 1);
    const results = dispatchDueValidationScans(CTX, { now: due, runtimeConfig: RUNTIME, workerId: 'runner-test' });
    assert.equal(results.length, 1);
    assert.equal(results[0].dispatched, true);
    const running = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME, now: due });
    assert.equal(running.status, 'running');
    assert.equal(running.dispatched_at, due.toISOString());
    assert.equal(running.steps[0].status, 'collecting');
    assert.equal(getStore().testRuns.length, 1);
    assert.equal(getStore().testRuns[0].scan_id, scan.id);
    assert.ok(actions().includes('validation_scan.dispatched'));
    assert.deepEqual(dispatchDueValidationScans(CTX, { now: due, runtimeConfig: RUNTIME }), []);
  });

  it('denies a due scan that lands outside the safe test window, audits it, and never force-runs it', () => {
    const scan = scheduledScan();
    getStore().targetGroups[0].safe_test_windows = [
      { start_at: '2026-06-01T02:00:00.000Z', end_at: '2026-06-01T04:00:00.000Z' },
    ];
    const due = new Date('2026-06-01T13:00:01.000Z');
    const [result] = dispatchDueValidationScans(CTX, { now: due, runtimeConfig: RUNTIME });
    assert.equal(result.dispatched, false);
    assert.equal(result.denied, 'safe_window_closed');
    const denied = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME, now: due });
    assert.equal(denied.status, 'denied');
    assert.equal(denied.abort_reason, 'safe_window_closed');
    assert.deepEqual(denied.steps.map((step) => step.status), ['skipped', 'skipped']);
    assert.equal(getStore().testRuns.length, 0);
    const audit = getStore().auditLog.find((entry) => entry.action === 'validation_scan.schedule_denied');
    assert.equal(audit.metadata.code, 'safe_window_closed');
    assert.equal(audit.metadata.scheduled_for, SCHEDULED_FOR);
  });

  it('denies a due scan while the kill switch is active or another run holds the group', () => {
    const scan = scheduledScan();
    getStore().socKillSwitch = { active: true, reason: 'incident', tenant_id: null };
    const due = new Date('2026-06-01T13:00:01.000Z');
    const [killed] = dispatchDueValidationScans(CTX, { now: due, runtimeConfig: RUNTIME });
    assert.equal(killed.denied, 'kill_switch_active');
    assert.equal(getStore().testRuns.length, 0);

    getStore().socKillSwitch = { active: false };
    const other = scheduledScan({ scheduled_for: '2026-06-01T14:00:00.000Z' });
    getStore().testRuns.push({
      id: 'run_foreign',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.leak_scan.safe',
      status: 'running',
      created_at: new Date().toISOString(),
      correlation: { nonce_hash: null, window_ms: 120000 },
    });
    const [blocked] = dispatchDueValidationScans(CTX, { now: new Date('2026-06-01T14:00:01.000Z'), runtimeConfig: RUNTIME });
    assert.equal(blocked.scan_id, other.id);
    assert.equal(blocked.denied, 'concurrent_run_blocked');
    assert.notEqual(scan.id, other.id);
  });

  it('creates exactly one next occurrence for recurring scans even when dispatched twice', () => {
    const scan = scheduledScan({ recurrence: { cadence: 'daily', timezone: 'UTC' } });
    assert.equal(scan.next_occurrence_at, '2026-06-02T13:00:00.000Z');
    const due = new Date('2026-06-01T13:00:01.000Z');
    dispatchDueValidationScans(CTX, { now: due, runtimeConfig: RUNTIME });
    dispatchDueValidationScans(CTX, { now: due, runtimeConfig: RUNTIME });
    const listed = listValidationScans(CTX, { status: 'scheduled', runtimeConfig: RUNTIME, now: due });
    assert.equal(listed.count, 1);
    const next = listed.items[0];
    assert.equal(next.scheduled_for, '2026-06-02T13:00:00.000Z');
    assert.equal(next.previous_scan_id, scan.id);
    assert.equal(next.occurrence_index, 1);
    assert.equal(next.recurrence_series_id, scan.id);
    assert.deepEqual(next.check_ids, scan.check_ids);
    const first = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME, now: due });
    assert.equal(first.next_scan_id, next.id);
    assert.equal(first.status, 'running');
  });

  it('still rolls a denied recurring occurrence forward to the next occurrence', () => {
    scheduledScan({ recurrence: 'weekly' });
    getStore().targetGroups[0].safe_test_windows = [
      { start_at: '2026-06-01T02:00:00.000Z', end_at: '2026-06-01T04:00:00.000Z' },
    ];
    const due = new Date('2026-06-01T13:00:01.000Z');
    const [result] = dispatchDueValidationScans(CTX, { now: due, runtimeConfig: RUNTIME });
    assert.equal(result.denied, 'safe_window_closed');
    const scheduled = listValidationScans(CTX, { status: 'scheduled', runtimeConfig: RUNTIME, now: due });
    assert.equal(scheduled.count, 1);
    assert.equal(scheduled.items[0].scheduled_for, '2026-06-08T13:00:00.000Z');
  });

  it('allows edits only while scheduled and re-plans the steps', () => {
    const scan = scheduledScan();
    const patched = patchValidationScan(CTX, scan.id, {
      name: 'Nightly checkout',
      check_ids: ['origin.leak_scan.safe'],
      scheduled_for: '2026-06-01T15:00:00.000Z',
      recurrence: 'monthly',
    }, { now: NOW });
    assert.equal(patched.name, 'Nightly checkout');
    assert.equal(patched.summary.total, 1);
    assert.equal(patched.scheduled_for, '2026-06-01T15:00:00.000Z');
    assert.deepEqual(patched.recurrence, { cadence: 'monthly', timezone: 'UTC' });
    assert.equal(patched.revision, 2);
    const updateAudit = getStore().auditLog.find((entry) => entry.action === 'validation_scan.updated');
    assert.ok(updateAudit.metadata.changed_fields.includes('check_ids'));

    const socPatch = patchValidationScan(CTX, scan.id, { check_ids: ['waf.offensive_sqli.soc'] }, { now: NOW });
    assert.equal(socPatch.error, 'soc_gated_check');
    const pastPatch = patchValidationScan(CTX, scan.id, { scheduled_for: '2026-05-01T00:00:00.000Z' }, { now: NOW });
    assert.equal(pastPatch.error, 'invalid_validation_scan');

    dispatchDueValidationScans(CTX, { now: new Date('2026-06-01T15:00:01.000Z'), runtimeConfig: RUNTIME });
    const locked = patchValidationScan(CTX, scan.id, { name: 'too late' }, { now: NOW });
    assert.equal(locked.error, 'scan_not_editable');
    assert.equal(locked.status, 409);
  });

  it('cancels a scheduled occurrence and, on request, stops the whole series', () => {
    const scan = scheduledScan({ recurrence: 'daily' });
    const due = new Date('2026-06-01T13:00:01.000Z');
    dispatchDueValidationScans(CTX, { now: due, runtimeConfig: RUNTIME });
    const running = getValidationScan(CTX, scan.id, { runtimeConfig: RUNTIME, now: due });
    const stopped = cancelValidationScan(CTX, running.id, { reason: 'stop series', cancel_series: true, now: due });
    assert.equal(stopped.status, 'cancelled');
    assert.equal(stopped.recurrence, null);
    const next = getValidationScan(CTX, running.next_scan_id, { runtimeConfig: RUNTIME, now: due });
    assert.equal(next.status, 'cancelled');
    assert.equal(next.cancel_reason, 'stop series');
    assert.equal(listValidationScans(CTX, { status: 'scheduled', runtimeConfig: RUNTIME, now: due }).count, 0);
    assert.ok(actions().includes('validation_scan.series_stopped'));
  });
});
