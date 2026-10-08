import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG, getCheckById } from '../../src/contracts/checks.mjs';
import * as contract from '../../src/contracts/validationScanManagement.mjs';
import {
  MAX_SCAN_CHECKS,
  buildActivityItems,
  classifyStartDenial,
  computeScanSummary,
  deriveScanStatus,
  nextScanOccurrenceAt,
  normalizeScanInput,
  planScanSteps,
  projectScanStep,
  requestSnapshotForCheck,
  scanOccurrenceKey,
  scanValidationResponse,
  sectionForCheck,
  withCheckSection,
} from '../../src/contracts/validationScanManagement.mjs';

const NOW = new Date('2026-06-01T12:00:00.000Z');
const FQDN_TARGET = { id: 'tgt_fqdn', kind: 'fqdn', value: 'origin.test' };
const URL_TARGET = { id: 'tgt_url', kind: 'url', value: 'https://app.test/health' };

function normalizeOrResponse(body, options) {
  try {
    return normalizeScanInput(body, options);
  } catch (err) {
    return scanValidationResponse(err);
  }
}

describe('validation scan contract: input normalization', () => {
  it('dedupes check ids, keeps order, and defaults optional fields', () => {
    const input = normalizeScanInput(
      { target_group_id: ' tg_1 ', check_ids: ['b', 'a', 'b', ' c '], name: '  Nightly  ' },
      { now: NOW },
    );
    assert.deepEqual(input, {
      target_group_id: 'tg_1',
      target_id: null,
      check_ids: ['b', 'a', 'c'],
      name: 'Nightly',
      scheduled_for: null,
      recurrence: null,
    });
  });

  it('rejects empty selections, oversized selections, and past schedules', () => {
    assert.equal(normalizeOrResponse({ target_group_id: 'tg_1', check_ids: [] }).field, 'check_ids');
    const tooMany = Array.from({ length: MAX_SCAN_CHECKS + 1 }, (_, i) => `check_${i}`);
    assert.equal(normalizeOrResponse({ target_group_id: 'tg_1', check_ids: tooMany }).field, 'check_ids');
    const past = normalizeOrResponse(
      { target_group_id: 'tg_1', check_ids: ['a'], scheduled_for: '2026-06-01T11:59:00.000Z' },
      { now: NOW },
    );
    assert.equal(past.error, 'invalid_validation_scan');
    assert.equal(past.field, 'scheduled_for');
    assert.equal(normalizeOrResponse({ check_ids: ['a'] }).field, 'target_ids');
  });

  it('requires a schedule for recurring scans and validates cadence and timezone', () => {
    const noSchedule = normalizeOrResponse(
      { target_group_id: 'tg_1', check_ids: ['a'], recurrence: { cadence: 'daily' } },
      { now: NOW },
    );
    assert.equal(noSchedule.field, 'recurrence');
    const badCadence = normalizeOrResponse(
      { target_group_id: 'tg_1', check_ids: ['a'], scheduled_for: '2026-06-02T12:00:00.000Z', recurrence: 'hourly' },
      { now: NOW },
    );
    assert.equal(badCadence.field, 'recurrence');
    const ok = normalizeScanInput(
      { target_group_id: 'tg_1', check_ids: ['a'], scheduled_for: '2026-06-02T12:00:00.000Z', recurrence: 'weekly' },
      { now: NOW },
    );
    assert.deepEqual(ok.recurrence, { cadence: 'weekly', timezone: 'UTC' });
    assert.equal(normalizeScanInput(
      { target_group_id: 'tg_1', check_ids: ['a'], scheduled_for: '2026-06-02T12:00:00.000Z', recurrence: 'none' },
      { now: NOW },
    ).recurrence, null);
  });

  it('supports partial normalization for PATCH bodies', () => {
    const partial = normalizeScanInput({ name: 'Renamed' }, { now: NOW, partial: true });
    assert.deepEqual(partial, { name: 'Renamed' });
  });
});

describe('validation scan contract: planning', () => {
  it('plans check-major steps for the whole group and records incompatible pairs as excluded', () => {
    const dnsCheck = getCheckById('dns.authoritative_response.safe');
    const leakCheck = getCheckById('origin.leak_scan.safe');
    const plan = planScanSteps({ checks: [dnsCheck, leakCheck], targets: [FQDN_TARGET, URL_TARGET] });
    assert.deepEqual(plan.steps.map((step) => [step.position, step.check_id, step.target_id]), [
      [0, 'dns.authoritative_response.safe', 'tgt_fqdn'],
      [1, 'origin.leak_scan.safe', 'tgt_fqdn'],
      [2, 'origin.leak_scan.safe', 'tgt_url'],
    ]);
    assert.deepEqual(plan.excluded.map((row) => [row.check_id, row.target_id, row.reason]), [
      ['dns.authoritative_response.safe', 'tgt_url', 'target_kind_not_supported'],
    ]);
    assert.equal(plan.steps[0].request_snapshot.protocol, 'dns');
    assert.equal(plan.steps[1].request_snapshot.kind, 'origin_leak_scan');
  });

  it('scopes planning to one exact target when requested', () => {
    const leakCheck = getCheckById('origin.leak_scan.safe');
    const plan = planScanSteps({ checks: [leakCheck], targets: [FQDN_TARGET, URL_TARGET], targetId: 'tgt_url' });
    assert.equal(plan.steps.length, 1);
    assert.equal(plan.steps[0].target_id, 'tgt_url');
  });

  it('derives bounded request metadata from the probe profile only', () => {
    const snapshot = requestSnapshotForCheck(getCheckById('waf.low_rate_limit.safe'));
    assert.equal(snapshot.kind, 'rate_limit_sequence');
    assert.equal(snapshot.max_requests, 5);
    assert.equal(snapshot.timeout_ms, 5000);
    assert.equal(snapshot.protocol, 'https');
    assert.deepEqual(Object.keys(snapshot).sort(), ['kind', 'max_requests', 'method', 'path', 'protocol', 'timeout_ms']);
    assert.equal(requestSnapshotForCheck(getCheckById('dns.authoritative_response.safe')).protocol, 'dns');
  });
});

describe('validation scan contract: executor helpers', () => {
  it('classifies start denials into defer, abort, step, and retry', () => {
    assert.equal(classifyStartDenial({ error: 'safe_min_interval_active' }), 'defer');
    assert.equal(classifyStartDenial({ error: 'safe_window_closed' }), 'abort');
    assert.equal(classifyStartDenial({ error: 'kill_switch_active' }), 'abort');
    assert.equal(classifyStartDenial({ error: 'safe_rate_cap_exceeded', status: 429 }), 'defer');
    assert.equal(classifyStartDenial({ error: 'entitlement_limit_exceeded', status: 403 }), 'defer');
    assert.equal(classifyStartDenial({ error: 'tenant_suspended', status: 403 }), 'abort');
    for (const dead of ['subscription_limit_exceeded', 'safe_runs_per_hour_limit_exceeded']) {
      assert.equal(classifyStartDenial({ error: dead, status: 500 }), 'retry', `${dead} is not a real start code`);
    }
    assert.equal(classifyStartDenial({ error: 'soc_gated_check' }), 'step');
    assert.equal(classifyStartDenial({ error: 'target_kind_not_supported' }), 'step');
    assert.equal(classifyStartDenial({ error: 'something_new', status: 422 }), 'step');
    assert.equal(classifyStartDenial({ error: 'start_test_run_failed', status: 500 }), 'retry');
    assert.equal(classifyStartDenial(null), 'retry');
  });

  it('summarizes and derives scan status from step states', () => {
    const steps = [
      { status: 'verdicted' },
      { status: 'denied' },
      { status: 'skipped' },
      { status: 'pending' },
      { status: 'collecting' },
      { status: 'deferred' },
    ];
    const summary = computeScanSummary(steps);
    assert.equal(summary.total, 6);
    assert.equal(summary.running, 1);
    assert.equal(summary.completed, 3);
    assert.equal(deriveScanStatus(steps), 'running');
    assert.equal(deriveScanStatus([{ status: 'verdicted' }, { status: 'denied' }]), 'completed');
    assert.equal(deriveScanStatus([{ status: 'denied' }, { status: 'skipped' }]), 'denied');
  });

  it('computes next occurrences with cadence math and stable occurrence keys', () => {
    assert.equal(nextScanOccurrenceAt({ cadence: 'daily', timezone: 'UTC' }, NOW), '2026-06-02T12:00:00.000Z');
    assert.equal(nextScanOccurrenceAt({ cadence: 'weekly', timezone: 'UTC' }, NOW), '2026-06-08T12:00:00.000Z');
    assert.equal(nextScanOccurrenceAt({ cadence: 'monthly', timezone: 'UTC' }, NOW), '2026-07-01T12:00:00.000Z');
    assert.equal(nextScanOccurrenceAt(null, NOW), null);
    const key = scanOccurrenceKey('ten_demo', 'scan_series', NOW.toISOString());
    assert.equal(key, scanOccurrenceKey('ten_demo', 'scan_series', '2026-06-01T12:00:00Z'));
    assert.notEqual(key, scanOccurrenceKey('ten_other', 'scan_series', NOW.toISOString()));
  });
});

describe('validation scan contract: projections', () => {
  it('maps every customer-selectable check to a taxonomy section or null', () => {
    const withSections = CHECK_CATALOG.map(withCheckSection);
    assert.ok(withSections.some((check) => check.section_id && check.section_label));
    for (const check of withSections) {
      assert.ok(Object.prototype.hasOwnProperty.call(check, 'section_id'));
      assert.ok(Object.prototype.hasOwnProperty.call(check, 'section_label'));
    }
    assert.equal(sectionForCheck('does.not.exist'), null);
  });

  it('projects signed-worker attestation counts and simulation zero counts without raw payloads', () => {
    const check = getCheckById('origin.leak_scan.safe');
    const step = { id: 'step_1', position: 0, status: 'verdicted', check_id: check.check_id, target_id: 'tgt_fqdn', test_run_id: 'run_1', request_snapshot: requestSnapshotForCheck(check) };
    const run = { id: 'run_1', status: 'verdicted', probe_external_result: 'blocked', correlation: { nonce_hash: 'abc' } };
    const signed = projectScanStep({
      step,
      check,
      target: FQDN_TARGET,
      run,
      verdict: { verdict: 'protected', confidence: 'medium', explanation: 'ok', severity: 'info' },
      events: [{ test_run_id: 'run_1', signal_type: 'probe_result', nonce_hash: 'abc', producer_kind: 'signed_probe', external_result: 'blocked', timestamp: NOW.toISOString(), metadata: { status_code: 403, safety_attestation: { requests_sent: 3, duration_ms: 120 }, payload: 'MUST_NOT_LEAK' } }],
      probeJob: { probe_profile: { kind: 'origin_leak_scan', max_requests: 4 }, constraints: { max_probe_requests: 4 } },
    });
    assert.equal(signed.requests_sent, 3);
    assert.equal(signed.duration_ms, 120);
    assert.equal(signed.requests_simulated, false);
    assert.equal(signed.request.max_requests, 4);
    assert.equal(signed.response.status_code, 403);
    assert.equal(signed.response.external_result, 'blocked');
    assert.equal(signed.verdict.verdict, 'protected');
    assert.equal(JSON.stringify(signed).includes('MUST_NOT_LEAK'), false);

    const simulated = projectScanStep({
      step: { ...step, status: 'collecting' },
      check,
      target: FQDN_TARGET,
      run: { ...run, status: 'collecting', probe_external_result: null },
      verdict: null,
      events: [{ test_run_id: 'run_1', signal_type: 'probe_result', nonce_hash: 'abc', producer_kind: 'internal_simulation', external_result: 'blocked', timestamp: NOW.toISOString(), metadata: { simulation: 'SAFE_PROBE_SIMULATION' } }],
    });
    assert.equal(simulated.requests_sent, 0);
    assert.equal(simulated.requests_simulated, true);
    assert.equal(simulated.verdict, null);
  });

  it('merges scan audit entries and child run events into one chronological metadata-only feed', () => {
    const steps = [{ id: 'step_1', check_id: 'origin.leak_scan.safe', test_run_id: 'run_1' }];
    const items = buildActivityItems({
      scan: { id: 'scan_1' },
      steps,
      auditEntries: [
        { id: 'aud_2', timestamp: '2026-06-01T12:00:02.000Z', action: 'validation_scan.step_started', resource_type: 'validation_scan', resource_id: 'scan_1', metadata: { step_id: 'step_1', check_id: 'origin.leak_scan.safe', test_run_id: 'run_1', secret_token: 'nope' } },
        { id: 'aud_1', timestamp: '2026-06-01T12:00:00.000Z', action: 'validation_scan.created', resource_type: 'validation_scan', resource_id: 'scan_1', metadata: { step_count: 1 } },
        { id: 'aud_3', timestamp: '2026-06-01T12:00:05.000Z', action: 'verdict.published', resource_type: 'test_run', resource_id: 'run_1', metadata: { verdict: 'protected', confidence: 'medium' } },
      ],
      runEvents: [
        { id: 'evt_1', timestamp: '2026-06-01T12:00:03.000Z', test_run_id: 'run_1', signal_type: 'probe_result', external_result: 'blocked', producer_kind: 'internal_simulation', metadata: { headers: { authorization: 'x' } } },
      ],
    });
    assert.deepEqual(items.map((item) => item.id), ['aud_1', 'aud_2', 'evt_1', 'aud_3']);
    assert.equal(items[1].step_id, 'step_1');
    assert.equal(items[2].kind, 'event');
    assert.equal(items[2].metadata.external_result, 'blocked');
    assert.equal(items[3].metadata.verdict, 'protected');
    const serialized = JSON.stringify(items);
    assert.equal(serialized.includes('secret_token'), false);
    assert.equal(serialized.includes('authorization'), false);
  });
});

describe('validation scan contract: activity cursor and deferral', () => {
  it('pages by ingestion order so a late observation with an older event time is still delivered', () => {
    const scan = { id: 'scan_1' };
    const steps = [{ id: 'step_1', check_id: 'c', test_run_id: 'run_1' }];
    const auditEntries = [
      { id: 'aud_1', sequence: 1, action: 'validation_scan.created', resource_type: 'validation_scan', resource_id: 'scan_1', timestamp: '2026-06-01T12:00:00.000Z' },
    ];
    const firstEvents = [
      { id: 'evt_a', test_run_id: 'run_1', signal_type: 'probe_result', timestamp: '2026-06-01T12:00:05.000Z', ingest_index: 0 },
    ];
    const first = contract.paginateActivity(contract.buildActivityItems({ scan, steps, auditEntries, runEvents: firstEvents }));
    assert.equal(first.items.length, 2);
    assert.equal(Object.prototype.hasOwnProperty.call(first.items[0], 'ingest'), false);
    const lateEvents = [
      ...firstEvents,
      { id: 'evt_late', test_run_id: 'run_1', signal_type: 'agent_observation', timestamp: '2026-06-01T11:59:00.000Z', ingest_index: 1 },
    ];
    const next = contract.paginateActivity(
      contract.buildActivityItems({ scan, steps, auditEntries, runEvents: lateEvents }),
      { after: first.cursor },
    );
    assert.deepEqual(next.items.map((item) => item.id), ['evt_late']);
    const drained = contract.paginateActivity(
      contract.buildActivityItems({ scan, steps, auditEntries, runEvents: lateEvents }),
      { after: next.cursor },
    );
    assert.equal(drained.items.length, 0);
    assert.equal(contract.decodeActivityCursor('not-a-cursor'), null);
  });

  it('computes hourly-cap and min-interval eligibility from persisted runs', () => {
    const now = new Date('2026-06-01T12:00:00.000Z');
    const runs = [
      { tenant_id: 't', target_group_id: 'g', created_at: '2026-06-01T11:10:00.000Z' },
      { tenant_id: 't', target_group_id: 'g', created_at: '2026-06-01T11:59:50.000Z' },
      { tenant_id: 'other', target_group_id: 'g', created_at: '2026-06-01T11:05:00.000Z' },
    ];
    assert.equal(
      contract.deferredStepEligibleAt({ code: 'safe_rate_cap_exceeded', runs, tenantId: 't', targetGroupId: 'g', now }),
      '2026-06-01T12:10:01.000Z',
    );
    assert.equal(
      contract.deferredStepEligibleAt({ code: 'safe_min_interval_active', runs, tenantId: 't', targetGroupId: 'g', minSecondsBetweenRuns: 30, now }),
      '2026-06-01T12:00:20.000Z',
    );
  });
});

