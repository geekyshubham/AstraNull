import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import * as contract from '../../src/contracts/validationScanManagement.mjs';
import * as ui from '../../apps/web/react/src/lib/validation-scan.mjs';

const NOW = new Date('2030-01-01T12:00:00.000Z');

function localPlusMinutes(minutes) {
  return ui.isoToLocalDatetime(new Date(NOW.getTime() + minutes * 60_000).toISOString());
}

describe('validation scan UI helpers: contract parity', () => {
  it('mirrors the backend status vocabularies and limits', () => {
    assert.deepEqual([...ui.SCAN_STATUSES], [...contract.SCAN_STATUSES]);
    assert.deepEqual([...ui.STEP_STATUSES], [...contract.STEP_STATUSES]);
    assert.deepEqual([...ui.ACTIVE_SCAN_STATUSES], [...contract.ACTIVE_SCAN_STATUSES]);
    assert.deepEqual([...ui.CANCELLABLE_SCAN_STATUSES], [...contract.CANCELLABLE_SCAN_STATUSES]);
    assert.deepEqual([...ui.TERMINAL_SCAN_STATUSES], [...contract.TERMINAL_SCAN_STATUSES]);
    assert.deepEqual([...ui.SCAN_RECURRENCE_CADENCES], [...contract.SCAN_RECURRENCE_CADENCES]);
    assert.equal(ui.MAX_SCAN_CHECKS, contract.MAX_SCAN_CHECKS);
    assert.equal(ui.MIN_SCHEDULE_LEAD_MS, contract.MIN_SCHEDULE_LEAD_MS);
    assert.equal(ui.MAX_SCAN_NAME_LENGTH, contract.MAX_SCAN_NAME_LENGTH);
  });

  it('assigns a badge tone to every scan and step status', () => {
    const tones = new Set(['default', 'success', 'warn', 'danger', 'info', 'muted']);
    for (const status of contract.SCAN_STATUSES) assert.ok(tones.has(ui.scanStatusTone(status)), status);
    for (const status of contract.STEP_STATUSES) assert.ok(tones.has(ui.stepStatusTone(status)), status);
    assert.equal(ui.scanStatusTone('completed'), 'success');
    assert.equal(ui.scanStatusTone('cancelled'), 'danger');
    assert.equal(ui.stepStatusTone('collecting'), 'info');
    assert.equal(ui.stepStatusTone('deferred'), 'warn');
  });

  it('derives lifecycle predicates from the contract status sets', () => {
    for (const status of contract.SCAN_STATUSES) {
      const scan = { status };
      assert.equal(ui.isScanActive(scan), contract.ACTIVE_SCAN_STATUSES.includes(status), status);
      assert.equal(ui.isScanCancellable(scan), contract.CANCELLABLE_SCAN_STATUSES.includes(status), status);
      assert.equal(ui.isScanTerminal(scan), contract.TERMINAL_SCAN_STATUSES.includes(status), status);
      assert.equal(ui.isScanEditable(scan), status === 'scheduled', status);
    }
  });
});

describe('validation scan UI helpers: form and payload', () => {
  const baseForm = ui.emptyScanForm({ targetIds: ['tgt_1'], checkIds: ['a.safe', 'b.safe', 'a.safe'] });

  it('builds a run-now payload with deduplicated checks and no schedule', () => {
    assert.deepEqual(ui.buildScanPayload(baseForm), { target_ids: ['tgt_1'], check_ids: ['a.safe', 'b.safe'] });
    assert.equal(ui.validateScanForm(baseForm, { now: NOW }).ok, true);
  });

  it('adds exact target, name, schedule, and recurrence when set', () => {
    const form = { ...baseForm, targetIds: ['tgt_1'], name: ' Nightly ', schedule: 'later', scheduledForLocal: localPlusMinutes(5), recurrence: 'weekly', timezone: 'UTC' };
    const payload = ui.buildScanPayload(form);
    assert.deepEqual(payload.target_ids, ['tgt_1']);
    assert.equal(payload.name, 'Nightly');
    assert.equal(new Date(payload.scheduled_for).getTime(), NOW.getTime() + 5 * 60_000);
    assert.deepEqual(payload.recurrence, { cadence: 'weekly', timezone: 'UTC' });
    assert.equal(ui.validateScanForm(form, { now: NOW }).ok, true);
    const normalized = contract.normalizeScanInput(payload, { now: NOW });
    assert.equal(normalized.recurrence.cadence, 'weekly');
  });

  it('rejects missing scope, empty selection, too many checks, past schedules, and recurrence without schedule', () => {
    assert.deepEqual(Object.keys(ui.validateScanForm(ui.emptyScanForm(), { now: NOW }).errors), ['target_ids', 'check_ids']);
    assert.ok(ui.validateScanForm({ ...baseForm, targetIds: [] }, { now: NOW }).errors.target_ids);
    const tooMany = { ...baseForm, checkIds: Array.from({ length: contract.MAX_SCAN_CHECKS + 1 }, (_, index) => `c${index}`) };
    assert.match(ui.validateScanForm(tooMany, { now: NOW }).errors.check_ids, new RegExp(String(contract.MAX_SCAN_CHECKS)));
    assert.ok(ui.validateScanForm({ ...baseForm, schedule: 'later', scheduledForLocal: localPlusMinutes(0) }, { now: NOW }).errors.scheduled_for);
    assert.ok(ui.validateScanForm({ ...baseForm, schedule: 'later', scheduledForLocal: '' }, { now: NOW }).errors.scheduled_for);
    assert.ok(ui.validateScanForm({ ...baseForm, recurrence: 'daily' }, { now: NOW }).errors.recurrence);
    assert.ok(ui.validateScanForm({ ...baseForm, name: 'x'.repeat(contract.MAX_SCAN_NAME_LENGTH + 1) }, { now: NOW }).errors.name);
  });

  it('builds a minimal PATCH from a scheduled scan and an edited form', () => {
    const scan = {
      id: 'scan_1',
      status: 'scheduled',
      target_group_id: 'tg_1',
      target_id: null,
      check_ids: ['a.safe'],
      name: 'Old',
      scheduled_for: '2030-01-02T10:00:00.000Z',
      recurrence: { cadence: 'weekly', timezone: 'UTC' },
    };
    const form = ui.scanFormFromScan(scan);
    assert.deepEqual(form.targetIds, []);
    assert.equal(form.recurrence, 'weekly');
    assert.deepEqual(ui.buildScanPatch(scan, form), {});
    assert.deepEqual(ui.buildScanPatch(scan, { ...form, name: 'New' }), { name: 'New' });
    assert.deepEqual(ui.buildScanPatch(scan, { ...form, name: '' }), { name: null });
    assert.deepEqual(ui.buildScanPatch(scan, { ...form, recurrence: 'none' }), { recurrence: 'none' });
    assert.deepEqual(ui.buildScanPatch(scan, { ...form, checkIds: ['a.safe', 'b.safe'] }), { check_ids: ['a.safe', 'b.safe'] });
    assert.deepEqual(ui.buildScanPatch(scan, { ...form, targetIds: ['tgt_9'] }), { target_ids: ['tgt_9'] });
  });

  it('humanizes backend error payloads without leaking raw codes', () => {
    assert.match(ui.scanErrorMessage({ error: 'soc_gated_check', check_id: 'waf.soc' }), /SOC governance/);
    assert.match(ui.scanErrorMessage({ error: 'soc_gated_check', check_id: 'waf.soc' }), /waf\.soc/);
    assert.match(ui.scanErrorMessage({ error: 'invalid_validation_scan', field: 'scheduled_for', message: 'scheduled_for must be at least one minute in the future.' }), /one minute/);
    assert.match(ui.scanErrorMessage({ error: 'scan_has_no_runnable_steps', excluded: [{}, {}] }), /2 incompatible/);
    assert.match(ui.scanErrorMessage({ error: 'concurrent_scan_blocked' }), /already using/);
    assert.equal(ui.scanErrorMessage({ error: 'weird_new_code' }), 'Weird new code.');
    assert.equal(ui.scanErrorMessage(null, 'fallback'), 'fallback');
    for (const code of Object.keys(ui.SCAN_ERROR_COPY)) assert.doesNotMatch(ui.SCAN_ERROR_COPY[code], /_/);
  });
});

describe('validation scan UI helpers: live view formatting', () => {
  it('formats request and response metadata without payloads', () => {
    assert.equal(
      ui.formatStepRequest({ kind: 'http_head', method: 'head', path: '/health', protocol: 'https', max_requests: 1, timeout_ms: 5000 }),
      'Http head · HEAD /health · HTTPS · max 1 request · 5000 ms timeout',
    );
    assert.equal(ui.formatStepRequest({ kind: 'dns_wire_query', protocol: 'dns', max_requests: 2, timeout_ms: null }), 'Dns wire query · DNS · max 2 requests');
    assert.equal(ui.formatStepRequest(null), 'Not recorded');
    assert.equal(ui.formatStepResponse({ external_result: 'blocked', status_code: 403 }), 'Blocked · HTTP 403');
    assert.equal(ui.formatStepResponse({ external_result: null, status_code: null }), 'Awaiting response');
  });

  it('labels requests sent for live, simulated, inline, and unknown cases', () => {
    assert.equal(ui.formatRequestsSent({ requests_sent: 3 }), '3');
    assert.equal(ui.formatRequestsSent({ requests_sent: 0, requests_simulated: true }), '0 (simulated, no live traffic)');
    assert.equal(ui.formatRequestsSent({ requests_sent: 0, requests_inline: true }), 'inline, no network');
    assert.equal(ui.formatRequestsSent({ requests_sent: null }), '—');
  });

  it('computes progress from the summary only', () => {
    assert.equal(ui.scanProgressPercent({ total: 4, completed: 1 }), 25);
    assert.equal(ui.scanProgressPercent({ total: 0, completed: 0 }), 0);
    assert.equal(ui.scanProgressPercent(null), 0);
    assert.equal(ui.scanProgressPercent(contract.computeScanSummary([{ status: 'verdicted' }, { status: 'running' }])), 50);
  });

  it('merges activity by id and orders chronologically', () => {
    const merged = ui.mergeActivity(
      [{ id: 'b', at: '2030-01-01T00:00:02.000Z' }, { id: 'a', at: '2030-01-01T00:00:01.000Z' }],
      [{ id: 'b', at: '2030-01-01T00:00:02.000Z', summary: 'updated' }, { id: 'c', at: '2030-01-01T00:00:03.000Z' }],
    );
    assert.deepEqual(merged.map((item) => item.id), ['a', 'b', 'c']);
    assert.equal(merged[1].summary, 'updated');
  });

  it('polls quickly while active, slowly while scheduled, backs off on errors, and stops when terminal', () => {
    assert.equal(ui.nextPollDelay({ status: 'running' }), ui.SCAN_POLL_BASE_MS);
    assert.equal(ui.nextPollDelay({ status: 'pending' }), ui.SCAN_POLL_BASE_MS);
    assert.equal(ui.nextPollDelay({ status: 'scheduled' }), ui.SCAN_POLL_SCHEDULED_MS);
    assert.equal(ui.nextPollDelay({ status: 'running', errorCount: 1 }), ui.SCAN_POLL_BASE_MS * 2);
    assert.equal(ui.nextPollDelay({ status: 'running', errorCount: 6 }), ui.SCAN_POLL_MAX_MS);
    for (const status of contract.TERMINAL_SCAN_STATUSES) assert.equal(ui.nextPollDelay({ status }), null, status);
  });

  it('describes scope, recurrence, and reasons in prose', () => {
    assert.equal(ui.scopeLabel({ target_group: { name: 'edge' }, target_id: 'tgt_1', target: { value: 'a.test' } }), 'Domain a.test');
    assert.equal(ui.scopeLabel({ target_group_id: 'tg_1' }), 'Domain selection not recorded');
    assert.equal(ui.recurrenceLabel(null), 'One-time');
    assert.equal(ui.recurrenceLabel({ cadence: 'weekly', timezone: 'UTC' }), 'Weekly (UTC)');
    assert.equal(ui.humanizeReason('scan_aborted:concurrent_run_blocked'), 'Scan aborted (concurrent run blocked)');
    assert.equal(ui.humanizeReason('safe_min_interval_active'), 'Safe min interval active');
  });
});

describe('validation scan UI helpers: explicit domain selection', () => {
  it('does not include private grouping identifiers in the reviewed payload', () => {
    const payload = ui.buildScanPayload(ui.emptyScanForm({ targetIds: ['tgt_a', 'tgt_b'], checkIds: ['waf.fingerprint.safe'] }));
    assert.deepEqual(payload.target_ids, ['tgt_a', 'tgt_b']);
    assert.equal(Object.hasOwn(payload, 'target_group_id'), false);
  });
});
