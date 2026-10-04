import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateCheckProbeLogs, buildScanLiveLogs } from '../../apps/web/react/src/lib/live-probe-logs.mjs';
const row = { runId: 'run_1', checkId: 'waf.fingerprint.safe', name: 'WAF check', status: 'running', requestsSent: 13, maxRequests: 16 };
const at = '2026-10-04T12:46:00.000Z';
test('request totals and catalog phases never fabricate per-request logs or timestamps', () => {
  assert.deepEqual(generateCheckProbeLogs(row, 'owned.test'), []);
  assert.deepEqual(buildScanLiveLogs({ id: 'scan', status: 'running' }, [row], [], 'owned.test'), []);
});
test('console uses only recorded worker times, response codes, and durations', () => {
  const events = [{ id: 'evt_1', test_run_id: row.runId, check_id: row.checkId, producer_kind: 'signed_probe', signal_type: 'probe_activity', timestamp: at,
    metadata: { activity: { stage: 'response_received', method: 'POST', url: 'https://owned.test/path', status_code: 418, duration_ms: 19 } } }];
  const logs = generateCheckProbeLogs(row, 'owned.test', events);
  assert.equal(logs.length, 1);
  assert.equal(logs[0].timestamp, at);
  assert.equal(logs[0].statusCode, 418);
  assert.equal(logs[0].latencyMs, 19);
  assert.match(logs[0].message, /POST.*HTTP 418.*19ms/);
  assert.equal(generateCheckProbeLogs(row, 'owned.test', [{ ...events[0], producer_kind: 'public_api' }]).length, 0);
  assert.equal(generateCheckProbeLogs(row, 'owned.test', [{ ...events[0], test_run_id: 'foreign_run' }]).length, 0);
});
test('missing status, duration, count, or timestamp stays missing', () => {
  const logs = generateCheckProbeLogs(row, 'owned.test', [{ id: 'evt_1', test_run_id: row.runId, check_id: row.checkId, producer_kind: 'signed_probe', signal_type: 'probe_result', metadata: { external_result: 'timeout' } }]);
  assert.equal(logs.length, 1);
  assert.equal(logs[0].timestamp, '');
  assert.equal(logs[0].statusCode, undefined);
  assert.equal(logs[0].latencyMs, undefined);
  assert.equal(logs[0].requestsSent, undefined);
  assert.equal(logs[0].message.includes('HTTP 200'), false);
});
test('scan console uses real audit and worker metadata, with no synthesized check sequence', () => {
  const audit = { id: 'audit_1', at, kind: 'scan', summary: 'Validation scan started' };
  const worker = { id: 'evt_1', at, kind: 'event', action: 'probe_activity', check_id: row.checkId,
    metadata: { producer_kind: 'signed_probe', activity: { stage: 'request_not_sent', reason: 'outside_request_budget' } } };
  const logs = buildScanLiveLogs({ id: 'scan' }, [row], [audit, worker, audit]);
  assert.equal(logs.length, 2);
  assert.equal(logs[0].message, 'Validation scan started');
  assert.match(logs[1].message, /Not sent.*outside_request_budget/);
  assert.equal(logs.some((item) => item.latencyMs != null), false);
});
