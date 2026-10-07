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

test('check probe logs keep raw connected responses neutral and display the published gap separately', () => {
  const exposedRow = {
    runId: 'run_waf_1',
    checkId: 'l7.waf_marker_rule.safe',
    name: 'WAF Marker Rule (Safe)',
    status: 'failed',
    verdict: 'edge_exposed',
    explanation: 'External probe reached the declared path; the edge did not block traffic before origin.',
    expectedBehavior: 'must_block_before_origin',
    startedAt: '2026-10-04T18:39:04.523Z',
    finishedAt: '2026-10-04T18:40:37.407Z',
    requestsSent: 1,
    maxRequests: 1,
  };
  const events = [
    {
      id: 'evt_probe_1',
      test_run_id: exposedRow.runId,
      check_id: exposedRow.checkId,
      producer_kind: 'signed_probe',
      signal_type: 'probe_result',
      timestamp: '2026-10-04T18:39:07.923Z',
      metadata: {
        external_result: 'connected',
        status_code: 200,
        safety_attestation: { requests_sent: 1 },
      },
    },
  ];

  const logs = generateCheckProbeLogs(exposedRow, 'astranull.site', events);
  assert.equal(logs.length, 3);

  // Line 1: Started
  assert.equal(logs[0].tag, 'STATE');
  assert.match(logs[0].message, /Run recorded.*WAF Marker Rule/);

  assert.equal(logs[1].tag, 'RECV');
  assert.equal(logs[1].tone, 'info');
  assert.match(logs[1].message, /Worker result recorded: connected.*HTTP 200/);
  assert.doesNotMatch(logs[1].message, /reached origin|edge did not block/);

  // Line 3: Outcome verdict — MUST NOT be a generic state line
  assert.equal(logs[2].tag, 'GAP');
  assert.equal(logs[2].tone, 'danger');
  assert.equal(logs[2].level, 'verdict');
  assert.match(logs[2].message, /Check outcome: Gap found · edge_exposed/);
  assert.match(logs[2].message, /External probe reached the declared path/);
});

test('check probe logs keep raw blocked responses neutral and display the published pass separately', () => {
  const protectedRow = {
    runId: 'run_waf_2',
    checkId: 'l7.waf_marker_rule.safe',
    name: 'WAF Marker Rule (Safe)',
    status: 'passed',
    verdict: 'edge_protected',
    explanation: 'External probe was blocked at the edge.',
    expectedBehavior: 'must_block_before_origin',
    startedAt: '2026-10-04T18:39:04.523Z',
    finishedAt: '2026-10-04T18:40:37.407Z',
  };
  const events = [
    {
      id: 'evt_probe_2',
      test_run_id: protectedRow.runId,
      check_id: protectedRow.checkId,
      producer_kind: 'signed_probe',
      signal_type: 'probe_result',
      timestamp: '2026-10-04T18:39:07.923Z',
      metadata: {
        external_result: 'blocked',
        status_code: 403,
      },
    },
  ];

  const logs = generateCheckProbeLogs(protectedRow, 'astranull.site', events);
  assert.equal(logs[1].tag, 'RECV');
  assert.equal(logs[1].tone, 'info');
  assert.match(logs[1].message, /Worker result recorded: blocked.*HTTP 403/);
  assert.equal(logs[2].tag, 'PASS');
  assert.equal(logs[2].tone, 'success');
  assert.match(logs[2].message, /Check outcome: Passed · edge_protected/);
});

test('check probe logs show recorded probe response from row.response if runEvents is empty', () => {
  const rowWithResponse = {
    runId: 'run_scan_step_1',
    checkId: 'l7.waf_marker_rule.safe',
    name: 'WAF Marker Rule (Safe)',
    status: 'failed',
    verdict: 'edge_exposed',
    explanation: 'Edge did not block traffic before origin.',
    expectedBehavior: 'must_block_before_origin',
    startedAt: '2026-10-04T18:39:04.523Z',
    finishedAt: '2026-10-04T18:40:37.407Z',
    response: {
      external_result: 'connected',
      status_code: 200,
    },
  };

  const logs = generateCheckProbeLogs(rowWithResponse, 'astranull.site', []);
  assert.equal(logs.length, 3);
  assert.equal(logs[1].tag, 'RECV');
  assert.equal(logs[1].tone, 'info');
  assert.match(logs[1].message, /Worker result recorded: connected · HTTP 200/);
});


test('a received activity event does not suppress the recorded final observation result', () => {
  const observed = { ...row, status: 'observed', verdict: 'inconclusive', expectedBehavior: 'must_block_before_origin', finishedAt: at,
    response: { external_result: 'connected', status_code: 200 } };
  const events = [{ id: 'received', test_run_id: row.runId, check_id: row.checkId, producer_kind: 'signed_probe', signal_type: 'probe_activity', timestamp: at,
    metadata: { activity: { stage: 'response_received', status_code: 200 } } }];
  const logs = generateCheckProbeLogs(observed, 'owned.test', events);
  assert.equal(logs.length, 3);
  assert.equal(logs.filter((log) => /Worker result recorded/.test(log.message)).length, 1);
  assert.ok(logs.some((log) => log.tag === 'OBSERVED'));
  assert.ok(logs.every((log) => log.tag !== 'EXPOSED' && !/reached origin/.test(log.message)));
  const resultEvent = { ...events[0], id: 'final', signal_type: 'probe_result', metadata: { external_result: 'connected' } };
  assert.equal(generateCheckProbeLogs(observed, 'owned.test', [...events, resultEvent]).filter((log) => /Worker result recorded/.test(log.message)).length, 1);
});
