import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;

before(async () => {
  freshStore();
  server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await closeServer(server);
});

beforeEach(() => {
  freshStore();
});

function expireCollectionWindows() {
  for (const run of getStore().testRuns) {
    run.collection_deadline_at = new Date(Date.now() - 1000).toISOString();
  }
}

describe('validation scans API', () => {
  it('runs the on-demand lifecycle: create with selected checks, watch progress, read activity, stop', async () => {
    const engineer = demoHeaders('engineer');
    const viewer = demoHeaders('viewer', 'ten_demo', 'usr_viewer');

    const created = await request(baseUrl, 'POST', '/v1/validation-scans', {
      headers: engineer,
      body: { target_group_id: 'tg_1', target_id: 'tgt_1', check_ids: ['dns.authoritative_response.safe', 'origin.leak_scan.safe', 'l3.firewall_exposure_scan.safe'] },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.status, 'running');
    assert.equal(created.json.target.id, 'tgt_1');
    assert.equal(created.json.summary.total, 3);
    assert.deepEqual(created.json.steps.map((step) => step.status), ['collecting', 'pending', 'pending']);
    assert.equal(created.json.steps[0].request.kind, 'dns_wire_query');
    assert.equal(created.json.steps[0].response.external_result, 'blocked');
    assert.equal(created.json.steps[0].requests_sent, 0);
    assert.equal(created.json.steps[0].requests_simulated, true);
    assert.equal(created.json.steps[0].section_label != null, true);
    assert.equal(getStore().testRuns.length, 1);

    expireCollectionWindows();
    const viewerRead = await request(baseUrl, 'GET', `/v1/validation-scans/${created.json.id}`, { headers: viewer });
    assert.equal(viewerRead.status, 200);
    assert.deepEqual(viewerRead.json.steps.map((step) => step.status), ['collecting', 'pending', 'pending']);
    assert.equal(getStore().testRuns.length, 1, 'read-only callers never advance scans or start child runs');
    const progressed = await request(baseUrl, 'GET', `/v1/validation-scans/${created.json.id}`, { headers: engineer });
    assert.equal(progressed.status, 200);
    assert.deepEqual(progressed.json.steps.map((step) => step.status), ['verdicted', 'collecting', 'pending']);
    assert.equal(progressed.json.steps[0].verdict.verdict, 'inconclusive');
    assert.equal(progressed.json.steps[0].test_run_id, getStore().testRuns[0].id);

    const activity = await request(baseUrl, 'GET', `/v1/validation-scans/${created.json.id}/activity`, { headers: viewer });
    assert.equal(activity.status, 200);
    assert.equal(activity.json.items[0].action, 'validation_scan.created');
    assert.ok(activity.json.items.some((item) => item.action === 'probe_result'));
    assert.ok(activity.json.items.some((item) => item.action === 'validation_scan.step_completed'));
    for (const item of activity.json.items) {
      assert.equal(JSON.stringify(item).includes('nonce_for'), false);
      assert.equal(Object.prototype.hasOwnProperty.call(item.metadata ?? {}, 'payload'), false);
    }

    const listed = await request(baseUrl, 'GET', '/v1/validation-scans?target_group_id=tg_1', { headers: viewer });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.count, 1);
    assert.equal(listed.json.items[0].id, created.json.id);

    const stopped = await request(baseUrl, 'POST', `/v1/validation-scans/${created.json.id}/cancel`, {
      headers: engineer,
      body: { reason: 'operator requested stop' },
    });
    assert.equal(stopped.status, 200);
    assert.equal(stopped.json.status, 'cancelled');
    assert.equal(stopped.json.cancel_reason, 'operator requested stop');
    assert.deepEqual(stopped.json.steps.map((step) => step.status), ['verdicted', 'cancelled', 'skipped']);
    assert.equal(getStore().testRuns.length, 2);
    assert.equal(getStore().testRuns[1].status, 'cancelled');
    const runCancelAudit = getStore().auditLog.find((entry) => entry.action === 'test_run.cancelled');
    assert.equal(runCancelAudit.metadata.reason, 'operator requested stop');
    assert.equal(runCancelAudit.metadata.cancelled_by, 'usr_admin');
    assert.equal(runCancelAudit.metadata.source, 'scan');

    const again = await request(baseUrl, 'POST', `/v1/validation-scans/${created.json.id}/cancel`, { headers: engineer });
    assert.equal(again.status, 409);
    assert.equal(again.json.error, 'not_cancellable');
    expireCollectionWindows();
    const final = await request(baseUrl, 'GET', `/v1/validation-scans/${created.json.id}`, { headers: engineer });
    assert.equal(final.json.status, 'cancelled');
    assert.equal(getStore().testRuns.length, 2);
  });

  it('enforces RBAC and refuses SOC-gated or unknown checks for the whole request', async () => {
    const viewer = demoHeaders('viewer', 'ten_demo', 'usr_viewer');
    const engineer = demoHeaders('engineer');
    const forbidden = await request(baseUrl, 'POST', '/v1/validation-scans', {
      headers: viewer,
      body: { target_group_id: 'tg_1', check_ids: ['origin.leak_scan.safe'] },
    });
    assert.equal(forbidden.status, 403);
    const soc = await request(baseUrl, 'POST', '/v1/validation-scans', {
      headers: engineer,
      body: { target_group_id: 'tg_1', check_ids: ['origin.leak_scan.safe', 'waf.offensive_sqli.soc'] },
    });
    assert.equal(soc.status, 403);
    assert.equal(soc.json.error, 'soc_gated_check');
    assert.equal(soc.json.check_id, 'waf.offensive_sqli.soc');
    const unknown = await request(baseUrl, 'POST', '/v1/validation-scans', {
      headers: engineer,
      body: { target_group_id: 'tg_1', check_ids: ['nope.safe'] },
    });
    assert.equal(unknown.status, 400);
    assert.equal(unknown.json.error, 'unknown_check');
    const empty = await request(baseUrl, 'POST', '/v1/validation-scans', {
      headers: engineer,
      body: { target_group_id: 'tg_1', check_ids: [] },
    });
    assert.equal(empty.status, 400);
    assert.equal(empty.json.field, 'check_ids');
    assert.equal(getStore().validationScans.length, 0);
    assert.equal(getStore().testRuns.length, 0);

    const otherTenant = demoHeaders('engineer', 'ten_other', 'usr_other');
    const missing = await request(baseUrl, 'GET', '/v1/validation-scans/scan_missing', { headers: otherTenant });
    assert.equal(missing.status, 404);
    const viewerCancel = await request(baseUrl, 'POST', '/v1/validation-scans/scan_missing/cancel', { headers: viewer });
    assert.equal(viewerCancel.status, 403);
  });

  it('schedules, edits, lists, and cancels a recurring scan through the API', async () => {
    const engineer = demoHeaders('engineer');
    const scheduledFor = new Date(Date.now() + 3_600_000).toISOString();
    const created = await request(baseUrl, 'POST', '/v1/validation-scans', {
      headers: engineer,
      body: {
        target_group_id: 'tg_1',
        check_ids: ['origin.leak_scan.safe'],
        scheduled_for: scheduledFor,
        recurrence: { cadence: 'daily', timezone: 'UTC' },
        name: 'Nightly',
      },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.status, 'scheduled');
    assert.equal(created.json.target, null);
    assert.equal(created.json.recurrence.cadence, 'daily');
    assert.ok(created.json.next_occurrence_at);
    assert.equal(getStore().testRuns.length, 0);

    const patched = await request(baseUrl, 'PATCH', `/v1/validation-scans/${created.json.id}`, {
      headers: engineer,
      body: { check_ids: ['origin.leak_scan.safe', 'dns.authoritative_response.safe'], target_id: 'tgt_1' },
    });
    assert.equal(patched.status, 200);
    assert.equal(patched.json.summary.total, 2);
    assert.equal(patched.json.target.id, 'tgt_1');

    const scheduled = await request(baseUrl, 'GET', '/v1/validation-scans?status=scheduled', { headers: engineer });
    assert.equal(scheduled.json.count, 1);

    const cancelled = await request(baseUrl, 'POST', `/v1/validation-scans/${created.json.id}/cancel`, {
      headers: engineer,
      body: { reason: 'no longer needed', cancel_series: true },
    });
    assert.equal(cancelled.status, 200);
    assert.equal(cancelled.json.status, 'cancelled');
    assert.equal(cancelled.json.recurrence, null);
    const afterCancel = await request(baseUrl, 'GET', '/v1/validation-scans?status=scheduled', { headers: engineer });
    assert.equal(afterCancel.json.count, 0);
  });

  it('records actor and reason when a single run is cancelled directly', async () => {
    const engineer = demoHeaders('engineer');
    const started = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: engineer,
      body: { check_id: 'origin.leak_scan.safe', target_group_id: 'tg_1', target_id: 'tgt_1' },
    });
    assert.equal(started.status, 201);
    const cancelled = await request(baseUrl, 'POST', `/v1/test-runs/${started.json.run.id}/cancel`, {
      headers: engineer,
      body: { reason: 'maintenance window' },
    });
    assert.equal(cancelled.status, 200);
    assert.equal(cancelled.json.status, 'cancelled');
    assert.equal(cancelled.json.summary.cancellation.reason, 'maintenance window');
    const entry = getStore().auditLog.find((row) => row.action === 'test_run.cancelled');
    assert.equal(entry.metadata.reason, 'maintenance window');
    assert.equal(entry.metadata.cancelled_by_role, 'engineer');

    const bare = await request(baseUrl, 'POST', `/v1/test-runs/${started.json.run.id}/cancel`, { headers: engineer });
    assert.equal(bare.status, 409);
  });

  it('exposes taxonomy sections on the check catalog for grouped selection', async () => {
    const checks = await request(baseUrl, 'GET', '/v1/checks', { headers: demoHeaders('viewer', 'ten_demo', 'usr_viewer') });
    assert.equal(checks.status, 200);
    assert.ok(checks.json.items.length > 0);
    for (const check of checks.json.items) {
      assert.ok(Object.prototype.hasOwnProperty.call(check, 'section_id'));
      assert.ok(Object.prototype.hasOwnProperty.call(check, 'section_label'));
    }
    assert.ok(checks.json.items.some((check) => check.section_id === 'A3'));
    const socGated = checks.json.items.filter((check) => check.safety_class === 'soc_gated');
    assert.ok(socGated.length > 0);
    const engineer = demoHeaders('engineer');
    const refused = await request(baseUrl, 'POST', '/v1/validation-scans', {
      headers: engineer,
      body: { target_group_id: 'tg_1', check_ids: [socGated[0].check_id] },
    });
    assert.equal(refused.status, 403);
    assert.equal(refused.json.error, 'soc_gated_check');
  });
});
