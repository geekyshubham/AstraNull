import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import {
  REPORT_EXPORT_FORMATS,
  REPORT_KINDS,
} from '../../src/contracts/complianceReports.mjs';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

// ADR-0008: outside-in only. The validation loop is start -> external probe evidence ->
// finalization -> verdict -> finding. No agents, bootstrap tokens, or observations.

let baseUrl;
let server;

before(() => {
  freshStore();
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => {
  server.close();
});

describe('integration first validation slice', () => {
  it('runs the external-only validation loop through report export', async () => {
    const h = demoHeaders('engineer');
    const tg = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: h,
      body: { name: 'Slice TG' },
    });
    assert.equal(tg.status, 201);
    const tgId = tg.json.id;

    const tgt = await request(baseUrl, 'POST', `/v1/target-groups/${tgId}/targets`, {
      headers: h,
      body: { value: 'slice.example.com', kind: 'fqdn' },
    });
    assert.equal(tgt.status, 201);

    const run = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: h,
      body: {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: tgId,
        target_id: tgt.json.id,
      },
    });
    assert.equal(run.status, 201);
    const runId = run.json.run.id;
    // Inline simulation records a probe_result event; the run enters collecting.
    assert.equal(run.json.run.status, 'collecting');

    const events = await request(baseUrl, 'GET', `/v1/test-runs/${runId}/events`, { headers: h });
    assert.ok(events.json.items.some((e) => e.signal_type === 'probe_result'));
    // Verdicts come from external probe evidence only — never an agent observation.
    assert.equal(events.json.items.some((e) => e.signal_type === 'agent_observation'), false);

    const report = await request(baseUrl, 'POST', '/v1/reports', {
      headers: demoHeaders('admin'),
      body: { kind: 'technical' },
    });
    assert.equal(report.status, 201);
    assert.ok(report.json.summary.readiness_score >= 0);

    const reports = await request(baseUrl, 'GET', '/v1/reports', { headers: demoHeaders('admin') });
    assert.equal(reports.status, 200);
    assert.ok(reports.json.items.some((item) => item.id === report.json.id));
    // The portal builds its kind/format dropdowns from these authoritative enums.
    assert.deepEqual(
      reports.json.capabilities.kinds.map((option) => option.value),
      [...REPORT_KINDS],
    );
    assert.deepEqual(
      reports.json.capabilities.formats.map((option) => option.value),
      [...REPORT_EXPORT_FORMATS],
    );
    assert.equal(reports.json.capabilities.kinds[0].label, 'Executive');
    assert.equal(reports.json.capabilities.default_kind, 'technical');

    const badFormat = await request(
      baseUrl,
      'GET',
      `/v1/reports/${report.json.id}/export?format=pdf`,
      { headers: demoHeaders('admin') },
    );
    assert.equal(badFormat.status, 400);
    assert.equal(badFormat.json.error, 'unsupported_format');
    assert.deepEqual(badFormat.json.supported_formats, [...REPORT_EXPORT_FORMATS]);

    const reportExport = await request(
      baseUrl,
      'GET',
      `/v1/reports/${report.json.id}/export?format=json`,
      { headers: demoHeaders('admin') },
    );
    assert.equal(reportExport.status, 200);

    const audit = await request(baseUrl, 'GET', '/v1/audit-log', { headers: demoHeaders('admin') });
    assert.ok(audit.json.items.some((a) => a.action === 'test_run.started'));
  });

  it('rejects public ingestion of reserved internal signal types', async () => {
    const h = demoHeaders('engineer');
    // agent_observation is a reserved internal signal type; a public caller cannot spoof it.
    const res = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: {
        event_id: 'evt_public_spoof',
        signal_type: 'agent_observation',
        source: 'external',
      },
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'reserved_signal_type');
  });

  it('blocks concurrent runs on one target group', async () => {
    const h = demoHeaders('engineer');
    const tg = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: h,
      body: { name: 'Concurrent TG' },
    });
    assert.equal(tg.status, 201);
    const tgId = tg.json.id;
    const tgt = await request(baseUrl, 'POST', `/v1/target-groups/${tgId}/targets`, {
      headers: h,
      body: { value: '203.0.113.9', kind: 'ip' },
    });
    assert.equal(tgt.status, 201);
    const tgtId = tgt.json.id;
    const first = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: h,
      body: {
        check_id: 'l3.forbidden_tcp_port.safe',
        target_group_id: tgId,
        target_id: tgtId,
      },
    });
    assert.equal(first.status, 201);
    const second = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: h,
      body: {
        check_id: 'l3.forbidden_tcp_port.safe',
        target_group_id: tgId,
        target_id: tgtId,
      },
    });
    assert.equal(second.status, 409);
  });
});
