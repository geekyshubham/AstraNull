import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { validHighScaleRequestPayload } from '../helpers/highScalePayload.mjs';
import { closeServer, demoHeaders, request, staffHeaders } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;

before(() => {
  freshStore();
  const env = {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
    ASTRANULL_CONNECTORS_ENABLED: '1',
  };
  server = createServer({ runtimeConfig: loadRuntimeConfig(env), env });
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => closeServer(server));

function multipartCsv(csv, field = 'file') {
  const boundary = '----astranullCsvBoundary7MA4YWxk';
  const body = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="${field}"; filename="targets.csv"`,
    'Content-Type: text/csv',
    '',
    csv,
    `--${boundary}--`,
    '',
  ].join('\r\n');
  return { rawBody: body, headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` } };
}

function groupTargets(groupId = 'tg_1') {
  return getStore().targets.filter((target) => target.tenant_id === 'ten_demo' && target.target_group_id === groupId);
}

describe('connector creation preflight', () => {
  it('validates a connector without persisting it and reports the deployment gate consistently', async () => {
    const features = await request(baseUrl, 'GET', '/v1/tenant/deployment-features', { headers: demoHeaders('admin') });
    assert.equal(features.status, 200);
    assert.equal(features.json.connectors, true);

    const before = getStore().wafConnectors.length;
    const preflight = await request(baseUrl, 'POST', '/v1/connectors', {
      headers: demoHeaders('admin'),
      body: { provider: 'cloudflare', name: 'edge', status: 'active', config: { read_only: true }, validate_only: true },
    });
    assert.equal(preflight.status, 200);
    assert.equal(preflight.json.valid, true);
    assert.equal(getStore().wafConnectors.length, before);

    const invalid = await request(baseUrl, 'POST', '/v1/connectors', {
      headers: demoHeaders('admin'),
      body: { provider: 'not_a_provider', name: 'edge', validate_only: true },
    });
    assert.equal(invalid.status, 400);

    const created = await request(baseUrl, 'POST', '/v1/connectors', {
      headers: demoHeaders('admin'),
      body: { provider: 'cloudflare', name: 'edge', status: 'active', config: { read_only: true } },
    });
    assert.equal(created.status, 201);
    assert.equal(getStore().wafConnectors.length, before + 1);
  });
});

describe('staff SOC cross-tenant high-scale queue', () => {
  it('lists customer intake across tenants for staff SOC only, audits the read, and enables tenant kill switch', async () => {
    const intake = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'staff soc visibility' }),
    });
    assert.equal(intake.status, 201);

    const listed = await request(baseUrl, 'GET', '/internal/admin/soc/high-scale-requests', {
      headers: staffHeaders('soc_analyst', 'staff_soc_1'),
    });
    assert.equal(listed.status, 200);
    const row = listed.json.items.find((item) => item.id === intake.json.id);
    assert.ok(row, 'customer intake must appear in the staff SOC queue');
    assert.equal(row.tenant_id, 'ten_demo');
    assert.equal(row.state, intake.json.state);
    assert.equal(row.kind, 'high_scale');
    assert.equal(row.emergency_contacts, undefined);
    assert.ok(listed.json.tenants.some((tenant) => tenant.tenant_id === 'ten_demo'));

    const audit = getStore().internalAuditLog.find((entry) => entry.action === 'staff.soc.high_scale_queue_viewed');
    assert.ok(audit);
    assert.equal(audit.staff_id, 'staff_soc_1');

    for (const role of ['billing_ops', 'support_engineer', 'internal_admin']) {
      const denied = await request(baseUrl, 'GET', '/internal/admin/soc/high-scale-requests', { headers: staffHeaders(role) });
      assert.equal(denied.status, 403, role);
    }
    const customer = await request(baseUrl, 'GET', '/internal/admin/soc/high-scale-requests', { headers: demoHeaders('admin') });
    assert.notEqual(customer.status, 200);

    const approveByAdmin = await request(baseUrl, 'POST', `/internal/soc/high-scale/${intake.json.id}/approve`, {
      headers: demoHeaders('admin'),
    });
    assert.equal(approveByAdmin.status, 403);

    const killOn = await request(baseUrl, 'POST', '/internal/soc/kill-switch', {
      headers: demoHeaders('soc', row.tenant_id, 'staff_soc_1'),
      body: { active: true, reason: 'staff soc drill' },
    });
    assert.equal(killOn.status, 200);
    const killOff = await request(baseUrl, 'POST', '/internal/soc/kill-switch', {
      headers: demoHeaders('soc', row.tenant_id, 'staff_soc_1'),
      body: { active: false },
    });
    assert.equal(killOff.status, 200);
  });
});

describe('agent update list resilience', () => {
  it('returns 200 and skips a malformed stored release', async () => {
    getStore().agentUpdateReleases.push({ id: 'aurel_bad', tenant_id: 'ten_demo', version: '0.0.1', status: 'published' });
    const res = await request(baseUrl, 'GET', '/v1/agent-updates', { headers: demoHeaders('admin') });
    assert.equal(res.status, 200);
    const items = res.json.items ?? res.json;
    assert.equal(items.some((item) => item.id === 'aurel_bad'), false);
  });
});

describe('customer target CSV import', () => {
  it('imports a multipart file field with a header row and audits the import', async () => {
    const beforeCount = groupTargets().length;
    const res = await request(baseUrl, 'POST', '/v1/target-groups/tg_1/targets:csv', {
      ...multipartCsv('kind,value,expected_behavior\nfqdn,csv-a.example.com,must_block_before_origin\nip,192.0.2.10,\n'),
      headers: { ...demoHeaders('engineer'), ...multipartCsv('').headers },
    });
    assert.equal(res.status, 201, res.text);
    assert.deepEqual(res.json.errors, []);
    assert.deepEqual(res.json.created.map((target) => [target.kind, target.value]), [
      ['fqdn', 'csv-a.example.com'],
      ['ip', '192.0.2.10'],
    ]);
    assert.equal(groupTargets().length, beforeCount + 2);
    const auditLog = getStore().auditLog;
    const summary = auditLog.find((entry) => entry.action === 'target.csv_imported');
    assert.ok(summary);
    assert.equal(summary.metadata.created_count, 2);
  });

  it('accepts headerless text/csv and infers ip/url/fqdn kinds', async () => {
    const res = await request(baseUrl, 'POST', '/v1/target-groups/tg_1/targets:csv', {
      rawBody: 'csv-b.example.com\r\n198.51.100.7\r\nhttps://csv-c.example.com/login\r\n',
      headers: { ...demoHeaders('admin'), 'Content-Type': 'text/csv' },
    });
    assert.equal(res.status, 201, res.text);
    assert.deepEqual(res.json.created.map((target) => target.kind), ['fqdn', 'ip', 'url']);
  });

  it('rejects the whole file with per-row errors when any row is invalid', async () => {
    const beforeCount = groupTargets().length;
    const res = await request(baseUrl, 'POST', '/v1/target-groups/tg_1/targets:csv', {
      body: { csv: 'kind,value\nfqdn,csv-d.example.com\nfqdn,not a host!\nfqdn,csv-d.example.com\nfqdn,csv-a.example.com\n' },
      headers: demoHeaders('admin'),
    });
    assert.equal(res.status, 422);
    assert.equal(res.json.error, 'csv_import_rejected');
    assert.deepEqual(res.json.created, []);
    assert.deepEqual(res.json.errors.map((entry) => [entry.row, entry.error]), [
      [3, 'invalid_target'],
      [4, 'duplicate_row'],
      [5, 'target_exists'],
    ]);
    assert.equal(groupTargets().length, beforeCount);
  });

  it('enforces RBAC, row limits, unknown columns, and target group scope', async () => {
    const viewer = await request(baseUrl, 'POST', '/v1/target-groups/tg_1/targets:csv', {
      body: { csv: 'value\ncsv-e.example.com\n' },
      headers: demoHeaders('viewer'),
    });
    assert.equal(viewer.status, 403);

    const rows = Array.from({ length: 1001 }, (_, index) => `host-${index}.csv-limit.example.com`).join('\n');
    const tooMany = await request(baseUrl, 'POST', '/v1/target-groups/tg_1/targets:csv', {
      rawBody: `value\n${rows}\n`,
      headers: { ...demoHeaders('admin'), 'Content-Type': 'text/csv' },
    });
    assert.equal(tooMany.status, 413);
    assert.equal(tooMany.json.error, 'csv_too_many_rows');

    const unknown = await request(baseUrl, 'POST', '/v1/target-groups/tg_1/targets:csv', {
      body: { csv: 'value,owner\ncsv-f.example.com,alice\n' },
      headers: demoHeaders('admin'),
    });
    assert.equal(unknown.status, 400);
    assert.equal(unknown.json.error, 'invalid_csv');

    const missingField = await request(baseUrl, 'POST', '/v1/target-groups/tg_1/targets:csv', {
      ...multipartCsv('value\ncsv-g.example.com\n', 'upload'),
      headers: { ...demoHeaders('admin'), ...multipartCsv('', 'upload').headers },
    });
    assert.equal(missingField.status, 400);

    const otherTenant = await request(baseUrl, 'POST', '/v1/target-groups/tg_1/targets:csv', {
      body: { csv: 'value\ncsv-h.example.com\n' },
      headers: demoHeaders('admin', 'ten_other'),
    });
    assert.equal(otherTenant.status, 404);
  });
});
