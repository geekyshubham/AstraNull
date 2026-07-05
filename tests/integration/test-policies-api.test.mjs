import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;

before(() => {
  freshStore();
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => {
  server?.close();
});

beforeEach(() => {
  freshStore();
});

describe('test policies API', () => {
  it('creates, lists, updates, and archives safe validation policies', async () => {
    const engineer = demoHeaders('engineer');

    const created = await request(baseUrl, 'POST', '/v1/test-policies', {
      headers: engineer,
      body: {
        target_group_id: 'tg_1',
        check_id: 'dns.authoritative_response.safe',
        cadence: 'weekly',
        expected_verdict: 'pass',
        safe_windows: [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'UTC' }],
      },
    });

    assert.equal(created.status, 201);
    assert.equal(created.json.target_group_id, 'tg_1');
    assert.equal(created.json.check_id, 'dns.authoritative_response.safe');
    assert.equal(created.json.cadence, 'weekly');
    assert.equal(created.json.check.safety_class, 'safe');
    assert.equal(created.json.target_group.name, 'TG');

    const listed = await request(baseUrl, 'GET', '/v1/test-policies', { headers: engineer });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.items.length, 1);
    assert.equal(listed.json.items[0].id, created.json.id);
    assert.equal(listed.json.items[0].target_count, 1);

    const patched = await request(baseUrl, 'PATCH', `/v1/test-policies/${created.json.id}`, {
      headers: engineer,
      body: { cadence: 'monthly', expected_verdict: 'warn' },
    });
    assert.equal(patched.status, 200);
    assert.equal(patched.json.cadence, 'monthly');
    assert.equal(patched.json.expected_verdict, 'warn');

    const archived = await request(baseUrl, 'DELETE', `/v1/test-policies/${created.json.id}`, {
      headers: engineer,
    });
    assert.equal(archived.status, 200);
    assert.equal(archived.json.archived, true);

    const listedAfterArchive = await request(baseUrl, 'GET', '/v1/test-policies', { headers: engineer });
    assert.equal(listedAfterArchive.status, 200);
    assert.equal(listedAfterArchive.json.items.length, 0);
  });

  it('rejects SOC-gated checks as customer-runnable policy bindings', async () => {
    const engineer = demoHeaders('engineer');
    const created = await request(baseUrl, 'POST', '/v1/test-policies', {
      headers: engineer,
      body: {
        target_group_id: 'tg_1',
        check_id: 'high_scale.volumetric.request_only',
        cadence: 'manual',
      },
    });

    assert.equal(created.status, 403);
    assert.equal(created.json.error, 'soc_gated_check');
  });
});
