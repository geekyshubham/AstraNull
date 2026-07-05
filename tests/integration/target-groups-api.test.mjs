import assert from 'node:assert/strict';
import { after, beforeEach, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
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

describe('target groups API CRUD', () => {
  it('patches, archives groups, and manages targets', async () => {
    const engineer = demoHeaders('engineer');
    const created = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: engineer,
      body: { name: 'API group', environment_id: 'env_demo' },
    });
    assert.equal(created.status, 201);
    const groupId = created.json.id;

    const patched = await request(baseUrl, 'PATCH', `/v1/target-groups/${groupId}`, {
      headers: engineer,
      body: { name: 'API group updated', description: 'patched' },
    });
    assert.equal(patched.status, 200);
    assert.equal(patched.json.name, 'API group updated');

    const target = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/targets`, {
      headers: engineer,
      body: { value: 'api.example.com', kind: 'fqdn' },
    });
    assert.equal(target.status, 201);
    const targetId = target.json.id;

    const targetPatched = await request(
      baseUrl,
      'PATCH',
      `/v1/target-groups/${groupId}/targets/${targetId}`,
      {
        headers: engineer,
        body: { value: 'api-updated.example.com' },
      },
    );
    assert.equal(targetPatched.status, 200);
    assert.equal(targetPatched.json.value, 'api-updated.example.com');

    const targetDeleted = await request(
      baseUrl,
      'DELETE',
      `/v1/target-groups/${groupId}/targets/${targetId}`,
      { headers: engineer },
    );
    assert.equal(targetDeleted.status, 200);
    assert.equal(targetDeleted.json.deleted, true);

    const archived = await request(baseUrl, 'DELETE', `/v1/target-groups/${groupId}`, {
      headers: engineer,
    });
    assert.equal(archived.status, 200);
    assert.equal(archived.json.archived, true);

    const list = await request(baseUrl, 'GET', '/v1/target-groups', { headers: engineer });
    assert.equal(list.status, 200);
    assert.equal(list.json.items.some((g) => g.id === groupId), false);

    const state = await request(baseUrl, 'GET', '/v1/state', { headers: engineer });
    assert.equal(state.status, 200);
    assert.equal(state.json.target_groups, 1);
    assert.match(state.json.readiness.factors[0].detail, /1 target group/);
    assert.equal(
      state.json.readiness.factors.find((factor) => factor.key === 'agent_placement')
        .placement_diagnostics.total_groups,
      1,
    );

    const run = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: engineer,
      body: {
        target_group_id: groupId,
        check_id: 'dns.authoritative_response.safe',
      },
    });
    assert.equal(run.status, 404);
    assert.equal(run.json.error, 'target_group_not_found');
  });

  it('returns 409 when archiving a group with an active run', async () => {
    const engineer = demoHeaders('engineer');
    const created = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: engineer,
      body: { name: 'Busy API group' },
    });
    const groupId = created.json.id;
    const target = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/targets`, {
      headers: engineer,
      body: { value: 'busy.example.com' },
    });

    getStore().testRuns.push({
      id: 'run_busy',
      tenant_id: 'ten_demo',
      target_group_id: groupId,
      target_id: target.json.id,
      status: 'running',
      check_id: 'dns_authority_exposure',
    });

    const archived = await request(baseUrl, 'DELETE', `/v1/target-groups/${groupId}`, {
      headers: engineer,
    });
    assert.equal(archived.status, 409);
    assert.equal(archived.json.error, 'target_group_active_run');
  });
});
