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
        body: { expected_behavior: 'should_be_protected' },
      },
    );
    assert.equal(targetPatched.status, 200);
    assert.equal(targetPatched.json.expected_behavior, 'should_be_protected');

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

  it('list items carry target_count and loa_state without the detail-only fields', async () => {
    const engineer = demoHeaders('engineer');
    const created = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: engineer,
      body: { name: 'Summary group', environment_id: 'env_demo' },
    });
    const groupId = created.json.id;
    for (const value of ['one.example.com', 'two.example.com']) {
      const added = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/targets`, {
        headers: engineer,
        body: { value, kind: 'fqdn' },
      });
      assert.equal(added.status, 201);
    }

    const list = await request(baseUrl, 'GET', '/v1/target-groups', { headers: engineer });
    assert.equal(list.status, 200);

    const summary = list.json.items.find((g) => g.id === groupId);
    assert.equal(summary.target_count, 2);
    assert.equal(summary.loa_state, 'required');
    assert.equal(summary.targets, undefined);
    assert.equal(summary.runs_recent, undefined);
    assert.equal(summary.findings_on_group, undefined);

    // freshStore seeds a signed LOA for tg_1; the list must surface it, not just the detail route.
    const seeded = list.json.items.find((g) => g.id === 'tg_1');
    assert.equal(seeded.target_count, 1);
    assert.equal(seeded.loa_state, 'signed');

    const detail = await request(baseUrl, 'GET', `/v1/target-groups/${groupId}`, {
      headers: engineer,
    });
    assert.equal(detail.json.target_count, summary.target_count);
    assert.equal(detail.json.loa_state, summary.loa_state);
  });

  it('archived list items carry the same summary keys', async () => {
    const engineer = demoHeaders('engineer');
    const created = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: engineer,
      body: { name: 'Archived summary group' },
    });
    const groupId = created.json.id;
    await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/targets`, {
      headers: engineer,
      body: { value: 'archived.example.com', kind: 'fqdn' },
    });
    await request(baseUrl, 'DELETE', `/v1/target-groups/${groupId}`, { headers: engineer });

    const archived = await request(baseUrl, 'GET', '/v1/target-groups?archived=true', {
      headers: engineer,
    });
    assert.equal(archived.status, 200);
    const item = archived.json.items.find((g) => g.id === groupId);
    assert.equal(item.target_count, 1);
    assert.equal(item.loa_state, 'required');
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

  it('ignores ownership/provenance spoofing and enforces canonical scoped dedupe', async () => {
    const engineer = demoHeaders('engineer');
    const created = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: engineer,
      body: {
        name: 'Trust boundary group',
        environment_id: 'env_demo',
        ownership_status: 'user_confirmed',
        dns_ownership: { verified: true },
      },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.ownership_status, 'unverified');
    assert.equal(created.json.dns_ownership, null);

    const duplicateGroup = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: engineer,
      body: { name: ' trust boundary GROUP ', environment_id: 'env_demo' },
    });
    assert.equal(duplicateGroup.status, 409);
    assert.equal(duplicateGroup.json.error, 'target_group_exists');

    const target = await request(baseUrl, 'POST', `/v1/target-groups/${created.json.id}/targets`, {
      headers: engineer,
      body: {
        kind: 'hostname',
        value: 'WWW.Example.COM.',
        metadata: {
          notes: 'keep me',
          verification_state: 'user_confirmed',
          eligibility: 'eligible',
          source: 'trusted_connector',
          provenance: { trusted: true },
        },
      },
    });
    assert.equal(target.status, 201);
    assert.equal(target.json.kind, 'fqdn');
    assert.equal(target.json.value, 'www.example.com');
    assert.deepEqual(target.json.metadata, { notes: 'keep me' });

    const duplicateTarget = await request(baseUrl, 'POST', `/v1/target-groups/${created.json.id}/targets`, {
      headers: engineer,
      body: { kind: 'fqdn', value: 'www.example.com' },
    });
    assert.equal(duplicateTarget.status, 409);
    assert.equal(duplicateTarget.json.error, 'target_exists');

    const inventory = await request(baseUrl, 'GET', '/v1/targets', { headers: engineer });
    const item = inventory.json.items.find((row) => row.id === target.json.id);
    assert.equal(item.verification_state, 'unverified');
    assert.equal(item.eligibility, 'not_eligible');
    assert.equal(item.source, 'manual');
  });
});
