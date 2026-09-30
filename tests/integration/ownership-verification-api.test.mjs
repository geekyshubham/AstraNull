import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let baseUrl;
let server;

const matchingFqdn = 'api.shop.example.com';

// ADR-0008 (outside-in only): the agent-observed ownership challenge is removed. The
// /v1/ownership-verifications write endpoints stay wired for API stability but fail closed;
// ownership is proven through the DNS challenge instead.
async function createTargetGroupWithTarget() {
  const h = demoHeaders('engineer');
  const tg = await request(baseUrl, 'POST', '/v1/target-groups', {
    headers: h,
    body: { name: 'Ownership TG', environment_id: 'env_demo' },
  });
  assert.equal(tg.status, 201);
  const tgId = tg.json.id;

  const tgt = await request(baseUrl, 'POST', `/v1/target-groups/${tgId}/targets`, {
    headers: h,
    body: { value: matchingFqdn, kind: 'fqdn' },
  });
  assert.equal(tgt.status, 201);
  return { tgId };
}

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

describe('ownership verification API (outside-in)', () => {
  it('fails closed on challenge creation, still lists, and enforces RBAC', async () => {
    const { tgId } = await createTargetGroupWithTarget();
    const engineer = demoHeaders('engineer');

    const createRes = await request(baseUrl, 'POST', '/v1/ownership-verifications', {
      headers: engineer,
      body: { target_group_id: tgId },
    });
    assert.equal(createRes.status, 410);
    assert.equal(createRes.json.error, 'ownership_agent_flow_removed');

    const listRes = await request(baseUrl, 'GET', '/v1/ownership-verifications', {
      headers: engineer,
    });
    assert.equal(listRes.status, 200);
    assert.ok(Array.isArray(listRes.json.items));
    assert.equal(listRes.json.items.length, 0);

    // RBAC is still enforced ahead of the fail-closed body: a viewer cannot write.
    const viewerCreate = await request(baseUrl, 'POST', '/v1/ownership-verifications', {
      headers: demoHeaders('viewer'),
      body: { target_group_id: tgId },
    });
    assert.equal(viewerCreate.status, 403);
    assert.equal(viewerCreate.json.error, 'forbidden');
  });
});
