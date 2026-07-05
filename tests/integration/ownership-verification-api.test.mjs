import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { agentHeaders, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { createBootstrapToken } from '../../src/services/tokens.mjs';

let baseUrl;
let server;

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
const matchingFqdn = 'api.shop.example.com';

async function registerAgentWithProbeEndpoint() {
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

  const { secret } = createBootstrapToken(ctx, {
    target_group_id: tgId,
    prebind_fqdn: matchingFqdn,
    max_registrations: 1,
  });

  const reg = await request(baseUrl, 'POST', '/v1/agents/register', {
    headers: demoHeaders('engineer'),
    body: {
      bootstrap_token: secret,
      hostname: 'ownership-agent-host',
      name: 'ownership-agent-host',
      capabilities: ['canary', 'heartbeat'],
    },
  });
  assert.equal(reg.status, 201);

  const agentId = reg.json.agent.id;
  const agentCredential = reg.json.agent_credential;

  const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
    headers: agentHeaders(agentCredential),
    body: {
      version: '0.2.0-production-readiness',
      probe_endpoint: { declared_fqdn: matchingFqdn },
    },
  });
  assert.equal(hb.status, 200);
  assert.equal(hb.json.probe_endpoint_accepted, true);

  return { tgId, agentId };
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

describe('ownership verification API', () => {
  it('creates challenge, lists record, rejects early confirm, enforces RBAC', async () => {
    const { tgId, agentId } = await registerAgentWithProbeEndpoint();
    const engineer = demoHeaders('engineer');

    const createRes = await request(baseUrl, 'POST', '/v1/ownership-verifications', {
      headers: engineer,
      body: { target_group_id: tgId, agent_id: agentId },
    });
    assert.equal(createRes.status, 201);
    assert.equal(createRes.json.verification.status, 'challenge_sent');
    assert.equal(typeof createRes.json.nonce, 'string');
    assert.ok(createRes.json.nonce.length > 0);
    const verificationId = createRes.json.verification.id;

    const listRes = await request(baseUrl, 'GET', '/v1/ownership-verifications', {
      headers: engineer,
    });
    assert.equal(listRes.status, 200);
    const listed = listRes.json.items.find((item) => item.id === verificationId);
    assert.ok(listed, 'verification appears in list');
    assert.equal(listed.status, 'challenge_sent');

    const confirmEarly = await request(
      baseUrl,
      'POST',
      `/v1/ownership-verifications/${verificationId}/confirm`,
      { headers: engineer },
    );
    assert.equal(confirmEarly.status, 409);
    assert.equal(confirmEarly.json.error, 'ownership_not_verified');

    const viewerCreate = await request(baseUrl, 'POST', '/v1/ownership-verifications', {
      headers: demoHeaders('viewer'),
      body: { target_group_id: tgId, agent_id: agentId },
    });
    assert.equal(viewerCreate.status, 403);
    assert.equal(viewerCreate.json.error, 'forbidden');
  });
});