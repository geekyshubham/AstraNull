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

function validProbeEndpoint(overrides = {}) {
  return {
    declared_fqdn: matchingFqdn,
    declared_ip: '203.0.113.10',
    discovered_public_ip: '203.0.113.55',
    discovered_via: 'operator_env',
    listen_port: 18080,
    path_prefix: '/astranull-canary',
    ...overrides,
  };
}

async function registerAgentWithPrebind({ hostname, prebindFqdn = matchingFqdn } = {}) {
  const h = demoHeaders('engineer');
  const tg = await request(baseUrl, 'POST', '/v1/target-groups', {
    headers: h,
    body: { name: `Probe TG ${hostname}`, environment_id: 'env_demo' },
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
    prebind_fqdn: prebindFqdn,
    max_registrations: 1,
  });

  const reg = await request(baseUrl, 'POST', '/v1/agents/register', {
    headers: demoHeaders('engineer'),
    body: {
      bootstrap_token: secret,
      hostname,
      name: hostname,
      capabilities: ['canary', 'heartbeat'],
    },
  });
  assert.equal(reg.status, 201);

  return {
    agentId: reg.json.agent.id,
    agentCredential: reg.json.agent_credential,
  };
}

function agentFromList(listResponse, agentId) {
  assert.equal(listResponse.status, 200);
  const agent = listResponse.json.items.find((item) => item.id === agentId);
  assert.ok(agent, `agent ${agentId} not in fleet list`);
  return agent;
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

describe('agent heartbeat probe_endpoint API', () => {
  it('accepts a valid probe_endpoint matching prebind and target group', async () => {
    const { agentId, agentCredential } = await registerAgentWithPrebind({
      hostname: 'probe-accept-host',
    });

    const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(agentCredential),
      body: {
        version: '0.2.0-production-readiness',
        probe_endpoint: validProbeEndpoint(),
      },
    });
    assert.equal(hb.status, 200);
    assert.equal(hb.json.probe_endpoint_accepted, true);

    const listed = await request(baseUrl, 'GET', '/v1/agents', { headers: demoHeaders('engineer') });
    const agent = agentFromList(listed, agentId);
    assert.equal(agent.probe_endpoint.declared_fqdn, matchingFqdn);
    assert.equal(agent.probe_endpoint_status, 'reported');
    assert.equal(agent.last_token_validation_status, 'valid');
  });

  it('rejects probe_endpoint when declared_fqdn mismatches token prebind_fqdn', async () => {
    const { agentId, agentCredential } = await registerAgentWithPrebind({
      hostname: 'probe-prebind-host',
    });

    const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(agentCredential),
      body: {
        version: '0.2.0-production-readiness',
        probe_endpoint: { declared_fqdn: 'evil.example.com' },
      },
    });
    assert.equal(hb.status, 200);
    assert.equal(hb.json.probe_endpoint_accepted, false);

    const listed = await request(baseUrl, 'GET', '/v1/agents', { headers: demoHeaders('engineer') });
    const agent = agentFromList(listed, agentId);
    assert.equal(agent.probe_endpoint_status, 'rejected');
  });

  it('rejects invalid probe_endpoint schema while heartbeat succeeds', async () => {
    const { agentId, agentCredential } = await registerAgentWithPrebind({
      hostname: 'probe-schema-host',
    });

    const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(agentCredential),
      body: {
        version: '0.2.0-production-readiness',
        probe_endpoint: { declared_ip: '127.0.0.1' },
      },
    });
    assert.equal(hb.status, 200);
    assert.equal(hb.json.probe_endpoint_accepted, false);
  });
});