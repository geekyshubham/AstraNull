import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { checkProbeEndpointBinding } from '../../src/lib/probeEndpoint.mjs';
import { heartbeatAgent, revokeAgent } from '../../src/services/agents.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

afterEach(() => {
  freshStore();
});

const matchingFqdn = 'api.shop.example.com';

function probeEndpointWithFqdn(fqdn) {
  return {
    declared_fqdn: fqdn,
    discovered_public_ip: '203.0.113.55',
    listen_port: 18080,
    path_prefix: '/astranull-canary',
    discovered_via: 'dns_resolve',
  };
}

function seedBindingFixture() {
  const tokenId = 'token_prebind';
  const targetGroupId = 'tg_shop';
  getStore().bootstrapTokens.push({
    id: tokenId,
    tenant_id: 'ten_demo',
    prebind_fqdn: matchingFqdn,
  });
  getStore().targets.push({
    id: 'tgt_fqdn',
    tenant_id: 'ten_demo',
    target_group_id: targetGroupId,
    kind: 'fqdn',
    value: matchingFqdn,
  });
  const agent = {
    id: 'agent_bind',
    tenant_id: 'ten_demo',
    name: 'bind-agent',
    hostname: 'host',
    fingerprint: 'AA:BB:CC',
    status: 'online',
    bootstrap_token_id: tokenId,
    target_group_id: targetGroupId,
  };
  getStore().agents.push(agent);
  return agent;
}

describe('checkProbeEndpointBinding', () => {
  it('passes when declared_fqdn is absent', () => {
    const result = checkProbeEndpointBinding({ discovered_public_ip: '203.0.113.1' });
    assert.equal(result.ok, true);
  });

  it('passes when fqdn matches prebind and is in target list', () => {
    const result = checkProbeEndpointBinding(
      { declared_fqdn: matchingFqdn },
      { prebindFqdn: matchingFqdn, targetGroupFqdns: [matchingFqdn] },
    );
    assert.equal(result.ok, true);
  });

  it('fails fqdn_prebind_mismatch on mismatch', () => {
    const result = checkProbeEndpointBinding(
      { declared_fqdn: matchingFqdn },
      { prebindFqdn: 'other.example.com', targetGroupFqdns: [matchingFqdn] },
    );
    assert.equal(result.ok, false);
    assert.equal(result.error, 'fqdn_prebind_mismatch');
  });

  it('fails target_group_mismatch when fqdn not in non-empty target list', () => {
    const result = checkProbeEndpointBinding(
      { declared_fqdn: matchingFqdn },
      { prebindFqdn: matchingFqdn, targetGroupFqdns: ['cdn.example.com'] },
    );
    assert.equal(result.ok, false);
    assert.equal(result.error, 'target_group_mismatch');
  });

  it('passes when prebind is null and target list is empty without resolved group', () => {
    const result = checkProbeEndpointBinding(
      { declared_fqdn: matchingFqdn },
      { prebindFqdn: null, targetGroupFqdns: [] },
    );
    assert.equal(result.ok, true);
  });

  it('fails target_group_mismatch when group is resolved but fqdn list is empty', () => {
    const result = checkProbeEndpointBinding(
      { declared_fqdn: matchingFqdn },
      { prebindFqdn: matchingFqdn, targetGroupFqdns: [], targetGroupResolved: true },
    );
    assert.equal(result.ok, false);
    assert.equal(result.error, 'target_group_mismatch');
  });

  it('passes when group is resolved and fqdn is in target list', () => {
    const result = checkProbeEndpointBinding(
      { declared_fqdn: matchingFqdn },
      {
        prebindFqdn: matchingFqdn,
        targetGroupFqdns: [matchingFqdn],
        targetGroupResolved: true,
      },
    );
    assert.equal(result.ok, true);
  });
});

describe('heartbeatAgent probe_endpoint binding', () => {
  it('accepts matching declared_fqdn against prebind and target group', () => {
    freshStore();
    const agent = seedBindingFixture();
    const result = heartbeatAgent(agent, {
      probe_endpoint: probeEndpointWithFqdn('API.Shop.Example.COM'),
    });

    assert.equal(result.probe_endpoint_accepted, true);
    assert.equal(agent.probe_endpoint_status, 'reported');
    assert.equal(agent.probe_endpoint.declared_fqdn, matchingFqdn);
    assert.equal(agent.probe_endpoint_error, undefined);
  });

  it('rejects mismatching declared_fqdn with fqdn_prebind_mismatch', () => {
    freshStore();
    const agent = seedBindingFixture();
    agent.probe_endpoint = {
      declared_fqdn: matchingFqdn,
      discovered_public_ip: '203.0.113.10',
    };
    agent.probe_endpoint_status = 'reported';

    const result = heartbeatAgent(agent, {
      probe_endpoint: probeEndpointWithFqdn('wrong.example.com'),
    });

    assert.equal(result.probe_endpoint_accepted, false);
    assert.equal(agent.probe_endpoint_status, 'rejected');
    assert.equal(agent.probe_endpoint_error, 'fqdn_prebind_mismatch');
    assert.equal(agent.probe_endpoint.declared_fqdn, matchingFqdn);
  });
});

describe('revokeAgent', () => {
  it('sets last_token_validation_status to invalid', () => {
    freshStore();
    const agent = {
      id: 'agent_revoke',
      tenant_id: 'ten_demo',
      name: 'revoke-agent',
      hostname: 'host',
      status: 'online',
      last_token_validation_status: 'valid',
    };
    getStore().agents.push(agent);

    revokeAgent({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' }, 'agent_revoke');

    assert.equal(agent.last_token_validation_status, 'invalid');
  });
});