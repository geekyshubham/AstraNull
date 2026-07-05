import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { validateProbeEndpoint } from '../../src/lib/probeEndpoint.mjs';
import { heartbeatAgent } from '../../src/services/agents.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

afterEach(() => {
  freshStore();
});

function seedAgent({ id = 'agent_test', tenantId = 'ten_demo' } = {}) {
  const agent = {
    id,
    tenant_id: tenantId,
    name: 'test-agent',
    hostname: 'host',
    fingerprint: 'AA:BB:CC',
    status: 'online',
  };
  getStore().agents.push(agent);
  return agent;
}

const validEndpoint = {
  declared_fqdn: 'API.Shop.Example.COM',
  discovered_public_ip: '203.0.113.55',
  listen_port: 18080,
  path_prefix: '/astranull-canary',
  discovered_via: 'dns_resolve',
  extra_field: 'drop-me',
};

describe('validateProbeEndpoint', () => {
  it('accepts a valid endpoint and returns normalized fields without unknown keys', () => {
    const result = validateProbeEndpoint(validEndpoint);
    assert.equal(result.ok, true);
    assert.deepEqual(result.normalized, {
      declared_fqdn: 'api.shop.example.com',
      discovered_public_ip: '203.0.113.55',
      listen_port: 18080,
      path_prefix: '/astranull-canary',
      discovered_via: 'dns_resolve',
    });
    assert.equal(result.normalized.extra_field, undefined);
  });

  it('rejects empty object and missing identifiers', () => {
    assert.equal(validateProbeEndpoint({}).ok, false);
    assert.equal(validateProbeEndpoint({ listen_port: 443 }).ok, false);
    assert.equal(validateProbeEndpoint(null).error, 'invalid_probe_endpoint');
  });

  it('rejects bad declared_fqdn values', () => {
    const cases = [
      { declared_fqdn: 'https://x', discovered_public_ip: '203.0.113.1' },
      { declared_fqdn: 'a/b', discovered_public_ip: '203.0.113.1' },
      { declared_fqdn: 'a@b', discovered_public_ip: '203.0.113.1' },
      { declared_fqdn: 'host:80', discovered_public_ip: '203.0.113.1' },
    ];
    for (const endpoint of cases) {
      const result = validateProbeEndpoint(endpoint);
      assert.equal(result.ok, false, JSON.stringify(endpoint));
      assert.equal(result.error, 'invalid_probe_endpoint');
    }
  });

  it('rejects private, loopback, link-local, and metadata IPs by default', () => {
    const cases = [
      { declared_ip: '10.0.0.1' },
      { declared_ip: '127.0.0.1' },
      { declared_ip: '169.254.1.1' },
      { declared_ip: '169.254.169.254' },
      { discovered_public_ip: '192.168.0.5' },
    ];
    for (const endpoint of cases) {
      const result = validateProbeEndpoint(endpoint);
      assert.equal(result.ok, false, JSON.stringify(endpoint));
    }
  });

  it('rejects out-of-range port, bad path_prefix, and bad discovered_via', () => {
    assert.equal(
      validateProbeEndpoint({
        declared_fqdn: 'api.example.com',
        listen_port: 70000,
      }).ok,
      false,
    );
    assert.equal(
      validateProbeEndpoint({
        declared_fqdn: 'api.example.com',
        listen_port: '443',
      }).ok,
      false,
    );
    assert.equal(
      validateProbeEndpoint({
        declared_fqdn: 'api.example.com',
        path_prefix: 'no-slash',
      }).ok,
      false,
    );
    assert.equal(
      validateProbeEndpoint({
        declared_fqdn: 'api.example.com',
        discovered_via: 'guesswork',
      }).ok,
      false,
    );
  });

  it('allowPrivate accepts RFC1918 declared_ip but still rejects loopback and metadata', () => {
    const allowed = validateProbeEndpoint(
      { declared_ip: '10.1.2.3' },
      { allowPrivate: true },
    );
    assert.equal(allowed.ok, true);

    const loopback = validateProbeEndpoint(
      { declared_ip: '127.0.0.1' },
      { allowPrivate: true },
    );
    assert.equal(loopback.ok, false);

    const metadata = validateProbeEndpoint(
      { declared_ip: '169.254.169.254' },
      { allowPrivate: true },
    );
    assert.equal(metadata.ok, false);
  });
});

describe('heartbeatAgent probe_endpoint', () => {
  it('accepts valid probe_endpoint on heartbeat', () => {
    freshStore();
    const agent = seedAgent();
    const result = heartbeatAgent(agent, {
      version: '9.9.9',
      probe_endpoint: validEndpoint,
    });

    assert.equal(result.probe_endpoint_accepted, true);
    assert.equal(agent.probe_endpoint_status, 'reported');
    assert.equal(agent.probe_endpoint.declared_fqdn, 'api.shop.example.com');
    assert.equal(agent.last_token_validation_status, 'valid');
    assert.ok(agent.last_token_validation_at);
    assert.equal(result.agent.id, agent.id);

    const heartbeatAudit = getStore().auditLog.find((a) => a.action === 'agent.heartbeat');
    assert.equal(heartbeatAudit.metadata.token_valid, true);
    assert.equal(heartbeatAudit.metadata.probe_endpoint_accepted, true);
  });

  it('rejects invalid probe_endpoint but heartbeat still succeeds', () => {
    freshStore();
    const agent = seedAgent();
    agent.probe_endpoint = {
      declared_fqdn: 'kept.example.com',
      discovered_public_ip: '203.0.113.10',
    };
    agent.probe_endpoint_status = 'reported';

    const result = heartbeatAgent(agent, {
      version: '1.0.0',
      probe_endpoint: { declared_ip: '127.0.0.1' },
    });

    assert.equal(result.probe_endpoint_accepted, false);
    assert.equal(agent.probe_endpoint_status, 'rejected');
    assert.equal(agent.probe_endpoint_error, 'invalid_probe_endpoint');
    assert.equal(agent.probe_endpoint.declared_fqdn, 'kept.example.com');
    assert.ok(result.agent);
    assert.equal(result.agent.id, agent.id);
  });
});