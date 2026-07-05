import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildProbeEndpoint } from '../../agents/linux/astranull-agent.mjs';

describe('buildProbeEndpoint', () => {
  it('builds from public FQDN and canary env vars', () => {
    const result = buildProbeEndpoint({
      env: {
        ASTRANULL_PUBLIC_FQDN: 'api.shop.example.com',
        ASTRANULL_CANARY_LISTEN: '18080',
        ASTRANULL_CANARY_PATH_PREFIX: '/astranull-canary',
      },
      args: {},
    });
    assert.deepEqual(result, {
      declared_fqdn: 'api.shop.example.com',
      listen_port: 18080,
      path_prefix: '/astranull-canary',
      discovered_via: 'operator_env',
    });
  });

  it('builds from public IP only', () => {
    const result = buildProbeEndpoint({
      env: { ASTRANULL_PUBLIC_IP: '203.0.113.10' },
      args: {},
    });
    assert.deepEqual(result, {
      declared_ip: '203.0.113.10',
      discovered_via: 'operator_env',
    });
  });

  it('returns null when no identifying fields are configured', () => {
    assert.equal(buildProbeEndpoint({ env: {}, args: {} }), null);
  });

  it('returns null when only canary port is configured', () => {
    const result = buildProbeEndpoint({
      env: { ASTRANULL_CANARY_LISTEN: '18080' },
      args: {},
    });
    assert.equal(result, null);
  });
});