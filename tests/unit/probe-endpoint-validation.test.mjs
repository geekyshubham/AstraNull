import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { validateProbeEndpoint } from '../../src/lib/probeEndpoint.mjs';
import { freshStore } from '../helpers/reset.mjs';

afterEach(() => {
  freshStore();
});

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
