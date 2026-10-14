import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import '../helpers/reset.mjs';
import { createServer } from '../../src/server.mjs';
import {
  CONTROL_DECLARATIONS_VERSION,
  ControlDeclarationsValidationError,
  declaredBlockSignature,
  declaredNetworkPolicyFor,
  declaredPortsForBoundedScan,
  emptyControlDeclarations,
  mapDeclaredBlockSignatureForProbe,
  normalizeControlDeclarations,
  probeDeclarationsSubset,
  summarizeControlDeclarationsForAudit,
} from '../../src/contracts/controlDeclarations.mjs';
import {
  DEFAULT_PROBE_PERSPECTIVES,
  listProbePerspectives,
  loadProbePerspectivesFromEnv,
} from '../../src/lib/probePerspectiveRegistry.mjs';

const TARGET = { kind: 'fqdn', value: 'origin.test' };

function accept(input, options = {}) {
  return normalizeControlDeclarations(input, { target: TARGET, ...options });
}

function reject(input, field, options = {}) {
  assert.throws(
    () => normalizeControlDeclarations(input, { target: TARGET, ...options }),
    (error) => {
      assert.equal(error instanceof ControlDeclarationsValidationError, true);
      assert.equal(error.code, 'invalid_control_declarations');
      assert.equal(error.status, 400);
      if (field) assert.equal(error.field, field);
      const body = error.toResponse();
      assert.equal(body.error, 'invalid_control_declarations');
      assert.equal(Array.isArray(body.errors), true);
      assert.ok(body.errors.length >= 1);
      return true;
    },
  );
}

describe('normalizeControlDeclarations', () => {
  it('exports version 1 and empty document', () => {
    assert.equal(CONTROL_DECLARATIONS_VERSION, 1);
    assert.deepEqual(emptyControlDeclarations(), { version: 1 });
  });

  it('accepts an empty object and a full valid document', () => {
    assert.deepEqual(accept({}), { version: 1 });
    assert.deepEqual(accept({ version: 1 }), { version: 1 });
    const out = accept({
      version: 1,
      network_policy: [
        { protocol: 'TCP', port: 22, action: 'Deny', address_family: 'Any', note: ' ssh ' },
      ],
      waf: {
        block_signature: {
          header_name: 'X-WAF-Block',
          header_value: 'edge-deny',
          status_codes: [403, 403, 406],
        },
        expected_action: 'block',
        rate_limit_canary: { path: '/rl', method: 'get', threshold: 3, window_seconds: 10 },
        marker_paths: ['/waf/sqli', '/waf/xss'],
      },
      origin: { lockdown_expected: true },
      perspectives: { allowlisted_perspective_ids: ['default'], denied_perspective_ids: [] },
      canary_sink: { url: 'https://origin.test/sink' },
      connection_limits: [{ protocol: 'tcp', port: 443, max_connections_per_source: 4 }],
      updated_at: '2000-01-01T00:00:00.000Z',
      updated_by: 'usr_spoof',
    });
    assert.equal(out.version, 1);
    assert.equal(out.updated_at, undefined);
    assert.equal(out.updated_by, undefined);
    assert.deepEqual(out.network_policy, [
      { protocol: 'tcp', port: 22, action: 'deny', address_family: 'any', note: 'ssh' },
    ]);
    assert.equal(out.waf.block_signature.header_name, 'x-waf-block');
    assert.equal(out.waf.block_signature.header_value, 'edge-deny');
    assert.deepEqual(out.waf.block_signature.status_codes, [403, 406]);
    assert.equal(out.waf.expected_action, 'block');
    assert.deepEqual(out.waf.rate_limit_canary, {
      path: '/rl',
      method: 'GET',
      threshold: 3,
      window_seconds: 10,
      expected_action: 'block',
    });
    assert.deepEqual(out.waf.marker_paths, ['/waf/sqli', '/waf/xss']);
    assert.deepEqual(out.origin, { lockdown_expected: true });
    assert.deepEqual(out.perspectives.allowlisted_perspective_ids, ['default']);
    assert.equal(out.canary_sink.url, 'https://origin.test/sink');
    assert.equal(out.connection_limits[0].max_connections_per_source, 4);
  });

  it('rejects a canary sink on a subdomain of the target host', () => {
    reject({ canary_sink: { url: 'https://canary.origin.test/hook' } }, 'canary_sink.url');
  });

  it('rejects unknown keys, bad versions, and non-objects', () => {
    reject({ extra: true }, 'control_declarations.extra');
    reject({ version: 2 }, 'version');
    reject(null, 'control_declarations');
    reject([], 'control_declarations');
    reject({ waf: { unexpected: 1 } }, 'waf.unexpected');
    reject({ origin: { lockdown_expected: true, extra: 1 } }, 'origin.extra');
  });

  it('rejects invalid network_policy rules', () => {
    reject({ network_policy: { protocol: 'tcp' } }, 'network_policy');
    reject({ network_policy: [{ protocol: 'tcp', port: 0, action: 'deny', address_family: 'any' }] }, 'network_policy[0].port');
    reject({ network_policy: [{ protocol: 'tcp', port: 65536, action: 'deny', address_family: 'any' }] }, 'network_policy[0].port');
    reject({ network_policy: [{ protocol: 'tcp', port: 22.5, action: 'deny', address_family: 'any' }] }, 'network_policy[0].port');
    reject({ network_policy: [{ protocol: 'icmp', port: 22, action: 'deny', address_family: 'any' }] }, 'network_policy[0].protocol');
    reject({ network_policy: [{ protocol: 'tcp', port: 22, action: 'drop', address_family: 'any' }] }, 'network_policy[0].action');
    reject({
      network_policy: [
        { protocol: 'tcp', port: 22, action: 'deny', address_family: 'ipv4' },
        { protocol: 'tcp', port: 22, action: 'allow', address_family: 'ipv4' },
      ],
    }, 'network_policy[1]');
    reject({
      network_policy: Array.from({ length: 65 }, (_, i) => ({
        protocol: 'tcp',
        port: i + 1,
        action: 'deny',
        address_family: 'any',
      })),
    }, 'network_policy');
  });

  it('rejects invalid WAF block signatures, canaries, and marker paths', () => {
    reject({
      waf: { block_signature: { header_name: 'x waf', header_value: 'v' } },
    }, 'waf.block_signature.header_name');
    reject({
      waf: { block_signature: { header_name: 'x-waf', header_value: 'bad\nvalue' } },
    }, 'waf.block_signature.header_value');
    reject({
      waf: { block_signature: { header_name: 'x-waf', header_value: 'x'.repeat(257) } },
    }, 'waf.block_signature.header_value');
    reject({
      waf: { block_signature: { header_name: 'x-waf', header_value: 'v', status_codes: [399] } },
    }, 'waf.block_signature.status_codes[0]');
    reject({
      waf: { block_signature: { header_name: 'x-waf', header_value: 'v', status_codes: [600] } },
    }, 'waf.block_signature.status_codes[0]');
    reject({ waf: { expected_action: 'allow' } }, 'waf.expected_action');
    reject({
      waf: { rate_limit_canary: { path: 'rl', method: 'GET', threshold: 1, window_seconds: 1 } },
    }, 'waf.rate_limit_canary.path');
    reject({
      waf: { rate_limit_canary: { path: '/rl', method: 'POST', threshold: 1, window_seconds: 1 } },
    }, 'waf.rate_limit_canary.method');
    reject({
      waf: { rate_limit_canary: { path: '/rl', method: 'GET', threshold: 0, window_seconds: 1 } },
    }, 'waf.rate_limit_canary.threshold');
    reject({
      waf: { rate_limit_canary: { path: '/rl', method: 'GET', threshold: 11, window_seconds: 1 } },
    }, 'waf.rate_limit_canary.threshold');
    reject({
      waf: { rate_limit_canary: { path: '/rl', method: 'GET', threshold: 1, window_seconds: 61 } },
    }, 'waf.rate_limit_canary.window_seconds');
    reject({
      waf: { rate_limit_canary: { path: '/rl', method: 'GET', threshold: 1, window_seconds: 1, expected_action: 'invalid' } },
    }, 'waf.rate_limit_canary.expected_action');
    reject({ waf: { marker_paths: ['relative'] } }, 'waf.marker_paths[0]');
    reject({ waf: { marker_paths: ['/a', '/b', '/c', '/d', '/e', '/f'] } }, 'waf.marker_paths');
    reject({ waf: { marker_paths: ['/a', '/a'] } }, 'waf.marker_paths[1]');
  });

  it('rejects unknown perspectives, bad canary sinks, and invalid connection limits', () => {
    reject({ perspectives: { allowlisted_perspective_ids: ['nope'] } }, 'perspectives.allowlisted_perspective_ids[0]');
    reject({ canary_sink: { url: 'http://origin.test/sink' } }, 'canary_sink.url');
    reject({ canary_sink: { url: 'https://user:pass@origin.test/sink' } }, 'canary_sink.url');
    reject({ canary_sink: { url: 'https://other.test/sink' } }, 'canary_sink.url');
    reject({
      connection_limits: [{ protocol: 'udp', port: 443, max_connections_per_source: 2 }],
    }, 'connection_limits[0].protocol');
    reject({
      connection_limits: [{ protocol: 'tcp', port: 443, max_connections_per_source: 0 }],
    }, 'connection_limits[0].max_connections_per_source');
    reject({
      connection_limits: [{ protocol: 'tcp', port: 443, max_connections_per_source: 11 }],
    }, 'connection_limits[0].max_connections_per_source');
  });

  it('accepts a perspective id from a custom registry env', () => {
    const env = {
      ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([
        { id: 'us-east', label: 'US East', region: 'us-east-1', asn: 64500, egress_ips: ['203.0.113.10'] },
      ]),
    };
    const out = accept({ perspectives: { allowlisted_perspective_ids: ['us-east'] } }, { env });
    assert.deepEqual(out.perspectives.allowlisted_perspective_ids, ['us-east']);
  });
});

describe('declaration helpers', () => {
  const declarations = accept({
    network_policy: [
      { protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' },
      { protocol: 'tcp', port: 3306, action: 'deny', address_family: 'ipv4' },
      { protocol: 'tcp', port: 9, action: 'allow', address_family: 'any' },
    ],
    waf: {
      block_signature: { header_name: 'x-waf-block', header_value: 'edge-deny', status_codes: [403] },
      expected_action: 'block',
    },
    origin: { lockdown_expected: true },
    canary_sink: { url: 'https://origin.test/sink' },
    connection_limits: [{ protocol: 'tcp', port: 443, max_connections_per_source: 2 }],
    perspectives: { allowlisted_perspective_ids: ['default'] },
  });

  it('looks up network policy by protocol, port, and family', () => {
    assert.equal(declaredNetworkPolicyFor(declarations, { protocol: 'tcp', port: 3306, addressFamily: 'ipv4' }).action, 'deny');
    assert.equal(declaredNetworkPolicyFor(declarations, { protocol: 'tcp', port: 22, addressFamily: 'ipv6' }).address_family, 'any');
    assert.equal(declaredNetworkPolicyFor(declarations, { protocol: 'udp', port: 22, addressFamily: 'any' }), null);
  });

  it('maps the declared block signature for existing graders', () => {
    const sig = declaredBlockSignature(declarations);
    assert.equal(sig.header_name, 'x-waf-block');
    const mapped = mapDeclaredBlockSignatureForProbe(declarations);
    assert.equal(mapped.header.name, 'x-waf-block');
    assert.equal(mapped.header.value, 'edge-deny');
    assert.equal(mapped.status_code, 403);
    assert.deepEqual(mapped.status_codes, [403]);
  });

  it('filters vetted ports for bounded scan and subsets fields per probe kind', () => {
    assert.deepEqual(declaredPortsForBoundedScan(declarations), [22, 3306]);
    const wafSubset = probeDeclarationsSubset(declarations, { probe_profile: { kind: 'waf_class_marker_probe' }, vector_family: 'waf' });
    assert.equal(wafSubset.waf.expected_action, 'block');
    assert.equal(wafSubset.network_policy, undefined);
    assert.equal(wafSubset.canary_sink.url, 'https://origin.test/sink');
    assert.deepEqual(wafSubset.perspectives.allowlisted_perspective_ids, ['default']);
    const netSubset = probeDeclarationsSubset(declarations, { probe_profile: { kind: 'port_scan_bounded' }, vector_family: 'l3_l4' });
    assert.equal(netSubset.waf, undefined);
    assert.equal(netSubset.network_policy.length, 3);
    assert.equal(netSubset.connection_limits.length, 1);
    const originSubset = probeDeclarationsSubset(declarations, { probe_profile: { kind: 'origin_leak_scan' } });
    assert.equal(originSubset.origin.lockdown_expected, true);
    assert.equal(originSubset.waf, undefined);
  });

  it('summarizes declarations for audit without the header value', () => {
    const summary = summarizeControlDeclarationsForAudit(declarations);
    assert.equal(summary.block_header_name, 'x-waf-block');
    assert.equal(summary.block_header_value_length, 9);
    assert.equal(JSON.stringify(summary).includes('edge-deny'), false);
    assert.equal(summary.canary_sink_host, 'origin.test');
  });
});

describe('probe perspective registry', () => {
  it('defaults to a single primary perspective', () => {
    const loaded = loadProbePerspectivesFromEnv({});
    assert.equal(loaded[0].id, 'default');
    assert.equal(loaded[0].label, 'Primary');
    assert.deepEqual(loaded[0].egress_ips, []);
    assert.equal(DEFAULT_PROBE_PERSPECTIVES[0].id, 'default');
    const listed = listProbePerspectives({});
    assert.deepEqual(listed, [{ id: 'default', label: 'Primary', region: null, egress_ips: [] }]);
  });

  it('parses a valid JSON array and rejects malformed config', () => {
    const env = {
      ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([
        { id: 'eu-west', label: 'EU West', region: 'eu-west-1', asn: '64501', egress_ips: ['198.51.100.10', '2001:db8::1'] },
      ]),
    };
    const loaded = loadProbePerspectivesFromEnv(env);
    assert.equal(loaded[0].id, 'eu-west');
    assert.equal(loaded[0].asn, 64501);
    assert.deepEqual(loaded[0].egress_ips, ['198.51.100.10', '2001:db8::1']);

    assert.throws(() => loadProbePerspectivesFromEnv({ ASTRANULL_PROBE_PERSPECTIVES: '{' }), /ASTRANULL_PROBE_PERSPECTIVES/);
    assert.throws(() => loadProbePerspectivesFromEnv({ ASTRANULL_PROBE_PERSPECTIVES: '[]' }), /ASTRANULL_PROBE_PERSPECTIVES/);
    assert.throws(() => loadProbePerspectivesFromEnv({ ASTRANULL_PROBE_PERSPECTIVES: '{"id":"x"}' }), /ASTRANULL_PROBE_PERSPECTIVES/);
    assert.throws(
      () => loadProbePerspectivesFromEnv({
        ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([{ id: 'Bad_ID', label: 'X', egress_ips: [] }]),
      }),
      /ASTRANULL_PROBE_PERSPECTIVES/,
    );
    assert.throws(
      () => loadProbePerspectivesFromEnv({
        ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([{ id: 'ok', label: 'X', egress_ips: ['not-an-ip'] }]),
      }),
      /ASTRANULL_PROBE_PERSPECTIVES/,
    );
    assert.throws(
      () => loadProbePerspectivesFromEnv({
        ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([
          { id: 'dup', label: 'A', egress_ips: [] },
          { id: 'dup', label: 'B', egress_ips: [] },
        ]),
      }),
      /duplicate id/,
    );
  });

  it('fails closed when createServer receives malformed perspectives', () => {
    assert.throws(
      () => createServer({
        env: {
          NODE_ENV: 'test',
          ASTRANULL_NO_PERSIST: '1',
          ASTRANULL_PROBE_PERSPECTIVES: 'not-json',
        },
      }),
      /ASTRANULL_PROBE_PERSPECTIVES/,
    );
  });
});
