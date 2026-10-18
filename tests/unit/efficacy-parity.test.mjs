import test from 'node:test';
import assert from 'node:assert/strict';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';

const meta = {
  port: 8080,
  address_family: 6,
  tcp_outcome: 'handshake',
  peer_is_cdn: false,
  sample_agreement: 'disagree',
  parity: 'mismatch',
  families: {
    ipv4: { tcp_outcome: 'timeout', sample_agreement: 'single', peer_is_cdn: false },
    ipv6: { tcp_outcome: 'handshake', sample_agreement: 'single', peer_is_cdn: false },
  },
};

const dualStackDecl = {
  network_policy: [
    { protocol: 'tcp', port: 8080, action: 'deny', address_family: 'ipv4' },
    { protocol: 'tcp', port: 8080, action: 'deny', address_family: 'ipv6' },
  ],
};

test('parity mismatch with dual-stack deny is exposed on IPv6 handshake', () => {
  const result = correlateExternalOnlyVerdict({
    probeKind: 'tcp_connect',
    externalResult: 'connected',
    probeIoObserved: true,
    probeMetadata: meta,
    declarations: dualStackDecl,
    expectedBehavior: 'must_block_before_origin',
  });
  assert.equal(result.verdict, 'exposed');
});

test('IPv4-only deny declaration is inconclusive when leak is on IPv6', () => {
  const result = correlateExternalOnlyVerdict({
    probeKind: 'tcp_connect',
    externalResult: 'connected',
    probeIoObserved: true,
    probeMetadata: meta,
    declarations: {
      network_policy: [{ protocol: 'tcp', port: 8080, action: 'deny', address_family: 'ipv4' }],
    },
    expectedBehavior: 'must_block_before_origin',
  });
  assert.equal(result.verdict, 'inconclusive');
});

test('IPv6 sample_agreement disagree is inconclusive', () => {
  const metaDisagree = {
    ...meta,
    families: {
      ...meta.families,
      ipv6: { tcp_outcome: 'handshake', sample_agreement: 'disagree', peer_is_cdn: false },
    },
  };
  const result = correlateExternalOnlyVerdict({
    probeKind: 'tcp_connect',
    externalResult: 'connected',
    probeIoObserved: true,
    probeMetadata: metaDisagree,
    declarations: dualStackDecl,
    expectedBehavior: 'must_block_before_origin',
  });
  assert.equal(result.verdict, 'inconclusive');
});

test('no I/O observed is inconclusive', () => {
  const result = correlateExternalOnlyVerdict({
    probeKind: 'tcp_connect',
    externalResult: 'connected',
    probeIoObserved: false,
    probeMetadata: meta,
    declarations: dualStackDecl,
    expectedBehavior: 'must_block_before_origin',
  });
  assert.equal(result.verdict, 'inconclusive');
});

test('externalResult timeout is inconclusive', () => {
  const result = correlateExternalOnlyVerdict({
    probeKind: 'tcp_connect',
    externalResult: 'timeout',
    probeIoObserved: true,
    probeMetadata: meta,
    declarations: dualStackDecl,
    expectedBehavior: 'must_block_before_origin',
  });
  assert.equal(result.verdict, 'inconclusive');
});
