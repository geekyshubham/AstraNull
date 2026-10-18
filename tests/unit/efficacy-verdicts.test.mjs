import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';

const nfwKind = 'tcp_connect';
const meta = { port: 22, address_family: 'ipv4', tcp_outcome: 'handshake', sample_agreement: 'agree', peer_is_cdn: false };
const decl = { network_policy: [{ protocol: 'tcp', port: 22, address_family: 'any', action: 'deny' }] };

describe('Efficacy Verdicts', () => {
  it('bare connected axfr is inconclusive', () => {
    const res = correlateExternalOnlyVerdict({ probeKind: 'dns_axfr_leak', externalResult: 'connected', probeIoObserved: true, expectedBehavior: 'must_block_before_origin', probeMetadata: {} });
    assert.equal(res.verdict, 'inconclusive');
    assert.equal(res.createsFinding, false);
  });

  it('attested true queried leaking row is exposed', () => {
    const res = correlateExternalOnlyVerdict({ probeKind: 'dns_axfr_leak', externalResult: 'connected', probeIoObserved: true, expectedBehavior: 'must_block_before_origin', probeMetadata: { nameserver_results: [{ nameserver: 'ns1.example.com', queried: true, axfr_leak: true }] } });
    assert.equal(res.verdict, 'exposed');
    assert.equal(res.createsFinding, true);
  });

  it('incomplete refusals are inconclusive', () => {
    const res = correlateExternalOnlyVerdict({ probeKind: 'dns_axfr_leak', externalResult: 'connected', probeIoObserved: true, expectedBehavior: 'must_block_before_origin', probeMetadata: { enforcement: 'enforced', axfr_refused: true, nameservers_total: 2, nameservers_queried: 1, nameserver_results: [{ axfr_refused: true }] } });
    assert.equal(res.verdict, 'inconclusive');
    assert.equal(res.createsFinding, false);
  });

  it('all structured queried refusals are protected', () => {
    const res = correlateExternalOnlyVerdict({ probeKind: 'dns_axfr_leak', externalResult: 'connected', probeIoObserved: true, expectedBehavior: 'must_block_before_origin', probeMetadata: { enforcement: 'enforced', axfr_refused: true, nameservers_total: 2, nameservers_queried: 2, nameserver_results: [{ nameserver: 'ns1', queried: true, axfr_refused: true, axfr_leak: false }, { nameserver: 'ns2', queried: true, axfr_refused: true, axfr_leak: false }] } });
    assert.equal(res.verdict, 'protected');
    assert.equal(res.createsFinding, false);
  });

  it('duplicate nameserver rows cannot count twice toward protection', () => {
    const res = correlateExternalOnlyVerdict({ probeKind: 'dns_axfr_leak', externalResult: 'connected', probeIoObserved: true, expectedBehavior: 'must_block_before_origin', probeMetadata: { enforcement: 'enforced', axfr_refused: true, nameservers_total: 2, nameservers_queried: 2, nameserver_results: [{ nameserver: 'ns1', queried: true, axfr_refused: true, axfr_leak: false }, { nameserver: 'ns1', queried: true, axfr_refused: true, axfr_leak: false }] } });
    assert.equal(res.verdict, 'inconclusive');
    assert.equal(res.createsFinding, false);
  });

  it('missing queried flag cannot prove protected', () => {
    const res = correlateExternalOnlyVerdict({ probeKind: 'dns_axfr_leak', externalResult: 'connected', probeIoObserved: true, expectedBehavior: 'must_block_before_origin', probeMetadata: { enforcement: 'enforced', axfr_refused: true, nameservers_total: 2, nameservers_queried: 2, nameserver_results: [{ nameserver: 'ns1', axfr_refused: true, axfr_leak: false }, { nameserver: 'ns2', queried: true, axfr_refused: true, axfr_leak: false }] } });
    assert.equal(res.verdict, 'inconclusive');
    assert.equal(res.createsFinding, false);
  });

  it('nfw no I/O remains inconclusive', () => {
    const res = correlateExternalOnlyVerdict({ probeKind: nfwKind, externalResult: 'connected', probeIoObserved: false, expectedBehavior: 'must_block_before_origin', probeMetadata: meta, declarations: decl });
    assert.equal(res.verdict, 'inconclusive');
    assert.equal(res.createsFinding, false);
  });

  it('nfw timeout stays inconclusive but keeps the per-port outcomes it did observe', () => {
    const metaPorts = { ...meta, port_results: [
      { port: 22, protocol: 'tcp', tcp_outcome: 'timeout', address_family: 'ipv4' },
      { port: 3389, protocol: 'tcp', tcp_outcome: 'timeout', address_family: 'ipv4' },
    ] };
    const res = correlateExternalOnlyVerdict({ probeKind: nfwKind, externalResult: 'timeout', probeIoObserved: true, expectedBehavior: 'must_block_before_origin', probeMetadata: metaPorts, declarations: decl });
    assert.equal(res.verdict, 'inconclusive');
    assert.equal(res.createsFinding, false);
    assert.equal(res.metadata.port_results.length, 2);
    assert.ok(res.metadata.port_results.every((row) => row.result === 'no_violation_observed'));
  });

  it('nfw terminal failed TCP handshake remains inconclusive', () => {
    const res = correlateExternalOnlyVerdict({ probeKind: nfwKind, externalResult: 'timeout', probeIoObserved: true, expectedBehavior: 'must_block_before_origin', probeMetadata: meta, declarations: decl });
    assert.equal(res.verdict, 'inconclusive');
    assert.equal(res.createsFinding, false);
  });

  it('nfw attested declared TCP deny handshake is exposed', () => {
    const res = correlateExternalOnlyVerdict({ probeKind: nfwKind, externalResult: 'connected', probeIoObserved: true, expectedBehavior: 'must_block_before_origin', probeMetadata: meta, declarations: decl });
    assert.equal(res.verdict, 'exposed');
    assert.equal(res.createsFinding, true);
  });

  it('dns.secondary_failover.safe requires exactly probe_result', () => {
    const check = getCheckById('dns.secondary_failover.safe');
    assert.deepEqual(check.evidence_required, ['probe_result']);
  });
});