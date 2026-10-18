import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { addAssuredObservation, assuranceWorld } from '../helpers/assurance-fixtures.mjs';

const MARKER_PROOF = addAssuredObservation(assuranceWorld()).event.metadata;

function correlate(probeKind, probeMetadata, extra = {}) {
  return correlateExternalOnlyVerdict({
    probeKind,
    externalResult: extra.externalResult ?? 'connected',
    expectedBehavior: 'must_block_before_origin',
    probeIoObserved: true,
    probeMetadata,
    declarations: extra.declarations ?? null,
    originBinding: null,
  });
}

describe('gap evidence names exactly what was missing', () => {
  it('names the managed-rule attack class that reached the origin', () => {
    const result = correlate('waf_class_marker_probe', { ...MARKER_PROOF, enforcement: 'not_enforced', marker_class: 'sqli' });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.explanation, 'Managed-rule marker for SQL injection was not enforced: the edge let it through to the origin.');
  });

  it('keeps the class-neutral wording when the marker class is unknown', () => {
    const result = correlate('waf_class_marker_probe', { ...MARKER_PROOF, enforcement: 'not_enforced', marker_class: null });
    assert.equal(result.explanation, 'Managed-rule marker was not enforced.');
  });

  it('lists every declared-deny port that answered, leading with the most sensitive one', () => {
    const declarations = { version: 1, network_policy: [
      { protocol: 'tcp', port: 8080, action: 'deny', address_family: 'any' },
      { protocol: 'tcp', port: 3389, action: 'deny', address_family: 'any' },
      { protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' },
    ] };
    const result = correlate('port_scan_bounded', {
      open_ports: [8080, 3389, 22, 443], peer_is_cdn: false, sample_agreement: 'agree',
      families: { ipv4: { open_ports: [8080, 3389, 22, 443] } },
    }, { declarations });
    assert.equal(result.verdict, 'exposed');
    assert.equal(result.severity, 'high');
    assert.match(result.explanation, /^Declared deny for tcp\/3389 \(ipv4\)/);
    assert.match(result.explanation, /Also violated: tcp\/8080 \(ipv4\), tcp\/22 \(ipv4\)\.$/);
    assert.doesNotMatch(result.explanation, /443/);
  });

  it('keeps single-port wording unchanged when only one declared port leaks', () => {
    const declarations = { version: 1, network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }] };
    const result = correlate('port_scan_bounded', {
      open_ports: [22, 443], peer_is_cdn: false, sample_agreement: 'agree', families: { ipv4: { open_ports: [22, 443] } },
    }, { declarations });
    assert.doesNotMatch(result.explanation, /Also violated/);
  });

  it('normalizes marker class names and labels the scanner user-agent marker', () => {
    const result = correlate('waf_class_marker_probe', { ...MARKER_PROOF, enforcement: 'not_enforced', marker_class: ' Scanner_User_Agent ' });
    assert.equal(result.explanation, 'Managed-rule marker for vulnerability-scanner user-agent was not enforced: the edge let it through to the origin.');
  });

  it('names a single leaking nameserver recorded without per-nameserver results', () => {
    const result = correlate('dns_axfr_leak', { axfr_leak: true, nameserver: 'ns9.example.test' });
    assert.equal(result.verdict, 'exposed');
    assert.match(result.explanation, /Nameservers that allowed the transfer: ns9\.example\.test\.$/);
  });

  it('names the nameservers that allowed a zone transfer', () => {
    const result = correlate('dns_axfr_leak', {
      nameserver_results: [
        { nameserver: 'ns1.example.test', queried: true, axfr_leak: true },
        { nameserver: 'ns2.example.test', queried: true, axfr_leak: false, axfr_refused: true },
      ],
    });
    assert.equal(result.verdict, 'exposed');
    assert.match(result.explanation, /Nameservers that allowed the transfer: ns1\.example\.test\.$/);
    assert.doesNotMatch(result.explanation, /ns2/);
  });
});
