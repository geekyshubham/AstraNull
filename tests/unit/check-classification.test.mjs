import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { CHECK_PROTECTION_CONTROLS, checkClassificationFields, classifyCheck } from '../../src/contracts/checkClassification.mjs';
import { projectScanStep, withCheckSection } from '../../src/contracts/validationScanManagement.mjs';

const byId = (id) => CHECK_CATALOG.find((check) => check.check_id === id);

describe('check layer and protection-control classification', () => {
  it('gives every non-operations check a control and every single-layer check a layer', () => {
    const missingControl = CHECK_CATALOG.filter((check) => check.vector_family !== 'operations' && classifyCheck(check).controls.length === 0);
    assert.deepEqual(missingControl.map((check) => check.check_id), []);
    const withoutLayer = CHECK_CATALOG.filter((check) => !classifyCheck(check).layer).map((check) => check.check_id);
    assert.ok(withoutLayer.every((id) => id.startsWith('ops.') || ['high_scale.degradation_recovery.request_only', 'pattern.ransom_ddos.readiness'].includes(id)), withoutLayer.join(', '));
  });

  it('maps network checks to the network firewall and web checks to the WAF', () => {
    assert.deepEqual(checkClassificationFields(byId('l3.forbidden_tcp_port.safe')), { layer: 'L4 · TCP', protection_controls: ['network_firewall'], declaration_only: false });
    assert.deepEqual(checkClassificationFields(byId('l3.icmp_flood.readiness')), { layer: 'L3 · IP', protection_controls: ['network_firewall'], declaration_only: true });
    assert.deepEqual(checkClassificationFields(byId('waf.ssrf_marker.safe')), { layer: 'L7 · HTTP', protection_controls: ['waf'], declaration_only: false });
    assert.deepEqual(checkClassificationFields(byId('dns.open_recursion_behavior.safe')), { layer: 'L7 · DNS', protection_controls: ['dns_provider'], declaration_only: false });
    assert.deepEqual(checkClassificationFields(byId('tls.full_audit.safe')), { layer: 'L6 · TLS', protection_controls: ['cdn_edge'], declaration_only: false });
    assert.deepEqual(checkClassificationFields(byId('origin.direct_bypass.safe')).protection_controls, ['cdn_edge', 'network_firewall']);
    assert.ok(CHECK_CATALOG.filter((check) => check.vector_family === 'l3_l4').every((check) => classifyCheck(check).controls[0].short === 'NFW'));
    assert.ok(CHECK_CATALOG.filter((check) => check.vector_family === 'waf').every((check) => classifyCheck(check).controls[0].short === 'WAF'));
  });

  it('labels QUIC Alt-Svc probes as L7 HTTP observation and slow-client checks as Edge', () => {
    assert.equal(classifyCheck(byId('protocol.http3_quic_exposure.safe')).layer.label, 'L7 · HTTP (Alt-Svc observation)');
    assert.equal(classifyCheck(byId('reflect.quic_reflection_exposure.safe')).layer.label, 'L7 · HTTP (Alt-Svc observation)');
    assert.equal(classifyCheck(byId('l7.slowloris.readiness')).controls[0].short, 'Edge');
    assert.equal(classifyCheck(byId('l7.slow_read.readiness')).controls[0].short, 'Edge');
    assert.equal(classifyCheck(byId('l7.http2_rapid_reset.validation')).controls[0].short, 'Edge');
    assert.equal(classifyCheck(byId('l7.connection_hoarding.readiness')).controls[0].short, 'Edge');
    assert.equal(classifyCheck(byId('l3.icmp_flood.readiness')).declaration_only, true);
    assert.equal(checkClassificationFields(byId('waf.evasion_cache_key_mismatch.posture')).declaration_only, true);
  });

  it('projects layer and controls on the API without storing them on catalog entries', () => {
    const check = byId('l3.forbidden_tcp_port.safe');
    assert.equal(Object.hasOwn(check, 'layer'), false);
    assert.equal(Object.hasOwn(check, 'protection_controls'), false);
    const projected = withCheckSection(check);
    assert.equal(projected.layer, 'L4 · TCP');
    assert.deepEqual(projected.protection_controls, ['network_firewall']);
    const step = projectScanStep({ step: { id: 'step_1', position: 0, status: 'pending', check_id: check.check_id, target_id: 'tgt_1' }, check, target: null, run: null, verdict: null });
    assert.equal(step.layer, 'L4 · TCP');
  });

  it('classifies a sparse scan step from its id, family and request kind', () => {
    assert.equal(classifyCheck({ check_id: 'reflect.x', vector_family: 'reflection', request: { kind: 'reflection_service_probe' } }).layer.label, 'L4 · UDP');
    assert.deepEqual(classifyCheck(null), { layer: null, controls: [], declaration_only: false });
    assert.deepEqual(Object.keys(CHECK_PROTECTION_CONTROLS), ['waf', 'network_firewall', 'cdn_edge', 'ddos', 'dns_provider']);
  });
});
