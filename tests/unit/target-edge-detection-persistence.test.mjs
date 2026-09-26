import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it, beforeEach } from 'node:test';
import {
  projectEdgeDetection,
  isPersistableEdgeDetection,
  edgeDetectionRowFields,
} from '../../src/lib/edgeDetectionProjection.mjs';
import { presentTargetEdgeDetection } from '../../src/lib/edgeDetectionPresenter.mjs';
import {
  recordTargetEdgeDetectionFromEvent,
  getTargetEdgeDetection,
  listTargetEdgeDetectionsForGroup,
} from '../../src/services/targetEdgeDetectionStore.mjs';
import { getStore } from '../../src/store.mjs';
import { getTargetDetail } from '../../src/services/targetDetail.mjs';

function edgeMetadata(overrides = {}) {
  return {
    external_result: 'connected',
    edge_signature_corpus_version: 'v2',
    edge_signature: {
      waf_present: true,
      waf_providers: ['cloudflare'],
      cdn_detected: true,
      cdn_providers: ['cloudfront'],
      conflicting_vendor_signals: false,
      best_vendor: {
        vendor: 'cloudflare',
        name: 'Cloudflare (Cloudflare Inc.)',
        confidence: 0.9,
        matched_signals: [{ signal: 'server=cloudflare', tier: 'passive' }],
      },
      vendor_matches: [{
        vendor: 'cloudflare',
        name: 'Cloudflare (Cloudflare Inc.)',
        confidence: 0.9,
        matched_signals: [{ signal: 'server=cloudflare', tier: 'passive' }],
      }],
      address_matches: [{ family: 'cdn', provider: 'cloudfront' }],
      cname_matches: [{ provider: 'amazon', type: 'waf', suffix: 'cloudfront.net' }],
    },
    dns_cname_chain: ['a.example.test', 'd1.cloudfront.net'],
    dns_resolved_ips: ['108.138.5.5', '2606:4700::6810:85e5'],
    ...overrides,
  };
}

describe('edge detection projection', () => {
  it('keeps WAF and CDN answers independent and typed', () => {
    const projection = projectEdgeDetection(edgeMetadata());
    assert.equal(projection.status, 'detected');
    assert.equal(projection.waf.status, 'detected');
    assert.equal(projection.waf.vendor, 'cloudflare');
    assert.equal(projection.cdn.status, 'detected');
    assert.equal(projection.cdn.provider, 'cloudfront');
    assert.deepEqual(projection.cdn_providers, ['cloudfront']);
  });

  it('projects marker effectiveness and never protects a WAF that passed every marker', () => {
    const projection = projectEdgeDetection(edgeMetadata({
      posture_status: 'protected',
      agent_corroborated: true,
      marker_probes: [
        { family: 'sqli_marker', variant: 'plain', blocked: false, allowed: true },
        { family: 'xss_marker', variant: 'plain', blocked: false, allowed: true },
        { family: 'path_traversal_marker', variant: 'plain', blocked: false, allowed: true },
      ],
    }));
    assert.equal(projection.effectiveness.status, 'present_but_not_effective');
    assert.equal(projection.effectiveness.percentage, 0);
    assert.equal(projection.protection.status, 'underprotected');
  });

  it('downgrades error and timeout metadata to inconclusive before persistence', () => {
    const projection = projectEdgeDetection(edgeMetadata({
      external_result: 'timeout',
      error_class: 'probe_timeout',
      marker_probes: [],
    }));
    assert.equal(projection.status, 'inconclusive');
    assert.equal(projection.reason, 'worker_result_error');
    assert.equal(projection.effectiveness.status, 'inconclusive');
    assert.equal(projection.protection.status, 'inconclusive');
    assert.equal(isPersistableEdgeDetection(edgeMetadata({ external_result: 'timeout' })), false);
  });

  it('does not present a stale protected tier without effective marker evidence', () => {
    const presented = presentTargetEdgeDetection({
      status: 'detected',
      waf_status: 'detected',
      cdn_status: 'not_detected',
      confidence: 0.8,
      conflicting_vendor_signals: false,
      evidence_json: {
        protection: {
          status: 'protected',
          label: 'Protected',
          evidence_tier: 'external_and_origin_corroborated',
          agent_corroborated: true,
        },
      },
    });
    assert.equal(presented.protection.status, 'inconclusive');
    assert.equal(presented.protection.label, 'Inconclusive');
    assert.equal(presented.protection.evidence_tier, 'insufficient_evidence');
  });

  it('treats an observed cloud-only range as detected without inventing a WAF or CDN', () => {
    const projection = projectEdgeDetection(edgeMetadata({
      edge_signature: {
        waf_present: false,
        waf_providers: [],
        cdn_detected: false,
        cdn_providers: [],
        cloud_hosted: true,
        cloud_providers: ['aws'],
        vendor_matches: [],
        address_matches: [{ family: 'cloud', provider: 'aws' }],
        cname_matches: [],
      },
    }));
    assert.equal(projection.status, 'detected');
    assert.equal(projection.waf.status, 'not_detected');
    assert.equal(projection.cdn.status, 'not_detected');
    assert.equal(projection.cloud.status, 'detected');
    assert.equal(projection.cloud.provider, 'aws');
  });

  it('reports not_detected only when both families explicitly report no match', () => {
    const projection = projectEdgeDetection(edgeMetadata({
      edge_signature: {
        waf_present: false,
        cdn_detected: false,
        waf_providers: [],
        cdn_providers: [],
        vendor_matches: [],
        address_matches: [],
        cname_matches: [],
      },
    }));
    assert.equal(projection.status, 'not_detected');
    assert.equal(projection.reason, 'completed_no_signature_match');
    const presented = presentTargetEdgeDetection(edgeDetectionRowFields(projection));
    assert.equal(
      presented.plain_language_summary,
      'No WAF or CDN was detected. WAF effectiveness was not scored because no WAF was detected.',
    );
  });

  it('stays inconclusive when a family never reported, instead of claiming absence', () => {
    const projection = projectEdgeDetection({
      external_result: 'connected',
      edge_signature: { waf_present: true, waf_providers: ['cloudflare'] },
    });
    assert.equal(projection.cdn.status, 'inconclusive');
    assert.equal(projection.cdn.reason, 'signal_not_reported');
  });

  it('withholds a vendor when signals conflict', () => {
    const projection = projectEdgeDetection(edgeMetadata({
      edge_signature: {
        ...edgeMetadata().edge_signature,
        conflicting_vendor_signals: true,
      },
    }));
    assert.equal(projection.conflicting_vendor_signals, true);
    assert.equal(projection.waf.vendor, undefined);
  });

  it('carries the resolved cdncheck chain into durable row fields', () => {
    const fields = edgeDetectionRowFields(projectEdgeDetection(edgeMetadata()), {
      testRunId: 'run-1',
      observedAt: '2026-09-01T00:00:00.000Z',
    });
    assert.deepEqual(fields.evidence_json.dns_resolved_ips, ['108.138.5.5', '2606:4700::6810:85e5']);
    assert.deepEqual(fields.evidence_json.cname_matches, [
      { provider: 'amazon', type: 'waf', suffix: 'cloudfront.net' },
    ]);
    assert.equal(fields.test_run_id, 'run-1');
  });

  it('refuses to persist simulations and worker errors', () => {
    assert.equal(isPersistableEdgeDetection(edgeMetadata()), true);
    assert.equal(isPersistableEdgeDetection({ simulation: 'SAFE_PROBE_SIMULATION', edge_signature: {} }), false);
    assert.equal(isPersistableEdgeDetection({ external_result: 'error', edge_signature: {} }), false);
    assert.equal(isPersistableEdgeDetection({ error_class: 'timeout', edge_signature: {} }), false);
    assert.equal(isPersistableEdgeDetection({ external_result: 'connected' }), false);
  });
});

describe('per-target edge detection persistence', () => {
  beforeEach(() => {
    getStore().targetEdgeDetections = [];
    getStore().targets = (getStore().targets ?? []).filter((row) => row.id !== 'tgt-summary');
    getStore().targetGroups = (getStore().targetGroups ?? []).filter((row) => row.id !== 'g-summary');
  });

  it('stores one current detection per target and updates it in place', () => {
    const first = recordTargetEdgeDetectionFromEvent({
      tenantId: 't1',
      targetGroupId: 'g1',
      targetId: 'tgt-1',
      testRunId: 'run-1',
      metadata: edgeMetadata(),
    });
    assert.equal(first.status, 'detected');

    recordTargetEdgeDetectionFromEvent({
      tenantId: 't1',
      targetGroupId: 'g1',
      targetId: 'tgt-1',
      testRunId: 'run-2',
      metadata: edgeMetadata(),
    });

    const rows = getStore().targetEdgeDetections.filter((row) => row.target_id === 'tgt-1');
    assert.equal(rows.length, 1, 'target keeps exactly one current detection');
    assert.equal(rows[0].test_run_id, 'run-2');
  });

  it('never persists a simulated probe result', () => {
    const stored = recordTargetEdgeDetectionFromEvent({
      tenantId: 't1',
      targetGroupId: 'g1',
      targetId: 'tgt-2',
      metadata: { simulation: 'SAFE_PROBE_SIMULATION', edge_signature: {} },
    });
    assert.equal(stored, null);
    assert.equal(getTargetEdgeDetection('t1', 'tgt-2'), null);
  });

  it('scopes reads to the tenant and group', () => {
    recordTargetEdgeDetectionFromEvent({
      tenantId: 't1', targetGroupId: 'g1', targetId: 'tgt-1', metadata: edgeMetadata(),
    });
    recordTargetEdgeDetectionFromEvent({
      tenantId: 't2', targetGroupId: 'g1', targetId: 'tgt-9', metadata: edgeMetadata(),
    });

    assert.equal(getTargetEdgeDetection('t2', 'tgt-1'), null, 'no cross-tenant read');
    const group = listTargetEdgeDetectionsForGroup('t1', 'g1');
    assert.deepEqual(Object.keys(group), ['tgt-1']);
  });

  it('keeps stacked layers and CTO-readable effectiveness in target detail', () => {
    const markerProbes = Array.from({ length: 10 }, (_, index) => ({
      family: index === 0 ? 'sqli_marker' : `variant_${index}`,
      variant: index === 0 ? 'plain' : `v${index}`,
      blocked: index < 9,
      allowed: index === 9,
    }));
    const metadata = edgeMetadata({
      posture_status: 'underprotected',
      marker_probes: markerProbes,
      edge_signature: {
        waf_present: true,
        waf_providers: ['awswaf'],
        cdn_detected: true,
        cdn_providers: ['cloudfront'],
        cloud_hosted: true,
        cloud_providers: ['aws'],
        confidence: 0.9,
        evidence_consistency: 'multiple_layers',
        conflicting_vendor_signals: false,
        conflicting_provider_signals: false,
        best_vendor: {
          vendor: 'awswaf',
          name: 'AWS Elastic Load Balancer (Amazon)',
          confidence: 0.8,
          matched_signals: [{ signal: 'header', tier: 'passive' }],
        },
        vendor_matches: [{
          vendor: 'awswaf',
          name: 'AWS Elastic Load Balancer (Amazon)',
          confidence: 0.8,
          matched_signals: [{ signal: 'header', tier: 'passive' }],
        }],
        address_matches: [
          { family: 'cdn', provider: 'cloudfront' },
          { family: 'cloud', provider: 'aws' },
        ],
        cname_matches: [],
        layers: [
          { family: 'cdn', provider: 'cloudfront', sources: ['address_range'], confidence: 0.7 },
          { family: 'waf', provider: 'awswaf', sources: ['response_fingerprint'], confidence: 0.8 },
          { family: 'cloud', provider: 'aws', sources: ['address_range'], confidence: 0.7 },
        ],
      },
    });

    const store = getStore();
    store.targetGroups.push({ id: 'g-summary', tenant_id: 't1', name: 'Summary group' });
    store.targets.push({
      id: 'tgt-summary',
      tenant_id: 't1',
      target_group_id: 'g-summary',
      kind: 'fqdn',
      value: 'summary.example.test',
      created_at: '2026-09-01T00:00:00.000Z',
    });
    recordTargetEdgeDetectionFromEvent({
      tenantId: 't1',
      targetGroupId: 'g-summary',
      targetId: 'tgt-summary',
      testRunId: 'run-summary',
      metadata,
    });

    const detail = getTargetDetail({ tenantId: 't1' }, 'tgt-summary');
    assert.deepEqual(
      detail.edge_detection.layers.map((layer) => [layer.family, layer.provider]),
      [['cdn', 'cloudfront'], ['waf', 'awswaf'], ['cloud', 'aws']],
    );
    assert.equal(detail.edge_detection.effectiveness.percentage, 90);
    assert.equal(detail.edge_detection.protection.status, 'underprotected');
    assert.equal(
      detail.edge_detection.plain_language_summary,
      'Detected Amazon CloudFront (CDN) and AWS WAF. The WAF blocked 9 of 10 safe test probes (90%).',
    );
    assert.match(detail.edge_detection.summary.network_firewall, /not tested/);
  });

  it('presents a stored row in the API shape', () => {
    recordTargetEdgeDetectionFromEvent({
      tenantId: 't1', targetGroupId: 'g1', targetId: 'tgt-1', metadata: edgeMetadata(),
    });
    const presented = presentTargetEdgeDetection(getTargetEdgeDetection('t1', 'tgt-1'));
    assert.equal(presented.waf.provider, 'cloudflare');
    assert.equal(presented.cdn.provider, 'cloudfront');
    assert.equal(presented.corpus_version, 'v2');
    assert.equal(presented.evidence.vendor_matches[0].vendor, 'cloudflare');
    assert.equal(presentTargetEdgeDetection(null), null);
  });
});
