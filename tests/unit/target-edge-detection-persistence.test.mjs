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
