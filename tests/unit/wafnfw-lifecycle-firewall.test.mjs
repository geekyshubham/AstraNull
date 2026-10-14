import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { firewallSideState, MIN_SAMPLES_FOR_UNAVAILABILITY, normalizeFirewallExpectation } from '../../src/contracts/protectionValidation.mjs';
import {
  classifyFirewallChangeItem,
  classifyFirewallSample,
  evaluateFirewallChange,
  firewallObservedSideState,
  perspectiveId,
  buildFirewallBaselineCapture,
  firewallSampleFromProbeEvent,
} from '../../src/lib/firewallChangeAcceptance.mjs';

const TENANT = 'ten_1';
const SOURCE = 'public-worker-eu';
const PRE_DAY = '2026-10-01';
const POST_DAY = '2026-10-03';
const TARGETS = {
  tgt_ssh: { id: 'tgt_ssh', tenant_id: TENANT, value: 'fw.example.test:22' },
  tgt_dns: { id: 'tgt_dns', tenant_id: TENANT, value: 'ns.example.test:53' },
};

function expectation(overrides = {}) {
  return {
    ...normalizeFirewallExpectation({
      destination_target_id: 'tgt_ssh',
      protocol: 'tcp',
      port: 22,
      expected: 'deny',
      source_perspective: SOURCE,
      change_id: 'CHG-1001',
      ...overrides,
    }, { tenantId: TENANT }),
    id: 'fwx_1',
    status: 'active',
  };
}

let seq = 0;
function sample({
  kind = 'tcp_connect',
  result = 'connected',
  metadata = {},
  target = 'tgt_ssh',
  day = PRE_DAY,
  minute = 0,
  worker = 'worker_eu_1',
  source = SOURCE,
} = {}) {
  seq += 1;
  const run = {
    id: `run_${seq}`,
    tenant_id: TENANT,
    target_id: target,
    check_id: kind === 'udp_probe' ? 'l3.forbidden_udp_port.safe' : 'l3.forbidden_tcp_port.safe',
    status: 'verdicted',
    check_version: '1.0.0',
  };
  const event = {
    id: `evt_${seq}`,
    tenant_id: TENANT,
    test_run_id: run.id,
    target_id: target,
    check_id: run.check_id,
    signal_type: 'probe_result',
    producer_kind: 'signed_probe',
    timestamp: `${day}T00:${String(minute).padStart(2, '0')}:00.000Z`,
    metadata: {
      profile_kind: kind,
      probe_kind: kind,
      external_result: result,
      probe_worker_id: worker,
      safety_attestation: { requests_sent: 1, duration_ms: 5 },
      address_family: 4,
      elapsed_ms: 10,
      ...metadata,
    },
  };
  return firewallSampleFromProbeEvent({
    event,
    run,
    target: TARGETS[target],
    verdictId: `verdict_${seq}`,
    sourcePerspective: source,
  });
}

function evaluate(exp, preSamples, postSamples) {
  const baseline = {
    id: 'fwb_1',
    ...buildFirewallBaselineCapture({
      tenantId: TENANT,
      changeId: 'CHG-1001',
      expectations: [{ id: exp.id, record: exp }],
      samples: preSamples,
      freshnessWindowSeconds: 2592000,
      capturedAt: '2026-10-02T00:00:00.000Z',
    }).capture,
  };
  return evaluateFirewallChange({
    tenantId: TENANT,
    baseline,
    expectations: { [exp.id]: exp },
    candidateSamples: postSamples,
    evaluatedAt: '2026-10-04T00:00:00.000Z',
    now: '2026-10-04T00:00:00.000Z',
  });
}

describe('wafnfw lifecycle firewall deny acceptance', () => {
  it('maps tcp rejected_icmp and udp reject outcomes to explicit denial', () => {
    const tcp = expectation();
    const udp = expectation({ protocol: 'udp', port: 53, destination_target_id: 'tgt_dns' });
    assert.equal(classifyFirewallSample(tcp, sample({
      result: 'error',
      metadata: { tcp_outcome: 'rejected_icmp', icmp: { kind: 'host_unreachable' } },
    })).observation_class, 'explicit_denial_observed');
    assert.equal(classifyFirewallSample(udp, sample({
      kind: 'udp_probe',
      target: 'tgt_dns',
      result: 'error',
      metadata: { udp_outcome: 'rejected_icmp' },
    })).denial_basis, 'rejected_icmp');
    assert.equal(classifyFirewallSample(udp, sample({
      kind: 'udp_probe',
      target: 'tgt_dns',
      result: 'error',
      metadata: { udp_outcome: 'port_unreachable' },
    })).denial_basis, 'port_unreachable');
    assert.equal(classifyFirewallSample(tcp, sample({
      result: 'error',
      metadata: { error_class: 'EHOSTUNREACH' },
    })).observation_class, 'transport_error');
  });

  it('requires two post-change samples before a deny is satisfied', () => {
    assert.equal(MIN_SAMPLES_FOR_UNAVAILABILITY, 2);
    assert.equal(firewallObservedSideState('deny', {
      observation: 'explicit_denial_observed',
      samples: 1,
      classes: ['explicit_denial_observed'],
    }), 'unverified');
    assert.equal(firewallObservedSideState('deny', {
      observation: 'explicit_denial_observed',
      samples: 2,
      classes: ['explicit_denial_observed'],
    }), 'satisfied');
    assert.equal(firewallSideState('deny', {
      observation: 'explicit_denial_observed',
      samples: 1,
      classes: ['explicit_denial_observed'],
    }), 'unverified');
    assert.equal(firewallSideState('deny', {
      observation: 'explicit_denial_observed',
      samples: 2,
      classes: ['explicit_denial_observed'],
    }), 'satisfied');
  });

  it('does not treat RST as a silent deny', () => {
    const state = firewallObservedSideState('deny', {
      observation: 'transport_error',
      samples: 2,
      classes: ['transport_error'],
    });
    assert.equal(state, 'unverified');
  });

  it('compares perspectives by id whether stored as a string or {id,label}', () => {
    assert.equal(perspectiveId(SOURCE), SOURCE);
    assert.equal(perspectiveId({ id: SOURCE, label: 'EU public' }), SOURCE);
    const exp = expectation();
    const pre = [sample({ source: { id: SOURCE, label: 'EU' } }), sample({ minute: 1, source: { id: SOURCE, label: 'EU' } })];
    const post = [
      sample({ day: POST_DAY, result: 'error', metadata: { tcp_outcome: 'rejected_icmp' }, source: { id: SOURCE, label: 'EU worker' } }),
      sample({ day: POST_DAY, minute: 1, result: 'error', metadata: { tcp_outcome: 'rejected_icmp' }, source: { id: SOURCE, label: 'EU worker' } }),
    ];
    const item = evaluate(exp, pre, post).evaluation.items[0];
    assert.equal(item.status, 'improvement');
    assert.equal(item.expectation_met, true);
  });

  it('marks mismatched perspective ids as not comparable', () => {
    const exp = expectation();
    const pre = [sample({ source: { id: SOURCE, label: 'EU' } })];
    const post = [sample({ day: POST_DAY, source: { id: 'public-worker-us', label: 'US' } })];
    const item = evaluate(exp, pre, post).evaluation.items[0];
    assert.equal(item.status, 'not_comparable');
    assert.ok(item.compatibility_reasons.includes('source_mismatch'));
  });

  it('does not conclude a UDP regression from a single silent pre sample', () => {
    const udp = expectation({ protocol: 'udp', port: 53, destination_target_id: 'tgt_dns' });
    const classified = classifyFirewallChangeItem({
      expectation: udp,
      baselineObservations: [{ observation_class: 'udp_silence', source_perspective: SOURCE }],
      candidateObservations: [
        { observation_class: 'reachable_transport_only', source_perspective: SOURCE },
        { observation_class: 'reachable_transport_only', source_perspective: SOURCE },
      ],
      compatibility: { comparable: true, reasons: [] },
    });
    assert.equal(classified.status, 'inconclusive');
    assert.equal(classified.pre_state, 'unverified');
  });
});
