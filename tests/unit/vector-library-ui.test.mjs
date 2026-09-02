import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  evidenceCapabilityCopy,
  preferredRunnableCheck,
  searchAndFilterVectors,
  vectorTargetAvailability,
} from '../../apps/web/react/src/lib/vector-library.mjs';

const fqdn = { id: 'tgt_exact', kind: 'fqdn', value: 'example.test' };
const safeCheck = {
  check_id: 'l7.rate.safe',
  name: 'Rate-limit behavior',
  safety_class: 'safe',
  supported_targets: ['fqdn'],
};
const urlCheck = {
  check_id: 'l7.route.safe',
  name: 'Route behavior',
  safety_class: 'safe',
  supported_targets: ['url'],
};

function vector(overrides = {}) {
  return {
    vector_id: 'APP-001',
    canonical_name: 'HTTP GET flood',
    section: 'L7 DDoS',
    family: 'Request flood',
    protocol_service: 'HTTP/S',
    intended_detection_goal: 'Intent only: assess rate-limit evidence. This is not an observed result.',
    failure_means: 'No throttle was observed within declared bounds.',
    expected_controls: 'Per-route rate limiting',
    evidence_capability: 'semantic_safe',
    execution_disposition: 'safe_validation_available',
    safe_check_ids: ['l7.rate.safe'],
    semantic_safe_check_ids: ['l7.rate.safe'],
    ...overrides,
  };
}

describe('portal vector-library truth and target selection', () => {
  it('keeps E1 and E2 labels explicitly below semantic proof', () => {
    assert.match(evidenceCapabilityCopy('declaration_only').detail, /does not prove exposure/i);
    assert.match(evidenceCapabilityCopy('transport_only').detail, /does not prove semantic susceptibility/i);
    assert.match(evidenceCapabilityCopy('soc_governed').detail, /only an authorized governed workflow/i);
    assert.match(evidenceCapabilityCopy('monitor_only').detail, /no active outside-in result/i);
  });

  it('requires an exact target before exposing compatible safe checks', () => {
    assert.equal(vectorTargetAvailability(vector(), [safeCheck], null).id, 'select_target');
    const available = vectorTargetAvailability(vector(), [safeCheck], fqdn);
    assert.equal(available.id, 'safe_runnable');
    assert.deepEqual(available.runnableChecks, [safeCheck]);
    assert.equal(preferredRunnableCheck(vector(), available), safeCheck);
  });

  it('never assigns semantic preference to declaration-only or transport-only rows', () => {
    for (const capability of ['declaration_only', 'transport_only']) {
      const nonSemantic = vector({ evidence_capability: capability, semantic_safe_check_ids: [] });
      const available = vectorTargetAvailability(nonSemantic, [safeCheck], fqdn);
      assert.equal(available.id, 'safe_runnable');
      assert.equal(preferredRunnableCheck(nonSemantic, available), null, capability);
    }
  });

  it('never turns SOC or monitor vectors into customer-runnable checks', () => {
    assert.equal(vectorTargetAvailability(vector({ execution_disposition: 'soc_gated_only' }), [safeCheck], fqdn).id, 'soc_gated');
    assert.equal(vectorTargetAvailability(vector({ execution_disposition: 'monitor_only' }), [safeCheck], fqdn).id, 'monitor_only');
  });

  it('separates unsupported targets from hidden additional-input checks and filters all 721-style fields', () => {
    assert.equal(vectorTargetAvailability(vector({ safe_check_ids: ['l7.route.safe'] }), [urlCheck], fqdn).id, 'target_not_supported');
    assert.equal(vectorTargetAvailability(vector({ safe_check_ids: ['l7.hidden.safe'] }), [safeCheck], fqdn).id, 'additional_input');
    const rows = [vector(), vector({ vector_id: 'APP-002', canonical_name: 'TLS request pressure', expected_controls: 'Connection budgets' })];
    assert.deepEqual(searchAndFilterVectors(rows, { query: 'connection budgets' }).map((row) => row.vector_id), ['APP-002']);
    assert.deepEqual(searchAndFilterVectors(rows, { targetAvailability: 'safe_runnable', checks: [safeCheck], target: fqdn }).map((row) => row.vector_id), ['APP-001', 'APP-002']);
  });
});
