import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS,
  VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  createPostgresValidationServices,
} from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import {
  VERDICT_INSERTED,
  verdictWasInserted,
} from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import {
  buildVerdictExplanationFields,
  normalizeVerdictKey,
  resolveRemediationTemplate,
  summarizeExternalProbeEvidence,
  summarizeObservationMode,
  summarizePlacementConfidence,
  trafficHopState,
} from '../../apps/web/react/src/lib/verdict-explanation.ts';

const RACE_CTX = { tenantId: 'ten_demo', userId: 'system', role: 'system' };
const FIXED_NOW = new Date('2026-01-01T00:00:00.000Z');

const RACE_TARGET = {
  id: 'tgt_1',
  value: '203.0.113.1',
  expected_behavior: 'must_block_before_origin',
};

function raceRun(overrides = {}) {
  return {
    id: 'run_1',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    target_id: 'tgt_1',
    check_id: 'origin.direct_bypass.safe',
    status: 'collecting',
    correlation: { nonce_hash: 'nh_1', window_ms: 120_000 },
    probe_external_result: 'connected',
    awaiting_external_probe: false,
    // Deadline already elapsed so the sweeper path considers the run finalizable.
    collection_deadline_at: '2025-01-01T00:00:00.000Z',
    remediation_template: 'block_origin',
    safety_constraints: { max_events: 50 },
    ...overrides,
  };
}

const PROBE_EVENT = {
  id: 'evt_probe',
  test_run_id: 'run_1',
  signal_type: 'probe_result',
  nonce_hash: 'nh_1',
  timestamp: FIXED_NOW.toISOString(),
  metadata: { external_result: 'connected' },
};

const OBSERVATION_EVENT = {
  id: 'evt_obs',
  test_run_id: 'run_1',
  signal_type: 'agent_observation',
  agent_id: 'ag_1',
  nonce_hash: 'nh_1',
  timestamp: FIXED_NOW.toISOString(),
};

const ONLINE_AGENT = {
  id: 'ag_1',
  tenant_id: 'ten_demo',
  status: 'online',
  target_group_id: 'tg_1',
};

/**
 * Shared backing "database" for two independent finalizer instances.
 *
 * `verdicts` enforces the real `uniq_verdict_per_test_run` + ON CONFLICT DO NOTHING
 * semantics: the first insert for a run wins, later inserts are suppressed and get the
 * incumbent back tagged VERDICT_INSERTED=false.
 *
 * `staleVerdictReads` keeps `getVerdictForRun` answering null so both racers get past
 * their pre-insert existence check, which is exactly the interleaving that let the old
 * DO UPDATE version overwrite a published verdict.
 */
function createSharedVerdictStore() {
  return {
    verdicts: new Map(),
    audits: [],
    findings: [],
    appendedEvents: [],
    runPatches: [],
    staleVerdictReads: true,
  };
}

function buildRaceRepositories(shared, { withObservation }) {
  const validationEvidence = {};
  for (const method of VALIDATION_EVIDENCE_REPOSITORY_METHODS) {
    validationEvidence[method] = async () => undefined;
  }

  const events = withObservation ? [PROBE_EVENT, OBSERVATION_EVENT] : [PROBE_EVENT];

  validationEvidence.getTestRun = async () => raceRun();
  validationEvidence.listRunEvents = async () => [...events, ...shared.appendedEvents];
  validationEvidence.getTargetGroup = async () => ({ id: 'tg_1', targets: [RACE_TARGET] });
  validationEvidence.updateTestRun = async (_ctx, id, patch) => {
    shared.runPatches.push({ id, patch });
    return { ...raceRun(), ...patch };
  };
  validationEvidence.appendEvent = async (_ctx, event) => {
    shared.appendedEvents.push(event);
    return event;
  };
  validationEvidence.getVerdictForRun = async (_ctx, runId) => {
    if (shared.staleVerdictReads) return null;
    return shared.verdicts.get(runId) ?? null;
  };
  validationEvidence.createVerdictIfAbsent = async (_ctx, record) => {
    const incumbent = shared.verdicts.get(record.test_run_id);
    if (incumbent) {
      return { ...incumbent, [VERDICT_INSERTED]: false };
    }
    const stored = { ...record, [VERDICT_INSERTED]: true };
    shared.verdicts.set(record.test_run_id, stored);
    return stored;
  };
  validationEvidence.findOpenFinding = async () => null;
  validationEvidence.upsertOpenFindingFromVerdict = async (_ctx, finding) => {
    shared.findings.push(finding);
    return finding;
  };

  const agentControl = {};
  for (const method of VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS) {
    agentControl[method] = async () => undefined;
  }
  agentControl.listAgents = async () => [ONLINE_AGENT];

  return {
    validationEvidence,
    audit: {
      appendAuditEvent: async (entry) => {
        shared.audits.push(entry);
        return entry;
      },
    },
    coreCatalog: { getTargetGroup: validationEvidence.getTargetGroup },
    agentControl,
    probeJobs: { createProbeJob: async () => undefined },
    killSwitch: { isKillSwitchActiveForTenant: async () => false },
  };
}

function buildRaceService(shared, { withObservation }) {
  return createPostgresValidationServices(buildRaceRepositories(shared, { withObservation }), {
    now: () => FIXED_NOW,
  });
}

function verdictAudits(shared) {
  return shared.audits.filter((entry) => String(entry.action ?? '').startsWith('verdict.'));
}

describe('concurrent verdict finalization is single-writer (createVerdictIfAbsent)', () => {
  it('observation finalizer wins: no-observation replay returns the incumbent and adds no audit', async () => {
    const shared = createSharedVerdictStore();
    // Observation-ingest finalizer: agentObserved = true -> bypassable / severity high.
    const observed = buildRaceService(shared, { withObservation: true });
    // Sweeper finalizer: agentObserved = false -> misplaced_agent / no finding.
    const unobserved = buildRaceService(shared, { withObservation: false });

    const winner = await observed.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1');
    assert.equal(winner.verdict, 'bypassable');

    const loserResult = await unobserved.testRuns.finalizeTestRun(RACE_CTX, 'run_1', {
      force: true,
    });

    // Exactly one verdict was stored, and it is the first one published.
    assert.equal(shared.verdicts.size, 1);
    const stored = shared.verdicts.get('run_1');
    assert.equal(stored.verdict, 'bypassable');

    // The losing finalizer observed the incumbent, not its own opposite verdict.
    const loserVerdict = loserResult?.verdict ?? loserResult;
    assert.equal(loserVerdict.verdict, 'bypassable');
    assert.notEqual(loserVerdict.verdict, 'misplaced_agent');
    assert.equal(verdictWasInserted(loserVerdict), false);

    // Audit trail and finding severity both describe the stored verdict, exactly once.
    const audits = verdictAudits(shared);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, 'verdict.published');
    assert.equal(audits[0].metadata.verdict, 'bypassable');
    assert.equal(
      shared.audits.some((entry) => entry.action === 'verdict.finalized_no_observation'),
      false,
    );

    assert.equal(shared.findings.length, 1);
    assert.equal(shared.findings[0].severity, 'high');
    assert.match(shared.findings[0].title, /bypassable/);
  });

  it('no-observation finalizer wins: later observation replay cannot rewrite verdict, audit or finding', async () => {
    const shared = createSharedVerdictStore();
    const unobserved = buildRaceService(shared, { withObservation: false });
    const observed = buildRaceService(shared, { withObservation: true });

    const winner = await unobserved.testRuns.finalizeTestRun(RACE_CTX, 'run_1', { force: true });
    assert.equal(winner.verdict.verdict, 'misplaced_agent');

    const loserVerdict = await observed.testRuns.maybeFinalizeRunAfterProbeIngest(
      RACE_CTX,
      'run_1',
    );

    assert.equal(shared.verdicts.size, 1);
    assert.equal(shared.verdicts.get('run_1').verdict, 'misplaced_agent');

    // The observation finalizer got the incumbent back instead of publishing 'bypassable'.
    assert.equal(loserVerdict.verdict, 'misplaced_agent');
    assert.equal(verdictWasInserted(loserVerdict), false);

    const audits = verdictAudits(shared);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, 'verdict.finalized_no_observation');
    assert.equal(audits[0].metadata.verdict, 'misplaced_agent');

    // misplaced_agent creates no finding; the suppressed 'bypassable' must not add a
    // high-severity finding that contradicts the stored verdict.
    assert.equal(shared.findings.length, 0);
  });

  it('two concurrent finalizers produce exactly one verdict and one audit event', async () => {
    const shared = createSharedVerdictStore();
    const observed = buildRaceService(shared, { withObservation: true });
    const unobserved = buildRaceService(shared, { withObservation: false });

    const [a, b] = await Promise.all([
      observed.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1'),
      unobserved.testRuns.finalizeTestRun(RACE_CTX, 'run_1', { force: true }),
    ]);

    assert.equal(shared.verdicts.size, 1);
    const stored = shared.verdicts.get('run_1');

    const audits = verdictAudits(shared);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].metadata.verdict, stored.verdict);

    // Both callers agree on the single stored verdict.
    const bVerdict = b?.verdict ?? b;
    assert.equal(a.verdict, stored.verdict);
    assert.equal(bVerdict.verdict, stored.verdict);

    // Findings, if any, match the stored verdict's severity.
    if (stored.verdict === 'bypassable') {
      assert.equal(shared.findings.length, 1);
      assert.equal(shared.findings[0].severity, 'high');
    } else {
      assert.equal(shared.findings.length, 0);
    }
  });

  it('verdictWasInserted treats a missing flag as inserted so plain doubles still work', () => {
    assert.equal(verdictWasInserted({ verdict: 'protected' }), true);
    assert.equal(verdictWasInserted({ verdict: 'protected', [VERDICT_INSERTED]: true }), true);
    assert.equal(verdictWasInserted({ verdict: 'protected', [VERDICT_INSERTED]: false }), false);
    assert.equal(verdictWasInserted(null), false);
  });

  it('the inserted flag is invisible to JSON and Object.keys (cannot leak into API shape)', () => {
    const verdict = { id: 'ver_1', verdict: 'protected', [VERDICT_INSERTED]: false };
    assert.equal(Object.keys(verdict).includes('inserted'), false);
    assert.equal(JSON.stringify(verdict).includes('inserted'), false);
    assert.deepEqual(Object.keys(verdict), ['id', 'verdict']);
  });
});

describe('verdict-explanation (React portal)', () => {
  it('summarizeExternalProbeEvidence reads external_result from metadata', () => {
    const summary = summarizeExternalProbeEvidence([
      {
        signal_type: 'probe_result',
        timestamp: '2026-01-01T00:00:00Z',
        metadata: { external_result: 'tcp_connect_ok' },
      },
    ]);
    assert.match(summary, /external_result tcp_connect_ok/);
  });

  it('buildVerdictExplanationFields prefers backend placement_confidence', () => {
    const fields = buildVerdictExplanationFields(
      {
        remediation_template: 'Fix edge path.',
        verdict: {
          verdict: 'bypassable',
          confidence: 'high',
          explanation: 'Marker reached origin.',
          placement_confidence: { level: 'high', observation_mode: 'packet_metadata' },
        },
        correlation: { nonce_hash: 'n1' },
      },
      [
        { signal_type: 'probe_result', metadata: { external_result: 'ok' } },
        { signal_type: 'agent_observation', nonce_hash: 'n1', agent_id: 'ag_1' },
      ],
    );

    const labels = fields.map((field) => field.label);
    assert.deepEqual(labels, [
      'External probe evidence',
      'Internal agent evidence',
      'Observation mode',
      'Placement confidence',
      'Conclusion',
      'Remediation',
    ]);
    const placement = fields.find((field) => field.label === 'Placement confidence');
    assert.match(placement?.value ?? '', /high/);
    assert.match(placement?.value ?? '', /packet_metadata/);
    const conclusion = fields.find((field) => field.label === 'Conclusion');
    assert.match(conclusion?.value ?? '', /bypassable/);
    const remediation = fields.find((field) => field.label === 'Remediation');
    assert.equal(remediation?.value, 'Fix edge path.');
  });

  it('buildVerdictExplanationFields returns empty array without verdict payload', () => {
    assert.deepEqual(buildVerdictExplanationFields({}, []), []);
    assert.deepEqual(buildVerdictExplanationFields(null, []), []);
  });

  it('summarizePlacementConfidence falls back when backend placement is absent', () => {
    const supported = summarizePlacementConfidence(
      [{ signal_type: 'agent_observation', nonce_hash: 'n1' }],
      [],
      undefined,
    );
    assert.match(supported, /supported by job-bound agent observation/);

    const limited = summarizePlacementConfidence(
      [],
      [{ signal_type: 'agent_no_observation' }],
      undefined,
    );
    assert.match(limited, /limited/);
  });

  it('normalizeVerdictKey and trafficHopState support visualization helpers', () => {
    assert.equal(normalizeVerdictKey('misplaced_agent'), 'misplaced');
    assert.equal(trafficHopState('origin', 'bypassable'), 'danger');
    assert.equal(trafficHopState('edge', 'protected'), 'ok');
  });

  it('summarizeObservationMode uses agent_no_observation metadata reason', () => {
    const summary = summarizeObservationMode([
      {
        signal_type: 'agent_no_observation',
        metadata: { reason: 'bounded_observation_window_elapsed' },
      },
    ]);
    assert.match(summary, /bounded_observation_window_elapsed/);
    assert.doesNotMatch(summary, /^agent_no_observation$/);
  });

  it('resolveRemediationTemplate expands waf_posture_remediation from finding and run evidence', () => {
    const guidance = resolveRemediationTemplate('waf_posture_remediation', {
      finding: {
        title: 'WAF posture unprotected: http://34.28.182.129/',
        notes: 'Posture status: unprotected. Reason codes: insufficient_validation_evidence.',
      },
      detail: {
        verdict: {
          placement_confidence: {
            level: 'invalid',
            observation_mode: 'unbound',
            reason: 'No agent is bound to this target group; internal path proof is unavailable.',
          },
        },
      },
      events: [
        {
          signal_type: 'probe_result',
          metadata: { external_result: 'error' },
        },
        {
          signal_type: 'agent_no_observation',
          metadata: { reason: 'bounded_observation_window_elapsed' },
        },
      ],
    });
    assert.match(guidance, /Enable WAF coverage/);
    assert.match(guidance, /reachable from external probes/);
    assert.match(guidance, /Bind an outbound agent/);
    assert.doesNotMatch(guidance, /waf_posture_remediation/);
  });

  it('buildVerdictExplanationFields resolves known remediation template keys for findings', () => {
    const fields = buildVerdictExplanationFields(
      {
        remediation_template: 'waf_posture_remediation',
        verdict: {
          verdict: 'inconclusive',
          confidence: 'low',
          explanation: 'Agent is offline or not bound to the target group; internal observation evidence is unavailable.',
          placement_confidence: {
            level: 'invalid',
            observation_mode: 'unbound',
            reason: 'No agent is bound to this target group; internal path proof is unavailable.',
          },
        },
      },
      [
        { signal_type: 'probe_result', metadata: { external_result: 'error' } },
        { signal_type: 'agent_no_observation', metadata: { reason: 'bounded_observation_window_elapsed' } },
      ],
      {
        finding: {
          title: 'WAF posture unprotected: http://34.28.182.129/',
          remediation_template: 'waf_posture_remediation',
        },
      },
    );

    const remediation = fields.find((field) => field.label === 'Remediation');
    assert.match(remediation?.value ?? '', /Bind an outbound agent/);
    assert.doesNotMatch(remediation?.value ?? '', /waf_posture_remediation/);

    const observationMode = fields.find((field) => field.label === 'Observation mode');
    assert.match(observationMode?.value ?? '', /bounded_observation_window_elapsed/);
  });
});