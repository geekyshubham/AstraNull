import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  POSTGRES_STATE_SERVICE_METHODS,
  STATE_CORE_CATALOG_REPOSITORY_METHODS,
  STATE_HIGH_SCALE_REPOSITORY_METHODS,
  STATE_KILL_SWITCH_REPOSITORY_METHODS,
  STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  createPostgresStateServices,
} from '../../src/persistence/postgres/stateServiceAdapters.mjs';
import { ARTIFACT_PROOF_FIELDS, REQUIRED_ARTIFACT_TYPES } from '../../src/lib/highScalePolicy.mjs';
import { computeTargetGroupScopeHash } from '../../src/lib/scopeHash.mjs';
import { projectReadiness } from '../../src/lib/readinessProjection.mjs';
import { assuranceWorld, addAssuredObservation } from '../helpers/assurance-fixtures.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const STATE_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/stateServiceAdapters.mjs'),
  'utf8',
);

const FIXED_NOW = new Date('2026-06-15T12:00:00.000Z');
const RECENT_TS = '2026-06-10T10:00:00.000Z';

function stubRepositories(overrides = {}) {
  const groups = overrides.groups ?? [{ id: 'tg_1', name: 'Edge', tenant_id: 'ten_demo' }];
  const runs = overrides.runs ?? [
    {
      id: 'run_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      created_at: RECENT_TS,
      completed_at: RECENT_TS,
    },
  ];
  const findings = overrides.findings ?? [{ id: 'find_1', tenant_id: 'ten_demo', status: 'open' }];
  const evidence = overrides.evidence ?? [
    { id: 'ev_1', tenant_id: 'ten_demo', test_run_id: 'run_1', related_event_id: 'evt_1', created_at: RECENT_TS },
  ];
  const events = overrides.events ?? [
    {
      id: 'evt_1',
      tenant_id: 'ten_demo',
      test_run_id: 'run_1',
      signal_type: 'probe_result',
      producer_kind: 'signed_probe',
      timestamp: RECENT_TS, ingested_at: RECENT_TS, nonce_hash: 'state_fixture_nonce',
    },
  ];
  const verdict = overrides.verdict ?? {
    id: 'ver_1',
    tenant_id: 'ten_demo',
    test_run_id: 'run_1',
    verdict: 'protected',
    evidence_ids: ['ev_1'],
    created_at: RECENT_TS,
  };
  const highScaleRequests = overrides.highScaleRequests ?? [];
  const killSwitchRecord = overrides.killSwitchRecord ?? {
    tenant_id: 'ten_demo',
    active: false,
    reason: null,
    updated_at: null,
    updated_by: null,
  };

  const coreCatalog = {
    listTargetGroups: async () => groups,
    listTargets: async () => overrides.targets ?? groups.map((group) => ({ id: group.id === 'tg_1' ? 'tgt_1' : `target_${group.id}`, tenant_id: 'ten_demo', target_group_id: group.id })),
  };
  const validationEvidence = {
    listTestRuns: async (_ctx, options) => {
      assert.equal(options.limit, 500);
      return runs;
    },
    listEvidence: async (_ctx, options) => {
      assert.equal(options.limit, 500);
      return evidence;
    },
    countOpenFindings: async () => findings.filter((finding) => finding.status === 'open').length,
    loadRunEvidenceBatch: async (_ctx, selection) => {
      assert.equal(selection.eventLimitPerRun, 1000);
      if (overrides.loadRunEvidenceBatch) return overrides.loadRunEvidenceBatch(selection);

      const verdicts = [];
      for (const runId of selection.runIds) {
        const candidate = overrides.getVerdictForRun
          ? await overrides.getVerdictForRun(runId)
          : runId === 'run_1' ? verdict : null;
        if (candidate) verdicts.push(candidate);
      }

      const selectedEventRunIds = new Set(selection.eventRunIds);
      for (const candidate of verdicts) {
        if (Array.isArray(candidate.evidence_ids) && candidate.evidence_ids.length > 0) {
          selectedEventRunIds.add(candidate.test_run_id);
        }
      }
      const selectedEvents = [];
      for (const runId of selection.runIds) {
        if (!selectedEventRunIds.has(runId)) continue;
        const runEvents = overrides.listRunEvents
          ? await overrides.listRunEvents(runId)
          : events.filter((event) => event.test_run_id === runId);
        selectedEvents.push(...runEvents);
      }
      return { verdicts, events: selectedEvents };
    },
  };
  const highScale = {
    listHighScaleRequests: async () => highScaleRequests,
  };
  const killSwitch = {
    getKillSwitchRecord: async () => killSwitchRecord,
  };

  return { coreCatalog, validationEvidence, highScale, killSwitch };
}

const GOVERNED_REQUEST = Object.freeze({
  tenant_id: 'ten_demo',
  target_group_id: 'tg_1',
  scope_hash: computeTargetGroupScopeHash('ten_demo', 'tg_1'),
  requested_scenario_families: ['udp_flood'],
  delivery_patterns: ['direct'],
  requested_limits: { max_gbps: 0.5, max_duration_minutes: 30 },
  requested_window: {
    window_start: '2026-06-10T00:00:00.000Z',
    window_end: '2026-06-20T00:00:00.000Z',
  },
});

function acceptedAuthorizationArtifacts(request = GOVERNED_REQUEST) {
  const authorizationBinding = {
    tenant_id: request.tenant_id,
    target_group_id: request.target_group_id,
    scope_hash: request.scope_hash,
    requested_window: request.requested_window,
    approved_schedule_window: request.requested_window,
    delivery_patterns: request.delivery_patterns,
  };
  return REQUIRED_ARTIFACT_TYPES.map((type) => ({
    id: `art_${type}`,
    type,
    status: 'accepted',
    approval_reference: 'APPROVED-1',
    approver: 'Security Owner',
    valid_window: {
      window_start: '2026-06-01T00:00:00.000Z',
      window_end: '2099-12-31T23:59:59.999Z',
    },
    approved_targets: [request.target_group_id],
    emergency_contacts: [{ name: 'SOC Lead', phone: '+15555550100' }],
    abort_criteria: {
      stop_on_customer_request: true,
      stop_on_service_health_degradation: true,
    },
    approved_scenario_families: request.requested_scenario_families,
    approved_delivery_patterns: request.delivery_patterns,
    approved_limits: request.requested_limits,
    authorization_binding: authorizationBinding,
    max_rate: 'bounded-by-soc-plan',
    max_duration_minutes: 30,
    proof_fields: ARTIFACT_PROOF_FIELDS[type] ?? [],
  }));
}

describe('postgres state service adapter', () => {
  it('exposes getState service method contract', () => {
    assert.deepEqual(POSTGRES_STATE_SERVICE_METHODS, ['getState']);
    assert.ok(STATE_CORE_CATALOG_REPOSITORY_METHODS.includes('listTargetGroups'));
    assert.ok(STATE_HIGH_SCALE_REPOSITORY_METHODS.includes('listHighScaleRequests'));
    assert.ok(STATE_KILL_SWITCH_REPOSITORY_METHODS.includes('getKillSwitchRecord'));
    for (const method of [
      'listTestRuns',
      'loadRunEvidenceBatch',
      'listEvidence',
      'countOpenFindings',
    ]) {
      assert.ok(STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS.includes(method), method);
    }
  });

  it('throws when required repositories or methods are missing', () => {
    assert.throws(() => createPostgresStateServices({}), /coreCatalog/);
    const partial = stubRepositories();
    delete partial.highScale.listHighScaleRequests;
    assert.throws(
      () => createPostgresStateServices(partial),
      /highScale\.listHighScaleRequests/,
    );
    const noHighScale = stubRepositories();
    delete noHighScale.highScale.listHighScaleRequests;
    assert.throws(
      () => createPostgresStateServices(noHighScale),
      /highScale\.listHighScaleRequests/,
    );
    const noKillSwitch = stubRepositories();
    delete noKillSwitch.killSwitch.getKillSwitchRecord;
    assert.throws(
      () => createPostgresStateServices(noKillSwitch),
      /killSwitch\.getKillSwitchRecord/,
    );
    const noFindingCount = stubRepositories();
    delete noFindingCount.validationEvidence.countOpenFindings;
    assert.throws(
      () => createPostgresStateServices(noFindingCount),
      /validationEvidence\.countOpenFindings/,
    );
  });

  it('does not import dev store or dev readiness modules', () => {
    assert.equal(/\bgetStore\b/.test(STATE_ADAPTER_SOURCE), false);
    assert.equal(/\bcomputeReadiness\b/.test(STATE_ADAPTER_SOURCE), false);
    assert.equal(/from\s+['"].*\/services\//.test(STATE_ADAPTER_SOURCE), false);
  });

  it('loads verdicts and events in one repository call for 500 selected runs', async () => {
    const runs = Array.from({ length: 500 }, (_, index) => ({
      id: `run_batch_${index}`,
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      created_at: new Date(FIXED_NOW.getTime() - index * 1_000).toISOString(),
      completed_at: RECENT_TS,
    }));
    let batchCalls = 0;
    let perRunVerdictCalls = 0;
    let perRunEventCalls = 0;
    let capturedSelection;
    const repositories = stubRepositories({
      runs,
      evidence: [],
      findings: [],
      loadRunEvidenceBatch: async (selection) => {
        batchCalls += 1;
        capturedSelection = selection;
        return {
          verdicts: selection.runIds.map((runId) => ({
            id: `verdict_${runId}`,
            tenant_id: 'ten_demo',
            test_run_id: runId,
            verdict: 'protected',
            evidence_ids: [`event_${runId}`],
            created_at: RECENT_TS,
          })),
          events: selection.runIds.map((runId) => ({
            id: `event_${runId}`,
            tenant_id: 'ten_demo',
            test_run_id: runId,
            signal_type: 'probe_result',
            producer_kind: 'signed_probe',
            timestamp: RECENT_TS,
          })),
        };
      },
    });
    repositories.validationEvidence.getVerdictForRun = async () => {
      perRunVerdictCalls += 1;
      throw new Error('state must not issue per-run verdict reads');
    };
    repositories.validationEvidence.listRunEvents = async () => {
      perRunEventCalls += 1;
      throw new Error('state must not issue per-run event reads');
    };

    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });

    assert.equal(batchCalls, 1);
    assert.equal(perRunVerdictCalls, 0);
    assert.equal(perRunEventCalls, 0);
    assert.equal(capturedSelection.runIds.length, 500);
    assert.equal(new Set(capturedSelection.runIds).size, 500);
    assert.equal(capturedSelection.eventRunIds.length, 30);
    assert.equal(capturedSelection.eventLimitPerRun, 1000);
    assert.equal(payload.recent_runs.length, 5);
  });

  it('labels legacy score without inventing complete inputs from capped readers', async () => {
    const repositories = stubRepositories({
      groups: [],
      agents: [],
      runs: [],
      evidence: [],
      findings: [],
      verdict: false,
    });
    repositories.coreCatalog.getCurrentTenant = async () => ({
      id: 'ten_demo',
      dashboard_rollup: {
        readiness: { score: 97, factors: [], updated_at: '2025-01-01T00:00:00.000Z' },
      },
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });

    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });

    assert.equal(payload.readiness.score, null);
    assert.equal(payload.readiness.legacy_snapshot.snapshot.score, 97);
    assert.equal(payload.readiness.legacy_snapshot.authoritative, false);
    assert.equal(payload.readiness.persistence, 'postgres');
  });
  it('uses an aggregate open-finding count without materializing finding rows', async () => {
    const repositories = stubRepositories();
    let aggregateCalls = 0;
    repositories.validationEvidence.countOpenFindings = async () => {
      aggregateCalls += 1;
      return 100_000;
    };
    repositories.validationEvidence.listFindings = async () => {
      throw new Error('state must not materialize finding rows');
    };
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });

    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });

    assert.equal(aggregateCalls, 1);
    assert.equal(payload.open_findings, 100_000);
    assert.match(
      payload.readiness.factors.find((factor) => factor.key === 'verdicts').detail,
      /Absence of findings is not proof of protection/,
    );
  });

  it('returns dashboard aggregate with evidence-backed readiness and repository-backed SOC state', async () => {
    const repositories = stubRepositories({
      highScaleRequests: [{ id: 'hs_1', tenant_id: 'ten_demo', state: 'submitted', artifacts: [] }],
      killSwitchRecord: {
        tenant_id: 'ten_demo',
        active: true,
        reason: 'incident',
        updated_at: '2026-06-15T11:00:00.000Z',
        updated_by: 'soc_1',
        secret_note: 'do not expose',
      },
      runs: [
        {
          id: 'run_5',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: '2026-06-14T00:00:00.000Z',
        },
        {
          id: 'run_4',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: '2026-06-13T00:00:00.000Z',
        },
        {
          id: 'run_3',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: '2026-06-12T00:00:00.000Z',
        },
        {
          id: 'run_2',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: '2026-06-11T00:00:00.000Z',
        },
        {
          id: 'run_1', correlation: { nonce_hash: 'state_fixture_nonce' },
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: RECENT_TS,
        },
        {
          id: 'run_old',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: '2026-05-01T00:00:00.000Z',
        },
      ],
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const payload = await state.getState(ctx);

    assert.equal(payload.tenant_id, 'ten_demo');
    assert.equal(payload.target_groups, 1);
    assert.equal(payload.open_findings, 1);
    assert.equal(payload.recent_runs.length, 5);
    assert.equal(payload.recent_runs[0].id, 'run_1');
    assert.equal(payload.recent_runs.at(-1).id, 'run_5');
    assert.equal(payload.recent_runs[0].verdict?.id, 'ver_1');
    assert.equal(payload.high_scale_requests, 1);
    assert.equal(payload.high_scale_status, 'degraded');
    assert.deepEqual(payload.kill_switch, {
      tenant_id: 'ten_demo',
      active: true,
      reason: 'incident',
      updated_at: '2026-06-15T11:00:00.000Z',
      updated_by: 'soc_1',
    });

    assert.equal(payload.readiness.score, null);
    assert.equal(payload.readiness.score_status, 'incomplete_inputs');
    const factorKeys = payload.readiness.factors.map((f) => f.key);
    assert.ok(factorKeys.includes('coverage'));
    assert.ok(factorKeys.includes('verdicts'));
    assert.ok(factorKeys.includes('evidence_freshness'));
    const soc = payload.readiness.factors.find((f) => f.key === 'soc_readiness');
    assert.equal(soc.score, 0);
    assert.match(soc.detail, /Kill switch state recorded/);
    assert.match(soc.detail, /Pending gates remain on 1 high-scale request: \d+ missing accepted artifacts, SOC approvals 0\/2\./);
    assert.doesNotMatch(soc.detail, /hs_1/, 'the governance detail never leaks a raw request ID');
    assert.equal(payload.readiness.governance.pending_gates[0].requestId, 'hs_1');
    assert.equal(payload.readiness.governance.pending_gates[0].label, 'High-scale request');
    assert.equal(payload.readiness.persistence, 'postgres');
  });

  it('ignores an evidence-bound protected verdict for an authoritative observation-only check', async () => {
    const repositories = stubRepositories({
      agents: [],
      findings: [],
      evidence: [],
      runs: [{
        id: 'run_1',
        tenant_id: 'ten_demo',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: 'dns.authoritative_response.safe',
        status: 'verdicted',
        created_at: RECENT_TS,
        completed_at: RECENT_TS,
      }],
      verdict: {
        id: 'ver_historical_protected',
        tenant_id: 'ten_demo',
        test_run_id: 'run_1',
        verdict: 'protected',
        evidence_ids: ['evt_dns_liveness'],
        created_at: RECENT_TS,
      },
      events: [{
        id: 'evt_dns_liveness',
        tenant_id: 'ten_demo',
        test_run_id: 'run_1',
        signal_type: 'probe_result',
        producer_kind: 'signed_probe',
        timestamp: RECENT_TS,
        metadata: { external_result: 'blocked', probe_kind: 'host_sni_bypass' },
      }],
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });

    for (const key of ['coverage', 'verdicts', 'evidence_freshness']) {
      assert.equal(payload.readiness.factors.find((factor) => factor.key === key).score, key === 'evidence_freshness' ? 0 : null, key);
    }
  });

  it('does not treat ops declarations or capped feeds as technical assurance', async () => {
    const repositories = stubRepositories({
      agents: [],
      findings: [],
      evidence: [],
      runs: [{
        id: 'run_ops_ready',
        tenant_id: 'ten_demo',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: 'ops.runbook_contact_validation.safe',
        status: 'verdicted',
        created_at: RECENT_TS,
        completed_at: RECENT_TS,
      }],
      verdict: false,
      getVerdictForRun: async (runId) => runId === 'run_ops_ready'
        ? {
            id: 'verdict_ops_ready',
            tenant_id: 'ten_demo',
            test_run_id: 'run_ops_ready',
            verdict: 'protected',
            evidence_ids: ['evt_ops_ready'],
            created_at: RECENT_TS,
          }
        : null,
      events: [{
        id: 'evt_ops_ready',
        tenant_id: 'ten_demo',
        test_run_id: 'run_ops_ready',
        signal_type: 'probe_result',
        producer_kind: 'signed_probe',
        timestamp: RECENT_TS,
        metadata: { external_result: 'connected', ops_validation_ok: true },
      }],
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });

    assert.equal(payload.readiness.factors.find((factor) => factor.key === 'coverage').score, null);
    assert.equal(payload.readiness.factors.find((factor) => factor.key === 'verdicts').score, null);
    assert.equal(payload.readiness.factors.find((factor) => factor.key === 'evidence_freshness').score, 0);
  });

  it('does not award readiness for vault evidence linked to a legacy reserved event', async () => {
    const repositories = stubRepositories({
      agents: [],
      findings: [],
      verdict: false,
      events: [{
        id: 'evt_legacy_link',
        tenant_id: 'ten_demo',
        test_run_id: 'run_1',
        signal_type: 'probe_result',
        producer_kind: 'legacy_untrusted',
        timestamp: RECENT_TS,
      }],
      evidence: [{
        id: 'evidence_legacy_link',
        tenant_id: 'ten_demo',
        test_run_id: 'run_1',
        related_event_id: 'evt_legacy_link',
        created_at: RECENT_TS,
      }],
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });
    const coverage = payload.readiness.factors.find((factor) => factor.key === 'coverage');
    const freshness = payload.readiness.factors.find((factor) => factor.key === 'evidence_freshness');
    assert.equal(coverage.score, null);
    assert.equal(freshness.score, 0);
    assert.match(freshness.detail, /Metadata refresh never renews evidence/);
  });

  it('loads trusted linked evidence for a run beyond the newest thirty', async () => {
    const runs = Array.from({ length: 31 }, (_, index) => ({
      id: `run_${index + 1}`,
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'completed',
      created_at: new Date(FIXED_NOW.getTime() - index * 60_000).toISOString(),
      completed_at: new Date(FIXED_NOW.getTime() - index * 60_000).toISOString(),
    }));
    const repositories = stubRepositories({
      agents: [],
      findings: [],
      runs,
      verdict: false,
      evidence: [{
        id: 'evidence_run_31',
        tenant_id: 'ten_demo',
        test_run_id: 'run_31',
        related_event_id: 'evt_run_31',
        created_at: RECENT_TS,
      }],
      events: [{
        id: 'evt_run_31',
        tenant_id: 'ten_demo',
        test_run_id: 'run_31',
        signal_type: 'probe_result',
        producer_kind: 'signed_probe',
        timestamp: RECENT_TS,
      }],
      getVerdictForRun: async (runId) => runId === 'run_31'
        ? {
            id: 'verdict_run_31',
            tenant_id: 'ten_demo',
            test_run_id: 'run_31',
            verdict: 'protected',
            evidence_ids: ['evt_run_31'],
            created_at: RECENT_TS,
          }
        : null,
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });
    const coverage = payload.readiness.factors.find((factor) => factor.key === 'coverage');
    const freshness = payload.readiness.factors.find((factor) => factor.key === 'evidence_freshness');

    assert.equal(coverage.score, null);
    assert.equal(freshness.score, 0);
  });

  it('reports pending high-scale gates without awarding SOC readiness credit', async () => {
    const repositories = stubRepositories({
      highScaleRequests: [
        {
          id: 'hs_pending',
          tenant_id: 'ten_demo',
          objective: 'Checkout launch surge rehearsal',
          state: 'under_review',
          artifacts: [{ id: 'art_auth', type: 'customer_authorization', status: 'accepted' }],
          soc_approvals: [{ user_id: 'soc_a', at: RECENT_TS }],
        },
      ],
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });
    const soc = payload.readiness.factors.find((f) => f.key === 'soc_readiness');
    assert.equal(payload.high_scale_requests, 1);
    assert.equal(payload.high_scale_status, 'pending');
    assert.equal(soc.score, 0);
    assert.match(soc.detail, /Pending gates remain on high-scale request "Checkout launch surge rehearsal"/);
    assert.match(soc.detail, /SOC approvals 1\/2/);
    assert.match(soc.detail, /\d+ missing accepted artifacts/);
    assert.doesNotMatch(soc.detail, /hs_pending/, 'the governance detail never leaks a raw request ID');
    assert.doesNotMatch(soc.detail, /customer_authorization_letter|emergency_contacts/, 'artifact types are counted, not listed');
    const [gate] = payload.readiness.governance.pending_gates;
    assert.equal(gate.requestId, 'hs_pending');
    assert.equal(gate.label, 'Checkout launch surge rehearsal');
    assert.equal(gate.approvals, 1);
    assert.ok(Array.isArray(gate.missing_artifacts) && gate.missing_artifacts.length > 0);
    assert.ok(gate.missing_artifacts.includes('customer_authorization_letter'));
    assert.equal(gate.pack_complete, false);
    assert.equal(soc.detail.match(/missing accepted artifacts/g)?.length, 1);
  });

  it('flags an incomplete authorization pack when every artifact is accepted but out of validity', async () => {
    const expired = acceptedAuthorizationArtifacts().map((artifact) => ({
      ...artifact,
      valid_window: { window_start: '2026-01-01T00:00:00.000Z', window_end: '2026-01-02T00:00:00.000Z' },
    }));
    const repositories = stubRepositories({
      highScaleRequests: [
        { ...GOVERNED_REQUEST, id: 'hs_expired', objective: 'Expired pack rehearsal', state: 'under_review', artifacts: expired, soc_approvals: [{ user_id: 'soc_a', at: RECENT_TS }] },
      ],
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });
    const soc = payload.readiness.factors.find((f) => f.key === 'soc_readiness');
    const [gate] = payload.readiness.governance.pending_gates;
    assert.equal(gate.requestId, 'hs_expired');
    assert.deepEqual(gate.missing_artifacts, []);
    assert.equal(gate.pack_complete, false, 'accepted but expired artifacts leave the pack incomplete');
    assert.equal(gate.approvals, 1);
    assert.match(soc.detail, /authorization artifact validity or scope incomplete, SOC approvals 1\/2\./);
    assert.doesNotMatch(soc.detail, /hs_expired/);
  });

  it('records governance but no protection credit for accepted authorization pack and two distinct approvers', async () => {
    const repositories = stubRepositories({
      highScaleRequests: [
        {
          ...GOVERNED_REQUEST,
          id: 'hs_ready',
          state: 'approved',
          artifacts: acceptedAuthorizationArtifacts(),
          soc_approvals: [
            { user_id: 'soc_a', at: RECENT_TS },
            { user_id: 'soc_b', at: RECENT_TS },
          ],
        },
      ],
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });
    const soc = payload.readiness.factors.find((f) => f.key === 'soc_readiness');
    assert.equal(soc.score, 0);
    assert.match(soc.detail, /authorization pack accepted/);
    assert.match(soc.detail, /2 SOC approver/);
    assert.doesNotMatch(soc.detail, /hs_ready/, 'governance evidence lines name the request, never its ID');
  });

  it('records governance without protection credit for kill-switch evidence and returns only safe fields', async () => {
    const repositories = stubRepositories({
      killSwitchRecord: {
        tenant_id: 'ten_demo',
        active: false,
        reason: 'drill',
        updated_at: '2026-06-15T11:30:00.000Z',
        updated_by: 'soc_2',
        raw_operator_note: 'sensitive',
      },
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });
    const soc = payload.readiness.factors.find((f) => f.key === 'soc_readiness');
    assert.equal(soc.score, 0);
    assert.match(soc.detail, /Kill switch state recorded/);
    assert.deepEqual(Object.keys(payload.kill_switch).sort(), [
      'active',
      'reason',
      'tenant_id',
      'updated_at',
      'updated_by',
    ]);
    assert.equal(payload.kill_switch.reason, 'drill');
  });
});


describe('complete-reader Postgres/readiness parity', () => {
  function repositoriesFor(world) {
    const repositories = stubRepositories({ groups: world.groups, targets: world.targets, runs: world.runs.slice(0, 500), evidence: world.evidenceItems, findings: world.findings });
    repositories.validationEvidence.readReadinessInputs = async (ctx, { asOf }) => {
      assert.equal(ctx.tenantId, world.tenantId); assert.equal(asOf.toISOString(), world.asOf);
      return { runs: world.runs, verdicts: world.verdicts, events: world.events, evidenceItems: world.evidenceItems, findings: world.findings, policies: world.policies, input_complete: true };
    };
    repositories.validationEvidence.loadRunEvidenceBatch = () => { throw new Error('complete reader must not use bounded evidence for assessment'); };
    return repositories;
  }
  async function assess(world) {
    const state = createPostgresStateServices(repositoriesFor(world), { now: () => new Date(world.asOf), catalog: world.catalog });
    return (await state.getState({ tenantId: world.tenantId, role: 'admin' })).readiness;
  }
  it('exactly matches shared dev semantics for target-pair coverage and finding severity', async () => {
    const world = assuranceWorld({ targetCount: 2, checkCount: 2 }); addAssuredObservation(world);
    world.findings.push({ id: 'f', tenant_id: world.tenantId, severity: 'high', status: 'accepted_risk' });
    assert.deepEqual(await assess(world), { ...projectReadiness(world), persistence: 'postgres' });
    assert.equal((await assess(world)).score, 25);
    assert.equal((await assess(world)).findings.accepted_risk_count, 1);
  });
  it('uses complete cohorts beyond the 500-run feed and never silently truncates the denominator', async () => {
    const world = assuranceWorld({ targetCount: 501 }); for (const target of world.targets) addAssuredObservation(world, { target });
    const result = await assess(world); assert.equal(result.score, 100); assert.equal(result.coverage.applicable_count, 501);
    world.events.at(-1).producer_kind = 'legacy_untrusted'; assert.equal((await assess(world)).score, 99);
  });
  it('keeps unsigned, incomplete, observation-only and stale proofs at zero in both modes', async () => {
    for (const mutation of [(w) => { w.events[0].producer_kind = 'legacy_untrusted'; }, (w) => { w.events[0].metadata.comparison_complete = false; }, (w) => { w.events[0].metadata.enforcement = 'not_enforced'; }, (w) => { delete w.events[0].metadata.enforcement; }, (w) => { w.events[0].nonce_hash = 'wrong_nonce'; }, (w) => { delete w.events[0].ingested_at; }, (w) => { w.catalog[0].observation_only = true; }, (w) => { w.asOf = '2026-10-20T12:00:00.000Z'; }]) {
      const world = assuranceWorld(); addAssuredObservation(world); mutation(world);
      assert.deepEqual(await assess(world), { ...projectReadiness(world), persistence: 'postgres' }); assert.equal((await assess(world)).score, 0);
    }
  });
  it('invalidates material scope/check changes at read time without rewriting custody', async () => {
    const world = assuranceWorld(); addAssuredObservation(world); const before = structuredClone({ runs: world.runs, verdicts: world.verdicts, events: world.events }); world.targets[0].value += '/changed';
    const result = await assess(world); assert.equal(result.current_assurance.status, 'retest_required'); assert.equal(result.score, 0);
    assert.deepEqual({ runs: world.runs, verdicts: world.verdicts, events: world.events }, before);
  });
  it('uses exact complete snapshot scope without expensive list-page hydration and falls back only without explicit scope proof', async () => {
    const world = assuranceWorld(); addAssuredObservation(world); const repos = repositoriesFor(world);
    repos.coreCatalog.listTargets = repos.coreCatalog.listTargetGroups = () => { throw new Error('presentation hydration must not run'); };
    repos.validationEvidence.readReadinessInputs = async () => ({ ...world, scope_complete: true });
    const result = await createPostgresStateServices(repos, { now: () => new Date(world.asOf), catalog: world.catalog }).getState({ tenantId: world.tenantId });
    assert.deepEqual(result.readiness, { ...projectReadiness(world), persistence: 'postgres' });
    assert.equal(result.target_groups, world.groups.length);
  });
  it('still refuses a reader that explicitly declares incomplete inputs', async () => {
    const world = assuranceWorld(); addAssuredObservation(world); const repos = repositoriesFor(world);
    repos.validationEvidence.readReadinessInputs = async () => ({ ...world, input_complete: false });
    const result = await createPostgresStateServices(repos, { now: () => new Date(world.asOf), catalog: world.catalog }).getState({ tenantId: world.tenantId });
    assert.equal(result.readiness.score, null); assert.equal(result.readiness.input_complete, false);
  });
});
