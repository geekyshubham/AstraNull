import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
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
  producer_kind: 'signed_probe',
  nonce_hash: 'nh_1',
  timestamp: FIXED_NOW.toISOString(),
  metadata: { external_result: 'connected' },
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
    findingUpsertCalls: 0,
    failures: new Map(),
    appendedEvents: [],
    runPatches: [],
    staleVerdictReads: true,
    auditLockTail: Promise.resolve(),
    catalogReads: 0,
    findingLockReads: [],
  };
}

function failNext(shared, key) {
  shared.failures.set(key, (shared.failures.get(key) ?? 0) + 1);
}

function consumeFailure(shared, key) {
  const remaining = shared.failures.get(key) ?? 0;
  if (remaining <= 0) return false;
  shared.failures.set(key, remaining - 1);
  return true;
}

function buildRaceRepositories(shared, { withObservation, runOverrides = {} }) {
  const auditClient = {};
  const activeRun = raceRun(runOverrides);
  const probeEvent = {
    ...PROBE_EVENT,
    id: `evt_probe_${activeRun.id}`,
    test_run_id: activeRun.id,
    nonce_hash: activeRun.correlation?.nonce_hash,
  };
  const validationEvidence = {};
  for (const method of VALIDATION_EVIDENCE_REPOSITORY_METHODS) {
    validationEvidence[method] = async () => undefined;
  }

  validationEvidence.withRunMutationLock = async (_ctx, _runId, callback, options = {}) => {
    assert.equal(options.client, auditClient);
    assert.equal(options.wait, true);
    return {
      acquired: true,
      result: await callback(options.client),
    };
  };
  // ADR-0008: verdicts derive from external probe evidence only; there is no agent
  // observation event. Both racing finalizers see the same probe evidence.
  const events = [probeEvent];

  validationEvidence.getTestRun = async (_ctx, id, options = {}) => {
    if (options.client !== undefined) assert.equal(options.client, auditClient);
    return id === activeRun.id ? { ...activeRun } : null;
  };
  validationEvidence.listRunEvents = async (_ctx, runId, options = {}) => {
    if (options.client !== undefined) assert.equal(options.client, auditClient);
    return [...events, ...shared.appendedEvents]
      .filter((event) => event.test_run_id === runId);
  };
  validationEvidence.getTargetGroup = async () => {
    shared.catalogReads += 1;
    return { id: activeRun.target_group_id, targets: [RACE_TARGET] };
  };
  validationEvidence.updateTestRun = async (_ctx, id, patch) => {
    shared.runPatches.push({ id, patch });
    return { ...activeRun, ...patch };
  };
  validationEvidence.appendEvent = async (_ctx, event) => {
    shared.appendedEvents.push(event);
    return event;
  };
  validationEvidence.getVerdictForRun = async (_ctx, runId, options = {}) => {
    if (shared.staleVerdictReads && !options.client) return null;
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
  validationEvidence.findOpenFinding = async (_ctx, binding) => shared.findings.find(
    (finding) => finding.status === 'open'
      && finding.target_group_id === binding.target_group_id
      && finding.target_id === binding.target_id
      && finding.check_id === binding.check_id,
  ) ?? null;
  validationEvidence.listFindings = async (_ctx, options = {}) => {
    if (options.forUpdate) {
      assert.equal(options.client, auditClient);
      shared.findingLockReads.push({
        target_group_id: options.target_group_id,
        target_id: options.target_id,
        check_id: options.check_id,
        client: options.client,
      });
    }
    return shared.findings.filter(
      (finding) => (options.target_group_id == null
          || finding.target_group_id === options.target_group_id)
        && (options.target_id == null || finding.target_id === options.target_id)
        && (options.check_id == null || finding.check_id === options.check_id)
        && (options.test_run_id == null || finding.test_run_id === options.test_run_id),
    ).map((finding) => ({ ...finding }));
  };
  validationEvidence.upsertOpenFindingFromVerdict = async (_ctx, finding, options = {}) => {
    assert.equal(options.client, auditClient);
    shared.findingUpsertCalls += 1;
    if (consumeFailure(shared, 'finding.upsert')) {
      throw new Error('injected finding upsert failure');
    }
    const incomingVerdict = [...shared.verdicts.values()].find(
      (verdict) => verdict.id === finding.last_verdict_id,
    );
    assert.ok(incomingVerdict, 'production SQL requires a durable incoming verdict row');
    const tupleRows = shared.findings.filter(
      (existing) => existing.target_group_id === finding.target_group_id
        && existing.target_id === finding.target_id
        && existing.check_id === finding.check_id,
    );
    if (tupleRows.some(
      (existing) => existing.verdict_id === incomingVerdict.id
        || existing.last_verdict_id === incomingVerdict.id,
    )) return null;

    const chronology = (verdict) => [
      Date.parse(verdict?.created_at ?? '') || Number.NEGATIVE_INFINITY,
      String(verdict?.id ?? ''),
    ];
    const compare = (left, right) => {
      const [leftAt, leftId] = chronology(left);
      const [rightAt, rightId] = chronology(right);
      if (leftAt !== rightAt) return leftAt - rightAt;
      return leftId.localeCompare(rightId);
    };
    const newerOrEqual = tupleRows.some((existing) => {
      const incumbentId = existing.last_verdict_id ?? existing.verdict_id;
      const incumbent = [...shared.verdicts.values()].find((verdict) => verdict.id === incumbentId);
      return incumbent && compare(incumbent, incomingVerdict) >= 0;
    });
    if (newerOrEqual) return null;

    const index = shared.findings.findIndex(
      (existing) => existing.status === 'open'
        && existing.target_group_id === finding.target_group_id
        && existing.target_id === finding.target_id
        && existing.check_id === finding.check_id,
    );
    if (index >= 0) {
      shared.findings[index] = { ...shared.findings[index], ...finding, id: shared.findings[index].id };
      return { ...shared.findings[index] };
    }
    const stored = { ...finding };
    shared.findings.push(stored);
    return { ...stored };
  };

  return {
    validationEvidence,
    audit: {
      withTenantAuditLock: async (_tenantId, callback) => {
        const priorLock = shared.auditLockTail;
        let releaseLock;
        shared.auditLockTail = new Promise((resolve) => { releaseLock = resolve; });
        await priorLock;
        const snapshot = {
          audits: structuredClone(shared.audits),
          findings: structuredClone(shared.findings),
        };
        try {
          return await callback({ client: auditClient, prior: null });
        } catch (error) {
          shared.audits = snapshot.audits;
          shared.findings = snapshot.findings;
          throw error;
        } finally {
          releaseLock();
        }
      },
      appendAuditEvent: async (entry, options = {}) => {
        assert.equal(options.client, auditClient);
        const idempotency = options.idempotency;
        if (idempotency) {
          const actions = idempotency.actions ?? [entry.action];
          const existing = shared.audits.find((auditEntry) =>
            actions.includes(auditEntry.action)
              && auditEntry.resource_type === idempotency.resourceType
              && auditEntry.resource_id === idempotency.resourceId
              && Object.entries(idempotency.metadata ?? {}).every(
                ([key, value]) => auditEntry.metadata?.[key] === value,
              ));
          if (existing) return existing;
        }
        if (consumeFailure(shared, `audit:${entry.action}`)) {
          throw new Error(`injected ${entry.action} audit failure`);
        }
        shared.audits.push(entry);
        return entry;
      },
    },
    coreCatalog: { getTargetGroup: validationEvidence.getTargetGroup },
    probeJobs: { createProbeJob: async () => undefined },
    killSwitch: { isKillSwitchActiveForTenant: async () => false },
  };
}

function buildRaceService(shared, { withObservation, runOverrides = {} }) {
  return createPostgresValidationServices(
    buildRaceRepositories(shared, { withObservation, runOverrides }),
    { now: () => FIXED_NOW },
  );
}

function durableVerdict(run, overrides = {}) {
  return {
    id: `verdict_${run.id}`,
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: run.target_id,
    check_id: run.check_id,
    verdict: 'bypassable',
    confidence: 'high',
    placement_confidence: { level: 'high', status: 'supported' },
    explanation: `Durable verdict for ${run.id}`,
    evidence_ids: [`evt_probe_${run.id}`, `evt_obs_${run.id}`],
    created_at: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

function durableFinding(verdict, run, overrides = {}) {
  return {
    id: `finding_${verdict.id}`,
    tenant_id: run.tenant_id,
    target_group_id: run.target_group_id,
    target_id: run.target_id,
    test_run_id: run.id,
    check_id: run.check_id,
    title: `Finding: ${verdict.verdict} on ${run.target_id}`,
    severity: 'high',
    status: 'open',
    notes: verdict.explanation,
    evidence_ids: [...verdict.evidence_ids],
    remediation_template: run.remediation_template,
    verdict_id: verdict.id,
    last_verdict_id: verdict.id,
    created_at: verdict.created_at,
    updated_at: verdict.created_at,
    ...overrides,
  };
}

function buildDurableRepairService(shared, run, { catalogUnavailable = false } = {}) {
  const repositories = buildRaceRepositories(shared, {
    withObservation: true,
    runOverrides: run,
  });
  if (catalogUnavailable) {
    repositories.coreCatalog.getTargetGroup = async () => {
      shared.catalogReads += 1;
      throw new Error('archived target must not be read from active catalog');
    };
  }
  return createPostgresValidationServices(repositories, { now: () => FIXED_NOW });
}

function verdictAudits(shared) {
  return shared.audits.filter((entry) => String(entry.action ?? '').startsWith('verdict.'));
}

function findingAudits(shared) {
  return shared.audits.filter((entry) => String(entry.action ?? '').startsWith('finding.'));
}

describe('concurrent verdict finalization is single-writer (createVerdictIfAbsent)', () => {
  it('first finalizer wins: a second finalizer returns the incumbent and adds no audit', async () => {
    const shared = createSharedVerdictStore();
    // ADR-0008: both finalizers see the same external probe evidence (connected ->
    // edge_exposed / severity medium). The single-writer invariant still holds.
    const observed = buildRaceService(shared, { withObservation: true });
    const unobserved = buildRaceService(shared, { withObservation: false });

    const winner = await observed.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1');
    assert.equal(winner.verdict, 'edge_exposed');

    const loserResult = await unobserved.testRuns.finalizeTestRun(RACE_CTX, 'run_1', {
      force: true,
    });

    // Exactly one verdict was stored, and it is the first one published.
    assert.equal(shared.verdicts.size, 1);
    const stored = shared.verdicts.get('run_1');
    assert.equal(stored.verdict, 'edge_exposed');

    // The losing finalizer observed the incumbent, not its own duplicate verdict.
    const loserVerdict = loserResult?.verdict ?? loserResult;
    assert.equal(loserVerdict.verdict, 'edge_exposed');
    assert.equal(verdictWasInserted(loserVerdict), false);

    // Audit trail and finding severity both describe the stored verdict, exactly once.
    const audits = verdictAudits(shared);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, 'verdict.published');
    assert.equal(audits[0].metadata.verdict, 'edge_exposed');
    assert.equal(
      shared.audits.some((entry) => entry.action === 'verdict.finalized_no_observation'),
      false,
    );

    assert.equal(shared.findings.length, 1);
    assert.equal(shared.findings[0].severity, 'medium');
    assert.match(shared.findings[0].title, /edge_exposed/);
  });

  it('no-observation finalizer wins: later observation replay cannot rewrite verdict, audit or finding', async () => {
    const shared = createSharedVerdictStore();
    const unobserved = buildRaceService(shared, { withObservation: false });
    const observed = buildRaceService(shared, { withObservation: true });

    const winner = await unobserved.testRuns.finalizeTestRun(RACE_CTX, 'run_1', { force: true });
    assert.equal(winner.verdict.verdict, 'edge_exposed');

    const loserVerdict = await observed.testRuns.maybeFinalizeRunAfterProbeIngest(
      RACE_CTX,
      'run_1',
    );

    assert.equal(shared.verdicts.size, 1);
    assert.equal(shared.verdicts.get('run_1').verdict, 'edge_exposed');

    // The second finalizer got the incumbent back instead of publishing a duplicate.
    assert.equal(loserVerdict.verdict, 'edge_exposed');
    assert.equal(verdictWasInserted(loserVerdict), false);

    const audits = verdictAudits(shared);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, 'verdict.published');
    assert.equal(audits[0].metadata.verdict, 'edge_exposed');

    // edge_exposed creates exactly one finding; the second finalizer must not duplicate it.
    assert.equal(shared.findings.length, 1);
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
    if (stored.verdict === 'edge_exposed') {
      assert.equal(shared.findings.length, 1);
      assert.equal(shared.findings[0].severity, 'medium');
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

describe('verdict publication side effects are crash-repairable', () => {
  it('repairs one verdict audit and required finding after verdict storage outlives an audit failure', async () => {
    const shared = createSharedVerdictStore();
    const service = buildRaceService(shared, { withObservation: true });
    failNext(shared, 'audit:verdict.published');

    await assert.rejects(
      () => service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1'),
      /injected verdict\.published audit failure/,
    );
    assert.equal(shared.verdicts.size, 1, 'immutable verdict survives the side-effect fault');
    assert.equal(verdictAudits(shared).length, 0);
    assert.equal(shared.findings.length, 0);

    const repaired = await service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1');

    assert.equal(repaired.verdict, 'edge_exposed');
    assert.equal(shared.verdicts.size, 1);
    assert.equal(verdictAudits(shared).length, 1);
    assert.equal(verdictAudits(shared)[0].metadata.verdict, 'edge_exposed');
    assert.equal(shared.findings.length, 1);
    assert.equal(shared.findings[0].last_verdict_id, repaired.id);
    assert.equal(findingAudits(shared).length, 1);
    assert.equal(findingAudits(shared)[0].metadata.verdict_id, repaired.id);
  });

  it('does not duplicate a stored verdict audit when retry repairs a failed finding write', async () => {
    const shared = createSharedVerdictStore();
    const service = buildRaceService(shared, { withObservation: true });
    failNext(shared, 'finding.upsert');

    await assert.rejects(
      () => service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1'),
      /injected finding upsert failure/,
    );
    assert.equal(shared.verdicts.size, 1);
    assert.equal(verdictAudits(shared).length, 0, 'failed publication transaction rolls back audit');
    assert.equal(shared.findings.length, 0);
    assert.equal(findingAudits(shared).length, 0);

    const repaired = await service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1');

    assert.equal(repaired.verdict, 'edge_exposed');
    assert.equal(verdictAudits(shared).length, 1);
    assert.equal(shared.findings.length, 1);
    assert.equal(shared.findingUpsertCalls, 2, 'failed write plus one successful repair');
    assert.equal(findingAudits(shared).length, 1);
  });

  it('skips a duplicate finding write when retry repairs its missing per-verdict audit', async () => {
    const shared = createSharedVerdictStore();
    const service = buildRaceService(shared, { withObservation: true });
    failNext(shared, 'audit:finding.created');

    await assert.rejects(
      () => service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1'),
      /injected finding\.created audit failure/,
    );
    assert.equal(shared.verdicts.size, 1);
    assert.equal(verdictAudits(shared).length, 0, 'final audit failure rolls back the transaction');
    assert.equal(shared.findings.length, 0, 'finding mutation rolls back with its final audit');
    assert.equal(shared.findingUpsertCalls, 1);
    assert.equal(findingAudits(shared).length, 0);

    const repaired = await service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1');

    assert.equal(shared.findings.length, 1);
    assert.equal(shared.findingUpsertCalls, 2, 'retry replays the rolled-back finding mutation');
    assert.equal(verdictAudits(shared).length, 1);
    assert.equal(findingAudits(shared).length, 1);
    assert.equal(findingAudits(shared)[0].metadata.verdict_id, repaired.id);
  });

  it('repairs an existing ops-readiness verdict audit once and never creates a finding', async () => {
    const shared = createSharedVerdictStore();
    shared.staleVerdictReads = false;
    shared.verdicts.set('run_1', {
      id: 'verdict_ops_incumbent',
      tenant_id: 'ten_demo',
      test_run_id: 'run_1',
      target_id: 'tgt_1',
      check_id: 'ops.runbook_contact_validation.safe',
      verdict: 'edge_exposed',
      confidence: 'medium',
      placement_confidence: { level: 'medium', status: 'ops_readiness' },
      explanation: 'Durable incumbent used to prove ops findings remain suppressed.',
      evidence_ids: ['evt_probe'],
    });
    const service = buildRaceService(shared, {
      withObservation: true,
      runOverrides: {
        check_id: 'ops.runbook_contact_validation.safe',
        status: 'verdicted',
      },
    });

    const first = await service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1');
    const second = await service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, 'run_1');

    assert.equal(first.id, 'verdict_ops_incumbent');
    assert.equal(second.id, 'verdict_ops_incumbent');
    assert.equal(verdictAudits(shared).length, 1);
    assert.equal(verdictAudits(shared)[0].action, 'verdict.published');
    assert.equal(verdictAudits(shared)[0].metadata.ops_readiness, true);
    assert.equal(shared.findings.length, 0);
    assert.equal(shared.findingUpsertCalls, 0);
    assert.equal(findingAudits(shared).length, 0);
  });
});

describe('terminal verdict publication is chronology-safe and archival-safe', () => {
  it('reconstructs a missing finding and audits from durable state after target archival', async () => {
    const shared = createSharedVerdictStore();
    shared.staleVerdictReads = false;
    const run = raceRun({ status: 'verdicted' });
    const verdict = durableVerdict(run);
    shared.verdicts.set(run.id, verdict);
    const service = buildDurableRepairService(shared, run, { catalogUnavailable: true });

    const repaired = await service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, run.id);

    assert.equal(repaired.id, verdict.id);
    assert.equal(shared.catalogReads, 0, 'incumbent repair must not consult the active catalog');
    assert.equal(shared.findings.length, 1);
    assert.equal(shared.findings[0].target_group_id, run.target_group_id);
    assert.equal(shared.findings[0].target_id, run.target_id);
    assert.equal(shared.findings[0].test_run_id, run.id);
    assert.equal(shared.findings[0].last_verdict_id, verdict.id);
    assert.deepEqual(shared.findings[0].evidence_ids, verdict.evidence_ids);
    assert.equal(verdictAudits(shared).length, 1);
    assert.equal(findingAudits(shared).length, 1);
    assert.equal(findingAudits(shared)[0].metadata.verdict_id, verdict.id);
    assert.ok(shared.findingLockReads.length >= 1);
    assert.ok(shared.findingLockReads.every((read) => read.client));
  });

  it('recognizes an archived exact closed finding as already published without reopening it', async () => {
    const shared = createSharedVerdictStore();
    shared.staleVerdictReads = false;
    const run = raceRun({ status: 'verdicted' });
    const verdict = durableVerdict(run);
    shared.verdicts.set(run.id, verdict);
    shared.findings.push(durableFinding(verdict, run, {
      status: 'resolved',
      closed_at: '2026-01-02T00:00:00.000Z',
    }));
    const service = buildDurableRepairService(shared, run, { catalogUnavailable: true });

    await service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, run.id);
    await service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, run.id);

    assert.equal(shared.catalogReads, 0);
    assert.equal(shared.findingUpsertCalls, 0);
    assert.equal(shared.findings.length, 1);
    assert.equal(shared.findings[0].status, 'resolved');
    assert.equal(shared.findings[0].closed_at, '2026-01-02T00:00:00.000Z');
    assert.equal(verdictAudits(shared).length, 1);
    assert.equal(findingAudits(shared).length, 1);
    assert.equal(findingAudits(shared)[0].metadata.verdict_id, verdict.id);
  });

  it('never regresses, reopens, or duplicates a newer closed finding during older replay', async () => {
    const shared = createSharedVerdictStore();
    shared.staleVerdictReads = false;
    const oldRun = raceRun({ id: 'run_old', status: 'verdicted' });
    const newerRun = raceRun({ id: 'run_new', status: 'verdicted' });
    const oldVerdict = durableVerdict(oldRun, {
      id: 'verdict_old',
      created_at: '2026-01-01T00:00:00.000Z',
    });
    const newerVerdict = durableVerdict(newerRun, {
      id: 'verdict_new',
      created_at: '2026-01-02T00:00:00.000Z',
    });
    shared.verdicts.set(oldRun.id, oldVerdict);
    shared.verdicts.set(newerRun.id, newerVerdict);
    const newerFinding = durableFinding(newerVerdict, newerRun, {
      id: 'finding_newer_closed',
      status: 'resolved',
      closed_at: '2026-01-03T00:00:00.000Z',
    });
    shared.findings.push(newerFinding);
    const service = buildDurableRepairService(shared, oldRun, { catalogUnavailable: true });

    await service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, oldRun.id);

    assert.equal(shared.findingUpsertCalls, 1, 'the SQL-equivalent chronology guard is exercised');
    assert.equal(shared.findings.length, 1);
    assert.deepEqual(shared.findings[0], newerFinding);
    assert.equal(findingAudits(shared).length, 0);
    assert.equal(verdictAudits(shared).length, 1);
  });

  it('treats an exact old closed publication as published even when last_verdict_id is newer', async () => {
    const shared = createSharedVerdictStore();
    shared.staleVerdictReads = false;
    const oldRun = raceRun({ id: 'run_exact_old', status: 'verdicted' });
    const newerRun = raceRun({ id: 'run_exact_new', status: 'verdicted' });
    const oldVerdict = durableVerdict(oldRun, {
      id: 'verdict_exact_old',
      created_at: '2026-01-01T00:00:00.000Z',
    });
    const newerVerdict = durableVerdict(newerRun, {
      id: 'verdict_exact_new',
      created_at: '2026-01-02T00:00:00.000Z',
    });
    shared.verdicts.set(oldRun.id, oldVerdict);
    shared.verdicts.set(newerRun.id, newerVerdict);
    shared.findings.push(durableFinding(oldVerdict, oldRun, {
      id: 'finding_exact_old_closed',
      status: 'resolved',
      last_verdict_id: newerVerdict.id,
      closed_at: '2026-01-03T00:00:00.000Z',
    }));
    const service = buildDurableRepairService(shared, oldRun, { catalogUnavailable: true });

    await service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, oldRun.id);

    assert.equal(shared.findingUpsertCalls, 0);
    assert.equal(shared.findings.length, 1);
    assert.equal(shared.findings[0].status, 'resolved');
    assert.equal(shared.findings[0].verdict_id, oldVerdict.id);
    assert.equal(shared.findings[0].last_verdict_id, newerVerdict.id);
    assert.equal(findingAudits(shared).length, 1);
    assert.equal(findingAudits(shared)[0].metadata.verdict_id, oldVerdict.id);
  });

  for (const order of ['old-first', 'new-first']) {
    it(`concurrent old/new repairs converge on the newer publication (${order})`, async () => {
      const shared = createSharedVerdictStore();
      shared.staleVerdictReads = false;
      const oldRun = raceRun({ id: `run_${order}_old`, status: 'verdicted' });
      const newerRun = raceRun({ id: `run_${order}_new`, status: 'verdicted' });
      const oldVerdict = durableVerdict(oldRun, {
        id: `verdict_${order}_old`,
        created_at: '2026-01-01T00:00:00.000Z',
      });
      const newerVerdict = durableVerdict(newerRun, {
        id: `verdict_${order}_new`,
        created_at: '2026-01-02T00:00:00.000Z',
      });
      shared.verdicts.set(oldRun.id, oldVerdict);
      shared.verdicts.set(newerRun.id, newerVerdict);
      const oldService = buildDurableRepairService(shared, oldRun);
      const newerService = buildDurableRepairService(shared, newerRun);
      const calls = order === 'old-first'
        ? [
            oldService.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, oldRun.id),
            newerService.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, newerRun.id),
          ]
        : [
            newerService.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, newerRun.id),
            oldService.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, oldRun.id),
          ];

      await Promise.all(calls);

      assert.equal(shared.findings.length, 1);
      assert.equal(shared.findings[0].status, 'open');
      assert.equal(shared.findings[0].last_verdict_id, newerVerdict.id);
      assert.equal(shared.findings[0].test_run_id, newerRun.id);
      assert.equal(verdictAudits(shared).length, 2);
      assert.equal(
        shared.findings.filter((finding) =>
          finding.target_group_id === oldRun.target_group_id
            && finding.target_id === oldRun.target_id
            && finding.check_id === oldRun.check_id).length,
        1,
      );
    });
  }

  it('fails a mismatched durable run/verdict tuple before finding or audit publication', async () => {
    const shared = createSharedVerdictStore();
    shared.staleVerdictReads = false;
    const run = raceRun({ id: 'run_mismatched', status: 'verdicted' });
    const verdict = durableVerdict(run, { target_id: 'tgt_wrong' });
    shared.verdicts.set(run.id, verdict);
    const service = buildDurableRepairService(shared, run, { catalogUnavailable: true });

    await assert.rejects(
      () => service.testRuns.maybeFinalizeRunAfterProbeIngest(RACE_CTX, run.id),
      /verdict_run_binding_mismatch:run_mismatched/,
    );

    assert.equal(shared.catalogReads, 0);
    assert.equal(shared.findingUpsertCalls, 0);
    assert.equal(shared.findingLockReads.length, 0);
    assert.equal(shared.findings.length, 0);
    assert.equal(shared.audits.length, 0);
  });
});

describe('verdict-explanation (React portal)', () => {
  it('summarizeExternalProbeEvidence reads external_result from metadata', () => {
    const summary = summarizeExternalProbeEvidence([
      {
        signal_type: 'probe_result',
        producer_kind: 'signed_probe',
        timestamp: '2026-01-01T00:00:00Z',
        metadata: { external_result: 'tcp_connect_ok' },
      },
    ]);
    assert.match(summary, /external_result tcp_connect_ok/);
  });

  it('buildVerdictExplanationFields reports external-probe fields only', () => {
    const fields = buildVerdictExplanationFields(
      {
        remediation_template: 'Fix edge path.',
        verdict: {
          verdict: 'bypassable',
          confidence: 'high',
          explanation: 'Marker reached origin.',
        },
        correlation: { nonce_hash: 'n1' },
      },
      [
        { signal_type: 'probe_result', producer_kind: 'signed_probe', metadata: { external_result: 'ok' } },
      ],
    );

    const labels = fields.map((field) => field.label);
    assert.deepEqual(labels, [
      'External probe evidence',
      'Conclusion',
      'Remediation',
    ]);
    const conclusion = fields.find((field) => field.label === 'Conclusion');
    assert.match(conclusion?.value ?? '', /bypassable/);
    const remediation = fields.find((field) => field.label === 'Remediation');
    assert.equal(remediation?.value, 'Fix edge path.');
  });

  it('ignores public_api signal lookalikes and never derives positive placement from them', () => {
    const fields = buildVerdictExplanationFields(
      {
        verdict: {
          verdict: 'protected',
          confidence: 'high',
          explanation: 'Backend verdict is present.',
          placement_confidence: {
            level: 'high',
            observation_mode: 'packet_metadata',
            agent_id: 'agt_public_decoy',
          },
        },
        correlation: { nonce_hash: 'nonce-trusted' },
      },
      [
        {
          signal_type: 'probe_result',
          producer_kind: 'signed_probe',
          metadata: { external_result: 'trusted-blocked' },
        },
        {
          signal_type: 'probe_result',
          producer_kind: 'public_api',
          metadata: { external_result: 'untrusted-probe-decoy' },
        },
        {
          signal_type: 'agent_observation',
          producer_kind: 'public_api',
          agent_id: 'agt_public_decoy',
          nonce_hash: 'nonce-trusted',
          metadata: { observation_mode: 'untrusted-agent-mode' },
        },
        {
          signal_type: 'agent_no_observation',
          producer_kind: 'public_api',
          metadata: { reason: 'untrusted-no-observation-decoy' },
        },
        {
          signal_type: 'agent_no_observation',
          producer_kind: 'internal_control_plane',
          metadata: { reason: 'trusted-window-elapsed' },
        },
      ],
    );
    const field = (label) => fields.find((entry) => entry.label === label)?.value ?? '';

    assert.match(field('External probe evidence'), /trusted-blocked/);
    assert.doesNotMatch(field('External probe evidence'), /untrusted-probe-decoy/);
    const labels = fields.map((entry) => entry.label);
    assert.deepEqual(labels, ['External probe evidence', 'Conclusion', 'Remediation']);
  });

  it('buildVerdictExplanationFields returns empty array without verdict payload', () => {
    assert.deepEqual(buildVerdictExplanationFields({}, []), []);
    assert.deepEqual(buildVerdictExplanationFields(null, []), []);
  });

  it('normalizeVerdictKey and trafficHopState support visualization helpers', () => {
    assert.equal(normalizeVerdictKey('bypassable'), 'bypassable');
    assert.equal(trafficHopState('origin', 'bypassable'), 'danger');
    assert.equal(trafficHopState('edge', 'protected'), 'ok');
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
          producer_kind: 'signed_probe',
          metadata: { external_result: 'error' },
        },
        {
          signal_type: 'agent_no_observation',
          producer_kind: 'internal_control_plane',
          metadata: { reason: 'bounded_observation_window_elapsed' },
        },
      ],
    });
    assert.match(guidance, /Enable WAF coverage/);
    assert.match(guidance, /reachable from external probes/);
    assert.doesNotMatch(guidance, /Bind an outbound agent/);
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
        { signal_type: 'probe_result', producer_kind: 'signed_probe', metadata: { external_result: 'error' } },
        { signal_type: 'agent_no_observation', producer_kind: 'internal_control_plane', metadata: { reason: 'bounded_observation_window_elapsed' } },
      ],
      {
        finding: {
          title: 'WAF posture unprotected: http://34.28.182.129/',
          remediation_template: 'waf_posture_remediation',
        },
      },
    );

    const remediation = fields.find((field) => field.label === 'Remediation');
    assert.match(remediation?.value ?? '', /Enable WAF coverage/);
    assert.doesNotMatch(remediation?.value ?? '', /Bind an outbound agent/);
    assert.doesNotMatch(remediation?.value ?? '', /waf_posture_remediation/);

    const labels = fields.map((field) => field.label);
    assert.deepEqual(labels, ['External probe evidence', 'Conclusion', 'Remediation']);
  });
});