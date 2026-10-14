import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { describe, it } from 'node:test';
import '../helpers/reset.mjs';
import {
  additionalInputRefusal,
  checkRequiresAdditionalInput,
  customerSelectableChecks,
  getCheckById,
  CHECK_CATALOG,
  targetInputRefusal,
} from '../../src/contracts/checks.mjs';
import { catalogRuleCoverage, CUSTOM_CANARY_ONLY_REASON, NEVER_RUNNABLE_REASON } from '../../src/contracts/ruleCoverage.mjs';
import { planScanSteps } from '../../src/contracts/validationScanManagement.mjs';
import { probeAxfrLeak } from '../../src/lib/capabilityProbes.mjs';
import { approvedScenarioVersion, deriveCheckDefinitionVersion, gradingSignatureVersionGap } from '../../src/lib/checkDefinitionVersion.mjs';
import { SIGNATURE_CORPUS_VERSION, WAF_GRADING_VERSION } from '../../src/lib/externalObservationOutcomes.mjs';
import { declaredDenyPortPlan } from '../../src/lib/networkProbeOutcomes.mjs';
import { listProbePerspectives, loadProbePerspectivesFromEnv, perspectiveWorkerSecret } from '../../src/lib/probePerspectiveRegistry.mjs';
import { coverageFrom, pairState } from '../../src/lib/protectionCoverage.mjs';
import { probeTcpConnect } from '../../src/lib/safeNetworkProbes.mjs';
import { buildTargetRuleCoverage } from '../../src/services/ruleCoverage.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { authenticateProbeWorker, probeWorkerAuthHeaders } from '../../src/services/probeCoordinator.mjs';
import { sanitizeProbeMetadata } from '../../workers/probe-worker.mjs';

const DENY_22 = { version: 1, network_policy: [{ protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' }] };

function fqdn(metadata) {
  return { id: 'tgt_r2', kind: 'fqdn', value: 'app.r2.example.com', ...(metadata ? { metadata } : {}) };
}

describe('R2 item 1: AXFR deadline cancel reports timeout', () => {
  function silentSocket() {
    return { once() {}, on() {}, write() {}, destroy() {} };
  }

  async function axfrWithAbort(reason, remainingAfterAbort) {
    const controller = new AbortController();
    let aborted = false;
    return probeAxfrLeak({
      constraints: { timeout_ms: 1000, max_requests: 2 },
      probe_profile: { kind: 'dns_axfr_leak', max_requests: 2 },
      target: { kind: 'fqdn', value: 'example.test' },
    }, {
      resolveNsFn: async () => ['ns1.example.test'],
      resolve4Fn: async () => ['203.0.113.53'],
      resolve6Fn: async () => [],
      jobDeadlineSignal: controller.signal,
      remainingJobTimeoutMs: () => (aborted ? remainingAfterAbort : 1000),
      observedJobDurationMs: () => 20,
      connectFn: () => {
        setTimeout(() => { aborted = true; controller.abort(reason); }, 10);
        return silentSocket();
      },
    });
  }

  it('maps a deadline-driven cancel to timeout and an operator stop to not_run', async () => {
    const deadline = await axfrWithAbort(Object.assign(new Error('deadline'), { code: 'probe_job_deadline_exceeded' }), 0);
    assert.equal(deadline.metadata.nameserver_results[0].reason, 'probe_canceled');
    assert.equal(deadline.external_result, 'timeout');
    const stopped = await axfrWithAbort(Object.assign(new Error('stop'), { code: 'probe_stopped' }), 500);
    assert.equal(stopped.external_result, 'not_run');
  });
});

describe('R2 item 2: target-dependent port requirements', () => {
  const portCheck = getCheckById('l3.tcp_flag_anomaly.readiness');
  const denyCheck = getCheckById('l3.basic_deny_rule.safe');

  it('refuses a port-less target and allows a declared tcp/22 rule or a host:port target', () => {
    assert.deepEqual(portCheck.runnable_requires, ['port']);
    assert.equal(additionalInputRefusal(portCheck, {}, { target: fqdn() }).error, 'port_required');
    assert.equal(additionalInputRefusal(denyCheck, {}, { target: fqdn() }).error, 'port_or_declared_deny_required');
    assert.equal(additionalInputRefusal(portCheck, {}, { target: fqdn({ control_declarations: DENY_22 }) }), null);
    assert.equal(additionalInputRefusal(denyCheck, {}, { target: fqdn({ control_declarations: DENY_22 }) }), null);
    assert.equal(additionalInputRefusal(portCheck, {}, { target: fqdn(), declarations: DENY_22 }), null);
    assert.equal(additionalInputRefusal(portCheck, {}, { target: { kind: 'tcp', value: '192.0.2.10:22' } }), null);
    assert.equal(additionalInputRefusal(denyCheck, {}, { target: { kind: 'tcp', value: '192.0.2.10:22' } }), null);
    const udpOnly = { version: 1, network_policy: [{ protocol: 'udp', port: 53, action: 'deny', address_family: 'any' }] };
    assert.equal(targetInputRefusal(portCheck, fqdn(), udpOnly).error, 'port_required');
  });

  it('keeps the no-target catalog view unchanged and lists the check for a satisfying target', () => {
    assert.equal(checkRequiresAdditionalInput(portCheck), true);
    assert.match(portCheck.description, /Not runnable until a TCP\/UDP port is declared/);
    const withoutTarget = customerSelectableChecks(CHECK_CATALOG).map((check) => check.check_id);
    const declared = customerSelectableChecks(CHECK_CATALOG, { target: fqdn(), declarations: DENY_22 }).map((check) => check.check_id);
    const bare = customerSelectableChecks(CHECK_CATALOG, { target: fqdn() }).map((check) => check.check_id);
    assert.equal(withoutTarget.includes(portCheck.check_id), false);
    assert.equal(bare.includes(portCheck.check_id), false);
    assert.equal(declared.includes(portCheck.check_id), true);
    assert.equal(declared.includes(denyCheck.check_id), true);
    assert.equal(customerSelectableChecks(CHECK_CATALOG, { deferTargetRequirements: true }).some((check) => check.check_id === denyCheck.check_id), true);
  });

  it('excludes scan steps per target with the requirement code', () => {
    const declaredTarget = { ...fqdn({ control_declarations: DENY_22 }), id: 'tgt_declared' };
    const bareTarget = { ...fqdn(), id: 'tgt_bare' };
    const plan = planScanSteps({ checks: [portCheck], targets: [declaredTarget, bareTarget], targetInputRefusal });
    assert.deepEqual(plan.steps.map((step) => step.target_id), ['tgt_declared']);
    assert.equal(plan.excluded.length, 1);
    assert.equal(plan.excluded[0].target_id, 'tgt_bare');
    assert.equal(plan.excluded[0].reason, 'port_required');
  });
});

describe('R2 item 3: every declared deny port within the budget', () => {
  function handshakeSocket() {
    const socket = new EventEmitter();
    socket.destroy = () => {};
    queueMicrotask(() => socket.emit('connect'));
    return socket;
  }
  function refusedSocket() {
    const socket = new EventEmitter();
    socket.destroy = () => {};
    queueMicrotask(() => socket.emit('error', Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' })));
    return socket;
  }
  const declarations = {
    version: 1,
    network_policy: [
      { protocol: 'tcp', port: 22, action: 'deny', address_family: 'any' },
      { protocol: 'tcp', port: 443, action: 'allow', address_family: 'any' },
      { protocol: 'tcp', port: 3389, action: 'deny', address_family: 'any' },
      { protocol: 'tcp', port: 5432, action: 'deny', address_family: 'any' },
    ],
  };
  const job = {
    id: 'pjob_r2_deny',
    check_id: 'nfw.declared_deny_tcp.safe',
    constraints: { timeout_ms: 500, max_requests: 2 },
    probe_profile: { kind: 'tcp_connect', max_requests: 2, timeout_ms: 500, declarations },
    target: { kind: 'fqdn', value: 'origin.test' },
  };

  it('probes two of three deny ports with budget 2, never an allow port, and reports each port', async () => {
    assert.deepEqual(declaredDenyPortPlan(job, { protocol: 'tcp', budget: 2 }), [22, 3389]);
    const dialed = [];
    const outcome = await probeTcpConnect(job, {
      sampleGapMs: 0,
      vettedHost: 'origin.test',
      vettedAddresses: ['203.0.113.20'],
      connectFn: ({ port }) => { dialed.push(port); return port === 3389 ? handshakeSocket() : refusedSocket(); },
    });
    assert.deepEqual(dialed, [22, 3389]);
    assert.equal(outcome.requests_sent, 2);
    assert.deepEqual(outcome.metadata.ports_probed, [22, 3389]);
    assert.deepEqual(outcome.metadata.declared_deny_ports, [22, 3389, 5432]);
    assert.deepEqual(outcome.metadata.unprobed_deny_ports, [5432]);
    assert.deepEqual(outcome.metadata.port_results.map((row) => [row.port, row.tcp_outcome]), [[22, 'refused_rst'], [3389, 'handshake']]);
    assert.equal(outcome.metadata.port, 3389);
    const sanitized = sanitizeProbeMetadata(outcome.metadata);
    assert.equal(sanitized.port_results.length, 2);

    const verdict = correlateExternalOnlyVerdict({
      probeKind: 'tcp_connect',
      checkId: 'nfw.declared_deny_tcp.safe',
      externalResult: outcome.external_result,
      probeIoObserved: true,
      probeMetadata: { ...sanitized, peer_is_cdn: false },
      declarations,
    });
    assert.equal(verdict.verdict, 'exposed');
    assert.equal(verdict.severity, 'high');
    assert.match(verdict.explanation, /tcp\/3389/);
    assert.deepEqual(verdict.metadata.port_results.map((row) => [row.port, row.result]), [[22, 'no_violation_observed'], [3389, 'violated']]);
  });

  it('keeps a single declared deny port on the single-port path', () => {
    assert.equal(declaredDenyPortPlan({ ...job, probe_profile: { ...job.probe_profile, declarations: DENY_22 } }, { protocol: 'tcp', budget: 2 }), null);
    assert.equal(declaredDenyPortPlan({ ...job, target: { kind: 'tcp', value: 'origin.test:22' } }, { protocol: 'tcp', budget: 2 }), null);
  });
});

describe('R2 item 5: signature corpus bump makes old blocked runs a version gap', () => {
  it('treats a waf-signatures.2026-10-13 blocked run as a corpus gap that loses credit', () => {
    const OLD = 'waf-signatures.2026-10-13';
    assert.notEqual(SIGNATURE_CORPUS_VERSION, OLD);
    assert.equal(gradingSignatureVersionGap({ grading_version: WAF_GRADING_VERSION, signature_corpus_version: OLD }), 'signature_corpus_version_mismatch');
    const check = getCheckById('waf.sqli_managed_marker.safe');
    const { check_version } = deriveCheckDefinitionVersion(check);
    const completedAt = new Date(Date.now() - 60_000).toISOString();
    const run = {
      id: 'run_old_corpus', status: 'verdicted', completed_at: completedAt, producer_kind: 'signed_probe',
      check_version, scenario_version: approvedScenarioVersion(check), probe_external_result: 'blocked',
      grading_version: WAF_GRADING_VERSION, signature_corpus_version: OLD,
    };
    const verdict = { verdict: 'protected', evidence_ids: ['evt_old_corpus'] };
    const old = pairState(run, verdict, check, Date.now());
    assert.equal(old.state, 'partial');
    assert.equal(old.pair_reason, 'signature_corpus_version_mismatch');
    assert.equal(old.retest_required, true);
    const current = pairState({ ...run, signature_corpus_version: SIGNATURE_CORPUS_VERSION }, verdict, check, Date.now());
    assert.notEqual(current.pair_reason, 'signature_corpus_version_mismatch');
  });
});

describe('R2 item 7: rule coverage customer copy is plain language', () => {
  const MACHINE_TOKEN = /[a-z]+_[a-z_]+/;
  const ALLOWED_TOKENS = new Set();
  const COPY_FIELDS = ['name', 'description', 'assurance_reason', 'not_assessable_reason', 'out_of_scope_reason'];

  function leaks(value) {
    if (typeof value !== 'string') return [];
    return (value.match(new RegExp(MACHINE_TOKEN.source, 'g')) ?? []).filter((token) => !ALLOWED_TOKENS.has(token));
  }

  function assertPlain(categories) {
    const found = [];
    for (const category of categories) {
      for (const field of COPY_FIELDS) for (const token of leaks(category[field])) found.push(`${category.id}.${field}: ${token}`);
      for (const check of category.checks ?? []) {
        for (const token of leaks(check.assurance_reason)) found.push(`${category.id}.${check.check_id}.assurance_reason: ${token}`);
      }
    }
    assert.deepEqual(found, []);
  }

  it('has no internal identifiers in catalog or target copy and keeps machine ids in separate fields', () => {
    assert.equal(MACHINE_TOKEN.test(CUSTOM_CANARY_ONLY_REASON), false);
    assert.equal(MACHINE_TOKEN.test(NEVER_RUNNABLE_REASON), false);
    const catalog = catalogRuleCoverage();
    assertPlain(catalog.categories);
    const target = buildTargetRuleCoverage({ targetId: 'tgt_r2', declarations: {}, runs: [] });
    assertPlain(target.categories);
    const limits = catalog.categories.find((row) => row.id === 'connection_limits');
    assert.ok(limits.probe_kinds.includes('connection_limit_probe'));
    assert.ok(limits.check_ids.includes('nfw.connection_limit.safe'));
    assert.deepEqual(limits.required_declarations, ['connection_limits']);
    const targetLimits = target.categories.find((row) => row.id === 'connection_limits');
    assert.deepEqual(targetLimits.check_ids, limits.check_ids);
    assert.deepEqual(targetLimits.probe_kinds, limits.probe_kinds);
  });
});

describe('R2 item 8: custom canary rollup keeps each member answer', () => {
  it('adds rolled_up_pairs without changing pair counts or scoring', () => {
    const target = { id: 'tgt_r2', tenant_id: 'ten_demo', target_group_id: 'tg_1', kind: 'fqdn', value: 'app.r2.example.com' };
    const canaries = CHECK_CATALOG.filter((check) => check.rule_family === 'custom_canary' && check.supported_targets.includes('fqdn')).slice(0, 2);
    assert.equal(canaries.length, 2);
    const [first, second] = canaries;
    const { check_version } = deriveCheckDefinitionVersion(second);
    const observedAt = new Date(Date.now() - 60_000).toISOString();
    const observations = [{
      check_id: second.check_id,
      run: { id: 'run_canary', tenant_id: 'ten_demo', target_id: target.id, check_id: second.check_id, status: 'verdicted', completed_at: observedAt, producer_kind: 'signed_probe', check_version, scenario_version: approvedScenarioVersion(second), grading_version: WAF_GRADING_VERSION, signature_corpus_version: 'waf-signatures.2026-10-13' },
      verdict: { verdict: 'protected', evidence_ids: ['evt_canary'] },
    }];
    const coverage = coverageFrom({ target, observations, catalog: canaries });
    assert.equal(coverage.coverage.pairs.length, 2);
    assert.equal(coverage.coverage.custom_canary_rollups.length, 1);
    assert.equal(coverage.coverage.applicable_count, 1);
    const row = coverage.coverage.custom_canary_rollups[0];
    assert.ok(row);
    assert.deepEqual(row.rolled_up_check_ids.sort(), [first.check_id, second.check_id].sort());
    const members = Object.fromEntries(row.rolled_up_pairs.map((member) => [member.check_id, member]));
    assert.deepEqual(Object.keys(members).sort(), [first.check_id, second.check_id].sort());
    assert.deepEqual(members[first.check_id], { check_id: first.check_id, last_run_id: null, state: 'not_run', fresh: false, version_gap: null, verdict: null, observed_at: null });
    assert.equal(members[second.check_id].state, 'partial');
    assert.equal(members[second.check_id].version_gap, 'signature_corpus_version_mismatch');
    assert.equal(members[second.check_id].verdict, 'protected');
    assert.equal(members[second.check_id].observed_at, observedAt);
  });
});

describe('R2 item 9: per-perspective worker secrets', () => {
  const SHARED = randomBytes(32).toString('hex');
  const EU_SECRET = randomBytes(32).toString('hex');
  const env = {
    ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([
      { id: 'eu-1', label: 'EU', egress_ips: [], worker_secret: EU_SECRET },
      { id: 'us-1', label: 'US', egress_ips: [] },
    ]),
  };
  const runtime = { probeMode: 'signed-worker', probeWorkerSecret: SHARED };
  const path = '/internal/probe/jobs';

  it('never exposes the secret from the registry', () => {
    assert.equal(perspectiveWorkerSecret('eu-1', env), EU_SECRET);
    assert.equal(perspectiveWorkerSecret('us-1', env), null);
    assert.equal(JSON.stringify(loadProbePerspectivesFromEnv(env)).includes(EU_SECRET), false);
    assert.equal(JSON.stringify(listProbePerspectives(env)).includes(EU_SECRET), false);
    assert.throws(() => loadProbePerspectivesFromEnv({ ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([{ id: 'eu-1', label: 'EU', worker_secret: 'a'.repeat(40) }]) }), /worker_secret/);
  });

  it('refuses a shared-secret claim of a secured perspective with 403 and an audit entry', () => {
    const forged = probeWorkerAuthHeaders('w_any', { method: 'GET', path, tenantId: 'ten_demo', perspectiveId: 'eu-1' }, SHARED);
    const denied = authenticateProbeWorker(forged, 'GET', path, '', runtime, { env });
    assert.equal(denied.ok, false);
    assert.equal(denied.status, 403);
    assert.equal(denied.body.error, 'probe_perspective_unauthenticated');
    assert.equal(denied.auditEntry.action, 'probe_worker.perspective_auth_denied');
    assert.equal(denied.auditEntry.resource_id, 'eu-1');
    assert.equal(JSON.stringify(denied).includes(EU_SECRET) || JSON.stringify(denied).includes(SHARED), false);

    const signed = probeWorkerAuthHeaders('w_eu', { method: 'GET', path, tenantId: 'ten_demo', perspectiveId: 'eu-1' }, EU_SECRET);
    const ok = authenticateProbeWorker(signed, 'GET', path, '', runtime, { env });
    assert.equal(ok.ok, true);
    assert.equal(ok.workerCtx.perspectiveAuthenticated, true);

    const open = probeWorkerAuthHeaders('w_us', { method: 'GET', path, tenantId: 'ten_demo', perspectiveId: 'us-1' }, SHARED);
    const legacy = authenticateProbeWorker(open, 'GET', path, '', runtime, { env });
    assert.equal(legacy.ok, true);
    assert.equal(legacy.workerCtx.perspectiveAuthenticated, false);
  });

  it('returns exposed for the allowlist check only with an authenticated perspective', () => {
    const base = {
      probeKind: 'tcp_connect',
      checkId: 'nfw.perspective_allowlist.safe',
      externalResult: 'connected',
      probeIoObserved: true,
      declarations: { perspectives: { denied_perspective_ids: ['eu-1'] } },
      env,
    };
    const unauthenticated = correlateExternalOnlyVerdict({ ...base, probeMetadata: { tcp_outcome: 'handshake', claimed_perspective_id: 'eu-1', perspective_authenticated: false } });
    assert.equal(unauthenticated.verdict, 'inconclusive');
    assert.match(unauthenticated.explanation, /not authenticated/);
    const authenticated = correlateExternalOnlyVerdict({ ...base, probeMetadata: { tcp_outcome: 'handshake', claimed_perspective_id: 'eu-1', perspective_authenticated: true } });
    assert.equal(authenticated.verdict, 'exposed');
  });
});
