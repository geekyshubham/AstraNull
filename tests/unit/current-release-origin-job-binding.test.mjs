/**
 * Current-release origin binding runtime fidelity (root-confirmed P1 pair, fielded:
 * backend-bound-job-fidelity.md / root-history-confirmed-review.md findings 1 and 6).
 *
 * 1. A bound run's signed probe job must carry ONLY the server-validated approved scope
 *    (exact existing binding, both current proofs): Host/SNI/port/path. The target is
 *    still the independently verified origin IP literal and stays target-bound.
 * 2. Stamped runs finalize against the immutable expected_behavior_json snapshot; today's
 *    catalog cannot change a collecting run's outcome semantics.
 *
 * No DNS and no sockets: all probe resolution uses injected capturing deps that throw if
 * any resolver would be contacted, and the TLS starter is a local stub.
 */
import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { approvedSignedOriginScope, probeHostSniBypass } from '../../src/lib/capabilityProbes.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import {
  BoundRunScopeMissingError,
  buildSignedProbeJobRecord,
  runBoundOriginScope,
  verifyProbeJobSignature,
} from '../../src/lib/probeJobs.mjs';
import { createOriginBinding } from '../../src/services/originBindings.mjs';
import { finalizeTestRun, startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const SECRET = 'a'.repeat(32);
const SIGNED_WORKER = { probeMode: 'signed-worker', probeWorkerSecret: SECRET };
const TENANT = 'ten_demo';
const GROUP = 'tg_1';
const DECLARED = '2026-09-01T00:00:00.000Z';
const CONTEXT = { tenantId: TENANT, userId: 'u1', role: 'admin' };

function target(partial) {
  getStore().targets.push({
    tenant_id: TENANT,
    target_group_id: GROUP,
    created_at: DECLARED,
    ...partial,
  });
  return getStore().targets.at(-1);
}

function verifyTarget(targetId) {
  const store = getStore();
  if (!Array.isArray(store.targetVerifications)) store.targetVerifications = [];
  store.targetVerifications.push({
    id: `tv_${targetId}_dns_verified`,
    tenant_id: TENANT,
    target_id: targetId,
    state: 'dns_verified',
    source_kind: 'dns_txt',
    source_ref: { dns_challenge_id: `dns_${targetId}` },
    transitioned_at: new Date().toISOString(),
    transitioned_by: 'system',
  });
}

function boundFixture({ originValue = '203.0.113.10' } = {}) {
  const origin = target({ id: 'tgt_origin', kind: 'ip', value: originValue });
  const protectedTarget = target({
    id: 'tgt_protected',
    kind: 'fqdn',
    value: 'app.example',
    declaration_json: { allowed_scope: { ports: [8443], paths: ['/health'] } },
  });
  verifyTarget(origin.id);
  verifyTarget(protectedTarget.id);
  const binding = createOriginBinding(CONTEXT, {
    protected_target_id: protectedTarget.id,
    origin_target_id: origin.id,
  });
  assert.equal(binding.error, undefined);
  return { origin, protectedTarget, binding };
}
function tlsCapture(deps = {}) {
  const captured = [];
  return {
    captured,
    httpsRequestFn: (opts, cb) => {
      captured.push(opts);
      return {
        on() { return this; },
        end() {
          cb({ statusCode: 200, headers: {}, resume() {} });
        },
      };
    },
    // Any DNS attempt must abort: bounded origin service uses the verified literal only.
    resolve4Fn: async () => { throw new Error('dns_call_not_allowed'); },
    resolve6Fn: async () => { throw new Error('dns_call_not_allowed'); },
    ...deps,
  };
}

function noDnsDeps(deps = {}) {
  return {
    // Any DNS attempt must abort: this job's socket destination is the verified literal.
    resolve4Fn: async () => { throw new Error('dns_call_not_allowed'); },
    resolve6Fn: async () => { throw new Error('dns_call_not_allowed'); },
    ...deps,
  };
}

describe('bound run approved-scope propagation (signed probe job)', () => {
  it('starts a real bound signed-worker run, signs the approved scope, and executes exactly it', async () => {
    freshStore();
    const { origin, binding } = boundFixture();
    // Untrusted metadata alias must not survive the signed descriptor either.
    const originTarget = getStore().targets.find((row) => row.id === origin.id);
    originTarget.metadata = { direct_origin_ip: '198.51.100.99' };
    const body = {
      check_id: 'origin.direct_reachability.safe',
      target_group_id: GROUP,
      target_id: origin.id,
      origin_binding_id: binding.id,
      // Untrusted caller input that must not reach signed Host/SNI/port/path selection.
      probe_profile: {
        protected_host: 'other.example',
        marker: 'astranull-safe-marker',
      },
    };

    const result = startTestRun(CONTEXT, body, SIGNED_WORKER);
    assert.equal(result.error, undefined, JSON.stringify(result));
    assert.ok(result.probe_job);
    const run = getStore().testRuns.find((row) => row.id === result.run.id);
    assert.equal(run.origin_binding_id, binding.id);

    // Scope snapshot captured at start in the existing provenance stamp — no migration.
    assert.deepEqual(run.provenance_json.origin_scope, {
      host: 'app.example',
      sni: 'app.example',
      port: 8443,
      path: '/health',
    });

    const job = getStore().probeJobs.find((row) => row.test_run_id === run.id);
    assert.ok(job);
    // Socket destination remains the independently verified target-bound origin IP.
    assert.equal(job.target.value, '203.0.113.10');
    assert.equal(job.target.kind, 'ip');
    assert.equal(JSON.stringify(job).includes('198.51.100.99'), false);
    // Untrusted body profile values cannot retarget the logical Host/SNI/port/path.
    assert.equal(job.probe_profile.protected_host, 'app.example');
    assert.equal(job.probe_profile.direct_ip, undefined);
    assert.deepEqual(job.constraints.origin_scope, {
      host: 'app.example',
      sni: 'app.example',
      port: 8443,
      path: '/health',
    });
    assert.equal(verifyProbeJobSignature(job, SECRET), true);

    // Tampering with any signed scope carrier kills the signature.
    const tamperedProfile = structuredClone(job);
    tamperedProfile.probe_profile.protected_host = 'evil.example';
    assert.equal(verifyProbeJobSignature(tamperedProfile, SECRET), false);
    const tamperedScope = structuredClone(job);
    tamperedScope.constraints.origin_scope.host = 'evil.example';
    assert.equal(verifyProbeJobSignature(tamperedScope, SECRET), false);
    const tamperedTarget = structuredClone(job);
    tamperedTarget.target.value = '198.51.100.99';
    assert.equal(verifyProbeJobSignature(tamperedTarget, SECRET), false);

    // Real approved probe resolution runs the exact signed scope against the literal.
    const tls = tlsCapture();
    const outcome = await probeHostSniBypass(structuredClone(job), tls);
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.protected_host, 'app.example');
    assert.equal(outcome.metadata.direct_ip, '203.0.113.10');
    assert.equal(tls.captured.length, 1);
    assert.equal(tls.captured[0].host, '203.0.113.10');
    assert.equal(tls.captured[0].servername, 'app.example');
    assert.equal(tls.captured[0].port, 8443);
    assert.equal(tls.captured[0].path, '/health');
    assert.equal(tls.captured[0].headers.Host, 'app.example');
  });

  it('keeps the signed path override authoritative when the caller labels a different path', async () => {
    freshStore();
    const { origin, binding } = boundFixture();
    const body = {
      check_id: 'origin.direct_reachability.safe',
      target_group_id: GROUP,
      target_id: origin.id,
      origin_binding_id: binding.id,
      probe_profile: { protected_host: 'other.example', probe_path: '/evil' },
    };
    const result = startTestRun(CONTEXT, body, SIGNED_WORKER);
    assert.equal(result.error, undefined, JSON.stringify(result));
    const job = getStore().probeJobs.find((row) => row.test_run_id === result.run.id);
    assert.equal(job.probe_profile.protected_host, 'app.example');
    assert.deepEqual(job.constraints.origin_scope.path, '/health');
    // Execution still trails the signed scope: the untrusted '/evil' label never executes.
    const https = tlsCapture();
    await probeHostSniBypass(structuredClone(job), https);
    assert.equal(https.captured[0].servername, 'app.example');
    assert.equal(https.captured[0].path, '/health');
    assert.equal(https.captured[0].port, 8443);
  });

  it('derives the signed scope only from the run provenance snapshot, never from caller input', () => {
    freshStore();
    const check = getCheckById('origin.direct_reachability.safe');
    const scope = { host: 'app.example', sni: 'app.example', port: 8443, path: '/health' };
    const boundRun = {
      id: 'run_bound',
      tenant_id: TENANT,
      origin_binding_id: 'obind_x',
      provenance_json: { origin_scope: scope },
    };
    assert.deepEqual(runBoundOriginScope(boundRun, check), scope);
    assert.equal(runBoundOriginScope(
      { id: 'run_x', tenant_id: TENANT, provenance_json: { origin_scope: scope } },
      check,
    ), null,
    'an origin_binding_id is required for any bound scope');
    assert.equal(runBoundOriginScope(boundRun, getCheckById('origin.leak_scan.safe')), null);
    for (const [label, provenance] of [
      ['host/sni mismatch', { origin_scope: { ...scope, sni: 'other.example' } }],
      ['invalid port', { origin_scope: { ...scope, port: 99999 } }],
      ['unsafe path', { origin_scope: { ...scope, path: '//evil.example:9/x' } }],
      ['unshaped host', { origin_scope: { ...scope, host: 'bad host', sni: 'bad host' } }],
      ['non-object scope', { origin_scope: 'app.example' }],
      ['missing scope', {}],
    ]) {
      assert.equal(
        runBoundOriginScope(
          { id: 'run_y', tenant_id: TENANT, origin_binding_id: 'obind_x', provenance_json: provenance },
          check,
        ),
        null,
        label,
      );
    }
    // An origin scope cannot ride a request body or target metadata; only provenance counts.
    assert.equal(
      runBoundOriginScope(
        { id: 'run_z', tenant_id: TENANT, origin_binding_id: 'obind_x' },
        check,
      ),
      null,
    );
  });

  it('consumes the exact signed scope safe keys and cannot be retargeted by profile labels', async () => {
    const approved = approvedSignedOriginScope({
      probe_profile: { kind: 'host_sni_bypass' },
      constraints: { origin_scope: { host: 'bound.example', sni: 'bound.example', port: 8443, path: '/health' } },
    });
    assert.deepEqual(approved, { host: 'bound.example', sni: 'bound.example', port: 8443, path: '/health' });

    // In-memory worker-side defense: even a tampered profile cannot retarget a signed job.
    let captured = null;
    const outcome = await probeHostSniBypass(
      {
        probe_profile: {
          kind: 'host_sni_bypass',
          protected_host: 'evil.example',
        },
        target: { kind: 'ip', value: '203.0.113.10' },
        constraints: {
          timeout_ms: 5000,
          max_requests: 1,
          origin_scope: { host: 'bound.example', sni: 'bound.example', port: 8443, path: '/health' },
        },
      },
      tlsCapture({ httpsRequestFn: (opts, cb) => { captured = opts; return { on() { return this; }, end() { cb({ statusCode: 204, headers: {}, resume() {} }); } }; } }),
    );
    assert.equal(captured.servername, 'bound.example');
    assert.equal(captured.host, '203.0.113.10', 'socket destination stays the target literal');
    assert.equal(captured.port, 8443);
    assert.equal(captured.path, '/health');
    assert.equal(captured.headers.Host, 'bound.example');
    assert.equal(outcome.metadata.protected_host, 'bound.example');
    assert.equal(outcome.metadata.error_class, undefined);

    // A URL target cannot smuggle its own port/path/Host label past the signed scope.
    let urlSeen = null;
    await probeHostSniBypass(
      {
        probe_profile: { kind: 'host_sni_bypass' },
        target: { kind: 'url', value: 'https://203.0.113.10:9999/wrong/path?leak=1' },
        constraints: {
          timeout_ms: 5000,
          max_requests: 1,
          origin_scope: { host: 'bound.example', sni: 'bound.example', port: 8443, path: '/health' },
        },
      },
      {
        fetchFn: async (url, init) => {
          urlSeen = { url: String(url), host: init.headers.Host, path: new URL(String(url)).pathname + new URL(String(url)).search };
          return { status: 200, headers: { get: () => null } };
        },
        ...noDnsDeps(),
      },
    );
    assert.equal(urlSeen.url, 'https://203.0.113.10:8443/health');
    assert.equal(urlSeen.host, 'bound.example');
    assert.equal(urlSeen.path, '/health');

    // HTTP URL targets rebuild onto the approved port/path, not the URL's own.
    let fetchUrl = null;
    await probeHostSniBypass(
      {
        probe_profile: { kind: 'host_sni_bypass' },
        target: { kind: 'url', value: 'http://203.0.113.10:8080/wrong/path' },
        constraints: {
          timeout_ms: 5000,
          max_requests: 1,
          origin_scope: { host: 'bound.example', sni: 'bound.example', port: 8443, path: '/health' },
        },
      },
      {
        fetchFn: async (url) => {
          fetchUrl = String(url);
          return { status: 200, headers: { get: () => null } };
        },
        ...noDnsDeps(),
      },
    );
    assert.equal(fetchUrl, 'http://203.0.113.10:8443/health');
  });

  it('rejects malformed approved-scope payloads and keeps legacy unbound behavior', async () => {
    assert.equal(approvedSignedOriginScope(null), null);
    assert.equal(approvedSignedOriginScope({ probe_profile: { kind: 'origin_leak_scan' }, constraints: { origin_scope: { host: 'x.example', sni: 'x.example' } } }), null);
    for (const [label, scope] of [
      ['split host', { host: 'bound.example', sni: 'other.example' }],
      ['bad port type', { host: 'bound.example', sni: 'bound.example', port: '8443 ' }],
      ['over-range port', { host: 'bound.example', sni: 'bound.example', port: 70000 }],
      ['unsafe path', { host: 'bound.example', sni: 'bound.example', path: '/x?y=1' }],
      ['empty host', { host: '   ', sni: '' }],
      ['unshaped host', { host: 'un_shaped.example', sni: 'un_shaped.example' }],
    ]) {
      assert.equal(
        approvedSignedOriginScope({
          probe_profile: { kind: 'host_sni_bypass' },
          constraints: { origin_scope: scope },
        }),
        null,
        label,
      );
    }

    // Legacy unbound host/SNI resolution is unchanged (no approved scope is consulted).
    let legacyCapture = null;
    const legacyOutcome = await probeHostSniBypass(
      {
        probe_profile: { kind: 'host_sni_bypass', protected_host: 'edge.example.test' },
        target: { kind: 'ip', value: '203.0.113.10' },
        constraints: { timeout_ms: 5000, max_requests: 1 },
      },
      tlsCapture({ httpsRequestFn: (opts, cb) => { legacyCapture = opts; return { on() { return this; }, end() { cb({ statusCode: 200, headers: {}, resume() {} }); } }; } }),
    );
    assert.equal(legacyCapture.servername, 'edge.example.test');
    assert.equal(legacyCapture.port, undefined, 'unbound jobs keep the default port');
    assert.equal(legacyCapture.path, '/');
    assert.equal(legacyOutcome.metadata.protected_host, 'edge.example.test');

    // Unbound real start: no origin_scope rides the signed job, and the request label survives.
    freshStore();
    const unbound = startTestRun(
      CONTEXT,
      {
        check_id: 'origin.direct_reachability.safe',
        target_group_id: GROUP,
        target_id: getStore().targets.find((row) => row.id === 'tgt_1')?.id,
        probe_profile: { protected_host: 'edge.example.test' },
      },
      { probeMode: 'simulation' },
    );
    assert.equal(unbound.error, undefined);
    assert.equal(unbound.run?.provenance_json?.origin_scope, undefined);
  });
});

describe('stamped run expected behavior snapshot at finalization', () => {
  const LEGACY_RUN_ID = 'run_legacy_expected';
  const NULL_SNAPSHOT_RUN_ID = 'run_null_expected';

  afterEach(() => {
    const check = getCheckById('origin.leak_scan.safe');
    check.default_expected_behavior = 'must_block_before_origin';
  });

  it('starts with catalog A then keeps A at finalize even when the catalog changed to B', async () => {
    freshStore();
    const check = getCheckById('origin.leak_scan.safe');
    assert.equal(check.default_expected_behavior, 'must_block_before_origin');

    const result = startTestRun(
      CONTEXT,
      { check_id: 'origin.leak_scan.safe', target_group_id: GROUP, target_id: 'tgt_1' },
      // In-process simulation start: no egress, no probe worker.
      { probeMode: 'simulation' },
    );
    assert.equal(result.error, undefined);
    const run = getStore().testRuns.find((row) => row.id === result.run.id);
    assert.equal(run.producer_kind, 'internal_simulation');
    assert.deepEqual(run.expected_behavior_json.value, 'must_block_before_origin');

    // The catalog changes while the run is collecting...
    check.default_expected_behavior = 'must_reach_canary';

    const finalized = finalizeTestRun(CONTEXT, run.id, { force: true });
    assert.equal(finalized.verdict.verdict, 'edge_exposed');
    assert.equal(finalized.verdict.explanation.includes('did not block traffic before origin'), true);
  });

  it('legacy unstamped runs keep the truthful catalog fallback and stamped null stays unrecorded', () => {
    freshStore();
    const check = getCheckById('origin.leak_scan.safe');
    check.default_expected_behavior = 'must_reach_canary';
    try {
      const store = getStore();
      store.testRuns.push(
        {
          id: LEGACY_RUN_ID,
          tenant_id: TENANT,
          target_group_id: GROUP,
          target_id: 'tgt_1',
          check_id: 'origin.leak_scan.safe',
          vector_family: 'origin',
          status: 'collecting',
          probe_external_result: 'connected',
          correlation: { nonce_hash: null, window_ms: 120000 },
          collection_deadline_at: new Date(Date.now() - 60000).toISOString(),
          created_at: new Date().toISOString(),
          origin_binding_id: null,
          retest_of_finding_id: null,
        },
        {
          id: NULL_SNAPSHOT_RUN_ID,
          tenant_id: TENANT,
          target_group_id: GROUP,
          target_id: 'tgt_1',
          check_id: 'origin.leak_scan.safe',
          vector_family: 'origin',
          producer_kind: 'internal_simulation',
          status: 'collecting',
          probe_external_result: 'connected',
          expected_behavior_json: null,
          correlation: { nonce_hash: null, window_ms: 120000 },
          collection_deadline_at: new Date(Date.now() - 60000).toISOString(),
          created_at: new Date().toISOString(),
          origin_binding_id: null,
          retest_of_finding_id: null,
        },
      );

      const legacy = finalizeTestRun(CONTEXT, LEGACY_RUN_ID, { force: true });
      assert.equal(legacy.verdict.verdict, 'allowed_as_expected', 'legacy unstamped runs fall back to today\'s catalog truthfully');

      const unrecorded = finalizeTestRun(CONTEXT, NULL_SNAPSHOT_RUN_ID, { force: true });
      assert.equal(unrecorded.verdict.verdict, 'inconclusive', 'a stamped run without a recorded snapshot must not read today\'s catalog');
      assert.equal(unrecorded.verdict.explanation, 'Insufficient external probe evidence for a definitive verdict.');
    } finally {
      check.default_expected_behavior = 'must_block_before_origin';
    }
  });

  it('buildSignedProbeJobRecord only embeds scope for bound host/SNI jobs and leaves legacy shape intact', () => {
    freshStore();
    const check = getCheckById('origin.direct_reachability.safe');
    const now = new Date('2026-07-06T00:00:00.000Z');
    const boundJob = buildSignedProbeJobRecord({
      run: {
        id: 'run_bound2',
        tenant_id: TENANT,
        safety_constraints: check.safety_constraints,
        origin_binding_id: 'obind_bound',
        provenance_json: { origin_scope: { host: 'app.example', sni: 'app.example', port: 8443, path: '/health' } },
      },
      check,
      target: { id: 'tgt_origin', kind: 'ip', value: '203.0.113.10' },
      probeProfile: { protected_host: 'other.example', direct_ip: '198.51.100.99' },
      probeWorkerSecret: SECRET,
      now,
      newId: () => 'pjob_bound2',
    });
    assert.equal(boundJob.probe_profile.protected_host, 'app.example');
    assert.equal(boundJob.probe_profile.direct_ip, undefined);
    assert.equal(boundJob.target.value, '203.0.113.10');
    assert.deepEqual(boundJob.constraints.origin_scope, {
      host: 'app.example',
      sni: 'app.example',
      port: 8443,
      path: '/health',
    });
    assert.equal(verifyProbeJobSignature(boundJob, SECRET), true);

    // Genuinely unbound job (no origin_binding_id at all) keeps legacy shape intact.
    const unboundJob = buildSignedProbeJobRecord({
      run: {
        id: 'run_unbound',
        tenant_id: TENANT,
        safety_constraints: check.safety_constraints,
      },
      check,
      target: { id: 'tgt_origin', kind: 'ip', value: '203.0.113.10' },
      probeProfile: { protected_host: 'edge.example.test' },
      probeWorkerSecret: SECRET,
      now,
      newId: () => 'pjob_unbound',
    });
    assert.equal(unboundJob.constraints.origin_scope, undefined);
    assert.equal(unboundJob.probe_profile.protected_host, 'edge.example.test');
    assert.equal(verifyProbeJobSignature(unboundJob, SECRET), true);
  });

  it('fails closed for a bound legacy/recovery record without its approved scope snapshot', () => {
    freshStore();
    const check = getCheckById('origin.direct_reachability.safe');
    const now = new Date('2026-07-06T00:00:00.000Z');
    const boundArgs = (runOverrides = {}, overrides = {}) => ({
      run: {
        id: 'run_bound_legacy',
        tenant_id: TENANT,
        safety_constraints: check.safety_constraints,
        origin_binding_id: 'obind_bound',
        ...runOverrides,
      },
      check,
      // Target metadata must never stand in for a missing approved scope.
      target: {
        id: 'tgt_origin',
        kind: 'ip',
        value: '203.0.113.10',
        metadata: { protected_host: 'different.example' },
      },
      probeProfile: { protected_host: 'other.example' },
      probeWorkerSecret: SECRET,
      now,
      newId: () => 'pjob_never',
      ...overrides,
    });

    // Missing snapshot (the reviewed JOB-RECOVERY-P1 repro: provenance_json:{}).
    for (const [label, provenance] of [
      ['missing provenance', undefined],
      ['empty provenance', {}],
      ['non-object provenance', 'app.example'],
      ['host/sni mismatch', { origin_scope: { host: 'app.example', sni: 'other.example', port: 8443, path: '/health' } }],
      ['invalid port', { origin_scope: { host: 'app.example', sni: 'app.example', port: 70000 } }],
      ['unsafe path', { origin_scope: { host: 'app.example', sni: 'app.example', path: '//evil.example:9/x' } }],
    ]) {
      assert.throws(
        () => buildSignedProbeJobRecord(boundArgs({ provenance_json: provenance })),
        (error) => error instanceof BoundRunScopeMissingError
          && error.code === 'bound_run_missing_approved_origin_scope',
        label,
      );
    }

    // Caller input (probe profile or target metadata) cannot repair the missing stored
    // snapshot into a valid bound scope: the build fails closed regardless.
    assert.throws(
      () => buildSignedProbeJobRecord(boundArgs({ provenance_json: {} }, { probeProfile: { protected_host: 'app.example' } })),
      (error) => error instanceof BoundRunScopeMissingError,
      'caller probe profile cannot repair a missing stored scope',
    );
    assert.throws(
      () => buildSignedProbeJobRecord(
        boundArgs({ provenance_json: {} }, { probeProfile: undefined, probeWorkerSecret: undefined }),
      ),
      (error) => error instanceof BoundRunScopeMissingError,
      'even without signing inputs the bound record fails closed',
    );
  });
});
