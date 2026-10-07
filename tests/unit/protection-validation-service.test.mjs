import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  assessComparisonCompatibility,
  classifyFirewallComparisonItem,
  entryPathDeclarationDigest,
  REQUIRED_LIMITATIONS,
  verifyBaselineDigest,
} from '../../src/contracts/protectionValidation.mjs';
import {
  archiveEntryPath,
  archiveExpectation,
  authorizeEntryPathForExecution,
  buildRunEvidenceReference,
  captureFirewallBaseline,
  capturePathValidationBaseline,
  createEntryPath,
  createFirewallExpectation,
  getBaselineCapture,
  getEntryPath,
  getEvaluation,
  listBaselineCaptures,
  listEntryPaths,
  listEvaluations,
  listExpectations,
  PROTECTION_VALIDATION_STORE_KEYS,
  recordComparisonEvaluation,
  recordPathValidationExpectation,
  resolveRunEvidence,
} from '../../src/services/protectionValidation.mjs';
import { getStore } from '../../src/store.mjs';

const TENANT = 'ten_pv_unit';
const OTHER = 'ten_pv_other';
const GROUP = 'tg_pv_unit';
const DECLARED = '2026-09-01T00:00:00.000Z';
const OWNER = { tenantId: TENANT, userId: 'usr_owner', role: 'owner' };
const VIEWER = { tenantId: TENANT, userId: 'usr_view', role: 'viewer' };
const SOC = { tenantId: TENANT, userId: 'usr_soc', role: 'soc' };
const OTHER_OWNER = { tenantId: OTHER, userId: 'usr_other', role: 'owner' };
const TCP_CHECK = 'l3.basic_deny_rule.safe';
const NOW = new Date('2026-10-06T00:00:00.000Z');

function scrub() {
  const store = getStore();
  const keys = [
    'targets', 'targetVerifications', 'originBindings', 'testRuns', 'probeJobs', 'events', 'verdicts', 'auditLog',
    ...Object.values(PROTECTION_VALIDATION_STORE_KEYS),
  ];
  for (const key of keys) {
    if (!Array.isArray(store[key])) continue;
    store[key] = store[key].filter((row) => row.tenant_id !== TENANT && row.tenant_id !== OTHER);
  }
}

function target(id, partial = {}, { verified = true, tenant = TENANT } = {}) {
  const store = getStore();
  store.targets.push({ id, tenant_id: tenant, target_group_id: GROUP, created_at: DECLARED, kind: 'fqdn', value: `${id}.example.test`, ...partial });
  if (verified) {
    store.targetVerifications.push({ id: `tv_${id}`, tenant_id: tenant, target_id: id, state: 'dns_verified', transitioned_at: DECLARED });
  }
}

function signedRun(id, overrides = {}) {
  const {
    tenant = TENANT,
    targetId = 'tgt_fw',
    check = TCP_CHECK,
    status = 'verdicted',
    producer = 'signed_probe',
    source = 'public-worker-eu',
    worker = 'worker_eu_1',
    port = 443,
    observedAt = '2026-10-05T00:00:00.000Z',
    signed = true,
  } = overrides;
  const store = getStore();
  store.testRuns.push({
    id, tenant_id: tenant, target_group_id: GROUP, target_id: targetId, check_id: check, status,
    producer_kind: producer, check_version: 'v1', scenario_version: null, completed_at: observedAt, provenance_json: {},
  });
  store.probeJobs.push({
    id: `job_${id}`, tenant_id: tenant, test_run_id: id, status: 'completed', leased_by: worker,
    job_signature: signed ? 'sig' : null, target: { id: targetId, port }, worker_metadata: { source_perspective: source }, completed_at: observedAt,
  });
  store.events.push({
    id: `evt_${id}`, tenant_id: tenant, test_run_id: id, signal_type: 'probe_result', producer_kind: 'signed_probe', timestamp: observedAt, metadata: {},
  });
  store.verdicts.push({ id: `vrd_${id}`, tenant_id: tenant, test_run_id: id, evidence_ids: [`ev_${id}`], created_at: observedAt });
}

function seed() {
  scrub();
  target('tgt_app');
  target('tgt_alt');
  target('tgt_login');
  target('tgt_unverified', {}, { verified: false });
  target('tgt_origin', { kind: 'ip', value: '203.0.113.10' });
  target('tgt_fw', { kind: 'ip', value: '198.51.100.5' });
  target('tgt_old', { kind: 'ip', value: '198.51.100.4' });
  target('tgt_deleted', { deleted_at: DECLARED });
  target('tgt_foreign', {}, { tenant: OTHER });
  const store = getStore();
  store.originBindings = store.originBindings ?? [];
  store.originBindings.push(
    { id: 'obind_pv', tenant_id: TENANT, protected_target_id: 'tgt_app', origin_target_id: 'tgt_origin', status: 'active', created_at: DECLARED },
    { id: 'obind_foreign', tenant_id: OTHER, protected_target_id: 'tgt_foreign', origin_target_id: 'tgt_foreign', status: 'active', created_at: DECLARED },
  );
}

function auditActions(action) {
  return getStore().auditLog.filter((row) => row.tenant_id === TENANT && row.action === action);
}

function trafficCounts() {
  const store = getStore();
  return { runs: store.testRuns.length, jobs: store.probeJobs.length };
}

const ALT = {
  entry_target_id: 'tgt_alt',
  relation_kind: 'alternate_hostname',
  owner: 'App Team',
  purpose: 'Legacy hostname kept for partner integrations',
  expected_behavior: 'must_be_protected_by_layers',
  required_layers: ['cdn_edge', 'waf'],
};

const FW = {
  destination_target_id: 'tgt_fw',
  protocol: 'tcp',
  port: 443,
  expected: 'allow',
  source_perspective: 'public-worker-eu',
  change_id: 'CHG-1001',
  owner: 'Network Team',
};

describe('protection validation entry paths (dev store)', () => {
  beforeEach(seed);

  it('creates, replays without a second audit, and rejects a conflicting scope', async () => {
    const before = trafficCounts();
    const created = await createEntryPath(OWNER, 'tgt_app', ALT, { now: NOW });
    assert.equal(created.error, undefined);
    assert.equal(created.replayed, false);
    assert.deepEqual(created.required_layers, ['waf', 'cdn_edge']);
    assert.equal(created.status, 'active');
    assert.equal(created.declaration_version, 1);
    assert.equal(created.declaration_source, 'explicit');
    assert.equal(created.contract_version, 'protection-validation-v1');
    assert.equal(created.currently_authorized, true);
    assert.equal(created.authorization_state, 'dns_verified');
    assert.equal(created.digest_verified, true);
    assert.equal(auditActions('entry_path.created').length, 1);

    const replay = await createEntryPath(OWNER, 'tgt_app', ALT, { now: NOW });
    assert.equal(replay.replayed, true);
    assert.equal(replay.id, created.id);
    assert.equal(auditActions('entry_path.created').length, 1);

    const conflict = await createEntryPath(OWNER, 'tgt_app', { ...ALT, purpose: 'Changed purpose' });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.error, 'entry_path_conflict');
    assert.equal(conflict.existing_id, created.id);
    assert.deepEqual(trafficCounts(), before);
  });

  it('rejects cross-tenant, missing, and deleted references without disclosure', async () => {
    const foreign = await createEntryPath(OWNER, 'tgt_app', { ...ALT, entry_target_id: 'tgt_foreign' });
    const missing = await createEntryPath(OWNER, 'tgt_app', { ...ALT, entry_target_id: 'tgt_nope' });
    assert.deepEqual(foreign, missing);
    assert.equal(foreign.status, 404);
    assert.equal(foreign.error, 'unknown_target');
    const foreignAnchor = await createEntryPath(OWNER, 'tgt_foreign', ALT);
    assert.equal(foreignAnchor.error, 'unknown_target');
    const deleted = await createEntryPath(OWNER, 'tgt_app', { ...ALT, entry_target_id: 'tgt_deleted' });
    assert.equal(deleted.status, 409);
    assert.equal(deleted.error, 'target_not_active');
    const otherTenant = await createEntryPath(OTHER_OWNER, 'tgt_foreign', { ...ALT, entry_target_id: 'tgt_app' });
    assert.equal(otherTenant.error, 'unknown_target');
  });

  it('requires a same-tenant active origin binding that joins anchor to entry', async () => {
    const origin = { entry_target_id: 'tgt_origin', relation_kind: 'origin', owner: 'Ops', purpose: 'Origin', expected_behavior: 'must_not_be_reachable' };
    assert.equal((await createEntryPath(OWNER, 'tgt_app', origin)).error, 'origin_binding_required');
    const foreign = await createEntryPath(OWNER, 'tgt_app', { ...origin, origin_binding_id: 'obind_foreign' });
    assert.equal(foreign.status, 404);
    assert.equal(foreign.error, 'unknown_origin_binding');
    const mismatch = await createEntryPath(OWNER, 'tgt_alt', { ...origin, origin_binding_id: 'obind_pv' });
    assert.equal(mismatch.status, 409);
    assert.equal(mismatch.error, 'origin_binding_mismatch');
    const created = await createEntryPath(OWNER, 'tgt_app', { ...origin, origin_binding_id: 'obind_pv' });
    assert.equal(created.origin_binding_id, 'obind_pv');
    const notAllowed = await createEntryPath(OWNER, 'tgt_app', { ...ALT, origin_binding_id: 'obind_pv' });
    assert.equal(notAllowed.error, 'origin_binding_not_allowed');
  });

  it('rejects server-owned fields, destination overrides, and enforces least privilege', async () => {
    const owned = await createEntryPath(OWNER, 'tgt_app', { ...ALT, declaration_digest: 'x' });
    assert.equal(owned.error, 'server_owned_field');
    assert.equal(owned.field, 'declaration_digest');
    const banned = await createEntryPath(OWNER, 'tgt_app', { ...ALT, scope: { host_override: 'evil.example' } });
    assert.equal(banned.error, 'scope_not_declared');
    assert.equal(JSON.stringify(banned).includes('evil.example'), false);
    assert.equal((await createEntryPath(VIEWER, 'tgt_app', ALT)).status, 403);
    assert.equal((await createEntryPath(SOC, 'tgt_app', ALT)).status, 403);
    const created = await createEntryPath(OWNER, 'tgt_app', ALT);
    assert.equal((await getEntryPath(VIEWER, created.id)).id, created.id);
    assert.equal((await getEntryPath(OTHER_OWNER, created.id)).status, 404);
  });

  it('archives once, keeps archived relations from authorizing, and versions a re-declaration', async () => {
    const created = await createEntryPath(OWNER, 'tgt_app', ALT, { now: NOW });
    assert.equal((await authorizeEntryPathForExecution(OWNER, created.id)).ok, true);
    const archived = await archiveEntryPath(OWNER, created.id);
    assert.equal(archived.status, 'archived');
    assert.ok(archived.archived_at);
    assert.equal(archived.currently_authorized, false);
    assert.equal((await archiveEntryPath(OWNER, created.id)).error, 'already_archived');
    assert.equal(auditActions('entry_path.archived').length, 1);
    const blocked = await authorizeEntryPathForExecution(OWNER, created.id);
    assert.equal(blocked.error, 'entry_path_archived');
    const redeclared = await createEntryPath(OWNER, 'tgt_app', { ...ALT, purpose: 'New purpose' });
    assert.equal(redeclared.declaration_version, 2);
    assert.notEqual(redeclared.declaration_digest, created.declaration_digest);
  });

  it('re-validates lifecycle and current ownership at execution time', async () => {
    const created = await createEntryPath(OWNER, 'tgt_app', { ...ALT, entry_target_id: 'tgt_unverified' });
    assert.equal(created.currently_authorized, false);
    assert.equal(created.authorization_reason, 'ownership_not_verified');
    const unverified = await authorizeEntryPathForExecution(OWNER, created.id);
    assert.equal(unverified.error, 'ownership_not_verified');
    const alt = await createEntryPath(OWNER, 'tgt_app', ALT);
    getStore().targets.find((row) => row.id === 'tgt_alt').deleted_at = NOW.toISOString();
    const deleted = await authorizeEntryPathForExecution(OWNER, alt.id);
    assert.equal(deleted.error, 'target_not_active');
    const row = getStore()[PROTECTION_VALIDATION_STORE_KEYS.entryPaths].find((entry) => entry.id === alt.id);
    row.required_layers = ['waf'];
    assert.notEqual(entryPathDeclarationDigest(row), row.declaration_digest);
    const tampered = await authorizeEntryPathForExecution(OWNER, alt.id);
    assert.equal(tampered.field, 'declaration_digest');
  });

  it('lists relations for anchor or entry with bounded cursor pagination and filters', async () => {
    await createEntryPath(OWNER, 'tgt_app', ALT, { now: new Date('2026-10-06T00:00:01Z') });
    await createEntryPath(OWNER, 'tgt_app', { ...ALT, entry_target_id: 'tgt_login', relation_kind: 'declared_login_url' }, { now: new Date('2026-10-06T00:00:02Z') });
    await createEntryPath(OWNER, 'tgt_app', { ...ALT, entry_target_id: 'tgt_app', relation_kind: 'primary_route' }, { now: new Date('2026-10-06T00:00:03Z') });
    const first = await listEntryPaths(VIEWER, 'tgt_app', { limit: 2 });
    assert.equal(first.count, 2);
    assert.ok(first.next_cursor);
    const second = await listEntryPaths(VIEWER, 'tgt_app', { limit: 2, cursor: first.next_cursor });
    assert.equal(second.count, 1);
    assert.equal(second.next_cursor, null);
    const ids = new Set([...first.items, ...second.items].map((row) => row.id));
    assert.equal(ids.size, 3);
    assert.equal((await listEntryPaths(VIEWER, 'tgt_login', {})).count, 1);
    assert.equal((await listEntryPaths(VIEWER, 'tgt_app', { relation_kind: 'primary_route' })).count, 1);
    assert.equal((await listEntryPaths(VIEWER, 'tgt_app', { status: 'bogus' })).error, 'invalid_query');
    assert.equal((await listEntryPaths(VIEWER, 'tgt_app', { cursor: 'not-a-cursor' })).error, 'invalid_cursor');
    assert.equal((await listEntryPaths(VIEWER, 'tgt_foreign', {})).error, 'unknown_target');
    assert.equal((await listEntryPaths(VIEWER, 'tgt_app', { limit: 1000 })).count, 3);
  });

  it('honors Idempotency-Key replay and conflict', async () => {
    const first = await createEntryPath(OWNER, 'tgt_app', ALT, { idempotencyKey: 'req-1' });
    const again = await createEntryPath(OWNER, 'tgt_app', ALT, { idempotencyKey: 'req-1' });
    assert.equal(again.replayed, true);
    assert.equal(again.id, first.id);
    const reused = await createEntryPath(OWNER, 'tgt_app', { ...ALT, entry_target_id: 'tgt_login' }, { idempotencyKey: 'req-1' });
    assert.equal(reused.error, 'idempotency_conflict');
    assert.equal((await createEntryPath(OWNER, 'tgt_app', ALT, { idempotencyKey: 'bad key!' })).error, 'invalid_idempotency_key');
  });
});

describe('protection validation firewall expectations, baselines, evaluations (dev store)', () => {
  beforeEach(seed);

  it('creates, replays, conflicts, filters, and archives firewall expectations', async () => {
    const created = await createFirewallExpectation(OWNER, FW, { now: NOW });
    assert.equal(created.replayed, false);
    assert.equal(created.expectation_version, 1);
    assert.equal(created.digest_verified, true);
    assert.equal((await createFirewallExpectation(OWNER, FW)).replayed, true);
    assert.equal(auditActions('firewall_expectation.created').length, 1);
    const conflict = await createFirewallExpectation(OWNER, { ...FW, expected: 'deny' });
    assert.equal(conflict.error, 'firewall_expectation_conflict');
    assert.equal((await createFirewallExpectation(OWNER, { ...FW, destination_target_id: 'tgt_foreign' })).error, 'unknown_target');
    const mapping = await createFirewallExpectation(OWNER, {
      ...FW,
      port: 8443,
      pre_post_mapping: { pre_destination_target_id: 'tgt_foreign', post_destination_target_id: 'tgt_fw', declared_by_customer: true },
    });
    assert.equal(mapping.error, 'unknown_target');
    assert.equal((await listExpectations(VIEWER, { change_id: 'CHG-1001' })).count, 1);
    assert.equal((await listExpectations(VIEWER, { change_id: 'CHG-9' })).count, 0);
    const archived = await archiveExpectation(OWNER, created.id, { kind: 'firewall_change' });
    assert.equal(archived.status, 'archived');
    assert.equal((await archiveExpectation(OWNER, created.id, { kind: 'firewall_change' })).error, 'already_archived');
    const next = await createFirewallExpectation(OWNER, { ...FW, expected: 'deny' });
    assert.equal(next.expectation_version, 2);
  });

  it('captures an immutable baseline only from finalized signed external evidence', async () => {
    const allow = await createFirewallExpectation(OWNER, FW);
    signedRun('run_pre_1');
    signedRun('run_pre_2', { observedAt: '2026-10-05T01:00:00.000Z' });
    const before = trafficCounts();
    const capture = await captureFirewallBaseline(OWNER, {
      change_id: 'CHG-1001',
      expectation_ids: [allow.id],
      test_run_ids: ['run_pre_1', 'run_pre_2'],
    }, { now: NOW });
    assert.equal(capture.error, undefined, JSON.stringify(capture));
    assert.equal(capture.replayed, false);
    assert.equal(capture.kind, 'firewall_change');
    assert.equal(capture.immutable, true);
    assert.equal(capture.digest_verified, true);
    assert.equal(capture.entries.length, 1);
    const [entry] = capture.entries;
    assert.equal(entry.expectation_digest, allow.digest);
    assert.equal(entry.references.length, 2);
    assert.equal(entry.references[0].worker_id, 'worker_eu_1');
    assert.equal(entry.references[0].source_perspective, 'public-worker-eu');
    assert.equal(entry.captured_at, '2026-10-05T01:00:00.000Z');
    assert.equal(verifyBaselineDigest(entry), true);
    assert.deepEqual(trafficCounts(), before);
    assert.equal(auditActions('firewall_baseline.captured').length, 1);

    const replay = await captureFirewallBaseline(OWNER, { change_id: 'CHG-1001', expectation_ids: [allow.id], test_run_ids: ['run_pre_2', 'run_pre_1'] });
    assert.equal(replay.replayed, true);
    assert.equal(replay.id, capture.id);
    assert.equal(auditActions('firewall_baseline.captured').length, 1);

    const read = await getBaselineCapture(VIEWER, capture.id, { kind: 'firewall_change' });
    assert.equal(read.baseline_digest, capture.baseline_digest);
    assert.equal((await getBaselineCapture(OTHER_OWNER, capture.id)).status, 404);
    const listed = await listBaselineCaptures(VIEWER, { change_id: 'CHG-1001' });
    assert.equal(listed.count, 1);
    assert.equal(listed.items[0].entry_count, 1);
    assert.equal(listed.items[0].entries[0].references.length, 2);
    assert.equal(listed.items[0].digest_verified, true);

    await archiveExpectation(OWNER, allow.id);
    const changed = await createFirewallExpectation(OWNER, { ...FW, expected: 'deny' });
    const pinned = await getBaselineCapture(VIEWER, capture.id);
    assert.equal(pinned.entries[0].expectation_digest, allow.digest);
    assert.notEqual(pinned.entries[0].expectation_digest, changed.digest);
    assert.equal(pinned.digest_verified, true);

    const row = getStore()[PROTECTION_VALIDATION_STORE_KEYS.baselines].find((candidate) => candidate.id === capture.id);
    row.references[0].check_version = 'tampered';
    assert.equal((await getBaselineCapture(VIEWER, capture.id)).digest_verified, false);
  });

  it('refuses unfinished, unsigned, unsourced, foreign, and unmatched evidence', async () => {
    const allow = await createFirewallExpectation(OWNER, FW);
    const capture = (runIds) => captureFirewallBaseline(OWNER, { change_id: 'CHG-1001', expectation_ids: [allow.id], test_run_ids: runIds });
    signedRun('run_running', { status: 'running' });
    signedRun('run_sim', { producer: 'internal_simulation' });
    signedRun('run_unsigned', { signed: false });
    signedRun('run_nosource', { source: null });
    signedRun('run_foreign', { tenant: OTHER, targetId: 'tgt_foreign' });
    signedRun('run_wrong_port', { port: 22 });
    signedRun('run_wrong_source', { source: 'public-worker-us' });
    const running = await capture(['run_running']);
    assert.equal(running.status, 409);
    assert.equal(running.error, 'evidence_not_finalized');
    assert.equal((await capture(['run_sim'])).reason, 'not_signed_external_evidence');
    assert.equal((await capture(['run_unsigned'])).reason, 'signed_job_missing');
    assert.equal((await capture(['run_nosource'])).error, 'invalid_comparison_baseline');
    const foreign = await capture(['run_foreign']);
    const missing = await capture(['run_missing']);
    assert.deepEqual(foreign, missing);
    assert.equal(foreign.status, 404);
    assert.equal((await capture(['run_wrong_port'])).error, 'invalid_comparison_baseline');
    assert.equal((await capture(['run_wrong_source'])).error, 'invalid_comparison_baseline');
    assert.equal(getStore()[PROTECTION_VALIDATION_STORE_KEYS.baselines].filter((row) => row.tenant_id === TENANT).length, 0);
    assert.equal(auditActions('firewall_baseline.captured').length, 0);
  });

  it('resolves post-change run references through the same signed-evidence gate', async () => {
    signedRun('run_post_a', { observedAt: '2026-10-05T12:00:00.000Z' });
    signedRun('run_post_sim', { producer: 'internal_simulation' });
    const resolved = await resolveRunEvidence(VIEWER, ['run_post_a']);
    assert.equal(resolved.items.length, 1);
    assert.equal(resolved.items[0].protocol, 'tcp');
    assert.equal(resolved.items[0].port, 443);
    assert.equal(resolved.items[0].reference.finalized, true);
    assert.equal((await resolveRunEvidence(VIEWER, ['run_post_sim'])).reason, 'not_signed_external_evidence');
    assert.equal((await resolveRunEvidence(OTHER_OWNER, ['run_post_a'])).status, 404);
    assert.equal((await resolveRunEvidence(VIEWER, [])).error, 'invalid_comparison_request');
  });

  it('captures the pre-change destination from an explicit customer mapping', async () => {
    const mapped = await createFirewallExpectation(OWNER, {
      ...FW,
      pre_post_mapping: { pre_destination_target_id: 'tgt_old', post_destination_target_id: 'tgt_fw', declared_by_customer: true },
    });
    signedRun('run_old', { targetId: 'tgt_old' });
    signedRun('run_new', { targetId: 'tgt_fw' });
    const wrong = await captureFirewallBaseline(OWNER, { change_id: 'CHG-1001', expectation_ids: [mapped.id], test_run_ids: ['run_new'] });
    assert.equal(wrong.error, 'invalid_comparison_baseline');
    const capture = await captureFirewallBaseline(OWNER, { change_id: 'CHG-1001', expectation_ids: [mapped.id], test_run_ids: ['run_old'] });
    assert.equal(capture.entries[0].target_id, 'tgt_old');
    assert.deepEqual(capture.entries[0].destination_mapping, mapped.pre_post_mapping);
  });

  it('records immutable firewall evaluations that never claim success from incompatible or empty evidence', async () => {
    const allow = await createFirewallExpectation(OWNER, FW);
    signedRun('run_pre');
    signedRun('run_post', { observedAt: '2026-10-05T12:00:00.000Z' });
    const capture = await captureFirewallBaseline(OWNER, { change_id: 'CHG-1001', expectation_ids: [allow.id], test_run_ids: ['run_pre'] });
    const baselineEntry = capture.entries[0];
    const post = buildRunEvidenceReference(
      getStore().testRuns.find((run) => run.id === 'run_post'),
      {
        jobs: getStore().probeJobs.filter((job) => job.test_run_id === 'run_post'),
        events: getStore().events.filter((event) => event.test_run_id === 'run_post').map((event) => ({ ...event, source_perspective: null })),
        verdicts: getStore().verdicts.filter((row) => row.test_run_id === 'run_post'),
      },
    );
    const postRef = { ...post.reference, source_perspective: 'public-worker-eu' };
    const candidate = { ...baselineEntry, references: [postRef], captured_at: postRef.observed_at };
    delete candidate.baseline_digest;
    const compatibility = assessComparisonCompatibility(baselineEntry, candidate);
    assert.equal(compatibility.comparable, true, JSON.stringify(compatibility));
    const item = classifyFirewallComparisonItem({
      expectation: allow,
      baseline: ['service_response_observed'],
      candidate: ['explicit_denial_observed'],
      compatibility,
    });
    assert.equal(item.status, 'regression');
    const before = trafficCounts();
    const evaluation = await recordComparisonEvaluation(OWNER, {
      kind: 'firewall_change',
      baseline_id: capture.id,
      baseline_digest: capture.baseline_digest,
      items: [{ expectation_id: allow.id, ...item, evidence_refs: [postRef] }],
      evaluated_at: '2026-10-06T00:00:00.000Z',
    }, { now: NOW });
    assert.equal(evaluation.error, undefined, JSON.stringify(evaluation));
    assert.equal(evaluation.summary.accepted, false);
    assert.equal(evaluation.summary.gaps.required_service_newly_unavailable, 1);
    assert.equal(evaluation.change_id, 'CHG-1001');
    assert.equal(evaluation.digest_verified, true);
    assert.deepEqual(evaluation.limitations, [...REQUIRED_LIMITATIONS.firewall_change]);
    assert.deepEqual(trafficCounts(), before);
    const replay = await recordComparisonEvaluation(OWNER, {
      kind: 'firewall_change',
      baseline_id: capture.id,
      baseline_digest: capture.baseline_digest,
      items: [{ expectation_id: allow.id, ...item, evidence_refs: [postRef] }],
      evaluated_at: '2026-10-06T00:00:00.000Z',
    });
    assert.equal(replay.replayed, true);
    assert.equal(replay.id, evaluation.id);
    assert.equal(auditActions('firewall_comparison.evaluated').length, 1);

    const empty = await recordComparisonEvaluation(OWNER, {
      kind: 'firewall_change', baseline_id: capture.id, baseline_digest: capture.baseline_digest, items: [], evaluated_at: '2026-10-06T01:00:00.000Z',
    }, { now: new Date(NOW.getTime() - 60_000) });
    assert.equal(empty.summary.accepted, false);
    assert.equal(empty.compatibility.comparable, false);

    const forged = await recordComparisonEvaluation(OWNER, {
      kind: 'firewall_change', baseline_id: capture.id, baseline_digest: 'a'.repeat(64), items: [], evaluated_at: '2026-10-06T02:00:00.000Z',
    });
    assert.equal(forged.error, 'baseline_not_comparable');
    const incompatible = await recordComparisonEvaluation(OWNER, {
      kind: 'firewall_change',
      baseline_id: capture.id,
      baseline_digest: capture.baseline_digest,
      items: [{ expectation_id: allow.id, status: 'matched', expectation_met: true, compatibility_reasons: ['source_mismatch'], evidence_refs: [postRef], limitations: REQUIRED_LIMITATIONS.firewall_change }],
      evaluated_at: '2026-10-06T03:00:00.000Z',
    });
    assert.equal(incompatible.status, 409);
    assert.equal(incompatible.error, 'baseline_not_comparable');
    const foreignRef = await recordComparisonEvaluation(OWNER, {
      kind: 'firewall_change',
      baseline_id: capture.id,
      baseline_digest: capture.baseline_digest,
      items: [{ expectation_id: allow.id, ...item, evidence_refs: [{ ...postRef, test_run_id: 'run_foreign_x' }] }],
      evaluated_at: '2026-10-06T04:00:00.000Z',
    });
    assert.equal(foreignRef.status, 404);
    assert.equal((await recordComparisonEvaluation(VIEWER, { kind: 'firewall_change', items: [] })).status, 403);

    assert.equal((await getEvaluation(VIEWER, evaluation.id, { kind: 'firewall_change' })).items.length, 1);
    assert.equal((await getEvaluation(OTHER_OWNER, evaluation.id)).status, 404);
    const listed = await listEvaluations(VIEWER, { baseline_id: capture.id, limit: 1 });
    assert.equal(listed.count, 1);
    assert.ok(listed.next_cursor);
    assert.equal(listed.items[0].items.length, 1);
    assert.equal(listed.items[0].digest_verified, true);
  });
});

describe('protection validation path expectations and baselines (dev store)', () => {
  beforeEach(seed);

  it('versions path expectations and pins declaration digests in path baselines', async () => {
    const relation = await createEntryPath(OWNER, 'tgt_app', ALT);
    const expectation = await recordPathValidationExpectation(OWNER, { anchor_target_id: 'tgt_app', scenario: 'waf.sqli.marker', layer_outcomes: { waf: 'enforce' } });
    assert.equal(expectation.expectation_version, 1);
    const same = await recordPathValidationExpectation(OWNER, { anchor_target_id: 'tgt_app', scenario: 'waf.sqli.marker', layer_outcomes: { waf: 'enforce' } });
    assert.equal(same.replayed, true);
    signedRun('run_alt', { targetId: 'tgt_alt', check: 'waf.fingerprint.safe', port: null });
    const baseline = await capturePathValidationBaseline(OWNER, {
      entry_path_id: relation.id,
      expectation_id: expectation.id,
      test_run_ids: ['run_alt'],
    });
    assert.equal(baseline.error, undefined, JSON.stringify(baseline));
    assert.equal(baseline.kind, 'path_validation');
    assert.equal(baseline.declaration_digest, relation.declaration_digest);
    assert.equal(baseline.declaration_version, 1);
    assert.equal(baseline.digest_verified, true);
    const replay = await capturePathValidationBaseline(OWNER, { entry_path_id: relation.id, expectation_id: expectation.id, test_run_ids: ['run_alt'] });
    assert.equal(replay.replayed, true);

    const changed = await recordPathValidationExpectation(OWNER, { anchor_target_id: 'tgt_app', scenario: 'waf.sqli.marker', layer_outcomes: { waf: 'enforce', cdn_edge: 'enforce' } });
    assert.equal(changed.expectation_version, 2);
    assert.equal(changed.replayed, false);
    await archiveEntryPath(OWNER, relation.id);
    const redeclared = await createEntryPath(OWNER, 'tgt_app', { ...ALT, purpose: 'Changed' });
    const stored = await getBaselineCapture(VIEWER, baseline.id);
    assert.equal(stored.declaration_digest, relation.declaration_digest);
    assert.equal(stored.expectation_digest, expectation.digest);
    const compat = assessComparisonCompatibility(stored, { ...stored, captured_at: stored.captured_at }, {
      currentDeclarationDigests: { [relation.id]: redeclared.declaration_digest },
    });
    assert.equal(compat.comparable, false);
    assert.ok(compat.reasons.includes('declaration_changed'));

    const archivedUse = await capturePathValidationBaseline(OWNER, { entry_path_id: relation.id, expectation_id: changed.id, test_run_ids: ['run_alt'] });
    assert.equal(archivedUse.error, 'entry_path_archived');
    assert.equal((await getBaselineCapture(VIEWER, baseline.id, { kind: 'firewall_change' })).status, 404);
  });

  it('records path evaluations against an anchor with same-tenant entry paths only', async () => {
    const relation = await createEntryPath(OWNER, 'tgt_app', ALT);
    const evaluation = await recordComparisonEvaluation(SOC, {
      kind: 'path_validation',
      anchor_target_id: 'tgt_app',
      primary_entry_path_id: relation.id,
      items: [
        { entry_path_id: relation.id, scenario: 'waf.sqli.marker', outcome: 'not_tested', limitations: REQUIRED_LIMITATIONS.path_validation },
        { entry_path_id: 'ep_unknown_skipped', scenario: 'waf.sqli.marker', outcome: 'skipped', limitations: REQUIRED_LIMITATIONS.path_validation },
      ],
      evaluated_at: '2026-10-06T00:00:00.000Z',
    }, { internal: true, actor: 'system' });
    assert.equal(evaluation.error, undefined, JSON.stringify(evaluation));
    assert.equal(evaluation.summary.accepted, false);
    assert.equal(evaluation.items[1].outcome, 'skipped');
    assert.equal(auditActions('entry_path_comparison.evaluated').length, 1);
    const foreignAnchor = await recordComparisonEvaluation(OWNER, {
      kind: 'path_validation', anchor_target_id: 'tgt_foreign', items: [], evaluated_at: '2026-10-06T00:00:00.000Z',
    });
    assert.equal(foreignAnchor.error, 'unknown_target');
    assert.equal((await listEvaluations(VIEWER, { kind: 'path_validation', anchor_target_id: 'tgt_app' })).count, 1);
  });
});
