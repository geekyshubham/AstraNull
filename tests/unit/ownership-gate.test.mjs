import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  MIN_PROOF_RANK,
  VERIFICATION_RANK,
  ownershipProofFromStates,
  ownershipSummaryFromTargetStates,
} from '../../src/lib/ownershipPolicy.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { addTarget } from '../../src/services/targetGroups.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'engineer' };
const SIGNED_WORKER = { probeMode: 'signed-worker', probeWorkerSecret: 's'.repeat(32) };

// fqdn-compatible and not host_sni_bypass, so signed-worker mode does not additionally demand a
// direct origin IP — that guard is unrelated to ownership.
const CHECK = 'origin.leak_scan.safe';
const OPS_READINESS_CHECK = 'ops.runbook_contact_validation.safe';

function setGroupOwnership(state) {
  getStore().targetGroups.find((g) => g.id === 'tg_1').ownership_status = state;
}

function seedTargetVerification(state, targetId = 'tgt_1') {
  const store = getStore();
  if (!Array.isArray(store.targetVerifications)) store.targetVerifications = [];
  store.targetVerifications.push({
    id: `tv_${targetId}_${state}`,
    tenant_id: 'ten_demo',
    target_id: targetId,
    state,
    source_kind: 'dns_txt',
    source_ref: { dns_challenge_id: 'dns_1' },
    transitioned_at: new Date().toISOString(),
    transitioned_by: 'system',
  });
}

function seedOnlineAgent() {
  getStore().agents.push({
    id: 'ag_own',
    tenant_id: 'ten_demo',
    status: 'online',
    capabilities: ['canary', 'packet', 'heartbeat'],
    target_group_id: 'tg_1',
  });
}

function ownershipDenials() {
  return getStore().auditLog.filter((a) => a.action === 'test_run.ownership_denied');
}

describe('ownership policy', () => {
  it('accepts dns_verified and stronger only when bound to the target', () => {
    assert.deepEqual(ownershipProofFromStates({ targetState: 'dns_verified' }), {
      verified: true,
      state: 'dns_verified',
      source: 'target',
    });
    for (const state of ['agent_verified', 'user_confirmed']) {
      assert.equal(ownershipProofFromStates({ targetState: state }).verified, true);
    }
  });

  it('never treats a group summary as authorization', () => {
    for (const state of ['dns_verified', 'agent_verified', 'user_confirmed']) {
      assert.deepEqual(ownershipProofFromStates({ groupState: state }), {
        verified: false,
        state: 'unverified',
        source: null,
      });
    }
  });

  it('treats unverified, pending, unknown, and absent target states as unproven', () => {
    for (const state of ['unverified', 'pending', 'not_a_real_state', null, undefined]) {
      assert.equal(
        ownershipProofFromStates({ targetState: state }).verified,
        false,
        `expected ${String(state)} to be unproven`,
      );
    }
    assert.equal(ownershipProofFromStates().verified, false);
  });

  it('computes an honest weakest-target group summary', () => {
    assert.equal(
      ownershipSummaryFromTargetStates(['agent_verified', 'unverified']),
      'unverified',
    );
    assert.equal(
      ownershipSummaryFromTargetStates(['agent_verified', 'dns_verified']),
      'dns_verified',
    );
    assert.equal(ownershipSummaryFromTargetStates(['user_confirmed']), 'user_confirmed');
  });

  it('pins the threshold at dns_verified so the ladder cannot silently loosen', () => {
    assert.equal(MIN_PROOF_RANK, VERIFICATION_RANK.dns_verified);
    assert.ok(VERIFICATION_RANK.pending < MIN_PROOF_RANK);
    assert.ok(VERIFICATION_RANK.agent_verified > MIN_PROOF_RANK);
  });
});

describe('ownership gate before live probe dispatch', () => {
  it('denies signed-worker runs against an unverified target group', () => {
    freshStore();
    seedOnlineAgent();
    setGroupOwnership('unverified');

    const result = startTestRun(ctx, { check_id: CHECK, target_group_id: 'tg_1', target_id: 'tgt_1' }, SIGNED_WORKER);

    assert.equal(result.error, 'ownership_not_verified');
    assert.equal(result.status, 409);
    const denials = ownershipDenials();
    assert.equal(denials.length, 1);
    assert.equal(denials[0].metadata.ownership_state, 'unverified');
    assert.equal(denials[0].metadata.target_id, 'tgt_1');
    // A denial must not leave a partial run or any dispatched work behind.
    assert.equal(getStore().testRuns.length, 0);
    assert.equal(getStore().probeJobs.length, 0);
    assert.equal(getStore().agentJobs.length, 0);
  });

  it('denies when a challenge was merely issued (pending is not proof of control)', () => {
    freshStore();
    seedOnlineAgent();
    setGroupOwnership('pending');
    seedTargetVerification('pending');

    const result = startTestRun(ctx, { check_id: CHECK, target_group_id: 'tg_1', target_id: 'tgt_1' }, SIGNED_WORKER);

    assert.equal(result.error, 'ownership_not_verified');
    assert.equal(ownershipDenials()[0].metadata.ownership_state, 'pending');
    assert.equal(getStore().testRuns.length, 0);
  });

  it('denies signed-worker runs when only the group summary is verified', () => {
    freshStore();
    seedOnlineAgent();
    setGroupOwnership('user_confirmed');

    const result = startTestRun(ctx, { check_id: CHECK, target_group_id: 'tg_1', target_id: 'tgt_1' }, SIGNED_WORKER);

    assert.deepEqual(result, { error: 'ownership_not_verified', status: 409 });
    assert.equal(ownershipDenials()[0].metadata.ownership_state, 'unverified');
  });

  it('allows signed-worker runs on per-target DNS proof when the group is unverified', () => {
    freshStore();
    seedOnlineAgent();
    setGroupOwnership('unverified');
    seedTargetVerification('dns_verified');

    const result = startTestRun(ctx, { check_id: CHECK, target_group_id: 'tg_1', target_id: 'tgt_1' }, SIGNED_WORKER);

    assert.notEqual(result.error, 'ownership_not_verified');
    assert.equal(ownershipDenials().length, 0);
  });


  it('denies newly added victim B while verified target A remains allowed', () => {
    freshStore();
    seedOnlineAgent();
    setGroupOwnership('agent_verified');
    seedTargetVerification('agent_verified', 'tgt_1');

    const victim = addTarget(ctx, 'tg_1', { kind: 'fqdn', value: 'victim.example' });
    assert.equal(victim.error, undefined);
    assert.equal(getStore().targetGroups[0].ownership_status, 'unverified');
    assert.equal(
      getStore().targetVerifications.some((row) => row.target_id === 'tgt_1'),
      true,
      'adding B must retain A proof',
    );

    const denied = startTestRun(
      ctx,
      { check_id: CHECK, target_group_id: 'tg_1', target_id: victim.id },
      SIGNED_WORKER,
    );
    assert.deepEqual(denied, { error: 'ownership_not_verified', status: 409 });
    assert.equal(ownershipDenials().at(-1).metadata.target_id, victim.id);

    const allowed = startTestRun(
      ctx,
      { check_id: CHECK, target_group_id: 'tg_1', target_id: 'tgt_1' },
      SIGNED_WORKER,
    );
    assert.equal(allowed.error, undefined);
    assert.ok(allowed.probe_job);
  });

  it('leaves in-process simulation runs ungated', () => {
    freshStore();
    seedOnlineAgent();
    setGroupOwnership('unverified');

    const result = startTestRun(ctx, { check_id: CHECK, target_group_id: 'tg_1', target_id: 'tgt_1' });

    assert.notEqual(result.error, 'ownership_not_verified');
    assert.equal(ownershipDenials().length, 0);
  });

  it('leaves ops-readiness checks ungated even in signed-worker mode', () => {
    freshStore();
    seedOnlineAgent();
    setGroupOwnership('unverified');

    const result = startTestRun(
      ctx,
      { check_id: OPS_READINESS_CHECK, target_group_id: 'tg_1', target_id: 'tgt_1' },
      SIGNED_WORKER,
    );

    assert.notEqual(result.error, 'ownership_not_verified');
    assert.equal(ownershipDenials().length, 0);
  });
});
