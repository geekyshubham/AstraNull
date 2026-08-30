import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { hashNonce } from '../../src/lib/crypto.mjs';
import {
  confirmOwnership,
  confirmTarget,
  createOwnershipChallenge,
  recordOwnershipSignal,
  recordOwnershipSignalByNonce,
  verifyOwnershipSetup,
} from '../../src/services/ownershipVerification.mjs';
import { ingestEvent } from '../../src/services/events.mjs';
import { addTarget, deleteTarget } from '../../src/services/targetGroups.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'owner' };

afterEach(() => {
  freshStore();
});

function seedOnlineAgent(overrides = {}) {
  const store = getStore();
  if (!Array.isArray(store.ownershipVerifications)) {
    store.ownershipVerifications = [];
  }
  const agent = {
    id: 'agent_1',
    tenant_id: 'ten_demo',
    name: 'canary',
    status: 'online',
    capabilities: ['canary', 'packet', 'heartbeat'],
    target_group_id: 'tg_1',
    probe_endpoint: { declared_fqdn: 'origin.test' },
    last_token_validation_status: 'valid',
    ...overrides,
  };
  store.agents.push(agent);
  return agent;
}

describe('ownership verification', () => {
  it('createOwnershipChallenge succeeds and stores challenge_sent record with nonce', () => {
    freshStore();
    seedOnlineAgent();

    const result = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.error, undefined);
    assert.equal(result.verification.status, 'challenge_sent');
    assert.equal(typeof result.nonce, 'string');
    assert.ok(result.nonce.length > 0);
    assert.equal(getStore().ownershipVerifications.length, 1);
    assert.equal(getStore().ownershipVerifications[0].target_id, 'tgt_1');
    assert.equal(
      getStore().ownershipVerifications[0].challenge_nonce_hash,
      hashNonce(result.nonce),
    );
  });

  it('rejects declared_fqdn not in target group', () => {
    freshStore();
    seedOnlineAgent({
      probe_endpoint: { declared_fqdn: 'evil.test' },
    });

    const result = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.error, 'declared_fqdn_not_in_target_group');
    assert.equal(result.status, 400);
  });

  it('rejects agent with invalid token', () => {
    freshStore();
    seedOnlineAgent({ last_token_validation_status: 'invalid' });

    const result = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.error, 'agent_token_invalid');
    assert.equal(result.status, 409);
  });

  it('rejects agent not bound to target group', () => {
    freshStore();
    seedOnlineAgent({ target_group_id: 'tg_other' });

    const result = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.error, 'agent_not_bound_to_target_group');
    assert.equal(result.status, 400);
  });

  it('recordOwnershipSignal verifies after probe and agent with matching nonce', () => {
    freshStore();
    seedOnlineAgent();

    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });
    const id = created.verification.id;
    const nonceHash = hashNonce(created.nonce);

    const probe = recordOwnershipSignal(ctx, id, { source: 'probe', nonce_hash: nonceHash });
    assert.equal(probe.verification.probe_observed, true);
    assert.equal(probe.verification.status, 'challenge_sent');

    const agent = recordOwnershipSignal(ctx, id, { source: 'agent', nonce_hash: nonceHash });
    assert.equal(agent.verification.agent_observed, true);
    assert.equal(agent.verification.status, 'verified');
    assert.ok(agent.verification.verified_at);

    const targetProof = getStore().targetVerifications.find(
      (row) => row.target_id === 'tgt_1' && row.state === 'agent_verified',
    );
    assert.ok(targetProof);
    assert.equal(targetProof.source_kind, 'agent_observation');
    assert.equal(targetProof.source_ref.ownership_verification_id, id);

    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    assert.equal(group.ownership_status, 'agent_verified');
  });

  it('agent completion proves only its declared target and keeps a multi-target summary honest', () => {
    freshStore();
    seedOnlineAgent();
    const victim = addTarget(ctx, 'tg_1', { kind: 'fqdn', value: 'victim.example' });
    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });
    const nonceHash = hashNonce(created.nonce);

    recordOwnershipSignal(ctx, created.verification.id, { source: 'probe', nonce_hash: nonceHash });
    const completed = recordOwnershipSignal(ctx, created.verification.id, {
      source: 'agent',
      nonce_hash: nonceHash,
    });

    assert.equal(completed.verification.status, 'verified');
    assert.deepEqual(
      getStore().targetVerifications.map((row) => [row.target_id, row.state]),
      [['tgt_1', 'agent_verified']],
    );
    assert.equal(
      getStore().targetVerifications.some((row) => row.target_id === victim.id),
      false,
    );
    assert.equal(getStore().targetGroups[0].ownership_status, 'unverified');
  });

  it('does not complete a challenge after its exact bound target becomes inactive', () => {
    freshStore();
    seedOnlineAgent();
    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });
    const nonceHash = hashNonce(created.nonce);
    recordOwnershipSignal(ctx, created.verification.id, { source: 'probe', nonce_hash: nonceHash });
    getStore().targets[0].deleted_at = new Date().toISOString();

    const result = recordOwnershipSignal(ctx, created.verification.id, {
      source: 'agent',
      nonce_hash: nonceHash,
    });

    assert.deepEqual(result, { error: 'ownership_target_not_active', status: 409 });
    assert.equal(created.verification.status, 'challenge_sent');
    assert.equal(created.verification.agent_observed, false);
    assert.equal((getStore().targetVerifications ?? []).length, 0);
  });

  it('recordOwnershipSignal rejects wrong nonce_hash', () => {
    freshStore();
    seedOnlineAgent();

    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    const result = recordOwnershipSignal(ctx, created.verification.id, {
      source: 'probe',
      nonce_hash: 'sha256:deadbeef',
    });

    assert.equal(result.error, 'nonce_mismatch');
    assert.equal(result.status, 400);
  });

  it('confirmOwnership after verified confirms the exact target and derives the group summary', () => {
    freshStore();
    seedOnlineAgent();

    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });
    const nonceHash = hashNonce(created.nonce);
    recordOwnershipSignal(ctx, created.verification.id, { source: 'probe', nonce_hash: nonceHash });
    recordOwnershipSignal(ctx, created.verification.id, { source: 'agent', nonce_hash: nonceHash });

    const confirmed = confirmOwnership(ctx, created.verification.id);
    assert.equal(confirmed.verification.confirmed_by_user_id, 'u1');
    assert.ok(confirmed.verification.confirmed_at);
    assert.equal(confirmed.target_id, 'tgt_1');
    assert.equal(confirmed.target_verification.target_id, 'tgt_1');
    assert.equal(confirmed.target_verification.state, 'user_confirmed');
    assert.equal(
      confirmed.target_verification.source_ref.ownership_verification_id,
      created.verification.id,
    );

    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    assert.equal(group.ownership_status, 'user_confirmed');
  });

  it('confirms A without blessing unverified B and is idempotent at the live-egress gate', () => {
    freshStore();
    seedOnlineAgent();
    const targetB = addTarget(ctx, 'tg_1', { kind: 'fqdn', value: 'unverified.example' });
    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });
    const nonceHash = hashNonce(created.nonce);
    recordOwnershipSignal(ctx, created.verification.id, { source: 'probe', nonce_hash: nonceHash });
    recordOwnershipSignal(ctx, created.verification.id, { source: 'agent', nonce_hash: nonceHash });

    const confirmed = confirmOwnership(ctx, created.verification.id);
    assert.equal(confirmed.target_id, 'tgt_1');
    assert.equal(confirmed.target_verification.state, 'user_confirmed');
    assert.equal(confirmed.ownership_status, 'unverified');
    assert.equal(getStore().targetGroups[0].ownership_status, 'unverified');
    assert.equal(
      getStore().targetVerifications.some(
        (row) => row.target_id === targetB.id && row.state !== 'unverified',
      ),
      false,
    );

    const confirmedAt = confirmed.verification.confirmed_at;
    const targetVerificationId = confirmed.target_verification.id;
    const confirmationAuditCount = getStore().auditLog.filter(
      (entry) => entry.action === 'ownership_verification.user_confirmed'
        || entry.action === 'target_verification.user_confirmed',
    ).length;
    const repeated = confirmOwnership(ctx, created.verification.id);
    assert.equal(repeated.verification.confirmed_at, confirmedAt);
    assert.equal(repeated.target_verification.id, targetVerificationId);
    assert.equal(
      getStore().targetVerifications.filter(
        (row) => row.target_id === 'tgt_1' && row.state === 'user_confirmed',
      ).length,
      1,
    );
    assert.equal(
      getStore().auditLog.filter(
        (entry) => entry.action === 'ownership_verification.user_confirmed'
          || entry.action === 'target_verification.user_confirmed',
      ).length,
      confirmationAuditCount,
    );

    const runtimeConfig = {
      probeMode: 'signed-worker',
      probeWorkerSecret: 'ownership-confirmation-test-secret',
    };
    const denied = startTestRun(ctx, {
      check_id: 'origin.leak_scan.safe',
      target_group_id: 'tg_1',
      target_id: targetB.id,
    }, runtimeConfig);
    assert.deepEqual(denied, { error: 'ownership_not_verified', status: 409 });

    const allowed = startTestRun(ctx, {
      check_id: 'origin.leak_scan.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    }, runtimeConfig);
    assert.equal(allowed.error, undefined);
    assert.equal(allowed.run.target_id, 'tgt_1');
    assert.equal(allowed.probe_job.status, 'pending');
  });

  it('cannot confirm a completed challenge after its bound target is deleted and re-added', () => {
    freshStore();
    seedOnlineAgent();
    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });
    const nonceHash = hashNonce(created.nonce);
    recordOwnershipSignal(ctx, created.verification.id, { source: 'probe', nonce_hash: nonceHash });
    const completed = recordOwnershipSignal(ctx, created.verification.id, {
      source: 'agent', nonce_hash: nonceHash,
    });
    assert.equal(completed.verification.status, 'verified');

    assert.equal(deleteTarget(ctx, 'tg_1', 'tgt_1').deleted, true);
    const replacement = addTarget(ctx, 'tg_1', { kind: 'fqdn', value: 'origin.test' });
    assert.notEqual(replacement.id, 'tgt_1');

    const result = confirmOwnership(ctx, created.verification.id);
    assert.deepEqual(result, { error: 'ownership_target_not_active', status: 409 });
    assert.equal(created.verification.confirmed_at, null);
    assert.equal(
      getStore().targetVerifications.some((row) => row.target_id === replacement.id),
      false,
    );
    assert.equal(getStore().targetGroups[0].ownership_status, 'unverified');
  });

  it('ingestEvent ownership_observation verifies after probe signal via nonce correlation', () => {
    freshStore();
    seedOnlineAgent();

    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });
    const nonceHash = created.verification.challenge_nonce_hash;

    const probe = recordOwnershipSignalByNonce(
      { tenantId: ctx.tenantId },
      { source: 'probe', nonce_hash: nonceHash },
    );
    assert.equal(probe.verification.probe_observed, true);
    assert.equal(probe.verification.status, 'challenge_sent');

    const ingested = ingestEvent(ctx, {
      event_id: 'e-own-1',
      signal_type: 'ownership_observation',
      nonce_hash: nonceHash,
    });
    assert.equal(ingested.error, undefined);

    const verification = getStore().ownershipVerifications.find(
      (v) => v.id === created.verification.id,
    );
    assert.equal(verification.status, 'verified');
    assert.ok(verification.verified_at);
    assert.equal(verification.agent_observed, true);

    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    assert.equal(group.ownership_status, 'agent_verified');
  });

  it('confirmOwnership rejects before verified', () => {
    freshStore();
    seedOnlineAgent();

    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    const result = confirmOwnership(ctx, created.verification.id);
    assert.equal(result.error, 'ownership_not_verified');
    assert.equal(result.status, 409);
  });

  it('confirms only a route-bound target in the active LOA snapshot using the authenticated actor', () => {
    freshStore();
    const store = getStore();
    store.targetVerifications = store.targetVerifications ?? [];
    store.targetVerifications.push({
      id: 'tv_agent', tenant_id: ctx.tenantId, target_id: 'tgt_1', state: 'agent_verified',
      transitioned_at: '2026-06-01T00:00:00.000Z',
    });
    store.loaSignatures = [{
      id: 'loa_1', tenant_id: ctx.tenantId, target_group_id: 'tg_1', state: 'signed',
      scope_snapshot: { targets: [] }, custody_digest_sha256: 'digest_loa_1',
    }];

    const excluded = confirmTarget(ctx, 'tg_1', 'tgt_1', { signer: 'attacker' });
    assert.equal(excluded.error, 'target_not_in_loa_scope');

    store.loaSignatures[0].scope_snapshot.targets = [{ target_id: 'tgt_1' }];
    const confirmed = confirmTarget(ctx, 'tg_1', 'tgt_1', { signer: 'attacker', note: 'approved' });
    assert.equal(confirmed.verification.state, 'user_confirmed');
    assert.equal(confirmed.verification.source_ref.signer, ctx.userId);
    assert.equal(confirmed.verification.source_ref.loa_id, 'loa_1');
    assert.equal(confirmed.verification.source_ref.loa_custody_digest_sha256, 'digest_loa_1');

    store.targetGroups.push({ id: 'tg_other', tenant_id: ctx.tenantId, name: 'Other' });
    const wrongGroup = confirmTarget(ctx, 'tg_other', 'tgt_1');
    assert.equal(wrongGroup.error, 'target_not_found');
  });

  it('does not accept an expired signed LOA for confirmation', () => {
    freshStore();
    const store = getStore();
    store.targetVerifications = store.targetVerifications ?? [];
    store.targetVerifications.push({
      id: 'tv_agent', tenant_id: ctx.tenantId, target_id: 'tgt_1', state: 'agent_verified',
      transitioned_at: '2026-06-01T00:00:00.000Z',
    });
    store.loaSignatures = [{
      id: 'loa_expired', tenant_id: ctx.tenantId, target_group_id: 'tg_1', state: 'signed',
      expires_at: '2000-01-01T00:00:00.000Z', scope_snapshot: { targets: ['tgt_1'] },
    }];
    const result = confirmTarget(ctx, 'tg_1', 'tgt_1');
    assert.equal(result.error, 'loa_missing');
  });

  it('verifyOwnershipSetup returns ready for a valid setup without persisting', () => {
    freshStore();
    seedOnlineAgent();

    const result = verifyOwnershipSetup(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.dry_run, true);
    assert.equal(result.ready, true);
    assert.equal(result.target_group_id, 'tg_1');
    assert.equal(result.agent_id, 'agent_1');
    assert.equal(result.declared_fqdn, 'origin.test');
    assert.deepEqual(result.checks, {
      agent_online: true,
      agent_bound: true,
      token_valid: true,
      fqdn_declared: true,
    });
    assert.equal(getStore().ownershipVerifications.length, 0);
    const audit = getStore().auditLog.find(
      (e) => e.action === 'ownership_verification.setup_verified',
    );
    assert.ok(audit);
  });

  it('verifyOwnershipSetup returns agent_not_online when agent is offline', () => {
    freshStore();
    seedOnlineAgent({ status: 'offline' });

    const result = verifyOwnershipSetup(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.dry_run, true);
    assert.equal(result.ready, false);
    assert.equal(result.error, 'agent_not_online');
    assert.equal(result.status, 409);
  });

  it('verifyOwnershipSetup returns target_group_not_found for missing group', () => {
    freshStore();
    seedOnlineAgent();

    const result = verifyOwnershipSetup(ctx, {
      target_group_id: 'tg_missing',
      agent_id: 'agent_1',
    });

    assert.equal(result.dry_run, true);
    assert.equal(result.ready, false);
    assert.equal(result.error, 'target_group_not_found');
    assert.equal(result.status, 404);
  });
});