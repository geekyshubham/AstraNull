import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createPortalRevampRepository,
  PORTAL_REVAMP_REPOSITORY_METHODS,
} from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { createPostgresPortalRevampServices } from '../../src/persistence/postgres/portalRevampServiceAdapters.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_owner', role: 'owner' };
const NOW = new Date('2026-06-01T12:00:00.000Z');

function portalRepository(overrides = {}) {
  const defaults = Object.fromEntries(
    PORTAL_REVAMP_REPOSITORY_METHODS.map((method) => [method, async () => null]),
  );
  return {
    ...defaults,
    listDnsChallengesByGroup: async () => [],
    ...overrides,
  };
}

function portalServices(overrides = {}, options = {}) {
  return createPostgresPortalRevampServices({
    repositories: {
      portalRevamp: portalRepository(overrides),
      audit: { appendAuditEvent: async (entry) => ({ id: 'audit_1', ...entry }) },
    },
    now: options.now ?? (() => new Date(NOW)),
  });
}

describe('postgres portal ownership hardening', () => {
  it('requires explicit non-empty LOA scope and derives it from current tenant/group targets', async () => {
    let inserted;
    let scopeReads = 0;
    const services = portalServices({
      getLoaScopeTargets: async () => {
        scopeReads += 1;
        return {
          target_group: { id: 'tg_1', tenant_id: CTX.tenantId },
          targets: [
            { id: 'tgt_agent', verification_state: 'agent_verified' },
            { id: 'tgt_dns', verification_state: 'dns_verified' },
            { id: 'tgt_confirmed', verification_state: 'user_confirmed' },
          ],
        };
      },
      getActiveLoaByGroup: async () => null,
      insertLoaSignature: async (_ctx, record) => {
        inserted = record;
        return { ...record, audit_entry_id: 'audit_loa' };
      },
    });

    for (const scopeAck of [undefined, []]) {
      const rejected = await services.loa.sign(CTX, 'tg_1', {
        attested: true,
        ...(scopeAck === undefined ? {} : { scope_ack: scopeAck }),
      });
      assert.deepEqual(rejected, { error: 'invalid_scope_ack', status: 400 });
    }
    assert.equal(scopeReads, 0);
    assert.equal(inserted, undefined);

    const foreign = await services.loa.sign(CTX, 'tg_1', {
      attested: true,
      scope_ack: ['tgt_agent', 'tgt_other_tenant'],
    });
    assert.deepEqual(foreign, { error: 'scope_target_not_found', status: 400 });
    assert.equal(inserted, undefined);

    const ineligibleOnly = await services.loa.sign(CTX, 'tg_1', {
      attested: true,
      scope_ack: ['tgt_dns'],
    });
    assert.deepEqual(ineligibleOnly, { error: 'invalid_scope_ack', status: 400 });
    assert.equal(inserted, undefined);

    const signed = await services.loa.sign(CTX, 'tg_1', {
      signer_name: 'Owner', signer_title: 'CISO', signer_email: 'owner@example.test',
      attested: true,
      scope_ack: ['tgt_agent', 'tgt_dns', 'tgt_confirmed'],
      scope_snapshot: { targets: ['attacker_supplied'] },
    });
    assert.deepEqual(inserted.scope_snapshot, {
      targets: ['tgt_agent', 'tgt_confirmed'],
      excluded: [{ target_id: 'tgt_dns', reason: 'unverified' }],
    });
    assert.deepEqual(signed.loa.scope_snapshot, inserted.scope_snapshot);
    assert.equal(JSON.stringify(signed).includes('attacker_supplied'), false);
  });

  it('delegates route-bound LOA confirmation to one atomic repository method', async () => {
    let atomicCall;
    const expected = {
      target: { id: 'tgt_1', tenant_id: CTX.tenantId, target_group_id: 'tg_1' },
      verification: {
        id: 'tv_1', target_id: 'tgt_1', state: 'user_confirmed',
        source_ref: { signer: CTX.userId, loa_id: 'loa_1' },
      },
      audit_entry_id: 'audit_verify',
    };
    const rejectLegacySequence = async () => {
      throw new Error('LOA confirmation must not use pre-read/write repository methods');
    };
    const services = portalServices({
      getActiveTarget: rejectLegacySequence,
      getActiveLoaByGroup: rejectLegacySequence,
      getTargetVerificationCurrent: rejectLegacySequence,
      insertTargetVerification: rejectLegacySequence,
      confirmTargetWithLoa: async (...args) => {
        atomicCall = args;
        return expected;
      },
    });

    const confirmed = await services.portalOwnership.confirmTarget(
      CTX, 'tg_1', 'tgt_1', { signer: 'attacker', note: 'approved' },
    );

    assert.deepEqual(confirmed, expected);
    assert.equal(atomicCall[0], CTX);
    assert.equal(atomicCall[1].target_group_id, 'tg_1');
    assert.equal(atomicCall[1].target_id, 'tgt_1');
    assert.equal(atomicCall[1].transitioned_at, NOW.toISOString());
    assert.equal(atomicCall[1].note, 'approved');
    assert.equal('signer' in atomicCall[1], false);
    assert.equal(typeof atomicCall[2].appendAuditEvent, 'function');

    const revoked = portalServices({
      confirmTargetWithLoa: async () => ({ error: 'loa_missing', status: 409 }),
    });
    assert.deepEqual(
      await revoked.portalOwnership.confirmTarget(CTX, 'tg_1', 'tgt_1', {}),
      { error: 'loa_missing', status: 409 },
    );
  });

  it('rejects wrong-route, unbound, expired, and inactive-target DNS challenges', async () => {
    const challenge = {
      id: 'dns_1', tenant_id: CTX.tenantId, target_group_id: 'tg_1', target_id: 'tgt_1',
      state: 'pending', record_name: '_astranull-challenge.example.test', record_value: 'TOKEN',
      expires_at: '2026-06-01T11:59:00.000Z',
    };
    let finalization;
    let resolverCalls = 0;
    const services = portalServices({
      findDnsChallenge: async () => challenge,
      getActiveTarget: async (_ctx, groupId, targetId) =>
        groupId === 'tg_1' && targetId === 'tgt_1' ? { id: targetId } : null,
      finalizeDnsOwnershipCheck: async (_ctx, input) => {
        finalization = input;
        return {
          error: 'challenge_expired', status: 409,
          challenge: { ...challenge, state: 'expired', last_checked_at: input.finalized_at },
        };
      },
    });

    const wrongRoute = await services.portalDns.verifyDnsOwnership(CTX, {
      target_group_id: 'tg_other', challenge_id: challenge.id,
    });
    assert.equal(wrongRoute.error, 'challenge_not_found');

    const expired = await services.portalDns.verifyDnsOwnership(CTX, {
      target_group_id: 'tg_1', challenge_id: challenge.id,
    }, { resolveTxt: async () => { resolverCalls += 1; return [['TOKEN']]; } });
    assert.equal(expired.error, 'challenge_expired');
    assert.equal(expired.status, 409);
    assert.equal(finalization.finalized_at, NOW.toISOString());
    assert.equal(finalization.matched, false);
    assert.equal(resolverCalls, 0);

    const unboundServices = portalServices({
      findDnsChallenge: async () => ({ ...challenge, target_id: null }),
    });
    const unbound = await unboundServices.portalDns.verifyDnsOwnership(CTX, {
      target_group_id: 'tg_1', challenge_id: challenge.id,
    });
    assert.equal(unbound.error, 'challenge_target_not_bound');

    const deletedServices = portalServices({
      findDnsChallenge: async () => ({ ...challenge, expires_at: '2026-06-01T12:01:00.000Z' }),
      getActiveTarget: async () => null,
    });
    const deleted = await deletedServices.portalDns.verifyDnsOwnership(CTX, {
      target_group_id: 'tg_1', challenge_id: challenge.id,
    });
    assert.equal(deleted.error, 'target_not_found');
  });

  it('uses a fresh finalization time when a matching DNS lookup crosses expiry', async () => {
    const beforeLookup = new Date('2026-06-01T11:59:59.900Z');
    const afterLookup = new Date('2026-06-01T12:00:00.100Z');
    const challenge = {
      id: 'dns_expiry_race', tenant_id: CTX.tenantId,
      target_group_id: 'tg_expiry_race', target_id: 'tgt_expiry_race',
      state: 'pending', record_name: '_astranull-challenge.race.example.test',
      record_value: 'RACE_TOKEN', expires_at: '2026-06-01T12:00:00.000Z',
    };
    const times = [beforeLookup, afterLookup];
    let finalization;
    const rejectLegacyWrite = async () => {
      throw new Error('DNS verification must not split finalization across repository writes');
    };
    const services = portalServices({
      findDnsChallenge: async () => challenge,
      getActiveTarget: async () => ({ id: challenge.target_id }),
      updateDnsChallenge: rejectLegacyWrite,
      insertTargetVerification: rejectLegacyWrite,
      finalizeDnsOwnershipCheck: async (_ctx, input) => {
        finalization = input;
        assert.ok(new Date(input.finalized_at) >= new Date(challenge.expires_at));
        return {
          error: 'challenge_expired', status: 409,
          challenge: { ...challenge, state: 'expired', resolved_at: null },
        };
      },
    }, { now: () => new Date(times.shift() ?? afterLookup) });

    const result = await services.portalDns.verifyDnsOwnership(CTX, {
      target_group_id: challenge.target_group_id,
      challenge_id: challenge.id,
    }, {
      resolveTxt: async () => {
        await Promise.resolve();
        return [[challenge.record_value]];
      },
    });

    assert.equal(finalization.finalized_at, afterLookup.toISOString());
    assert.equal(finalization.matched, true);
    assert.deepEqual(result, {
      error: 'challenge_expired', status: 409,
      challenge: { ...challenge, state: 'expired', resolved_at: null },
    });
  });
});

function recordingPool(handler) {
  const events = [];
  const client = {
    released: false,
    async query(text, params) {
      events.push({ type: 'query', text: String(text).trim(), params });
      return handler(text, params, events);
    },
    release() { this.released = true; },
  };
  return {
    events,
    client,
    connectCount: 0,
    async connect() { this.connectCount += 1; return client; },
  };
}

describe('postgres portal audited transaction boundary', () => {
  it('expires and audits a timed-out LOA before replacement on the same locked client', async () => {
    const pool = recordingPool((text, params) => {
      const sql = String(text);
      if (sql.includes('SELECT id FROM loa_signatures') && sql.includes('expires_at IS NOT NULL')) {
        return { rows: [{ id: 'loa_expired' }] };
      }
      if (sql.includes('SELECT id FROM loa_signatures') && sql.includes("state = 'signed'")) {
        return { rows: [] };
      }
      if (sql.includes('INSERT INTO loa_signatures')) {
        return { rows: [{
          id: params[0], tenant_id: params[1], target_group_id: params[2], state: params[3],
          signer_name: params[4], signer_title: params[5], signer_email: params[6],
          signed_at: params[7], expires_at: params[8], emergency_contact: JSON.parse(params[9]),
          attested: params[10], scope_snapshot: JSON.parse(params[11]),
          custody_artifact_id: params[12], custody_digest_sha256: params[13], audit_entry_id: params[14],
        }] };
      }
      return { rows: [] };
    });
    const repository = createPortalRevampRepository(pool);
    const auditCalls = [];
    const audit = {
      async appendAuditEvent(entry, options) {
        auditCalls.push({ entry, client: options.client });
        return { id: `audit_${auditCalls.length}` };
      },
    };
    const inserted = await repository.insertLoaSignature(CTX, {
      id: 'loa_replacement', target_group_id: 'tg_1', state: 'signed',
      signer_name: 'Owner', signer_title: 'CISO', signer_email: 'owner@example.test',
      signed_at: NOW.toISOString(), expires_at: null, emergency_contact: {}, attested: true,
      scope_snapshot: { targets: ['tgt_1'], excluded: [] },
      custody_artifact_id: 'artifact_1', custody_digest_sha256: 'digest_1',
    }, audit);

    assert.equal(inserted.id, 'loa_replacement');
    assert.deepEqual(auditCalls.map((call) => call.entry.action), ['loa.expired', 'loa.signed']);
    assert.ok(auditCalls.every((call) => call.client === pool.client));
    const expirationUpdate = pool.events.find((event) =>
      event.type === 'query' && event.text.includes("SET state = 'expired'"));
    const replacementInsert = pool.events.find((event) =>
      event.type === 'query' && event.text.includes('INSERT INTO loa_signatures'));
    assert.ok(expirationUpdate);
    assert.ok(replacementInsert);
    assert.equal(pool.events.at(-1).text, 'COMMIT');
  });

  it('returns a concurrent active-LOA conflict before signed audit or insertion', async () => {
    let inserted = false;
    const pool = recordingPool((text) => {
      const sql = String(text);
      if (sql.includes('SELECT id FROM loa_signatures') && sql.includes('expires_at IS NOT NULL')) {
        return { rows: [] };
      }
      if (sql.includes('SELECT id FROM loa_signatures') && sql.includes("state = 'signed'")) {
        return { rows: [{ id: 'loa_concurrent' }] };
      }
      if (sql.includes('INSERT INTO loa_signatures')) inserted = true;
      return { rows: [] };
    });
    const repository = createPortalRevampRepository(pool);
    let audited = false;
    const result = await repository.insertLoaSignature(CTX, {
      id: 'loa_loser', target_group_id: 'tg_1', state: 'signed',
      signer_name: 'Owner', signer_title: 'CISO', signer_email: 'owner@example.test',
      signed_at: NOW.toISOString(), expires_at: null, emergency_contact: {}, attested: true,
      scope_snapshot: { targets: ['tgt_1'], excluded: [] },
      custody_artifact_id: 'artifact_1', custody_digest_sha256: 'digest_1',
    }, { appendAuditEvent: async () => { audited = true; return { id: 'audit_unexpected' }; } });
    assert.deepEqual(result, { error: 'loa_active', status: 409 });
    assert.equal(audited, false);
    assert.equal(inserted, false);
  });

  it('expires a DNS challenge that crossed expiry and never inserts dns_verified', async () => {
    const challenge = {
      id: 'dns_expiry_atomic', tenant_id: CTX.tenantId,
      target_group_id: 'tg_expiry_atomic', target_id: 'tgt_expiry_atomic',
      record_name: '_astranull-challenge.atomic.example.test', record_value: 'TOKEN',
      ttl_seconds: 60, state: 'pending', issued_at: '2026-06-01T11:45:00.000Z',
      expires_at: '2026-06-01T12:00:00.000Z', resolved_at: null,
      last_checked_at: null, last_check_result: null, audit_entry_id: 'audit_issued',
    };
    let insertedVerification = false;
    let resolved = false;
    const pool = recordingPool((text, params) => {
      const sql = String(text);
      if (sql.includes('SELECT * FROM dns_challenges') && sql.includes('FOR UPDATE')) {
        return { rows: [challenge] };
      }
      if (sql.includes('FROM target_groups tg') && sql.includes('JOIN targets t')) {
        return { rows: [{
          id: challenge.target_id, tenant_id: CTX.tenantId,
          target_group_id: challenge.target_group_id, deleted_at: null,
        }] };
      }
      if (sql.includes("SET state = 'expired'") && sql.includes("state = 'pending'")) {
        return { rows: [{
          ...challenge,
          state: 'expired',
          resolved_at: null,
          last_checked_at: params[3],
          last_check_result: JSON.parse(params[4]),
          audit_entry_id: params[5],
        }] };
      }
      if (sql.includes("SET state = 'resolved'")) resolved = true;
      if (sql.includes('INSERT INTO target_verifications')) insertedVerification = true;
      return { rows: [] };
    });
    const repository = createPortalRevampRepository(pool);
    const auditCalls = [];
    const audit = {
      async appendAuditEvent(entry, options) {
        auditCalls.push({ entry, options });
        return { id: `audit_${auditCalls.length}` };
      },
    };

    const result = await repository.finalizeDnsOwnershipCheck(CTX, {
      challenge_id: challenge.id,
      target_group_id: challenge.target_group_id,
      finalized_at: '2026-06-01T12:00:00.100Z',
      matched: true,
      last_check_result: { resolver: 'system', records: ['TOKEN'], matched: true },
      verification_id: 'tv_must_not_insert',
      transitioned_by: CTX.userId,
    }, audit);

    assert.equal(result.error, 'challenge_expired');
    assert.equal(result.challenge.state, 'expired');
    assert.equal(result.challenge.resolved_at, null);
    assert.equal(result.challenge.last_check_result.matched, false);
    assert.equal(result.challenge.last_check_result.expired, true);
    assert.equal(resolved, false);
    assert.equal(insertedVerification, false);
    assert.deepEqual(auditCalls.map((call) => call.entry.action), [
      'dns_ownership.challenge_expired',
    ]);
    assert.ok(auditCalls.every((call) => call.options.client === pool.client));
    const expiration = pool.events.find((event) =>
      event.type === 'query' && event.text.includes("SET state = 'expired'"));
    assert.match(expiration.text, /state = 'pending'/);
    assert.match(expiration.text, /expires_at <=/);
    assert.equal(pool.events.at(-1).text, 'COMMIT');
  });

  it('rolls back DNS resolution when dns_verified insertion fails', async () => {
    const challenge = {
      id: 'dns_atomic_rollback', tenant_id: CTX.tenantId,
      target_group_id: 'tg_atomic_rollback', target_id: 'tgt_atomic_rollback',
      record_name: '_astranull-challenge.rollback.example.test', record_value: 'TOKEN',
      ttl_seconds: 60, state: 'pending', issued_at: '2026-06-01T11:45:00.000Z',
      expires_at: '2026-06-01T12:01:00.000Z', resolved_at: null,
      last_checked_at: null, last_check_result: null, audit_entry_id: 'audit_issued',
    };
    const pool = recordingPool((text, params) => {
      const sql = String(text);
      if (sql.includes('SELECT * FROM dns_challenges') && sql.includes('FOR UPDATE')) {
        return { rows: [challenge] };
      }
      if (sql.includes('FROM target_groups tg') && sql.includes('JOIN targets t')) {
        return { rows: [{
          id: challenge.target_id, tenant_id: CTX.tenantId,
          target_group_id: challenge.target_group_id, deleted_at: null,
        }] };
      }
      if (sql.includes("SET state = 'resolved'")) {
        return { rows: [{
          ...challenge,
          state: 'resolved', resolved_at: params[3], last_checked_at: params[3],
          last_check_result: JSON.parse(params[4]), audit_entry_id: params[5],
        }] };
      }
      if (sql.includes('INSERT INTO target_verifications')) {
        throw new Error('verification insert failed');
      }
      return { rows: [] };
    });
    const repository = createPortalRevampRepository(pool);
    const auditClients = [];
    const audit = {
      async appendAuditEvent(_entry, options) {
        auditClients.push(options.client);
        return { id: `audit_${auditClients.length}` };
      },
    };

    await assert.rejects(
      repository.finalizeDnsOwnershipCheck(CTX, {
        challenge_id: challenge.id,
        target_group_id: challenge.target_group_id,
        finalized_at: NOW.toISOString(),
        matched: true,
        last_check_result: { resolver: 'system', records: ['TOKEN'], matched: true },
        verification_id: 'tv_atomic_rollback',
        transitioned_by: CTX.userId,
      }, audit),
      /verification insert failed/,
    );

    assert.deepEqual(auditClients, [pool.client, pool.client]);
    assert.ok(pool.events.some((event) =>
      event.type === 'query' && event.text.includes("SET state = 'resolved'")));
    assert.equal(pool.events.at(-1).text, 'ROLLBACK');
    assert.equal(pool.events.some((event) => event.type === 'query' && event.text === 'COMMIT'), false);
  });

  it('returns loa_missing without audit or write when revocation wins before confirmation lock', async () => {
    let audited = false;
    let inserted = false;
    const pool = recordingPool((text) => {
      const sql = String(text);
      if (sql.includes('FROM target_groups tg') && sql.includes('JOIN targets t')) {
        return { rows: [{
          id: 'tgt_revoke_race', tenant_id: CTX.tenantId,
          target_group_id: 'tg_revoke_race', deleted_at: null,
        }] };
      }
      if (sql.includes('SELECT loa.*') && sql.includes('FROM loa_signatures loa')) {
        return { rows: [] };
      }
      if (sql.includes('INSERT INTO target_verifications')) inserted = true;
      return { rows: [] };
    });
    const repository = createPortalRevampRepository(pool);
    const result = await repository.confirmTargetWithLoa(CTX, {
      target_group_id: 'tg_revoke_race',
      target_id: 'tgt_revoke_race',
      verification_id: 'tv_revoke_race',
      transitioned_at: NOW.toISOString(),
      note: null,
    }, {
      appendAuditEvent: async () => {
        audited = true;
        return { id: 'audit_unexpected' };
      },
    });

    assert.deepEqual(result, { error: 'loa_missing', status: 409 });
    assert.equal(audited, false);
    assert.equal(inserted, false);
    const lockIndex = pool.events.findIndex((event) =>
      event.type === 'query' && event.text.includes('pg_advisory_xact_lock'));
    const loaIndex = pool.events.findIndex((event) =>
      event.type === 'query' && event.text.includes('SELECT loa.*'));
    assert.ok(lockIndex >= 0 && lockIndex < loaIndex);
    assert.match(pool.events[loaIndex].text, /state = 'signed'/);
    assert.match(pool.events[loaIndex].text, /expires_at > \$3::timestamptz/);
    assert.match(pool.events[loaIndex].text, /FOR UPDATE OF loa/);
    assert.equal(pool.events.at(-1).text, 'COMMIT');
  });

  it('locks target, active LOA, and prerequisite before auditing user_confirmed', async () => {
    const target = {
      id: 'tgt_confirm_atomic', tenant_id: CTX.tenantId,
      target_group_id: 'tg_confirm_atomic', deleted_at: null,
    };
    const activeLoa = {
      id: 'loa_confirm_atomic', tenant_id: CTX.tenantId,
      target_group_id: target.target_group_id, state: 'signed',
      signed_at: '2026-05-01T00:00:00.000Z', expires_at: null,
      scope_snapshot: { targets: [{ target_id: target.id }] },
      custody_digest_sha256: 'digest_confirm_atomic',
    };
    const pool = recordingPool((text, params) => {
      const sql = String(text);
      if (sql.includes('FROM target_groups tg') && sql.includes('JOIN targets t')) {
        return { rows: [target] };
      }
      if (sql.includes('SELECT loa.*') && sql.includes('FROM loa_signatures loa')) {
        return { rows: [activeLoa] };
      }
      if (sql.includes('SELECT * FROM target_verifications') && sql.includes('FOR UPDATE')) {
        return { rows: [{ id: 'tv_agent', target_id: target.id, state: 'agent_verified' }] };
      }
      if (sql.includes('INSERT INTO target_verifications')) {
        return { rows: [{
          id: params[0], tenant_id: params[1], target_id: params[2],
          state: 'user_confirmed', source_kind: 'user_attestation',
          source_ref: JSON.parse(params[3]), transitioned_at: params[4],
          transitioned_by: params[5], audit_entry_id: params[6],
        }] };
      }
      return { rows: [] };
    });
    const repository = createPortalRevampRepository(pool);
    const auditCalls = [];
    const audit = {
      async appendAuditEvent(entry, options) {
        pool.events.push({ type: 'audit' });
        auditCalls.push({ entry, options });
        return { id: 'audit_confirm_atomic' };
      },
    };

    const result = await repository.confirmTargetWithLoa(CTX, {
      target_group_id: target.target_group_id,
      target_id: target.id,
      verification_id: 'tv_confirm_atomic',
      transitioned_at: NOW.toISOString(),
      note: 'approved',
    }, audit);

    assert.equal(result.verification.state, 'user_confirmed');
    assert.deepEqual(result.verification.source_ref, {
      signer: CTX.userId,
      note: 'approved',
      loa_id: activeLoa.id,
      loa_custody_digest_sha256: activeLoa.custody_digest_sha256,
    });
    assert.equal(result.audit_entry_id, 'audit_confirm_atomic');
    assert.equal(auditCalls[0].options.client, pool.client);
    const labels = pool.events.map((event) => event.type === 'audit'
      ? 'audit'
      : event.text.includes('pg_advisory_xact_lock') ? 'lock'
        : event.text.includes('FROM target_groups tg') ? 'target'
          : event.text.includes('SELECT loa.*') ? 'loa'
            : event.text.includes('SELECT * FROM target_verifications') ? 'prerequisite'
              : event.text.includes('INSERT INTO target_verifications') ? 'insert' : event.text);
    assert.ok(labels.indexOf('lock') < labels.indexOf('target'));
    assert.ok(labels.indexOf('target') < labels.indexOf('loa'));
    assert.ok(labels.indexOf('loa') < labels.indexOf('prerequisite'));
    assert.ok(labels.indexOf('prerequisite') < labels.indexOf('audit'));
    assert.ok(labels.indexOf('audit') < labels.indexOf('insert'));
    assert.equal(labels.at(-1), 'COMMIT');
  });

  it('serializes LOA revoke on the tenant advisory lock', async () => {
    const pool = recordingPool((text, params) => {
      const sql = String(text);
      if (sql.includes('SELECT id, target_group_id FROM loa_signatures')) {
        return { rows: [{ id: 'loa_revoke', target_group_id: 'tg_1' }] };
      }
      if (sql.includes('UPDATE loa_signatures SET state')) {
        return { rows: [{
          id: params[1], tenant_id: params[0], target_group_id: 'tg_1',
          state: params[2], signed_at: NOW.toISOString(), audit_entry_id: params[3],
        }] };
      }
      return { rows: [] };
    });
    const repository = createPortalRevampRepository(pool);
    const audit = {
      async appendAuditEvent(_entry, options) {
        pool.events.push({ type: 'audit', client: options.client });
        return { id: 'audit_revoke' };
      },
    };

    const revoked = await repository.updateLoaSignature(
      CTX, 'loa_revoke', { state: 'revoked' }, audit,
    );

    assert.equal(revoked.state, 'revoked');
    const lockIndex = pool.events.findIndex((event) =>
      event.type === 'query' && event.text.includes('pg_advisory_xact_lock'));
    const selectIndex = pool.events.findIndex((event) =>
      event.type === 'query' && event.text.includes('SELECT id, target_group_id FROM loa_signatures'));
    const auditIndex = pool.events.findIndex((event) => event.type === 'audit');
    const updateIndex = pool.events.findIndex((event) =>
      event.type === 'query' && event.text.includes('UPDATE loa_signatures SET state'));
    assert.ok(lockIndex < selectIndex && selectIndex < auditIndex && auditIndex < updateIndex);
    assert.equal(pool.events[auditIndex].client, pool.client);
    assert.equal(pool.events.at(-1).text, 'COMMIT');
  });

  it('uses one pool client and orders tenant lock + audit before mutation in one transaction', async () => {
    const pool = recordingPool((text, params) => {
      if (String(text).includes('INSERT INTO dns_challenges')) {
        return { rows: [{
          id: params[0], tenant_id: params[1], target_group_id: params[2], target_id: params[3],
          record_name: params[4], record_value: params[5], ttl_seconds: params[6], state: params[7],
          issued_at: params[8], expires_at: params[9], audit_entry_id: params[10],
        }] };
      }
      return { rows: [] };
    });
    const repository = createPortalRevampRepository(pool);
    const auditClients = [];
    const audit = {
      async appendAuditEvent(_entry, options) {
        pool.events.push({ type: 'audit' });
        auditClients.push(options.client);
        return { id: 'audit_1' };
      },
    };
    await repository.insertDnsChallenge(CTX, {
      id: 'dns_1', target_group_id: 'tg_1', target_id: 'tgt_1',
      record_name: '_astranull-challenge.example.test', record_value: 'TOKEN',
      ttl_seconds: 60, state: 'pending', issued_at: NOW.toISOString(),
      expires_at: new Date(NOW.getTime() + 60_000).toISOString(),
    }, audit);

    assert.equal(pool.connectCount, 1);
    assert.deepEqual(auditClients, [pool.client]);
    const labels = pool.events.map((event) => event.type === 'audit'
      ? 'audit'
      : event.text.includes('pg_advisory_xact_lock') ? 'lock'
        : event.text.includes('INSERT INTO dns_challenges') ? 'mutation' : event.text);
    assert.ok(labels.indexOf('lock') < labels.indexOf('audit'));
    assert.ok(labels.indexOf('audit') < labels.indexOf('mutation'));
    assert.equal(labels[0], 'BEGIN');
    assert.equal(labels.at(-1), 'COMMIT');
    assert.equal(pool.client.released, true);
  });

  it('rolls back the data mutation when audit persistence fails', async () => {
    let mutated = false;
    const pool = recordingPool((text) => {
      if (String(text).includes('INSERT INTO dns_challenges')) mutated = true;
      return { rows: [] };
    });
    const repository = createPortalRevampRepository(pool);
    await assert.rejects(
      repository.insertDnsChallenge(CTX, {
        id: 'dns_1', target_group_id: 'tg_1', target_id: 'tgt_1',
        record_name: '_astranull-challenge.example.test', record_value: 'TOKEN',
        ttl_seconds: 60, state: 'pending', issued_at: NOW.toISOString(),
        expires_at: new Date(NOW.getTime() + 60_000).toISOString(),
      }, { appendAuditEvent: async () => { throw new Error('audit failed'); } }),
      /audit failed/,
    );
    assert.equal(mutated, false);
    assert.ok(pool.events.some((event) => event.type === 'query' && event.text === 'ROLLBACK'));
    assert.equal(pool.events.some((event) => event.type === 'query' && event.text === 'COMMIT'), false);
  });
});
