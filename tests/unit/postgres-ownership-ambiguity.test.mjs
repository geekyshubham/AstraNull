import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createOwnershipVerificationRepository } from '../../src/persistence/postgres/ownershipVerificationRepository.mjs';
import { DEMO_AUTO_VERIFY_ENV, isDemoAutoVerifyTenant } from '../../src/lib/demoAutoVerify.mjs';

const CTX = { tenantId: 'Astra-chronology-fixture', userId: 'usr_owner', role: 'owner' };
const AMBIGUOUS = { id: 'tv_ambiguous', tenant_id: CTX.tenantId, target_id: 'tgt_ambiguous',
  state: 'pending', source_kind: 'ownership_ambiguous', source_ref: {},
  transitioned_at: new Date('2026-10-10T00:00:00.000Z') };

let previousDemoTenants;
before(() => {
  previousDemoTenants = process.env[DEMO_AUTO_VERIFY_ENV];
  process.env[DEMO_AUTO_VERIFY_ENV] = CTX.tenantId;
});
after(() => {
  if (previousDemoTenants === undefined) delete process.env[DEMO_AUTO_VERIFY_ENV];
  else process.env[DEMO_AUTO_VERIFY_ENV] = previousDemoTenants;
});

function recordingPool(handler) {
  const queries = [];
  const client = { async query(sql, params) {
    queries.push({ sql, params });
    return { rows: handler(sql, params) ?? [] };
  }, release() {} };
  return { queries, client, async connect() { return client; } };
}

test('PostgreSQL demo compatibility cannot upgrade ambiguous ownership authority', async () => {
  assert.equal(isDemoAutoVerifyTenant(CTX.tenantId), true);
  const pool = recordingPool((sql) => /JOIN target_verification_current current/.test(sql) ? [AMBIGUOUS] : []);
  const repo = createOwnershipVerificationRepository(pool);
  const current = await repo.getCurrentTargetVerification(CTX, 'tg_ambiguous', 'tgt_ambiguous');
  assert.equal(current.state, 'pending');
  assert.equal(current.source_kind, 'ownership_ambiguous');
  assert.deepEqual(current.source_ref, {});
  assert.equal(pool.queries.some(({ sql }) => /^\s*(INSERT|UPDATE)/.test(sql)), false);
});

test('historical verified challenge cannot upgrade ambiguous current ownership', async () => {
  const pool = recordingPool((sql) => {
    if (/FROM ownership_verifications/.test(sql)) return [{ id: 'own_old', tenant_id: CTX.tenantId,
      target_group_id: 'tg_ambiguous', declared_fqdn: 'app.example.test', status: 'verified',
      created_at: '2026-10-09T00:00:00.000Z', confirmed_at: null }];
    if (/FROM target_groups tg/.test(sql)) return [{ id: 'tgt_ambiguous', tenant_id: CTX.tenantId,
      target_group_id: 'tg_ambiguous', kind: 'fqdn', value: 'app.example.test' }];
    if (/FROM target_verifications tv/.test(sql)) return [AMBIGUOUS];
    if (/INSERT INTO target_verifications/.test(sql)) return [{ ...AMBIGUOUS, id: 'tv_new',
      state: 'user_confirmed', source_kind: 'user_attestation' }];
    if (/UPDATE ownership_verifications/.test(sql)) return [{ id: 'own_old', tenant_id: CTX.tenantId,
      status: 'verified', confirmed_at: '2026-10-10T01:00:00.000Z' }];
    return [];
  });
  let audits = 0;
  const repo = createOwnershipVerificationRepository(pool);
  const result = await repo.confirmOwnershipAtomic(CTX, { verification_id: 'own_old',
    confirmed_at: '2026-10-10T01:00:00.000Z', confirmed_by_user_id: CTX.userId,
    target_verification_id: 'tv_new', transitioned_by: CTX.userId }, {
    async appendAuditEvent() { audits++; return { id: 'unexpected_audit' }; },
  });
  assert.deepEqual(result, { error: 'ownership_transition_invalid', status: 409 });
  assert.equal(audits, 0);
  assert.equal(pool.queries.some(({ sql }) => /^\s*(INSERT|UPDATE)/.test(sql)), false);
  const auditLock = pool.queries.findIndex(({ sql }) => /pg_advisory_xact_lock/.test(sql));
  const firstRowLock = pool.queries.findIndex(({ sql }) => /FOR UPDATE/.test(sql));
  assert.ok(auditLock >= 0 && auditLock < firstRowLock);
});
