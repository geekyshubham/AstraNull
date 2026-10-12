import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { readFileSync, readdirSync } from 'node:fs';
import { createReviewedExecutionGrantIssuance } from '../../src/services/reviewedExecutionGrantIssuance.mjs';
import { signPreparedReviewedExecutionGrant } from '../../src/lib/preparedReviewedExecutionGrant.mjs';
import { buildReviewedExecutionGrantEnvelope } from '../../src/contracts/reviewedExecutionGrant.mjs';
import { validateCurrentReviewedOperationBinding } from '../../src/contracts/reviewedOperationBinding.mjs';
import { withTenantContext, withStandaloneTenantContext, assertNoManagedTenantTransaction } from '../../src/persistence/postgres/tenantContext.mjs';
import { canonicalJsonStringify } from '../../src/lib/custody.mjs';
import { validateDbSchema } from '../../scripts/validate-db-schema.mjs';
import { SECRET, KEY, grantFixture, keyFixture, deferred } from '../helpers/reviewed-grant-fixture.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const denied = (result, error) => { assert.equal(result.ok, false, JSON.stringify(result)); if (error) assert.equal(result.error, error); assert.equal(result.execution_available, false); };
function fixture(options = {}) {
  const f = grantFixture(), keys = keyFixture();
  let row = null, calls = 0, transactions = 0, chain = Promise.resolve();
  const events = [], audits = [], killSwitch = { active: false };
  const repository = { durableReviewedGrantBackend: true,
    withTransaction: async (ctx, request, callback) => {
      const previous = chain, held = deferred(); chain = held.promise;
      await previous;
      const number = ++transactions;
      let working = structuredClone(row);
      try {
        const tx = { job: structuredClone(f.job), run: structuredClone(f.run), reservation: structuredClone(f.reservation),
          killSwitch: structuredClone(killSwitch), policy: null, now: async () => new Date().toISOString(),
          withAuthority: async (fn) => {
            const snapshot = structuredClone(f.snapshot);
            const valid = validateCurrentReviewedOperationBinding(tx.job.constraints.reviewed_operation_binding,
              { tenantId: ctx.tenantId, review: f.review, target: snapshot.target, check: snapshot.check, ownership: snapshot.ownership, now: Date.now() });
            return valid.ok ? fn(snapshot) : valid;
          },
          getSlot: async () => structuredClone(working),
          insert: async (claim) => { working = structuredClone(claim); events.push('claim');
            if (options.auditFailure === 'claim') throw new Error('audit failure'); audits.push('claim'); },
          finish: async (claim, token, signature, at) => {
            if (working.completion_token_hash !== hash(token)) return null;
            working = { ...working, state: 'issued', grant_signature: signature, finished_at: at };
            if (options.auditFailure === 'issued') throw new Error('audit failure'); audits.push('issued'); return structuredClone(working);
          },
        };
        const result = await callback(tx);
        row = working;
        events.push(`commit${number}`);
        if (options.ambiguousCommit === number) throw new Error('lost COMMIT acknowledgement');
        return result;
      } finally { held.resolve(); }
    },
    closeUnknown: async (_ctx, id, token, code) => {
      if (!row || row.id !== id || row.completion_token_hash !== hash(token) || row.state !== 'signing_unknown') return false;
      if (options.closeFailure) throw new Error('closure unavailable');
      row = { ...row, state: 'closed_unknown', failure_code: code, finished_at: new Date().toISOString() };
      audits.push('closed'); return true;
    },
  };
  const adapter = { async signEnvelope({ envelope, signal }) {
    assertNoManagedTenantTransaction(); calls++; events.push('sign');
    assert.equal(row.state, 'signing_unknown'); assert.equal(events.includes('commit1'), true);
    assert.equal(canonicalJsonStringify(envelope), row.envelope_canonical);
    if (options.sign) return options.sign({ envelope, signal, f, keys, killSwitch });
    return keys.receipt(envelope);
  } };
  const service = createReviewedExecutionGrantIssuance({ repository, probeWorkerSecret: SECRET, trust: keys.trust,
    keyReference: KEY, signingAdapter: adapter, timeoutMs: options.timeoutMs ?? 1000 });
  return { ...f, keys, repository, service, killSwitch, events, audits, calls: () => calls, row: () => row };
}

test('claim/audit COMMIT precedes one signer; issued/audit COMMIT precedes return; exact issued replay is never signed', async () => {
  const f = fixture(), before = structuredClone(f.job);
  const first = await f.service.issueOnce(f.ctx, f.request);
  assert.equal(first.ok, true, JSON.stringify(first)); assert.equal(first.execution_available, false);
  assert.deepEqual(f.events, ['claim', 'commit1', 'sign', 'commit2']); assert.deepEqual(f.audits, ['claim', 'issued']);
  assert.deepEqual(f.job, before); assert.equal(f.row().state, 'issued');
  assert.equal(f.row().claimed_at, first.grant.envelope.authority.grant_issued_at);
  const replay = await f.service.issueOnce(f.ctx, f.request);
  assert.equal(replay.replayed, true); assert.equal(canonicalJsonStringify(replay.grant), canonicalJsonStringify(first.grant));
  assert.equal(f.calls(), 1); assert.deepEqual(f.audits, ['claim', 'issued']);
});
test('two concurrent requests consume one slot and invoke one signer', async () => {
  const gate = deferred(), entered = deferred();
  const f = fixture({ sign: async ({ envelope, keys }) => { entered.resolve(); await gate.promise; return keys.receipt(envelope); } });
  const first = f.service.issueOnce(f.ctx, f.request); await entered.promise;
  denied(await f.service.issueOnce(f.ctx, f.request), 'reviewed_grant_consumed_unknown');
  gate.resolve(); assert.equal((await first).ok, true); assert.equal(f.calls(), 1);
});
for (const field of ['job', 'reservation', 'grant', 'now', 'workerId', 'client', 'approved']) test(`reject strict caller field ${field} before backend/signing`, async () => {
  const f = fixture(); denied(await f.service.issueOnce(f.ctx, { ...f.request, [field]: {} }), 'reviewed_grant_request_invalid');
  assert.equal(f.row(), null); assert.equal(f.calls(), 0);
});
test('no durable backend or configured server HMAC material means no dev issuance', async () => {
  const f = fixture();
  denied(await createReviewedExecutionGrantIssuance().issueOnce(f.ctx, f.request), 'reviewed_grant_durable_backend_unavailable');
  denied(await createReviewedExecutionGrantIssuance({ repository: f.repository }).issueOnce(f.ctx, f.request), 'reviewed_grant_configuration_unavailable');
  denied(await f.service.issueOnce({ tenantId: f.ctx.tenantId }, f.request), 'unauthorized'); assert.equal(f.calls(), 0);
});
test('shape-valid but unauthentic original HMAC rejects before durable claim and before signing', async () => {
  const f = fixture(); f.job.job_signature = 'b'.repeat(64);
  denied(await f.service.issueOnce(f.ctx, f.request), 'reviewed_grant_original_hmac_invalid'); assert.equal(f.calls(), 0); assert.equal(f.row(), null);
});
for (const [label, mutate] of [
  ['historical assurance version', (f) => { f.run.safety_constraints.assurance_scope.version = 'assurance-scope.v2'; }],
  ['unavailable persisted reservation', (f) => { f.reservation.id = 'another'; }],
  ['canonical lease loss', (f) => { f.job.leased_at = f.job.leased_at.replace('Z', '001Z'); }],
  ['kill switch unavailable', (f) => { delete f.killSwitch.active; }],
  ['run nonce mismatch', (f) => { f.run.correlation_json.nonce_hash = 'b'.repeat(64); }],
]) test(`${label} denies before claim/signing`, async () => {
  const f = fixture(); mutate(f); denied(await f.service.issueOnce(f.ctx, f.request)); assert.equal(f.row(), null); assert.equal(f.calls(), 0);
});
for (const [label, options, state] of [
  ['preparation audit rollback', { auditFailure: 'claim' }, null],
  ['ambiguous preparation COMMIT', { ambiguousCommit: 1 }, 'signing_unknown'],
]) test(`${label} invokes zero signer calls and never reclaims committed unknown`, async () => {
  const f = fixture(options); denied(await f.service.issueOnce(f.ctx, f.request)); assert.equal(f.calls(), 0); assert.equal(f.row()?.state ?? null, state);
  if (state) { denied(await f.service.issueOnce(f.ctx, f.request), 'reviewed_grant_consumed_unknown'); assert.equal(f.calls(), 0); }
});
for (const [label, options, state] of [
  ['finalization audit rollback', { auditFailure: 'issued' }, 'closed_unknown'],
  ['lost final COMMIT response', { ambiguousCommit: 2 }, 'issued'],
  ['unavailable closure', { sign: async () => { throw new Error('lost signer response'); }, closeFailure: true }, 'signing_unknown'],
]) test(`${label} never releases an uncommitted grant and never re-signs`, async () => {
  const f = fixture(options); denied(await f.service.issueOnce(f.ctx, f.request)); assert.equal(f.row().state, state);
  const retry = await f.service.issueOnce(f.ctx, f.request);
  assert.equal(retry.ok, state === 'issued'); assert.equal(f.calls(), 1);
});
for (const [label, mutate] of [
  ['revocation', ({ f }) => { f.review.revoked_at = new Date().toISOString(); f.review.revoked_by = 'usr_grant_owner'; }],
  ['lease change', ({ f }) => { f.job.leased_by = 'worker_other'; }],
  ['reservation change', ({ f }) => { f.reservation.reserved_at = new Date().toISOString(); }],
  ['job signature change', ({ f }) => { f.job.job_signature = 'b'.repeat(64); }],
  ['run stop', ({ f }) => { f.run.status = 'cancelled'; }],
  ['kill switch', ({ killSwitch }) => { killSwitch.active = true; }],
  ['scope change', ({ f }) => { f.run.safety_constraints.assurance_scope.version = 'assurance-scope.v2'; }],
  ['history generation', ({ f }) => { f.snapshot.ownershipHistory.push({ ...f.ownership, id: 'new_equivalent' }); }],
  ['key retirement', ({ keys, f }) => { keys.trust.tenants[f.ctx.tenantId][KEY].signing_enabled = false; }],
]) test(`current ${label} during signer wait permanently withholds grant`, async () => {
  const f = fixture({ sign: async (input) => { mutate(input); return input.keys.receipt(input.envelope); } });
  denied(await f.service.issueOnce(f.ctx, f.request)); assert.equal(f.row().state, 'closed_unknown'); assert.equal(f.calls(), 1);
  await f.service.issueOnce(f.ctx, f.request); assert.equal(f.calls(), 1);
});
test('equivalent duplicate latest history order reversal preserves chosen actual proof and full-history digest', async () => {
  const f = fixture({ sign: async ({ f: state, envelope, keys }) => {
    state.snapshot.ownershipHistory.reverse(); state.snapshot.ownership = state.snapshot.ownershipHistory[0];
    return keys.receipt(envelope);
  } });
  const duplicate = { ...f.ownership, id: 'proof_equivalent_other' };
  f.snapshot.ownershipHistory.push(duplicate);
  const result = await f.service.issueOnce(f.ctx, f.request);
  assert.equal(result.ok, true, JSON.stringify(result)); assert.equal(f.calls(), 1);
  const selected = f.row().provenance_json.dns_proof;
  assert.ok(f.snapshot.ownershipHistory.some((row) => canonicalJsonStringify(row) === canonicalJsonStringify(selected)));
});
test('unknown signer timeout and late real signature never reclaim or finalize', async () => {
  const late = deferred(); let supplied;
  const f = fixture({ timeoutMs: 10, sign: async ({ envelope, keys, signal }) => { supplied = { envelope, keys, signal }; await late.promise; return keys.receipt(envelope); } });
  denied(await f.service.issueOnce(f.ctx, f.request), 'reviewed_grant_signing_timeout');
  assert.equal(supplied.signal.aborted, true); assert.equal(f.row().state, 'closed_unknown');
  late.resolve(); await delay(10); denied(await f.service.issueOnce(f.ctx, f.request)); assert.equal(f.calls(), 1); assert.equal(f.row().state, 'closed_unknown');
});
test('wrong independent signature is never issued despite matching key receipt metadata', async () => {
  const foreign = keyFixture();
  const f = fixture({ sign: async ({ envelope, keys }) => ({ ...keys.receipt(envelope), signature: foreign.receipt(envelope).signature }) });
  denied(await f.service.issueOnce(f.ctx, f.request), 'reviewed_grant_signature_invalid'); assert.equal(f.row().state, 'closed_unknown');
});
test('wrong completion token cannot close an actual owned unknown slot', async () => {
  const f = fixture({ ambiguousCommit: 1 }); await f.service.issueOnce(f.ctx, f.request);
  assert.equal(await f.repository.closeUnknown(f.ctx, f.row().id, Buffer.alloc(32), 'test_failure'), false);
  assert.equal(f.row().state, 'signing_unknown');
});
test('standalone helper rejects ANY enclosing managed tenant transaction before sign or backend connection', async () => {
  const f = fixture(); let connections = 0;
  const client = { query: async () => ({ rows: [] }), release() {} };
  const pool = { connect: async () => { connections++; return client; } };
  await withTenantContext(pool, f.ctx.tenantId, async () => {
    denied(await f.service.issueOnce(f.ctx, f.request), 'reviewed_grant_enclosing_transaction');
    await assert.rejects(withStandaloneTenantContext({}, 'ten_foreign', () => assert.fail()), { code: 'reviewed_grant_enclosing_transaction' });
  });
  assert.equal(connections, 1); assert.equal(f.calls(), 0); assert.equal(f.row(), null);
});

test('prepared helper preserves exact persisted issuance clock, checks actual pre/post time and active trust', async () => {
  const f = grantFixture(), k = keyFixture();
  const envelope = buildReviewedExecutionGrantEnvelope(f.context, k.signer).envelope;
  let calls = 0;
  const result = await signPreparedReviewedExecutionGrant({ envelope, context: f.context, trust: k.trust,
    signingAdapter: { signEnvelope: async ({ envelope: e }) => { calls++; assert.deepEqual(e, envelope); return k.receipt(e); } } });
  assert.equal(result.ok, true, JSON.stringify(result)); assert.equal(calls, 1);
  assert.equal(result.grant.envelope.authority.grant_issued_at, f.context.now);
  const expired = await signPreparedReviewedExecutionGrant({ envelope, context: f.context, trust: k.trust,
    now: () => Date.parse(envelope.authority.not_after), signingAdapter: { signEnvelope: () => assert.fail() } });
  assert.equal(expired.error, 'reviewed_grant_expired');
  const cancel = new AbortController(); cancel.abort();
  assert.equal((await signPreparedReviewedExecutionGrant({ envelope, context: f.context, trust: k.trust, signal: cancel.signal,
    signingAdapter: { signEnvelope: () => assert.fail() } })).error, 'reviewed_grant_signing_cancelled');
});

for (const kind of ['retired', 'expired', 'backwards']) test(`prepared helper ${kind} before invocation microtask calls ZERO signers`, async () => {
  const f = grantFixture(), k = keyFixture(), envelope = buildReviewedExecutionGrantEnvelope(f.context, k.signer).envelope;
  let clock = Date.now(), calls = 0;
  const pending = signPreparedReviewedExecutionGrant({ envelope, context: f.context, trust: k.trust, now: () => clock,
    signingAdapter: { signEnvelope: async () => { calls++; return k.receipt(envelope); } } });
  if (kind === 'retired') k.trust.tenants[f.ctx.tenantId][KEY].signing_enabled = false;
  if (kind === 'expired') clock = Date.parse(envelope.authority.not_after);
  if (kind === 'backwards') clock -= 1;
  assert.equal((await pending).ok, false); assert.equal(calls, 0);
});
test('prepared post-signing clock is compared to invocation, not just the earlier preparation check', async () => {
  const f = grantFixture(), k = keyFixture(), envelope = buildReviewedExecutionGrantEnvelope(f.context, k.signer).envelope;
  let clock = Date.now();
  const pending = signPreparedReviewedExecutionGrant({ envelope, context: f.context, trust: k.trust, now: () => clock,
    signingAdapter: { signEnvelope: async () => { clock -= 1; return k.receipt(envelope); } } });
  clock += 100;
  assert.equal((await pending).error, 'reviewed_grant_clock_invalid');
});

test('prepared signing cancellation during asynchronous wait discards actual late signature', async () => {
  const f = grantFixture(), k = keyFixture(), envelope = buildReviewedExecutionGrantEnvelope(f.context, k.signer).envelope;
  const late = deferred(), ready = deferred(), controller = new AbortController(); let calls = 0, signerSignal;
  const pending = signPreparedReviewedExecutionGrant({ envelope, context: f.context, trust: k.trust, signal: controller.signal,
    signingAdapter: { signEnvelope: async ({ signal }) => { calls++; signerSignal = signal; ready.resolve(); await late.promise; return k.receipt(envelope); } } });
  await ready.promise; controller.abort();
  assert.equal((await pending).error, 'reviewed_grant_signing_cancelled'); assert.equal(signerSignal.aborted, true);
  late.resolve(); await delay(1); assert.equal(calls, 1);
});
test('issued replay revalidates currently active pinned trust without signing', async () => {
  const f = fixture(), issued = await f.service.issueOnce(f.ctx, f.request);
  assert.equal(issued.ok, true);
  f.keys.trust.tenants[f.ctx.tenantId][KEY].signing_enabled = false;
  denied(await f.service.issueOnce(f.ctx, f.request), 'reviewed_grant_key_retired');
  assert.equal(f.calls(), 1); assert.equal(f.row().state, 'issued');
});

test('0078 exact migration/schema parity, required registry, tenant FKs, bounded integrity and immutable lifecycle fail closed', () => {
  const schemaSql = readFileSync(new URL('../../db/schema.sql', import.meta.url), 'utf8');
  const name = '0078_reviewed_execution_grant_issuances.sql';
  const migrationSqls = readdirSync(new URL('../../db/migrations/', import.meta.url)).filter((n) => n.endsWith('.sql'))
    .map((n) => ({ name: n, sql: readFileSync(new URL(`../../db/migrations/${n}`, import.meta.url), 'utf8') }));
  const migration = migrationSqls.find((m) => m.name === name);
  assert.ok(schemaSql.includes(migration.sql.trim())); assert.equal(validateDbSchema({ schemaSql, migrationSqls }).ok, true);
  assert.equal(validateDbSchema({ schemaSql, migrationSqls: migrationSqls.filter((m) => m.name !== name) }).ok, false);
  for (const clause of ['UNIQUE (tenant_id, probe_job_id)', 'UNIQUE (tenant_id, test_run_id)', 'UNIQUE (tenant_id, reservation_id)',
    'ALTER TABLE reviewed_execution_grant_issuances FORCE ROW LEVEL SECURITY;', 'CONSTRAINT reviewed_grant_integrity_check CHECK',
    'CREATE TRIGGER reviewed_execution_grant_issuances_history_guard BEFORE INSERT OR UPDATE OR DELETE']) {
    assert.equal(validateDbSchema({ schemaSql: schemaSql.replace(clause, '-- removed\n'), migrationSqls }).ok, false, clause);
  }
});
