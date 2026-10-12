import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createPortalRevampRepository } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { createPostgresPortalRevampServices } from '../../src/persistence/postgres/portalRevampServiceAdapters.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const CTX = { tenantId: 'ten_dns_finalize_races', userId: 'usr_dns_finalize', role: 'owner' };
const GROUP = 'tg_dns_finalize_races';

describe('PostgreSQL DNS ownership asynchronous finalization', () => {
  it('rejects stale lookup scope and ownership while preserving replay and unrelated changes', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) { t.skip(availability.reason); return; }
    await withEphemeralPostgres(async (pool) => {
      const audit = createAuditRepository(pool);
      const repository = createPortalRevampRepository(pool);
      const { portalDns } = createPostgresPortalRevampServices({ repositories: { portalRevamp: repository, audit } });
      await withTenantContext(pool, CTX.tenantId, async (client) => {
        await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'DNS finalization races')`, [CTX.tenantId]);
        await client.query(`INSERT INTO target_groups (id, tenant_id, name, validation_mode)
          VALUES ($1, $2, 'DNS finalization races', 'external_only')`, [GROUP, CTX.tenantId]);
      });
      let sequence = 0;
      async function fixture() {
        const suffix = ++sequence;
        const targetId = `tgt_dns_finalize_${suffix}`;
        await withTenantContext(pool, CTX.tenantId, (client) => client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
           VALUES ($1, $2, $3, 'fqdn', $4, $4)`,
          [targetId, CTX.tenantId, GROUP, `owned-${suffix}.example.test`],
        ));
        const challenge = await repository.insertDnsChallenge(CTX, {
          id: `dns_finalize_${suffix}`, target_group_id: GROUP, target_id: targetId,
          record_name: `_astranull-challenge.owned-${suffix}.example.test`, record_value: `TOKEN_${suffix}`,
          ttl_seconds: 60, state: 'pending', issued_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 300_000).toISOString(),
        }, audit);
        return { targetId, challenge };
      }
      async function appendOwnership(targetId, state) {
        return repository.insertTargetVerification(CTX, {
          id: `tv_dns_intervening_${++sequence}`, target_id: targetId, state, source_kind: 'dns_txt',
          source_ref: { declaration_fixture: true }, transitioned_at: new Date().toISOString(),
          transitioned_by: CTX.userId,
        }, audit);
      }
      async function counts(targetId, challengeId) {
        return withTenantContext(pool, CTX.tenantId, async (client) => {
          const verification = await client.query(
            `SELECT id, state, source_ref FROM target_verifications
             WHERE tenant_id = $1 AND target_id = $2 ORDER BY id`, [CTX.tenantId, targetId],
          );
          const logs = await client.query(
            `SELECT id, action FROM audit_logs WHERE tenant_id = $1
             AND ((resource_type = 'dns_challenge' AND resource_id = $2)
               OR (resource_type = 'target_verification' AND metadata_json->>'target_id' = $3))
             ORDER BY sequence`, [CTX.tenantId, challengeId, targetId],
          );
          return { verification: verification.rows, audits: logs.rows };
        });
      }
      async function mutate(fn) {
        return withTenantContext(pool, CTX.tenantId, async (client) => {
          await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [CTX.tenantId]);
          return fn(client);
        });
      }
      await t.test('uses a scalar exact target ID for the active target lookup', async () => {
        const { targetId } = await fixture();
        assert.equal((await repository.getActiveTarget(CTX, GROUP, targetId))?.id, targetId);
        assert.equal(await repository.getActiveTarget(CTX, GROUP, `${targetId}_missing`), null);
        assert.equal(await repository.getActiveTarget(CTX, `${GROUP}_missing`, targetId), null);
      });
      for (const state of ['pending', 'unverified', 'user_confirmed']) {
        await t.test(`does not overwrite intervening ${state} ownership`, async () => {
          const { targetId, challenge } = await fixture();
          let afterChange;
          const result = await portalDns.verifyDnsOwnership(CTX, {
            target_group_id: GROUP, challenge_id: challenge.id,
          }, { resolveTxt: async (name) => {
            assert.equal(name, challenge.record_name);
            await appendOwnership(targetId, state);
            afterChange = await counts(targetId, challenge.id);
            return [[challenge.record_value]];
          } });
          assert.equal(result.error, 'ownership_state_changed');
          assert.equal(result.status, 409);
          assert.deepEqual(await counts(targetId, challenge.id), afterChange);
          assert.equal((await repository.findDnsChallenge(CTX, challenge.id)).state, 'pending');
        });
      }
      for (const change of ['token', 'record_name', 'target_value', 'target_kind', 'target_binding']) {
        await t.test(`rejects changed ${change} rather than accepting the old TXT result`, async () => {
          const { targetId, challenge } = await fixture();
          const sibling = await fixture();
          const before = await counts(targetId, challenge.id);
          const result = await portalDns.verifyDnsOwnership(CTX, {
            target_group_id: GROUP, challenge_id: challenge.id,
          }, { resolveTxt: async () => {
            await mutate(async (client) => {
              if (change === 'token' || change === 'record_name' || change === 'target_binding') {
                const column = { token: 'record_value', record_name: 'record_name', target_binding: 'target_id' }[change];
                const value = change === 'target_binding' ? sibling.targetId : 'CHANGED';
                await client.query(`UPDATE dns_challenges SET ${column} = $3
                  WHERE tenant_id = $1 AND id = $2`, [CTX.tenantId, challenge.id, value]);
              } else {
                const column = change === 'target_kind' ? 'kind' : 'value';
                await client.query(`UPDATE targets SET ${column} = $3
                  WHERE tenant_id = $1 AND id = $2`,
                [CTX.tenantId, targetId, change === 'target_kind' ? 'ip' : 'changed.example.test']);
              }
            });
            return [[challenge.record_value]];
          } });
          assert.equal(result.error, 'challenge_binding_changed');
          assert.equal(result.status, 409);
          assert.deepEqual(await counts(targetId, challenge.id), before);
          assert.equal((await repository.findDnsChallenge(CTX, challenge.id)).state, 'pending');
          assert.equal((await counts(sibling.targetId, sibling.challenge.id)).verification.length, 0);
        });
      }
      await t.test('returns the retained terminal result for parallel matching lookups without duplicate writes', async () => {
        const { targetId, challenge } = await fixture();
        const finish = [];
        const started = [];
        const run = (index) => portalDns.verifyDnsOwnership(CTX, { target_group_id: GROUP, challenge_id: challenge.id }, {
          resolveTxt: () => { started.push(index); return new Promise((resolve) => { finish[index] = resolve; }); },
        });
        const first = run(0);
        const second = run(1);
        // Both calls must reach the injected resolver, not merely queue behind finalization.
        await new Promise((resolve, reject) => {
          const deadline = Date.now() + 2000;
          const check = () => {
            if (started.length === 2) return resolve();
            if (Date.now() > deadline) return reject(new Error('both DNS lookups did not start'));
            setTimeout(check, 1);
          };
          check();
        });
        finish[0]([[challenge.record_value]]);
        const accepted = await first;
        assert.equal(accepted.verified, true);
        const afterFirst = await counts(targetId, challenge.id);
        finish[1]([[challenge.record_value]]);
        const replay = await second;
        assert.equal(replay.verified, true);
        assert.equal(replay.audit_entry_id, accepted.audit_entry_id);
        assert.deepEqual(await counts(targetId, challenge.id), afterFirst);
        assert.equal(afterFirst.verification.length, 1);
      });
      for (const field of ['expires_at', 'issued_at']) {
        await t.test(`rejects nonfinite stored ${field} before DNS or a success audit`, async () => {
          const { targetId, challenge } = await fixture();
          await mutate((client) => client.query(`UPDATE dns_challenges SET ${field} = 'infinity'::timestamptz
            WHERE tenant_id = $1 AND id = $2`, [CTX.tenantId, challenge.id]));
          const before = await counts(targetId, challenge.id);
          let resolverCalls = 0;
          const result = await portalDns.verifyDnsOwnership(CTX, { target_group_id: GROUP, challenge_id: challenge.id }, {
            resolveTxt: async () => { resolverCalls += 1; return [[challenge.record_value]]; },
          });
          assert.equal(result.error, 'challenge_binding_changed');
          assert.equal(result.status, 409);
          assert.equal(resolverCalls, 0);
          assert.deepEqual(await counts(targetId, challenge.id), before);
          assert.equal((await repository.findDnsChallenge(CTX, challenge.id)).state, 'pending');
        });
      }
      await t.test('requires an exact internal lookup binding before any live finalization writes', async () => {
        const { targetId, challenge } = await fixture();
        const snapshot = await repository.getDnsOwnershipCheckSnapshot(CTX, {
          challenge_id: challenge.id, target_group_id: GROUP, target_id: targetId,
        });
        assert.match(snapshot.lookup_binding.ownership_generation, /^[a-f0-9]{64}$/);
        const before = await counts(targetId, challenge.id);
        for (const binding of [undefined, null, {},
          { ...snapshot.lookup_binding, version: 'unknown' },
          { ...snapshot.lookup_binding, ownership_generation: 'incomplete' },
          { ...snapshot.lookup_binding, extra: 'not_reviewed' }]) {
          const result = await repository.finalizeDnsOwnershipCheck(CTX, {
            challenge_id: challenge.id, target_group_id: GROUP, finalized_at: new Date().toISOString(),
            matched: true, verification_id: 'tv_dns_missing_binding', transitioned_by: CTX.userId,
            lookup_binding: binding,
          }, audit);
          assert.equal(result.error, 'dns_lookup_binding_missing');
          assert.equal(result.status, 503);
          assert.deepEqual(await counts(targetId, challenge.id), before);
          assert.equal((await repository.findDnsChallenge(CTX, challenge.id)).state, 'pending');
        }
      });
      await t.test('rechecks expiry after waiting for the tenant audit lock, before DNS', async () => {
        const { targetId, challenge } = await fixture();
        const expiresAt = Date.now() + 500;
        await mutate((client) => client.query(`UPDATE dns_challenges SET expires_at = $3::timestamptz
          WHERE tenant_id = $1 AND id = $2`, [CTX.tenantId, challenge.id, new Date(expiresAt).toISOString()]));
        const writer = await pool.connect();
        let pending;
        let resolverCalls = 0;
        try {
          await writer.query('BEGIN');
          await writer.query('SELECT pg_advisory_xact_lock(hashtext($1))', [CTX.tenantId]);
          const pid = (await writer.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          pending = portalDns.verifyDnsOwnership(CTX, { target_group_id: GROUP, challenge_id: challenge.id }, {
            resolveTxt: async () => { resolverCalls += 1; return [[challenge.record_value]]; },
          });
          let blocked = false;
          const deadline = Date.now() + 2000;
          while (Date.now() < deadline) {
            const blockers = await pool.query(`SELECT pid FROM pg_stat_activity
              WHERE $1::integer = ANY(pg_blocking_pids(pid))`, [pid]);
            if (blockers.rows.length) { blocked = true; break; }
            await new Promise((resolve) => setTimeout(resolve, 1));
          }
          assert.equal(blocked, true, 'snapshot must wait for the audit-first writer');
          await new Promise((resolve) => setTimeout(resolve, Math.max(0, expiresAt - Date.now() + 10)));
          await writer.query('COMMIT');
          const result = await pending;
          assert.equal(result.error, 'challenge_expired');
          assert.equal(result.status, 409);
          assert.equal(resolverCalls, 0);
          assert.equal((await counts(targetId, challenge.id)).verification.length, 0);
          assert.equal((await repository.findDnsChallenge(CTX, challenge.id)).state, 'expired');
        } finally {
          await writer.query('ROLLBACK').catch(() => {});
          writer.release();
          if (pending) await pending;
        }
      });
      await t.test('accepts a healthy matching lookup after a different target changes ownership', async () => {
        const { targetId, challenge } = await fixture();
        const sibling = await fixture();
        const result = await portalDns.verifyDnsOwnership(CTX, { target_group_id: GROUP, challenge_id: challenge.id }, {
          resolveTxt: async () => { await appendOwnership(sibling.targetId, 'pending'); return [[challenge.record_value]]; },
        });
        assert.equal(result.verified, true);
        assert.equal((await counts(targetId, challenge.id)).verification.length, 1);
        assert.equal((await counts(sibling.targetId, sibling.challenge.id)).verification[0].state, 'pending');
      });
    });
  });
});
