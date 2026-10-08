import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createPortalRevampRepository } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { createPostgresPortalRevampServices } from '../../src/persistence/postgres/portalRevampServiceAdapters.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const ctx = { tenantId: 'ten_direct_auth', userId: 'usr_owner', role: 'owner' };
const group = 'tg_direct_auth';

test('Postgres authorizations retain distinct domain scope and serialize concurrent overlap', { timeout: 120_000 }, async (t) => {
  const availability = await resolvePostgresHarnessAvailability(process.env);
  if (!availability.available) return t.skip(availability.reason);
  await withEphemeralPostgres(async (pool) => {
    await withTenantContext(pool, ctx.tenantId, async (client) => {
      await client.query("INSERT INTO tenants (id, name) VALUES ($1, 'Direct authorization')", [ctx.tenantId]);
      await client.query("INSERT INTO environments (id, tenant_id, name) VALUES ('env_auth', $1, 'legacy')", [ctx.tenantId]);
      await client.query("INSERT INTO target_groups (id, tenant_id, environment_id, name) VALUES ($1, $2, 'env_auth', 'retained policy')", [group, ctx.tenantId]);
      for (const id of ['tgt_auth_a', 'tgt_auth_b', 'tgt_auth_c']) {
        await client.query("INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value) VALUES ($1,$2,$3,'fqdn',$4,$4)", [id, ctx.tenantId, group, `${id}.example.test`]);
        await client.query("INSERT INTO target_verifications (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id) VALUES ($1,$2,$3,'dns_verified','dns_txt','{}',now(),'system',$4)", [`tv_${id}`, ctx.tenantId, id, `audit_${id}`]);
      }
    });
    const portalRevamp = createPortalRevampRepository(pool);
    const { loa } = createPostgresPortalRevampServices({ repositories: { portalRevamp, audit: createAuditRepository(pool) } });
    const payload = { signer_name: 'Owner', signer_email: 'owner@example.test', attested: true };
    const a = await loa.sign(ctx, group, { ...payload, scope_ack: ['tgt_auth_a'] });
    const b = await loa.sign(ctx, group, { ...payload, scope_ack: ['tgt_auth_b'] });
    assert.equal(a.error, undefined, JSON.stringify(a));
    assert.equal(b.error, undefined, JSON.stringify(b));
    assert.deepEqual(a.loa.scope_snapshot.targets, ['tgt_auth_a']);
    assert.deepEqual(b.loa.scope_snapshot.targets, ['tgt_auth_b']);
    assert.equal((await loa.getActive(ctx, group, 'tgt_auth_a')).loa.id, a.loa.id);
    assert.equal((await loa.getActive(ctx, group, 'tgt_auth_b')).loa.id, b.loa.id);
    assert.equal((await loa.getActive({ ...ctx, tenantId: 'ten_foreign' }, group, 'tgt_auth_a')).loa, null);
    const results = await Promise.all([loa.sign(ctx, group, { ...payload, scope_ack: ['tgt_auth_c'] }), loa.sign(ctx, group, { ...payload, scope_ack: ['tgt_auth_c'] })]);
    assert.equal(results.filter((result) => !result.error).length, 1);
    assert.equal(results.find((result) => result.error)?.error, 'loa_active');
    // A direct SQL writer cannot bypass the repository's overlap guard.
    await assert.rejects(withTenantContext(pool, ctx.tenantId, async (client) => {
      await client.query("INSERT INTO loa_signatures (id, tenant_id, target_group_id, state, signer_name, signer_title, signer_email, signed_at, emergency_contact, attested, scope_snapshot, custody_artifact_id, custody_digest_sha256, audit_entry_id) VALUES ('loa_overlap',$1,$2,'signed','Owner','','owner@example.test',now(),'{}',true,$3::jsonb,'art_overlap','digest_overlap','audit_overlap')", [ctx.tenantId, group, JSON.stringify({ targets: ['tgt_auth_a'] })]);
    }), (error) => error.code === '23505');
    const confirmed = await portalRevamp.confirmTargetWithLoa(ctx, { target_group_id: group, target_id: 'tgt_auth_a', verification_id: 'tv_confirm_a', transitioned_at: new Date().toISOString() }, createAuditRepository(pool));
    assert.equal(confirmed.error, undefined, JSON.stringify(confirmed));
    await loa.revoke(ctx, b.loa.id, 'scope test');
    assert.equal((await loa.getActive(ctx, group, 'tgt_auth_b')).loa, null);
    assert.equal((await loa.getActive(ctx, group, 'tgt_auth_a')).loa.id, a.loa.id);
  }, availability.env ?? process.env);
});
