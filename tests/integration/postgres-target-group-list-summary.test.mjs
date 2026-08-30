import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const IDS = {
  tenantA: 'ten_tgsum_a',
  tenantB: 'ten_tgsum_b',
  environmentA: 'env_tgsum_a',
  environmentB: 'env_tgsum_b',
  signedGroup: 'tg_tgsum_signed',
  bareGroup: 'tg_tgsum_bare',
  archivedGroup: 'tg_tgsum_archived',
  otherTenantGroup: 'tg_tgsum_other',
};

async function seed(client) {
  await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')`, [
    IDS.tenantA,
    IDS.tenantB,
  ]);
  await client.query(
    `INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'envA'), ($3, $4, 'envB')`,
    [IDS.environmentA, IDS.tenantA, IDS.environmentB, IDS.tenantB],
  );
  await client.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name, created_at)
     VALUES ($1, $2, $3, 'signed group', now() - interval '3 hours'),
            ($4, $5, $6, 'bare group', now() - interval '2 hours'),
            ($7, $8, $9, 'archived group', now() - interval '1 hour'),
            ($10, $11, $12, 'other tenant group', now())`,
    [
      IDS.signedGroup, IDS.tenantA, IDS.environmentA,
      IDS.bareGroup, IDS.tenantA, IDS.environmentA,
      IDS.archivedGroup, IDS.tenantA, IDS.environmentA,
      IDS.otherTenantGroup, IDS.tenantB, IDS.environmentB,
    ],
  );
  await client.query(`UPDATE target_groups SET archived_at = now() WHERE id = $1`, [
    IDS.archivedGroup,
  ]);

  const targets = [
    ['tgt_tgsum_1', IDS.tenantA, IDS.signedGroup, 'one.example'],
    ['tgt_tgsum_2', IDS.tenantA, IDS.signedGroup, 'two.example'],
    ['tgt_tgsum_3', IDS.tenantA, IDS.signedGroup, 'three.example'],
    ['tgt_tgsum_4', IDS.tenantA, IDS.archivedGroup, 'four.example'],
    // Same group id under another tenant: the count must not bleed across tenants.
    ['tgt_tgsum_5', IDS.tenantB, IDS.otherTenantGroup, 'five.example'],
  ];
  for (const [id, tenantId, groupId, value] of targets) {
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
       VALUES ($1, $2, $3, 'fqdn', $4, $4)`,
      [id, tenantId, groupId, value],
    );
  }

  await client.query(
    `INSERT INTO loa_signatures (
       id, tenant_id, target_group_id, state, signer_name, signer_title, signer_email,
       emergency_contact, attested, scope_snapshot, custody_artifact_id,
       custody_digest_sha256, audit_entry_id
     ) VALUES (
       'loa_tgsum_signed', $1, $2, 'signed', 'Signer', 'CISO', 's@example.com',
       '{"name":"Ops","role":"SRE","phone":"+1","email":"ops@example.com"}'::jsonb,
       true, '{"targets":[]}'::jsonb, 'art_tgsum', 'sha256-tgsum', 'aud_tgsum'
     )`,
    [IDS.tenantA, IDS.signedGroup],
  );
  await client.query(
    `INSERT INTO loa_signatures (
       id, tenant_id, target_group_id, state, signer_name, signer_title, signer_email,
       emergency_contact, attested, scope_snapshot, custody_artifact_id,
       custody_digest_sha256, audit_entry_id
     ) VALUES (
       'loa_tgsum_revoked', $1, $2, 'revoked', 'Signer', 'CISO', 's@example.com',
       '{"name":"Ops","role":"SRE","phone":"+1","email":"ops@example.com"}'::jsonb,
       true, '{"targets":[]}'::jsonb, 'art_tgsum_r', 'sha256-tgsum-r', 'aud_tgsum_r'
     )`,
    [IDS.tenantA, IDS.bareGroup],
  );
}

describe('postgres listTargetGroups summary join', () => {
  it('returns target_count and loa_state scoped to the calling tenant', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await withTenantContext(pool, IDS.tenantA, (client) => seed(client));

      const repo = createCoreCatalogRepository(pool);
      const active = await repo.listTargetGroups({ tenantId: IDS.tenantA });

      assert.deepEqual(
        active.map((g) => g.id),
        [IDS.signedGroup, IDS.bareGroup],
      );
      assert.equal(active[0].target_count, 3);
      assert.equal(active[0].loa_state, 'signed');
      // A revoked signature is not an active LOA.
      assert.equal(active[1].target_count, 0);
      assert.equal(active[1].loa_state, 'required');

      const archived = await repo.listTargetGroups(
        { tenantId: IDS.tenantA },
        { archived: true },
      );
      assert.deepEqual(archived.map((g) => g.id), [IDS.archivedGroup]);
      assert.equal(archived[0].target_count, 1);
      assert.equal(archived[0].loa_state, 'required');

      const otherTenant = await repo.listTargetGroups({ tenantId: IDS.tenantB });
      assert.deepEqual(otherTenant.map((g) => g.id), [IDS.otherTenantGroup]);
      assert.equal(otherTenant[0].target_count, 1);
      assert.equal(otherTenant[0].loa_state, 'required');
    });
  });
});
