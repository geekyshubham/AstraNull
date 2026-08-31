import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  LEAN_GROUP_LOOKUP,
  TARGET_GROUP_FINDINGS_LIMIT,
  createCoreCatalogRepository,
} from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const IDS = {
  tenantA: 'ten_tgdet_a',
  tenantB: 'ten_tgdet_b',
  environmentA: 'env_tgdet_a',
  environmentB: 'env_tgdet_b',
  signedGroup: 'tg_tgdet_signed',
  bareGroup: 'tg_tgdet_bare',
  otherTenantGroup: 'tg_tgdet_other',
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
            ($7, $8, $9, 'other tenant group', now())`,
    [
      IDS.signedGroup, IDS.tenantA, IDS.environmentA,
      IDS.bareGroup, IDS.tenantA, IDS.environmentA,
      IDS.otherTenantGroup, IDS.tenantB, IDS.environmentB,
    ],
  );

  const targets = [
    ['tgt_tgdet_1', IDS.tenantA, IDS.signedGroup, 'one.example'],
    ['tgt_tgdet_2', IDS.tenantA, IDS.signedGroup, 'two.example'],
    // Same group id under another tenant: nothing may bleed across tenants.
    ['tgt_tgdet_3', IDS.tenantB, IDS.otherTenantGroup, 'three.example'],
  ];
  for (const [id, tenantId, groupId, value] of targets) {
    await client.query(
      `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
       VALUES ($1, $2, $3, 'fqdn', $4, $4)`,
      [id, tenantId, groupId, value],
    );
  }

  // Seven runs so the recent cap (6) and the started_at DESC ordering both bite.
  for (let i = 1; i <= 7; i += 1) {
    await client.query(
      `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, started_at)
       VALUES ($1, $2, $3, $4, $5, $6, now() - ($7 || ' minutes')::interval)`,
      [
        `run_tgdet_${i}`,
        IDS.tenantA,
        IDS.signedGroup,
        'tgt_tgdet_1',
        `chk_${i}`,
        i === 1 ? 'running' : 'completed',
        String(i * 10),
      ],
    );
  }
  await client.query(
    `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, started_at)
     VALUES ($1, $2, $3, $4, 'chk_other', 'completed', now())`,
    ['run_tgdet_other', IDS.tenantB, IDS.otherTenantGroup, 'tgt_tgdet_3'],
  );

  await client.query(
    `INSERT INTO findings (id, tenant_id, target_group_id, target_id, title, severity, status, created_at)
     VALUES ($1, $2, $3, $4, 'Origin reachable', 'high', 'open', now() - interval '2 hours'),
            ($5, $6, $7, NULL, 'Group scoped drift', 'medium', 'closed', now() - interval '1 hour')`,
    [
      'fnd_tgdet_1', IDS.tenantA, IDS.signedGroup, 'tgt_tgdet_1',
      'fnd_tgdet_2', IDS.tenantA, IDS.signedGroup,
    ],
  );
  await client.query(
    `INSERT INTO findings (id, tenant_id, target_group_id, title, severity, status)
     VALUES ($1, $2, $3, 'Other tenant finding', 'high', 'open')`,
    ['fnd_tgdet_other', IDS.tenantB, IDS.otherTenantGroup],
  );

  await client.query(
    `INSERT INTO loa_signatures (
       id, tenant_id, target_group_id, state, signer_name, signer_title, signer_email,
       emergency_contact, attested, scope_snapshot, custody_artifact_id,
       custody_digest_sha256, audit_entry_id
     ) VALUES (
       'loa_tgdet_signed', $1, $2, 'signed', 'Signer', 'CISO', 's@example.com',
       '{"name":"Ops","role":"SRE","phone":"+1","email":"ops@example.com"}'::jsonb,
       true, '{"targets":[]}'::jsonb, 'art_tgdet', 'sha256-tgdet', 'aud_tgdet'
     )`,
    [IDS.tenantA, IDS.signedGroup],
  );
  await client.query(
    `INSERT INTO loa_signatures (
       id, tenant_id, target_group_id, state, signer_name, signer_title, signer_email,
       emergency_contact, attested, scope_snapshot, custody_artifact_id,
       custody_digest_sha256, audit_entry_id
     ) VALUES (
       'loa_tgdet_revoked', $1, $2, 'revoked', 'Signer', 'CISO', 's@example.com',
       '{"name":"Ops","role":"SRE","phone":"+1","email":"ops@example.com"}'::jsonb,
       true, '{"targets":[]}'::jsonb, 'art_tgdet_r', 'sha256-tgdet-r', 'aud_tgdet_r'
     )`,
    [IDS.tenantA, IDS.bareGroup],
  );
}

describe('postgres getTargetGroup detail parity', () => {
  it('returns the dev-json enriched detail shape scoped to the calling tenant', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await withTenantContext(pool, IDS.tenantA, (client) => seed(client));

      const repo = createCoreCatalogRepository(pool);
      const detail = await repo.getTargetGroup({ tenantId: IDS.tenantA }, IDS.signedGroup);

      assert.equal(detail.id, IDS.signedGroup);
      assert.deepEqual(detail.targets.map((t2) => t2.id), ['tgt_tgdet_1', 'tgt_tgdet_2']);
      assert.equal(detail.target_count, 2);
      assert.equal(detail.loa_state, 'signed');
      assert.deepEqual(detail.loa, {
        state: 'signed',
        signer_name: 'Signer',
        signed_at: detail.loa.signed_at,
        custody_digest_sha256: 'sha256-tgdet',
      });
      assert.match(detail.loa.signed_at, /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/);

      // Capped at 6 and newest-first (run_tgdet_1 started 10 minutes ago).
      assert.equal(detail.runs_recent.length, 6);
      assert.deepEqual(
        detail.runs_recent.map((run) => run.id),
        ['run_tgdet_1', 'run_tgdet_2', 'run_tgdet_3', 'run_tgdet_4', 'run_tgdet_5', 'run_tgdet_6'],
      );
      assert.deepEqual(detail.runs_recent[0], {
        id: 'run_tgdet_1',
        policy_id: null,
        check_count: 'chk_1',
        verdict: 'running',
        started_at: detail.runs_recent[0].started_at,
        agent_id: null,
      });
      assert.match(detail.runs_recent[0].started_at, /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/);

      // Newest-first by created_at (fnd_tgdet_2 is 1 hour old, fnd_tgdet_1 is 2 hours old).
      assert.deepEqual(detail.findings_on_group, [
        {
          id: 'fnd_tgdet_2',
          target_id: null,
          title: 'Group scoped drift',
          severity: 'medium',
          status: 'closed',
        },
        {
          id: 'fnd_tgdet_1',
          target_id: 'tgt_tgdet_1',
          title: 'Origin reachable',
          severity: 'high',
          status: 'open',
        },
      ]);
      assert.equal(detail.findings_on_group_total, 2);
      assert.deepEqual(detail.meta, {
        targets_empty_reason: null,
        runs_empty_reason: null,
        findings_empty_reason: null,
      });

      const bare = await repo.getTargetGroup({ tenantId: IDS.tenantA }, IDS.bareGroup);
      assert.equal(bare.target_count, 0);
      // A revoked signature is not an active LOA.
      assert.equal(bare.loa, null);
      assert.equal(bare.loa_state, 'required');
      assert.deepEqual(bare.runs_recent, []);
      assert.deepEqual(bare.findings_on_group, []);
      assert.equal(bare.findings_on_group_total, 0);
      assert.deepEqual(bare.meta, {
        targets_empty_reason: 'No targets have been declared for this group yet.',
        runs_empty_reason: 'No test runs have been recorded for this target group yet.',
        findings_empty_reason: 'No findings are published for this target group yet.',
      });

      // Cross-tenant reads must not see tenant A rows, and tenant A must not see B's.
      assert.equal(await repo.getTargetGroup({ tenantId: IDS.tenantB }, IDS.signedGroup), null);
      const otherTenant = await repo.getTargetGroup(
        { tenantId: IDS.tenantB },
        IDS.otherTenantGroup,
      );
      assert.equal(otherTenant.target_count, 1);
      assert.deepEqual(otherTenant.runs_recent.map((run) => run.id), ['run_tgdet_other']);
      assert.deepEqual(
        otherTenant.findings_on_group.map((finding) => finding.id),
        ['fnd_tgdet_other'],
      );
    });
  });

  it('caps findings_on_group at 50 newest-first and reports the untruncated total', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await withTenantContext(pool, IDS.tenantA, async (client) => {
        await seed(client);
        // seed() already wrote 2 findings on the signed group.
        const extra = TARGET_GROUP_FINDINGS_LIMIT + 5 - 2;
        for (let i = 0; i < extra; i += 1) {
          await client.query(
            `INSERT INTO findings (id, tenant_id, target_group_id, title, severity, status, created_at)
             VALUES ($1, $2, $3, $4, 'low', 'open', now() + ($5 || ' minutes')::interval)`,
            [
              `fnd_tgdet_bulk_${String(i).padStart(3, '0')}`,
              IDS.tenantA,
              IDS.signedGroup,
              `Bulk finding ${i}`,
              String(i + 1),
            ],
          );
        }
      });

      const repo = createCoreCatalogRepository(pool);
      const detail = await repo.getTargetGroup({ tenantId: IDS.tenantA }, IDS.signedGroup);

      assert.equal(detail.findings_on_group.length, TARGET_GROUP_FINDINGS_LIMIT);
      assert.equal(detail.findings_on_group_total, TARGET_GROUP_FINDINGS_LIMIT + 5);
      // Newest first: the last-inserted bulk finding leads, the oldest seed rows fall off.
      assert.equal(
        detail.findings_on_group[0].id,
        `fnd_tgdet_bulk_${String(TARGET_GROUP_FINDINGS_LIMIT + 5 - 2 - 1).padStart(3, '0')}`,
      );
      assert.equal(
        detail.findings_on_group.some((finding) => finding.id === 'fnd_tgdet_1'),
        false,
        'the oldest findings are truncated, not the newest',
      );
    });
  });

  it('stamps verification_state on detail targets and skips the aggregates when lean', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await withTenantContext(pool, IDS.tenantA, (client) => seed(client));
      const repo = createCoreCatalogRepository(pool);

      // dev-json's detail stamps every target with a verification_state; Postgres omitted it.
      const detail = await repo.getTargetGroup({ tenantId: IDS.tenantA }, IDS.signedGroup);
      assert.deepEqual(
        detail.targets.map((target) => target.verification_state),
        ['unverified', 'unverified'],
      );

      // The lean lookup keeps everything internal callers read and drops the rest.
      const lean = await repo.getTargetGroup(
        { tenantId: IDS.tenantA },
        IDS.signedGroup,
        LEAN_GROUP_LOOKUP,
      );
      assert.equal(lean.id, IDS.signedGroup);
      assert.equal(lean.environment_id, IDS.environmentA);
      assert.equal(lean.validation_mode, detail.validation_mode);
      assert.equal(lean.ownership_status, detail.ownership_status);
      assert.deepEqual(lean.targets.map((target) => target.id), ['tgt_tgdet_1', 'tgt_tgdet_2']);
      assert.equal(lean.target_count, 2);
      for (const key of ['runs_recent', 'findings_on_group', 'loa', 'meta']) {
        assert.equal(key in lean, false, `lean lookup must not carry ${key}`);
      }

      // Tenant scoping and the archived/deleted filter still apply on the lean path.
      assert.equal(
        await repo.getTargetGroup({ tenantId: IDS.tenantB }, IDS.signedGroup, LEAN_GROUP_LOOKUP),
        null,
      );
    });
  });
});
