import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresCatalogServices } from '../../src/persistence/postgres/serviceAdapters.mjs';
import {
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';
const TENANT_A = 'ten_tgc_a';
const TENANT_B = 'ten_tgc_b';
const GROUP_ID = 'tg_tgc_counts';
const BARE_GROUP_ID = 'tg_tgc_bare';
const ZERO_GROUP_ID = 'tg_tgc_zero';
const FOREIGN_GROUP_ID = 'tg_tgc_foreign';

async function createAppRolePool(adminPool, databaseName) {
  await adminPool.query(
    `ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`,
  );
  const url = new URL(
    databaseUrlWithDatabase(adminPool.options.connectionString, databaseName).replace(/^postgresql:/i, 'postgres:'),
  );
  url.username = APP_ROLE_NAME;
  url.password = APP_ROLE_PASSWORD;
  const pool = createPgPool({ ASTRANULL_DATABASE_URL: url.toString().replace(/^postgres:/i, 'postgresql:') });
  const check = await pool.query(
    'SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user',
  );
  assert.equal(check.rows[0].role, APP_ROLE_NAME);
  assert.equal(check.rows[0].rolsuper, false);
  assert.equal(check.rows[0].rolbypassrls, false);
  return pool;
}

/**
 * Recording pool over the real app-role pool. `withTenantContext` lands on
 * `connect()` itself, so every borrowed client is released exactly once by the
 * shared finally and teardown `pool.end()` can never wait on a leaked client.
 * @param {import('pg').Pool} realPool
 * @param {string[]} texts
 */
function recordingPool(realPool, texts) {
  return {
    connect: async () => {
      const client = await realPool.connect();
      const wrapped = {
        query(sql, params) {
          texts.push(String(sql));
          return client.query(sql, params);
        },
        release: (arg) => client.release(arg),
      };
      return wrapped;
    },
  };
}

describe('postgres current-release target group open findings counts', () => {
  it('counts the exact open lifecycle with one bounded aggregate per read under real RLS', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await ownerPool.query(`INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')`, [TENANT_A, TENANT_B]);
      await ownerPool.query(
        `INSERT INTO environments (id, tenant_id, name) VALUES ('env_tgc_a', $1, 'A'), ('env_tgc_b', $2, 'B')`,
        [TENANT_A, TENANT_B],
      );
      await ownerPool.query(
        `INSERT INTO target_groups (id, tenant_id, environment_id, name)
         VALUES
           ($1, $2, 'env_tgc_a', 'counts'),
           ($3, $2, 'env_tgc_a', 'bare'),
           ($4, $2, 'env_tgc_a', 'zero'),
           ($5, $6, 'env_tgc_b', 'foreign')`,
        [GROUP_ID, TENANT_A, BARE_GROUP_ID, ZERO_GROUP_ID, FOREIGN_GROUP_ID, TENANT_B],
      );
      await ownerPool.query(
        `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, deleted_at)
         VALUES
           ('tgt_tgc_count', $1, $2, 'fqdn', 'count.example.com', 'count.example.com', NULL),
           ('tgt_tgc_moved', $1, $3, 'fqdn', 'moved.example.com', 'moved.example.com', NULL),
           ('tgt_tgc_dead',  $1, $2, 'fqdn', 'dead.example.com', 'dead.example.com', now())`,
        [TENANT_A, GROUP_ID, BARE_GROUP_ID],
      );

      const findings = [];
      // Stored open findings for the counted group: the list counter must never
      // be a capped 50-row findings page.
      for (let i = 0; i < 55; i += 1) {
        findings.push([`fnd_tgc_bulk_${i}`, TENANT_A, GROUP_ID, 'tgt_tgc_count', `chk_bulk_${i}`, 'open', 'Bulk gap']);
      }
      // Non-open lifecycle rows: in_progress belongs to the UI Active bucket,
      // remediation_pending was a legacy alias, and closures never count.
      findings.push(['fnd_tgc_progress', TENANT_A, GROUP_ID, 'tgt_tgc_count', 'chk_progress', 'in_progress', 'In progress']);
      findings.push(['fnd_tgc_remediation', TENANT_A, GROUP_ID, 'tgt_tgc_count', 'chk_remediation', 'remediation_pending', 'Legacy pending']);
      findings.push(['fnd_tgc_accepted', TENANT_A, GROUP_ID, 'tgt_tgc_count', 'chk_accepted', 'accepted_risk', 'Accepted']);
      findings.push(['fnd_tgc_accepted_plain', TENANT_A, GROUP_ID, 'tgt_tgc_count', 'chk_accepted_plain', 'accepted', 'Accepted plain']);
      findings.push(['fnd_tgc_resolved', TENANT_A, GROUP_ID, 'tgt_tgc_count', 'chk_resolved', 'resolved', 'Resolved']);
      findings.push(['fnd_tgc_closed', TENANT_A, GROUP_ID, 'tgt_tgc_count', 'chk_closed', 'closed', 'Closed']);
      findings.push(['fnd_tgc_false', TENANT_A, GROUP_ID, 'tgt_tgc_count', 'chk_false', 'false_positive', 'False positive']);
      // Case and padding variants of the open value still count as open.
      findings.push(['fnd_tgc_open_padded', TENANT_A, GROUP_ID, null, 'chk_open_padded', '  Open  ', 'Padded open']);
      // Stored group plus moved member target: matches both groups, never twice
      // within one group.
      findings.push(['fnd_tgc_moved', TENANT_A, GROUP_ID, 'tgt_tgc_moved', 'chk_moved', 'open', 'Moved member']);
      findings.push(['fnd_tgc_stored_only', TENANT_A, BARE_GROUP_ID, null, 'chk_stored_only', 'open', 'Stored only']);
      // An active member target without a stored group id still counts for the group.
      findings.push(['fnd_tgc_member_only', TENANT_A, null, 'tgt_tgc_count', 'chk_member_only', 'open', 'Member only']);
      // A deleted member target does not extend membership.
      findings.push(['fnd_tgc_dead_member', TENANT_A, null, 'tgt_tgc_dead', 'chk_dead_member', 'open', 'Dead member']);
      // Foreign tenant row on its own foreign group.
      findings.push(['fnd_tgc_foreign_row', TENANT_B, FOREIGN_GROUP_ID, null, 'chk_foreign', 'open', 'Foreign group gap']);

      for (const [id, tenant, groupId, targetId, checkId, status, title] of findings) {
        await ownerPool.query(
          `INSERT INTO findings (id, tenant_id, target_group_id, target_id, check_id, title, severity, status, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, 'medium', $7, now() - random() * interval '10 days')`,
          [id, tenant, groupId, targetId, checkId, title, status],
        );
      }

      await ensureHarnessAppRole(ownerPool);
      const appPool = await createAppRolePool(ownerPool, databaseName);
      try {
        // The recorded pool wraps the real app-role pool (NOSUPERUSER,
        // NOBYPASSRLS): every borrowed client is released by the shared
        // withTenantContext finally, so the recordings cannot leak clients.
        const texts = [];
        const foreignTexts = [];
        const repo = createCoreCatalogRepository(recordingPool(appPool, texts));
        const list = await repo.listTargetGroups({ tenantId: TENANT_A, userId: 'usr_tgc', role: 'engineer' });
        const foreignList = await createCoreCatalogRepository(recordingPool(appPool, foreignTexts))
          .listTargetGroups({ tenantId: TENANT_B, userId: 'usr_tgc', role: 'engineer' });

        assert.equal(list.length, 3);
        const counts = new Map(list.map((group) => [group.id, group.open_findings_count]));
        // 55 bulk open + padded open + the moved stored-group finding + the
        // member-only finding. in_progress, the legacy remediation_pending
        // alias, and every closure status are excluded.
        assert.equal(counts.get(GROUP_ID), 58);
        assert.equal(counts.get(BARE_GROUP_ID), 2);
        // A group with no matching findings reports an actually counted zero.
        assert.equal(counts.get(ZERO_GROUP_ID), 0);
        for (const group of list) {
          assert.equal(typeof group.open_findings_count, 'number');
          assert.equal(Number.isInteger(group.open_findings_count), true);
        }
        const bare = list.find((group) => group.id === BARE_GROUP_ID);
        assert.equal(bare.target_count, 1);

        // The count agrees with the same-predicate status=open findings total.
        const openRows = await createValidationEvidenceRepository(appPool)
          .listFindings(
            { tenantId: TENANT_A, userId: 'usr_tgc', role: 'engineer' },
            { target_group_id: GROUP_ID, status: 'open' },
          );
        assert.equal(openRows.length, counts.get(GROUP_ID));

        // Tenant isolation under the real RLS app role: the foreign tenant
        // never counts or lists A rows even with identical row shapes.
        assert.deepEqual(
          foreignList.map((group) => [group.id, group.open_findings_count]),
          [[FOREIGN_GROUP_ID, 1]],
        );
        assert.equal(foreignTexts.some((text) => text.includes(GROUP_ID)), false);

        // One SQL read carrying the grouped aggregate: no per-group query loop
        // and no capped findings page anywhere in the statement.
        assert.equal(texts.filter((text) => text.includes('FROM target_groups')).length, 1);
        const listText = texts.find((text) => text.includes('COUNT(*)::int AS open_findings_count'));
        assert.equal(listText != null, true);
        assert.equal(listText.includes("lower(btrim(f.status)) = 'open'"), true);
        assert.equal(listText.includes('f.status IN'), false);
        assert.equal(listText.includes('LIMIT $'), false);

        // The production service adapter forwards repository rows and does not
        // strip the additive count field.
        const services = createPostgresCatalogServices({ coreCatalog: createCoreCatalogRepository(appPool) });
        const forwarded = await services.targetGroups.listTargetGroups(
          { tenantId: TENANT_A, userId: 'usr_tgc', role: 'engineer' },
        );
        assert.deepEqual(
          forwarded.map((group) => [group.id, group.open_findings_count]),
          list.map((group) => [group.id, group.open_findings_count]),
        );
      } finally {
        await closePgPool(appPool);
      }
    }, availability.env);
  });
});
