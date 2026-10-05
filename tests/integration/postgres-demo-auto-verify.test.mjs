import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { DEMO_AUTO_VERIFY_AUDIT_ACTION, DEMO_AUTO_VERIFY_ENV } from '../../src/lib/demoAutoVerify.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const DEMO = 'ten_pg_demo';
const OTHER = 'ten_pg_other';

async function seedTenant(pool, tenantId) {
  await withTenantContext(pool, tenantId, async (client) => {
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, $1)`, [tenantId]);
    await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'env')`, [`env_${tenantId}`, tenantId]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name) VALUES ($1, $2, $3, 'group')`,
      [`tg_${tenantId}`, tenantId, `env_${tenantId}`],
    );
  });
}

async function currentVerification(pool, tenantId, targetId) {
  return withTenantContext(pool, tenantId, async (client) => {
    const { rows } = await client.query(
      `SELECT state, source_kind, source_ref FROM target_verification_current WHERE tenant_id = $1 AND target_id = $2`,
      [tenantId, targetId],
    );
    return rows[0] ?? null;
  });
}

describe('postgres demo auto-verify', () => {
  let previous;
  beforeEach(() => {
    previous = process.env[DEMO_AUTO_VERIFY_ENV];
    process.env[DEMO_AUTO_VERIFY_ENV] = DEMO;
  });
  afterEach(() => {
    if (previous === undefined) delete process.env[DEMO_AUTO_VERIFY_ENV];
    else process.env[DEMO_AUTO_VERIFY_ENV] = previous;
  });

  it('records an audited demo verification only for the allowlisted tenant', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (pool) => {
      await seedTenant(pool, DEMO);
      await seedTenant(pool, OTHER);
      const auditRepository = createAuditRepository(pool);
      const catalog = createCoreCatalogRepository(pool, { auditRepository });

      const demoCtx = { tenantId: DEMO, userId: 'usr_demo', role: 'admin' };
      const demoTarget = await catalog.createTargetDirect(demoCtx, {
        kind: 'fqdn', value: 'anything.example.org', target_group_id: `tg_${DEMO}`,
      });
      const verification = await currentVerification(pool, DEMO, demoTarget.id);
      assert.equal(verification?.state, 'user_confirmed');
      assert.equal(verification?.source_kind, 'manual_override');
      assert.equal(verification?.source_ref?.method, 'demo_auto_verify');
      const audit = await auditRepository.listAuditEntries(demoCtx, {});
      assert.ok((audit.items ?? audit).some((row) => row.action === DEMO_AUTO_VERIFY_AUDIT_ACTION && row.resource_id === demoTarget.id));

      const otherCtx = { tenantId: OTHER, userId: 'usr_other', role: 'admin' };
      const otherTarget = await catalog.createTargetDirect(otherCtx, {
        kind: 'fqdn', value: 'anything.example.org', target_group_id: `tg_${OTHER}`,
      });
      assert.equal(await currentVerification(pool, OTHER, otherTarget.id), null);
    });
  });
});
