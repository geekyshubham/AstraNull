import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createInternalManagementRepository } from '../../src/persistence/postgres/internalManagementRepository.mjs';
import { createPostgresInternalManagementServices } from '../../src/persistence/postgres/internalManagementServiceAdapters.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import {
  assertRlsPoliciesExist,
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
  withTenantContextAsAppRole,
} from '../helpers/pg-harness.mjs';

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';

const PLATFORM_SCOPE_POLICIES = [
  'platform_scope_read_tenants',
  'platform_scope_read_users',
  'platform_scope_read_tenant_accounts',
  'platform_scope_read_tenant_subscriptions',
  'platform_scope_read_internal_approval_requests',
  'platform_scope_read_internal_audit_log',
];

/**
 * The default harness pool connects as the migration owner, which is a SUPERUSER with
 * BYPASSRLS — RLS is not enforced on it, so a repository test driven through it would pass
 * whether or not the platform-scope policies exist. Every assertion here runs through a pool
 * that authenticates as the non-superuser, NOBYPASSRLS `astranull_app` role, so the RLS
 * behaviour under test is real.
 *
 * @param {import('pg').Pool} adminPool
 * @param {string} ownerDatabaseUrl
 */
async function createAppRolePool(adminPool, ownerDatabaseUrl) {
  await adminPool.query(
    `ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`,
  );
  const url = new URL(ownerDatabaseUrl.replace(/^postgresql:/i, 'postgres:'));
  url.username = APP_ROLE_NAME;
  url.password = APP_ROLE_PASSWORD;
  const appUrl = url.toString().replace(/^postgres:/i, 'postgresql:');
  const pool = createPgPool({ ASTRANULL_DATABASE_URL: appUrl });
  const check = await pool.query(
    'SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user',
  );
  assert.equal(check.rows[0].role, APP_ROLE_NAME, 'must connect as the app role');
  assert.equal(check.rows[0].rolsuper, false, 'app role must not be superuser (RLS must apply)');
  assert.equal(check.rows[0].rolbypassrls, false, 'app role must not have BYPASSRLS');
  return pool;
}

/**
 * @param {import('pg').Pool} ownerPool owner pool (used for the ephemeral db url)
 * @param {(ctx: { appPool: import('pg').Pool, repo: any, services: any }) => Promise<void>} run
 */
async function withAppRoleRepository(ownerPool, databaseName, run) {
  await ensureHarnessAppRole(ownerPool);
  const ownerUrl = ownerPool.options.connectionString;
  const appPool = await createAppRolePool(
    ownerPool,
    databaseUrlWithDatabase(ownerUrl, databaseName),
  );
  try {
    const repo = createInternalManagementRepository(appPool);
    const services = createPostgresInternalManagementServices({ internalManagement: repo });
    await run({ appPool, repo, services });
  } finally {
    await closePgPool(appPool);
  }
}

const SIGNUP_INSERT = `
  INSERT INTO signup_requests (
    id, organization_name, contact_email, contact_name, email_domain,
    requested_plan, intended_use, region, state
  ) VALUES ($1, $2, $3, $4, $5, 'starter', 'Defensive DDoS readiness validation.', 'us', $6)
`;

describe('postgres internal management platform-scope RLS', () => {
  it('staff audit reads return tenant-attributed rows and stay tenant-isolated', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(
      async (ownerPool, { databaseName }) => {
        await assertRlsPoliciesExist(ownerPool, PLATFORM_SCOPE_POLICIES);

        const tenantA = 'ten_pscope_a';
        const tenantB = 'ten_pscope_b';

        await withTenantContext(ownerPool, tenantA, async (client) => {
          await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Tenant A')`, [tenantA]);
          await client.query(
            `INSERT INTO tenant_accounts (tenant_id, legal_name, region, lifecycle_state)
             VALUES ($1, 'Tenant A LLC', 'us', 'active')`,
            [tenantA],
          );
        });
        await withTenantContext(ownerPool, tenantB, async (client) => {
          await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Tenant B')`, [tenantB]);
          await client.query(
            `INSERT INTO tenant_accounts (tenant_id, legal_name, region, lifecycle_state)
             VALUES ($1, 'Tenant B LLC', 'us', 'suspended')`,
            [tenantB],
          );
        });

        await withAppRoleRepository(ownerPool, databaseName, async ({ appPool, repo }) => {
          // --- audit integrity: tenant-attributed rows must be visible to staff reads ---
          const written = await repo.appendInternalAudit({
            id: 'iaud_pscope_a',
            tenant_id: tenantA,
            staff_id: 'staff_1',
            staff_role: 'internal_admin',
            action: 'staff.tenant.updated',
            resource_type: 'tenant',
            resource_id: tenantA,
            reason: 'lifecycle change',
            metadata: { lifecycle_state: 'active' },
            created_at: new Date().toISOString(),
          });
          assert.equal(written.tenant_id, tenantA);

          // A platform-level (tenant_id IS NULL) row, which was visible even before the fix.
          await repo.appendInternalAudit({
            id: 'iaud_pscope_null',
            tenant_id: null,
            staff_id: 'staff_1',
            staff_role: 'internal_admin',
            action: 'signup.request_submitted',
            created_at: new Date().toISOString(),
          });

          const all = await repo.listInternalAudit({});
          const ids = all.map((row) => row.id);
          assert.ok(
            ids.includes('iaud_pscope_a'),
            'listInternalAudit must return the tenant-attributed row (audit-integrity defect)',
          );
          assert.ok(ids.includes('iaud_pscope_null'), 'platform-level row must remain visible');

          // filters.tenant_id branch
          const filtered = await repo.listInternalAudit({ tenant_id: tenantA });
          assert.deepEqual(
            filtered.map((row) => row.id),
            ['iaud_pscope_a'],
            'filters.tenant_id must return the tenant-attributed row',
          );

          // --- listTenants / getInternalOverview ---
          const tenants = await repo.listTenants();
          const tenantIds = tenants.map((row) => row.tenant_id).sort();
          assert.deepEqual(tenantIds, [tenantA, tenantB], 'listTenants must return both tenants');

          const overview = await repo.getInternalOverview();
          assert.equal(overview.tenant_count, 2, 'tenant_count must count both tenants');
          assert.equal(overview.blocked_tenants, 1, 'suspended tenant must be counted');

          // --- REGRESSION: tenant isolation must still hold in the opposite direction ---
          await withTenantContextAsAppRole(appPool, tenantB, async (client) => {
            const leaked = await client.query(
              `SELECT id FROM internal_audit_log WHERE id = $1 OR tenant_id = $2`,
              ['iaud_pscope_a', tenantA],
            );
            assert.equal(leaked.rows.length, 0, 'tenant B must not read tenant A audit rows');

            const leakedTenants = await client.query(
              `SELECT id FROM tenants WHERE id = $1`,
              [tenantA],
            );
            assert.equal(leakedTenants.rows.length, 0, 'tenant B must not read tenant A tenant row');

            const leakedAccounts = await client.query(
              `SELECT tenant_id FROM tenant_accounts WHERE tenant_id = $1`,
              [tenantA],
            );
            assert.equal(leakedAccounts.rows.length, 0, 'tenant B must not read tenant A account');
          });

          // A tenant-scoped request path must never be able to escalate to platform scope,
          // even if it sets the marker itself: the policies also require an unset app.tenant_id.
          await withTenantContextAsAppRole(appPool, tenantB, async (client) => {
            await client.query(`SELECT set_config('app.platform_scope', 'on', true)`);
            const escalated = await client.query(
              `SELECT id FROM internal_audit_log WHERE tenant_id = $1`,
              [tenantA],
            );
            assert.equal(
              escalated.rows.length,
              0,
              'app.platform_scope must not escalate a tenant-scoped connection',
            );
            const escalatedTenants = await client.query(`SELECT id FROM tenants WHERE id = $1`, [
              tenantA,
            ]);
            assert.equal(escalatedTenants.rows.length, 0, 'no cross-tenant tenants read');
          });

          // The marker must be transaction-local: a fresh transaction has no platform scope.
          const bare = await appPool.query(
            `SELECT current_setting('app.platform_scope', true) AS scope`,
          );
          assert.ok(
            bare.rows[0].scope === null || bare.rows[0].scope === '',
            'app.platform_scope must not persist on a pooled connection',
          );
        });
      },
      process.env,
      { databaseName: undefined },
    );
  });

  it('overlapping approvals provision exactly one tenant and the loser gets a conflict', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await ownerPool.query(SIGNUP_INSERT, [
        'signup_race_1',
        'Race Org',
        'ops@race.example',
        'Ops Lead',
        'race.example',
        'submitted',
      ]);

      await withAppRoleRepository(ownerPool, databaseName, async ({ appPool, repo, services }) => {
        const ctx = { staffId: 'staff_race', staffRole: 'internal_admin' };
        const [first, second] = await Promise.all([
          services.approveSignupRequest(ctx, 'signup_race_1', { reason: 'ok' }),
          services.approveSignupRequest(ctx, 'signup_race_1', { reason: 'ok' }),
        ]);

        const results = [first, second];
        const winners = results.filter((r) => r && !r.error && r.provisioning);
        const losers = results.filter((r) => r && r.error);

        assert.equal(winners.length, 1, `exactly one approve must win: ${JSON.stringify(results)}`);
        assert.equal(losers.length, 1, 'the losing approve must report a conflict');
        assert.ok(
          ['signup_state_conflict', 'invalid_state_transition'].includes(losers[0].error),
          `loser error must be a 409-mapped conflict, got ${losers[0].error}`,
        );

        // Exactly one tenant provisioned — the core duplicate-provisioning guarantee.
        const tenants = await repo.listTenants();
        assert.equal(tenants.length, 1, 'exactly one tenant may be provisioned');
        assert.equal(tenants[0].tenant_id, winners[0].provisioning.tenant_id);

        const signup = await repo.getSignupRequest('signup_race_1');
        assert.equal(signup.state, 'customer_invited');
        assert.equal(signup.provisioned_tenant_id, winners[0].provisioning.tenant_id);

        // Only one owner user for the provisioned tenant (no partial duplicate rows).
        const users = await withTenantContextAsAppRole(
          appPool,
          winners[0].provisioning.tenant_id,
          async (client) => {
            const { rows } = await client.query('SELECT id FROM users WHERE tenant_id = $1', [
              winners[0].provisioning.tenant_id,
            ]);
            return rows;
          },
        );
        assert.equal(users.length, 1, 'exactly one owner user row');
      });
    });
  });

  it('the atomic provisioning claim rejects a second claim on the same approved signup', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await ownerPool.query(SIGNUP_INSERT, [
        'signup_claim_1',
        'Claim Org',
        'ops@claim.example',
        'Ops Lead',
        'claim.example',
        'approved',
      ]);

      await withAppRoleRepository(ownerPool, databaseName, async ({ repo }) => {
        const now = new Date().toISOString();
        const buildPayload = (suffix) => ({
          signupId: 'signup_claim_1',
          expectedStates: ['approved'],
          signupPatch: {
            state: 'provisioned',
            reviewer_staff_id: 'staff_claim',
            decision_reason: 'approved',
            customer_notice: null,
            provisioned_tenant_id: `ten_claim_${suffix}`,
            updated_at: now,
            decided_at: now,
          },
          tenant: {
            id: `ten_claim_${suffix}`,
            name: `Claim Org ${suffix}`,
            privacy_settings: {},
            created_at: now,
          },
          environment: {
            id: `env_claim_${suffix}`,
            name: 'Production Validation',
            privacy_settings: {},
            settings_json: {},
            created_at: now,
          },
          user: {
            id: `user_claim_${suffix}`,
            email: 'ops@claim.example',
            name: 'Ops Lead',
            role: 'owner',
            status: 'invited',
            invited_at: now,
            created_at: now,
          },
          account: {
            legal_name: 'Claim Org',
            support_owner: 'staff_claim',
            region: 'us',
            lifecycle_state: 'active',
            contract_reference: null,
            created_at: now,
          },
          subscription: {
            plan_id: 'starter',
            status: 'active',
            billing_provider_ref: null,
            effective_at: now,
            renewal_at: null,
            limits: {},
            feature_entitlements: {},
          },
          grants: [],
        });

        const [a, b] = await Promise.all([
          repo.provisionTenantForApprovedSignup(buildPayload('a')),
          repo.provisionTenantForApprovedSignup(buildPayload('b')),
        ]);

        const claimed = [a, b].filter(Boolean);
        assert.equal(claimed.length, 1, 'exactly one claim may succeed');
        assert.equal(claimed[0].request.state, 'provisioned');

        // The loser rolled back entirely: only the winner's tenant row exists.
        const tenants = await repo.listTenants();
        assert.equal(tenants.length, 1, 'losing claim must not leave a tenant row behind');
        assert.equal(tenants[0].tenant_id, claimed[0].request.provisioned_tenant_id);
      });
    });
  });
});
