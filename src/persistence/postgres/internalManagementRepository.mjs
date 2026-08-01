import { normalizePrivacySettings } from '../../lib/privacySettings.mjs';
import { runWithTenantClient, withTenantContext } from './tenantContext.mjs';

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function mapSignup(row) {
  if (!row) return null;
  return {
    id: row.id,
    organization_name: row.organization_name,
    contact_email: row.contact_email,
    contact_name: row.contact_name,
    email_domain: row.email_domain,
    requested_plan: row.requested_plan,
    intended_use: row.intended_use,
    region: row.region,
    high_scale_interest: Boolean(row.high_scale_interest),
    state: row.state,
    reviewer_staff_id: row.reviewer_staff_id ?? null,
    decision_reason: row.decision_reason ?? null,
    customer_notice: row.customer_notice ?? null,
    provisioned_tenant_id: row.provisioned_tenant_id ?? null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
    decided_at: toIso(row.decided_at),
  };
}

function mapTenant(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    created_at: toIso(row.created_at),
    privacy_settings: normalizePrivacySettings(row.privacy_settings),
  };
}

function mapTenantAccount(row) {
  if (!row) return null;
  return {
    tenant_id: row.tenant_id,
    legal_name: row.legal_name ?? null,
    support_owner: row.support_owner ?? null,
    region: row.region ?? 'us',
    lifecycle_state: row.lifecycle_state ?? 'active',
    contract_reference: row.contract_reference ?? null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

function mapSubscription(row, grants = []) {
  if (!row) return null;
  return {
    tenant_id: row.tenant_id,
    plan_id: row.plan_id,
    status: row.status,
    billing_provider_ref: row.billing_provider_ref ?? null,
    effective_at: toIso(row.effective_at),
    renewal_at: toIso(row.renewal_at),
    limits: asObject(row.limits_json),
    feature_entitlements: asObject(row.feature_entitlements_json),
    entitlement_grants: grants,
  };
}

function mapGrant(row) {
  if (!row) return null;
  return {
    tenant_id: row.tenant_id,
    feature: row.feature,
    enabled: Boolean(row.enabled),
    limit_value: row.limit_value ?? null,
    source: row.source,
    expires_at: toIso(row.expires_at),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

function mapUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    email: row.email,
    name: row.name,
    role: row.role,
    status: row.status ?? 'active',
    invited_at: row.invited_at ? toIso(row.invited_at) : row.metadata_json?.invited_at ?? null,
    disabled_at: row.disabled_at ? toIso(row.disabled_at) : row.metadata_json?.disabled_at ?? null,
  };
}

function mapApproval(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id ?? null,
    kind: row.kind,
    subject_ref: row.subject_ref ?? null,
    state: row.state,
    assigned_to: row.assigned_to ?? null,
    decision: row.decision ?? null,
    reason: row.reason ?? null,
    evidence_refs: row.evidence_refs ?? [],
    reviewer_staff_id: row.reviewer_staff_id ?? null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
    decided_at: toIso(row.decided_at),
  };
}

function mapBreakGlassActivation(row) {
  if (!row) return null;
  return {
    id: row.id,
    status: row.status,
    reason: row.reason ?? null,
    ticket_reference: row.ticket_reference,
    activated_by: row.activated_by ?? null,
    activated_role: row.activated_role ?? null,
    activated_at: toIso(row.activated_at),
    expires_at: toIso(row.expires_at),
    duration_minutes: Number(row.duration_minutes),
  };
}

function mapInternalAudit(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id ?? null,
    staff_id: row.staff_id ?? null,
    staff_role: row.staff_role ?? null,
    action: row.action,
    resource_type: row.resource_type ?? null,
    resource_id: row.resource_id ?? null,
    reason: row.reason ?? null,
    metadata: row.metadata_json ?? {},
    created_at: toIso(row.created_at),
  };
}

/**
 * Run staff-scope ("platform scope") reads of internal management tables.
 *
 * Internal tables (tenants, users, tenant_accounts, tenant_subscriptions,
 * internal_approval_requests, internal_audit_log) are FORCE RLS. Reading them over a raw
 * pool with no context makes `tenant_id = current_setting('app.tenant_id', true)` evaluate
 * to NULL, silently dropping every tenant-attributed row. This helper opens a transaction
 * and asserts the explicit `app.platform_scope` marker honoured by the additive SELECT-only
 * `platform_scope_read_*` policies (db/migrations/0038_platform_scope_internal_reads.sql).
 *
 * Both settings are transaction-local (`set_config(..., true)`), so the marker can never
 * outlive its transaction or leak onto a pooled connection reused by a tenant request.
 * `app.tenant_id` is pinned empty because the policies require it to be unset — a
 * tenant-scoped request path (which always sets a non-empty app.tenant_id) can therefore
 * never acquire platform scope.
 *
 * @param {import('pg').Pool} pool
 * @param {(client: import('pg').PoolClient) => Promise<unknown>} callback
 */
export async function withPlatformScope(pool, callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.tenant_id', '', true)`);
    await client.query(`SELECT set_config('app.platform_scope', 'on', true)`);
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // preserve original error
    }
    throw err;
  } finally {
    client.release();
  }
}

async function queryPlatform(pool, sql, params = []) {
  return withPlatformScope(pool, async (client) => {
    const { rows } = await client.query(sql, params);
    return rows;
  });
}

async function queryNullableTenant(pool, tenantId, callback) {
  if (tenantId) return withTenantContext(pool, tenantId, callback);
  return runWithTenantClient(pool, 'platform_internal', undefined, callback);
}

/**
 * Guarded signup state transition. The `state = ANY($9::text[])` precondition makes the
 * read-modify-write safe against lost updates (and duplicate tenant provisioning), matching
 * the pattern already used by decideApprovalRequest.
 */
const SIGNUP_UPDATE_SQL = `UPDATE signup_requests SET
           state = $2,
           reviewer_staff_id = $3,
           decision_reason = $4,
           customer_notice = $5,
           provisioned_tenant_id = $6,
           updated_at = $7::timestamptz,
           decided_at = $8::timestamptz
         WHERE id = $1 AND state = ANY($9::text[])
         RETURNING *`;

function signupUpdateParams(id, next, expectedStates) {
  return [
    id,
    next.state,
    next.reviewer_staff_id,
    next.decision_reason,
    next.customer_notice,
    next.provisioned_tenant_id,
    next.updated_at,
    next.decided_at,
    expectedStates,
  ];
}

/**
 * Insert the full tenant provisioning row set. Caller must already hold an open transaction
 * with `app.tenant_id` set to `tenant.id` (the target tables are FORCE RLS).
 *
 * @param {import('pg').PoolClient} client
 */
async function insertTenantProvisioningRows(client, { tenant, environment, user, account, subscription, grants }) {
  // tenant-query-audit: allow — every statement in this function is scoped, but by the CALLER, not
  // here. The function takes an already-open transaction client; both callers (approveSignupRequest
  // and the provisioning retry path) run `set_config('app.tenant_id', payload.tenant.id, true)`
  // before calling, which is the contract stated in the JSDoc above.
  //
  // Safety does not rest on this comment: the target tables are FORCE ROW LEVEL SECURITY with
  // WITH CHECK on the tenant setting, so an unscoped caller does not silently write cross-tenant
  // rows — the INSERT is rejected by the database.
  await client.query(
    `INSERT INTO tenants (id, name, privacy_settings, created_at)
     VALUES ($1, $2, $3::jsonb, $4::timestamptz)`,
    [tenant.id, tenant.name, JSON.stringify(tenant.privacy_settings), tenant.created_at],
  );
  await client.query(
    `INSERT INTO environments (id, tenant_id, name, status, privacy_settings, settings_json, created_at)
     VALUES ($1, $2, $3, 'active', $4::jsonb, $5::jsonb, $6::timestamptz)`,
    [
      environment.id,
      tenant.id,
      environment.name,
      JSON.stringify(environment.privacy_settings ?? tenant.privacy_settings),
      JSON.stringify(environment.settings_json ?? {}),
      environment.created_at,
    ],
  );
  await client.query(
    `INSERT INTO users (id, tenant_id, email, name, role, status, metadata_json, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::timestamptz)`,
    [
      user.id,
      tenant.id,
      user.email,
      user.name,
      user.role,
      user.status,
      JSON.stringify({ invited_at: user.invited_at }),
      user.created_at,
    ],
  );
  await client.query(
    `INSERT INTO tenant_accounts (
       tenant_id, legal_name, support_owner, region, lifecycle_state, contract_reference, created_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7::timestamptz)`,
    [
      tenant.id,
      account.legal_name,
      account.support_owner,
      account.region,
      account.lifecycle_state,
      account.contract_reference,
      account.created_at,
    ],
  );
  await client.query(
    `INSERT INTO tenant_subscriptions (
       tenant_id, plan_id, status, billing_provider_ref, effective_at, renewal_at,
       limits_json, feature_entitlements_json, created_at
     ) VALUES ($1,$2,$3,$4,$5::timestamptz,$6::timestamptz,$7::jsonb,$8::jsonb,$9::timestamptz)`,
    [
      tenant.id,
      subscription.plan_id,
      subscription.status,
      subscription.billing_provider_ref,
      subscription.effective_at,
      subscription.renewal_at,
      JSON.stringify(subscription.limits),
      JSON.stringify(subscription.feature_entitlements),
      subscription.effective_at,
    ],
  );
  for (const grant of grants) {
    await client.query(
      `INSERT INTO entitlement_grants (
         tenant_id, feature, enabled, limit_value, source, expires_at, created_at
       ) VALUES ($1,$2,$3,$4::jsonb,$5,$6::timestamptz,$7::timestamptz)
       ON CONFLICT (tenant_id, feature) DO UPDATE SET
         enabled = EXCLUDED.enabled,
         limit_value = EXCLUDED.limit_value,
         source = EXCLUDED.source,
         expires_at = EXCLUDED.expires_at,
         updated_at = NOW()`,
      [
        tenant.id,
        grant.feature,
        grant.enabled,
        grant.limit_value == null ? null : JSON.stringify(grant.limit_value),
        grant.source,
        grant.expires_at,
        grant.created_at,
      ],
    );
  }
}

export function createInternalManagementRepository(pool) {
  return {
    async createSignupRequest(record) {
      const { rows } = await pool.query(
        `INSERT INTO signup_requests (
           id, organization_name, contact_email, contact_name, email_domain, requested_plan,
           intended_use, region, high_scale_interest, state, reviewer_staff_id,
           decision_reason, customer_notice, provisioned_tenant_id, created_at, updated_at, decided_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::timestamptz,$16::timestamptz,$17::timestamptz)
         RETURNING *`,
        [
          record.id,
          record.organization_name,
          record.contact_email,
          record.contact_name,
          record.email_domain,
          record.requested_plan,
          record.intended_use,
          record.region,
          record.high_scale_interest,
          record.state,
          record.reviewer_staff_id,
          record.decision_reason,
          record.customer_notice,
          record.provisioned_tenant_id,
          record.created_at,
          record.updated_at,
          record.decided_at,
        ],
      );
      return mapSignup(rows[0]);
    },

    async findActiveSignupByDomainOrOrg(emailDomain, organizationName) {
      const { rows } = await pool.query(
        `SELECT * FROM signup_requests
         WHERE state <> 'rejected'
           AND (email_domain = $1 OR lower(organization_name) = lower($2))
         ORDER BY created_at DESC
         LIMIT 1`,
        [emailDomain, organizationName],
      );
      return mapSignup(rows[0] ?? null);
    },

    async getSignupRequest(id) {
      const { rows } = await pool.query('SELECT * FROM signup_requests WHERE id = $1', [id]);
      return mapSignup(rows[0] ?? null);
    },

    async listSignupRequests(filters = {}) {
      const params = [];
      const where = [];
      if (filters.state) {
        params.push(filters.state);
        where.push(`state = $${params.length}`);
      }
      const { rows } = await pool.query(
        `SELECT * FROM signup_requests
         ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
         ORDER BY created_at DESC`,
        params,
      );
      return rows.map(mapSignup);
    },

    /**
     * Guarded read-modify-write. Returns null when the row is gone OR when another writer
     * changed `state` between our read and our write (lost race) — callers surface 409.
     * `patch.expected_states` overrides the default precondition (the state we just read).
     */
    async updateSignupRequest(id, patch) {
      const existing = await this.getSignupRequest(id);
      if (!existing) return null;
      const next = { ...existing, ...patch, updated_at: patch.updated_at ?? new Date().toISOString() };
      const expectedStates = Array.isArray(patch.expected_states) && patch.expected_states.length
        ? patch.expected_states.map(String)
        : [existing.state];
      const { rows } = await pool.query(
        SIGNUP_UPDATE_SQL,
        signupUpdateParams(id, next, expectedStates),
      );
      return mapSignup(rows[0] ?? null);
    },

    /**
     * Atomically claim an approved signup and provision its tenant in ONE transaction.
     *
     * The guarded `UPDATE ... WHERE state = ANY(expected_states)` is the concurrency claim:
     * a second overlapping approve blocks on the row lock, then re-evaluates the predicate
     * against the committed state and matches zero rows. Because the claim and every
     * provisioning INSERT share one transaction, a tenant can never be provisioned twice and
     * a failed provisioning cannot leave the request marked provisioned.
     *
     * @returns {Promise<{ request: object } | null>} null means lost race / row gone -> 409.
     */
    async provisionTenantForApprovedSignup({ signupId, expectedStates, signupPatch, ...payload }) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        // signup_requests has no RLS; app.tenant_id is required by the FORCE-RLS tenant tables.
        await client.query('SELECT set_config($1, $2, true)', ['app.tenant_id', payload.tenant.id]);
        // Claim BEFORE any side effect: taking the signup row lock first makes an overlapping
        // approve fail fast without inserting any tenant/user rows at all.
        // provisioned_tenant_id is deferred to after the inserts because
        // signup_requests.provisioned_tenant_id REFERENCES tenants(id) and that FK is checked
        // immediately — setting it here would violate the constraint.
        const claim = await client.query(
          SIGNUP_UPDATE_SQL,
          signupUpdateParams(
            signupId,
            { ...signupPatch, provisioned_tenant_id: null },
            expectedStates.map(String),
          ),
        );
        if (claim.rowCount === 0) {
          await client.query('ROLLBACK');
          return null;
        }
        await insertTenantProvisioningRows(client, payload);
        const linked = await client.query(
          `UPDATE signup_requests SET provisioned_tenant_id = $2 WHERE id = $1 RETURNING *`,
          [signupId, payload.tenant.id],
        );
        await client.query('COMMIT');
        return { request: mapSignup(linked.rows[0]) };
      } catch (err) {
        try {
          await client.query('ROLLBACK');
        } catch {
          // preserve original error
        }
        throw err;
      } finally {
        client.release();
      }
    },

    async provisionTenantFromSignup(payload) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('SELECT set_config($1, $2, true)', ['app.tenant_id', payload.tenant.id]);
        await insertTenantProvisioningRows(client, payload);
        await client.query('COMMIT');
      } catch (err) {
        // Guard the rollback: a failing ROLLBACK (e.g. dead connection) must not mask the
        // original provisioning error. Matches tenantContext.mjs.
        try {
          await client.query('ROLLBACK');
        } catch {
          // preserve original error
        }
        throw err;
      } finally {
        client.release();
      }
    },

    async appendInternalAudit(entry) {
      const id = entry.id;
      const tenantId = entry.tenant_id ?? null;
      return queryNullableTenant(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO internal_audit_log (
             id, tenant_id, staff_id, staff_role, action, resource_type, resource_id,
             reason, metadata_json, created_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::timestamptz)
           RETURNING *`,
          [
            id,
            tenantId,
            entry.staff_id ?? null,
            entry.staff_role ?? null,
            entry.action,
            entry.resource_type ?? null,
            entry.resource_id ?? null,
            entry.reason ?? null,
            JSON.stringify(entry.metadata ?? {}),
            entry.created_at,
          ],
        );
        return mapInternalAudit(rows[0]);
      });
    },

    async getInternalOverview() {
      // Single platform-scope transaction: all five counts read FORCE-RLS internal tables and
      // returned zeros/undercounts before the platform_scope policies existed.
      const [signups, blocked, approvals, highScale, tenants] = await withPlatformScope(
        pool,
        async (client) => {
          // tenant-query-audit: allow — these are staff-console aggregates ACROSS tenants, which is
          // the whole point of the overview; there is no tenant to scope them to.
          //
          // Safety does not rest on this comment. withPlatformScope() sets app.platform_scope=on and
          // clears app.tenant_id, both transaction-local (set_config(..., true)), so the reads are
          // authorized only by the platform_scope_read_* policies from migration 0038. Those are
          // FOR SELECT only and additionally require app.tenant_id to be unset, so this path cannot
          // write and cannot be reached from an ordinary tenant-scoped transaction.
          const run = async (sql, params = []) => (await client.query(sql, params)).rows;
          return [
            await run(`SELECT count(*)::int AS count FROM signup_requests WHERE state = ANY($1::text[])`, [['submitted', 'under_review', 'approved']]),
            await run(`SELECT count(*)::int AS count FROM tenant_accounts WHERE lifecycle_state = 'suspended'`),
            await run(`SELECT count(*)::int AS count FROM internal_approval_requests WHERE state = ANY($1::text[])`, [['submitted', 'under_review']]),
            await run(`SELECT count(*)::int AS count FROM internal_approval_requests WHERE kind = $1 AND state = ANY($2::text[])`, ['high_scale_validation', ['submitted', 'under_review']]),
            // tenant-query-audit: allow — deliberate cross-tenant staff aggregate (total tenant
            // count for the staff console). It cannot be tenant-filtered by definition. Safety
            // does not rest on this comment: the query runs inside withPlatformScope(), so RLS
            // still governs it via the SELECT-only platform_scope_read_* policies, which require
            // the transaction-local app.platform_scope marker AND an unset app.tenant_id.
            await run(`SELECT count(*)::int AS count FROM tenant_accounts`),
          ];
        },
      );
      return {
        pending_signups: signups[0]?.count ?? 0,
        blocked_tenants: blocked[0]?.count ?? 0,
        pending_approval_requests: approvals[0]?.count ?? 0,
        high_scale_reviews: highScale[0]?.count ?? 0,
        tenant_count: tenants[0]?.count ?? 0,
      };
    },

    async listTenants(query = {}) {
      const q = String(query.q ?? '').trim().toLowerCase();
      const params = [];
      const where = [];
      if (q) {
        params.push(`%${q}%`);
        where.push(`(lower(t.name) LIKE $${params.length} OR lower(t.id) LIKE $${params.length})`);
      }
      // Staff-scope listing across all tenants: tenants/tenant_accounts/tenant_subscriptions/users
      // are FORCE RLS, so this returned zero rows without platform scope.
      const rows = await queryPlatform(
        pool,
        `SELECT t.id, t.name, t.created_at, a.lifecycle_state, a.region, a.support_owner,
                s.plan_id, s.status AS subscription_status,
                (SELECT count(*)::int FROM users u WHERE u.tenant_id = t.id) AS user_count
         FROM tenants t
         LEFT JOIN tenant_accounts a ON a.tenant_id = t.id
         LEFT JOIN tenant_subscriptions s ON s.tenant_id = t.id
         ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
         ORDER BY t.created_at DESC`,
        params,
      );
      return rows.map((row) => ({
        tenant_id: row.id,
        name: row.name,
        created_at: toIso(row.created_at),
        lifecycle_state: row.lifecycle_state ?? 'active',
        region: row.region ?? null,
        plan_id: row.plan_id ?? null,
        subscription_status: row.subscription_status ?? null,
        user_count: row.user_count ?? 0,
        support_owner: row.support_owner ?? null,
      }));
    },

    async getTenantDetail(tenantId) {
      return withTenantContext(pool, tenantId, async (client) => {
        const tenant = await client.query('SELECT * FROM tenants WHERE id = $1', [tenantId]);
        if (!tenant.rows[0]) return null;
        const account = await client.query('SELECT * FROM tenant_accounts WHERE tenant_id = $1', [tenantId]);
        const subscription = await client.query('SELECT * FROM tenant_subscriptions WHERE tenant_id = $1', [tenantId]);
        const grants = await client.query('SELECT * FROM entitlement_grants WHERE tenant_id = $1 ORDER BY feature', [tenantId]);
        const users = await client.query('SELECT * FROM users WHERE tenant_id = $1 ORDER BY created_at', [tenantId]);
        const audit = await client.query(
          `SELECT id, tenant_id, timestamp AS created_at, actor_user_id AS staff_id, actor_role AS staff_role,
                  action, resource_type, resource_id, NULL::text AS reason, metadata_json
           FROM audit_logs
           WHERE tenant_id = $1
           ORDER BY timestamp DESC
           LIMIT 20`,
          [tenantId],
        );
        const signup = await pool.query(
          'SELECT id, state FROM signup_requests WHERE provisioned_tenant_id = $1 LIMIT 1',
          [tenantId],
        );
        return {
          tenant: mapTenant(tenant.rows[0]),
          account: mapTenantAccount(account.rows[0] ?? null),
          subscription: mapSubscription(subscription.rows[0] ?? null, grants.rows.map(mapGrant)),
          users: users.rows.map(mapUser),
          signup_request: signup.rows[0] ? { id: signup.rows[0].id, state: signup.rows[0].state } : null,
          recent_tenant_audit: audit.rows.map(mapInternalAudit),
        };
      });
    },

    async patchTenant(tenantId, body) {
      return withTenantContext(pool, tenantId, async (client) => {
        if (body.name) {
          await client.query('UPDATE tenants SET name = $2 WHERE id = $1', [tenantId, String(body.name).trim()]);
        }
        const current = await client.query('SELECT * FROM tenant_accounts WHERE tenant_id = $1', [tenantId]);
        const existing = mapTenantAccount(current.rows[0] ?? null) ?? { tenant_id: tenantId, region: 'us', lifecycle_state: 'active' };
        const next = { ...existing };
        for (const key of ['legal_name', 'support_owner', 'region', 'lifecycle_state', 'contract_reference']) {
          if (body[key] !== undefined) next[key] = body[key];
        }
        await client.query(
          `INSERT INTO tenant_accounts (
             tenant_id, legal_name, support_owner, region, lifecycle_state, contract_reference, created_at, updated_at
           ) VALUES ($1,$2,$3,$4,$5,$6,NOW(),NOW())
           ON CONFLICT (tenant_id) DO UPDATE SET
             legal_name = EXCLUDED.legal_name,
             support_owner = EXCLUDED.support_owner,
             region = EXCLUDED.region,
             lifecycle_state = EXCLUDED.lifecycle_state,
             contract_reference = EXCLUDED.contract_reference,
             updated_at = NOW()`,
          [
            tenantId,
            next.legal_name ?? null,
            next.support_owner ?? null,
            next.region ?? 'us',
            next.lifecycle_state ?? 'active',
            next.contract_reference ?? null,
          ],
        );
      });
      return this.getTenantDetail(tenantId);
    },

    async getTenantSubscription(tenantId) {
      return withTenantContext(pool, tenantId, async (client) => {
        const subscription = await client.query('SELECT * FROM tenant_subscriptions WHERE tenant_id = $1', [tenantId]);
        const grants = await client.query('SELECT * FROM entitlement_grants WHERE tenant_id = $1 ORDER BY feature', [tenantId]);
        return mapSubscription(subscription.rows[0] ?? null, grants.rows.map(mapGrant));
      });
    },

    async patchTenantSubscription(tenantId, subscription) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE tenant_subscriptions SET
             plan_id = $2,
             status = $3,
             billing_provider_ref = $4,
             effective_at = $5::timestamptz,
             renewal_at = $6::timestamptz,
             limits_json = $7::jsonb,
             feature_entitlements_json = $8::jsonb,
             updated_at = NOW()
           WHERE tenant_id = $1
           RETURNING *`,
          [
            tenantId,
            subscription.plan_id,
            subscription.status,
            subscription.billing_provider_ref,
            subscription.effective_at,
            subscription.renewal_at,
            JSON.stringify(subscription.limits),
            JSON.stringify(subscription.feature_entitlements),
          ],
        );
        const grants = await client.query('SELECT * FROM entitlement_grants WHERE tenant_id = $1 ORDER BY feature', [tenantId]);
        return mapSubscription(rows[0] ?? null, grants.rows.map(mapGrant));
      });
    },

    async upsertEntitlementGrant(tenantId, grant) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO entitlement_grants (
             tenant_id, feature, enabled, limit_value, source, expires_at, created_at, updated_at
           ) VALUES ($1,$2,$3,$4::jsonb,$5,$6::timestamptz,NOW(),NOW())
           ON CONFLICT (tenant_id, feature) DO UPDATE SET
             enabled = EXCLUDED.enabled,
             limit_value = EXCLUDED.limit_value,
             source = EXCLUDED.source,
             expires_at = EXCLUDED.expires_at,
             updated_at = NOW()
           RETURNING *`,
          [
            tenantId,
            grant.feature,
            grant.enabled,
            grant.limit_value == null ? null : JSON.stringify(grant.limit_value),
            grant.source,
            grant.expires_at,
          ],
        );
        return mapGrant(rows[0]);
      });
    },

    async updateUserInvite(tenantId, userId, patch) {
      return withTenantContext(pool, tenantId, async (client) => {
        const existing = await client.query(
          `SELECT * FROM users WHERE tenant_id = $1 AND ($2::text IS NULL OR id = $2) AND role = 'owner' ORDER BY created_at LIMIT 1`,
          [tenantId, userId ?? null],
        );
        if (!existing.rows[0]) return null;
        const user = mapUser(existing.rows[0]);
        const metadata = { ...asObject(existing.rows[0].metadata_json), invited_at: patch.invited_at };
        const { rows } = await client.query(
          `UPDATE users SET status = 'invited', metadata_json = $3::jsonb WHERE tenant_id = $1 AND id = $2 RETURNING *`,
          [tenantId, user.id, JSON.stringify(metadata)],
        );
        return mapUser(rows[0]);
      });
    },

    async disableTenantUser(tenantId, userId, patch) {
      return withTenantContext(pool, tenantId, async (client) => {
        const existing = await client.query('SELECT * FROM users WHERE tenant_id = $1 AND id = $2', [tenantId, userId]);
        if (!existing.rows[0]) return null;
        const metadata = {
          ...asObject(existing.rows[0].metadata_json),
          disabled_at: patch.disabled_at,
          disabled_by: patch.disabled_by,
          disabled_reason: patch.disabled_reason,
        };
        const { rows } = await client.query(
          `UPDATE users SET status = 'disabled', metadata_json = $3::jsonb WHERE tenant_id = $1 AND id = $2 RETURNING *`,
          [tenantId, userId, JSON.stringify(metadata)],
        );
        return mapUser(rows[0]);
      });
    },

    async listApprovalRequests(filters = {}) {
      const params = [];
      const where = [];
      if (filters.state) {
        params.push(filters.state);
        where.push(`state = $${params.length}`);
      }
      if (filters.kind) {
        params.push(filters.kind);
        where.push(`kind = $${params.length}`);
      }
      // Same forced-RLS defect as listInternalAudit. Also required for consistency with
      // getInternalOverview's pending_approval_requests / high_scale_reviews counts, which
      // now see tenant-attributed rows.
      const rows = await queryPlatform(
        pool,
        `SELECT * FROM internal_approval_requests
         ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
         ORDER BY created_at DESC`,
        params,
      );
      return rows.map(mapApproval);
    },

    async decideApprovalRequest(id, patch) {
      // tenant-query-audit: allow — fails CLOSED, not open. Measured against the real 0021 policy as
      // a non-BYPASSRLS role with no tenant context: this UPDATE affects 0 rows for a
      // tenant-attributed approval, and only succeeds for a NULL-tenant one. No cross-tenant write.
      //
      // Why it is not simply wrapped in queryPlatform() the way listInternalAudit is: migration 0038
      // grants platform scope `FOR SELECT` only, so platform scope authorizes no UPDATE at all.
      // A correct fix needs the tenant's own transaction (whose id comes from getApprovalRequest,
      // which has the same visibility limit) or a new platform write policy — a schema change that
      // should be designed deliberately rather than bolted on here.
      //
      // Impact today is latent: no `INSERT INTO internal_approval_requests` exists anywhere in
      // src/, so nothing in the application creates approval rows, tenant-attributed or otherwise.
      // Tracked separately rather than silently half-fixed.
      const { rows } = await pool.query(
        `UPDATE internal_approval_requests SET
           state = $2,
           decision = $3,
           reason = $4,
           reviewer_staff_id = $5,
           decided_at = $6::timestamptz,
           updated_at = $6::timestamptz
         WHERE id = $1 AND state = ANY($7::text[])
         RETURNING *`,
        [id, patch.state, patch.decision, patch.reason, patch.reviewer_staff_id, patch.decided_at, ['submitted', 'under_review']],
      );
      return mapApproval(rows[0] ?? null);
    },

    async getApprovalRequest(id) {
      // tenant-query-audit: allow — lookup by primary key on a bare pool connection. NOT a
      // cross-tenant read: internal_approval_requests is FORCE RLS and its 0021 policy is
      // `tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true)`. Measured against
      // that exact policy as a non-BYPASSRLS role with no tenant context set: only the NULL-tenant
      // row is visible, and a tenant-attributed row is invisible (`tenant_id = NULL` is NULL, not
      // true). So this fails CLOSED.
      //
      // It is however functionally incomplete, and deliberately left that way for now — see the
      // note on decideApprovalRequest below. Fixing this SELECT alone would be WORSE than leaving
      // it: internalManagementServiceAdapters.decideApprovalRequest feeds this row into the UPDATE,
      // which cannot be platform-scoped, then reads `updated.tenant_id` — turning today's silent
      // no-op into a TypeError. The two have to change together.
      const { rows } = await pool.query('SELECT * FROM internal_approval_requests WHERE id = $1', [id]);
      return mapApproval(rows[0] ?? null);
    },

    async listInternalAudit(filters = {}) {
      const params = [];
      const where = [];
      if (filters.tenant_id) {
        params.push(filters.tenant_id);
        where.push(`tenant_id = $${params.length}`);
      }
      if (filters.staff_id) {
        params.push(filters.staff_id);
        where.push(`staff_id = $${params.length}`);
      }
      if (filters.action) {
        params.push(filters.action);
        where.push(`action = $${params.length}`);
      }
      const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 500);
      params.push(limit);
      // Audit integrity: internal_audit_log is FORCE RLS. Without platform scope every
      // tenant-attributed entry was silently dropped, so the staff console showed an
      // incomplete audit trail (only rows with tenant_id IS NULL survived).
      //
      // tenant-query-audit: allow — the staff audit console reads across tenants by design, so
      // there is no tenant_id predicate to add. `tenant_id = $N` above is appended only when the
      // caller passes a filter, and is an optional narrowing, not the isolation control.
      // Safety does not rest on this comment: queryPlatform() runs inside withPlatformScope(),
      // which sets app.platform_scope and clears app.tenant_id, both transaction-local
      // (set_config(..., true)), so RLS still governs the read through the SELECT-only
      // platform_scope_read_* policies and the scope cannot leak onto a pooled connection.
      const rows = await queryPlatform(
        pool,
        `SELECT * FROM internal_audit_log
         ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
         ORDER BY created_at DESC
         LIMIT $${params.length}`,
        params,
      );
      return rows.map(mapInternalAudit);
    },

    async listBreakGlassActivations() {
      // Platform-level table (no tenant_id, no RLS) — see 0041 migration header.
      const rows = await queryPlatform(
        pool,
        `SELECT id, status, reason, ticket_reference, activated_by, activated_role,
                activated_at, expires_at, duration_minutes
         FROM break_glass_activations
         ORDER BY activated_at DESC
         LIMIT 200`,
      );
      return rows.map(mapBreakGlassActivation);
    },

    async saveBreakGlassActivation(activation) {
      // Supersede + insert in ONE transaction so a concurrent activation cannot leave two
      // rows in 'active'. The UPDATE runs first, so the loser of a race supersedes the
      // winner's row only if it commits after it; the partial unique index below is the
      // backstop that rejects a genuinely overlapping second 'active' row.
      return withPlatformScope(pool, async (client) => {
        await client.query(
          `UPDATE break_glass_activations
           SET status = 'superseded'
           WHERE status = 'active' AND id <> $1`,
          [activation.id],
        );
        const { rows } = await client.query(
          `INSERT INTO break_glass_activations (
             id, status, reason, ticket_reference, activated_by, activated_role,
             activated_at, expires_at, duration_minutes
           ) VALUES ($1,$2,$3,$4,$5,$6,$7::timestamptz,$8::timestamptz,$9)
           ON CONFLICT (id) DO NOTHING
           RETURNING id, status, reason, ticket_reference, activated_by, activated_role,
                     activated_at, expires_at, duration_minutes`,
          [
            activation.id,
            activation.status ?? 'active',
            activation.reason ?? null,
            activation.ticket_reference,
            activation.activated_by ?? null,
            activation.activated_role ?? null,
            activation.activated_at,
            activation.expires_at,
            activation.duration_minutes,
          ],
        );
        if (rows[0]) return mapBreakGlassActivation(rows[0]);
        const existing = await client.query(
          `SELECT id, status, reason, ticket_reference, activated_by, activated_role,
                  activated_at, expires_at, duration_minutes
           FROM break_glass_activations
           WHERE id = $1`,
          [activation.id],
        );
        return mapBreakGlassActivation(existing.rows[0]);
      });
    },
  };
}
