import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  POSTGRES_SUBSCRIPTION_SERVICE_METHODS,
  createPostgresSubscriptionServices,
} from '../../src/persistence/postgres/serviceAdapters.mjs';
import { getSubscriptionPlan } from '../../src/contracts/subscriptions.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/subscriptionServiceAdapters.mjs'),
  'utf8',
);

const NOW = new Date('2026-01-01T12:00:00.000Z');
const nowFn = () => NOW;

function createRecordingRepositories(overrides = {}) {
  const calls = [];
  const record = (method) => async (...args) => {
    calls.push({ method, args });
    const fn = overrides[method];
    return typeof fn === 'function' ? fn(...args) : fn;
  };

  const repositories = {
    internalManagement: {
      getTenantDetail: record('getTenantDetail'),
    },
    coreCatalog: {
      listTargetGroups: record('listTargetGroups'),
    },
    agentControl: {
      listAgents: record('listAgents'),
    },
    validationEvidence: {
      listTestRuns: record('listTestRuns'),
      listFindings: record('listFindings'),
    },
    highScale: {
      listHighScaleRequests: record('listHighScaleRequests'),
    },
  };

  return { repositories, calls };
}

function defaultDetail(tenantId) {
  return {
    tenant: { id: tenantId, name: 'Tenant X' },
    account: {
      tenant_id: tenantId,
      support_owner: 'staff_owner',
      region: 'eu',
      lifecycle_state: 'active',
    },
    subscription: {
      tenant_id: tenantId,
      plan_id: 'professional',
      status: 'active',
      billing_provider_ref: null,
      effective_at: '2026-01-01T00:00:00.000Z',
      renewal_at: null,
      limits: { users: 25 },
      feature_entitlements: {
        waf_posture: true,
        external_discovery: false,
        connectors: false,
        high_scale_program: true,
      },
      entitlement_grants: [
        { tenant_id: tenantId, feature: 'connectors', enabled: true, source: 'staff_override' },
      ],
    },
    users: [{ id: 'u1' }, { id: 'u2' }],
    recent_tenant_audit: [
      {
        id: 'aud_1',
        action: 'target_group.created',
        staff_role: 'admin',
        resource_type: 'target_group',
        resource_id: 'tg_1',
        created_at: '2026-01-01T11:00:00.000Z',
      },
      {
        id: 'aud_2',
        action: 'agent.registered',
        staff_role: 'admin',
        resource_type: 'agent',
        resource_id: 'ag_1',
        created_at: '2026-01-01T10:00:00.000Z',
      },
    ],
  };
}

function overridesFor(tenantId) {
  return {
    getTenantDetail: (id) => (id === tenantId ? defaultDetail(tenantId) : null),
    listTargetGroups: () => [{ id: 'g1' }, { id: 'g2' }, { id: 'g3' }],
    listAgents: () => [{ id: 'ag1', tenant_id: tenantId }],
    listTestRuns: () => [
      { id: 'r1', tenant_id: tenantId, started_at: '2026-01-01T11:30:00.000Z' },
      { id: 'r2', tenant_id: tenantId, started_at: null, created_at: '2026-01-01T11:59:00.000Z' },
      { id: 'r3', tenant_id: tenantId, started_at: '2026-01-01T10:00:00.000Z' },
    ],
    listFindings: () => [
      { id: 'f1', tenant_id: tenantId, status: 'open' },
      { id: 'f2', tenant_id: tenantId, status: 'closed' },
      { id: 'f3', tenant_id: tenantId, status: 'triaged' },
    ],
    listHighScaleRequests: () => [
      { id: 'hs1', tenant_id: tenantId, state: 'submitted' },
      { id: 'hs2', tenant_id: tenantId, state: 'closed' },
      { id: 'hs3', tenant_id: 'other_tenant', state: 'submitted' },
    ],
  };
}

describe('postgres subscription service adapter', () => {
  it('exposes a stable service method list', () => {
    assert.deepEqual(POSTGRES_SUBSCRIPTION_SERVICE_METHODS, ['getCurrentSubscriptionSummary']);
  });

  it('never reads the dev getStore() path', () => {
    assert.equal(/getStore/.test(ADAPTER_SOURCE), false);
    assert.equal(/from '\.\.\/\.\.\/store\.mjs'/.test(ADAPTER_SOURCE), false);
  });

  it('fails early when a required repository is missing', () => {
    assert.throws(
      () => createPostgresSubscriptionServices({}),
      /requires repositories\.internalManagement/,
    );
    assert.throws(
      () =>
        createPostgresSubscriptionServices({
          internalManagement: { getTenantDetail: () => null },
        }),
      /requires repositories\.coreCatalog/,
    );
  });

  it('fails early when a required repository method is missing', () => {
    const { repositories } = createRecordingRepositories();
    delete repositories.validationEvidence.listFindings;
    assert.throws(
      () => createPostgresSubscriptionServices(repositories),
      /requires validationEvidence\.listFindings\(\)/,
    );
  });

  it('computes the summary shape and counts from Postgres repositories', async () => {
    const tenantId = 'ten_x';
    const { repositories, calls } = createRecordingRepositories(overridesFor(tenantId));
    const service = createPostgresSubscriptionServices(repositories, { now: nowFn });

    const ctx = { tenantId, userId: 'usr_admin', role: 'admin' };
    const summary = await service.getCurrentSubscriptionSummary(ctx);

    // Top-level shape
    assert.deepEqual(Object.keys(summary).sort(), [
      'account',
      'plan',
      'subscription',
      'support',
      'tenant_id',
      'usage',
    ]);
    assert.equal(summary.tenant_id, tenantId);
    assert.equal(summary.account.support_owner, 'staff_owner');

    // Subscription + effective entitlements (grant flips connectors on)
    assert.equal(summary.subscription.plan_id, 'professional');
    assert.equal(summary.subscription.effective_entitlements.connectors, true);
    assert.equal(summary.subscription.effective_entitlements.waf_posture, true);
    assert.deepEqual(summary.plan, getSubscriptionPlan('professional'));

    // Usage counts
    assert.deepEqual(summary.usage, {
      users: 2,
      target_groups: 3,
      agents: 1,
      safe_runs_started_last_hour: 2,
      open_findings: 2,
      pending_high_scale_requests: 1,
      audit_events: 2,
    });

    // Support block
    assert.equal(summary.support.owner, 'staff_owner');
    assert.equal(summary.support.lifecycle_state, 'active');
    assert.equal(summary.support.region, 'eu');
    assert.equal(summary.support.escalation_state, 'soc_review_pending');
    assert.equal(summary.support.recent_audit.length, 2);
    // mapInternalAudit renames actor_role -> staff_role; summary restores actor_role.
    assert.equal(summary.support.recent_audit[0].actor_role, 'admin');
    assert.deepEqual(Object.keys(summary.support.recent_audit[0]).sort(), [
      'action',
      'actor_role',
      'created_at',
      'id',
      'resource_id',
      'resource_type',
    ]);

    // Tenant scoping: detail keyed by tenantId, repo reads receive tenant ctx.
    const detailCall = calls.find((c) => c.method === 'getTenantDetail');
    assert.deepEqual(detailCall.args, [tenantId]);
    for (const method of ['listTargetGroups', 'listAgents', 'listTestRuns', 'listFindings', 'listHighScaleRequests']) {
      const call = calls.find((c) => c.method === method);
      assert.equal(call.args[0].tenantId, tenantId);
    }
  });

  it('escalates to customer_review when only findings are open', async () => {
    const tenantId = 'ten_y';
    const overrides = overridesFor(tenantId);
    overrides.listHighScaleRequests = () => [];
    const { repositories } = createRecordingRepositories(overrides);
    const service = createPostgresSubscriptionServices(repositories, { now: nowFn });

    const summary = await service.getCurrentSubscriptionSummary({ tenantId });
    assert.equal(summary.usage.pending_high_scale_requests, 0);
    assert.equal(summary.support.escalation_state, 'customer_review');
  });

  it('falls back to a default subscription when the tenant has no subscription row', async () => {
    const tenantId = 'ten_z';
    const overrides = overridesFor(tenantId);
    overrides.getTenantDetail = (id) => ({
      ...defaultDetail(id),
      subscription: null,
      account: null,
      users: [],
      recent_tenant_audit: [],
    });
    const { repositories } = createRecordingRepositories(overrides);
    const service = createPostgresSubscriptionServices(repositories, { now: nowFn });

    const summary = await service.getCurrentSubscriptionSummary({ tenantId });
    assert.equal(summary.subscription.plan_id, 'starter');
    assert.equal(summary.subscription.tenant_id, tenantId);
    assert.ok(summary.subscription.effective_entitlements);
    assert.deepEqual(summary.plan, getSubscriptionPlan('starter'));
    assert.equal(summary.support.owner, null);
    assert.equal(summary.support.lifecycle_state, 'unrecorded');
    assert.equal(summary.usage.users, 0);
    assert.equal(summary.usage.audit_events, 0);
  });

  it('returns an empty summary without hitting repositories when no tenant is present', async () => {
    const { repositories, calls } = createRecordingRepositories(overridesFor('ten_x'));
    const service = createPostgresSubscriptionServices(repositories, { now: nowFn });

    const summary = await service.getCurrentSubscriptionSummary({});
    assert.equal(summary.tenant_id, null);
    assert.equal(summary.subscription, null);
    assert.equal(summary.plan, null);
    assert.equal(summary.usage.users, 0);
    assert.equal(summary.support.escalation_state, 'nominal');
    assert.equal(calls.length, 0);
  });
});
