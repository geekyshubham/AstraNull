import { CHECK_CATALOG } from './contracts/checks.mjs';
import { buildDefaultEntitlementGrants, buildDefaultSubscription } from './contracts/subscriptions.mjs';
import { getStore, migrateDevStore, persistStore } from './store.mjs';

const DEMO_TENANT_ID = 'ten_demo';
const DEMO_ENV_ID = 'env_demo';
const DEMO_TARGET_GROUP_ID = 'tg_demo_origin';
const DEMO_TARGET_ID = 'tgt_demo_1';

function resolveDemoTargetGroup(store) {
  return (
    store.targetGroups.find(
      (entry) => entry.id === DEMO_TARGET_GROUP_ID && entry.tenant_id === DEMO_TENANT_ID,
    )
    ?? store.targetGroups.find((entry) => entry.tenant_id === DEMO_TENANT_ID)
  );
}

function resolveDemoTarget(store, targetGroupId) {
  return (
    store.targets.find(
      (entry) => entry.id === DEMO_TARGET_ID && entry.target_group_id === targetGroupId,
    )
    ?? store.targets.find((entry) => entry.target_group_id === targetGroupId)
  );
}

function ensureDemoSubscription(store) {
  const tenant = store.tenants.find((entry) => entry.id === DEMO_TENANT_ID);
  if (!tenant) return;

  if (!Array.isArray(store.tenantAccounts)) store.tenantAccounts = [];
  if (!store.tenantAccounts.some((account) => account.tenant_id === DEMO_TENANT_ID)) {
    store.tenantAccounts.push({
      tenant_id: DEMO_TENANT_ID,
      legal_name: tenant.name,
      support_owner: 'ops@demo.astranull.local',
      region: 'us',
      lifecycle_state: 'active',
      contract_reference: 'DEMO-CONTRACT-001',
      created_at: new Date().toISOString(),
    });
  }

  if (!Array.isArray(store.tenantSubscriptions)) store.tenantSubscriptions = [];
  if (!store.tenantSubscriptions.some((subscription) => subscription.tenant_id === DEMO_TENANT_ID)) {
    store.tenantSubscriptions.push(buildDefaultSubscription('professional', DEMO_TENANT_ID));
  }

  if (!Array.isArray(store.entitlementGrants)) store.entitlementGrants = [];
  if (!store.entitlementGrants.some((grant) => grant.tenant_id === DEMO_TENANT_ID)) {
    store.entitlementGrants.push(...buildDefaultEntitlementGrants('professional', DEMO_TENANT_ID));
  }
}

function ensureDemoDetailFixtures(store) {
  const tenant = store.tenants.find((entry) => entry.id === DEMO_TENANT_ID);
  const targetGroup = resolveDemoTargetGroup(store);
  if (!tenant || !targetGroup) return;

  ensureDemoSubscription(store);

  const target = resolveDemoTarget(store, targetGroup.id);
  const targetId = target?.id ?? DEMO_TARGET_ID;
  const now = new Date().toISOString();

  if (!store.agents.some((agent) => agent.tenant_id === DEMO_TENANT_ID)) {
    store.agents.push({
      id: 'agent_demo',
      tenant_id: DEMO_TENANT_ID,
      name: 'demo-agent',
      hostname: 'demo-host.astranull.local',
      target_group_id: targetGroup.id,
      environment_id: targetGroup.environment_id ?? DEMO_ENV_ID,
      status: 'online',
      capabilities: ['heartbeat', 'canary'],
      last_heartbeat_at: now,
      created_at: now,
      updated_at: now,
      version: '0.1.0-demo',
    });
  }

  if (!store.testRuns.some((run) => run.tenant_id === DEMO_TENANT_ID)) {
    const runId = 'run_demo';
    store.testRuns.push({
      id: runId,
      tenant_id: DEMO_TENANT_ID,
      target_group_id: targetGroup.id,
      target_id: targetId,
      check_id: 'origin.direct_bypass.safe',
      vector_family: 'origin_bypass',
      safety_class: 'safe',
      status: 'verdicted',
      created_at: now,
      started_at: now,
      completed_at: now,
      updated_at: now,
      created_by: 'usr_admin',
      correlation: { nonce_hash: 'demo_nonce_hash', window_ms: 120000 },
    });
    store.verdicts.push({
      id: 'evidence_demo',
      tenant_id: DEMO_TENANT_ID,
      test_run_id: runId,
      target_id: targetId,
      check_id: 'origin.direct_bypass.safe',
      verdict: 'protected',
      confidence: 0.82,
      placement_confidence: {
        level: 'medium',
        status: 'evidence_backed',
        score: 72,
      },
      explanation: 'Demo verdict seeded for workspace detail surfaces.',
      evidence_ids: [],
      severity: 'medium',
      created_at: now,
      conclusion: 'Protection observed before origin in demo seed.',
      external_result: { summary: 'Outside probe saw edge block behavior.' },
      internal_result: { summary: 'Agent did not observe origin penetration.' },
    });
  }
}

export function seedIfEmpty() {
  const store = getStore();
  if (migrateDevStore(store)) {
    persistStore();
  }
  if (store.tenants.length > 0) {
    ensureDemoSubscription(store);
    ensureDemoDetailFixtures(store);
    persistStore();
    return;
  }

  const tenantId = DEMO_TENANT_ID;
  const envId = DEMO_ENV_ID;
  store.tenants.push({
    id: tenantId,
    name: 'Demo Organization',
    created_at: new Date().toISOString(),
    privacy_settings: {
      store_packet_payloads: false,
      metadata_retention_days: 90,
      redact_headers_by_default: true,
    },
  });
  store.environments.push({
    id: envId,
    tenant_id: tenantId,
    name: 'Production Validation',
    created_at: new Date().toISOString(),
  });
  store.users.push({
    id: 'usr_admin',
    tenant_id: tenantId,
    email: 'admin@demo.astranull.local',
    role: 'admin',
    name: 'Demo Admin',
  });
  store.users.push({
    id: 'usr_soc',
    tenant_id: tenantId,
    email: 'soc@demo.astranull.local',
    role: 'soc',
    name: 'Demo SOC',
  });

  const tgId = DEMO_TARGET_GROUP_ID;
  store.targetGroups.push({
    id: tgId,
    tenant_id: tenantId,
    environment_id: envId,
    name: 'Origin Protection Group',
    description: 'Customer-declared origin targets for bypass validation.',
    expected_behavior_default: 'must_block_before_origin',
    created_at: new Date().toISOString(),
  });
  store.targets.push({
    id: DEMO_TARGET_ID,
    tenant_id: tenantId,
    target_group_id: tgId,
    kind: 'fqdn',
    value: 'origin.demo.customer.example',
    expected_behavior: 'must_block_before_origin',
    created_at: new Date().toISOString(),
  });

  store.checkCatalog = CHECK_CATALOG.map((c) => ({ ...c }));
  store.readiness[tenantId] = {
    score: 42,
    factors: [],
    updated_at: new Date().toISOString(),
  };

  ensureDemoDetailFixtures(store);
  persistStore();
}