#!/usr/bin/env node
/**
 * Seeds .data/astranull-dev.json with the full portal demo fixture.
 * Restart the API after running (in-memory store is loaded at startup).
 */
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { migrateDevStore, writeDevStoreToDisk, clearStoreCacheForTests } from '../src/store.mjs';
import {
  buildPortalDemoStore,
  PORTAL_DEMO_IDS,
} from '../tests/fixtures/portal-demo/seed.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const ISO_INSTANT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

/** The frozen fixture instant is replayed as this far in the past, so demo activity reads as recent. */
const DEMO_ANCHOR_AGE_MS = 2 * 60 * 60 * 1000;
const RUNNING_RUN_AGE_MS = 7 * 60 * 1000;
const AGENT_HEARTBEAT_AGE_MS = 18 * 1000;
const DEMO_AGENT_VERSION = '0.2.0';

/**
 * Collections whose timestamps are shifted onto seed time.
 *
 * Deliberately an allow-list, not an exclude-list: `auditLog` is hash-chained over its
 * own `timestamp`, and `loaSignatures` / `highScaleAuthorizationArtifacts` carry a
 * custody digest computed over `signed_at`. Rewriting a timestamp in any of those
 * invalidates the integrity check that reads it, so a new fixture collection has to be
 * added here on purpose rather than swept in by default.
 */
const REBASED_COLLECTIONS = Object.freeze([
  'agents',
  'agentJobs',
  'probeJobs',
  'testRuns',
  'events',
  'verdicts',
  'findings',
  'reports',
  'notificationEvents',
  'highScaleRequests',
  'highScaleTelemetry',
  'signupRequests',
  'signupQueueEvents',
  'wafValidationRuns',
  'wafScenarioResults',
  'wafPostureSnapshots',
  'wafDriftEvents',
  'wafDriftScanResults',
  'wafActionItems',
  'wafConnectors',
  'wafConnectorSnapshots',
  'cvePipelineItems',
  'cveAssetMatches',
  'discoveryEntities',
  'discoveryCandidates',
  'externalAssetCandidates',
  'supplyChainRisks',
]);

function shiftIsoInstants(value, deltaMs) {
  if (typeof value === 'string') {
    if (!ISO_INSTANT_RE.test(value)) return value;
    const ms = Date.parse(value);
    return Number.isNaN(ms) ? value : new Date(ms + deltaMs).toISOString();
  }
  if (Array.isArray(value)) return value.map((item) => shiftIsoInstants(item, deltaMs));
  if (value && typeof value === 'object') {
    for (const [key, nested] of Object.entries(value)) {
      value[key] = shiftIsoInstants(nested, deltaMs);
    }
  }
  return value;
}

/**
 * Replays the frozen demo fixture at seed time: the dev portal should not open on a
 * "running" run that started 53 days ago next to an agent that is Online with no heartbeat.
 * @param {Record<string, unknown>} store
 * @param {Date} [now]
 */
export function rebaseDemoStoreTimestamps(store, now = new Date()) {
  const frozenMs = Date.parse(PORTAL_DEMO_IDS.frozenAt);
  const deltaMs = now.getTime() - DEMO_ANCHOR_AGE_MS - frozenMs;
  for (const collection of REBASED_COLLECTIONS) {
    if (!Array.isArray(store[collection])) continue;
    store[collection] = shiftIsoInstants(store[collection], deltaMs);
  }

  const agent = store.agents?.find((row) => row.id === PORTAL_DEMO_IDS.agentId);
  if (agent) {
    const heartbeatAt = new Date(now.getTime() - AGENT_HEARTBEAT_AGE_MS).toISOString();
    agent.status = 'online';
    agent.version = DEMO_AGENT_VERSION;
    agent.last_heartbeat_at = heartbeatAt;
    agent.last_token_validation_at = heartbeatAt;
    agent.last_token_validation_status = 'valid';
  }

  const runningRun = store.testRuns?.find((row) => row.status === 'running');
  if (runningRun) {
    const startedAt = new Date(now.getTime() - RUNNING_RUN_AGE_MS).toISOString();
    runningRun.started_at = startedAt;
    runningRun.created_at = startedAt;
  }

  return store;
}

function parseArgs(argv) {
  return { help: argv.includes('--help') || argv.includes('-h') };
}

function main() {
  const { help } = parseArgs(process.argv);
  if (help) {
    console.log(`Usage: node scripts/seed-dev-portal-demo.mjs

Writes the portal demo fixture to .data/astranull-dev.json (overwrites existing dev store).
Restart \`npm run dev:api\` afterward so the control plane reloads the file.

Session defaults (dev-headers):
  x-tenant-id: ${PORTAL_DEMO_IDS.tenantId}
  x-user-id: usr_admin
  x-role: admin

Detail deep-links (append to /app#...):
  target-group-detail?id=${PORTAL_DEMO_IDS.targetGroupId}
  target-detail?id=${PORTAL_DEMO_IDS.targetId}
  agent-detail?id=${PORTAL_DEMO_IDS.agentId}
  run-detail?id=${PORTAL_DEMO_IDS.runId}
  finding-detail?id=${PORTAL_DEMO_IDS.findingId}
  report-detail?id=${PORTAL_DEMO_IDS.reportId}
  environment-detail?id=${PORTAL_DEMO_IDS.environmentId}
  check-detail?id=origin.direct_bypass.safe
  policy-detail?id=${PORTAL_DEMO_IDS.policyId}
  evidence-detail?id=${PORTAL_DEMO_IDS.evidenceId}
  queue-detail?id=${PORTAL_DEMO_IDS.highScaleId}
  tenant-detail?id=${PORTAL_DEMO_IDS.provisionedTenantId}
`);
    return;
  }

  delete process.env.ASTRANULL_NO_PERSIST;
  const store = buildPortalDemoStore();
  rebaseDemoStoreTimestamps(store);
  migrateDevStore(store);
  writeDevStoreToDisk(store);
  clearStoreCacheForTests();

  const counts = {
    tenants: store.tenants.length,
    environments: store.environments.length,
    target_groups: store.targetGroups.length,
    targets: store.targets.length,
    agents: store.agents.length,
    runs: store.testRuns.length,
    findings: store.findings.length,
    reports: store.reports.length,
    notifications_rules: store.notificationRules.length,
    audit: store.auditLog.length,
    signup_requests: store.signupRequests.length,
    high_scale: store.highScaleRequests.length,
    release_evidence: store.productionReleaseEvidence.length,
    waf_connectors: store.wafConnectors.length,
  };

  console.log(`seed-dev-portal-demo: wrote ${path.join(ROOT, '.data', 'astranull-dev.json')}`);
  console.log(`seed-dev-portal-demo: tenant=${PORTAL_DEMO_IDS.tenantId}`);
  for (const [key, value] of Object.entries(counts)) {
    console.log(`  ${key}: ${value}`);
  }
  console.log('seed-dev-portal-demo: restart the API (`npm run dev:api`) then open http://127.0.0.1:5173/app');
}

// Guarded so unit tests can import `rebaseDemoStoreTimestamps` without writing the dev store.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}