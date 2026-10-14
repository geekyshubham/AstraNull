#!/usr/bin/env node
/**
 * Seeds .data/astranull-dev.json with the full portal demo fixture.
 * Restart the API after running (in-memory store is loaded at startup).
 */
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { migrateDevStore, writeDevStoreToDisk, clearStoreCacheForTests, resolveDataFile } from '../src/store.mjs';
import {
  buildPortalDemoStore,
  PORTAL_DEMO_IDS,
} from '../tests/fixtures/portal-demo/seed.mjs';
import { getCheckById } from '../src/contracts/checks.mjs';
import { approvedScenarioVersion, deriveRunEvidenceStamp } from '../src/lib/checkDefinitionVersion.mjs';
import { deriveAssuranceScope } from '../src/lib/assuranceScope.mjs';


const ISO_INSTANT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

/** The frozen fixture instant is replayed as this far in the past, so demo activity reads as recent. */
const DEMO_ANCHOR_AGE_MS = 2 * 60 * 60 * 1000;
const RUNNING_RUN_AGE_MS = 7 * 60 * 1000;

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
 * "running" run that started 53 days ago.
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

  const runningRun = store.testRuns?.find((row) => row.status === 'running');
  if (runningRun) {
    const startedAt = new Date(now.getTime() - RUNNING_RUN_AGE_MS).toISOString();
    runningRun.started_at = startedAt;
    runningRun.created_at = startedAt;
  }

  return store;
}

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

// Synthetic control declarations for the demo checkout target; documentation ranges only.
export const DEMO_CONTROL_DECLARATIONS = Object.freeze({
  version: 1,
  network_policy: [
    { protocol: 'tcp', port: 22, action: 'deny', address_family: 'any', note: 'SSH only through the bastion' },
    { protocol: 'tcp', port: 3389, action: 'deny', address_family: 'any' },
    { protocol: 'tcp', port: 443, action: 'allow', address_family: 'any' },
    { protocol: 'tcp', port: 5900, action: 'deny', address_family: 'any', note: 'Remote desktop (VNC)' },
  ],
  waf: {
    block_signature: { header_name: 'x-edge-block', header_value: 'denied', status_codes: [403] },
    expected_action: 'block',
  },
  origin: { lockdown_expected: true },
  perspectives: { allowlisted_perspective_ids: ['default'], denied_perspective_ids: [] },
  updated_by: 'usr_admin',
});

const GRADING = { grading_version: 'waf-grading.v2', signature_corpus_version: 'waf-signatures.2026-10-13.2' };
const PREVIOUS_GRADING = { grading_version: 'waf-grading.v2', signature_corpus_version: 'waf-signatures.2026-09-01.1' };
const UNAUTHENTICATED_PERSPECTIVE = { source_perspective: { id: 'default', label: 'Primary' }, claimed_perspective_id: 'default', perspective_authenticated: false };

function markerMetadata({ markerClass, scope, placements, trailing = 'allowed', enforcement = 'enforced', sourcePenalized = false, grading = GRADING, responseFeatures = null, baseline = null }) {
  const graded = placements.filter((row) => row.outcome !== 'inconclusive').length;
  const resolvedBaseline = baseline ?? (responseFeatures ? {
    placement: 'baseline',
    status_code: 200,
    header_subset: { 'content-type': 'text/html' },
    body_length_bucket: 'lt_8kb',
    signature_id: null,
  } : null);
  return {
    probe_kind: 'waf_class_marker_probe',
    classifier_version: 'marker-comparison-v4',
    assurance_scope: scope,
    marker_class: markerClass,
    marker_inert: true,
    planned_marker_legs: graded,
    completed_marker_legs: graded,
    comparison_complete: !sourcePenalized,
    baseline_health: 'healthy',
    permitted_baseline_health: 'healthy',
    observation_only: sourcePenalized,
    readiness_conclusion: !sourcePenalized,
    cache_buster: true,
    source_penalized: sourcePenalized,
    trailing_control: { outcome: trailing, status_code: trailing === 'allowed' ? 200 : 403 },
    leg_order: placements.map((row) => row.placement),
    placements: placements.map((row) => ({ signature_id: null, cache_status: 'DYNAMIC', location_changed: false, ...row })),
    enforcement,
    posture_status: sourcePenalized ? 'source_penalized' : enforcement === 'enforced' ? 'blocked_all' : enforcement === 'partial' ? 'blocked_partial' : 'allowed_all',
    requests_sent: placements.length + 2,
    safety_attestation: { requests_sent: placements.length + 2 },
    external_result: sourcePenalized ? 'inconclusive' : enforcement === 'enforced' ? 'blocked' : 'allowed',
    ...(responseFeatures ? { response_features: responseFeatures } : {}),
    ...(resolvedBaseline ? { baseline: resolvedBaseline } : {}),
    ...grading,
  };
}

const allowedFeature = (placement) => ({ placement, status_code: 200, header_subset: { 'content-type': 'text/html' }, body_bytes: 2048 });

const blocked = (placement) => ({ placement, outcome: 'blocked', status_code: 403, signature_id: 'declared:x-edge-block' });
const allowed = (placement) => ({ placement, outcome: 'allowed', status_code: 200 });

// Synthetic WAF/NFW evidence on the demo checkout target so every new portal state renders locally.
export function addWafNfwDemoEvidence(store, ids = PORTAL_DEMO_IDS) {
  const frozenMs = Date.parse(ids.frozenAt);
  const target = (store.targets ?? []).find((row) => row.id === ids.targetId);
  if (!target) return store;
  target.metadata = {
    ...(target.metadata ?? {}),
    control_declarations: { ...DEMO_CONTROL_DECLARATIONS, updated_at: new Date(frozenMs - 3 * HOUR_MS).toISOString() },
  };
  const runs = [
    { checkId: 'waf.sqli_managed_marker.safe', verdict: 'protected', offsetMs: 10 * 60 * 1000, metadata: markerMetadata({ markerClass: 'sqli', scope: 'managed_rule_marker', placements: [blocked('query'), blocked('path'), blocked('header')] }), explanation: 'Every graded placement of the managed SQL injection marker was blocked with your declared block header.' },
    { checkId: 'waf.xss_managed_marker.safe', verdict: 'protected', offsetMs: 12 * 60 * 1000, metadata: markerMetadata({ markerClass: 'xss', scope: 'managed_rule_marker', placements: [blocked('query'), blocked('path'), blocked('header')] }), explanation: 'Every graded placement of the managed cross-site scripting marker was blocked.' },
    { checkId: 'waf.path_traversal_managed_marker.safe', verdict: 'exposed', offsetMs: 14 * 60 * 1000, metadata: markerMetadata({ markerClass: 'path_traversal', scope: 'managed_rule_marker', enforcement: 'partial', placements: [allowed('query'), blocked('path'), { placement: 'header', outcome: 'challenged', status_code: 403, signature_id: 'cloudflare_managed_challenge' }] }), explanation: 'The query-string placement reached the application; a challenge on the header placement does not count as a block.' },
    { checkId: 'waf.scanner_signature_marker.safe', verdict: 'inconclusive', offsetMs: 16 * 60 * 1000, metadata: markerMetadata({ markerClass: 'scanner_user_agent', scope: 'managed_rule_marker', enforcement: 'unknown', sourcePenalized: true, trailing: 'blocked', placements: [blocked('user_agent')] }), explanation: 'The follow-up control request was refused too, so the probe source was penalized and the marker result is not trusted.' },
    { checkId: 'waf.ssrf_marker.safe', verdict: 'protected', offsetMs: 18 * 60 * 1000, metadata: markerMetadata({ markerClass: 'ssrf', scope: 'custom_canary_rule', placements: [blocked('query'), blocked('path'), blocked('header')] }), explanation: 'Your custom rule for the AstraNull canary token blocked every placement.' },
    { checkId: 'waf.xxe_marker.safe', verdict: 'protected', offsetMs: 20 * 60 * 1000, metadata: markerMetadata({ markerClass: 'xxe', scope: 'custom_canary_rule', placements: [blocked('query'), blocked('path'), blocked('header')] }), explanation: 'Your custom rule for the AstraNull canary token blocked every placement.' },
    { checkId: 'waf.crlf_injection_marker.safe', verdict: 'exposed', offsetMs: 22 * 60 * 1000, metadata: markerMetadata({ markerClass: 'crlf', scope: 'custom_canary_rule', enforcement: 'not_enforced', placements: [allowed('query'), allowed('path'), allowed('header')], responseFeatures: [allowedFeature('query'), allowedFeature('path'), allowedFeature('header')] }), explanation: 'No custom rule acted on the CRLF canary token.' },
    { checkId: 'waf.nosql_injection_marker.safe', verdict: 'protected', offsetMs: -35 * DAY_MS, metadata: markerMetadata({ markerClass: 'nosql', scope: 'custom_canary_rule', placements: [blocked('query'), blocked('path'), blocked('header')] }), explanation: 'Recorded 35 days ago; outside the coverage freshness window.' },
    { checkId: 'waf.evasion_double_url.safe', verdict: 'exposed', offsetMs: 24 * 60 * 1000, metadata: { probe_kind: 'waf_evasion_marker_probe', classifier_version: 'marker-comparison-v4', planned_marker_legs: 2, completed_marker_legs: 2, comparison_complete: true, permitted_baseline_health: 'healthy', transform: 'double_url', reference_outcome: 'blocked', transform_outcome: 'allowed', normalization_gap: true, reference_not_enforced: false, source_penalized: false, trailing_control: { outcome: 'allowed', status_code: 200 }, cache_buster: true, leg_order: ['reference', 'transform'], requests_sent: 4, safety_attestation: { requests_sent: 4 }, external_result: 'allowed', ...GRADING }, explanation: 'The plain marker was blocked but the double-URL-encoded marker reached the application.' },
    { checkId: 'waf.evasion_mixed_url.safe', verdict: 'protected', offsetMs: 26 * 60 * 1000, metadata: { probe_kind: 'waf_evasion_marker_probe', classifier_version: 'marker-comparison-v4', planned_marker_legs: 2, completed_marker_legs: 2, comparison_complete: true, permitted_baseline_health: 'healthy', enforcement: 'enforced', transform: 'mixed_url', reference_outcome: 'blocked', transform_outcome: 'blocked', normalization_gap: false, reference_not_enforced: false, source_penalized: false, trailing_control: { outcome: 'allowed', status_code: 200 }, cache_buster: true, requests_sent: 4, safety_attestation: { requests_sent: 4 }, external_result: 'blocked', ...GRADING }, explanation: 'Both the plain and mixed-URL-encoded markers were blocked.' },
    {
      checkId: 'nfw.declared_deny_tcp.safe',
      verdict: 'exposed',
      offsetMs: 30 * 60 * 1000,
      metadata: {
        probe_kind: 'tcp_connect', protocol: 'tcp', port: 22, address: '192.0.2.10', address_family: 4, tcp_outcome: 'handshake', icmp: null, service_validated: true, peer_is_cdn: false,
        families: { ipv4: { address: '192.0.2.10', tcp_outcome: 'handshake' }, ipv6: { address: '2001:db8::10', tcp_outcome: 'rejected_icmp' } },
        parity: 'mismatch', samples: [{ tcp_outcome: 'handshake' }, { tcp_outcome: 'handshake' }], sample_agreement: 'agree',
        port_results: [
          { protocol: 'tcp', port: 22, address: '192.0.2.10', address_family: 4, tcp_outcome: 'handshake', icmp: null, service_validated: true, peer_is_cdn: false, families: { ipv4: { address: '192.0.2.10', tcp_outcome: 'handshake' }, ipv6: { address: '2001:db8::10', tcp_outcome: 'rejected_icmp' } }, parity: 'mismatch', sample_agreement: 'agree' },
          { protocol: 'tcp', port: 3389, address: '192.0.2.10', address_family: 4, tcp_outcome: 'timeout', icmp: null, service_validated: false, peer_is_cdn: false, families: { ipv4: { address: '192.0.2.10', tcp_outcome: 'timeout' }, ipv6: { address: '2001:db8::10', tcp_outcome: 'timeout' } }, parity: 'match', sample_agreement: 'agree' },
        ],
        declared_deny_ports: [22, 3389, 5900],
        ports_probed: [22, 3389],
        unprobed_deny_ports: [5900],
        ...UNAUTHENTICATED_PERSPECTIVE,
        requests_sent: 2, safety_attestation: { requests_sent: 2 }, external_result: 'connected',
      },
      verdictExtra: {
        port_results: [
          { protocol: 'tcp', port: 22, outcome: 'handshake', result: 'violated', severity: 'high', explanation: 'TCP 22 is declared denied, yet a non-CDN address completed the handshake.' },
          { protocol: 'tcp', port: 3389, outcome: 'timeout', result: 'no_violation_observed', severity: null, explanation: null },
        ],
      },
      explanation: 'TCP 22 is declared denied, yet a non-CDN address completed the handshake over IPv4. IPv6 was rejected, so the two families differ.',
    },
    { checkId: 'waf.open_redirect_marker.safe', verdict: 'protected', offsetMs: 28 * 60 * 1000, metadata: markerMetadata({ markerClass: 'open_redirect', scope: 'custom_canary_rule', placements: [blocked('query'), blocked('path'), blocked('header')], grading: PREVIOUS_GRADING }), runExtra: PREVIOUS_GRADING, verdictExtra: PREVIOUS_GRADING, explanation: 'Your custom rule blocked the marker in the query, path and header, graded with the previous signature corpus.' },
    {
      checkId: 'nfw.declared_deny_tcp.safe',
      verdict: 'inconclusive',
      offsetMs: -26 * HOUR_MS,
      metadata: {
        probe_kind: 'tcp_connect', protocol: 'tcp', port: 3389, address: '192.0.2.10', address_family: 4, tcp_outcome: 'timeout', icmp: null, service_validated: false, peer_is_cdn: false,
        families: { ipv4: { address: '192.0.2.10', tcp_outcome: 'timeout' }, ipv6: { address: '2001:db8::10', tcp_outcome: 'timeout' } },
        parity: 'match', samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }], sample_agreement: 'agree',
        port_results: [
          { protocol: 'tcp', port: 3389, address: '192.0.2.10', address_family: 4, tcp_outcome: 'timeout', icmp: null, service_validated: false, peer_is_cdn: false, families: { ipv4: { address: '192.0.2.10', tcp_outcome: 'timeout' }, ipv6: { address: '2001:db8::10', tcp_outcome: 'timeout' } }, parity: 'match', sample_agreement: 'agree', samples: [{ tcp_outcome: 'timeout' }, { tcp_outcome: 'timeout' }] },
        ],
        declared_deny_ports: [3389],
        ports_probed: [3389],
        unprobed_deny_ports: [],
        source_perspective: { id: 'default', label: 'Primary' }, claimed_perspective_id: 'default', perspective_authenticated: true,
        requests_sent: 2, safety_attestation: { requests_sent: 2 }, external_result: 'timeout',
      },
      verdictExtra: {
        port_results: [{ protocol: 'tcp', port: 3389, outcome: 'timeout', result: 'no_violation_observed', severity: null, explanation: null }],
      },
      explanation: 'TCP 3389 gave no reply in two agreeing samples from the same perspective. Silence from outside cannot prove the port is denied; it only shows the earlier violation did not reproduce.',
    },
  ];
  store.testRuns ??= [];
  store.verdicts ??= [];
  store.events ??= [];
  // The readiness fixture's assured runs for these checks would otherwise be newer than this evidence.
  const seededRunIds = new Set(runs.map((entry) => `run_portal_assurance_${ids.targetId}_${entry.checkId}`));
  store.testRuns = store.testRuns.filter((run) => !seededRunIds.has(run.id));
  store.events = store.events.filter((event) => !seededRunIds.has(event.test_run_id));
  store.verdicts = store.verdicts.filter((verdict) => !seededRunIds.has(verdict.test_run_id));
  const group = (store.targetGroups ?? []).find((row) => row.id === target.target_group_id) ?? null;
  for (const [index, entry] of runs.entries()) {
    const check = getCheckById(entry.checkId);
    if (!check) continue;
    const startedAt = new Date(frozenMs + entry.offsetMs).toISOString();
    const completedAt = new Date(frozenMs + entry.offsetMs + 20_000).toISOString();
    const runId = `run_wafnfw_${index + 1}`;
    const nonce = `nonce_wafnfw_${index + 1}`;
    const eventId = `evt_wafnfw_${index + 1}`;
    const stamp = deriveRunEvidenceStamp(check, undefined, { probeMode: 'signed-worker', scenarioVersion: approvedScenarioVersion(check) });
    const version = { check_version: stamp.check_version };
    store.testRuns.push({
      id: runId,
      tenant_id: ids.tenantId,
      target_group_id: ids.targetGroupId,
      target_id: ids.targetId,
      check_id: entry.checkId,
      vector_family: check.vector_family,
      status: 'verdicted',
      created_at: startedAt,
      started_at: startedAt,
      completed_at: completedAt,
      ...stamp,
      correlation: { nonce_hash: nonce },
      safety_constraints: { assurance_scope: deriveAssuranceScope({ target, policy: null, targetGroup: group }) },
      validation_mode: 'external_only',
      ...(entry.runExtra ?? {}),
    });
    store.events.push({
      id: eventId,
      event_id: `probe:${eventId}`,
      tenant_id: ids.tenantId,
      test_run_id: runId,
      target_id: ids.targetId,
      check_id: entry.checkId,
      source: 'probe_worker',
      signal_type: 'probe_result',
      producer_kind: 'signed_probe',
      nonce_hash: nonce,
      timestamp: completedAt,
      ingested_at: completedAt,
      metadata: { ...entry.metadata, check_version: version.check_version, scenario_version: approvedScenarioVersion(check) },
    });
    store.verdicts.push({
      id: `vrd_wafnfw_${index + 1}`,
      tenant_id: ids.tenantId,
      test_run_id: runId,
      target_id: ids.targetId,
      check_id: entry.checkId,
      verdict: entry.verdict,
      explanation: entry.explanation,
      evidence_ids: [eventId],
      check_version: version.check_version,
      scenario_version: approvedScenarioVersion(check),
      created_at: completedAt,
      finalized_at: completedAt,
      ...(entry.verdictExtra ?? {}),
    });
  }
  store.findings ??= [];
  const finding = (id, extra) => ({
    id,
    tenant_id: ids.tenantId,
    target_group_id: ids.targetGroupId,
    target_id: ids.targetId,
    owner_group: 'edge-sre',
    opened_at: new Date(frozenMs - 2 * DAY_MS).toISOString(),
    created_at: new Date(frozenMs - 2 * DAY_MS).toISOString(),
    ...extra,
  });
  store.findings.push(
    finding('fnd_wafnfw_deny_22', { check_id: 'nfw.declared_deny_tcp.safe', test_run_id: 'run_wafnfw_11', evidence_ids: ['evt_wafnfw_11'], severity: 's2', title: 'Declared-denied TCP 22 answered from the internet', state: 'open', status: 'open' }),
    finding('fnd_wafnfw_double_url', { check_id: 'waf.evasion_double_url.safe', test_run_id: 'run_wafnfw_9', evidence_ids: ['evt_wafnfw_9'], severity: 's3', title: 'Normalization gap: double URL encoding bypassed the SQL injection rule', state: 'open', status: 'open' }),
    finding('fnd_wafnfw_xss_fixed', { check_id: 'waf.xss_managed_marker.safe', test_run_id: 'run_wafnfw_2', severity: 's3', title: 'Managed XSS marker reached the application', state: 'fix_verified', status: 'fix_verified', verifying_run_id: 'run_wafnfw_2', verification_basis: 'passing_retest', closed_at: new Date(frozenMs + 13 * 60 * 1000).toISOString() }),
    finding('fnd_wafnfw_deny_3389_fixed', { check_id: 'nfw.declared_deny_tcp.safe', test_run_id: 'run_wafnfw_13', evidence_ids: ['evt_wafnfw_13'], severity: 's2', title: 'Declared-denied TCP 3389 answered from the internet', state: 'fix_verified', status: 'fix_verified', verifying_run_id: 'run_wafnfw_13', verification_basis: 'violation_not_reproduced', closed_at: new Date(frozenMs - 26 * HOUR_MS + 30_000).toISOString() }),
    finding('fnd_wafnfw_crlf_accepted', { check_id: 'waf.crlf_injection_marker.safe', test_run_id: 'run_wafnfw_7', evidence_ids: ['evt_wafnfw_7'], severity: 's4', title: 'No custom rule acts on the CRLF canary token', state: 'accepted_risk', status: 'accepted_risk', risk_acceptance: { reason: 'Responses never echo headers on this service; tracked for the next WAF rule review.', review_at: new Date(frozenMs + 60 * DAY_MS).toISOString(), accepted_by: 'usr_owner', accepted_at: new Date(frozenMs - DAY_MS).toISOString() } }),
  );
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
  run-detail?id=${PORTAL_DEMO_IDS.runId}
  finding-detail?id=${PORTAL_DEMO_IDS.findingId}
  report-detail?id=${PORTAL_DEMO_IDS.reportId}
  check-detail?id=origin.direct_bypass.safe
  policy-detail?id=${PORTAL_DEMO_IDS.policyId}
  evidence-detail?id=${PORTAL_DEMO_IDS.evidenceId}
  queue-detail?id=${PORTAL_DEMO_IDS.highScaleId}
  tenant-detail?id=${PORTAL_DEMO_IDS.provisionedTenantId}
`);
    return;
  }

  delete process.env.ASTRANULL_NO_PERSIST;
  const store = buildPortalDemoStore({ readinessObservedAt: PORTAL_DEMO_IDS.frozenAt });
  addWafNfwDemoEvidence(store);
  rebaseDemoStoreTimestamps(store);
  migrateDevStore(store);
  writeDevStoreToDisk(store);
  clearStoreCacheForTests();

  const counts = {
    tenants: store.tenants.length,
    target_groups: store.targetGroups.length,
    targets: store.targets.length,
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

  console.log(`seed-dev-portal-demo: wrote ${resolveDataFile()}`);
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