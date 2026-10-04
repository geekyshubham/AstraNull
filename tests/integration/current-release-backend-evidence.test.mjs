import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';
import { getEvidenceContext } from '../../src/services/evidenceContext.mjs';
import { createAuditRepository } from '../../src/persistence/postgres/auditRepository.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresValidationServices } from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createProbeJobRepository } from '../../src/persistence/postgres/probeJobRepository.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';

const TENANT = 'ten_ctx';
const OTHER = 'ten_ctx_other';

function seedDev() {
  const capEvents = Array.from({ length: 27 }, (_, index) => ({
    id: index === 26 ? 'evt_extra_25' : `evt_cap_${index}`,
    tenant_id: TENANT,
    test_run_id: 'run_cap',
    target_id: 'tgt_web',
    check_id: 'app.marker.safe',
    metadata: index === 26
      ? {
        method: 'HEAD',
        path: '/primary-last',
        requests_simulated: 2,
        provenance_kind: 'internal_simulation',
        note: 'omitted-event-token-zz',
      }
      : { method: 'GET', path: '/cap-window-only' },
  }));
  capEvents.push({
    id: 'evt_foreign',
    tenant_id: TENANT,
    test_run_id: 'run_cap',
    target_id: 'tgt_web',
    check_id: 'other.check',
    metadata: { method: 'GET', path: '/foreign-secret-zz' },
  });
  resetStoreForTests({
    tenants: [{ id: TENANT, name: 'Ctx' }, { id: OTHER, name: 'Other' }],
    targetGroups: [{ id: 'tg_ctx', tenant_id: TENANT, name: 'Ctx', expected_behavior_default: 'group-current-behavior' }],
    targets: [
      { id: 'tgt_web', tenant_id: TENANT, target_group_id: 'tg_ctx', kind: 'fqdn', value: 'app.example.test', expected_behavior: 'current-target-behavior', created_at: '2026-10-01T00:00:00.000Z' },
      { id: 'tgt_other', tenant_id: OTHER, target_group_id: 'tg_other', kind: 'fqdn', value: 'other.example.test', created_at: '2026-10-01T00:00:00.000Z' },
    ],
    testRuns: [
      { id: 'run_open', tenant_id: TENANT, target_group_id: 'tg_ctx', target_id: 'tgt_web', check_id: 'app.marker.safe', status: 'verdicted', created_at: '2026-10-02T00:00:00.000Z' },
      { id: 'run_later', tenant_id: TENANT, target_group_id: 'tg_ctx', target_id: 'tgt_web', check_id: 'app.marker.safe', status: 'verdicted', created_at: '2026-10-04T00:00:00.000Z' },
      { id: 'run_other_check', tenant_id: TENANT, target_group_id: 'tg_ctx', target_id: 'tgt_web', check_id: 'other.check', status: 'verdicted', created_at: '2026-10-05T00:00:00.000Z' },
      { id: 'run_cap', tenant_id: TENANT, target_group_id: 'tg_ctx', target_id: 'tgt_web', check_id: 'app.marker.safe', status: 'verdicted', expected_behavior: 'immutable-run-behavior', created_at: '2026-10-06T00:00:00.000Z' },
    ],
    verdicts: [
      { id: 'verdict_open', tenant_id: TENANT, test_run_id: 'run_open', target_id: 'tgt_web', check_id: 'app.marker.safe', verdict: 'allowed', explanation: 'origin allowed', evidence_ids: ['ev_original'], expected_behavior: 'block_at_edge', created_at: '2026-10-02T00:00:00.000Z' },
      { id: 'verdict_later', tenant_id: TENANT, test_run_id: 'run_later', target_id: 'tgt_web', check_id: 'app.marker.safe', verdict: 'blocked', evidence_ids: ['ev_later'], created_at: '2026-10-04T00:00:00.000Z' },
      { id: 'verdict_other', tenant_id: TENANT, test_run_id: 'run_other_check', target_id: 'tgt_web', check_id: 'other.check', verdict: 'blocked', evidence_ids: ['ev_other'], created_at: '2026-10-05T00:00:00.000Z' },
      { id: 'verdict_cap', tenant_id: TENANT, test_run_id: 'run_cap', target_id: 'tgt_web', check_id: 'app.marker.safe', verdict: 'allowed', explanation: 'cap', evidence_ids: [], created_at: '2026-10-06T00:00:00.000Z' },
    ],
    findings: [
      {
        id: 'fnd_open',
        tenant_id: TENANT,
        target_group_id: 'tg_ctx',
        target_id: 'tgt_web',
        check_id: 'app.marker.safe',
        test_run_id: 'run_open',
        verdict_id: 'verdict_open',
        last_verdict_id: null,
        title: 'Origin finding',
        severity: 'medium',
        status: 'open',
        notes: 'origin note',
        evidence_ids: ['ev_original'],
        created_at: '2026-10-02T00:00:00.000Z',
      },
      {
        id: 'fnd_other',
        tenant_id: OTHER,
        target_id: 'tgt_other',
        check_id: 'app.marker.safe',
        test_run_id: 'run_other_tenant',
        title: 'Do not leak',
        severity: 'high',
        status: 'open',
        evidence_ids: ['ev_other_tenant'],
        created_at: '2026-10-02T00:00:00.000Z',
      },
      {
        id: 'fnd_cap',
        tenant_id: TENANT,
        target_id: 'tgt_web',
        check_id: 'app.marker.safe',
        test_run_id: 'run_cap',
        verdict_id: 'verdict_cap',
        title: 'Capped primary',
        severity: 'medium',
        status: 'open',
        expected_behavior: 'current-target-behavior',
        evidence_ids: ['ev_cap'],
        created_at: '2026-10-06T00:00:00.000Z',
      },
      {
        id: 'fnd_foreign',
        tenant_id: TENANT,
        target_id: 'tgt_web',
        check_id: 'app.marker.safe',
        test_run_id: 'run_cap',
        verdict_id: 'verdict_cap',
        title: 'Foreign pointer',
        severity: 'low',
        status: 'open',
        evidence_ids: ['ev_foreign'],
        created_at: '2026-10-06T00:00:00.000Z',
      },
    ],
    evidenceVault: [
      {
        id: 'ev_original',
        tenant_id: TENANT,
        test_run_id: 'run_open',
        related_event_id: 'evt_open',
        label: 'marker',
        metadata: {
          sha256: 'digest-original',
          verified_at: '2026-10-04T00:00:00Z',
          verify_method: 'customer_supplied',
        },
        created_at: '2026-10-02T00:00:00.000Z',
      },
      { id: 'ev_later', tenant_id: TENANT, test_run_id: 'run_later', metadata: { sha256: 'digest-later' }, created_at: '2026-10-04T00:00:00.000Z' },
      {
        id: 'ev_cap',
        tenant_id: TENANT,
        test_run_id: 'run_cap',
        related_event_id: 'evt_extra_25',
        metadata: { sha256: 'digest-cap', probe_event_id: 'evt_extra_25' },
        created_at: '2026-10-06T00:00:00.000Z',
      },
      {
        id: 'ev_foreign',
        tenant_id: TENANT,
        test_run_id: 'run_cap',
        related_event_id: 'evt_foreign',
        metadata: { sha256: 'digest-foreign' },
        created_at: '2026-10-06T00:00:00.000Z',
      },
    ],
    events: [
      {
        id: 'evt_open',
        tenant_id: TENANT,
        test_run_id: 'run_open',
        target_id: 'tgt_web',
        check_id: 'app.marker.safe',
        metadata: {
          method: 'GET',
          path: '/health?token=super-secret-query',
          protocol: 'https',
          engine: 'bounded-check',
          status_code: 200,
          external_result: 'allowed',
          cookie: 'session=secret-cookie',
          authorization: 'Bearer abc',
          headers: { cookie: 'session=secret-cookie' },
          body: 'raw-body-secret',
          agent_id: 'agent-should-not-leak',
        },
      },
      {
        id: 'evt_decoy',
        tenant_id: TENANT,
        test_run_id: 'run_open',
        target_id: 'tgt_web',
        check_id: 'app.marker.safe',
        metadata: { method: 'POST', path: '/admin', status_code: 500, external_result: 'blocked' },
      },
      ...capEvents,
    ],
    reports: [
      {
        id: 'rpt_ctx',
        tenant_id: TENANT,
        title: 'Captured',
        status: 'ready',
        kind: 'readiness',
        created_at: '2026-10-01T00:00:00.000Z',
        run_ids: ['run_open'],
        summary: { as_of: '2026-10-01T00:00:00.000Z', evidence_ids: ['ev_original'] },
      },
    ],
    auditLog: [
      {
        id: 'aud_ctx',
        tenant_id: TENANT,
        actor_user_id: 'usr_admin',
        actor_role: 'admin',
        action: 'finding.created',
        resource_type: 'finding',
        resource_id: 'fnd_open',
        timestamp: '2026-10-02T00:00:00.000Z',
        metadata: { authorization: 'Bearer abc', cookie: 'session=secret-cookie' },
      },
    ],
    targetEdgeDetections: [
      {
        id: 'edge_ctx',
        tenant_id: TENANT,
        target_group_id: 'tg_ctx',
        target_id: 'tgt_web',
        test_run_id: 'run_open',
        cdn_status: 'detected',
        cdn_provider: null,
        waf_status: 'detected',
        waf_vendor: 'waf-only-vendor-zz',
        evidence_json: {
          vendor_matches: [{
            vendor: 'waf-only-vendor-zz',
            name: 'waf-fingerprint',
            matched_signals: [
              'Cookie: session=raw-cookie-zz',
              'Authorization: Basic dXNlcjpwYXNz',
              { signal: 'server_header', value: 'Set-Cookie: sid=raw-set-cookie-zz' },
            ],
          }],
          layers: [{
            family: 'waf',
            provider: 'waf-only-vendor-zz',
            sources: ['cname_suffix'],
            matched_signals: ['Set-Cookie: sid=raw-set-cookie-zz', 'Basic dXNlcjpwYXNz'],
          }],
          waf: { addresses: ['not-an-ip', 'Basic dXNlcjpwYXNz'], fingerprints: ['waf-fingerprint'] },
          wafw00f: { firewall: 'waf-fingerprint' },
        },
        observed_at: '2026-10-03T00:00:00.000Z',
      },
    ],
    validationScans: [
      {
        id: 'scan_ctx',
        tenant_id: TENANT,
        status: 'scheduled',
        scheduled_for: '2020-01-01T00:00:00.000Z',
        steps: [],
      },
    ],
    notificationEvents: [],
    evidenceBundles: [],
  });
}

let server;
let baseUrl;

before(() => {
  seedDev();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await closeServer(server);
});

beforeEach(() => {
  seedDev();
});

describe('GET /v1/evidence-context', () => {
  it('returns the originating finding proof and does not mutate or leak secrets', async () => {
    const beforeStore = getStore();
    const runs = beforeStore.testRuns.map((run) => run.status).join(',');
    const scan = beforeStore.validationScans[0].status;
    const audits = beforeStore.auditLog.length;
    const notifications = beforeStore.notificationEvents.length;
    const findings = beforeStore.findings.length;

    const res = await request(baseUrl, 'GET', '/v1/evidence-context?entry=finding&finding_id=fnd_open', {
      headers: demoHeaders('admin', TENANT, 'usr_admin'),
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.entry, 'finding');
    assert.equal(res.json.subject.finding_id, 'fnd_open');
    assert.equal(res.json.subject.check_id, 'app.marker.safe');
    assert.deepEqual(res.json.primary.evidence_ids, ['ev_original']);
    assert.equal(res.json.primary.verdict_id, 'verdict_open');
    assert.equal(res.json.primary.integrity.status, 'recorded_digest');
    assert.equal(res.json.primary.integrity.verified_at, null);
    assert.equal(res.json.primary.integrity.method, null);
    assert.equal(res.json.primary.integrity.refs[0].status, 'recorded_digest');
    assert.equal(res.json.originating.verdict_id, 'verdict_open');
    assert.equal(res.json.latest_distinct, null);
    assert.equal(res.json.latest_same_check.verdict_id, 'verdict_later');
    assert.equal(res.json.latest_same_check.closes_finding, false);
    assert.notEqual(res.json.latest_same_check.verdict_id, 'verdict_other');
    assert.equal(res.json.request_summary.path, '/health');
    assert.equal(res.json.request_summary.method, 'GET');
    assert.equal(res.json.request_summary.event_id, 'evt_open');
    assert.equal(res.json.answer.expected_behavior, 'block_at_edge');
    assert.equal(res.json.answer.expected_behavior_source, 'verdict.expected_behavior');
    assert.equal(res.json.request_summary.request_count.status, 'not_recorded');
    assert.equal(res.json.request_summary.request_count.requests_sent, undefined);
    assert.equal(res.json.response_summary.external_result, 'allowed');
    assert.equal(res.json.response_summary.status_code, 200);
    assert.equal(res.json.evaluation.confidence, 'external_only');
    assert.equal(res.json.truncation.events.returned, 2);
    assert.equal(res.json.truncation.events.truncated, false);
    const blob = JSON.stringify(res.json);
    for (const secret of ['super-secret-query', 'session=secret-cookie', 'raw-body-secret', 'agent-should-not-leak', 'Bearer abc', 'waf-only-vendor-zz', '/admin', 'current-target-behavior', 'group-current-behavior', 'immutable-run-behavior']) {
      assert.equal(blob.includes(secret), false, secret);
    }
    assert.equal(res.json.alternatives.some((item) => item.event_id === 'evt_decoy' && item.relationship === 'unmatched_operation'), true);

    const afterStore = getStore();
    assert.equal(afterStore.testRuns.map((run) => run.status).join(','), runs);
    assert.equal(afterStore.validationScans[0].status, scan);
    assert.equal(afterStore.auditLog.length, audits);
    assert.equal(afterStore.notificationEvents.length, notifications);
    assert.equal(afterStore.findings.length, findings);
    assert.equal(afterStore.findings[0].status, 'open');
  });

  it('keeps report refs, provider families, and denial distinct from not_found', async () => {
    const headers = demoHeaders('admin', TENANT, 'usr_admin');
    const report = await request(baseUrl, 'GET', '/v1/evidence-context?entry=report&report_id=rpt_ctx', { headers });
    assert.equal(report.status, 200);
    assert.deepEqual(report.json.subject.run_ids, ['run_open']);
    assert.equal(report.json.subject.as_of, '2026-10-01T00:00:00.000Z');
    assert.equal(report.json.primary, null);
    assert.equal(report.json.state, 'ready');
    assert.equal(report.json.unavailable_reason, null);
    assert.equal(report.json.alternatives.some((item) => item.relationship === 'report_snapshot_run' && item.test_run_id === 'run_open'), true);
    assert.equal(report.json.alternatives.some((item) => item.relationship === 'report_snapshot_evidence' && item.evidence_id === 'ev_original'), true);
    assert.equal(report.json.latest_distinct, null);
    assert.equal(JSON.stringify(report.json).includes('run_later'), false);

    const cdn = await request(baseUrl, 'GET', '/v1/evidence-context?entry=provider&target_id=tgt_web&family=cdn', { headers });
    assert.equal(cdn.status, 200);
    assert.equal(cdn.json.subject.provider, null);
    assert.equal(cdn.json.subject.status, 'detected');
    assert.equal(cdn.json.primary, null);
    assert.equal(cdn.json.unavailable_reason, 'no_refs');
    assert.equal(JSON.stringify(cdn.json).includes('waf-only-vendor-zz'), false);
    for (const leaked of ['raw-cookie-zz', 'raw-set-cookie-zz', 'dXNlcjpwYXNz', 'not-an-ip']) {
      assert.equal(JSON.stringify(cdn.json).includes(leaked), false, leaked);
    }

    const waf = await request(baseUrl, 'GET', '/v1/evidence-context?entry=provider&target_id=tgt_web&family=waf', { headers });
    assert.equal(waf.status, 200);
    assert.equal(waf.json.subject.provider, 'waf-only-vendor-zz');
    assert.equal(waf.json.subject.proof.fingerprints.includes('waf-fingerprint'), true);
    assert.equal(waf.json.subject.proof.matched_signals.includes('server_header'), true);
    const wafBlob = JSON.stringify(waf.json);
    for (const leaked of ['raw-cookie-zz', 'raw-set-cookie-zz', 'dXNlcjpwYXNz', 'not-an-ip', 'Basic ', 'Cookie:', 'Set-Cookie:']) {
      assert.equal(wafBlob.includes(leaked), false, leaked);
    }

    const capped = await request(baseUrl, 'GET', '/v1/evidence-context?entry=finding&finding_id=fnd_cap', { headers });
    assert.equal(capped.status, 200);
    assert.equal(capped.json.request_summary.event_id, 'evt_extra_25');
    assert.equal(capped.json.request_summary.method, 'HEAD');
    assert.equal(capped.json.request_summary.path, '/primary-last');
    assert.equal(capped.json.request_summary.request_count.requests_simulated, 2);
    assert.equal(capped.json.request_summary.request_count.requests_sent, undefined);
    assert.equal(capped.json.request_summary.provenance.kind, 'internal_simulation');
    assert.equal(capped.json.request_summary.provenance.source_field, 'metadata.provenance_kind');
    assert.equal(capped.json.request_summary.provenance.live_external, false);
    assert.equal(capped.json.answer.expected_behavior, 'immutable-run-behavior');
    assert.equal(capped.json.answer.expected_behavior_source, 'run.expected_behavior');
    assert.equal(capped.json.evaluation.confidence, 'external_only');
    assert.equal(capped.json.truncation.events.truncated, true);
    assert.equal(capped.json.truncation.events.returned, 20);
    assert.equal(capped.json.truncation.events.limit, 20);
    assert.deepEqual(capped.json.truncation.events.referenced_loaded, ['evt_extra_25']);
    assert.deepEqual(capped.json.truncation.events.referenced_missing, []);
    const cappedBlob = JSON.stringify(capped.json);
    for (const leaked of ['/cap-window-only', '/foreign-secret-zz', 'omitted-event-token-zz', 'current-target-behavior', 'group-current-behavior']) {
      assert.equal(cappedBlob.includes(leaked), false, leaked);
    }

    const foreign = await request(baseUrl, 'GET', '/v1/evidence-context?entry=finding&finding_id=fnd_foreign', { headers });
    assert.equal(foreign.status, 200);
    assert.equal(foreign.json.request_summary.status, 'referenced');
    assert.equal(foreign.json.request_summary.ref_status, 'missing');
    assert.equal(foreign.json.request_summary.event_id, 'evt_foreign');
    assert.equal(foreign.json.request_summary.path, undefined);
    const foreignBlob = JSON.stringify(foreign.json);
    assert.equal(foreignBlob.includes('/foreign-secret-zz'), false);
    assert.equal(foreignBlob.includes('/cap-window-only'), false);
    assert.deepEqual(foreign.json.truncation.events.referenced_missing, ['evt_foreign']);

    const origin = await request(baseUrl, 'GET', '/v1/evidence-context?entry=provider&target_id=tgt_web&family=origin_hosting', { headers });
    assert.equal(origin.status, 200);
    assert.equal(origin.json.subject.status, 'unknown');
    assert.equal(origin.json.subject.reason, 'no_origin_hosting_observation');
    assert.equal(origin.json.unavailable_reason, 'no_refs');

    const mismatch = await request(
      baseUrl,
      'GET',
      '/v1/evidence-context?entry=check_result&target_id=tgt_web&check_id=other.check&test_run_id=run_open',
      { headers },
    );
    assert.equal(mismatch.status, 404);
    assert.equal(mismatch.json.error, 'not_found');

    const missing = await request(baseUrl, 'GET', '/v1/evidence-context?entry=finding&finding_id=fnd_other', { headers });
    assert.equal(missing.status, 404);

    const grouped = await request(baseUrl, 'GET', '/v1/evidence-context?entry=group_member&finding_id=fnd_open&group_id=grp_1', { headers });
    assert.equal(grouped.status, 400);
    assert.equal(grouped.json.error, 'group_id_not_supported');

    const denied = await request(baseUrl, 'GET', '/v1/evidence-context?entry=audit&audit_id=aud_ctx', {
      headers: demoHeaders('viewer', TENANT, 'usr_viewer'),
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.json.permission, 'audit:read');

    const audit = await request(baseUrl, 'GET', '/v1/evidence-context?entry=audit&audit_id=aud_ctx', { headers });
    assert.equal(audit.status, 200);
    assert.equal(audit.json.subject.action, 'finding.created');
    assert.equal(audit.json.subject.resource_id, 'fnd_open');
    assert.equal(JSON.stringify(audit.json).includes('Bearer abc'), false);
    assert.equal(JSON.stringify(audit.json).includes('session=secret-cookie'), false);
  });
});

describe('postgres evidence context reads', () => {
  it('resolves the same finding relationship through Postgres services', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason ?? 'postgres harness unavailable');
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await withTenantContext(pool, TENANT, async (client) => {
        await client.query('INSERT INTO tenants (id, name) VALUES ($1, $1)', [TENANT]);
        await client.query(
          'INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, $1)',
          ['env_ctx', TENANT],
        );
        await client.query(
          `INSERT INTO target_groups (id, tenant_id, environment_id, name, expected_behavior_default)
           VALUES ($1, $2, $3, $1, 'group-current-behavior')`,
          ['tg_ctx', TENANT, 'env_ctx'],
        );
        await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, expected_behavior)
           VALUES ('tgt_web', $1, 'tg_ctx', 'fqdn', 'app.example.test', 'app.example.test', 'current-target-behavior')`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO test_runs (id, tenant_id, target_group_id, target_id, check_id, status, created_at)
           VALUES ('run_open', $1, 'tg_ctx', 'tgt_web', 'app.marker.safe', 'verdicted', '2026-10-02T00:00:00.000Z'),
                  ('run_later', $1, 'tg_ctx', 'tgt_web', 'app.marker.safe', 'verdicted', '2026-10-04T00:00:00.000Z')`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO verdicts (id, tenant_id, test_run_id, target_id, check_id, verdict, explanation, evidence_ids, created_at)
           VALUES ('verdict_open', $1, 'run_open', 'tgt_web', 'app.marker.safe', 'allowed', 'origin allowed', ARRAY['ev_original'], '2026-10-02T00:00:00.000Z'),
                  ('verdict_later', $1, 'run_later', 'tgt_web', 'app.marker.safe', 'blocked', 'later', ARRAY['ev_later'], '2026-10-04T00:00:00.000Z')`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO findings (
             id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity, status,
             evidence_ids, verdict_id, notes, created_at
           ) VALUES (
             'fnd_open', $1, 'tg_ctx', 'tgt_web', 'run_open', 'app.marker.safe', 'Origin', 'medium', 'open',
             ARRAY['ev_original'], 'verdict_open', 'origin note', '2026-10-02T00:00:00.000Z'
           )`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO events (id, tenant_id, test_run_id, target_id, check_id, signal_type, producer_kind, timestamp, metadata_json)
           VALUES (
             'evt_open', $1, 'run_open', 'tgt_web', 'app.marker.safe', 'note', 'legacy_untrusted', '2026-10-02T00:00:01.000Z',
             '{"method":"GET","path":"/health?token=super-secret-query","status_code":200,"external_result":"allowed","authorization":"Bearer abc","body":"raw-body-secret"}'::jsonb
           ), (
             'evt_decoy', $1, 'run_open', 'tgt_web', 'app.marker.safe', 'note', 'legacy_untrusted', '2026-10-02T00:00:02.000Z',
             '{"method":"POST","path":"/admin","status_code":500,"external_result":"blocked"}'::jsonb
           )`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO events (id, tenant_id, test_run_id, target_id, check_id, signal_type, producer_kind, timestamp, metadata_json)
           SELECT 'evt_extra_' || g, $1, 'run_open', 'tgt_web', 'app.marker.safe', 'note', 'legacy_untrusted',
                  timestamptz '2026-10-02 00:01:00+00' + make_interval(secs => g),
                  CASE WHEN g = 25 THEN '{"method":"HEAD","path":"/primary-last","requests_simulated":2,"provenance_kind":"internal_simulation","note":"omitted-event-token-zz"}'::jsonb
                       ELSE '{"method":"GET"}'::jsonb END
           FROM generate_series(1, 25) AS g`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO events (id, tenant_id, test_run_id, target_id, check_id, signal_type, producer_kind, timestamp, metadata_json)
           VALUES (
             'evt_foreign', $1, 'run_open', 'tgt_web', 'other.check', 'note', 'legacy_untrusted', '2026-10-02T00:02:00.000Z',
             '{"method":"GET","path":"/foreign-secret-zz"}'::jsonb
           )`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO evidence_vault (id, tenant_id, test_run_id, label, metadata_json, related_event_id, created_at)
           VALUES (
             'ev_original', $1, 'run_open', 'marker',
             '{"sha256":"digest-original","cookie":"session=secret-cookie","verified_at":"2026-10-04T00:00:00Z","verify_method":"customer_supplied"}'::jsonb,
             'evt_open', '2026-10-02T00:00:00.000Z'
           ), (
             'ev_late', $1, 'run_open', 'late',
             '{"sha256":"digest-late","probe_event_id":"evt_extra_25"}'::jsonb,
             'evt_extra_25', '2026-10-02T00:01:25.000Z'
           ), (
             'ev_foreign', $1, 'run_open', 'foreign',
             '{"sha256":"digest-foreign"}'::jsonb,
             'evt_foreign', '2026-10-02T00:02:00.000Z'
           )`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO findings (
             id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity, status,
             evidence_ids, verdict_id, created_at
           ) VALUES (
             'fnd_late', $1, 'tg_ctx', 'tgt_web', 'run_open', 'app.marker.safe', 'Late', 'medium', 'resolved',
             ARRAY['ev_late'], 'verdict_open', '2026-10-02T00:01:25.000Z'
           ), (
             'fnd_foreign', $1, 'tg_ctx', 'tgt_web', 'run_open', 'app.marker.safe', 'Foreign', 'low', 'resolved',
             ARRAY['ev_foreign'], 'verdict_open', '2026-10-02T00:02:00.000Z'
           )`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO audit_logs (id, tenant_id, sequence, entry_hash, action, actor_user_id, actor_role, resource_type, resource_id)
           VALUES ('aud_ctx', $1, 1, 'hash-ctx', 'finding.created', 'usr_admin', 'admin', 'finding', 'fnd_open')`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO target_edge_detections (
             id, tenant_id, target_group_id, target_id, test_run_id, cdn_status, waf_status, waf_vendor, evidence_json, observed_at
           ) VALUES (
             'edge_ctx', $1, 'tg_ctx', 'tgt_web', 'run_open', 'detected', 'detected', 'waf-only-vendor-zz',
             '{"vendor_matches":[{"vendor":"waf-only-vendor-zz","name":"waf-fingerprint","matched_signals":["Cookie: session=raw-cookie-zz","Authorization: Basic dXNlcjpwYXNz",{"signal":"server_header","value":"Set-Cookie: sid=raw-set-cookie-zz"}]}],"layers":[{"family":"waf","provider":"waf-only-vendor-zz","sources":["cname_suffix"],"matched_signals":["Set-Cookie: sid=raw-set-cookie-zz","Basic dXNlcjpwYXNz"]}],"waf":{"addresses":["not-an-ip","Basic dXNlcjpwYXNz"],"fingerprints":["waf-fingerprint"]},"wafw00f":{"firewall":"waf-fingerprint"}}'::jsonb,
             '2026-10-03T00:00:00.000Z'
           )`,
          [TENANT],
        );
      });

      const auditRepo = createAuditRepository(pool);
      const validation = createPostgresValidationServices({
        validationEvidence: createValidationEvidenceRepository(pool),
        audit: auditRepo,
        coreCatalog: createCoreCatalogRepository(pool),
        probeJobs: createProbeJobRepository(pool),
        killSwitch: createKillSwitchRepository(pool),
      });
      const deps = {
        ...validation,
        audit: auditRepo,
        persistenceMode: 'postgres',
        targetDetail: {
          async getTargetDetail(ctx, id) {
            return withTenantContext(pool, ctx.tenantId, async (client) => {
              const { rows } = await client.query(
                'SELECT id, tenant_id, kind, value FROM targets WHERE tenant_id = $1 AND id = $2',
                [ctx.tenantId, id],
              );
              if (!rows[0]) return { error: 'not_found', status: 404, target: null };
              return { target: rows[0] };
            });
          },
        },
      };
      const pgCtx = { tenantId: TENANT, userId: 'usr_pg', role: 'admin' };
      const finding = await getEvidenceContext(pgCtx, { entry: 'finding', finding_id: 'fnd_open' }, deps);
      assert.equal(finding.status, 200);
      assert.deepEqual(finding.body.primary.evidence_ids, ['ev_original']);
      assert.equal(finding.body.primary.integrity.status, 'recorded_digest');
      assert.equal(finding.body.primary.integrity.verified_at, null);
      assert.equal(finding.body.primary.integrity.method, null);
      assert.equal(finding.body.latest_distinct, null);
      assert.equal(finding.body.latest_same_check.verdict_id, 'verdict_later');
      assert.equal(finding.body.latest_same_check.closes_finding, false);
      assert.equal(finding.body.request_summary.path, '/health');
      assert.equal(finding.body.request_summary.method, 'GET');
      assert.equal(finding.body.request_summary.event_id, 'evt_open');
      assert.equal(finding.body.request_summary.request_count.status, 'not_recorded');
      assert.equal(finding.body.request_summary.request_count.requests_sent, undefined);
      assert.equal(finding.body.answer.expected_behavior, null);
      assert.equal(finding.body.answer.expected_behavior_source, null);
      assert.equal(finding.body.response_summary.status_code, 200);
      assert.equal(finding.body.truncation.events.truncated, true);
      assert.equal(finding.body.truncation.events.returned, 20);
      assert.equal(finding.body.truncation.events.limit, 20);
      assert.equal(finding.body.truncation.events.source_count, null);
      const blob = JSON.stringify(finding.body);
      for (const secret of ['super-secret-query', 'session=secret-cookie', 'raw-body-secret', 'Bearer abc', 'omitted-event-token-zz', '/admin', 'current-target-behavior', 'group-current-behavior', '/primary-last', '/foreign-secret-zz']) {
        assert.equal(blob.includes(secret), false, secret);
      }
      const boundedEvents = await deps.testRuns.getRunEvents(pgCtx, 'run_open', { limit: 5 });
      assert.equal(boundedEvents.length, 5);
      const widerEvents = await deps.testRuns.getRunEvents(pgCtx, 'run_open', { limit: 100 });
      assert.equal(widerEvents.length, 28);
      const exactEvent = await deps.testRuns.getRunEvents(pgCtx, 'run_open', {
        ids: ['evt_extra_25'],
        target_id: 'tgt_web',
        check_id: 'app.marker.safe',
      });
      assert.equal(exactEvent.length, 1);
      assert.equal(exactEvent[0].id, 'evt_extra_25');
      assert.equal(exactEvent[0].metadata.method, 'HEAD');
      const hiddenForeign = await deps.testRuns.getRunEvents(pgCtx, 'run_open', {
        ids: ['evt_foreign'],
        target_id: 'tgt_web',
        check_id: 'app.marker.safe',
      });
      assert.equal(hiddenForeign.length, 0);
      const emptyLookup = await deps.testRuns.getRunEvents(pgCtx, 'run_open', { ids: [] });
      assert.deepEqual(emptyLookup, []);

      const cdn = await getEvidenceContext(pgCtx, { entry: 'provider', target_id: 'tgt_web', family: 'cdn' }, deps);
      assert.equal(cdn.status, 200);
      assert.equal(cdn.body.subject.provider, null);
      assert.equal(cdn.body.primary, null);
      assert.equal(cdn.body.unavailable_reason, 'no_refs');
      assert.equal(JSON.stringify(cdn.body).includes('waf-only-vendor-zz'), false);
      for (const leaked of ['raw-cookie-zz', 'raw-set-cookie-zz', 'dXNlcjpwYXNz', 'not-an-ip']) {
        assert.equal(JSON.stringify(cdn.body).includes(leaked), false, leaked);
      }
      const waf = await getEvidenceContext(pgCtx, { entry: 'provider', target_id: 'tgt_web', family: 'waf' }, deps);
      assert.equal(waf.status, 200);
      assert.equal(waf.body.subject.provider, 'waf-only-vendor-zz');
      assert.equal(waf.body.subject.proof.fingerprints.includes('waf-fingerprint'), true);
      assert.equal(waf.body.subject.proof.matched_signals.includes('server_header'), true);
      const wafBlob = JSON.stringify(waf.body);
      for (const leaked of ['raw-cookie-zz', 'raw-set-cookie-zz', 'dXNlcjpwYXNz', 'not-an-ip', 'Basic ', 'Cookie:', 'Set-Cookie:']) {
        assert.equal(wafBlob.includes(leaked), false, leaked);
      }

      const late = await getEvidenceContext(pgCtx, { entry: 'finding', finding_id: 'fnd_late' }, deps);
      assert.equal(late.status, 200);
      assert.equal(late.body.request_summary.event_id, 'evt_extra_25');
      assert.equal(late.body.request_summary.method, 'HEAD');
      assert.equal(late.body.request_summary.path, '/primary-last');
      assert.equal(late.body.request_summary.request_count.status, 'recorded');
      assert.equal(late.body.request_summary.request_count.requests_simulated, 2);
      assert.equal(late.body.request_summary.request_count.requests_sent, undefined);
      assert.equal(late.body.request_summary.provenance.kind, 'internal_simulation');
      assert.equal(late.body.request_summary.provenance.source_field, 'metadata.provenance_kind');
      assert.equal(late.body.request_summary.provenance.live_external, false);
      assert.equal(late.body.evaluation.confidence, 'external_only');
      assert.equal(late.body.answer.expected_behavior, null);
      assert.equal(late.body.answer.expected_behavior_source, null);
      assert.equal(late.body.truncation.events.truncated, true);
      assert.equal(late.body.truncation.events.returned, 20);
      assert.equal(late.body.truncation.events.limit, 20);
      assert.equal(late.body.truncation.events.source_count, null);
      assert.equal(late.body.truncation.events.referenced_event_ids.includes('evt_extra_25'), true);
      assert.equal(late.body.truncation.events.referenced_loaded.includes('evt_extra_25'), true);
      assert.equal(late.body.truncation.events.referenced_missing.includes('evt_extra_25'), false);
      const lateBlob = JSON.stringify(late.body);
      for (const leaked of ['omitted-event-token-zz', '/foreign-secret-zz', 'current-target-behavior', 'group-current-behavior', '/admin']) {
        assert.equal(lateBlob.includes(leaked), false, leaked);
      }

      const foreign = await getEvidenceContext(pgCtx, { entry: 'finding', finding_id: 'fnd_foreign' }, deps);
      assert.equal(foreign.status, 200);
      assert.equal(foreign.body.request_summary.status, 'referenced');
      assert.equal(foreign.body.request_summary.ref_status, 'missing');
      assert.equal(foreign.body.request_summary.event_id, 'evt_foreign');
      assert.equal(foreign.body.request_summary.path, undefined);
      const foreignBlob = JSON.stringify(foreign.body);
      assert.equal(foreignBlob.includes('/foreign-secret-zz'), false);
      assert.equal(foreignBlob.includes('/health'), false);
      assert.equal(foreign.body.truncation.events.referenced_missing.includes('evt_foreign'), true);
      assert.equal(foreign.body.truncation.events.referenced_loaded.includes('evt_foreign'), false);

      const audit = await getEvidenceContext(pgCtx, { entry: 'audit', audit_id: 'aud_ctx' }, deps);
      assert.equal(audit.status, 200);
      assert.equal(audit.body.subject.action, 'finding.created');
      assert.equal(audit.body.subject.resource_id, 'fnd_open');

      const hidden = await getEvidenceContext(
        { tenantId: OTHER, userId: 'usr_pg', role: 'admin' },
        { entry: 'finding', finding_id: 'fnd_open' },
        deps,
      );
      assert.equal(hidden.status, 404);
    }, availability.env ?? process.env);
  });
});
