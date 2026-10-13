import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  AUTHORIZATION_ARTIFACT_CATALOG,
  GOVERNED_HIGH_SCALE_SCENARIOS,
  REQUIRED_AUTHORIZATION_ARTIFACT_TYPES,
  authorizationArtifactTypesForRequest,
  buildLifecycleTimeline,
  buildMetadataArtifactUploadBody,
  defaultScheduleWindow,
  explainArtifactReviewStatus,
  governedLimitDisplay,
  killSwitchActiveForTenant,
  orderedArtifactsForType,
  providerApprovalRequired,
  requestDomainDisplay,
  scheduledWindowState,
  scheduleWindowErrors,
  summarizeAuthorizationPackProgress
} from '../../apps/web/react/src/lib/high-scale.ts';

describe('high-scale react helpers', () => {
  it('covers every required authorization template artifact type', () => {
    const catalogTypes = AUTHORIZATION_ARTIFACT_CATALOG
      .filter((entry) => entry.artifact_type !== 'provider_approval')
      .map((entry) => entry.artifact_type);
    assert.deepEqual(catalogTypes, [...REQUIRED_AUTHORIZATION_ARTIFACT_TYPES]);
  });

  it('describes UDP authorization with exact governed IDs and numeric limit units', () => {
    const udp = GOVERNED_HIGH_SCALE_SCENARIOS.find((scenario) => scenario.id === 'udp_flood');
    assert.ok(udp);
    assert.equal(udp.limit.field, 'max_gbps');
    assert.equal(udp.limit.unit, 'Gbps');
    assert.deepEqual(udp.deliveryPatterns.map((pattern) => pattern.id), ['direct', 'spoofed']);
  });

  it('builds lifecycle timeline only from audit_trail entries', () => {
    const timeline = buildLifecycleTimeline({
      state: 'submitted',
      audit_trail: [
        { action: 'approve', at: '2026-01-02T00:00:00.000Z', by: 'soc_a' },
        { action: 'submitted', at: '2026-01-01T00:00:00.000Z', by: 'engineer' }
      ]
    });
    assert.equal(timeline.length, 2);
    assert.equal(timeline[0].action, 'submitted');
    assert.equal(timeline[1].action, 'approve');
  });

  it('does not invent lifecycle steps when audit_trail is empty', () => {
    assert.deepEqual(buildLifecycleTimeline({ state: 'submitted', audit_trail: [] }), []);
  });

  it('includes provider approval only when provider context requires it', () => {
    const withoutProvider = authorizationArtifactTypesForRequest({
      provider_context: { provider_name: '', requires_provider_approval: false }
    });
    assert.equal(withoutProvider.includes('provider_approval'), false);

    const withProvider = authorizationArtifactTypesForRequest({
      provider_context: { provider_name: 'Cloudflare', requires_provider_approval: true }
    });
    assert.equal(withProvider.includes('provider_approval'), true);
    assert.equal(providerApprovalRequired({ provider_context: { provider_name: 'AWS' } }), true);
  });

  it('explains artifact review status from pack requirement and artifact review state', () => {
    const pending = explainArtifactReviewStatus('test_plan', { status: 'pending_review' }, {
      status: 'pending_review',
      type: 'test_plan'
    });
    assert.match(pending, /awaiting SOC review/i);

    const rejected = explainArtifactReviewStatus('legal_approval', { status: 'rejected' }, {
      status: 'rejected',
      review_notes: 'Missing legal reviewer signature reference'
    });
    assert.match(rejected, /rejected/i);
    assert.match(rejected, /signature reference/i);
  });

  it('builds metadata-only artifact upload bodies from request context', () => {
    const body = buildMetadataArtifactUploadBody({
      id: 'hs_1',
      tenant_id: 'tenant_1',
      target_ids: ['tgt_1'],
      scope_hash: 'scope_hash_1',
      requested_window: {
        window_start: '2026-01-01T00:00:00.000Z',
        window_end: '2026-01-02T00:00:00.000Z'
      },
      requested_scenario_families: ['udp_flood'],
      delivery_patterns: ['direct'],
      requested_limits: { max_gbps: 0.5, max_duration_minutes: 45 },
      emergency_contacts: [{ name: 'On-call', contact: 'ops@example.invalid' }],
      abort_criteria: { threshold: 'error_rate_above_5pct', auto_stop: true },
      provider_context: { provider_name: 'Cloudflare' }
    }, 'provider_approval', {
      filename: 'provider-approval.json',
      content_sha256: 'a'.repeat(64),
      custody_id: 'cust_customer_ref'
    });

    assert.equal(body.type, 'provider_approval');
    assert.equal(body.filename, 'provider-approval.json');
    assert.equal(body.content_sha256, 'a'.repeat(64));
    assert.equal(body.custody_uri, 'custody://cust_customer_ref');
    assert.equal(body.provider_name, 'Cloudflare');
    assert.deepEqual(body.approved_scenario_families, ['udp_flood']);
    assert.deepEqual(body.approved_delivery_patterns, ['direct']);
    assert.deepEqual(body.approved_limits, { max_gbps: 0.5, max_duration_minutes: 45 });
    assert.equal(Object.hasOwn(body, 'max_rate'), false);
    assert.deepEqual(body.authorization_binding, {
      tenant_id: 'tenant_1',
      target_ids: ['tgt_1'],
      scope_hash: 'scope_hash_1',
      requested_window: {
        window_start: '2026-01-01T00:00:00.000Z',
        window_end: '2026-01-02T00:00:00.000Z'
      },
      approved_schedule_window: {
        window_start: '2026-01-01T00:00:00.000Z',
        window_end: '2026-01-02T00:00:00.000Z'
      },
      delivery_patterns: ['direct']
    });
    assert.equal(body.reference_uri, 'metadata://high-scale/provider_approval/hs_1');
  });

  it('does not invent scenario, pattern, or numeric limit authorization defaults', () => {
    const body = buildMetadataArtifactUploadBody({ id: 'hs_empty' }, 'test_plan', {
      filename: 'test-plan.json',
      content_sha256: 'b'.repeat(64)
    });

    assert.deepEqual(body.approved_scenario_families, []);
    assert.deepEqual(body.approved_delivery_patterns, []);
    assert.deepEqual(body.approved_limits, {});
    assert.equal(Object.hasOwn(body, 'max_duration_minutes'), false);
  });

  it('keeps customer high-scale surfaces free of SOC execution endpoints', () => {
    // Security invariant: customer runs SOC-gate panel and queue detail must not
    // call SOC-only execution endpoints. SOC execution lives on staff surfaces.
    const runsSocGate = readFileSync(new URL('../../apps/web/react/src/components/runs/runs-soc-gate.tsx', import.meta.url), 'utf8');
    assert.equal(runsSocGate.includes('/internal/soc/high-scale/'), false);
    assert.ok(runsSocGate.includes("buildDetailHref('queue-detail'"));
    assert.ok(runsSocGate.includes('/v1/high-scale-requests'));

    const detailSource = readFileSync(new URL('../../apps/web/react/src/pages/detail-pages.tsx', import.meta.url), 'utf8');
    const customerStart = detailSource.indexOf('function HighScaleDetailView(');
    const customerEnd = detailSource.indexOf('function SocRequestDetailView(', customerStart);
    const customerDetailView = customerStart >= 0 && customerEnd > customerStart
      ? detailSource.slice(customerStart, customerEnd)
      : '';
    assert.ok(customerDetailView.length > 0, 'HighScaleDetailView should retain customer authorization-pack helpers');
    assert.equal(customerDetailView.includes('/internal/soc/high-scale/'), false);
    assert.ok(customerDetailView.includes('buildLifecycleTimeline'));
    assert.ok(customerDetailView.includes('explainArtifactReviewStatus'));
    assert.ok(customerDetailView.includes('authorizationArtifactTypesForRequest'));
    assert.ok(customerDetailView.includes('buildMetadataArtifactUploadBody'));
    assert.ok(customerDetailView.includes('/v1/high-scale-requests/'));
    assert.ok(customerDetailView.includes('custody_id'));
    assert.ok(customerDetailView.includes('content_sha256'));
    assert.ok(customerDetailView.includes('filename'));

    const staffStart = detailSource.indexOf('function SocRequestDetailView(');
    assert.ok(staffStart >= 0, 'SocRequestDetailView should exist for queue-detail staff workspace');
    assert.ok(detailSource.includes("'queue-detail'"));
  });
});
describe('high-scale schedule window helpers', () => {
  const NOW = Date.parse('2026-05-10T12:00:00.000Z');
  const request = (window, artifacts = []) => ({ requested_window: window, artifacts });
  const requested = { window_start: '2026-05-10T00:00:00.000Z', window_end: '2026-05-11T00:00:00.000Z', timezone: 'Europe/Berlin' };

  it('defaults to the customer-requested window with the start clamped to now', () => {
    assert.deepEqual(defaultScheduleWindow(request(requested), NOW), {
      window_start: '2026-05-10T12:00:00.000Z',
      window_end: '2026-05-11T00:00:00.000Z',
      timezone: 'Europe/Berlin'
    });
    const future = { window_start: '2026-06-01T08:00:00.000Z', window_end: '2026-06-01T10:00:00.000Z' };
    assert.deepEqual(defaultScheduleWindow(request(future), NOW), { ...future, timezone: 'UTC' });
  });

  it('never defaults to a window the authorization letter does not cover', () => {
    const letter = { type: 'customer_authorization_letter', status: 'accepted', valid_window: { window_start: '2026-05-10T14:00:00.000Z', window_end: '2026-05-10T18:00:00.000Z' } };
    assert.deepEqual(defaultScheduleWindow(request(requested, [letter]), NOW), {
      window_start: '2026-05-10T14:00:00.000Z',
      window_end: '2026-05-10T18:00:00.000Z',
      timezone: 'Europe/Berlin'
    });
  });

  it('offers no default when the requested window is missing or already ended', () => {
    assert.equal(defaultScheduleWindow({}, NOW), null);
    assert.equal(defaultScheduleWindow(request({ window_start: '2026-04-01T00:00:00.000Z', window_end: '2026-04-02T00:00:00.000Z' }), NOW), null);
  });

  it('accepts a draft inside the requested window', () => {
    assert.deepEqual(scheduleWindowErrors(request(requested), { window_start: '2026-05-10T13:00:00.000Z', window_end: '2026-05-10T15:00:00.000Z' }, NOW), []);
  });

  it('rejects unparseable, inverted, ended, and out-of-window drafts with field details', () => {
    const fields = (draft, req = request(requested)) => scheduleWindowErrors(req, draft, NOW).map((entry) => entry.field);
    assert.deepEqual(fields({ window_start: '', window_end: 'not a date' }), ['window_start', 'window_end']);
    assert.deepEqual(fields({ window_start: '2026-05-10T15:00:00.000Z', window_end: '2026-05-10T14:00:00.000Z' }), ['window_end']);
    assert.ok(fields({ window_start: '2026-05-10T01:00:00.000Z', window_end: '2026-05-10T02:00:00.000Z' }).includes('window_end'));
    assert.deepEqual(fields({ window_start: '2026-05-09T23:00:00.000Z', window_end: '2026-05-11T01:00:00.000Z' }), ['window_start', 'window_end']);
    const letter = { type: 'customer_authorization_letter', status: 'accepted', valid_window: { window_start: '2026-05-10T14:00:00.000Z', window_end: '2026-05-10T18:00:00.000Z' } };
    const outsideLetter = scheduleWindowErrors(request(requested, [letter]), { window_start: '2026-05-10T13:00:00.000Z', window_end: '2026-05-10T19:00:00.000Z' }, NOW);
    assert.ok(outsideLetter.some((entry) => /authorization letter becomes valid/.test(entry.message)));
    assert.ok(outsideLetter.some((entry) => /authorization letter expires/.test(entry.message)));
    assert.ok(scheduleWindowErrors({}, { window_start: '2026-05-10T13:00:00.000Z', window_end: '2026-05-10T15:00:00.000Z' }, NOW)
      .some((entry) => /customer-requested window is not recorded/.test(entry.message)));
  });

  it('classifies a scheduled window like the server (inclusive at both ends)', () => {
    const start = '2026-05-10T10:00:00.000Z';
    const end = '2026-05-10T14:00:00.000Z';
    assert.equal(scheduledWindowState(start, end, Date.parse(start)), 'open');
    assert.equal(scheduledWindowState(start, end, Date.parse(end)), 'open');
    assert.equal(scheduledWindowState(start, end, Date.parse(start) - 1), 'upcoming');
    assert.equal(scheduledWindowState(start, end, Date.parse(end) + 1), 'expired');
    assert.equal(scheduledWindowState('', end, NOW), 'unscheduled');
    assert.equal(scheduledWindowState(end, start, NOW), 'unscheduled');
  });

  it('reads a seeded July window as expired months later, never as a confirmed safe window', () => {
    assert.equal(scheduledWindowState('2026-07-14T08:00:00.000Z', '2026-07-14T10:00:00.000Z', Date.parse('2026-10-13T00:00:00.000Z')), 'expired');
  });
});

describe('high-scale governed scope helpers', () => {
  const data = {
    targets: [
      { id: 'tgt_1', value: 'checkout.example.com', target_group_id: 'tg_1' },
      { id: 'tgt_2', value: 'api.example.com', target_group_id: 'tg_1' },
      { id: 'tgt_3', value: 'old.example.com', target_group_id: 'tg_1', deleted_at: '2026-01-01T00:00:00.000Z' }
    ]
  };

  it('lists explicit target IDs first, resolving each to its declared domain', () => {
    assert.deepEqual(requestDomainDisplay(data, { target_ids: ['tgt_2', 'tgt_unknown'], target_id: 'tgt_1' }), ['api.example.com', 'tgt_unknown']);
  });

  it('uses the single target_id when no list is recorded', () => {
    assert.deepEqual(requestDomainDisplay(data, { target_id: 'tgt_1' }), ['checkout.example.com']);
  });

  it('falls back to the active members of the recorded target_group_id', () => {
    assert.deepEqual(requestDomainDisplay(data, { target_group_id: 'tg_1' }), ['checkout.example.com', 'api.example.com']);
  });

  it('returns no domains when no scope is recorded', () => {
    assert.deepEqual(requestDomainDisplay(data, {}), []);
    assert.deepEqual(requestDomainDisplay(null, { target_group_id: 'tg_1' }), []);
  });

  it('formats the recorded rate cap and duration for the requested scenario', () => {
    assert.equal(governedLimitDisplay({ requested_scenario_families: ['syn_flood'], requested_limits: { max_cps: 25000, max_duration_minutes: 30 } }), '25,000 connections/second · 30 min');
  });

  it('shows every recorded limit when no known scenario matches, and a dash when nothing is recorded', () => {
    assert.equal(governedLimitDisplay({ requested_scenario_families: ['custom'], requested_limits: { max_gbps: 2, max_rps: 900 } }), '2 Gbps · 900 requests/second');
    assert.equal(governedLimitDisplay({ requested_limits: {} }), '—');
  });
});

describe('high-scale authorization pack progress', () => {
  it('summarizes accepted, awaiting-review, and still-to-record artifacts', () => {
    const types = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'];
    const packStatus = {
      requirements: [
        { type: 'a', status: 'accepted' },
        { type: 'b', status: 'accepted' },
        { type: 'c', status: 'accepted' },
        { type: 'd', status: 'pending_review' },
        { type: 'e', status: 'pending_review' },
        { type: 'f', status: 'rejected' }
      ]
    };
    assert.equal(summarizeAuthorizationPackProgress(packStatus, types), '3 of 9 accepted · 2 awaiting SOC review · 4 to record');
  });

  it('omits empty segments and handles a missing pack status', () => {
    assert.equal(summarizeAuthorizationPackProgress({ requirements: [{ type: 'a', status: 'accepted' }] }, ['a']), '1 of 1 accepted');
    assert.equal(summarizeAuthorizationPackProgress(null, ['a', 'b']), '0 of 2 accepted · 2 to record');
  });
});

describe('high-scale SOC artifact review rows', () => {
  it('lists every upload of a type with the pack-determining artifact first', () => {
    const artifacts = [
      { id: 'a_old_rejected', type: 'legal_approval', status: 'rejected', created_at: '2026-07-01T00:00:00.000Z' },
      { id: 'a_pending', type: 'legal_approval', status: 'pending_review', created_at: '2026-07-03T00:00:00.000Z' },
      { id: 'a_accepted', type: 'legal_approval', status: 'accepted', created_at: '2026-07-02T00:00:00.000Z' },
      { id: 'other', type: 'scope_declaration', status: 'pending_review' }
    ];
    assert.deepEqual(orderedArtifactsForType(artifacts, 'legal_approval').map((row) => row.id), ['a_accepted', 'a_pending', 'a_old_rejected']);
    assert.deepEqual(orderedArtifactsForType(artifacts, 'provider_approval'), []);
  });
});

describe('tenant kill switch scoping', () => {
  it('mirrors server scoping: tenant map, scoped tenant_id, then legacy global', () => {
    assert.equal(killSwitchActiveForTenant(null, 'ten_a'), false);
    assert.equal(killSwitchActiveForTenant({ active: false, tenant_id: 'ten_a' }, 'ten_a'), false);
    assert.equal(killSwitchActiveForTenant({ active: true, tenant_id: 'ten_b' }, 'ten_a'), false);
    assert.equal(killSwitchActiveForTenant({ active: true, tenant_id: 'ten_a' }, 'ten_a'), true);
    assert.equal(killSwitchActiveForTenant({ active: true, tenants: { ten_b: true } }, 'ten_a'), false);
    assert.equal(killSwitchActiveForTenant({ active: true, tenants: { ten_a: true } }, 'ten_a'), true);
    assert.equal(killSwitchActiveForTenant({ active: true }, 'ten_a'), true);
    assert.equal(killSwitchActiveForTenant({ enabled: true, tenant_id: null }, 'ten_a'), true);
  });
});
