import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  AUTHORIZATION_ARTIFACT_CATALOG,
  REQUIRED_AUTHORIZATION_ARTIFACT_TYPES,
  authorizationArtifactTypesForRequest,
  buildLifecycleTimeline,
  buildMetadataArtifactUploadBody,
  explainArtifactReviewStatus,
  providerApprovalRequired
} from '../../apps/web/react/src/lib/high-scale.ts';

describe('high-scale react helpers', () => {
  it('covers every required authorization template artifact type', () => {
    const catalogTypes = AUTHORIZATION_ARTIFACT_CATALOG
      .filter((entry) => entry.artifact_type !== 'provider_approval')
      .map((entry) => entry.artifact_type);
    assert.deepEqual(catalogTypes, [...REQUIRED_AUTHORIZATION_ARTIFACT_TYPES]);
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
      target_group_id: 'tg_1',
      requested_window: {
        window_start: '2026-01-01T00:00:00.000Z',
        window_end: '2026-01-02T00:00:00.000Z'
      },
      requested_scenario_families: ['volumetric_metadata'],
      requested_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 45 },
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
    assert.equal(body.reference_uri, 'metadata://high-scale/provider_approval/hs_1');
  });

  it('keeps customer high-scale surfaces free of SOC execution endpoints', () => {
    // Security invariant: neither the customer high-scale list page nor its
    // dedicated detail view may call SOC-only execution endpoints. SOC execution
    // lives exclusively in SocRequestDetailView (staff surface).
    const listSource = readFileSync(new URL('../../apps/web/react/src/pages/page-components.tsx', import.meta.url), 'utf8');
    const listPage = listSource.match(/export function HighScalePage[\s\S]*?(?=\nexport function )/)?.[0] ?? '';
    assert.equal(listPage.includes('/internal/soc/high-scale/'), false);
    // List page routes to the dedicated request detail page and keeps the SOC governance pointer.
    assert.ok(listPage.includes("buildDetailHref('high-scale-detail'"));
    assert.ok(listPage.includes('href="#soc"'));

    const detailSource = readFileSync(new URL('../../apps/web/react/src/pages/detail-pages.tsx', import.meta.url), 'utf8');
    const detailView = detailSource.match(/function HighScaleDetailView[\s\S]*?(?=\nfunction )/)?.[0] ?? '';
    // The customer detail view must also stay free of SOC execution endpoints...
    assert.equal(detailView.includes('/internal/soc/high-scale/'), false);
    // ...while carrying the customer authorization-pack + lifecycle capability that moved here.
    assert.ok(detailView.includes('buildLifecycleTimeline'));
    assert.ok(detailView.includes('explainArtifactReviewStatus'));
    assert.ok(detailView.includes('authorizationArtifactTypesForRequest'));
    assert.ok(detailView.includes('buildMetadataArtifactUploadBody'));
    assert.ok(detailView.includes('/v1/high-scale-requests/'));
    assert.ok(detailView.includes('custody_id'));
    assert.ok(detailView.includes('content_sha256'));
    assert.ok(detailView.includes('filename'));
  });
});