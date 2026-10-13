import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { beforeEach, test } from 'node:test';
import { addArtifact, createHighScaleRequest, reviewArtifact } from '../../src/services/highScale.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { validHighScaleRequestPayload } from '../helpers/highScalePayload.mjs';

const customer = { tenantId: 'ten_demo', userId: 'engineer', role: 'engineer' };
const soc = { tenantId: 'ten_demo', userId: 'soc_a', role: 'soc' };

function seedArtifact() {
  const req = createHighScaleRequest(customer, validHighScaleRequestPayload({ target_group_id: 'tg_1' }));
  assert.ok(req.id, JSON.stringify(req));
  const artifact = addArtifact(customer, req.id, {
    type: 'test_plan',
    filename: 'test-plan.pdf',
    content_sha256: createHash('sha256').update('synthetic test plan').digest('hex'),
    reference_uri: `metadata://high-scale/test_plan/${req.id}`,
    approval_reference: 'REF-SYNTHETIC',
    approver: 'customer-declared',
  });
  assert.ok(artifact?.id, JSON.stringify(artifact));
  return { req, artifact };
}

function reviewAudits(artifactId) {
  return getStore().auditLog.filter((entry) => entry.action === 'high_scale.artifact_reviewed' && entry.resource_id === artifactId);
}

beforeEach(() => {
  freshStore();
});

test('rejecting an authorization artifact without a reason is refused and leaves it unreviewed', () => {
  const { req, artifact } = seedArtifact();
  for (const notes of [undefined, '', '   ']) {
    const result = reviewArtifact(soc, req.id, artifact.id, { status: 'rejected', notes });
    assert.deepEqual(result, { error: 'review_notes_required', status: 400 });
  }
  const stored = getStore().highScaleRequests.find((row) => row.id === req.id).artifacts.find((row) => row.id === artifact.id);
  assert.equal(stored.status, 'pending_review');
  assert.equal(stored.reviewed_by, undefined);
  assert.equal(reviewAudits(artifact.id).length, 0);
});

test('a rejection records the trimmed customer-facing reason on the artifact and in the audit metadata', () => {
  const { req, artifact } = seedArtifact();
  const result = reviewArtifact(soc, req.id, artifact.id, { status: 'rejected', notes: '  Approver signature reference is missing.  ' });
  assert.equal(result.status, 'rejected');
  assert.equal(result.review_notes, 'Approver signature reference is missing.');
  const [entry] = reviewAudits(artifact.id);
  assert.equal(entry.metadata.status, 'rejected');
  assert.equal(entry.metadata.notes, 'Approver signature reference is missing.');
  assert.equal(entry.metadata.request_id, req.id);
});

test('acceptance needs no note and records none', () => {
  const { req, artifact } = seedArtifact();
  const result = reviewArtifact(soc, req.id, artifact.id, { status: 'accepted', notes: null });
  assert.equal(result.status, 'accepted');
  assert.equal(result.review_notes, null);
  assert.equal(reviewAudits(artifact.id)[0].metadata.notes, null);
});
