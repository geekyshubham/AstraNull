import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { buildLoaCustodyDigest } from '../../src/lib/authorizationArtifactLedger.mjs';
import { transitionHighScale } from '../../src/services/highScale.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { seedPortalBaseline, PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';

let baseUrl;
let server;
const ctx = { tenantId: PORTAL_BASELINE_IDS.tenantId, userId: 'usr_owner', role: 'owner' };

before(() => {
  seedPortalBaseline();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

beforeEach(() => {
  seedPortalBaseline();
});

function ownerHeaders() {
  return demoHeaders('owner', PORTAL_BASELINE_IDS.tenantId, 'usr_owner');
}

describe('LOA portal integration (FT-LOA-01..06)', () => {
  it('FT-LOA-01 sign with attested:true writes loa + custody digest', async () => {
    await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa/${PORTAL_BASELINE_IDS.loaId}/revoke`,
      { headers: ownerHeaders(), body: { reason: 'reset' } },
    );

    const payload = {
      signer_name: 'Jordan Signer',
      signer_title: 'VP Eng',
      signer_email: 'jordan@acme.com',
      attested: true,
      emergency_contact: { name: 'Ops', role: 'SRE', phone: '+1', email: 'ops@acme.com' },
      scope_ack: ['tgt_checkout_1', 'tgt_checkout_2'],
    };
    const res = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa`,
      { headers: ownerHeaders(), body: payload },
    );
    assert.equal(res.status, 201);
    assert.ok(res.json.custody_digest_sha256);
    const loa = getStore().loaSignatures.find((row) => row.id === res.json.loa.id);
    assert.ok(loa);
    const digest = buildLoaCustodyDigest({
      tenant_id: ctx.tenantId,
      target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
      signer_name: payload.signer_name,
      signer_email: payload.signer_email,
      signed_at: loa.signed_at,
      scope_snapshot: loa.scope_snapshot,
    });
    assert.equal(digest, res.json.custody_digest_sha256);
    assert.ok(getStore().highScaleAuthorizationArtifacts.some((a) => a.id === res.json.custody_artifact_id));
  });

  it('FT-LOA-02 attested:false returns 403 attestation_required', async () => {
    const res = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa`,
      { headers: ownerHeaders(), body: { signer_name: 'X', signer_title: 'Y', signer_email: 'z@a.com', attested: false } },
    );
    assert.equal(res.status, 403);
    assert.equal(res.json.error, 'attestation_required');
  });

  it('rejects omitted and empty scope_ack without defaulting to eligible targets', async () => {
    const before = getStore().loaSignatures.length;
    for (const scopeAck of [undefined, []]) {
      const body = {
        signer_name: 'A', signer_title: 'B', signer_email: 'a@b.com', attested: true,
        emergency_contact: { name: 'Ops', role: 'SRE', phone: '+1', email: 'ops@acme.com' },
        ...(scopeAck === undefined ? {} : { scope_ack: scopeAck }),
      };
      const res = await request(
        baseUrl,
        'POST',
        `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa`,
        { headers: ownerHeaders(), body },
      );
      assert.equal(res.status, 400);
      assert.equal(res.json.error, 'invalid_scope_ack');
      assert.equal(getStore().loaSignatures.length, before);
    }
  });

  it('FT-LOA-03 active LOA returns 409 loa_active', async () => {
    const res = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa`,
      { headers: ownerHeaders(), body: {
        signer_name: 'A', signer_title: 'B', signer_email: 'a@b.com', attested: true,
        emergency_contact: { name: 'Ops', role: 'SRE', phone: '+1', email: 'ops@acme.com' },
        scope_ack: ['tgt_checkout_1'],
      } },
    );
    assert.equal(res.status, 409);
    assert.equal(res.json.error, 'loa_active');
  });

  it('FT-LOA-04 scope_snapshot excludes unverified targets', async () => {
    await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa/${PORTAL_BASELINE_IDS.loaId}/revoke`,
      { headers: ownerHeaders(), body: { reason: 'reset' } },
    );
    const ineligibleOnly = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa`,
      { headers: ownerHeaders(), body: {
        signer_name: 'A', signer_title: 'B', signer_email: 'a@b.com', attested: true,
        emergency_contact: { name: 'Ops', role: 'SRE', phone: '+1', email: 'ops@acme.com' },
        scope_ack: ['tgt_checkout_3'],
      } },
    );
    assert.equal(ineligibleOnly.status, 400);
    assert.equal(ineligibleOnly.json.error, 'invalid_scope_ack');

    const res = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa`,
      { headers: ownerHeaders(), body: {
        signer_name: 'A', signer_title: 'B', signer_email: 'a@b.com', attested: true,
        emergency_contact: { name: 'Ops', role: 'SRE', phone: '+1', email: 'ops@acme.com' },
        scope_ack: ['tgt_checkout_1', 'tgt_checkout_2', 'tgt_checkout_3'],
      } },
    );
    assert.equal(res.status, 201);
    assert.ok(res.json.loa.scope_snapshot.targets.includes('tgt_checkout_1'));
    assert.ok(res.json.loa.scope_snapshot.excluded.some((row) => row.target_id === 'tgt_checkout_3'));
  });

  it('rejects foreign scope acknowledgements and ignores a caller-provided scope snapshot', async () => {
    await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa/${PORTAL_BASELINE_IDS.loaId}/revoke`,
      { headers: ownerHeaders(), body: { reason: 'scope regression' } },
    );
    getStore().targets.push(
      {
        id: 'tgt_other_group', tenant_id: ctx.tenantId, target_group_id: 'tg_other',
        kind: 'fqdn', value: 'other.example.test', created_at: new Date().toISOString(),
      },
      {
        id: 'tgt_other_tenant', tenant_id: 'ten_other', target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
        kind: 'fqdn', value: 'foreign.example.test', created_at: new Date().toISOString(),
      },
    );
    const baseBody = {
      signer_name: 'Owner', signer_title: 'CISO', signer_email: 'owner@example.test',
      attested: true,
      emergency_contact: { name: 'Ops', role: 'SRE', phone: '+1', email: 'ops@example.test' },
    };
    for (const foreignTarget of ['tgt_other_group', 'tgt_other_tenant']) {
      const rejected = await request(
        baseUrl,
        'POST',
        `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa`,
        { headers: ownerHeaders(), body: { ...baseBody, scope_ack: [foreignTarget] } },
      );
      assert.equal(rejected.status, 400);
      assert.equal(rejected.json.error, 'scope_target_not_found');
    }

    const signed = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa`,
      {
        headers: ownerHeaders(),
        body: {
          ...baseBody,
          scope_ack: ['tgt_checkout_1'],
          scope_snapshot: { targets: ['tgt_other_tenant'] },
        },
      },
    );
    assert.equal(signed.status, 201);
    assert.deepEqual(signed.json.loa.scope_snapshot.targets, ['tgt_checkout_1']);
    assert.equal(JSON.stringify(signed.json.loa.scope_snapshot).includes('tgt_other_tenant'), false);
  });

  it('transitions and audits an expired signed LOA before replacement', async () => {
    const predecessor = getStore().loaSignatures.find(
      (row) => row.id === PORTAL_BASELINE_IDS.loaId,
    );
    predecessor.expires_at = '2000-01-01T00:00:00.000Z';

    const replacement = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa`,
      { headers: ownerHeaders(), body: {
        signer_name: 'Replacement', signer_title: 'CISO', signer_email: 'replacement@acme.com',
        attested: true,
        emergency_contact: { name: 'Ops', role: 'SRE', phone: '+1', email: 'ops@acme.com' },
        scope_ack: ['tgt_checkout_1'],
      } },
    );
    assert.equal(replacement.status, 201);
    assert.equal(predecessor.state, 'expired');
    assert.ok(getStore().auditLog.some(
      (entry) => entry.action === 'loa.expired' && entry.resource_id === predecessor.id,
    ));
  });

  it('FT-LOA-05 revoke frees active index and allows resign', async () => {
    const revoke = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa/${PORTAL_BASELINE_IDS.loaId}/revoke`,
      { headers: ownerHeaders(), body: { reason: 'rotate' } },
    );
    assert.equal(revoke.status, 200);
    assert.equal(revoke.json.loa.state, 'revoked');

    const resign = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa`,
      { headers: ownerHeaders(), body: {
        signer_name: 'New', signer_title: 'CISO', signer_email: 'new@acme.com', attested: true,
        emergency_contact: { name: 'Ops', role: 'SRE', phone: '+1', email: 'ops@acme.com' },
        scope_ack: ['tgt_checkout_1'],
      } },
    );
    assert.equal(resign.status, 201);
  });

  it('FT-LOA-06 revoke blocks in-flight SOC-gated run start', async () => {
    await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa/${PORTAL_BASELINE_IDS.loaId}/revoke`,
      { headers: ownerHeaders(), body: { reason: 'block runs' } },
    );
    const blocked = transitionHighScale(ctx, 'hsr_checkout_scheduled', 'start', { adapter_mode: 'dry-run' });
    assert.equal(blocked.error, 'loa_missing');
    assert.equal(blocked.status, 409);
  });

  it('rejects expired and partial-scope LOAs at high-scale start', () => {
    const loa = getStore().loaSignatures.find(
      (row) => row.id === PORTAL_BASELINE_IDS.loaId,
    );
    loa.expires_at = '2000-01-01T00:00:00.000Z';
    const expired = transitionHighScale(ctx, 'hsr_checkout_scheduled', 'start', { adapter_mode: 'dry-run' });
    assert.equal(expired.error, 'loa_expired');

    loa.expires_at = new Date(Date.now() + 86_400_000).toISOString();
    loa.scope_snapshot = { targets: [] };
    const partial = transitionHighScale(ctx, 'hsr_checkout_scheduled', 'start', { adapter_mode: 'dry-run' });
    assert.equal(partial.error, 'loa_scope_mismatch');
    assert.equal(partial.status, 409);
  });
});